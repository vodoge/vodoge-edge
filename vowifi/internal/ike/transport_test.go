package ike

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/engine/swu"
	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

// TestSocketSatisfiesMirrorSeams is the load-bearing assertion of T041a: one
// concrete type, one UDP socket, plugged into every seam the read-only mirror
// exposes. If a vendor bump changes any of these signatures this test stops
// compiling, which is the point.
func TestSocketSatisfiesMirrorSeams(t *testing.T) {
	f := newFakeEPDG(t)
	f.Start()
	s := dialFake(t, f, SocketConfig{})

	var (
		_ ikev2.InitTransport             = s
		_ swu.ESPPacketReadWriteTransport = s
		_ swu.NATTKeepaliveSender         = s
		_ swu.ESPPacketTransportCloser    = s
	)

	// The factories are what the manager actually reads at
	// ike_tunnel_manager.go:374-401.
	ikeTransport, err := s.IKETransportFactory()(swu.TunnelConfig{}, swu.IKETransportConfig{})
	if err != nil {
		t.Fatalf("IKETransportFactory: %v", err)
	}
	espTransport, err := s.ESPTransportFactory()(swu.TunnelConfig{}, swu.ESPTransportConfig{})
	if err != nil {
		t.Fatalf("ESPTransportFactory: %v", err)
	}
	if ikeTransport != ikev2.InitTransport(s) {
		t.Errorf("IKE factory handed back a different transport")
	}
	if espTransport != swu.ESPPacketTransport(s) {
		t.Errorf("ESP factory handed back a different transport, so IKE and ESP would not share a five-tuple")
	}
}

// TestSocketBindsNATTPort records the fact the whole single-socket design rests
// on. It is skipped rather than failed when the port is already taken, because a
// developer machine may legitimately be running an IPsec stack.
func TestSocketBindsNATTPort(t *testing.T) {
	s, err := Listen(SocketConfig{LocalPort: NATTPort, LocalIP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("UDP %d unavailable on this host: %v", NATTPort, err)
	}
	defer s.Close(nil)
	if s.LocalPort() != NATTPort {
		t.Fatalf("LocalPort = %d, want %d", s.LocalPort(), NATTPort)
	}
}

// TestSocketDemultiplexesNonESPMarker is the bug the mirror cannot avoid:
// UDPESPPacketTransport.ReadESPPacket (udp_esp_transport.go:110) hits `continue`
// on a marker-prefixed datagram, so an IKE reply sharing the ESP socket would be
// swallowed with no error. Ours routes both.
func TestSocketDemultiplexesNonESPMarker(t *testing.T) {
	f := newFakeEPDG(t)
	// The fake stays silent; this test injects datagrams by hand so it controls
	// exactly what lands on the wire.
	s := dialFake(t, f, SocketConfig{})

	espPacket := append([]byte{0x11, 0x22, 0x33, 0x44}, bytes.Repeat([]byte{0xab}, 60)...)
	ikeMessage := buildProbeMessage(t, 0x0102030405060708)

	sendRaw(t, f, s, append([]byte{0, 0, 0, 0}, ikeMessage...))
	sendRaw(t, f, s, espPacket)
	sendRaw(t, f, s, []byte{0xff})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got, err := s.ReadESPPacket(ctx)
	if err != nil {
		t.Fatalf("ReadESPPacket: %v", err)
	}
	if !bytes.Equal(got, espPacket) {
		t.Fatalf("ESP payload round-trip mismatch")
	}

	// The IKE datagram must still be queued, with its marker stripped.
	select {
	case queued := <-s.ike:
		if !bytes.Equal(queued, ikeMessage) {
			t.Fatalf("IKE payload was altered in the demux")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("IKE message never reached the IKE queue: the demux swallowed it")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().KeepalivesReceived == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	stats := s.Stats()
	if stats.KeepalivesReceived != 1 {
		t.Errorf("KeepalivesReceived = %d, want 1", stats.KeepalivesReceived)
	}
	if stats.ESPReceived != 1 || stats.IKEReceived != 1 {
		t.Errorf("ESPReceived=%d IKEReceived=%d, want 1 and 1", stats.ESPReceived, stats.IKEReceived)
	}
}

func TestSocketSendsKeepaliveAndESP(t *testing.T) {
	f := newFakeEPDG(t)
	received := make(chan []byte, 4)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := f.conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			received <- append([]byte(nil), buf[:n]...)
		}
	}()
	s := dialFake(t, f, SocketConfig{})

	if err := s.SendNATTKeepalive(context.Background()); err != nil {
		t.Fatalf("SendNATTKeepalive: %v", err)
	}
	if got := waitFor(t, received); len(got) != 1 || got[0] != 0xff {
		t.Fatalf("keepalive on the wire = %x, want ff (RFC 3948 section 4)", got)
	}

	esp := append([]byte{0xde, 0xad, 0xbe, 0xef}, bytes.Repeat([]byte{7}, 32)...)
	if err := s.SendESPPacket(context.Background(), esp); err != nil {
		t.Fatalf("SendESPPacket: %v", err)
	}
	if got := waitFor(t, received); !bytes.Equal(got, esp) {
		t.Fatalf("ESP packet was rewritten on the way out")
	}

	// A payload starting with four zero bytes would be read by the peer as an
	// IKE message. The mirror guards this at udp_esp_transport.go:44 and so do we.
	if err := s.SendESPPacket(context.Background(), make([]byte, 64)); err == nil {
		t.Fatalf("SendESPPacket accepted a payload that looks like a non-ESP marker")
	} else if !errors.Is(err, ErrBadESPPacket) {
		t.Fatalf("SendESPPacket error = %v, want ErrBadESPPacket", err)
	}
}

// TestExchangeIKERetransmits exercises the RFC 7296 section 2.1 duty: the
// initiator owns reliability.
func TestExchangeIKERetransmits(t *testing.T) {
	f := newFakeEPDG(t)
	f.dropFirst = 2
	f.Start()
	s := dialFake(t, f, SocketConfig{Retransmit: testPolicy(5)})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req := buildProbeMessage(t, 0x1122334455667788)
	resp, err := s.ExchangeIKE(ctx, req)
	if err != nil {
		t.Fatalf("ExchangeIKE: %v", err)
	}
	if len(resp) == 0 {
		t.Fatalf("empty response")
	}
	stats := s.Stats()
	if stats.IKERetransmits < 2 {
		t.Fatalf("IKERetransmits = %d, want at least 2", stats.IKERetransmits)
	}
	if stats.IKESent != stats.IKERetransmits+1 {
		t.Fatalf("IKESent = %d, retransmits = %d: the counters disagree", stats.IKESent, stats.IKERetransmits)
	}
	if f.requestCount() < 1 {
		t.Fatalf("fake ePDG saw no request")
	}
}

func TestExchangeIKEGivesUpAfterAllAttempts(t *testing.T) {
	f := newFakeEPDG(t)
	f.dropFirst = 100
	f.Start()
	s := dialFake(t, f, SocketConfig{Retransmit: RetransmitPolicy{
		Initial: 60 * time.Millisecond, Multiplier: 1, Max: 60 * time.Millisecond, Attempts: 3,
	}})

	_, err := s.ExchangeIKE(context.Background(), buildProbeMessage(t, 0x9999888877776666))
	if !errors.Is(err, ErrRetransmitExhausted) {
		t.Fatalf("ExchangeIKE error = %v, want ErrRetransmitExhausted", err)
	}
	if got := s.Stats().IKESent; got != 3 {
		t.Fatalf("IKESent = %d, want exactly Attempts=3", got)
	}
}

// TestExchangeIKEIgnoresMismatchedResponses guards the reason we match on the
// header rather than taking the next datagram: a late answer to an earlier
// request would otherwise attach a stale responder SPI to this exchange.
func TestExchangeIKEIgnoresMismatchedResponses(t *testing.T) {
	f := newFakeEPDG(t)
	f.unsolicitedJunk = true
	f.Start()
	s := dialFake(t, f, SocketConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := buildProbeMessage(t, 0x0f0e0d0c0b0a0908)
	resp, err := s.ExchangeIKE(ctx, req)
	if err != nil {
		t.Fatalf("ExchangeIKE: %v", err)
	}
	hdr, err := ikev2.ParseHeader(resp)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if hdr.MessageID != 0 {
		t.Fatalf("accepted a response with message id %d; the junk copy carried 0xdead", hdr.MessageID)
	}
	if hdr.InitiatorSPI != 0x0f0e0d0c0b0a0908 {
		t.Fatalf("responder SPI mismatch slipped through")
	}
}

func TestSocketDropsForeignSources(t *testing.T) {
	f := newFakeEPDG(t)
	s := dialFake(t, f, SocketConfig{})

	stranger, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("stranger listen: %v", err)
	}
	defer stranger.Close()
	if _, err := stranger.WriteToUDP(append([]byte{0, 0, 0, 0}, buildProbeMessage(t, 1)...), s.LocalAddr()); err != nil {
		t.Fatalf("stranger write: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().ForeignSourceDrops == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("a datagram from an unrelated host was accepted")
}

func TestSocketExchangeAfterCloseFails(t *testing.T) {
	f := newFakeEPDG(t)
	f.Start()
	s := dialFake(t, f, SocketConfig{})
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := s.ExchangeIKE(context.Background(), buildProbeMessage(t, 5)); err == nil {
		t.Fatalf("ExchangeIKE succeeded on a closed socket")
	}
	if _, err := s.ReadESPPacket(context.Background()); err == nil {
		t.Fatalf("ReadESPPacket succeeded on a closed socket")
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestRetransmitPolicyNormalization(t *testing.T) {
	got := RetransmitPolicy{Multiplier: 0.1, Attempts: -3}.normalized()
	if got.Multiplier < 1 {
		t.Errorf("Multiplier = %v; a value below 1 would produce a tight retry loop", got.Multiplier)
	}
	if got.Attempts < 1 {
		t.Errorf("Attempts = %d, want at least 1", got.Attempts)
	}
	if got.Max < got.Initial {
		t.Errorf("Max %v < Initial %v", got.Max, got.Initial)
	}
}

func buildProbeMessage(t *testing.T, spi uint64) []byte {
	t.Helper()
	msg := ikev2.Message{
		Header: ikev2.Header{
			InitiatorSPI: spi,
			ExchangeType: ikev2.ExchangeIKE_SA_INIT,
			Flags:        ikev2.FlagInitiator,
		},
		Payloads: []ikev2.Payload{ikev2.NoncePayload(bytes.Repeat([]byte{9}, 32))},
	}
	raw, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	return raw
}

func sendRaw(t *testing.T, f *fakeEPDG, s *Socket, payload []byte) {
	t.Helper()
	if _, err := f.conn.WriteToUDP(payload, s.LocalAddr()); err != nil {
		t.Fatalf("fake ePDG write: %v", err)
	}
}

func waitFor(t *testing.T, ch chan []byte) []byte {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for a datagram")
		return nil
	}
}
