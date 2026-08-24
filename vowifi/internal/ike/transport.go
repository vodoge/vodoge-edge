package ike

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boa-z/vowifi-go/engine/swu"
	"github.com/boa-z/vowifi-go/engine/swu/ikev2"

	"github.com/yuanshuai1122/vodoge-edge/vowifi/internal/capture"
)

// NATTPort is the IPsec NAT traversal port. Everything in this package rides
// one socket pinned here.
//
// Measured on the edge VM as uid 1000 on 2026-08-24:
//
//	PORT 500  bind FAIL errno=13 Permission denied
//	PORT 4500 bind OK
//	net.ipv4.ip_unprivileged_port_start = 1024
//
// So 4500 is reachable without root and 500 is not, which is what makes the
// single-socket design legal here. T038 already proved both ports get complete
// IKE_SA_INIT answers from T-Mobile and AT&T, so restricting to 4500 costs no
// reachability, always carries the non-ESP marker, and keeps IKE and the ESP
// data plane on one five-tuple so NAT mappings cannot diverge.
const NATTPort uint16 = 4500

// Errors reported by the socket.
var (
	ErrSocketClosed        = errors.New("vowifi/ike: socket is closed")
	ErrRetransmitExhausted = errors.New("vowifi/ike: no response after all retransmissions")
	ErrNoRemote            = errors.New("vowifi/ike: no remote endpoint configured")
	ErrBadESPPacket        = errors.New("vowifi/ike: refusing to send a packet that is not ESP")
)

// The mirror hands us exactly these seams. Assert them at compile time so a
// vendor bump that changes a signature breaks the build here rather than at 3am
// on a live ePDG.
var (
	_ ikev2.InitTransport             = (*Socket)(nil)
	_ swu.ESPPacketTransport          = (*Socket)(nil)
	_ swu.ESPPacketReceiver           = (*Socket)(nil)
	_ swu.ESPPacketReadWriteTransport = (*Socket)(nil)
	_ swu.NATTKeepaliveSender         = (*Socket)(nil)
	_ swu.ESPPacketTransportCloser    = (*Socket)(nil)
)

// RetransmitPolicy implements the RFC 7296 section 2.1 retransmission duty: the
// initiator owns reliability and must back off exponentially.
type RetransmitPolicy struct {
	// Initial is the wait before the first retransmission.
	Initial time.Duration
	// Multiplier scales the wait after each attempt. Values below 1 are treated
	// as 1 so a misconfiguration cannot produce a tight retry loop.
	Multiplier float64
	// Max caps a single wait.
	Max time.Duration
	// Attempts is the total number of transmissions, original included.
	Attempts int
}

// DefaultRetransmitPolicy is tuned for an ePDG across an intercontinental path.
// T038 measured live responses from Dallas, but the GSLB can hand out a node
// anywhere in 208.54.0.0/16, so the first wait is generous rather than snappy.
func DefaultRetransmitPolicy() RetransmitPolicy {
	return RetransmitPolicy{
		Initial:    2 * time.Second,
		Multiplier: 1.8,
		Max:        20 * time.Second,
		Attempts:   5,
	}
}

func (p RetransmitPolicy) normalized() RetransmitPolicy {
	if p.Initial <= 0 {
		p.Initial = DefaultRetransmitPolicy().Initial
	}
	if p.Multiplier < 1 {
		p.Multiplier = 1
	}
	if p.Max <= 0 || p.Max < p.Initial {
		p.Max = p.Initial
	}
	if p.Attempts <= 0 {
		p.Attempts = 1
	}
	return p
}

// SocketConfig configures the one long-lived UDP socket.
type SocketConfig struct {
	// LocalIP is the bind address. nil binds the wildcard.
	LocalIP net.IP
	// LocalPort defaults to NATTPort. Production must not change it.
	LocalPort uint16
	// EphemeralLocalPort asks the kernel for any free port instead of pinning
	// 4500. It exists for tests that need to run in parallel; production leaves
	// it false, because sharing one fixed five-tuple with the ESP data plane is
	// the reason this socket exists.
	EphemeralLocalPort bool
	// Remote is the default peer for sends. It may be replaced with SetRemote
	// when the GSLB hands out a different ePDG.
	Remote *net.UDPAddr
	// Retransmit governs ExchangeIKE.
	Retransmit RetransmitPolicy
	// Capture, when set, records every datagram in both directions.
	Capture *capture.Writer
	// QueueDepth bounds the demultiplexed backlogs.
	QueueDepth int
	// UseNonESPMarker defaults to true whenever either endpoint uses 4500.
	UseNonESPMarker *bool
	// AcceptAnySource disables the source-address filter. Off by default: a
	// stray datagram from an unrelated host must not be parsed as an IKE reply.
	AcceptAnySource bool
}

// Stats are counters worth having when a tunnel is "sometimes" broken.
type Stats struct {
	IKESent            uint64
	IKEReceived        uint64
	IKERetransmits     uint64
	IKEUnmatchedDrops  uint64
	ESPSent            uint64
	ESPReceived        uint64
	KeepalivesSent     uint64
	KeepalivesReceived uint64
	ForeignSourceDrops uint64
	QueueOverflowDrops uint64
	ShortDatagramDrops uint64
	CaptureErrors      uint64
}

// Socket is one long-lived *net.UDPConn pinned to 4500 that serves both the IKE
// control plane and the ESP data plane.
//
// The mirror cannot do this with its own types. UDPESPPacketTransport.
// ReadESPPacket (engine/swu/udp_esp_transport.go:110) hits `continue` on any
// datagram carrying the non-ESP marker, and on 4500 that marker is exactly what
// an IKE message looks like. Sharing that reader would make IKE replies vanish
// with no error anywhere. So the demultiplexing has to happen in one read loop
// that owns both sides, which is this type.
type Socket struct {
	conn      *net.UDPConn
	localIP   net.IP
	localPort uint16
	marker    bool
	policy    RetransmitPolicy
	capture   *capture.Writer
	anySource bool

	remoteMu sync.RWMutex
	remote   *net.UDPAddr

	exchangeMu sync.Mutex

	ike  chan []byte
	esp  chan []byte
	done chan struct{}

	closeOnce sync.Once
	closeErr  error

	readErr atomic.Pointer[error]

	statsMu sync.Mutex
	stats   Stats
}

// Listen opens the socket. The caller owns Close.
func Listen(cfg SocketConfig) (*Socket, error) {
	port := cfg.LocalPort
	if port == 0 && !cfg.EphemeralLocalPort {
		port = NATTPort
	}
	bindIP := cfg.LocalIP
	network := "udp4"
	if bindIP != nil && bindIP.To4() == nil {
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: bindIP, Port: int(port)})
	if err != nil {
		return nil, fmt.Errorf("vowifi/ike: bind %s:%d: %w", bindIP, port, err)
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("vowifi/ike: local address is %T, want *net.UDPAddr", conn.LocalAddr())
	}
	depth := cfg.QueueDepth
	if depth <= 0 {
		depth = 32
	}
	marker := true
	if cfg.UseNonESPMarker != nil {
		marker = *cfg.UseNonESPMarker
	} else if uint16(local.Port) != NATTPort && (cfg.Remote == nil || cfg.Remote.Port != int(NATTPort)) {
		marker = false
	}
	s := &Socket{
		conn:      conn,
		localPort: uint16(local.Port),
		marker:    marker,
		policy:    cfg.Retransmit.normalized(),
		capture:   cfg.Capture,
		anySource: cfg.AcceptAnySource,
		remote:    cfg.Remote,
		ike:       make(chan []byte, depth),
		esp:       make(chan []byte, depth),
		done:      make(chan struct{}),
	}
	s.localIP = resolveLocalIP(local.IP, cfg.Remote)
	s.capture.SetLocalAddr(s.LocalAddr())
	s.capture.SetRemoteAddr(cfg.Remote)
	go s.readLoop()
	return s, nil
}

// resolveLocalIP picks the address our NAT_DETECTION_SOURCE_IP must hash.
//
// A wildcard bind has no useful IP of its own, so the kernel routing table is
// asked which source it would pick for the peer. Getting this wrong is not
// cosmetic: the notify would hash 0.0.0.0 and the responder would conclude we
// are behind a NAT that does not exist.
func resolveLocalIP(bound net.IP, remote *net.UDPAddr) net.IP {
	if bound != nil && !bound.IsUnspecified() {
		return bound
	}
	if remote == nil {
		return bound
	}
	probe, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return bound
	}
	defer probe.Close()
	if addr, ok := probe.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP
	}
	return bound
}

// LocalAddr is the address other endpoints should see, subject to NAT.
func (s *Socket) LocalAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: s.localIP, Port: int(s.localPort)}
}

// LocalIP returns the source address used for NAT detection hashing.
func (s *Socket) LocalIP() net.IP { return s.localIP }

// LocalPort returns the pinned local port. It is never zero, which is the whole
// point: the mirror's initNATPayloads (init.go:371-373) returns nil when the
// local port is zero, so the stock stack silently sends no NAT_DETECTION at all.
func (s *Socket) LocalPort() uint16 { return s.localPort }

// Remote returns the current peer.
func (s *Socket) Remote() *net.UDPAddr {
	s.remoteMu.RLock()
	defer s.remoteMu.RUnlock()
	return s.remote
}

// SetRemote repoints the socket at another ePDG candidate. T038 saw seven
// distinct addresses from seven lookups, so the peer is not a constant.
func (s *Socket) SetRemote(addr *net.UDPAddr) {
	s.remoteMu.Lock()
	s.remote = addr
	if s.localIP == nil || s.localIP.IsUnspecified() {
		s.localIP = resolveLocalIP(s.localIP, addr)
	}
	s.remoteMu.Unlock()
	s.capture.SetLocalAddr(s.LocalAddr())
	s.capture.SetRemoteAddr(addr)
}

// Stats returns a snapshot of the counters.
func (s *Socket) Stats() Stats {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	return s.stats
}

func (s *Socket) bump(f func(*Stats)) {
	s.statsMu.Lock()
	f(&s.stats)
	s.statsMu.Unlock()
}

func (s *Socket) readLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.done:
			default:
				stored := err
				s.readErr.Store(&stored)
			}
			close(s.ike)
			close(s.esp)
			return
		}
		wire := append([]byte(nil), buf[:n]...)
		if !s.anySource && !s.sourceAllowed(from) {
			s.bump(func(st *Stats) { st.ForeignSourceDrops++ })
			continue
		}
		s.record(capture.DirRx, from, wire)
		switch capture.Classify(wire) {
		case capture.KindNATT:
			s.bump(func(st *Stats) { st.KeepalivesReceived++ })
		case capture.KindIKE:
			s.bump(func(st *Stats) { st.IKEReceived++ })
			s.deliver(s.ike, wire[4:])
		case capture.KindESP:
			s.bump(func(st *Stats) { st.ESPReceived++ })
			s.deliver(s.esp, wire)
		default:
			s.bump(func(st *Stats) { st.ShortDatagramDrops++ })
		}
	}
}

func (s *Socket) sourceAllowed(from *net.UDPAddr) bool {
	remote := s.Remote()
	if remote == nil || from == nil {
		return true
	}
	return remote.Port == from.Port && remote.IP.Equal(from.IP)
}

func (s *Socket) deliver(ch chan []byte, payload []byte) {
	select {
	case ch <- payload:
	default:
		// Drop the oldest so a stale reply cannot wedge a live exchange, and
		// count it: a growing overflow counter is the signature of a peer that
		// is answering faster than we consume.
		select {
		case <-ch:
			s.bump(func(st *Stats) { st.QueueOverflowDrops++ })
		default:
		}
		select {
		case ch <- payload:
		default:
			s.bump(func(st *Stats) { st.QueueOverflowDrops++ })
		}
	}
}

func (s *Socket) record(dir capture.Direction, peer *net.UDPAddr, payload []byte) {
	if s.capture == nil {
		return
	}
	if err := s.capture.Record(dir, s.LocalAddr(), peer, payload); err != nil {
		s.bump(func(st *Stats) { st.CaptureErrors++ })
	}
}

func (s *Socket) write(peer *net.UDPAddr, wire []byte) error {
	if peer == nil {
		return ErrNoRemote
	}
	select {
	case <-s.done:
		return ErrSocketClosed
	default:
	}
	if _, err := s.conn.WriteToUDP(wire, peer); err != nil {
		return err
	}
	s.record(capture.DirTx, peer, wire)
	return nil
}

// ExchangeIKE satisfies ikev2.InitTransport (engine/swu/ikev2/init.go:27-29).
//
// It owns RFC 7296 retransmission and response matching. Matching is not
// optional decoration: a retransmitted answer to a previous request arrives on
// the same socket, and accepting it would attach a stale responder SPI and
// nonce to the current exchange.
func (s *Socket) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	header, err := ikev2.ParseHeader(request)
	if err != nil {
		return nil, fmt.Errorf("vowifi/ike: outgoing message is not IKEv2: %w", err)
	}
	peer := s.Remote()
	if peer == nil {
		return nil, ErrNoRemote
	}
	wire := request
	if s.marker {
		wire = append([]byte{0, 0, 0, 0}, request...)
	}

	s.exchangeMu.Lock()
	defer s.exchangeMu.Unlock()
	s.drainStale()

	wait := s.policy.Initial
	for attempt := 0; attempt < s.policy.Attempts; attempt++ {
		if attempt > 0 {
			s.bump(func(st *Stats) { st.IKERetransmits++ })
		}
		if err := s.write(peer, wire); err != nil {
			return nil, err
		}
		s.bump(func(st *Stats) { st.IKESent++ })

		deadline := time.NewTimer(wait)
		resp, expired, err := s.awaitResponse(ctx, header, deadline)
		deadline.Stop()
		if err != nil {
			return nil, err
		}
		if !expired {
			return resp, nil
		}
		next := time.Duration(float64(wait) * s.policy.Multiplier)
		if next > s.policy.Max {
			next = s.policy.Max
		}
		wait = next
	}
	return nil, fmt.Errorf("%w: %d transmissions to %s", ErrRetransmitExhausted, s.policy.Attempts, peer)
}

func (s *Socket) awaitResponse(ctx context.Context, request ikev2.Header, timer *time.Timer) ([]byte, bool, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-s.done:
			return nil, false, ErrSocketClosed
		case raw, ok := <-s.ike:
			if !ok {
				return nil, false, s.readFailure()
			}
			if matchesResponse(request, raw) {
				return raw, false, nil
			}
			s.bump(func(st *Stats) { st.IKEUnmatchedDrops++ })
		case <-timer.C:
			return nil, true, nil
		}
	}
}

func (s *Socket) readFailure() error {
	if err := s.readErr.Load(); err != nil && *err != nil {
		return *err
	}
	return ErrSocketClosed
}

// drainStale clears responses left over from an earlier exchange.
func (s *Socket) drainStale() {
	for {
		select {
		case _, ok := <-s.ike:
			if !ok {
				return
			}
			s.bump(func(st *Stats) { st.IKEUnmatchedDrops++ })
		default:
			return
		}
	}
}

func matchesResponse(request ikev2.Header, raw []byte) bool {
	resp, err := ikev2.ParseHeader(raw)
	if err != nil {
		return false
	}
	if resp.Flags&ikev2.FlagResponse == 0 {
		return false
	}
	if resp.InitiatorSPI != request.InitiatorSPI {
		return false
	}
	if resp.MessageID != request.MessageID {
		return false
	}
	return resp.ExchangeType == request.ExchangeType
}

// SendESPPacket satisfies swu.ESPPacketTransport.
func (s *Socket) SendESPPacket(ctx context.Context, packet []byte) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	switch capture.Classify(packet) {
	case capture.KindESP:
	default:
		// The same guard the mirror applies at udp_esp_transport.go:44, kept
		// because an ESP packet whose first four bytes are zero would be read
		// by the peer as an IKE message.
		return fmt.Errorf("%w: %d bytes classified as %s", ErrBadESPPacket, len(packet), capture.Classify(packet))
	}
	if err := s.write(s.Remote(), packet); err != nil {
		return err
	}
	s.bump(func(st *Stats) { st.ESPSent++ })
	return nil
}

// ReadESPPacket satisfies swu.ESPPacketReceiver. Unlike the mirror's own reader
// it cannot swallow IKE traffic, because IKE went to a different queue in the
// single read loop above.
func (s *Socket) ReadESPPacket(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, ErrSocketClosed
	case packet, ok := <-s.esp:
		if !ok {
			return nil, s.readFailure()
		}
		return packet, nil
	}
}

// SendNATTKeepalive satisfies swu.NATTKeepaliveSender (RFC 3948 section 4: a
// single 0xff byte).
func (s *Socket) SendNATTKeepalive(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if err := s.write(s.Remote(), []byte{0xff}); err != nil {
		return err
	}
	s.bump(func(st *Stats) { st.KeepalivesSent++ })
	return nil
}

// Close satisfies swu.ESPPacketTransportCloser.
func (s *Socket) Close(context.Context) error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.closeErr = s.conn.Close()
	})
	return s.closeErr
}

// IKETransportFactory returns the value for swu.IKEPacketTunnelManagerConfig.
// IKETransportFactory (ike_tunnel_manager.go:67). The manager consults it before
// falling back to ikev2.UDPTransport at :374-387.
func (s *Socket) IKETransportFactory() swu.IKETransportFactory {
	return func(swu.TunnelConfig, swu.IKETransportConfig) (ikev2.InitTransport, error) {
		return s, nil
	}
}

// ESPTransportFactory returns the value for swu.IKEPacketTunnelManagerConfig.
// ESPTransportFactory (ike_tunnel_manager.go:68), consulted at :389-401.
// It hands back the same Socket, which is the entire point of the design.
func (s *Socket) ESPTransportFactory() swu.IKEESPTransportFactory {
	return func(swu.TunnelConfig, swu.ESPTransportConfig) (swu.ESPPacketTransport, error) {
		return s, nil
	}
}
