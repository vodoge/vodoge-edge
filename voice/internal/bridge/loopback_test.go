package bridge

import (
	"reflect"
	"testing"
	"time"

	"github.com/pion/rtp"
)

// TestRelayConfigNeverInstallsTransforms holds the hard constraint of T040 in
// place: rtp_relay.go only runs its RTP quality statistics, RTCP feedback
// inspection and two-way DTMF handling while the transform is nil, and it drops
// all three silently otherwise. Payload conversion must therefore happen on the
// WebRTC side of the loopback, never in RTPRelayTransforms.
func TestRelayConfigNeverInstallsTransforms(t *testing.T) {
	cfg := NewRelayConfig("127.0.0.1", RelayPorts{})
	v := reflect.ValueOf(cfg.Transforms)
	for i := 0; i < v.NumField(); i++ {
		if !v.Field(i).IsNil() {
			t.Fatalf("relay transform %s is installed; transcoding must go through the loopback instead",
				v.Type().Field(i).Name)
		}
	}
	if transformsInstalled(cfg.Transforms) {
		t.Fatal("transformsInstalled disagrees with the zero value")
	}
	if cfg.ClientListenIP != "127.0.0.1" || cfg.ClientAdvertiseIP != "127.0.0.1" {
		t.Fatalf("client leg must stay on the loopback, got listen=%q advertise=%q",
			cfg.ClientListenIP, cfg.ClientAdvertiseIP)
	}
}

func TestTransformsInstalledDetectsEachSlot(t *testing.T) {
	base := NewRelayConfig("127.0.0.1", RelayPorts{}).Transforms
	v := reflect.ValueOf(&base).Elem()
	for i := 0; i < v.NumField(); i++ {
		probe := base
		reflect.ValueOf(&probe).Elem().Field(i).Set(reflect.ValueOf(
			func(b []byte) ([]byte, error) { return b, nil },
		))
		if !transformsInstalled(probe) {
			t.Fatalf("a transform in slot %s went undetected", v.Type().Field(i).Name)
		}
	}
}

func TestNewLoopbackRefusesANonLoopbackAddress(t *testing.T) {
	// Plaintext RTP is only acceptable because it never leaves the box.
	if _, err := NewLoopback(LoopbackConfig{LoopbackIP: "192.168.78.10"}); err == nil {
		t.Fatal("expected a non-loopback media address to be refused")
	}
}

// recorder collects the packets the relay sends back toward the browser.
type recorder struct {
	ch chan *rtp.Packet
}

func newRecorder() *recorder { return &recorder{ch: make(chan *rtp.Packet, 512)} }

func (r *recorder) WriteRTP(p *rtp.Packet) error {
	select {
	case r.ch <- p:
	default:
	}
	return nil
}

// TestLoopbackCarriesAudioToTheFakePeerAndBack exercises the whole plaintext
// half of the path: bridge socket -> relay client leg -> relay IMS leg ->
// stand-in peer -> back the same way. It is the part of "audible both ways"
// that does not need a browser.
func TestLoopbackCarriesAudioToTheFakePeerAndBack(t *testing.T) {
	rec := newRecorder()
	loop, err := NewLoopback(LoopbackConfig{
		LoopbackIP: "127.0.0.1",
		Peer: FakePeerConfig{
			ToneHz:      1000,
			ToneOnMS:    40,
			ToneOffMS:   40,
			EchoDelayMS: 60,
		},
		Logf: t.Logf,
	})
	if err != nil {
		t.Fatalf("new loopback: %v", err)
	}
	defer loop.Close()
	loop.SetBrowser(rec)

	const frames = 50
	payload := make([]byte, PCMUFrameSamples)
	for i := range payload {
		payload[i] = ULawEncode(int16(12000))
	}
	go func() {
		pkt := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: PCMUPayloadType, SSRC: 0x11223344}}
		for i := 0; i < frames; i++ {
			pkt.SequenceNumber = uint16(i)
			pkt.Timestamp = uint32(i * PCMUFrameSamples)
			pkt.Payload = payload
			if err := loop.WriteRTP(pkt); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	deadline := time.After(10 * time.Second)
	got := 0
	for got < 20 {
		select {
		case <-rec.ch:
			got++
		case <-deadline:
			t.Fatalf("only %d packets came back from the relay; stats=%+v", got, loop.Stats())
		}
	}

	stats := loop.Stats()
	if stats.TransformsInstalled {
		t.Fatal("relay transforms are installed")
	}
	if stats.Relay.ClientToIMSRTPPackets == 0 {
		t.Fatalf("relay forwarded nothing toward the IMS leg: %+v", stats)
	}
	if stats.Relay.IMSToClientRTPPackets == 0 {
		t.Fatalf("relay forwarded nothing back toward the client leg: %+v", stats)
	}
	if stats.FakeIMSPeer.ReceivedRTP == 0 || stats.FakeIMSPeer.SentRTP == 0 {
		t.Fatalf("the stand-in IMS peer is not talking: %+v", stats.FakeIMSPeer)
	}
	if stats.FakeIMSPeer.ParseErrors != 0 || stats.FakeIMSPeer.SendErrors != 0 {
		t.Fatalf("stand-in peer reported errors: %+v", stats.FakeIMSPeer)
	}
	t.Logf("loopback stats: %+v", stats)
}

// TestFakePeerEchoesWhatItHears is the audible-both-ways property stated as an
// assertion: feed it silence-free audio and the same audio has to come back,
// after the configured delay, loud enough to hear.
func TestFakePeerEchoesWhatItHears(t *testing.T) {
	rec := newRecorder()
	loop, err := NewLoopback(LoopbackConfig{
		LoopbackIP: "127.0.0.1",
		Peer: FakePeerConfig{
			ToneLevel:   0.0001, // keep the tone out of the measurement
			ToneOnMS:    1,
			ToneOffMS:   10000,
			EchoDelayMS: 60,
			EchoLevel:   1.0,
		},
		Logf: t.Logf,
	})
	if err != nil {
		t.Fatalf("new loopback: %v", err)
	}
	defer loop.Close()
	loop.SetBrowser(rec)

	const amplitude = 16000
	payload := make([]byte, PCMUFrameSamples)
	for i := range payload {
		payload[i] = ULawEncode(amplitude)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		pkt := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: PCMUPayloadType, SSRC: 0x55667788}}
		seq := uint16(0)
		for {
			select {
			case <-stop:
				return
			default:
			}
			pkt.SequenceNumber = seq
			pkt.Timestamp = uint32(seq) * PCMUFrameSamples
			pkt.Payload = payload
			_ = loop.WriteRTP(pkt)
			seq++
			time.Sleep(10 * time.Millisecond)
		}
	}()

	deadline := time.After(10 * time.Second)
	for {
		select {
		case pkt := <-rec.ch:
			if peak(pkt.Payload) > amplitude/2 {
				return // the echo made the full round trip at usable level
			}
		case <-deadline:
			t.Fatalf("never heard the echo come back; stats=%+v", loop.Stats())
		}
	}
}

func peak(payload []byte) int16 {
	var max int16
	for _, b := range payload {
		v := ULawDecode(b)
		if v < 0 {
			v = -v
		}
		if v > max {
			max = v
		}
	}
	return max
}

func TestULawRoundTripIsStable(t *testing.T) {
	// G.711 mu-law has two encodings of zero: 0xFF is +0 and 0x7F is -0. Every
	// other code has to survive a decode/encode round trip byte for byte.
	if ULawDecode(0x7F) != 0 || ULawDecode(0xFF) != 0 {
		t.Fatalf("both zero codes must decode to 0, got %d and %d", ULawDecode(0x7F), ULawDecode(0xFF))
	}
	for i := 0; i < 256; i++ {
		u := byte(i)
		if u == 0x7F {
			continue
		}
		if got := ULawEncode(ULawDecode(u)); got != u {
			t.Fatalf("mu-law round trip changed 0x%02x into 0x%02x", u, got)
		}
	}
	for _, sample := range []int16{0, 1, -1, 1000, -1000, 16000, -16000, 32767, -32768} {
		decoded := ULawDecode(ULawEncode(sample))
		diff := int(decoded) - int(sample)
		if diff < 0 {
			diff = -diff
		}
		// mu-law is logarithmic: the tolerance has to scale with the sample.
		tolerance := 8 + abs(int(sample))/8
		if diff > tolerance {
			t.Fatalf("mu-law round trip of %d gave %d (off by %d, tolerance %d)", sample, decoded, diff, tolerance)
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func TestEchoLineHoldsAudioForTheConfiguredDelay(t *testing.T) {
	const (
		delay = 160 // 20 ms at 8 kHz
		frame = 80
	)
	line := newEchoLine(delay, 8000)
	out := make([]int16, frame)

	line.write(make([]int16, delay)) // exactly the delay, nothing readable yet
	line.read(out)
	for _, v := range out {
		if v != 0 {
			t.Fatal("the delay line gave audio back before the delay had elapsed")
		}
	}

	marker := make([]int16, frame)
	for i := range marker {
		marker[i] = 4242
	}
	line.write(marker)
	// Once delay more samples have been written the marker is exactly delay
	// samples behind the write head, which is when it must come out.
	line.write(make([]int16, delay))
	line.read(out)
	for i, v := range out {
		if v != 4242 {
			t.Fatalf("expected the delayed marker, sample %d was %d", i, v)
		}
	}
}

func TestEchoLineIsSilentWhenNothingArrived(t *testing.T) {
	line := newEchoLine(800, 8000)
	out := make([]int16, PCMUFrameSamples)
	for i := range out {
		out[i] = 99
	}
	line.read(out)
	for _, v := range out {
		if v != 0 {
			t.Fatalf("expected silence, got %d", v)
		}
	}
}

// TestEchoLineMutesAStalledSender keeps the delay line from turning into a
// buzzer: when the far side stops sending, the last frame must not loop.
func TestEchoLineMutesAStalledSender(t *testing.T) {
	const (
		delay = 160
		frame = 80
	)
	line := newEchoLine(delay, 8000)
	loud := make([]int16, 4*delay)
	for i := range loud {
		loud[i] = 12000
	}
	line.write(loud)

	out := make([]int16, frame)
	line.read(out)
	if out[0] != 12000 {
		t.Fatalf("expected the delayed audio, got %d", out[0])
	}
	for i := 0; i <= maxStaleEchoReads; i++ {
		line.read(out)
	}
	for _, v := range out {
		if v != 0 {
			t.Fatalf("a stalled sender must decay to silence, got %d", v)
		}
	}
}
