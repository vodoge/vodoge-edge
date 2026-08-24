// Package bridge terminates the browser-facing WebRTC leg of a voice call and
// hands the resulting plaintext RTP to the vowifi-go media relay over a
// loopback socket.
//
// The media path is deliberately shaped as
//
//	SRTP unwrap (pion)  ->  pluggable payload transform  ->  relay client leg
//
// Phase 1 installs the identity transform. Both legs negotiate PCMU (RFC 7874
// guarantees every browser has G.711, and the relay's forwardLoop only moves
// bytes), so nothing is transcoded and the binary still cross-compiles with
// CGO_ENABLED=0. When the IMS leg later needs AMR-WB the cgo codec drops into
// the same slot without reshaping anything around it.
//
// Transcoding must never be installed through voicehost.RTPRelayTransforms.
// rtp_relay.go only runs its RTP quality statistics (:1341), its RTCP feedback
// inspection (:1352) and its two-way DTMF handling (:1355) while the transform
// is nil, and it drops all three silently when one is attached. That is why the
// transform lives on this side of the loopback socket instead.
package bridge

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

const (
	// PCMUPayloadType is the static RTP payload type of G.711 mu-law.
	PCMUPayloadType uint8 = 0
	// PCMUClockRate is the RTP clock of G.711.
	PCMUClockRate = 8000
	// PCMUFrameSamples is one 20 ms G.711 frame.
	PCMUFrameSamples = PCMUClockRate / 50
)

// PayloadTransform converts the RTP payload spoken on one leg of the bridge
// into the payload spoken on the other leg.
//
// Phase 1 only ever uses Identity, but this interface is the seam a cgo
// transcoder plugs into: it reports the payload type and clock rate of its
// output so the caller can rewrite the RTP header, and it may return an empty
// payload when a real codec needs more input before it can emit a frame.
//
// A transform that is not one output packet per input packet must also own its
// sequence numbering; convert below passes the input sequence through, which is
// correct for 1:1 transforms such as Identity and PCMU<->PCMA.
type PayloadTransform interface {
	// Name is used in logs and in the /stats snapshot.
	Name() string
	// PayloadType is the RTP payload type the output carries.
	PayloadType() uint8
	// ClockRate is the RTP clock of the output, used to rescale timestamps.
	ClockRate() int
	// Transform appends the converted payload of one packet to dst.
	Transform(dst, src []byte) ([]byte, error)
}

type identityTransform struct {
	payloadType uint8
	clockRate   int
}

// Identity returns the phase-1 transform: it copies the payload through
// untouched. Both legs of the phase-a loopback negotiate PCMU, so this is not a
// placeholder that must be replaced before the call works -- it is the correct
// transform for a PCMU-to-PCMU bridge.
func Identity(payloadType uint8, clockRate int) PayloadTransform {
	return identityTransform{payloadType: payloadType, clockRate: clockRate}
}

func (t identityTransform) Name() string       { return "identity" }
func (t identityTransform) PayloadType() uint8 { return t.payloadType }
func (t identityTransform) ClockRate() int     { return t.clockRate }

func (t identityTransform) Transform(dst, src []byte) ([]byte, error) {
	return append(dst, src...), nil
}

// convert applies t to one packet and returns the packet to emit on the far
// leg. It returns a nil packet and a nil error when the transform swallowed the
// input because it needs more of it.
func convert(t PayloadTransform, in *rtp.Packet, inClockRate int) (*rtp.Packet, error) {
	if in == nil {
		return nil, nil
	}
	if t == nil {
		return nil, errors.New("bridge: nil payload transform")
	}
	payload, err := t.Transform(nil, in.Payload)
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		return nil, nil
	}
	out := &rtp.Packet{Header: in.Header, Payload: payload}
	out.Header.PayloadType = t.PayloadType()
	out.Header.Timestamp = rescaleTimestamp(in.Timestamp, inClockRate, t.ClockRate())
	return out, nil
}

// rescaleTimestamp maps an RTP timestamp from one clock to another. It is a
// no-op on the phase-1 identity path (both clocks are 8000) and becomes load
// bearing the moment a 16 kHz codec appears on the IMS leg.
func rescaleTimestamp(ts uint32, from, to int) uint32 {
	if from <= 0 || to <= 0 || from == to {
		return ts
	}
	return uint32(uint64(ts) * uint64(to) / uint64(from))
}

// RTPWriter is the far side of the bridge: in production the loopback socket
// that feeds the relay's client leg, in tests a recorder.
type RTPWriter interface {
	WriteRTP(*rtp.Packet) error
}

// PeerConfig configures the browser-facing leg.
type PeerConfig struct {
	// API carries the ICE candidate policy and the PCMU-only media engine; see
	// LocalMediaPolicy.NewAPI.
	API *webrtc.API
	// Relay receives every browser packet after SRTP unwrap and transform.
	Relay RTPWriter
	// ToRelay converts browser payloads into relay payloads, ToBrowser the
	// other way. Both default to Identity(PCMU).
	ToRelay   PayloadTransform
	ToBrowser PayloadTransform
	// RelayClockRate is the RTP clock of the packets arriving from the relay.
	RelayClockRate int
	Logf           func(string, ...any)
}

func (c *PeerConfig) applyDefaults() {
	if c.ToRelay == nil {
		c.ToRelay = Identity(PCMUPayloadType, PCMUClockRate)
	}
	if c.ToBrowser == nil {
		c.ToBrowser = Identity(PCMUPayloadType, PCMUClockRate)
	}
	if c.RelayClockRate <= 0 {
		c.RelayClockRate = PCMUClockRate
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// PeerStats is the browser leg's half of the evidence for "audible both ways".
type PeerStats struct {
	State             string `json:"state"`
	ICEState          string `json:"ice_state"`
	FromBrowserRTP    uint64 `json:"from_browser_rtp_packets"`
	FromBrowserBytes  uint64 `json:"from_browser_rtp_bytes"`
	ToBrowserRTP      uint64 `json:"to_browser_rtp_packets"`
	ToBrowserBytes    uint64 `json:"to_browser_rtp_bytes"`
	Dropped           uint64 `json:"dropped_packets"`
	ToRelayTransform  string `json:"to_relay_transform"`
	ToBrowserTransfrm string `json:"to_browser_transform"`
}

// Peer terminates DTLS-SRTP for one browser.
type Peer struct {
	cfg   PeerConfig
	pc    *webrtc.PeerConnection
	track *webrtc.TrackLocalStaticRTP

	fromBrowser      atomic.Uint64
	fromBrowserBytes atomic.Uint64
	toBrowser        atomic.Uint64
	toBrowserBytes   atomic.Uint64
	dropped          atomic.Uint64

	closeOnce sync.Once
}

// NewPeer builds the browser leg. It touches no network until Answer.
func NewPeer(cfg PeerConfig) (*Peer, error) {
	cfg.applyDefaults()
	if cfg.API == nil {
		return nil, errors.New("bridge: peer needs an API built from a LocalMediaPolicy")
	}
	if cfg.Relay == nil {
		return nil, errors.New("bridge: peer needs a relay writer")
	}
	pc, err := cfg.API.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return nil, fmt.Errorf("bridge: new peer connection: %w", err)
	}
	track, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypePCMU, ClockRate: PCMUClockRate},
		"audio", "vodoge-voice",
	)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("bridge: new local track: %w", err)
	}
	p := &Peer{cfg: cfg, pc: pc, track: track}
	sender, err := pc.AddTrack(track)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("bridge: add track: %w", err)
	}
	// RTCP from the browser has to be drained or the sender's buffer fills up.
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := sender.Read(buf); err != nil {
				return
			}
		}
	}()
	pc.OnTrack(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if remote.Kind() != webrtc.RTPCodecTypeAudio {
			return
		}
		p.cfg.Logf("browser track: %s pt=%d clock=%d", remote.Codec().MimeType, remote.PayloadType(), remote.Codec().ClockRate)
		p.pumpFromBrowser(remote)
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		p.cfg.Logf("peer connection state: %s", s)
	})
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		p.cfg.Logf("ice connection state: %s", s)
	})
	return p, nil
}

// Answer consumes the browser's offer and returns an answer with ICE gathering
// already complete, so the local signalling endpoint stays one request/response
// exchange instead of a trickle channel.
func (p *Peer) Answer(offer string) (string, error) {
	if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer}); err != nil {
		return "", fmt.Errorf("bridge: set remote description: %w", err)
	}
	answer, err := p.pc.CreateAnswer(nil)
	if err != nil {
		return "", fmt.Errorf("bridge: create answer: %w", err)
	}
	gathered := webrtc.GatheringCompletePromise(p.pc)
	if err := p.pc.SetLocalDescription(answer); err != nil {
		return "", fmt.Errorf("bridge: set local description: %w", err)
	}
	<-gathered
	local := p.pc.LocalDescription()
	if local == nil {
		return "", errors.New("bridge: no local description after gathering")
	}
	return local.SDP, nil
}

func (p *Peer) pumpFromBrowser(remote *webrtc.TrackRemote) {
	clockRate := int(remote.Codec().ClockRate)
	if clockRate <= 0 {
		clockRate = PCMUClockRate
	}
	for {
		pkt, _, err := remote.ReadRTP()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				p.cfg.Logf("browser track read stopped: %v", err)
			}
			return
		}
		p.fromBrowser.Add(1)
		p.fromBrowserBytes.Add(uint64(len(pkt.Payload)))
		out, err := convert(p.cfg.ToRelay, pkt, clockRate)
		if err != nil {
			p.dropped.Add(1)
			continue
		}
		if out == nil {
			continue
		}
		if err := p.cfg.Relay.WriteRTP(out); err != nil {
			p.dropped.Add(1)
		}
	}
}

// WriteRTP pushes one packet coming back from the relay into the browser. It
// satisfies RTPWriter so the loopback leg can be pointed straight at it.
func (p *Peer) WriteRTP(pkt *rtp.Packet) error {
	out, err := convert(p.cfg.ToBrowser, pkt, p.cfg.RelayClockRate)
	if err != nil {
		p.dropped.Add(1)
		return err
	}
	if out == nil {
		return nil
	}
	if err := p.track.WriteRTP(out); err != nil {
		p.dropped.Add(1)
		// The browser has not bound the track yet, or it went away. Neither is
		// worth tearing the call down for.
		if errors.Is(err, io.ErrClosedPipe) {
			return nil
		}
		return err
	}
	p.toBrowser.Add(1)
	p.toBrowserBytes.Add(uint64(len(out.Payload)))
	return nil
}

// Stats snapshots the browser leg.
func (p *Peer) Stats() PeerStats {
	return PeerStats{
		State:             p.pc.ConnectionState().String(),
		ICEState:          p.pc.ICEConnectionState().String(),
		FromBrowserRTP:    p.fromBrowser.Load(),
		FromBrowserBytes:  p.fromBrowserBytes.Load(),
		ToBrowserRTP:      p.toBrowser.Load(),
		ToBrowserBytes:    p.toBrowserBytes.Load(),
		Dropped:           p.dropped.Load(),
		ToRelayTransform:  p.cfg.ToRelay.Name(),
		ToBrowserTransfrm: p.cfg.ToBrowser.Name(),
	}
}

// Close releases the peer connection.
func (p *Peer) Close() error {
	var err error
	p.closeOnce.Do(func() { err = p.pc.Close() })
	return err
}

// CallConfig ties the two legs together.
type CallConfig struct {
	Policy   LocalMediaPolicy
	Loopback LoopbackConfig
	Logf     func(string, ...any)
}

// CallStats is the whole-path snapshot: what the browser sent, what crossed the
// relay, and what the stand-in IMS peer saw. All three have to move for the
// call to be audible in both directions.
type CallStats struct {
	Peer     PeerStats     `json:"peer"`
	Loopback LoopbackStats `json:"loopback"`
}

// Call is one browser-to-fake-peer voice path:
//
//	browser --SRTP--> Peer --transform--> Loopback --UDP--> relay client leg
//	relay IMS leg --UDP--> FakeIMSPeer --tone+echo--> back the same way
type Call struct {
	peer     *Peer
	loopback *Loopback
	closed   sync.Once
}

// NewCall builds the loopback plumbing first (so the relay is listening before
// any browser media arrives) and then the browser leg on top of it.
func NewCall(cfg CallConfig) (*Call, error) {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	api, err := cfg.Policy.NewAPI()
	if err != nil {
		return nil, err
	}
	cfg.Loopback.Logf = cfg.Logf
	loop, err := NewLoopback(cfg.Loopback)
	if err != nil {
		return nil, err
	}
	peer, err := NewPeer(PeerConfig{
		API:            api,
		Relay:          loop,
		RelayClockRate: PCMUClockRate,
		Logf:           cfg.Logf,
	})
	if err != nil {
		_ = loop.Close()
		return nil, err
	}
	loop.SetBrowser(peer)
	return &Call{peer: peer, loopback: loop}, nil
}

// Answer produces the SDP answer and audits it against the candidate policy
// before it can reach a browser.
func (c *Call) Answer(policy LocalMediaPolicy, offer string) (string, error) {
	answer, err := c.peer.Answer(offer)
	if err != nil {
		return "", err
	}
	if err := policy.AuditAnswer(answer); err != nil {
		return "", err
	}
	return answer, nil
}

// Stats snapshots every hop of the path.
func (c *Call) Stats() CallStats {
	return CallStats{Peer: c.peer.Stats(), Loopback: c.loopback.Stats()}
}

// Close tears both legs down.
func (c *Call) Close() error {
	var err error
	c.closed.Do(func() {
		err = errors.Join(c.peer.Close(), c.loopback.Close())
	})
	return err
}
