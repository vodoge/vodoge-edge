package bridge

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

func TestIdentityTransformCopiesThePayloadThrough(t *testing.T) {
	tr := Identity(PCMUPayloadType, PCMUClockRate)
	if tr.Name() != "identity" || tr.PayloadType() != PCMUPayloadType || tr.ClockRate() != PCMUClockRate {
		t.Fatalf("unexpected transform shape: %s pt=%d clock=%d", tr.Name(), tr.PayloadType(), tr.ClockRate())
	}
	src := []byte{1, 2, 3, 4}
	out, err := tr.Transform(nil, src)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if string(out) != string(src) {
		t.Fatalf("identity transform changed the payload: %v -> %v", src, out)
	}
	out[0] = 0xFF
	if src[0] != 1 {
		t.Fatal("transform aliased its input; a codec swapped in later would corrupt the source packet")
	}
}

func TestConvertRewritesPayloadTypeAndRescalesTimestamp(t *testing.T) {
	in := &rtp.Packet{
		Header:  rtp.Header{Version: 2, PayloadType: 0, SequenceNumber: 7, Timestamp: 16000, SSRC: 9},
		Payload: []byte{9, 9, 9},
	}
	// Stand in for the future AMR-WB leg: same bytes, different RTP shape.
	out, err := convert(Identity(96, 16000), in, 8000)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if out.PayloadType != 96 {
		t.Fatalf("payload type not rewritten: %d", out.PayloadType)
	}
	if out.Timestamp != 32000 {
		t.Fatalf("timestamp not rescaled 8k->16k: %d", out.Timestamp)
	}
	if out.SequenceNumber != 7 || out.SSRC != 9 {
		t.Fatalf("sequence/ssrc must pass through for a 1:1 transform: %+v", out.Header)
	}
	if in.Timestamp != 16000 {
		t.Fatal("convert mutated its input packet")
	}
}

func TestRescaleTimestampIsANoOpForEqualClocks(t *testing.T) {
	if got := rescaleTimestamp(123456789, 8000, 8000); got != 123456789 {
		t.Fatalf("identity clock rescale changed the timestamp: %d", got)
	}
	if got := rescaleTimestamp(1000, 0, 8000); got != 1000 {
		t.Fatalf("unknown input clock must leave the timestamp alone: %d", got)
	}
}

// TestBrowserToFakePeerIsAudibleBothWays is the phase-a acceptance criterion
// written down as a test. A second pion PeerConnection stands in for the
// browser: it offers PCMU, terminates DTLS-SRTP against the bridge, pushes
// audio in, and has to get audio back.
//
// It asserts the full chain rather than any single hop, because every previous
// version of "the media path works" in this project failed at a hop that was
// individually green.
func TestBrowserToFakePeerIsAudibleBothWays(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a real DTLS handshake over loopback")
	}
	policy := LocalMediaPolicy{AllowLoopbackCandidates: true}

	call, err := NewCall(CallConfig{
		Policy: policy,
		Loopback: LoopbackConfig{
			LoopbackIP: "127.0.0.1",
			Peer: FakePeerConfig{
				ToneHz:      1000,
				ToneOnMS:    60,
				ToneOffMS:   60,
				EchoDelayMS: 60,
			},
		},
		Logf: t.Logf,
	})
	if err != nil {
		t.Fatalf("new call: %v", err)
	}
	defer call.Close()

	api, err := policy.NewAPI()
	if err != nil {
		t.Fatalf("browser api: %v", err)
	}
	browser, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("browser peer connection: %v", err)
	}
	defer browser.Close()

	track, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypePCMU, ClockRate: PCMUClockRate},
		"audio", "browser",
	)
	if err != nil {
		t.Fatalf("browser track: %v", err)
	}
	if _, err := browser.AddTrack(track); err != nil {
		t.Fatalf("browser add track: %v", err)
	}

	var inbound atomic.Uint64
	var loudInbound atomic.Uint64
	browser.OnTrack(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		for {
			pkt, _, err := remote.ReadRTP()
			if err != nil {
				return
			}
			inbound.Add(1)
			if peak(pkt.Payload) > 1000 {
				loudInbound.Add(1)
			}
		}
	})

	connected := make(chan struct{})
	var once atomic.Bool
	browser.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		t.Logf("browser state: %s", s)
		if s == webrtc.PeerConnectionStateConnected && once.CompareAndSwap(false, true) {
			close(connected)
		}
	})

	offer, err := browser.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}
	if err := browser.SetLocalDescription(offer); err != nil {
		t.Fatalf("set local description: %v", err)
	}
	<-webrtc.GatheringCompletePromise(browser)

	answer, err := call.Answer(policy, browser.LocalDescription().SDP)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}
	if err := browser.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
		t.Fatalf("set remote description: %v", err)
	}

	select {
	case <-connected:
	case <-time.After(20 * time.Second):
		t.Fatalf("the browser side never connected; stats=%+v", call.Stats())
	}

	// Speak: 2 seconds of a loud, constant tone at 20 ms per frame.
	payload := make([]byte, PCMUFrameSamples)
	for i := range payload {
		payload[i] = ULawEncode(16000)
	}
	stop := make(chan struct{})
	go func() {
		pkt := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: PCMUPayloadType, SSRC: 0xDEADBEEF}}
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
			_ = track.WriteRTP(pkt)
			seq++
			time.Sleep(20 * time.Millisecond)
		}
	}()

	deadline := time.After(20 * time.Second)
	for {
		s := call.Stats()
		if s.Peer.FromBrowserRTP >= 25 && s.Loopback.Relay.ClientToIMSRTPPackets >= 25 &&
			s.Loopback.FakeIMSPeer.ReceivedRTP >= 25 && s.Loopback.FakeIMSPeer.SentRTP >= 25 &&
			s.Loopback.Relay.IMSToClientRTPPackets >= 25 && s.Peer.ToBrowserRTP >= 25 &&
			loudInbound.Load() >= 10 {
			close(stop)
			t.Logf("phase-a media path: %+v", s)
			t.Logf("browser inbound rtp=%d, of which audible=%d", inbound.Load(), loudInbound.Load())
			if s.Loopback.TransformsInstalled {
				t.Fatal("relay transforms were installed behind our back")
			}
			if s.Peer.ToRelayTransform != "identity" || s.Peer.ToBrowserTransfrm != "identity" {
				t.Fatalf("phase 1 must run the identity transform, got %s/%s",
					s.Peer.ToRelayTransform, s.Peer.ToBrowserTransfrm)
			}
			return
		}
		select {
		case <-deadline:
			close(stop)
			t.Fatalf("media did not make the full round trip: %+v (browser inbound=%d audible=%d)",
				s, inbound.Load(), loudInbound.Load())
		case <-time.After(200 * time.Millisecond):
		}
	}
}
