package bridge

import (
	"net"
	"strings"
	"testing"

	"github.com/pion/webrtc/v4"
)

func TestPolicyRefusesToGatherEverything(t *testing.T) {
	if err := (LocalMediaPolicy{}).Validate(); err == nil {
		t.Fatal("an unrestricted candidate policy must be refused: the edge VM also faces the modems and the upstream NAT")
	}
	if err := (LocalMediaPolicy{AdvertiseIPs: []string{"not-an-ip"}}).Validate(); err == nil {
		t.Fatal("a malformed advertise address must be refused")
	}
	if err := (LocalMediaPolicy{Interfaces: []string{"ens160"}, PortMin: 40000}).Validate(); err == nil {
		t.Fatal("a half-specified port range must be refused")
	}
	edge := LocalMediaPolicy{Interfaces: []string{"ens160"}, AdvertiseIPs: []string{"192.168.78.10"}, PortMin: 40000, PortMax: 40100}
	if err := edge.Validate(); err != nil {
		t.Fatalf("the edge policy must be valid: %v", err)
	}
}

func TestPolicyOnlyAllowsTheNamedInterfaceAndAddress(t *testing.T) {
	p := LocalMediaPolicy{Interfaces: []string{"ens160"}, AdvertiseIPs: []string{"192.168.78.10"}}
	if !p.AllowsInterface("ens160") {
		t.Fatal("ens160 must be allowed")
	}
	for _, name := range []string{"lo", "docker0", "wwan0", "tun0"} {
		if p.AllowsInterface(name) {
			t.Fatalf("%s must not be gathered from", name)
		}
	}
	if !p.AllowsIP(net.ParseIP("192.168.78.10")) {
		t.Fatal("the advertised address must be allowed")
	}
	for _, raw := range []string{"127.0.0.1", "192.168.6.83", "10.0.0.5", "198.18.0.7"} {
		if p.AllowsIP(net.ParseIP(raw)) {
			t.Fatalf("%s must not be advertised to a browser", raw)
		}
	}
}

func candidateSDP(lines ...string) string {
	head := []string{
		"v=0",
		"o=- 0 0 IN IP4 127.0.0.1",
		"s=-",
		"t=0 0",
		"m=audio 9 UDP/TLS/RTP/SAVPF 0",
		"c=IN IP4 0.0.0.0",
	}
	return strings.Join(append(head, lines...), "\r\n") + "\r\n"
}

func TestAuditAnswerAcceptsOnlyAllowedHostCandidates(t *testing.T) {
	p := LocalMediaPolicy{Interfaces: []string{"ens160"}, AdvertiseIPs: []string{"192.168.78.10"}}
	ok := candidateSDP("a=candidate:1 1 udp 2130706431 192.168.78.10 40002 typ host")
	if err := p.AuditAnswer(ok); err != nil {
		t.Fatalf("the allowed host candidate was refused: %v", err)
	}
}

func TestAuditAnswerRefusesWhatMustNeverReachABrowser(t *testing.T) {
	p := LocalMediaPolicy{Interfaces: []string{"ens160"}, AdvertiseIPs: []string{"192.168.78.10"}}
	cases := map[string]string{
		"a second interface":  candidateSDP("a=candidate:1 1 udp 2130706431 192.168.6.83 40002 typ host"),
		"a server-reflexive":  candidateSDP("a=candidate:2 1 udp 1694498815 43.108.53.126 40002 typ srflx raddr 192.168.78.10 rport 40002"),
		"a relayed candidate": candidateSDP("a=candidate:3 1 udp 16777215 43.108.53.126 3478 typ relay raddr 0.0.0.0 rport 0"),
		"an mDNS candidate":   candidateSDP("a=candidate:4 1 udp 2130706431 1f2e3d4c-0000-0000-0000-000000000000.local 40002 typ host"),
		"a loopback leak":     candidateSDP("a=candidate:5 1 udp 2130706431 127.0.0.1 40002 typ host"),
		"no candidate at all": candidateSDP(),
	}
	for name, sdp := range cases {
		if err := p.AuditAnswer(sdp); err == nil {
			t.Fatalf("%s must not be handed to a browser", name)
		}
	}
	if err := p.AuditAnswer(""); err == nil {
		t.Fatal("an empty answer must be refused")
	}
}

func TestNewAPIRegistersPCMUOnly(t *testing.T) {
	p := LocalMediaPolicy{AllowLoopbackCandidates: true}
	api, err := p.NewAPI()
	if err != nil {
		t.Fatalf("new api: %v", err)
	}
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("new peer connection: %v", err)
	}
	defer pc.Close()
	if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio); err != nil {
		t.Fatalf("add transceiver: %v", err)
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}
	lower := strings.ToLower(offer.SDP)
	if !strings.Contains(lower, "pcmu/8000") {
		t.Fatalf("PCMU missing from the offer:\n%s", offer.SDP)
	}
	// Anything else would mean the browser could pick a codec the relay's
	// 8 kHz G.711 assumption cannot carry without a transcoder.
	for _, banned := range []string{"opus/48000", "pcma/8000", "g722/8000"} {
		if strings.Contains(lower, banned) {
			t.Fatalf("%s must not be offered in phase 1:\n%s", banned, offer.SDP)
		}
	}
}
