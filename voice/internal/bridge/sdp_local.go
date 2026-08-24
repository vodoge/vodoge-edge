package bridge

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/pion/interceptor"
	"github.com/pion/webrtc/v4"
)

// LocalMediaPolicy decides what the edge is willing to put in front of a
// browser.
//
// The edge VM's address (192.168.78.10) is only reachable from the VMware host
// and from the other guests on vmnet8. Handing that host candidate to an
// arbitrary browser would be leaking internal topology for nothing, since no
// arbitrary browser can use it anyway. So the policy is explicit rather than
// implied: name the interface, name the address, and refuse to emit anything
// else -- no srflx, no relay, no second interface, and in particular nothing
// from the modem-facing or loopback interfaces.
//
// The signalling endpoint enforces the other half of the same rule (see
// internal/devsignal): only a caller on the local operator network gets an
// answer at all.
type LocalMediaPolicy struct {
	// Interfaces is the allow list of interface names candidates may come from.
	// Empty means "any", which is only appropriate in tests.
	Interfaces []string
	// AdvertiseIPs is the allow list of addresses that may appear as a
	// candidate. Empty means "any address on an allowed interface".
	AdvertiseIPs []string
	// PortMin and PortMax bound the media port range. Zero means the kernel
	// picks, which is fine on the edge VM but makes firewalling harder.
	PortMin uint16
	PortMax uint16
	// AllowLoopbackCandidates is only for in-process tests, where both peers
	// live on 127.0.0.1.
	AllowLoopbackCandidates bool
}

// Validate rejects a policy that would gather more than intended.
func (p LocalMediaPolicy) Validate() error {
	if p.PortMin != 0 || p.PortMax != 0 {
		if p.PortMin == 0 || p.PortMax == 0 || p.PortMin > p.PortMax {
			return fmt.Errorf("bridge: bad media port range %d-%d", p.PortMin, p.PortMax)
		}
	}
	for _, raw := range p.AdvertiseIPs {
		if net.ParseIP(raw) == nil {
			return fmt.Errorf("bridge: %q is not an IP address", raw)
		}
	}
	if len(p.Interfaces) == 0 && len(p.AdvertiseIPs) == 0 && !p.AllowLoopbackCandidates {
		return errors.New("bridge: refusing an unrestricted candidate policy: name the interface or the address")
	}
	return nil
}

// AllowsInterface reports whether candidates may be gathered from iface.
func (p LocalMediaPolicy) AllowsInterface(name string) bool {
	if len(p.Interfaces) == 0 {
		return true
	}
	for _, want := range p.Interfaces {
		if strings.EqualFold(strings.TrimSpace(want), name) {
			return true
		}
	}
	return false
}

// AllowsIP reports whether ip may appear in an answer.
func (p LocalMediaPolicy) AllowsIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() && !p.AllowLoopbackCandidates {
		return false
	}
	if len(p.AdvertiseIPs) == 0 {
		return true
	}
	for _, raw := range p.AdvertiseIPs {
		if allowed := net.ParseIP(strings.TrimSpace(raw)); allowed != nil && allowed.Equal(ip) {
			return true
		}
	}
	return false
}

// SettingEngine turns the policy into pion's gathering configuration.
func (p LocalMediaPolicy) SettingEngine() (webrtc.SettingEngine, error) {
	var se webrtc.SettingEngine
	if err := p.Validate(); err != nil {
		return se, err
	}
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	se.SetInterfaceFilter(p.AllowsInterface)
	se.SetIPFilter(p.AllowsIP)
	se.SetIncludeLoopbackCandidate(p.AllowLoopbackCandidates)
	if p.PortMin != 0 && p.PortMax != 0 {
		if err := se.SetEphemeralUDPPortRange(p.PortMin, p.PortMax); err != nil {
			return se, fmt.Errorf("bridge: media port range: %w", err)
		}
	}
	return se, nil
}

// NewAPI builds the pion API for this policy: PCMU only, host candidates only.
//
// Registering exactly one codec is what makes the phase-1 "no transcoding"
// claim true by construction instead of by hope. If a browser ever fails to
// offer PCMU the answer fails loudly here rather than quietly negotiating Opus
// and pushing 48 kHz frames at a relay that expects 8 kHz G.711.
func (p LocalMediaPolicy) NewAPI() (*webrtc.API, error) {
	se, err := p.SettingEngine()
	if err != nil {
		return nil, err
	}
	m := &webrtc.MediaEngine{}
	if err := m.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypePCMU, ClockRate: PCMUClockRate},
		PayloadType:        webrtc.PayloadType(PCMUPayloadType),
	}, webrtc.RTPCodecTypeAudio); err != nil {
		return nil, fmt.Errorf("bridge: register PCMU: %w", err)
	}
	ir := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(m, ir); err != nil {
		return nil, fmt.Errorf("bridge: register interceptors: %w", err)
	}
	return webrtc.NewAPI(
		webrtc.WithMediaEngine(m),
		webrtc.WithInterceptorRegistry(ir),
		webrtc.WithSettingEngine(se),
	), nil
}

// AuditAnswer is the last gate before an SDP answer reaches a browser. Filters
// are configuration and configuration drifts; this reads the bytes that are
// actually about to go out.
func (p LocalMediaPolicy) AuditAnswer(sdp string) error {
	if strings.TrimSpace(sdp) == "" {
		return errors.New("bridge: empty answer")
	}
	candidates := 0
	scanner := bufio.NewScanner(strings.NewReader(sdp))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "a=candidate:") {
			continue
		}
		candidates++
		if err := p.auditCandidate(strings.TrimPrefix(line, "a=candidate:")); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("bridge: read answer: %w", err)
	}
	if candidates == 0 {
		return errors.New("bridge: answer carries no ICE candidate: the media policy gathered nothing")
	}
	return nil
}

func (p LocalMediaPolicy) auditCandidate(value string) error {
	fields := strings.Fields(value)
	if len(fields) < 8 {
		return fmt.Errorf("bridge: unparsable ICE candidate %q", value)
	}
	address := fields[4]
	typ := ""
	for i := 5; i+1 < len(fields); i++ {
		if fields[i] == "typ" {
			typ = fields[i+1]
			break
		}
	}
	if typ != "host" {
		return fmt.Errorf("bridge: refusing to advertise a %q candidate: phase a is host-only", typ)
	}
	ip := net.ParseIP(address)
	if ip == nil {
		// An mDNS (.local) candidate would land here. pion is configured not to
		// gather them; if one shows up the policy has been bypassed.
		return fmt.Errorf("bridge: refusing to advertise non-literal candidate address %q", address)
	}
	if !p.AllowsIP(ip) {
		return fmt.Errorf("bridge: refusing to advertise candidate address %s: not in the local media allow list", address)
	}
	return nil
}
