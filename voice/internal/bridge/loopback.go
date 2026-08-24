package bridge

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boa-z/vowifi-go/runtimehost/voicehost"
	"github.com/pion/rtp"
)

// ---------------------------------------------------------------------------
// The relay leg
// ---------------------------------------------------------------------------

// RelayPorts pins the four UDP ports of the relay plus the two the bridge binds
// on its side of the loopback. Zero means "let the kernel pick", which is what
// phase a uses everywhere: nothing outside this host can reach these sockets,
// so there is no reason to fight over fixed numbers.
type RelayPorts struct {
	ClientRTP  int
	ClientRTCP int
	IMSRTP     int
	IMSRTCP    int
}

// NewRelayConfig builds the voicehost relay configuration for one loopback
// call.
//
// Transforms is left zero deliberately and must stay that way. rtp_relay.go
// gates its RTP quality statistics, its RTCP feedback inspection and its
// two-way DTMF handling on "transform == nil", so attaching a transform here
// would silently disable all three. Payload conversion belongs on the WebRTC
// side of this loopback (see PayloadTransform in peer.go).
func NewRelayConfig(loopbackIP string, ports RelayPorts) voicehost.RTPRelayConfig {
	return voicehost.RTPRelayConfig{
		ClientListenIP:     loopbackIP,
		ClientAdvertiseIP:  loopbackIP,
		ClientPort:         ports.ClientRTP,
		ClientRTCPPort:     ports.ClientRTCP,
		ClientRTPClockRate: PCMUClockRate,
		IMSListenIP:        loopbackIP,
		IMSAdvertiseIP:     loopbackIP,
		IMSPort:            ports.IMSRTP,
		IMSRTCPPort:        ports.IMSRTCP,
		IMSRTPClockRate:    PCMUClockRate,
		BufferSize:         2048,
	}
}

// LoopbackConfig configures the plaintext RTP loopback between the WebRTC
// bridge and the vowifi-go relay.
type LoopbackConfig struct {
	// Context bounds the relay's forwarding goroutines.
	Context context.Context
	// LoopbackIP must be a loopback address: the RTP on this hop is in the
	// clear, and it is only in the clear because it never leaves the host.
	LoopbackIP string
	// Ports pins the relay's four UDP ports; zero means ephemeral.
	Ports RelayPorts
	// BridgeRTPPort / BridgeRTCPPort pin the bridge's own two sockets, the ones
	// the relay believes are "the client". Zero means ephemeral.
	BridgeRTPPort  int
	BridgeRTCPPort int
	// Peer configures the stand-in for the IMS far end.
	Peer FakePeerConfig
	Logf func(string, ...any)
}

func (c *LoopbackConfig) applyDefaults() {
	if c.Context == nil {
		c.Context = context.Background()
	}
	if c.LoopbackIP == "" {
		c.LoopbackIP = "127.0.0.1"
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	if c.Peer.ListenIP == "" {
		c.Peer.ListenIP = c.LoopbackIP
	}
	if c.Peer.Logf == nil {
		c.Peer.Logf = c.Logf
	}
}

// LoopbackStats is the middle of the evidence chain: how much the bridge handed
// the relay, how much the relay actually forwarded each way, and what the
// stand-in IMS peer saw.
type LoopbackStats struct {
	BridgeEndpoint      string        `json:"bridge_endpoint"`
	RelayClientEndpoint string        `json:"relay_client_endpoint"`
	RelayIMSEndpoint    string        `json:"relay_ims_endpoint"`
	BridgeToRelayRTP    uint64        `json:"bridge_to_relay_rtp_packets"`
	RelayToBridgeRTP    uint64        `json:"relay_to_bridge_rtp_packets"`
	Dropped             uint64        `json:"dropped_packets"`
	Relay               RelayStats    `json:"relay"`
	FakeIMSPeer         FakePeerStats `json:"fake_ims_peer"`
	TransformsInstalled bool          `json:"relay_transforms_installed"`
}

// RelayStats is the subset of voicehost.RTPRelayStats that phase a reports.
type RelayStats struct {
	ClientToIMSRTPPackets uint64 `json:"client_to_ims_rtp_packets"`
	IMSToClientRTPPackets uint64 `json:"ims_to_client_rtp_packets"`
	ClientToIMSRTPBytes   uint64 `json:"client_to_ims_rtp_bytes"`
	IMSToClientRTPBytes   uint64 `json:"ims_to_client_rtp_bytes"`
	ClientToIMSRTPDrops   uint64 `json:"client_to_ims_rtp_drops"`
	IMSToClientRTPDrops   uint64 `json:"ims_to_client_rtp_drops"`
}

// Loopback owns the relay session, the bridge's side of the relay's client leg,
// and the stand-in IMS peer.
type Loopback struct {
	cfg   LoopbackConfig
	relay *voicehost.RTPRelaySession
	peer  *FakeIMSPeer

	rtpConn  *net.UDPConn
	rtcpConn *net.UDPConn

	relayClientRTP  *net.UDPAddr
	relayClientRTCP *net.UDPAddr

	browser atomic.Pointer[RTPWriter]

	toRelay   atomic.Uint64
	fromRelay atomic.Uint64
	dropped   atomic.Uint64

	transformsInstalled bool

	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewLoopback stands up, in order: the fake IMS peer, the relay pointed at it,
// the bridge's own sockets, and finally the relay's client target. The order
// matters -- the relay drops anything it receives before it has a target for
// that direction (rtp_relay.go forwardLoop), so both targets are installed
// before any media can arrive.
func NewLoopback(cfg LoopbackConfig) (*Loopback, error) {
	cfg.applyDefaults()
	ip := net.ParseIP(cfg.LoopbackIP)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("bridge: loopback IP %q is not a loopback address: the relay hop carries plaintext RTP", cfg.LoopbackIP)
	}

	peer, err := NewFakeIMSPeer(cfg.Peer)
	if err != nil {
		return nil, err
	}

	relayCfg := NewRelayConfig(cfg.LoopbackIP, cfg.Ports)
	ctx, cancel := context.WithCancel(cfg.Context)
	relay, err := voicehost.NewRTPRelaySessionForIMSRemote(ctx, relayCfg, peer.Endpoint())
	if err != nil {
		cancel()
		_ = peer.Close()
		return nil, fmt.Errorf("bridge: start rtp relay: %w", err)
	}

	l := &Loopback{
		cfg:                 cfg,
		relay:               relay,
		peer:                peer,
		cancel:              cancel,
		transformsInstalled: transformsInstalled(relayCfg.Transforms),
	}

	l.rtpConn, err = listenLoopbackUDP(cfg.LoopbackIP, cfg.BridgeRTPPort)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	l.rtcpConn, err = listenLoopbackUDP(cfg.LoopbackIP, cfg.BridgeRTCPPort)
	if err != nil {
		_ = l.Close()
		return nil, err
	}

	bridgeEndpoint := voicehost.SDPInfo{
		ConnectionIP: cfg.LoopbackIP,
		MediaPort:    udpPort(l.rtpConn),
		RTCPIP:       cfg.LoopbackIP,
		RTCPPort:     udpPort(l.rtcpConn),
		Payloads:     []int{int(PCMUPayloadType)},
		Direction:    "sendrecv",
	}
	if err := relay.SetClientRemote(bridgeEndpoint); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("bridge: point relay client leg at the bridge: %w", err)
	}

	clientEndpoint := relay.ClientEndpoint()
	l.relayClientRTP, err = udpAddr(clientEndpoint.ConnectionIP, clientEndpoint.MediaPort)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	l.relayClientRTCP, err = udpAddr(clientEndpoint.RTCPIP, clientEndpoint.RTCPPort)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	if err := peer.SetTarget(relay.IMSEndpoint()); err != nil {
		_ = l.Close()
		return nil, err
	}

	l.wg.Add(2)
	go l.pumpFromRelay()
	go l.drainRTCP()

	cfg.Logf("loopback ready: bridge %s <-> relay client %s, relay ims %s <-> fake peer %s",
		l.rtpConn.LocalAddr(), l.relayClientRTP, endpointString(relay.IMSEndpoint()), endpointString(peer.Endpoint()))
	return l, nil
}

// WriteRTP sends one packet to the relay's client leg. It satisfies RTPWriter.
func (l *Loopback) WriteRTP(pkt *rtp.Packet) error {
	raw, err := pkt.Marshal()
	if err != nil {
		l.dropped.Add(1)
		return err
	}
	if _, err := l.rtpConn.WriteToUDP(raw, l.relayClientRTP); err != nil {
		l.dropped.Add(1)
		return err
	}
	l.toRelay.Add(1)
	return nil
}

// SetBrowser installs the sink for packets coming back out of the relay.
func (l *Loopback) SetBrowser(w RTPWriter) {
	if w == nil {
		l.browser.Store(nil)
		return
	}
	l.browser.Store(&w)
}

func (l *Loopback) pumpFromRelay() {
	defer l.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, _, err := l.rtpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := &rtp.Packet{}
		if err := pkt.Unmarshal(buf[:n]); err != nil {
			l.dropped.Add(1)
			continue
		}
		l.fromRelay.Add(1)
		sink := l.browser.Load()
		if sink == nil {
			continue
		}
		if err := (*sink).WriteRTP(pkt); err != nil {
			l.dropped.Add(1)
		}
	}
}

// drainRTCP keeps the bridge's RTCP socket readable. Phase a does not translate
// RTCP -- the browser leg's RTCP is terminated by pion and the relay's RTCP
// bookkeeping stays inside the relay -- but the socket has to exist and be
// drained so the relay has a live RTCP target instead of an ICMP-unreachable.
func (l *Loopback) drainRTCP() {
	defer l.wg.Done()
	buf := make([]byte, 2048)
	for {
		if _, _, err := l.rtcpConn.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

// Stats snapshots the relay hop.
func (l *Loopback) Stats() LoopbackStats {
	relayStats := l.relay.Stats()
	out := LoopbackStats{
		BridgeToRelayRTP: l.toRelay.Load(),
		RelayToBridgeRTP: l.fromRelay.Load(),
		Dropped:          l.dropped.Load(),
		Relay: RelayStats{
			ClientToIMSRTPPackets: relayStats.ClientToIMSRTPPackets,
			IMSToClientRTPPackets: relayStats.IMSToClientRTPPackets,
			ClientToIMSRTPBytes:   relayStats.ClientToIMSRTPBytes,
			IMSToClientRTPBytes:   relayStats.IMSToClientRTPBytes,
			ClientToIMSRTPDrops:   relayStats.ClientToIMSRTPDrops,
			IMSToClientRTPDrops:   relayStats.IMSToClientRTPDrops,
		},
		FakeIMSPeer:         l.peer.Stats(),
		TransformsInstalled: l.transformsInstalled,
	}
	if l.rtpConn != nil {
		out.BridgeEndpoint = l.rtpConn.LocalAddr().String()
	}
	if l.relayClientRTP != nil {
		out.RelayClientEndpoint = l.relayClientRTP.String()
	}
	out.RelayIMSEndpoint = endpointString(l.relay.IMSEndpoint())
	return out
}

// FakePeer exposes the stand-in IMS endpoint, mostly so tests can inspect it.
func (l *Loopback) FakePeer() *FakeIMSPeer { return l.peer }

// Close tears the loopback down.
func (l *Loopback) Close() error {
	var err error
	l.closeOnce.Do(func() {
		var errs []error
		if l.relay != nil {
			errs = append(errs, l.relay.Close())
		}
		if l.rtpConn != nil {
			errs = append(errs, l.rtpConn.Close())
		}
		if l.rtcpConn != nil {
			errs = append(errs, l.rtcpConn.Close())
		}
		if l.peer != nil {
			errs = append(errs, l.peer.Close())
		}
		if l.cancel != nil {
			l.cancel()
		}
		l.wg.Wait()
		err = errors.Join(errs...)
	})
	return err
}

// ---------------------------------------------------------------------------
// The stand-in IMS peer
// ---------------------------------------------------------------------------

// FakePeerConfig configures the thing on the far side of the relay's IMS leg.
//
// It is not a soft phone and does not speak SIP: phase a is about the media
// path only. It does exactly enough to make the call audible in both
// directions at once -- it plays a tone the operator can hear without saying
// anything, and it echoes back what it receives after a delay so the operator
// can hear their own voice make the round trip.
type FakePeerConfig struct {
	ListenIP string
	RTPPort  int
	RTCPPort int

	// ToneHz, ToneOnMS and ToneOffMS describe the beep the peer plays on its
	// own. A gated tone is used rather than a continuous one so a stall is
	// obvious by ear: a continuous tone sounds the same whether it is live or
	// stuck in a jitter buffer.
	ToneHz    float64
	ToneOnMS  int
	ToneOffMS int
	// ToneLevel and EchoLevel are linear gains in [0,1].
	ToneLevel float64
	EchoLevel float64
	// EchoDelayMS is how long the peer holds received audio before sending it
	// back. Long enough to be unmistakably an echo, short enough to stay usable.
	EchoDelayMS int

	FrameMS     int
	PayloadType uint8
	SSRC        uint32
	Logf        func(string, ...any)
}

func (c *FakePeerConfig) applyDefaults() {
	if c.ListenIP == "" {
		c.ListenIP = "127.0.0.1"
	}
	if c.ToneHz <= 0 {
		c.ToneHz = 440
	}
	if c.ToneOnMS <= 0 {
		c.ToneOnMS = 300
	}
	if c.ToneOffMS <= 0 {
		c.ToneOffMS = 1200
	}
	if c.ToneLevel <= 0 {
		c.ToneLevel = 0.20
	}
	if c.EchoLevel <= 0 {
		c.EchoLevel = 0.85
	}
	if c.EchoDelayMS <= 0 {
		c.EchoDelayMS = 700
	}
	if c.FrameMS <= 0 {
		c.FrameMS = 20
	}
	if c.SSRC == 0 {
		c.SSRC = rand.Uint32()
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// FakePeerStats is the far end's half of the evidence.
type FakePeerStats struct {
	Endpoint    string `json:"endpoint"`
	Target      string `json:"target"`
	ReceivedRTP uint64 `json:"received_rtp_packets"`
	SentRTP     uint64 `json:"sent_rtp_packets"`
	ParseErrors uint64 `json:"parse_errors"`
	SendErrors  uint64 `json:"send_errors"`
}

// FakeIMSPeer plays tone plus delayed echo over plaintext RTP.
type FakeIMSPeer struct {
	cfg      FakePeerConfig
	rtpConn  *net.UDPConn
	rtcpConn *net.UDPConn

	targetMu   sync.RWMutex
	target     *net.UDPAddr
	targetRTCP *net.UDPAddr

	echo *echoLine

	received    atomic.Uint64
	sent        atomic.Uint64
	parseErrors atomic.Uint64
	sendErrors  atomic.Uint64

	seq  uint16
	ts   uint32
	tone float64

	stop      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewFakeIMSPeer binds the peer's sockets and starts its send/receive loops.
func NewFakeIMSPeer(cfg FakePeerConfig) (*FakeIMSPeer, error) {
	cfg.applyDefaults()
	rtpConn, err := listenLoopbackUDP(cfg.ListenIP, cfg.RTPPort)
	if err != nil {
		return nil, fmt.Errorf("bridge: fake ims peer rtp socket: %w", err)
	}
	rtcpConn, err := listenLoopbackUDP(cfg.ListenIP, cfg.RTCPPort)
	if err != nil {
		_ = rtpConn.Close()
		return nil, fmt.Errorf("bridge: fake ims peer rtcp socket: %w", err)
	}
	frame := cfg.FrameMS * PCMUClockRate / 1000
	if frame <= 0 {
		frame = PCMUFrameSamples
	}
	p := &FakeIMSPeer{
		cfg:      cfg,
		rtpConn:  rtpConn,
		rtcpConn: rtcpConn,
		echo:     newEchoLine(cfg.EchoDelayMS*PCMUClockRate/1000, 4*PCMUClockRate),
		seq:      uint16(rand.Uint32()),
		ts:       rand.Uint32(),
		stop:     make(chan struct{}),
	}
	p.wg.Add(3)
	go p.recvLoop()
	go p.drainRTCP()
	go p.sendLoop(frame)
	return p, nil
}

// Endpoint is what the relay's IMS leg should be pointed at.
func (p *FakeIMSPeer) Endpoint() voicehost.SDPInfo {
	return voicehost.SDPInfo{
		ConnectionIP: p.cfg.ListenIP,
		MediaPort:    udpPort(p.rtpConn),
		RTCPIP:       p.cfg.ListenIP,
		RTCPPort:     udpPort(p.rtcpConn),
		Payloads:     []int{int(p.cfg.PayloadType)},
		Direction:    "sendrecv",
	}
}

// SetTarget points the peer at the relay's IMS leg. Until it is called the peer
// still learns a target from the source address of the first packet it
// receives, which keeps it usable in front of anything that speaks first.
func (p *FakeIMSPeer) SetTarget(info voicehost.SDPInfo) error {
	addr, err := udpAddr(info.ConnectionIP, info.MediaPort)
	if err != nil {
		return err
	}
	rtcpPort := info.RTCPPort
	if rtcpPort == 0 {
		rtcpPort = info.MediaPort + 1
	}
	rtcpIP := info.RTCPIP
	if rtcpIP == "" {
		rtcpIP = info.ConnectionIP
	}
	rtcpAddr, err := udpAddr(rtcpIP, rtcpPort)
	if err != nil {
		return err
	}
	p.targetMu.Lock()
	p.target = addr
	p.targetRTCP = rtcpAddr
	p.targetMu.Unlock()
	return nil
}

func (p *FakeIMSPeer) currentTarget() *net.UDPAddr {
	p.targetMu.RLock()
	defer p.targetMu.RUnlock()
	return p.target
}

func (p *FakeIMSPeer) recvLoop() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	samples := make([]int16, 0, 512)
	for {
		n, src, err := p.rtpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := &rtp.Packet{}
		if err := pkt.Unmarshal(buf[:n]); err != nil {
			p.parseErrors.Add(1)
			continue
		}
		p.received.Add(1)
		p.targetMu.Lock()
		if p.target == nil {
			p.target = src
		}
		p.targetMu.Unlock()
		samples = samples[:0]
		for _, b := range pkt.Payload {
			samples = append(samples, ULawDecode(b))
		}
		p.echo.write(samples)
	}
}

func (p *FakeIMSPeer) drainRTCP() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		if _, _, err := p.rtcpConn.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

func (p *FakeIMSPeer) sendLoop(frame int) {
	defer p.wg.Done()
	ticker := time.NewTicker(time.Duration(p.cfg.FrameMS) * time.Millisecond)
	defer ticker.Stop()
	echo := make([]int16, frame)
	payload := make([]byte, frame)
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
		}
		target := p.currentTarget()
		if target == nil {
			// Still advance the clock so the stream stays continuous once a
			// target appears.
			p.advance(frame)
			continue
		}
		p.echo.read(echo)
		p.mix(echo, payload)
		pkt := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				PayloadType:    p.cfg.PayloadType,
				SequenceNumber: p.seq,
				Timestamp:      p.ts,
				SSRC:           p.cfg.SSRC,
			},
			Payload: payload,
		}
		raw, err := pkt.Marshal()
		if err != nil {
			p.sendErrors.Add(1)
			p.advance(frame)
			continue
		}
		if _, err := p.rtpConn.WriteToUDP(raw, target); err != nil {
			p.sendErrors.Add(1)
			p.advance(frame)
			continue
		}
		p.sent.Add(1)
		p.advance(frame)
	}
}

func (p *FakeIMSPeer) advance(frame int) {
	p.seq++
	p.ts += uint32(frame)
}

// mix writes one frame of tone-plus-echo into dst as mu-law.
func (p *FakeIMSPeer) mix(echo []int16, dst []byte) {
	period := float64(p.cfg.ToneOnMS+p.cfg.ToneOffMS) / 1000
	onFor := float64(p.cfg.ToneOnMS) / 1000
	step := 1.0 / float64(PCMUClockRate)
	for i := range dst {
		var sample float64
		if math.Mod(p.tone, period) < onFor {
			sample = math.Sin(2*math.Pi*p.cfg.ToneHz*p.tone) * p.cfg.ToneLevel * 32767
		}
		p.tone += step
		if i < len(echo) {
			sample += float64(echo[i]) * p.cfg.EchoLevel
		}
		dst[i] = ULawEncode(clampToInt16(sample))
	}
}

// Stats snapshots the far end.
func (p *FakeIMSPeer) Stats() FakePeerStats {
	out := FakePeerStats{
		ReceivedRTP: p.received.Load(),
		SentRTP:     p.sent.Load(),
		ParseErrors: p.parseErrors.Load(),
		SendErrors:  p.sendErrors.Load(),
	}
	if p.rtpConn != nil {
		out.Endpoint = p.rtpConn.LocalAddr().String()
	}
	if target := p.currentTarget(); target != nil {
		out.Target = target.String()
	}
	return out
}

// Close stops the peer.
func (p *FakeIMSPeer) Close() error {
	var err error
	p.closeOnce.Do(func() {
		close(p.stop)
		var errs []error
		if p.rtpConn != nil {
			errs = append(errs, p.rtpConn.Close())
		}
		if p.rtcpConn != nil {
			errs = append(errs, p.rtcpConn.Close())
		}
		p.wg.Wait()
		err = errors.Join(errs...)
	})
	return err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// echoLine is a delay line. The writer is the RTP receive loop, the reader is
// the 20 ms send tick, and the two run on independent clocks.
//
// Each read returns the window that ends exactly delay samples behind the write
// head rather than advancing a cursor of its own. That keeps the echo delay
// constant no matter how the two clocks drift, which is what matters for a
// demo: the operator has to be able to say "I hear myself about 0.7 s later"
// and have that stay true. A drifting cursor would instead accumulate lag until
// the echo turned into an unbounded delay.
//
// staleReads mutes the line when nothing new has arrived, so a stalled sender
// produces silence instead of the last frame looping forever.
type echoLine struct {
	mu         sync.Mutex
	buf        []int16
	delay      int64
	w          int64
	lastW      int64
	staleReads int
}

func newEchoLine(delaySamples, capacity int) *echoLine {
	if capacity <= 0 {
		capacity = 4 * PCMUClockRate
	}
	if delaySamples < 0 {
		delaySamples = 0
	}
	if delaySamples >= capacity {
		delaySamples = capacity - 1
	}
	return &echoLine{buf: make([]int16, capacity), delay: int64(delaySamples)}
}

func (e *echoLine) write(samples []int16) {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := int64(len(e.buf))
	for _, s := range samples {
		e.buf[int(e.w%n)] = s
		e.w++
	}
}

// maxStaleEchoReads is how many send ticks may pass with no new input before
// the delay line mutes. Two ticks of slack absorbs ordinary jitter; more than
// that means the far side has actually stopped talking.
const maxStaleEchoReads = 2

func (e *echoLine) read(dst []int16) {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := int64(len(e.buf))
	need := int64(len(dst))
	start := e.w - e.delay - need
	if e.w == e.lastW {
		e.staleReads++
	} else {
		e.staleReads = 0
		e.lastW = e.w
	}
	if start < 0 || need > n || e.delay+need > n || e.staleReads > maxStaleEchoReads {
		for i := range dst {
			dst[i] = 0
		}
		return
	}
	for i := range dst {
		dst[i] = e.buf[int((start+int64(i))%n)]
	}
}

func clampToInt16(v float64) int16 {
	if v > 32767 {
		return 32767
	}
	if v < -32768 {
		return -32768
	}
	return int16(v)
}

const (
	ulawBias = 0x84
	ulawClip = 32635
)

func ulawSegment(v int32) int32 {
	switch {
	case v < 2:
		return 0
	case v < 4:
		return 1
	case v < 8:
		return 2
	case v < 16:
		return 3
	case v < 32:
		return 4
	case v < 64:
		return 5
	case v < 128:
		return 6
	default:
		return 7
	}
}

// ULawEncode converts one linear sample to G.711 mu-law (ITU-T G.711, the
// classic Sun reference implementation).
func ULawEncode(pcm int16) byte {
	sample := int32(pcm)
	var sign int32
	if sample < 0 {
		sample = -sample
		sign = 0x80
	}
	if sample > ulawClip {
		sample = ulawClip
	}
	sample += ulawBias
	exponent := ulawSegment((sample >> 7) & 0xFF)
	mantissa := (sample >> (exponent + 3)) & 0x0F
	return byte(^(sign | (exponent << 4) | mantissa))
}

// ULawDecode converts one G.711 mu-law byte back to a linear sample.
func ULawDecode(u byte) int16 {
	v := int32(^u)
	sign := v & 0x80
	exponent := (v >> 4) & 0x07
	mantissa := v & 0x0F
	sample := ((mantissa << 3) + ulawBias) << uint(exponent)
	sample -= ulawBias
	if sign != 0 {
		sample = -sample
	}
	return int16(sample)
}

func listenLoopbackUDP(host string, port int) (*net.UDPConn, error) {
	addr, err := udpAddr(host, port)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", addr)
}

func udpAddr(host string, port int) (*net.UDPAddr, error) {
	if host == "" {
		return nil, errors.New("bridge: empty UDP host")
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(port)))
}

func udpPort(conn *net.UDPConn) int {
	if conn == nil {
		return 0
	}
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0
	}
	return addr.Port
}

func endpointString(info voicehost.SDPInfo) string {
	return net.JoinHostPort(info.ConnectionIP, fmt.Sprint(info.MediaPort))
}

// transformsInstalled reports whether any relay-side transform is attached. It
// exists so the running process can prove, in its own /stats output, that the
// forbidden path is not in use.
func transformsInstalled(t voicehost.RTPRelayTransforms) bool {
	return t.ClientToIMSRTP != nil || t.IMSToClientRTP != nil ||
		t.ClientToIMSRTCP != nil || t.IMSToClientRTCP != nil ||
		t.GeneratedToIMSRTP != nil || t.GeneratedToClientRTP != nil ||
		t.GeneratedToIMSRTCP != nil || t.GeneratedToClientRTCP != nil
}
