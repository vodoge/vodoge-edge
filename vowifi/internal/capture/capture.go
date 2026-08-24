// Package capture records and replays the raw UDP datagrams of an IKEv2 / ESP
// session.
//
// Why this exists in T041a rather than "later": the first contact with a real
// ePDG happens once, at 3am, over a Dallas egress, against a GSLB pool that
// hands out a different node every lookup. If that exchange is not reproducible
// offline, byte for byte, then every subsequent debugging round needs live
// hardware and a live carrier. The upstream mirror has internal/tracefixture,
// but it only covers SIP text; the IKE/ESP layer has no replay ability at all.
//
// The recording is a classic pcap file so Wireshark dissects ISAKMP and ESP
// directly, plus a sidecar JSON holding the seed values (initiator SPI, NonceI,
// DH group and DH scalar) without which a replayed request cannot be
// byte-identical - RunIKE_SA_INIT generates those internally, which is one of
// the reasons this repo replaces it.
package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Errors reported by this package.
var (
	ErrMalformedCapture = errors.New("vowifi/capture: malformed capture file")
	ErrReplayExhausted  = errors.New("vowifi/capture: replay ran out of recorded datagrams")
	ErrReplayMismatch   = errors.New("vowifi/capture: replayed request differs from the recording")
	ErrUnsupportedAddr  = errors.New("vowifi/capture: unsupported address family")
)

// pcap constants. LINKTYPE_RAW carries a bare IP packet and lets one file hold
// both IPv4 and IPv6 (the version nibble disambiguates), which matters because
// ePDG candidates are resolved fresh on every attempt.
const (
	pcapMagicNanos  uint32 = 0xa1b23c4d
	pcapVersionMaj  uint16 = 2
	pcapVersionMin  uint16 = 4
	pcapSnapLen     uint32 = 262144
	linkTypeRaw     uint32 = 101
	ipv4HeaderLen          = 20
	ipv6HeaderLen          = 40
	udpHeaderLen           = 8
	protocolUDP     uint8  = 17
	sessionSuffix          = ".session.json"
	sessionVersion         = 1
	secretsWarnText        = "CONTAINS THE EPHEMERAL DH PRIVATE SCALAR AND NONCE. Lab debugging artifact only: anyone holding this file plus the pcap can derive the IKE SA keys. Do not distribute."
)

// Direction says who sent a datagram.
type Direction string

// Direction values.
const (
	DirTx Direction = "tx"
	DirRx Direction = "rx"
)

// Kind classifies a datagram on the NAT-T port.
type Kind string

// Kind values.
const (
	KindIKE     Kind = "ike"     // non-ESP marker prefixed
	KindESP     Kind = "esp"     // anything else of usable length
	KindNATT    Kind = "natt"    // the single 0xff keepalive byte
	KindUnknown Kind = "unknown" // too short to be either
)

// Seed is everything needed to reproduce our side of an IKE_SA_INIT byte for
// byte. Without it a replay regenerates a fresh SPI and nonce and the recorded
// response no longer matches its own request header.
type Seed struct {
	InitiatorSPI uint64 `json:"initiator_spi"`
	NonceI       []byte `json:"nonce_i,omitempty"`
	DHGroup      uint16 `json:"dh_group"`
	DHPrivate    []byte `json:"dh_private,omitempty"`
}

// Valid reports whether the seed can drive a byte-exact replay.
func (s Seed) Valid() bool {
	return s.InitiatorSPI != 0 && len(s.NonceI) > 0 && s.DHGroup != 0 && len(s.DHPrivate) > 0
}

// Session is the sidecar metadata stored next to the pcap.
type Session struct {
	Version    int       `json:"version"`
	CreatedAt  time.Time `json:"created_at"`
	LocalAddr  string    `json:"local_addr"`
	RemoteAddr string    `json:"remote_addr"`
	Note       string    `json:"note,omitempty"`
	Warning    string    `json:"warning,omitempty"`
	Seed       *Seed     `json:"seed,omitempty"`
}

// WriterOptions configures a recording.
type WriterOptions struct {
	// Path is the pcap file. The sidecar goes to Path + ".session.json".
	Path string
	// LocalAddr is used to label direction on read-back.
	LocalAddr *net.UDPAddr
	// RemoteAddr is informational.
	RemoteAddr *net.UDPAddr
	// RecordSecrets must be set explicitly before Seed data is persisted.
	RecordSecrets bool
	// Note is free text describing the run.
	Note string
	// Warnf receives the one-line secrets warning. nil means silence.
	Warnf func(format string, args ...any)
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// Writer streams datagrams into a pcap file.
type Writer struct {
	mu      sync.Mutex
	file    *os.File
	opts    WriterOptions
	session Session
	seed    *Seed
	closed  bool
	count   int
}

// NewWriter creates the pcap and prepares the sidecar.
func NewWriter(opts WriterOptions) (*Writer, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("vowifi/capture: empty capture path")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if dir := filepath.Dir(opts.Path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	f, err := os.Create(opts.Path)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, 0, 24)
	hdr = binary.LittleEndian.AppendUint32(hdr, pcapMagicNanos)
	hdr = binary.LittleEndian.AppendUint16(hdr, pcapVersionMaj)
	hdr = binary.LittleEndian.AppendUint16(hdr, pcapVersionMin)
	hdr = binary.LittleEndian.AppendUint32(hdr, 0)
	hdr = binary.LittleEndian.AppendUint32(hdr, 0)
	hdr = binary.LittleEndian.AppendUint32(hdr, pcapSnapLen)
	hdr = binary.LittleEndian.AppendUint32(hdr, linkTypeRaw)
	if _, err := f.Write(hdr); err != nil {
		f.Close()
		return nil, err
	}
	w := &Writer{file: f, opts: opts}
	w.session = Session{
		Version:    sessionVersion,
		CreatedAt:  opts.Now().UTC(),
		LocalAddr:  addrString(opts.LocalAddr),
		RemoteAddr: addrString(opts.RemoteAddr),
		Note:       opts.Note,
	}
	return w, nil
}

// SetSeed stores the replay seed. It is only persisted when RecordSecrets is
// set; otherwise the sidecar records that secrets were withheld, so a later
// reader learns why replay is impossible instead of guessing.
func (w *Writer) SetSeed(seed Seed) {
	w.mu.Lock()
	defer w.mu.Unlock()
	copied := seed
	copied.NonceI = append([]byte(nil), seed.NonceI...)
	copied.DHPrivate = append([]byte(nil), seed.DHPrivate...)
	w.seed = &copied
}

// SetLocalAddr records the local endpoint once the kernel has picked it.
func (w *Writer) SetLocalAddr(addr *net.UDPAddr) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.session.LocalAddr = addrString(addr)
}

// SetRemoteAddr records the peer. The socket calls this so a recording is
// self-describing even when the Writer was created before the ePDG candidate
// was chosen; offline replay needs both endpoints to rebuild the InitConfig.
func (w *Writer) SetRemoteAddr(addr *net.UDPAddr) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.session.RemoteAddr = addrString(addr)
}

// Count returns how many datagrams have been recorded.
func (w *Writer) Count() int {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}

// Record appends one datagram. A nil Writer is a no-op so callers can leave
// capture switched off without branching at every call site.
func (w *Writer) Record(dir Direction, local, remote *net.UDPAddr, payload []byte) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return fmt.Errorf("vowifi/capture: writer is closed")
	}
	src, dst := local, remote
	if dir == DirRx {
		src, dst = remote, local
	}
	frame, err := synthesizeIPUDP(src, dst, payload)
	if err != nil {
		return err
	}
	ts := w.opts.Now()
	rec := make([]byte, 0, 16+len(frame))
	rec = binary.LittleEndian.AppendUint32(rec, uint32(ts.Unix()))
	rec = binary.LittleEndian.AppendUint32(rec, uint32(ts.Nanosecond()))
	rec = binary.LittleEndian.AppendUint32(rec, uint32(len(frame)))
	rec = binary.LittleEndian.AppendUint32(rec, uint32(len(frame)))
	rec = append(rec, frame...)
	if _, err := w.file.Write(rec); err != nil {
		return err
	}
	w.count++
	return nil
}

// Close flushes the pcap and writes the sidecar.
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	session := w.session
	if w.seed != nil {
		if w.opts.RecordSecrets {
			seed := *w.seed
			session.Seed = &seed
			session.Warning = secretsWarnText
			if w.opts.Warnf != nil {
				w.opts.Warnf("capture %s: %s", w.opts.Path+sessionSuffix, secretsWarnText)
			}
		} else {
			session.Warning = "seed withheld: RecordSecrets was not set, so this capture cannot be replayed byte-exactly"
		}
	}
	blob, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		w.file.Close()
		return err
	}
	blob = append(blob, '\n')
	if err := os.WriteFile(w.opts.Path+sessionSuffix, blob, 0o600); err != nil {
		w.file.Close()
		return err
	}
	return w.file.Close()
}

// Record is one recorded datagram.
type Record struct {
	Time    time.Time
	Dir     Direction
	Kind    Kind
	Src     *net.UDPAddr
	Dst     *net.UDPAddr
	Payload []byte
}

// Capture is a parsed recording.
type Capture struct {
	Session Session
	Records []Record
}

// Open reads a pcap plus its sidecar back into memory.
func Open(path string) (*Capture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) < 24 {
		return nil, fmt.Errorf("%w: shorter than a pcap global header", ErrMalformedCapture)
	}
	if magic := binary.LittleEndian.Uint32(raw[0:4]); magic != pcapMagicNanos {
		return nil, fmt.Errorf("%w: magic %#08x, want %#08x", ErrMalformedCapture, magic, pcapMagicNanos)
	}
	if link := binary.LittleEndian.Uint32(raw[20:24]); link != linkTypeRaw {
		return nil, fmt.Errorf("%w: link type %d, want %d", ErrMalformedCapture, link, linkTypeRaw)
	}
	out := &Capture{}
	sidecar, err := os.ReadFile(path + sessionSuffix)
	if err == nil {
		if err := json.Unmarshal(sidecar, &out.Session); err != nil {
			return nil, fmt.Errorf("%w: sidecar: %w", ErrMalformedCapture, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	localAddr := out.Session.LocalAddr

	body := raw[24:]
	for len(body) > 0 {
		if len(body) < 16 {
			return nil, fmt.Errorf("%w: truncated record header", ErrMalformedCapture)
		}
		sec := binary.LittleEndian.Uint32(body[0:4])
		nsec := binary.LittleEndian.Uint32(body[4:8])
		inclLen := int(binary.LittleEndian.Uint32(body[8:12]))
		if inclLen < 0 || 16+inclLen > len(body) {
			return nil, fmt.Errorf("%w: record length %d overruns the file", ErrMalformedCapture, inclLen)
		}
		frame := body[16 : 16+inclLen]
		body = body[16+inclLen:]
		src, dst, payload, err := parseIPUDP(frame)
		if err != nil {
			return nil, err
		}
		dir := DirRx
		if localAddr != "" && src.String() == localAddr {
			dir = DirTx
		} else if localAddr == "" {
			return nil, fmt.Errorf("%w: sidecar has no local_addr, direction is unrecoverable", ErrMalformedCapture)
		}
		out.Records = append(out.Records, Record{
			Time:    time.Unix(int64(sec), int64(nsec)).UTC(),
			Dir:     dir,
			Kind:    Classify(payload),
			Src:     src,
			Dst:     dst,
			Payload: payload,
		})
	}
	return out, nil
}

// Classify labels a datagram seen on UDP 4500.
func Classify(payload []byte) Kind {
	switch {
	case len(payload) == 1 && payload[0] == 0xff:
		return KindNATT
	case len(payload) >= 4 && payload[0] == 0 && payload[1] == 0 && payload[2] == 0 && payload[3] == 0:
		return KindIKE
	case len(payload) >= 8:
		return KindESP
	default:
		return KindUnknown
	}
}

// ReplayOptions configures an offline replay.
type ReplayOptions struct {
	// UseNonESPMarker mirrors the live socket: on 4500 every IKE message is
	// prefixed with four zero bytes, and the recording holds the prefixed form.
	UseNonESPMarker bool
	// RequireExactRequests turns the replay into a byte-for-byte assertion. This
	// is what turns "the replay produced a plausible result" into "the replay
	// reproduced the recording", which is the only version worth having.
	RequireExactRequests bool
}

// ReplayTransport serves a recorded session back to the same code that produced
// it. It implements the same three mirror interfaces as the live socket:
// ikev2.InitTransport, swu.ESPPacketReadWriteTransport and
// swu.NATTKeepaliveSender.
type ReplayTransport struct {
	mu      sync.Mutex
	records []Record
	cursor  int
	opts    ReplayOptions
	sent    [][]byte
}

// NewReplayTransport builds a replay over an already-parsed capture.
func NewReplayTransport(c *Capture, opts ReplayOptions) *ReplayTransport {
	records := make([]Record, len(c.Records))
	copy(records, c.Records)
	return &ReplayTransport{records: records, opts: opts}
}

// OpenReplay is Open plus NewReplayTransport, also returning the seed needed to
// drive a byte-exact rerun.
func OpenReplay(path string, opts ReplayOptions) (*ReplayTransport, Seed, error) {
	c, err := Open(path)
	if err != nil {
		return nil, Seed{}, err
	}
	var seed Seed
	if c.Session.Seed != nil {
		seed = *c.Session.Seed
	}
	return NewReplayTransport(c, opts), seed, nil
}

// SentRequests returns every wire-form request the replay consumed.
func (r *ReplayTransport) SentRequests() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.sent))
	copy(out, r.sent)
	return out
}

// Remaining reports how many recorded datagrams have not been consumed.
func (r *ReplayTransport) Remaining() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.records) - r.cursor
}

// ExchangeIKE satisfies ikev2.InitTransport against the recording.
func (r *ReplayTransport) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	wire := request
	if r.opts.UseNonESPMarker {
		wire = append([]byte{0, 0, 0, 0}, request...)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, append([]byte(nil), wire...))

	// Consume the recorded transmissions that correspond to this request,
	// including any retransmissions that the recording captured.
	matched := false
	for r.cursor < len(r.records) {
		rec := r.records[r.cursor]
		if rec.Dir != DirTx {
			break
		}
		r.cursor++
		if rec.Kind != KindIKE {
			continue
		}
		if bytes.Equal(rec.Payload, wire) {
			matched = true
			continue
		}
		if r.opts.RequireExactRequests {
			return nil, fmt.Errorf("%w: request %d differs at %d bytes vs %d recorded",
				ErrReplayMismatch, len(r.sent), len(wire), len(rec.Payload))
		}
	}
	if r.opts.RequireExactRequests && !matched {
		return nil, fmt.Errorf("%w: no recorded transmission matches request %d", ErrReplayMismatch, len(r.sent))
	}
	for r.cursor < len(r.records) {
		rec := r.records[r.cursor]
		r.cursor++
		if rec.Dir != DirRx || rec.Kind != KindIKE {
			continue
		}
		payload := rec.Payload
		if r.opts.UseNonESPMarker && len(payload) >= 4 {
			payload = payload[4:]
		}
		return append([]byte(nil), payload...), nil
	}
	return nil, fmt.Errorf("%w: no response recorded after request %d", ErrReplayExhausted, len(r.sent))
}

// SendESPPacket satisfies swu.ESPPacketTransport.
func (r *ReplayTransport) SendESPPacket(ctx context.Context, packet []byte) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, append([]byte(nil), packet...))
	for r.cursor < len(r.records) {
		rec := r.records[r.cursor]
		if rec.Dir != DirTx {
			return nil
		}
		r.cursor++
		if rec.Kind != KindESP {
			continue
		}
		if r.opts.RequireExactRequests && !bytes.Equal(rec.Payload, packet) {
			return fmt.Errorf("%w: ESP packet %d differs from the recording", ErrReplayMismatch, len(r.sent))
		}
		return nil
	}
	return nil
}

// ReadESPPacket satisfies swu.ESPPacketReceiver.
func (r *ReplayTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for r.cursor < len(r.records) {
		rec := r.records[r.cursor]
		r.cursor++
		if rec.Dir != DirRx || rec.Kind != KindESP {
			continue
		}
		return append([]byte(nil), rec.Payload...), nil
	}
	return nil, fmt.Errorf("%w: no further inbound ESP packets", ErrReplayExhausted)
}

// SendNATTKeepalive satisfies swu.NATTKeepaliveSender.
func (r *ReplayTransport) SendNATTKeepalive(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, []byte{0xff})
	return nil
}

// Close satisfies swu.ESPPacketTransportCloser.
func (r *ReplayTransport) Close(context.Context) error { return nil }

func addrString(a *net.UDPAddr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

func synthesizeIPUDP(src, dst *net.UDPAddr, payload []byte) ([]byte, error) {
	if src == nil || dst == nil {
		return nil, fmt.Errorf("%w: nil endpoint", ErrUnsupportedAddr)
	}
	if len(payload) > 0xffff-udpHeaderLen {
		return nil, fmt.Errorf("%w: datagram of %d bytes", ErrMalformedCapture, len(payload))
	}
	src4, dst4 := src.IP.To4(), dst.IP.To4()
	udp := make([]byte, 0, udpHeaderLen+len(payload))
	udp = binary.BigEndian.AppendUint16(udp, uint16(src.Port))
	udp = binary.BigEndian.AppendUint16(udp, uint16(dst.Port))
	udp = binary.BigEndian.AppendUint16(udp, uint16(udpHeaderLen+len(payload)))
	udp = binary.BigEndian.AppendUint16(udp, 0) // checksum omitted; legal over IPv4
	udp = append(udp, payload...)

	if src4 != nil && dst4 != nil {
		total := ipv4HeaderLen + len(udp)
		ip := make([]byte, ipv4HeaderLen)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(total))
		ip[8] = 64
		ip[9] = protocolUDP
		copy(ip[12:16], src4)
		copy(ip[16:20], dst4)
		binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip))
		return append(ip, udp...), nil
	}
	src16, dst16 := src.IP.To16(), dst.IP.To16()
	if src16 == nil || dst16 == nil {
		return nil, fmt.Errorf("%w: %v -> %v", ErrUnsupportedAddr, src.IP, dst.IP)
	}
	ip := make([]byte, ipv6HeaderLen)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(udp)))
	ip[6] = protocolUDP
	ip[7] = 64
	copy(ip[8:24], src16)
	copy(ip[24:40], dst16)
	return append(ip, udp...), nil
}

func parseIPUDP(frame []byte) (*net.UDPAddr, *net.UDPAddr, []byte, error) {
	if len(frame) < 1 {
		return nil, nil, nil, fmt.Errorf("%w: empty frame", ErrMalformedCapture)
	}
	var srcIP, dstIP net.IP
	var rest []byte
	switch frame[0] >> 4 {
	case 4:
		if len(frame) < ipv4HeaderLen {
			return nil, nil, nil, fmt.Errorf("%w: short IPv4 header", ErrMalformedCapture)
		}
		ihl := int(frame[0]&0x0f) * 4
		if ihl < ipv4HeaderLen || len(frame) < ihl {
			return nil, nil, nil, fmt.Errorf("%w: IPv4 IHL %d", ErrMalformedCapture, ihl)
		}
		if frame[9] != protocolUDP {
			return nil, nil, nil, fmt.Errorf("%w: IPv4 protocol %d, want UDP", ErrMalformedCapture, frame[9])
		}
		srcIP = net.IP(append([]byte(nil), frame[12:16]...))
		dstIP = net.IP(append([]byte(nil), frame[16:20]...))
		rest = frame[ihl:]
	case 6:
		if len(frame) < ipv6HeaderLen {
			return nil, nil, nil, fmt.Errorf("%w: short IPv6 header", ErrMalformedCapture)
		}
		if frame[6] != protocolUDP {
			return nil, nil, nil, fmt.Errorf("%w: IPv6 next header %d, want UDP", ErrMalformedCapture, frame[6])
		}
		srcIP = net.IP(append([]byte(nil), frame[8:24]...))
		dstIP = net.IP(append([]byte(nil), frame[24:40]...))
		rest = frame[ipv6HeaderLen:]
	default:
		return nil, nil, nil, fmt.Errorf("%w: IP version %d", ErrMalformedCapture, frame[0]>>4)
	}
	if len(rest) < udpHeaderLen {
		return nil, nil, nil, fmt.Errorf("%w: short UDP header", ErrMalformedCapture)
	}
	srcPort := int(binary.BigEndian.Uint16(rest[0:2]))
	dstPort := int(binary.BigEndian.Uint16(rest[2:4]))
	length := int(binary.BigEndian.Uint16(rest[4:6]))
	if length < udpHeaderLen || length > len(rest) {
		return nil, nil, nil, fmt.Errorf("%w: UDP length %d against %d available", ErrMalformedCapture, length, len(rest))
	}
	payload := append([]byte(nil), rest[udpHeaderLen:length]...)
	return &net.UDPAddr{IP: srcIP, Port: srcPort}, &net.UDPAddr{IP: dstIP, Port: dstPort}, payload, nil
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
