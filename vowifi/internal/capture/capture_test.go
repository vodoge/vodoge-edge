package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func addr(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

// TestPcapRoundTripPreservesBytes is the base guarantee: whatever went on the
// wire comes back out unaltered, including the non-ESP marker and the keepalive.
func TestPcapRoundTripPreservesBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "round-trip.pcap")
	local := addr("10.0.0.7", 4500)
	remote := addr("208.54.26.131", 4500)

	w, err := NewWriter(WriterOptions{Path: path, LocalAddr: local, RemoteAddr: remote, Note: "unit"})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ike := append([]byte{0, 0, 0, 0}, bytes.Repeat([]byte{0x21}, 300)...)
	esp := append([]byte{0xaa, 0xbb, 0xcc, 0xdd}, bytes.Repeat([]byte{0x42}, 120)...)
	keepalive := []byte{0xff}

	for _, step := range []struct {
		dir     Direction
		payload []byte
	}{
		{DirTx, ike},
		{DirRx, ike},
		{DirTx, keepalive},
		{DirTx, esp},
		{DirRx, esp},
	} {
		if err := w.Record(step.dir, local, remote, step.payload); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if w.Count() != 5 {
		t.Fatalf("Count = %d, want 5", w.Count())
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(c.Records) != 5 {
		t.Fatalf("read %d records, want 5", len(c.Records))
	}
	wantKinds := []Kind{KindIKE, KindIKE, KindNATT, KindESP, KindESP}
	wantDirs := []Direction{DirTx, DirRx, DirTx, DirTx, DirRx}
	for i, rec := range c.Records {
		if rec.Kind != wantKinds[i] {
			t.Errorf("record %d kind = %s, want %s", i, rec.Kind, wantKinds[i])
		}
		if rec.Dir != wantDirs[i] {
			t.Errorf("record %d dir = %s, want %s", i, rec.Dir, wantDirs[i])
		}
	}
	if !bytes.Equal(c.Records[0].Payload, ike) {
		t.Errorf("IKE payload was altered by the pcap round trip")
	}
	if !bytes.Equal(c.Records[3].Payload, esp) {
		t.Errorf("ESP payload was altered by the pcap round trip")
	}
	if !bytes.Equal(c.Records[2].Payload, keepalive) {
		t.Errorf("keepalive was altered by the pcap round trip")
	}
	if c.Records[0].Src.String() != local.String() || c.Records[0].Dst.String() != remote.String() {
		t.Errorf("tx endpoints = %s -> %s", c.Records[0].Src, c.Records[0].Dst)
	}
	if c.Records[1].Src.String() != remote.String() {
		t.Errorf("rx source = %s, want %s", c.Records[1].Src, remote)
	}
	if c.Session.Note != "unit" {
		t.Errorf("sidecar note = %q", c.Session.Note)
	}
}

// TestPcapHeaderIsWiresharkReadable checks the exact bytes a dissector reads.
// A file Wireshark refuses to open is not a debugging aid at 3am.
func TestPcapHeaderIsWiresharkReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "header.pcap")
	local := addr("192.0.2.1", 4500)
	w, err := NewWriter(WriterOptions{Path: path, LocalAddr: local, RemoteAddr: addr("198.51.100.2", 4500)})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	payload := append([]byte{0, 0, 0, 0}, bytes.Repeat([]byte{1}, 40)...)
	if err := w.Record(DirTx, local, addr("198.51.100.2", 4500), payload); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got := binary.LittleEndian.Uint32(raw[0:4]); got != pcapMagicNanos {
		t.Errorf("magic = %#x, want %#x", got, pcapMagicNanos)
	}
	if got := binary.LittleEndian.Uint16(raw[4:6]); got != 2 {
		t.Errorf("version major = %d, want 2", got)
	}
	if got := binary.LittleEndian.Uint32(raw[20:24]); got != linkTypeRaw {
		t.Errorf("link type = %d, want %d (LINKTYPE_RAW)", got, linkTypeRaw)
	}
	frame := raw[24+16:]
	if frame[0]>>4 != 4 {
		t.Fatalf("synthesized IP version = %d, want 4", frame[0]>>4)
	}
	if frame[9] != protocolUDP {
		t.Fatalf("IP protocol = %d, want 17", frame[9])
	}
	// The header checksum must be right or Wireshark flags every packet.
	if got := ipv4Checksum(frame[:20]); got != 0 {
		t.Errorf("IPv4 checksum does not verify (recomputed residual %#x)", got)
	}
	if got := int(binary.BigEndian.Uint16(frame[20:22])); got != 4500 {
		t.Errorf("UDP source port = %d, want 4500", got)
	}
	if got := int(binary.BigEndian.Uint16(frame[24:26])); got != udpHeaderLen+len(payload) {
		t.Errorf("UDP length = %d, want %d", got, udpHeaderLen+len(payload))
	}
}

func TestIPv6CaptureRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v6.pcap")
	local := addr("2001:db8::1", 4500)
	remote := addr("2001:db8::2", 4500)
	w, err := NewWriter(WriterOptions{Path: path, LocalAddr: local, RemoteAddr: remote})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	payload := append([]byte{0, 0, 0, 0}, bytes.Repeat([]byte{9}, 64)...)
	if err := w.Record(DirTx, local, remote, payload); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(c.Records) != 1 || !bytes.Equal(c.Records[0].Payload, payload) {
		t.Fatalf("IPv6 round trip lost the payload")
	}
	if c.Records[0].Dir != DirTx {
		t.Fatalf("IPv6 direction = %s, want tx", c.Records[0].Dir)
	}
}

// TestSecretsAreWithheldUnlessRequested guards the one thing in a capture that
// is actually dangerous.
func TestSecretsAreWithheldUnlessRequested(t *testing.T) {
	dir := t.TempDir()
	seed := Seed{InitiatorSPI: 0x1122334455667788, NonceI: []byte{1, 2, 3}, DHGroup: 14, DHPrivate: []byte{9, 9, 9}}

	t.Run("withheld by default", func(t *testing.T) {
		path := filepath.Join(dir, "no-secrets.pcap")
		w, err := NewWriter(WriterOptions{Path: path, LocalAddr: addr("10.0.0.1", 4500)})
		if err != nil {
			t.Fatalf("NewWriter: %v", err)
		}
		w.SetSeed(seed)
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		blob, err := os.ReadFile(path + sessionSuffix)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		var got Session
		if err := json.Unmarshal(blob, &got); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if got.Seed != nil {
			t.Fatalf("the DH scalar was written without RecordSecrets")
		}
		if !strings.Contains(got.Warning, "withheld") {
			t.Errorf("sidecar does not explain why replay is impossible: %q", got.Warning)
		}
	})

	t.Run("written with a warning when asked", func(t *testing.T) {
		path := filepath.Join(dir, "secrets.pcap")
		var warned string
		w, err := NewWriter(WriterOptions{
			Path:          path,
			LocalAddr:     addr("10.0.0.1", 4500),
			RecordSecrets: true,
			Warnf:         func(f string, a ...any) { warned = f },
		})
		if err != nil {
			t.Fatalf("NewWriter: %v", err)
		}
		w.SetSeed(seed)
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		_, got, err := OpenReplay(path, ReplayOptions{})
		if err != nil {
			t.Fatalf("OpenReplay: %v", err)
		}
		if got.InitiatorSPI != seed.InitiatorSPI || !bytes.Equal(got.DHPrivate, seed.DHPrivate) {
			t.Fatalf("seed did not survive the sidecar round trip")
		}
		if warned == "" {
			t.Errorf("no warning was emitted when secrets were written")
		}
		if runtime.GOOS == "windows" {
			// Windows has no POSIX mode bits; os.WriteFile reports 0666 no
			// matter what was requested. The edge machine is Linux, so assert
			// there and skip here rather than weakening the check everywhere.
			t.Skip("POSIX permission bits are not modelled on windows")
		}
		info, err := os.Stat(path + sessionSuffix)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("sidecar permissions = %v, want owner-only", perm)
		}
	})
}

func TestSeedValid(t *testing.T) {
	full := Seed{InitiatorSPI: 1, NonceI: []byte{1}, DHGroup: 14, DHPrivate: []byte{1}}
	if !full.Valid() {
		t.Fatalf("a complete seed reported invalid")
	}
	for name, s := range map[string]Seed{
		"no spi":     {NonceI: []byte{1}, DHGroup: 14, DHPrivate: []byte{1}},
		"no nonce":   {InitiatorSPI: 1, DHGroup: 14, DHPrivate: []byte{1}},
		"no group":   {InitiatorSPI: 1, NonceI: []byte{1}, DHPrivate: []byte{1}},
		"no private": {InitiatorSPI: 1, NonceI: []byte{1}, DHGroup: 14},
	} {
		if s.Valid() {
			t.Errorf("%s: reported valid", name)
		}
	}
}

// TestReplayStrictModeCatchesDrift proves RequireExactRequests is not
// decoration. A replay that quietly accepts different bytes would let a
// regression pass as a successful reproduction.
func TestReplayStrictModeCatchesDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strict.pcap")
	local := addr("10.0.0.1", 4500)
	remote := addr("10.0.0.2", 4500)
	w, err := NewWriter(WriterOptions{Path: path, LocalAddr: local, RemoteAddr: remote})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	request := bytes.Repeat([]byte{0x33}, 64)
	response := bytes.Repeat([]byte{0x44}, 96)
	if err := w.Record(DirTx, local, remote, append([]byte{0, 0, 0, 0}, request...)); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := w.Record(DirRx, local, remote, append([]byte{0, 0, 0, 0}, response...)); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	opts := ReplayOptions{UseNonESPMarker: true, RequireExactRequests: true}

	strict, _, err := OpenReplay(path, opts)
	if err != nil {
		t.Fatalf("OpenReplay: %v", err)
	}
	got, err := strict.ExchangeIKE(context.Background(), request)
	if err != nil {
		t.Fatalf("ExchangeIKE with the recorded request: %v", err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("replayed response differs from the recording")
	}
	if strict.Remaining() != 0 {
		t.Errorf("Remaining = %d, want 0", strict.Remaining())
	}

	drifted, _, err := OpenReplay(path, opts)
	if err != nil {
		t.Fatalf("OpenReplay: %v", err)
	}
	altered := append([]byte(nil), request...)
	altered[0] ^= 0x01
	if _, err := drifted.ExchangeIKE(context.Background(), altered); !errors.Is(err, ErrReplayMismatch) {
		t.Fatalf("strict replay accepted drifted bytes: err = %v", err)
	}

	lenient, _, err := OpenReplay(path, ReplayOptions{UseNonESPMarker: true})
	if err != nil {
		t.Fatalf("OpenReplay: %v", err)
	}
	if _, err := lenient.ExchangeIKE(context.Background(), altered); err != nil {
		t.Fatalf("lenient replay rejected drifted bytes: %v", err)
	}
}

func TestReplayExhaustion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short.pcap")
	local := addr("10.0.0.1", 4500)
	remote := addr("10.0.0.2", 4500)
	w, err := NewWriter(WriterOptions{Path: path, LocalAddr: local, RemoteAddr: remote})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Record(DirTx, local, remote, append([]byte{0, 0, 0, 0}, bytes.Repeat([]byte{1}, 32)...)); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r, _, err := OpenReplay(path, ReplayOptions{UseNonESPMarker: true})
	if err != nil {
		t.Fatalf("OpenReplay: %v", err)
	}
	if _, err := r.ExchangeIKE(context.Background(), bytes.Repeat([]byte{1}, 32)); !errors.Is(err, ErrReplayExhausted) {
		t.Fatalf("error = %v, want ErrReplayExhausted", err)
	}
	if _, err := r.ReadESPPacket(context.Background()); !errors.Is(err, ErrReplayExhausted) {
		t.Fatalf("ReadESPPacket error = %v, want ErrReplayExhausted", err)
	}
	if err := r.SendNATTKeepalive(context.Background()); err != nil {
		t.Fatalf("SendNATTKeepalive: %v", err)
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestReplayServesESP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "esp.pcap")
	local := addr("10.0.0.1", 4500)
	remote := addr("10.0.0.2", 4500)
	w, err := NewWriter(WriterOptions{Path: path, LocalAddr: local, RemoteAddr: remote})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	out := append([]byte{1, 2, 3, 4}, bytes.Repeat([]byte{5}, 40)...)
	in := append([]byte{9, 8, 7, 6}, bytes.Repeat([]byte{4}, 40)...)
	if err := w.Record(DirTx, local, remote, out); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := w.Record(DirRx, local, remote, in); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, _, err := OpenReplay(path, ReplayOptions{UseNonESPMarker: true, RequireExactRequests: true})
	if err != nil {
		t.Fatalf("OpenReplay: %v", err)
	}
	if err := r.SendESPPacket(context.Background(), out); err != nil {
		t.Fatalf("SendESPPacket: %v", err)
	}
	got, err := r.ReadESPPacket(context.Background())
	if err != nil {
		t.Fatalf("ReadESPPacket: %v", err)
	}
	if !bytes.Equal(got, in) {
		t.Fatalf("replayed ESP payload mismatch")
	}
	if len(r.SentRequests()) != 1 {
		t.Errorf("SentRequests = %d, want 1", len(r.SentRequests()))
	}
}

func TestOpenRejectsCorruptFiles(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]byte{
		"too short":  {1, 2, 3},
		"bad magic":  append([]byte{0, 0, 0, 0}, bytes.Repeat([]byte{0}, 40)...),
		"bad record": append(validHeader(), 1, 2, 3),
	}
	for name, blob := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".pcap")
		if err := os.WriteFile(path, blob, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := Open(path); !errors.Is(err, ErrMalformedCapture) {
			t.Errorf("%s: err = %v, want ErrMalformedCapture", name, err)
		}
	}
}

// TestOpenRefusesToGuessDirection matters because a capture whose direction is
// invented is worse than no capture.
func TestOpenRefusesToGuessDirection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-local.pcap")
	local := addr("10.0.0.1", 4500)
	remote := addr("10.0.0.2", 4500)
	w, err := NewWriter(WriterOptions{Path: path, LocalAddr: local, RemoteAddr: remote})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Record(DirTx, local, remote, bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := os.Remove(path + sessionSuffix); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := Open(path); !errors.Is(err, ErrMalformedCapture) {
		t.Fatalf("Open without a sidecar err = %v, want ErrMalformedCapture", err)
	}
}

func TestNilWriterIsInert(t *testing.T) {
	var w *Writer
	if err := w.Record(DirTx, addr("10.0.0.1", 4500), addr("10.0.0.2", 4500), []byte{1}); err != nil {
		t.Fatalf("nil Writer Record: %v", err)
	}
	if w.Count() != 0 {
		t.Fatalf("nil Writer Count = %d", w.Count())
	}
	if err := w.Close(); err != nil {
		t.Fatalf("nil Writer Close: %v", err)
	}
}

func TestTimestampsAreMonotonicAndSane(t *testing.T) {
	path := filepath.Join(t.TempDir(), "time.pcap")
	local := addr("10.0.0.1", 4500)
	remote := addr("10.0.0.2", 4500)
	base := time.Date(2026, 8, 24, 3, 0, 0, 500, time.UTC)
	step := 0
	w, err := NewWriter(WriterOptions{
		Path: path, LocalAddr: local, RemoteAddr: remote,
		Now: func() time.Time { step++; return base.Add(time.Duration(step) * time.Millisecond) },
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := w.Record(DirTx, local, remote, bytes.Repeat([]byte{byte(i)}, 32)); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := 1; i < len(c.Records); i++ {
		if !c.Records[i].Time.After(c.Records[i-1].Time) {
			t.Fatalf("record %d timestamp %v is not after %v", i, c.Records[i].Time, c.Records[i-1].Time)
		}
	}
	if c.Records[0].Time.Nanosecond() == 0 {
		t.Errorf("sub-second resolution was lost; the nanosecond pcap magic is pointless then")
	}
}

func validHeader() []byte {
	hdr := make([]byte, 0, 24)
	hdr = binary.LittleEndian.AppendUint32(hdr, pcapMagicNanos)
	hdr = binary.LittleEndian.AppendUint16(hdr, pcapVersionMaj)
	hdr = binary.LittleEndian.AppendUint16(hdr, pcapVersionMin)
	hdr = binary.LittleEndian.AppendUint32(hdr, 0)
	hdr = binary.LittleEndian.AppendUint32(hdr, 0)
	hdr = binary.LittleEndian.AppendUint32(hdr, pcapSnapLen)
	return binary.LittleEndian.AppendUint32(hdr, linkTypeRaw)
}
