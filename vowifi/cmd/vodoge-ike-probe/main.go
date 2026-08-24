// Command vodoge-ike-probe runs one IKE_SA_INIT against an ePDG and records it.
//
// It is deliberately read-only with respect to the network: IKE_SA_INIT carries
// no identity (T036 confirmed this from the mirror source), so running this
// probe proves reachability and algorithm selection and nothing else. Whether
// the carrier accepts this SIM is an IKE_AUTH question and belongs to T041b/d.
//
// The GSLB behind epdg.epc.mnc260.mcc310.pub.3gppnetwork.org handed T038 seven
// different addresses in seven lookups, so the FQDN is resolved on every run and
// every candidate is tried until one completes. Each failure records the suite
// that node selected, because at least one node in the pool speaks a legacy
// suite this stack cannot key (see internal/ike/suite.go).
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/boa-z/vowifi-go/engine/swu/ikev2"

	"github.com/yuanshuai1122/vodoge-edge/vowifi/internal/capture"
	"github.com/yuanshuai1122/vodoge-edge/vowifi/internal/ike"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "vodoge-ike-probe: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		target        = flag.String("target", "", "ePDG host or FQDN (required unless -replay is set)")
		port          = flag.Int("port", int(ike.NATTPort), "ePDG UDP port")
		localPort     = flag.Int("local-port", int(ike.NATTPort), "local UDP port to pin")
		localIP       = flag.String("local-ip", "", "local bind address (default: wildcard)")
		groupList     = flag.String("groups", "", "comma-separated DH groups to offer (default: 14,2,19,31 as measured by T038)")
		timeout       = flag.Duration("timeout", 30*time.Second, "overall deadline per candidate")
		attempts      = flag.Int("attempts", 5, "transmissions per message, RFC 7296 retransmission included")
		capturePath   = flag.String("capture", "", "write a pcap here (a .session.json sidecar goes alongside)")
		recordSecrets = flag.Bool("record-secrets", false, "store the DH scalar in the sidecar so the capture can be replayed byte-exactly; the file then reveals the IKE SA keys")
		replayPath    = flag.String("replay", "", "replay a previously recorded pcap instead of touching the network")
		strictReplay  = flag.Bool("strict-replay", true, "in replay mode, require our request bytes to match the recording exactly")
		exportAuth    = flag.String("export-auth", "", "in replay mode, write every AUTH payload body to this directory as .auth.bin files")
		maxCandidates = flag.Int("max-candidates", 4, "how many resolved addresses to try")
	)
	flag.Parse()

	groups, err := parseGroups(*groupList)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *replayPath != "" {
		return runReplay(ctx, *replayPath, *strictReplay, *exportAuth)
	}
	if strings.TrimSpace(*target) == "" {
		return fmt.Errorf("-target is required")
	}

	candidates, err := resolveCandidates(ctx, *target, *port)
	if err != nil {
		return err
	}
	if len(candidates) > *maxCandidates {
		candidates = candidates[:*maxCandidates]
	}
	fmt.Printf("resolved %s to %d candidate(s): %s\n", *target, len(candidates), joinAddrs(candidates))

	var failures []string
	for i, candidate := range candidates {
		fmt.Printf("\n--- candidate %d/%d: %s ---\n", i+1, len(candidates), candidate)
		err := probeOne(ctx, probeParams{
			remote:        candidate,
			localIP:       *localIP,
			localPort:     uint16(*localPort),
			groups:        groups,
			timeout:       *timeout,
			attempts:      *attempts,
			capturePath:   capturePathFor(*capturePath, i),
			recordSecrets: *recordSecrets,
		})
		if err == nil {
			return nil
		}
		fmt.Printf("candidate %s failed: %v\n", candidate, err)
		failures = append(failures, fmt.Sprintf("%s: %v", candidate, err))
		if ctx.Err() != nil {
			break
		}
	}
	return fmt.Errorf("all %d candidate(s) failed:\n  %s", len(candidates), strings.Join(failures, "\n  "))
}

type probeParams struct {
	remote        *net.UDPAddr
	localIP       string
	localPort     uint16
	groups        []uint16
	timeout       time.Duration
	attempts      int
	capturePath   string
	recordSecrets bool
}

func probeOne(ctx context.Context, p probeParams) error {
	var writer *capture.Writer
	if p.capturePath != "" {
		var err error
		writer, err = capture.NewWriter(capture.WriterOptions{
			Path:          p.capturePath,
			RemoteAddr:    p.remote,
			RecordSecrets: p.recordSecrets,
			Note:          fmt.Sprintf("vodoge-ike-probe IKE_SA_INIT to %s", p.remote),
			Warnf:         func(format string, args ...any) { fmt.Fprintf(os.Stderr, "WARNING: "+format+"\n", args...) },
		})
		if err != nil {
			return err
		}
		defer func() {
			if err := writer.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "capture close: %v\n", err)
				return
			}
			fmt.Printf("capture: %s (%d datagrams)\n", p.capturePath, writer.Count())
		}()
	}

	cfg := ike.SocketConfig{
		LocalPort: p.localPort,
		Remote:    p.remote,
		Capture:   writer,
		Retransmit: ike.RetransmitPolicy{
			Initial:    DefaultInitialWait,
			Multiplier: 1.8,
			Max:        20 * time.Second,
			Attempts:   p.attempts,
		},
	}
	if p.localIP != "" {
		ip := net.ParseIP(p.localIP)
		if ip == nil {
			return fmt.Errorf("cannot parse -local-ip %q", p.localIP)
		}
		cfg.LocalIP = ip
	}
	socket, err := ike.Listen(cfg)
	if err != nil {
		return err
	}
	defer socket.Close(context.Background())

	fmt.Printf("local %s -> remote %s\n", socket.LocalAddr(), p.remote)

	initCfg, err := ike.InitConfigFor(socket, ikev2.SecurityAssociation{})
	if err != nil {
		return err
	}
	runner := ike.NewInitRunner()
	runner.Groups = p.groups
	runner.Capture = writer

	runCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	result, err := runner.Run(runCtx, initCfg)
	detail, haveDetail := runner.LastDetail()
	if err != nil {
		if haveDetail && len(detail.GroupsTried) > 0 {
			fmt.Printf("groups tried: %v\n", detail.GroupsTried)
		}
		return err
	}

	fmt.Printf("IKE_SA_INIT complete\n")
	fmt.Printf("  SPIi/SPIr    %016x / %016x\n", result.InitiatorSPI, result.ResponderSPI)
	fmt.Printf("  selected     %s\n", detail.Selection)
	fmt.Printf("  suite        %s\n", detail.Selection.SuiteName)
	fmt.Printf("  groups tried %v\n", detail.GroupsTried)
	fmt.Printf("  cookie rnds  %d\n", detail.CookieRounds)
	fmt.Printf("  nonce i/r    %d / %d octets\n", len(result.NonceI), len(result.NonceR))
	fmt.Printf("  shared secr  %d octets\n", len(result.SharedSecret))
	fmt.Printf("  key material %d octets, SK_ei %d, SK_ai %d\n",
		len(result.KeyMaterial), len(result.Keys.SKEi), len(result.Keys.SKAi))
	fmt.Printf("  MOBIKE       %v\n", result.MOBIKESupported)
	fmt.Printf("  NAT-D sent   %v (responder echoed source=%v destination=%v)\n",
		detail.NAT.Sent, detail.NAT.ResponderSentSource, detail.NAT.ResponderSentDestination)
	fmt.Printf("  behind NAT   local=%v peer=%v\n", detail.NAT.BehindNAT, detail.NAT.PeerBehindNAT)

	stats := socket.Stats()
	fmt.Printf("  socket       sent=%d recv=%d retransmits=%d unmatched=%d foreign=%d\n",
		stats.IKESent, stats.IKEReceived, stats.IKERetransmits, stats.IKEUnmatchedDrops, stats.ForeignSourceDrops)
	fmt.Printf("\nThis proves reachability and algorithm selection only. IKE_SA_INIT carries\n")
	fmt.Printf("no identity, so it is not evidence that the carrier accepts this SIM.\n")
	return nil
}

// DefaultInitialWait is the first retransmission delay used by the probe.
const DefaultInitialWait = 2 * time.Second

func runReplay(ctx context.Context, path string, strict bool, exportAuthDir string) error {
	transport, seed, err := capture.OpenReplay(path, capture.ReplayOptions{
		UseNonESPMarker:      true,
		RequireExactRequests: strict,
	})
	if err != nil {
		return err
	}
	if !seed.Valid() {
		return fmt.Errorf("%s has no usable seed: it was recorded without -record-secrets, so a byte-exact replay is impossible", path)
	}
	c, err := capture.Open(path)
	if err != nil {
		return err
	}
	local, err := net.ResolveUDPAddr("udp", c.Session.LocalAddr)
	if err != nil {
		return fmt.Errorf("sidecar local_addr %q: %w", c.Session.LocalAddr, err)
	}
	remote, err := net.ResolveUDPAddr("udp", c.Session.RemoteAddr)
	if err != nil {
		return fmt.Errorf("sidecar remote_addr %q: %w", c.Session.RemoteAddr, err)
	}
	fmt.Printf("replaying %s: %d datagrams recorded %s\n", path, len(c.Records), c.Session.CreatedAt.Format(time.RFC3339))

	runner := ike.NewInitRunner()
	runner.Seed = seed
	result, err := runner.Run(ctx, ikev2.InitConfig{
		Transport:  transport,
		LocalIP:    local.IP,
		LocalPort:  uint16(local.Port),
		RemoteIP:   remote.IP,
		RemotePort: uint16(remote.Port),
	})
	if err != nil {
		return err
	}
	detail, _ := runner.LastDetail()
	fmt.Printf("replay reproduced the exchange\n")
	fmt.Printf("  SPIi/SPIr    %016x / %016x\n", result.InitiatorSPI, result.ResponderSPI)
	fmt.Printf("  selected     %s\n", detail.Selection)
	fmt.Printf("  SKEYSEED     %d octets\n", len(result.SKEYSEED))

	if err := replayAuthLadder(ctx, c, transport, result); err != nil {
		return err
	}
	fmt.Printf("  unconsumed   %d datagram(s)\n", transport.Remaining())
	return exportAuthPayloads(c, result.Keys, exportAuthDir)
}

// replayAuthLadder replays the IKE_AUTH ladder when the sidecar carries one.
//
// The extra seed material is not optional. IKE_SA_INIT needed a pinned SPI,
// nonce and DH scalar; IKE_AUTH additionally consumes a fresh child SPI, one CBC
// IV per protected message and the card's answers, and every one of those
// changes the ciphertext. A run that regenerated any of them would still finish,
// which is precisely the failure worth refusing: it would look like a successful
// replay while proving nothing about the recorded bytes.
func replayAuthLadder(ctx context.Context, c *capture.Capture, transport *capture.ReplayTransport, init ikev2.InitResult) error {
	seed := c.Session.AuthSeed
	if !seed.Valid() {
		fmt.Printf("  IKE_AUTH     not recorded (no auth seed in the sidecar)\n")
		return nil
	}
	runner := ike.NewAuthRunner(ikev2.Identity{Type: seed.ResponderIDType, Data: seed.ResponderID})
	runner.ChildSPI = seed.ChildSPI
	runner.PinnedIVs = seed.IVs
	auth, err := runner.Run(ctx, ikev2.FullAuthConfig{
		Transport:   transport,
		Init:        init,
		Keys:        init.Keys,
		SIM:         ike.NewRecordedAKAProvider(seed.AKA),
		InitiatorID: ikev2.Identity{Type: seed.InitiatorIDType, Data: seed.InitiatorID},
		EAPIdentity: seed.EAPIdentity,
	})
	detail, _ := runner.LastDetail()
	if err != nil {
		fmt.Printf("  IKE_AUTH     replay failed after %d exchange(s): %v\n", len(detail.Rounds), err)
		return err
	}
	fmt.Printf("  IKE_AUTH     %d exchange(s) reproduced byte for byte\n", len(detail.Rounds))
	fmt.Printf("  IDr sent     %v; EAP_ONLY_AUTHENTICATION sent %v\n", detail.SentIDr, detail.SentEAPOnlyNotify)
	fmt.Printf("  EAP-Success  message %d; CHILD_SA message %d\n",
		detail.EAPSuccessMessageID, detail.ChildSAMessageID)
	fmt.Printf("  peer AUTH    verified=%v method=%d\n", detail.PeerAuthVerified, detail.PeerAuthMethod)
	if auth.ChildSA != nil {
		fmt.Printf("  CHILD_SA     local SPI %x remote SPI %x\n", auth.ChildSA.LocalSPI, auth.ChildSA.RemoteSPI)
	}
	return nil
}

// exportAuthPayloads is the tool T041d will reach for first.
//
// When the first real ePDG rejects us, the question is "what exactly was in the
// AUTH payload, ours and theirs". Both live inside SK, so a pcap opened without
// keys shows nothing. The keys come back from replaying IKE_SA_INIT, so the
// recording plus its sidecar is enough - no live carrier, no hardware.
func exportAuthPayloads(c *capture.Capture, keys ikev2.IKEKeys, dir string) error {
	records, err := c.AuthPayloads(keys)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Printf("  AUTH         none in this recording\n")
		return nil
	}
	for _, rec := range records {
		value, parseErr := ike.ParseAuthPayload(rec.Body)
		reserved := ike.AuthPayloadReserved(rec.Body)
		if parseErr != nil {
			fmt.Printf("  AUTH %-2s msg %d  UNPARSEABLE (%d octets): %v\n",
				rec.Dir, rec.MessageID, len(rec.Body), parseErr)
			continue
		}
		fmt.Printf("  AUTH %-2s msg %d  method=%d reserved=%x data=%d octets encrypted=%v\n",
			rec.Dir, rec.MessageID, value.Method, reserved, len(value.Data), rec.Encrypted)
		fmt.Printf("               %x\n", value.Data)
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		name := filepath.Join(dir, fmt.Sprintf("msg%d-%s.auth.bin", rec.MessageID, rec.Dir))
		// The whole body, header included: the four-octet header is the part
		// most likely to be wrong and stripping it here would hide it.
		if err := os.WriteFile(name, rec.Body, 0o600); err != nil {
			return err
		}
		fmt.Printf("               wrote %s (%d octets, header included)\n", name, len(rec.Body))
	}
	return nil
}

func resolveCandidates(ctx context.Context, target string, port int) ([]*net.UDPAddr, error) {
	host := target
	if h, p, err := net.SplitHostPort(target); err == nil {
		host = h
		if parsed, convErr := strconv.Atoi(p); convErr == nil {
			port = parsed
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return []*net.UDPAddr{{IP: ip, Port: port}}, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w (the edge machine rewrites DNS into fake-IP 198.18.0.0/16; use an address or a DoH-resolved one)", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s resolved to nothing", host)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].String() < ips[j].String() })
	out := make([]*net.UDPAddr, 0, len(ips))
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		if strings.HasPrefix(ip.String(), "198.18.") {
			return nil, fmt.Errorf("%s resolved to %s, which is the edge fake-IP range: DNS was rewritten, not answered", host, ip)
		}
		out = append(out, &net.UDPAddr{IP: ip, Port: port})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s produced no usable addresses", host)
	}
	return out, nil
}

func parseGroups(list string) ([]uint16, error) {
	if strings.TrimSpace(list) == "" {
		return ike.DefaultProposalGroups(), nil
	}
	var out []uint16
	for _, field := range strings.Split(list, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		value, err := strconv.ParseUint(field, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("bad DH group %q: %w", field, err)
		}
		if !ike.DHGroupSupported(uint16(value)) {
			return nil, fmt.Errorf("DH group %d is not implemented; supported: %v", value, ike.SupportedDHGroups())
		}
		out = append(out, uint16(value))
	}
	if len(out) == 0 {
		return ike.DefaultProposalGroups(), nil
	}
	return out, nil
}

func capturePathFor(base string, index int) string {
	if base == "" {
		return ""
	}
	if index == 0 {
		return base
	}
	return fmt.Sprintf("%s.%d", base, index)
}

func joinAddrs(addrs []*net.UDPAddr) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}
