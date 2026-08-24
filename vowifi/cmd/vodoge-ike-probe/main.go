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
	"encoding/hex"
	"errors"
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

	"github.com/boa-z/vowifi-go/engine/sim"
	"github.com/boa-z/vowifi-go/engine/swu/ikev2"

	"github.com/yuanshuai1122/vodoge-edge/vowifi/internal/aka"
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
		akaSelftest   = flag.Bool("aka-selftest", false, "ask the AT lease socket for one AKA challenge and print what the card said; touches no network")
		akaSocket     = flag.String("aka-socket", "", "AT lease socket path (default: $VODOGE_AT_LEASE_SOCKET, then "+aka.DefaultSocketPath+")")
		akaIMEI       = flag.String("aka-imei", "", "which module to use; empty lets the daemon choose")
		akaTimeout    = flag.Duration("aka-timeout", aka.DefaultTimeout, "hard upper bound on one challenge")
		akaGrace      = flag.Duration("aka-grace", aka.DefaultGrace, "how long to keep waiting for the answer to an abandoned challenge, for the record")
		akaRAND       = flag.String("aka-rand", defaultAKARAND, "RAND as 32 hex digits")
		akaAUTN       = flag.String("aka-autn", defaultAKAAUTN, "AUTN as 32 hex digits")
		akaRepeat     = flag.Int("aka-repeat", 1, "how many challenges to send")

		auth      = flag.Bool("auth", false, "run the whole IKEv2 ladder against the ePDG this card names, with the card answering EAP-AKA")
		panelURL  = flag.String("panel", ike.DefaultPanelURL, "edge daemon panel base URL; the card readout comes from its /api/status")
		doh       = flag.String("doh", ike.DefaultDoHEndpoint, "DoH endpoint used to resolve the ePDG FQDN, because the box's own resolver answers everything from 198.18.0.0/16")
		keepalive = flag.Duration("keepalive", ike.DefaultKeepalivePeriod, "NAT-T keepalive interval, started as soon as IKE_SA_INIT completes; negative disables it")
		authWait  = flag.Duration("auth-timeout", ike.DefaultAuthTimeout, "deadline for the whole IKE_AUTH ladder")
		egress    = flag.String("egress-candidates", "", "comma-separated source IPs to try when reversing the responder's NAT_DETECTION_DESTINATION_IP (default: the two measured on this box)")
		dryRun    = flag.Bool("dry-run", false, "with -auth: derive the identity and resolve the ePDG, then stop without sending anything")
		idr       = flag.String("idr", "none", "which IDr to assert: none (the default; T041d measured T-Mobile US refusing every IKE_AUTH that carried one), card (the FQDN derived from the card), or dns (the canonical name that FQDN resolved to)")
		noEAPOnly = flag.Bool("no-eap-only", false, "drop N(EAP_ONLY_AUTHENTICATION) from the first IKE_AUTH request")
	)
	flag.Parse()

	groups, err := parseGroups(*groupList)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *akaSelftest {
		return runAKASelftest(akaSelftestParams{
			socket:  *akaSocket,
			imei:    *akaIMEI,
			timeout: *akaTimeout,
			grace:   *akaGrace,
			rand:    *akaRAND,
			autn:    *akaAUTN,
			repeat:  *akaRepeat,
		})
	}
	if *replayPath != "" {
		return runReplay(ctx, *replayPath, *strictReplay, *exportAuth)
	}
	if *auth {
		// -target is refused rather than ignored. The whole point of this mode
		// is that the ePDG name is derived from the card; accepting a name
		// here would put a human-chosen operator back into the one exchange
		// that exists to prove the operator was not human-chosen.
		if strings.TrimSpace(*target) != "" {
			return fmt.Errorf("-auth derives the ePDG from the card and refuses -target; " +
				"use -target without -auth for a reachability probe")
		}
		candidates, err := parseEgressCandidates(*egress)
		if err != nil {
			return err
		}
		return runLiveAuth(ctx, liveAuthParams{
			panelURL:      *panelURL,
			doh:           *doh,
			imei:          *akaIMEI,
			port:          *port,
			localIP:       *localIP,
			localPort:     uint16(*localPort),
			groups:        groups,
			initTimeout:   *timeout,
			authTimeout:   *authWait,
			keepalive:     *keepalive,
			attempts:      *attempts,
			capturePath:   *capturePath,
			recordSecrets: *recordSecrets,
			maxCandidates: *maxCandidates,
			akaSocket:     *akaSocket,
			akaTimeout:    *akaTimeout,
			akaGrace:      *akaGrace,
			egress:        candidates,
			dryRun:        *dryRun,
			idr:           strings.ToLower(strings.TrimSpace(*idr)),
			noEAPOnly:     *noEAPOnly,
		})
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
	fmt.Printf("  behind NAT   local=%v peer=%v\n", detail.NAT.BehindNAT, detail.NAT.PeerBehindNAT)
	// Which egress the responder saw is worth knowing here too, and this is the
	// cheap place to learn it: a reachability probe carries no identity and can
	// be run before the card is switched, so the egress question is answered
	// before the run that costs an SQN step.
	reportEgress(detail.NAT, result.InitiatorSPI, result.ResponderSPI, p.remote, nil)

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

	// The ladder error is held rather than returned. A recording of a rejected
	// exchange is the one most worth exporting, and returning here would make
	// -export-auth work only on the runs that did not need it.
	ladderErr := replayAuthLadder(ctx, c, transport, result)
	fmt.Printf("  unconsumed   %d datagram(s)\n", transport.Remaining())
	if err := exportAuthPayloads(c, result.Keys, exportAuthDir); err != nil {
		return err
	}
	return ladderErr
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
	// A recording with no IDr in its seed is a recording of a run that sent no
	// IDr, and T041d found that T-Mobile answers AUTHENTICATION_FAILED to the
	// ones that do. Refusing to replay it would make the single most important
	// capture in this repository unreplayable. Strict mode still asserts the
	// request bytes, so if the recording really did carry an IDr the replay
	// fails on the comparison rather than on this decision.
	if seed.ResponderIDType == 0 || len(seed.ResponderID) == 0 {
		runner.AllowMissingResponderID = true
	}
	// The card's answers, out of the sidecar. This is the criterion 2b evidence
	// and it is readable with no hardware, no carrier and no live run - which is
	// the whole point of having recorded it.
	for i, v := range seed.AKA {
		fmt.Printf("  AKA vector %d (from the recording, not from a card)\n", i+1)
		fmt.Printf("    AT_RAND  %X\n", v.RAND)
		fmt.Printf("    AT_AUTN  %X\n", v.AUTN)
		if v.Failure == "" {
			fmt.Printf("    RES      %X\n", v.RES)
			fmt.Printf("    CK/IK    %d/%d octets (not printed)\n", len(v.CK), len(v.IK))
		} else {
			fmt.Printf("    failure  %s (AUTS %X)\n", v.Failure, v.AUTS)
		}
	}

	auth, err := runner.Run(ctx, ikev2.FullAuthConfig{
		Transport:   transport,
		Init:        init,
		Keys:        init.Keys,
		SIM:         ike.NewRecordedAKAProvider(seed.AKA),
		InitiatorID: ikev2.Identity{Type: seed.InitiatorIDType, Data: seed.InitiatorID},
		EAPIdentity: seed.EAPIdentity,
	})
	detail, _ := runner.LastDetail()
	if detail.EAPSuccessMessageID != 0 {
		fmt.Printf("  EAP-Success  message %d (reproduced from the recording)\n", detail.EAPSuccessMessageID)
	}
	for _, n := range detail.ResponseNotifies {
		fmt.Printf("  notify       msg %d type %d data %x\n", n.MessageID, n.Type, n.Data)
	}
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

// The synthetic challenge T033 and T047 used on the bench. Both eUICCs answered
// 9862 to it, so it is the pair to reach for when the question is "is the path
// alive", as opposed to "what does this card do with a well-formed AUTN".
const (
	defaultAKARAND = "000102030405060708090A0B0C0D0E0F"
	defaultAKAAUTN = "101112131415161718191A1B1C1D1E1F"
)

type akaSelftestParams struct {
	socket  string
	imei    string
	timeout time.Duration
	grace   time.Duration
	rand    string
	autn    string
	repeat  int
}

// runAKASelftest asks the card one question and prints the answer verbatim.
//
// This is the forensics mode. The interesting evidence on this path is not
// "did it work" - it is which status word a particular card produces for a
// particular AUTN, because that mapping is the one thing on the whole path that
// cannot be established by reading a specification. The three sources that
// disagree about 98xx all sound confident.
//
// It sends `authenticate` and nothing else. The lease also speaks `execute_at`,
// which would run any AT command at all; this tool has no way to ask for that
// and must not grow one.
//
// It touches no network. A challenge does touch the card: an AUTHENTICATE the
// card accepts advances SQN, which is normal and is what the network expects,
// but it is the reason this is not something to run in a loop for fun.
func runAKASelftest(p akaSelftestParams) error {
	randBytes, err := hex.DecodeString(strings.TrimSpace(p.rand))
	if err != nil || len(randBytes) != 16 {
		return fmt.Errorf("-aka-rand must be 32 hex digits: %q", p.rand)
	}
	autnBytes, err := hex.DecodeString(strings.TrimSpace(p.autn))
	if err != nil || len(autnBytes) != 16 {
		return fmt.Errorf("-aka-autn must be 32 hex digits: %q", p.autn)
	}
	if p.repeat < 1 {
		p.repeat = 1
	}

	// A challenge that timed out is not over: the daemon is still running it and
	// will answer into a connection the caller has walked away from. Waiting for
	// that answer before exiting is the only way to record what the abandoned
	// exchange actually did, and "what did the abandoned exchange do" is the
	// question this whole mode exists to answer.
	late := make(chan struct{}, 64)
	provider := &aka.Provider{
		SocketPath: p.socket,
		IMEI:       p.imei,
		Timeout:    p.timeout,
		Grace:      p.grace,
		Observe: func(o aka.Observation) {
			printAKAObservation(o)
			if o.Late {
				late <- struct{}{}
			}
		},
	}
	fmt.Printf("AT lease     %s\n", provider.SocketPathOrDefault())
	fmt.Printf("module       %s\n", orAny(p.imei))
	fmt.Printf("deadline     %s (grace %s)\n", p.timeout, p.grace)
	fmt.Printf("RAND         %s\n", strings.ToUpper(hex.EncodeToString(randBytes)))
	fmt.Printf("AUTN         %s\n", strings.ToUpper(hex.EncodeToString(autnBytes)))

	var failures, abandoned int
	for i := 0; i < p.repeat; i++ {
		fmt.Printf("\n--- challenge %d/%d ---\n", i+1, p.repeat)
		result, err := provider.CalculateAKA(randBytes, autnBytes)
		switch {
		case err == nil:
			// RES goes on the wire inside EAP, so printing it costs nothing.
			// CK and IK are session key material and only their lengths are
			// printed: a receipt that quoted them would be a receipt nobody
			// could safely paste anywhere.
			fmt.Printf("  verdict    accepted; RES %s, CK %d octets, IK %d octets\n",
				strings.ToUpper(hex.EncodeToString(result.RES)), len(result.CK), len(result.IK))
		case errors.Is(err, sim.ErrAuthFailure):
			fmt.Printf("  verdict    the card rejected the challenge -> sim.ErrAuthFailure "+
				"(eapaka sends EAP-Response/AKA-Authentication-Reject)\n    %v\n", err)
		case errors.Is(err, sim.ErrSyncFailure):
			var carrier interface{ AUTS() []byte }
			auts := []byte(nil)
			if errors.As(err, &carrier) {
				auts = carrier.AUTS()
			}
			fmt.Printf("  verdict    resynchronisation -> sim.ErrSyncFailure, AUTS %s "+
				"(eapaka sends AT_AUTS)\n", strings.ToUpper(hex.EncodeToString(auts)))
		case errors.Is(err, aka.ErrTimeout):
			failures++
			abandoned++
			fmt.Printf("  verdict    NO ANSWER within the bound. This is not a card verdict and is\n" +
				"             deliberately not retried; the exchange is still running on the daemon,\n" +
				"             so the next challenge may queue behind it.\n")
			fmt.Printf("    %v\n", err)
		default:
			failures++
			fmt.Printf("  verdict    not a card verdict: %v\n", err)
		}
	}
	for i := 0; i < abandoned; i++ {
		fmt.Printf("\nwaiting up to %s for the answer to an abandoned challenge...\n", p.grace)
		select {
		case <-late:
		case <-time.After(p.grace + time.Second):
			fmt.Printf("  it never came. The module is still held by whatever is in front of it.\n")
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d challenge(s) did not reach the card", failures, p.repeat)
	}
	return nil
}

// printAKAObservation prints the daemon's own words, uninterpreted. This is the
// line a receipt quotes.
func printAKAObservation(o aka.Observation) {
	tag := "answer"
	if o.Late {
		tag = "LATE answer to an abandoned challenge"
	}
	fmt.Printf("  %s after %s\n", tag, o.Elapsed.Round(time.Millisecond))
	if o.Outcome != "" {
		fmt.Printf("    outcome  %s\n", o.Outcome)
	}
	if o.StatusWord != "" {
		fmt.Printf("    sw       %s\n", o.StatusWord)
	}
	if o.Detail != "" {
		fmt.Printf("    detail   %s\n", o.Detail)
	}
	if o.ErrorCode != "" {
		fmt.Printf("    error    %s: %s\n", o.ErrorCode, o.Message)
	}
}

func orAny(imei string) string {
	if strings.TrimSpace(imei) == "" {
		return "(daemon's choice)"
	}
	return imei
}

// MaxLiveAuthCandidates bounds how many ePDG addresses a live run will try.
//
// Three, and it is a hard number rather than a default. Two things make this
// unlike the reachability probe: a Challenge the card accepts advances SQN, and
// the GSLB behind the ePDG name hands out a different address on every lookup,
// so "try them all" is unbounded. If three nodes in a row will not answer
// IKE_SA_INIT, that is a network result and the fourth attempt is not evidence,
// it is impatience.
const MaxLiveAuthCandidates = 3

type liveAuthParams struct {
	panelURL      string
	doh           string
	imei          string
	port          int
	localIP       string
	localPort     uint16
	groups        []uint16
	initTimeout   time.Duration
	authTimeout   time.Duration
	keepalive     time.Duration
	attempts      int
	capturePath   string
	recordSecrets bool
	maxCandidates int
	akaSocket     string
	akaTimeout    time.Duration
	akaGrace      time.Duration
	egress        []net.IP
	idr           string
	noEAPOnly     bool
	responderID   ikev2.Identity
	dryRun        bool
}

// runLiveAuth is T041d: the first contact.
//
// The order of the first three steps is the load-bearing part. The card is read
// first, the ePDG name is derived from that reading, and only then is anything
// resolved or dialled - so there is no point in this program at which an
// operator identity could have come from a flag, a config file or a constant.
// Goal oracle criterion 2b rejects an identity we chose, and the cheapest way
// to be able to say we did not choose one is to have nowhere to put it.
func runLiveAuth(ctx context.Context, p liveAuthParams) error {
	readout, err := ike.FetchCardReadout(ctx, p.panelURL, p.imei)
	if err != nil {
		return err
	}
	subscription, err := readout.Subscription()
	if err != nil {
		return err
	}
	fmt.Printf("card readout\n")
	fmt.Printf("  ICCID      %s\n", readout.ICCID)
	fmt.Printf("  state      %s (registration is not required for this exchange; the ePDG is\n"+
		"             reached over the public internet and the card only has to be enabled)\n", readout.State)
	for _, line := range subscription.Describe() {
		fmt.Printf("  %s\n", line)
	}

	fqdn := subscription.EPDGFQDN()
	resolver := &ike.DoHResolver{Endpoint: p.doh}
	answer, err := resolver.LookupA(ctx, fqdn)
	if err != nil {
		return err
	}
	fmt.Printf("\nDNS over %s\n", answer.Endpoint)
	for _, hop := range answer.Chain {
		fmt.Printf("  %s\n", hop)
	}

	// The IDr choice, made here rather than inside the tunnel, because it is a
	// diagnostic axis and not a property of the subscription. Every option is
	// still derived: "card" is the name the IMSI produces, "dns" is the name
	// that name resolved to. Neither is typed in.
	switch p.idr {
	case "", "none":
		p.idr = "none"
	case "card":
		p.responderID = subscription.ResponderIdentity()
	case "dns":
		if answer.Canonical == "" {
			return fmt.Errorf("-idr dns: the lookup returned no canonical name to use")
		}
		p.responderID = ike.IdentityFQDN(answer.Canonical)
	default:
		return fmt.Errorf("-idr %q: want none, card or dns", p.idr)
	}
	fmt.Printf("  IDr        %s\n", describeIDr(p, subscription))
	fmt.Printf("  EAP-only   %v\n", !p.noEAPOnly)

	limit := p.maxCandidates
	if limit <= 0 || limit > MaxLiveAuthCandidates {
		limit = MaxLiveAuthCandidates
	}
	candidates := make([]*net.UDPAddr, 0, len(answer.IPs))
	for _, ip := range answer.IPs {
		candidates = append(candidates, &net.UDPAddr{IP: ip, Port: p.port})
	}
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	fmt.Printf("  trying     %s\n", joinAddrs(candidates))

	if p.dryRun {
		fmt.Printf("\n-dry-run: nothing was sent. The card was read, the name was derived from it,\n" +
			"and the name resolved. No packet reached a carrier and no challenge reached the card.\n")
		return nil
	}

	egressCandidates := p.egress
	if len(egressCandidates) == 0 {
		egressCandidates = ike.KnownEgressIPs()
	}

	var failures []string
	for i, candidate := range candidates {
		fmt.Printf("\n--- candidate %d/%d: %s ---\n", i+1, len(candidates), candidate)
		result, err := liveAuthOnce(ctx, p, subscription, candidate, i, egressCandidates)
		reportLiveResult(result, err)
		if err == nil {
			return nil
		}
		failures = append(failures, fmt.Sprintf("%s: %s: %v", candidate, result.Outcome, err))
		// A carrier that put a challenge in front of the card has already told
		// us the thing worth knowing. Trying the next node would spend another
		// SQN step to learn nothing new.
		if result.SawCarrierChallenge() {
			return fmt.Errorf("%s: %w", result.Outcome, err)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return fmt.Errorf("all %d candidate(s) failed:\n  %s", len(candidates), strings.Join(failures, "\n  "))
}

func liveAuthOnce(
	ctx context.Context,
	p liveAuthParams,
	subscription ike.Subscription,
	remote *net.UDPAddr,
	index int,
	egress []net.IP,
) (ike.LiveResult, error) {
	var writer *capture.Writer
	if path := capturePathFor(p.capturePath, index); path != "" {
		var err error
		writer, err = capture.NewWriter(capture.WriterOptions{
			Path:          path,
			RemoteAddr:    remote,
			RecordSecrets: p.recordSecrets,
			Note: fmt.Sprintf("vodoge-ike-probe live IKE_AUTH to %s (%s) for IMSI %s on %s",
				remote, subscription.EPDGFQDN(), subscription.IMSI, subscription.IMEI),
			Warnf: func(format string, args ...any) { fmt.Fprintf(os.Stderr, "WARNING: "+format+"\n", args...) },
		})
		if err != nil {
			return ike.LiveResult{}, err
		}
		defer func() {
			if err := writer.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "capture close: %v\n", err)
				return
			}
			fmt.Printf("  capture    %s (%d datagrams)\n", path, writer.Count())
			fmt.Printf("             replay: vodoge-ike-probe -replay %s -export-auth %s.auth\n", path, path)
		}()
	}

	cfg := ike.SocketConfig{
		LocalPort: p.localPort,
		Remote:    remote,
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
			return ike.LiveResult{}, fmt.Errorf("cannot parse -local-ip %q", p.localIP)
		}
		cfg.LocalIP = ip
	}
	socket, err := ike.Listen(cfg)
	if err != nil {
		return ike.LiveResult{}, err
	}
	defer func() { _ = socket.Close(context.Background()) }()
	fmt.Printf("  socket     local %s -> remote %s\n", socket.LocalAddr(), remote)

	// The card, and nothing else. aka.Provider speaks one operation to the
	// lease socket and this tool has no flag that could ask for another.
	provider := &aka.Provider{
		SocketPath: p.akaSocket,
		IMEI:       subscription.IMEI,
		Timeout:    p.akaTimeout,
		Grace:      p.akaGrace,
		Observe:    printAKAObservation,
	}
	fmt.Printf("  AT lease   %s (module %s)\n", provider.SocketPathOrDefault(), subscription.IMEI)

	result, runErr := ike.RunLiveTunnel(ctx, ike.LiveConfig{
		Socket:       socket,
		Subscription: subscription,
		AKA:          provider,
		ResponderID:  p.responderID,

		DisableEAPOnly:  p.noEAPOnly,
		Groups:          p.groups,
		Capture:         writer,
		KeepalivePeriod: p.keepalive,
		InitTimeout:     p.initTimeout,
		AuthTimeout:     p.authTimeout,
		Log:             func(format string, args ...any) { fmt.Printf("  "+format+"\n", args...) },
	})
	if result.InitDone {
		reportEgress(result.InitDetail.NAT, result.Init.InitiatorSPI, result.Init.ResponderSPI, remote, egress)
	}
	stats := socket.Stats()
	fmt.Printf("  socket     sent=%d recv=%d retransmits=%d unmatched=%d foreign=%d keepalives=%d\n",
		stats.IKESent, stats.IKEReceived, stats.IKERetransmits, stats.IKEUnmatchedDrops,
		stats.ForeignSourceDrops, stats.KeepalivesSent)
	return result, runErr
}

// reportEgress answers "which of this box's two UDP exits did the carrier see".
//
// It is not cosmetic. A US carrier's ePDG applies policy to the source address,
// and this box reaches some destinations through a Beijing CGNAT and others
// through a GCP node in Dallas (T038 section 7). Reading the answer out of the
// responder's own NAT-D hash is the only measurement available from inside the
// VM, and T038 established that it is exact: six lookups, six unique hits.
func reportEgress(nat ike.NATDetection, spiI, spiR uint64, remote *net.UDPAddr, candidates []net.IP) {
	fmt.Printf("  NAT-D      sent=%v; responder echoed source=%v destination=%v\n",
		nat.Sent, nat.ResponderSentSource, nat.ResponderSentDestination)
	if len(candidates) == 0 {
		candidates = ike.KnownEgressIPs()
	}
	if len(nat.PeerDestinationHash) == 0 {
		fmt.Printf("  egress     unmeasurable: this responder sent no NAT_DETECTION_DESTINATION_IP,\n" +
			"             so the apparent source address cannot be recovered from this exchange\n")
		return
	}
	endpoint, ok := ike.SolveApparentEndpoint(nat.PeerDestinationHash, spiI, spiR, candidates)
	if !ok {
		names := make([]string, 0, len(candidates))
		for _, ip := range candidates {
			names = append(names, ip.String())
		}
		fmt.Printf("  egress     the responder hash matches none of %v on any port;\n"+
			"             we left this box by a third path nobody has recorded\n", names)
		return
	}
	fmt.Printf("  egress     %s as %s saw us (recovered from its NAT-D hash)\n", endpoint, remote.IP)
}

// reportLiveResult prints the verdict in the terms goal oracle criterion 2b is
// written in, and refuses to round a refusal up to a success.
func reportLiveResult(result ike.LiveResult, err error) {
	fmt.Printf("\n  outcome    %s\n", result.Outcome)
	fmt.Printf("  meaning    %s\n", wrapIndent(result.Outcome.Explain(), "             "))
	if err != nil {
		fmt.Printf("  error      %v\n", err)
	}
	detail := result.AuthDetail
	if result.AuthAttempted {
		fmt.Printf("  IKE_AUTH   %d exchange(s); IDr sent %v; EAP_ONLY_AUTHENTICATION sent %v; peer sent IDr %v\n",
			len(detail.Rounds), detail.SentIDr, detail.SentEAPOnlyNotify, detail.PeerSentIDr)
		if len(detail.PeerIDBody) > 0 {
			fmt.Printf("  peer IDr   %x\n", detail.PeerIDBody)
		}
		for _, n := range detail.ResponseNotifies {
			if len(n.Malformed) > 0 {
				fmt.Printf("  notify     msg %d UNPARSEABLE %x\n", n.MessageID, n.Malformed)
				continue
			}
			fmt.Printf("  notify     msg %d type %d (%s) data %x\n", n.MessageID, n.Type, notifyName(n.Type), n.Data)
		}
		// EAP-Success is the carrier's verdict on the RES, and it is a
		// different claim from "the card produced one". Printing the message it
		// arrived in keeps the two separable in the receipt.
		if detail.EAPSuccessMessageID != 0 {
			fmt.Printf("  EAP-Success message %d: the operator accepted the RES\n", detail.EAPSuccessMessageID)
		} else if result.AuthAttempted {
			fmt.Printf("  EAP-Success none: the operator never accepted an EAP exchange\n")
		}
		if detail.ChildSAMessageID != 0 {
			fmt.Printf("  CHILD_SA   message %d\n", detail.ChildSAMessageID)
		}
		if detail.EarlyPeerAuthMethod != 0 {
			fmt.Printf("  peer AUTH  method %d arrived before EAP finished: the responder ignored RFC 5998\n",
				detail.EarlyPeerAuthMethod)
		}
		if len(detail.LocalAuth) > 0 {
			fmt.Printf("  our AUTH   method %d, %d octets\n", detail.LocalAuthMethod, len(detail.LocalAuth))
		}
		if len(detail.PeerAuth) > 0 {
			fmt.Printf("  peer AUTH  method %d verified=%v\n", detail.PeerAuthMethod, detail.PeerAuthVerified)
		}
	}

	vectors := result.Challenges()
	if len(vectors) == 0 {
		fmt.Printf("  criterion  2b NOT MET: no EAP-AKA Challenge from this carrier ever reached the card.\n")
		return
	}
	fmt.Printf("  criterion  2b first half MET: this carrier put %d EAP-AKA Challenge(s) in front of\n"+
		"             the enabled profile on the bench eUICC.\n", len(vectors))
	for i, v := range vectors {
		fmt.Printf("  challenge %d\n", i+1)
		fmt.Printf("    AT_RAND  %X\n", v.RAND)
		fmt.Printf("    AT_AUTN  %X\n", v.AUTN)
		switch v.Failure {
		case "":
			// RES travels inside EAP on the wire, so printing it costs nothing.
			// CK and IK are session key material: lengths only, so this output
			// is safe to paste into a receipt.
			fmt.Printf("    RES      %X\n", v.RES)
			fmt.Printf("    CK/IK    %d/%d octets (not printed)\n", len(v.CK), len(v.IK))
		case "sync":
			fmt.Printf("    verdict  the card asked to resynchronise; AT_AUTS %X\n", v.AUTS)
			fmt.Printf("    2b       second half NOT met by this challenge\n")
		case "auth":
			fmt.Printf("    verdict  the card REFUSED this challenge (see the status word above)\n")
			fmt.Printf("    2b       second half NOT met: the challenge was real, the RES was not produced\n")
		default:
			fmt.Printf("    verdict  the card was not reached: %s. Not a card verdict.\n", v.Failure)
		}
	}
	if result.CardAnsweredChallenge() {
		fmt.Printf("  criterion  2b second half MET: the RES above was computed by the enabled profile\n" +
			"             on the bench eUICC from the carrier own RAND/AUTN.\n")
	}
}

// notifyName labels the notify types that actually turn up in an IKE_AUTH
// rejection. Anything else prints as its number rather than as a guess.
func notifyName(value uint16) string {
	switch value {
	case 14:
		return "NO_PROPOSAL_CHOSEN"
	case 17:
		return "INVALID_SYNTAX"
	case 24:
		return "AUTHENTICATION_FAILED"
	case 34:
		return "SINGLE_PAIR_REQUIRED"
	case 35:
		return "NO_ADDITIONAL_SAS"
	case 36:
		return "INTERNAL_ADDRESS_FAILURE"
	case 37:
		return "FAILED_CP_REQUIRED"
	case 38:
		return "TS_UNACCEPTABLE"
	case 39:
		return "INVALID_SELECTORS"
	case 16385:
		return "INITIAL_CONTACT"
	case 16388:
		return "NAT_DETECTION_SOURCE_IP"
	case 16389:
		return "NAT_DETECTION_DESTINATION_IP"
	case 16396:
		return "IPCOMP_SUPPORTED"
	case 16403:
		return "MOBIKE_SUPPORTED"
	case ike.NotifyEAPOnlyAuthentication:
		return "EAP_ONLY_AUTHENTICATION"
	default:
		return "unnamed"
	}
}

func wrapIndent(text, indent string) string {
	return strings.ReplaceAll(text, "\n", "\n"+indent)
}

func parseEgressCandidates(list string) ([]net.IP, error) {
	if strings.TrimSpace(list) == "" {
		return nil, nil
	}
	var out []net.IP
	for _, field := range strings.Split(list, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		ip := net.ParseIP(field)
		if ip == nil {
			return nil, fmt.Errorf("bad -egress-candidates entry %q", field)
		}
		out = append(out, ip)
	}
	return out, nil
}

// describeIDr names the IDr and, more importantly, where it came from. On a
// rejected first contact the provenance is the part that has to survive into
// the receipt.
func describeIDr(p liveAuthParams, subscription ike.Subscription) string {
	switch {
	case len(p.responderID.Data) == 0:
		return "(omitted - the default, because T041d measured every IKE_AUTH carrying one " +
			"coming back AUTHENTICATION_FAILED from T-Mobile US)"
	case string(p.responderID.Data) == subscription.EPDGFQDN():
		return string(p.responderID.Data) + " (derived from the card's MCC/MNC)"
	default:
		return string(p.responderID.Data) + " (the canonical name the card-derived FQDN resolved to)"
	}
}
