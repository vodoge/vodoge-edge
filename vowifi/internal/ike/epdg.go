package ike

// ePDG discovery and subscriber identity, both derived from what the card says.
//
// Goal oracle criterion 2b refuses any identity we chose ourselves. The MCC and
// MNC that go into the ePDG FQDN, and the IMSI that goes into the IMPI, must
// come off the eUICC that is going to answer the AKA challenge - otherwise the
// run proves that some operator accepted some subscriber, which is not the
// claim. So there is no flag anywhere in this package that sets an MCC, an MNC,
// an IMSI or an IMPI: the only constructor takes a card readout and refuses one
// that does not hang together.
//
// The DNS half is here for the same reason. The edge box answers every name out
// of a fake-IP range (T036: even a random name gets 198.18.0.x), so the system
// resolver cannot be used to find the ePDG, and pasting an address in by hand
// would take the FQDN - the card-derived part - back out of the loop. DoH keeps
// the card-derived name as the thing that is actually resolved.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

// Errors from ePDG discovery and identity derivation.
var (
	// ErrCardReadout means the readout itself is missing or malformed, i.e.
	// there is nothing to derive from. It is deliberately distinct from a
	// derivation that produced a wrong-looking answer.
	ErrCardReadout = errors.New("vowifi/ike: card readout is unusable")
	// ErrInconsistentReadout means the IMSI and the home PLMN disagree. That is
	// worth stopping for: one of the two is not coming off this card.
	ErrInconsistentReadout = errors.New("vowifi/ike: IMSI and home PLMN disagree")
	// ErrAmbiguousMNCLength means the readout cannot say whether the MNC is two
	// or three digits. See Subscription for why that is not recoverable here.
	ErrAmbiguousMNCLength = errors.New("vowifi/ike: MNC length is ambiguous in this readout")
	// ErrModemNotFound means the panel does not know the module we were told to
	// use.
	ErrModemNotFound = errors.New("vowifi/ike: no such modem in the panel readout")
	// ErrFakeIPAnswer means DNS answered out of 198.18.0.0/16, which on this box
	// means the name was rewritten rather than resolved (T036).
	ErrFakeIPAnswer = errors.New("vowifi/ike: DNS answered from the edge fake-IP range")
	// ErrNoAddress means the lookup produced no usable A record.
	ErrNoAddress = errors.New("vowifi/ike: name resolved to no usable address")
)

// MinMNCDigits and MaxMNCDigits bound an MNC. 3GPP TS 23.003 section 2.2.
const (
	MinMNCDigits = 2
	MaxMNCDigits = 3
)

// Subscription is one card's identity, as read off that card.
//
// IMEI is in here only to say which module answered. It never goes on the wire:
// criterion 2b names a self-supplied IMEI as inadmissible, and nothing in this
// package puts one in an IKEv2 payload.
type Subscription struct {
	// IMEI selects the module. Hardware selector, not an identity claim.
	IMEI string
	// IMSI as the card reports it, digits only.
	IMSI string
	// MCC is the first three IMSI digits.
	MCC string
	// MNC is the next two or three IMSI digits, verbatim - leading zeros
	// included, because "00" and "000" are different networks.
	MNC string
	// Source records where the readout came from, so a receipt can say.
	Source string
	// HomePLMN is the readout's own rendering of the home network, kept for the
	// same reason.
	HomePLMN string
}

// DeriveSubscription turns a card readout into an ePDG identity, or refuses.
//
// The MNC length is the whole difficulty. Only the card knows it (EF_AD byte 4,
// low nibble) and getting it wrong is silent: 310240 cut at two digits is the
// unassigned pair 310-24 and the FQDN mnc024, which resolves to nothing that
// will ever say so. The edge daemon reads EF_AD and reports the split, but it
// renders it with `format!("{:03}-{:02}")` (edge-core/src/network.rs:115-117)
// through a u16, so a three-digit MNC beginning with a zero comes back
// indistinguishable from a two-digit one.
//
// Rather than trust either half alone, this cross-checks them: the MNC digits
// are taken from the IMSI verbatim, and the readout's home PLMN is used only to
// decide how many of them to take. A length that cannot be settled that way is
// ErrAmbiguousMNCLength rather than a guess, because a guess here produces a
// plausible wrong network and criterion 2a was about exactly these digits.
func DeriveSubscription(imei, imsi, homePLMN, source string) (Subscription, error) {
	imei = strings.TrimSpace(imei)
	imsi = strings.TrimSpace(imsi)
	homePLMN = strings.TrimSpace(homePLMN)
	if imsi == "" {
		return Subscription{}, fmt.Errorf("%w: no IMSI", ErrCardReadout)
	}
	if !isDigits(imsi) {
		return Subscription{}, fmt.Errorf("%w: IMSI %q is not decimal", ErrCardReadout, imsi)
	}
	// TS 23.003 section 2.2: at most 15 digits, and MCC plus a two-digit MNC is
	// already five, so anything shorter than six cannot name a network.
	if len(imsi) < 6 || len(imsi) > 15 {
		return Subscription{}, fmt.Errorf("%w: IMSI has %d digits", ErrCardReadout, len(imsi))
	}
	mccText, mncText, err := splitPLMN(homePLMN)
	if err != nil {
		return Subscription{}, err
	}
	if imsi[:3] != mccText {
		return Subscription{}, fmt.Errorf("%w: IMSI starts %q but the home PLMN says MCC %q",
			ErrInconsistentReadout, imsi[:3], mccText)
	}
	want, err := strconv.Atoi(mncText)
	if err != nil {
		return Subscription{}, fmt.Errorf("%w: MNC %q is not decimal", ErrCardReadout, mncText)
	}
	var matches []string
	for digits := MinMNCDigits; digits <= MaxMNCDigits; digits++ {
		if len(imsi) < 3+digits {
			continue
		}
		candidate := imsi[3 : 3+digits]
		got, convErr := strconv.Atoi(candidate)
		if convErr != nil || got != want {
			continue
		}
		matches = append(matches, candidate)
	}
	switch len(matches) {
	case 1:
	case 0:
		return Subscription{}, fmt.Errorf("%w: no %d..%d digit prefix of IMSI %q after the MCC equals MNC %q",
			ErrInconsistentReadout, MinMNCDigits, MaxMNCDigits, imsi, mncText)
	default:
		return Subscription{}, fmt.Errorf("%w: IMSI %q with home PLMN %q fits both %q and %q; "+
			"the readout lost the leading zero and EF_AD is the only thing that can settle it",
			ErrAmbiguousMNCLength, imsi, homePLMN, matches[0], matches[1])
	}
	return Subscription{
		IMEI:     imei,
		IMSI:     imsi,
		MCC:      mccText,
		MNC:      matches[0],
		Source:   source,
		HomePLMN: homePLMN,
	}, nil
}

func splitPLMN(value string) (string, string, error) {
	mcc, mnc, ok := strings.Cut(value, "-")
	if !ok {
		return "", "", fmt.Errorf("%w: home PLMN %q is not MCC-MNC", ErrCardReadout, value)
	}
	mcc, mnc = strings.TrimSpace(mcc), strings.TrimSpace(mnc)
	if len(mcc) != 3 || !isDigits(mcc) {
		return "", "", fmt.Errorf("%w: MCC %q is not three digits", ErrCardReadout, mcc)
	}
	if len(mnc) < MinMNCDigits || len(mnc) > MaxMNCDigits || !isDigits(mnc) {
		return "", "", fmt.Errorf("%w: MNC %q is not %d..%d digits", ErrCardReadout, mnc, MinMNCDigits, MaxMNCDigits)
	}
	return mcc, mnc, nil
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// PadMNC left-pads an MNC to three digits.
//
// Three, not four and not two. 3GPP TS 23.003 section 19.4.2.4 writes the label
// as mnc<MNC> with the MNC padded to three digits, and the mirror does the same
// at engine/swu/ike_tunnel_manager.go:668. So 240 stays 240 and 00 becomes 000;
// a two-digit MNC written as mnc00, or a three-digit one written as mnc0240,
// names a host that does not exist.
func PadMNC(mnc string) string {
	for len(mnc) < 3 {
		mnc = "0" + mnc
	}
	return mnc
}

// EPDGFQDN is the ePDG name for this subscription.
//
// Same format string as the mirror's epdgAddressForTunnel
// (engine/swu/ike_tunnel_manager.go:659-669), reproduced rather than called
// because that function is unexported and takes a swu.TunnelConfig whose MCC
// and MNC would then be ours to fill in - which is the thing criterion 2b
// refuses.
func (s Subscription) EPDGFQDN() string {
	return fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", PadMNC(s.MNC), s.MCC)
}

// IMPI is the EAP-AKA permanent identity, i.e. the private user identity.
//
// TS 23.003 section 14.2: "0" for EAP-AKA, then the IMSI, then the operator
// realm. Same construction as the mirror's eapIdentityForTunnel
// (engine/swu/ike_tunnel_manager.go:671-688), and note the realm is
// nai.epc... while the ePDG name is epc... - they are different labels and
// swapping them is a silent failure.
func (s Subscription) IMPI() string {
	return fmt.Sprintf("0%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org", s.IMSI, PadMNC(s.MNC), s.MCC)
}

// InitiatorIdentity is the IDi: the IMPI as an RFC 822 address.
func (s Subscription) InitiatorIdentity() ikev2.Identity {
	return ikev2.Identity{Type: ikev2.IDRFC822Addr, Data: []byte(s.IMPI())}
}

// ResponderIdentity is the IDr: the ePDG FQDN, per TS 24.302 section 7.2.2.
func (s Subscription) ResponderIdentity() ikev2.Identity {
	return IdentityFQDN(s.EPDGFQDN())
}

// WellKnownIMSAPN is the APN Network Identifier every IMS deployment uses.
//
// It is a well-known constant, not an identity: GSMA IR.92 section 4.1 and
// 3GPP TS 23.003 section 9.1 both fix the IMS well-known APN as "ims", and
// every operator identifier around it is still derived from the card. It is a
// parameter rather than a literal because an operator that used a different
// APN Network Identifier would need one word changed, not a rebuild of the
// derivation chain - and because a receipt should be able to say which APN was
// asked for.
const WellKnownIMSAPN = "ims"

// APNFQDN is the TS 23.003 section 19.4.2.4 APN-FQDN:
//
//	<APN Network Identifier>.apn.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
//
// The operator half comes from the card, exactly as EPDGFQDN's does. Only the
// APN Network Identifier is supplied, and TS 23.003 calls that a network
// configuration name rather than a subscriber identity - it names the packet
// data network to attach to, and every subscriber on the operator uses the same
// one.
//
// This is the payload TS 24.302 section 7.2.2 puts in the IDr of an SWu
// IKE_AUTH. Note what that means: on this interface the IDr is not "the name of
// the box we are talking to", it is "which PDN we want". T041d read it the
// first way, sent the ePDG's own name, and was answered AUTHENTICATION_FAILED.
func (s Subscription) APNFQDN(apn string) (string, error) {
	apn = strings.Trim(strings.TrimSpace(strings.ToLower(apn)), ".")
	if apn == "" {
		return "", fmt.Errorf("%w: no APN network identifier", ErrCardReadout)
	}
	for i := 0; i < len(apn); i++ {
		c := apn[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'
		if !ok {
			return "", fmt.Errorf("%w: APN %q is not a DNS label", ErrCardReadout, apn)
		}
	}
	return fmt.Sprintf("%s.apn.epc.mnc%s.mcc%s.pub.3gppnetwork.org", apn, PadMNC(s.MNC), s.MCC), nil
}

// APNIdentity is APNFQDN as an ID_FQDN identity, ready to be an IDr.
func (s Subscription) APNIdentity(apn string) (ikev2.Identity, error) {
	fqdn, err := s.APNFQDN(apn)
	if err != nil {
		return ikev2.Identity{}, err
	}
	return IdentityFQDN(fqdn), nil
}

// Describe is the derivation chain, one line per step, for the receipt.
func (s Subscription) Describe() []string {
	return []string{
		fmt.Sprintf("module    %s (hardware selector; never sent on the wire)", s.IMEI),
		fmt.Sprintf("readout   %s", s.Source),
		fmt.Sprintf("IMSI      %s (from the card)", s.IMSI),
		fmt.Sprintf("home PLMN %s -> MCC %s, MNC %s (%d digits)", s.HomePLMN, s.MCC, s.MNC, len(s.MNC)),
		fmt.Sprintf("ePDG      %s", s.EPDGFQDN()),
		fmt.Sprintf("IMPI      %s", s.IMPI()),
	}
}

// DefaultPanelURL is where the edge daemon's panel listens.
const DefaultPanelURL = "http://127.0.0.1:8743"

type panelStatus struct {
	Modems []panelModem `json:"modems"`
}

type panelModem struct {
	IMEI        string `json:"imei"`
	ICCID       string `json:"iccid"`
	State       string `json:"state"`
	IMSI        string `json:"imsi"`
	HomeNumeric string `json:"home_numeric"`
	Home        string `json:"home"`
}

// CardReadout is one modem's line of the panel status, kept verbatim.
type CardReadout struct {
	IMEI        string
	ICCID       string
	State       string
	IMSI        string
	HomeNumeric string
	Home        string
	Source      string
}

// FetchCardReadout asks the edge daemon what the card says.
//
// This is a read of the daemon's own poll results, not a command: it goes to
// GET /api/status, which serves the IMSI from AT+CIMI and the home PLMN from
// that IMSI split where EF_AD says (edge-bin/src/main.rs:2778-2809). Reading
// EF_AD from here instead would mean execute_at on the AT lease, which T041c
// ruled out and this package does not do.
func FetchCardReadout(ctx context.Context, panelURL, imei string) (CardReadout, error) {
	base := strings.TrimSpace(panelURL)
	if base == "" {
		base = DefaultPanelURL
	}
	endpoint, err := url.JoinPath(base, "/api/status")
	if err != nil {
		return CardReadout{}, fmt.Errorf("%w: panel URL %q: %w", ErrCardReadout, base, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return CardReadout{}, err
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return CardReadout{}, fmt.Errorf("%w: %s: %w", ErrCardReadout, endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return CardReadout{}, fmt.Errorf("%w: %s answered %s", ErrCardReadout, endpoint, resp.Status)
	}
	var status panelStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return CardReadout{}, fmt.Errorf("%w: %s: %w", ErrCardReadout, endpoint, err)
	}
	imei = strings.TrimSpace(imei)
	known := make([]string, 0, len(status.Modems))
	for _, m := range status.Modems {
		known = append(known, m.IMEI)
		if imei != "" && m.IMEI != imei {
			continue
		}
		if imei == "" && len(status.Modems) != 1 {
			break
		}
		return CardReadout{
			IMEI:        m.IMEI,
			ICCID:       m.ICCID,
			State:       m.State,
			IMSI:        m.IMSI,
			HomeNumeric: m.HomeNumeric,
			Home:        m.Home,
			Source:      endpoint,
		}, nil
	}
	if imei == "" {
		return CardReadout{}, fmt.Errorf("%w: %d modems present, name one: %v",
			ErrModemNotFound, len(status.Modems), known)
	}
	return CardReadout{}, fmt.Errorf("%w: %q; present: %v", ErrModemNotFound, imei, known)
}

// Subscription derives the identity from this readout.
func (c CardReadout) Subscription() (Subscription, error) {
	return DeriveSubscription(c.IMEI, c.IMSI, c.HomeNumeric, c.Source)
}

// DefaultDoHEndpoint is the resolver used when the system one cannot be
// trusted. T038 reached three independent DoH providers from this box; this is
// the one it used first.
const DefaultDoHEndpoint = "https://cloudflare-dns.com/dns-query"

// FakeIPPrefix is what the edge box answers with instead of resolving. T036
// found it answers *every* name this way, random ones included, so a non-empty
// answer proves nothing on its own.
const FakeIPPrefix = "198.18."

// DoHResolver resolves a name over DNS-over-HTTPS.
//
// Not the system resolver: on this box that returns 198.18.0.x for anything at
// all, so a plain LookupIP would hand back an address that looks fine, dials
// the host's TUN proxy, and produces a failure that reads like a carrier
// problem (T036 section 1).
type DoHResolver struct {
	// Endpoint is a DoH JSON endpoint. Empty means DefaultDoHEndpoint.
	Endpoint string
	// Client is for tests. Nil means a client with a 20s timeout.
	Client *http.Client
}

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type dohResponse struct {
	Status int         `json:"Status"`
	Answer []dohAnswer `json:"Answer"`
}

// DNSAnswer is what a lookup produced, including the CNAME chain.
//
// The chain matters here: T031 found that the card's own mnc240 name is a CNAME
// onto the geo name under mnc260, which is how a 310-240 subscription ends up on
// the infrastructure T038 measured under 310-260. Dropping the chain would make
// that look like a contradiction.
type DNSAnswer struct {
	Name     string
	Endpoint string
	Chain    []string
	IPs      []net.IP
	// Canonical is the owner name of the first A record, with the trailing dot
	// stripped: the name the card-derived name actually resolved to.
	//
	// It is a candidate IDr, and a legitimate one: it was produced by resolving
	// the name the card named, not chosen by anybody. Whether an ePDG wants it
	// or the original is not something any specification settles.
	Canonical string
}

// LookupA resolves a name to A records over DoH.
func (r *DoHResolver) LookupA(ctx context.Context, name string) (DNSAnswer, error) {
	endpoint := strings.TrimSpace(r.Endpoint)
	if endpoint == "" {
		endpoint = DefaultDoHEndpoint
	}
	out := DNSAnswer{Name: name, Endpoint: endpoint}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return out, err
	}
	query := req.URL.Query()
	query.Set("name", name)
	query.Set("type", "A")
	req.URL.RawQuery = query.Encode()
	req.Header.Set("Accept", "application/dns-json")

	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return out, fmt.Errorf("DoH %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("DoH %s answered %s", endpoint, resp.Status)
	}
	var body dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return out, fmt.Errorf("DoH %s: %w", endpoint, err)
	}
	if body.Status != 0 {
		return out, fmt.Errorf("%w: DoH status %d for %s", ErrNoAddress, body.Status, name)
	}
	for _, answer := range body.Answer {
		switch answer.Type {
		case 5:
			out.Chain = append(out.Chain, fmt.Sprintf("%s CNAME %s", answer.Name, answer.Data))
		case 1:
			ip := net.ParseIP(strings.TrimSpace(answer.Data))
			if ip == nil {
				continue
			}
			if strings.HasPrefix(ip.String(), FakeIPPrefix) {
				return out, fmt.Errorf("%w: %s -> %s", ErrFakeIPAnswer, name, ip)
			}
			out.IPs = append(out.IPs, ip)
			out.Chain = append(out.Chain, fmt.Sprintf("%s A %s", answer.Name, ip))
			if out.Canonical == "" {
				out.Canonical = strings.TrimSuffix(strings.TrimSpace(answer.Name), ".")
			}
		}
	}
	if len(out.IPs) == 0 {
		return out, fmt.Errorf("%w: %s over %s", ErrNoAddress, name, endpoint)
	}
	return out, nil
}

// ApparentEndpoint is how the far side saw our source address.
type ApparentEndpoint struct {
	IP   net.IP
	Port uint16
}

func (e ApparentEndpoint) String() string {
	if e.IP == nil {
		return "unknown"
	}
	return net.JoinHostPort(e.IP.String(), strconv.Itoa(int(e.Port)))
}

// SolveApparentEndpoint recovers our public address from the responder's
// NAT_DETECTION_DESTINATION_IP.
//
// The notify is SHA-1(SPIi || SPIr || our-apparent-IP || our-apparent-port), so
// with the SPIs known and a short list of candidate egress addresses the port
// falls out of 65536 hashes. T038 did this by hand and got 6/6 unique hits; the
// reason to have it in the tool is that this box has two UDP egresses with
// different NATs (T038 section 7 / T062) and "which one did the ePDG see" is
// otherwise unanswerable from inside the VM.
//
// A miss is not an error. T038 measured T-Mobile not sending the notify at all.
func SolveApparentEndpoint(hash []byte, spiI, spiR uint64, candidates []net.IP) (ApparentEndpoint, bool) {
	if len(hash) == 0 {
		return ApparentEndpoint{}, false
	}
	for _, ip := range candidates {
		if ip == nil {
			continue
		}
		for port := 1; port <= 65535; port++ {
			got, err := ikev2.NATDetectionHash(spiI, spiR, ip, uint16(port))
			if err != nil {
				break
			}
			if equalBytes(got, hash) {
				return ApparentEndpoint{IP: ip, Port: uint16(port)}, true
			}
		}
	}
	return ApparentEndpoint{}, false
}

// KnownEgressIPs are the two UDP egresses measured on this box.
//
// 34.174.243.156 is the GCP node in Dallas that T038 recovered from AT&T's own
// NAT-D hash for ePDG traffic; 111.198.29.210 is the Beijing China Unicom CGNAT
// address T062 measured for ordinary UDP. Which of the two a given destination
// takes is a host-side proxy rule we cannot read from in here, which is exactly
// why the run measures it instead of assuming.
func KnownEgressIPs() []net.IP {
	return []net.IP{
		net.ParseIP("34.174.243.156"),
		net.ParseIP("111.198.29.210"),
	}
}
