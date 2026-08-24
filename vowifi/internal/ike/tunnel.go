package ike

// The confluence: one socket, IKE_SA_INIT, NAT keepalive, IKE_AUTH with a real
// card behind it. T041a, T041b and T041c each went green on their own and none
// of them had ever met a carrier.
//
// The reason this is a type and not four lines in main.go is the keepalive. The
// mapping this exchange depends on is created by the IKE_SA_INIT request and
// then has to survive an IKE_AUTH ladder that includes a round trip to a USIM,
// and T062 measured this box's UDP mapping expiring somewhere in (20s, 40s] of
// idleness. The window where that matters opens the moment IKE_SA_INIT
// completes, which is exactly the point where a straight-line script is busy
// deriving keys and not sending anything. So the keepalive has to be started by
// whatever owns the phase transition, and this is that thing.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/boa-z/vowifi-go/engine/sim"
	"github.com/boa-z/vowifi-go/engine/swu/ikev2"

	"github.com/yuanshuai1122/vodoge-edge/vowifi/internal/capture"
)

// DefaultKeepalivePeriod is how often a NAT-T keepalive goes out while an
// exchange is in flight.
//
// RFC 3948 section 4 suggests 20 seconds and that is what most clients use. It
// is too long here: T062 measured this box losing an idle UDP mapping somewhere
// after 20 seconds and before 40, and that measurement is on the direct CGNAT
// path, not on the proxied path an ePDG takes - which nothing has measured. Ten
// seconds is half of the shortest interval anyone has evidence for, which is
// the right amount of paranoia for an exchange that can only be attempted a few
// times before it starts costing SQN on a real card.
const DefaultKeepalivePeriod = 10 * time.Second

// DefaultInitTimeout and DefaultAuthTimeout bound the two phases.
//
// IKE_AUTH gets more because it contains the card round trip; it still has to
// stay well inside the ePDG's own patience, which RFC 7296 does not specify and
// which nobody here has measured.
const (
	DefaultInitTimeout = 30 * time.Second
	DefaultAuthTimeout = 60 * time.Second
)

// LiveOutcome is which of the failure classes a run landed in.
//
// The three that T041d must not confuse are Unreachable, AuthRejected and
// CardRefused. They look similar from a distance - "it did not work" - and they
// have nothing in common: the first is a network fact, the second says our
// payloads are wrong, and the third is the largest step forward this project
// can take short of a tunnel, because it means a real carrier put a real
// EAP-AKA challenge in front of a real card.
type LiveOutcome string

const (
	// OutcomeUnreachable is class 1: IKE_SA_INIT got no answer at all.
	OutcomeUnreachable LiveOutcome = "udp-unreachable"
	// OutcomeAuthNoReply is class 2 with the quietest possible rejection: the
	// ePDG answered IKE_SA_INIT and then dropped IKE_AUTH.
	OutcomeAuthNoReply LiveOutcome = "ike-auth-no-reply"
	// OutcomeAuthRejected is class 2: the ePDG answered IKE_AUTH but never put
	// an EAP-AKA Challenge in front of the card.
	OutcomeAuthRejected LiveOutcome = "ike-auth-rejected"
	// OutcomeCardRefused is class 3: the Challenge arrived and the card said
	// no. Criterion 2b's first half holds, its second half does not.
	OutcomeCardRefused LiveOutcome = "card-refused-challenge"
	// OutcomeChallengeAnswered means the card computed a RES for the carrier's
	// RAND/AUTN, but the ladder did not finish afterwards.
	OutcomeChallengeAnswered LiveOutcome = "challenge-answered"
	// OutcomeAddressRejected is the class T072 discovered and had no name for:
	// authentication completed, EAP-Success came back, and then the ePDG
	// refused the CFG_REQUEST with INTERNAL_ADDRESS_FAILURE. It is a strictly
	// later failure than OutcomeChallengeAnswered and it points at a different
	// file, so it gets its own label rather than being folded into "the ladder
	// did not finish".
	OutcomeAddressRejected LiveOutcome = "internal-address-rejected"
	// OutcomeEstablished means the CHILD_SA came up.
	OutcomeEstablished LiveOutcome = "tunnel-established"
	// OutcomeLocalFault means we broke before the network could answer.
	OutcomeLocalFault LiveOutcome = "local-fault"
)

// LiveConfig drives one attempt against one ePDG address.
type LiveConfig struct {
	// Socket is already bound and already pointed at the candidate.
	Socket *Socket
	// Subscription is the card readout. Everything identity-shaped on the wire
	// comes from here; there is deliberately no field for an FQDN or an IMPI.
	Subscription Subscription
	// AKA is the provider that will answer the Challenge. On the bench this is
	// aka.Provider, i.e. the card.
	AKA sim.AKAProvider
	// ResponderID is the IDr. The zero value sends none, and that default is
	// measured rather than assumed.
	//
	// T041b made "a missing IDr is an error" a deliberate decision, by analogy
	// with NAT_DETECTION, and TS 24.302 section 7.2.2 does ask the UE for one.
	// T041d put it in front of T-Mobile US and it is wrong there: on
	// 2026-08-24, five distinct GSLB nodes, every IKE_AUTH carrying an IDr came
	// back AUTHENTICATION_FAILED at message 1 and every IKE_AUTH without one
	// got an EAP-AKA Challenge. Two different, defensible IDr values were tried
	// - the card-derived FQDN and the canonical name it resolves to - and both
	// were refused, so it is the payload's presence that this ePDG objects to,
	// not its contents.
	//
	// Anything put here must still be derived from the card. The canonical name
	// DNS returned for the card-derived FQDN qualifies; a name somebody typed
	// does not.
	ResponderID ikev2.Identity
	// ConfigVariant selects the CFG_REQUEST shape and the traffic selectors
	// that belong with it. Empty means DefaultConfigVariant.
	//
	// This is the axis T081 exists to search. T072's run sent
	// ConfigVariantMirror and was answered INTERNAL_ADDRESS_FAILURE; every
	// other value here is an attempt to find out which part of that request the
	// ePDG objected to, and each attempt costs one SQN step on the bench card.
	ConfigVariant ConfigVariant
	// ConfigType overrides the CP payload type. Zero means CFG_REQUEST, which
	// is what a UE sends; CFG_SET is reachable only so that axis can be
	// measured and written down.
	ConfigType uint8
	// DisableEAPOnly drops N(EAP_ONLY_AUTHENTICATION). RFC 5998 says a
	// responder that does not support it should ignore it, but "should" is not
	// "does" and this is one of the three decisions T041b made on paper. Still
	// unmeasured: T041d's successful run carried the notify.
	DisableEAPOnly bool
	// Groups overrides the DH offer.
	Groups []uint16
	// Capture records both phases into one pcap.
	Capture *capture.Writer
	// KeepalivePeriod is the NAT-T interval. Zero means
	// DefaultKeepalivePeriod; negative disables keepalives.
	KeepalivePeriod time.Duration
	// InitTimeout and AuthTimeout bound the phases. Zero means the defaults.
	InitTimeout time.Duration
	AuthTimeout time.Duration
	// Log receives progress lines. Nil is silence.
	Log func(format string, args ...any)
}

// LiveResult is everything one attempt produced, success or not.
type LiveResult struct {
	FQDN string
	// ResponderIDUsed is the IDr actually put on the wire, or "(omitted)".
	ResponderIDUsed string
	IMPI            string

	InitDone   bool
	Init       ikev2.InitResult
	InitDetail RunDetail

	AuthAttempted bool
	AuthDone      bool
	Auth          ikev2.FullAuthResult
	AuthDetail    AuthDetail

	// ConfigVariantUsed is the CFG_REQUEST shape that was actually sent. It is
	// on the result rather than only on the config because a receipt has to
	// name the variant next to the outcome it produced.
	ConfigVariantUsed ConfigVariant

	Keepalives uint64
	Outcome    LiveOutcome
	Err        error
}

// Config is the CFG_REPLY the ePDG sent, decoded.
func (r LiveResult) Config() ConfigReply { return r.AuthDetail.PeerConfiguration }

// TunnelIsUp reports criterion 4's first half: a CHILD_SA exists and the ePDG
// gave us an address to source packets from.
//
// A CHILD_SA on its own is not enough. Without an internal address there is
// nothing to put in the source field of the first IMS packet, so reporting a
// tunnel at that point would be the "implemented" versus "works on the bench"
// mistake this goal's charter opens with.
func (r LiveResult) TunnelIsUp() bool {
	return r.Auth.ChildSA != nil && r.AuthDetail.PeerConfiguration.HaveInternalAddress()
}

// Challenges returns the RAND/AUTN/RES the card was actually asked about.
func (r LiveResult) Challenges() []capture.AKAVector { return r.AuthDetail.AKAVectors }

// SawCarrierChallenge reports the first half of criterion 2b: an ePDG put an
// EAP-AKA Challenge in front of this card.
//
// It is defined as "the card was asked", not as "a Challenge was parsed",
// because the only way a vector exists is that eapaka took AT_RAND and AT_AUTN
// out of a packet the carrier sent and handed them to the provider.
func (r LiveResult) SawCarrierChallenge() bool { return len(r.AuthDetail.AKAVectors) > 0 }

// CardAnsweredChallenge reports the second half: the card computed a RES rather
// than refusing.
func (r LiveResult) CardAnsweredChallenge() bool {
	for _, v := range r.AuthDetail.AKAVectors {
		if v.Failure == "" && len(v.RES) > 0 {
			return true
		}
	}
	return false
}

// RunLiveTunnel runs IKE_SA_INIT and then IKE_AUTH over one socket, keeping the
// NAT mapping alive across the seam.
//
// It never returns a bare error: the LiveResult is filled in on every path,
// because on this card a failure is the deliverable just as much as a success
// is, and a caller that only got an error would have nothing to write down.
func RunLiveTunnel(ctx context.Context, cfg LiveConfig) (LiveResult, error) {
	variant := cfg.ConfigVariant
	if variant == "" {
		variant = DefaultConfigVariant
	}
	out := LiveResult{
		FQDN:              cfg.Subscription.EPDGFQDN(),
		IMPI:              cfg.Subscription.IMPI(),
		ConfigVariantUsed: variant,
		Outcome:           OutcomeLocalFault,
	}
	// Refused here rather than three payloads later, so a typo costs nothing.
	// Past this point the next thing that happens is an SQN step on a card the
	// user cannot physically reach.
	if _, err := variant.ConfigurationOfType(cfg.ConfigType); err != nil {
		out.Err = err
		return out, err
	}
	if cfg.Socket == nil {
		out.Err = fmt.Errorf("%w: no socket", ErrInvalidAuthConfig)
		return out, out.Err
	}
	if cfg.Subscription.IMSI == "" {
		out.Err = fmt.Errorf("%w: no card readout, so there is no identity to assert", ErrCardReadout)
		return out, out.Err
	}
	logf := cfg.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}

	initCfg, err := InitConfigFor(cfg.Socket, ikev2.SecurityAssociation{})
	if err != nil {
		out.Err = err
		return out, err
	}
	initRunner := NewInitRunner()
	if len(cfg.Groups) > 0 {
		initRunner.Groups = cfg.Groups
	}
	initRunner.Capture = cfg.Capture

	initCtx, cancelInit := context.WithTimeout(ctx, orDuration(cfg.InitTimeout, DefaultInitTimeout))
	initResult, initErr := initRunner.Run(initCtx, initCfg)
	cancelInit()
	if detail, ok := initRunner.LastDetail(); ok {
		out.InitDetail = detail
	}
	if initErr != nil {
		out.Err = initErr
		out.Outcome = classifyInitFailure(initErr)
		return out, initErr
	}
	out.InitDone = true
	out.Init = initResult
	logf("IKE_SA_INIT complete: SPIi %016x SPIr %016x, %s",
		initResult.InitiatorSPI, initResult.ResponderSPI, out.InitDetail.Selection.SuiteName)

	// The mapping is now created and the next thing on the wire is an IKE_AUTH
	// that has to wait for a USIM. Start feeding the NAT before that, not
	// after: by the time IKE_AUTH is late it is already too late.
	stopKeepalive := startKeepalive(ctx, cfg.Socket, cfg.KeepalivePeriod, logf)

	authRunner := NewAuthRunner(cfg.ResponderID)
	authRunner.InitiatorID = cfg.Subscription.InitiatorIdentity()
	authRunner.DisableEAPOnlyAuthentication = cfg.DisableEAPOnly
	authRunner.ConfigVariant = variant
	authRunner.ConfigType = cfg.ConfigType
	authRunner.Capture = cfg.Capture
	out.ResponderIDUsed = string(cfg.ResponderID.Data)
	if cfg.ResponderID.Type == 0 || len(cfg.ResponderID.Data) == 0 {
		authRunner.AllowMissingResponderID = true
		out.ResponderIDUsed = "(omitted)"
	}

	authCtx, cancelAuth := context.WithTimeout(ctx, orDuration(cfg.AuthTimeout, DefaultAuthTimeout))
	out.AuthAttempted = true
	authResult, authErr := authRunner.Run(authCtx, ikev2.FullAuthConfig{
		Transport:   cfg.Socket,
		Init:        initResult,
		Keys:        initResult.Keys,
		SIM:         cfg.AKA,
		InitiatorID: cfg.Subscription.InitiatorIdentity(),
		EAPIdentity: cfg.Subscription.IMPI(),
	})
	cancelAuth()
	stopKeepalive()
	out.Keepalives = cfg.Socket.Stats().KeepalivesSent

	if detail, ok := authRunner.LastDetail(); ok {
		out.AuthDetail = detail
	}
	out.Auth = authResult
	if authErr != nil {
		out.Err = authErr
		out.Outcome = classifyAuthFailure(out, authErr)
		return out, authErr
	}
	out.AuthDone = true
	out.Outcome = OutcomeChallengeAnswered
	if authResult.ChildSA != nil {
		out.Outcome = OutcomeEstablished
		for _, line := range out.AuthDetail.PeerConfiguration.Describe() {
			logf("CFG_REPLY   %s", line)
		}
	}
	return out, nil
}

// startKeepalive feeds the NAT mapping until the returned function is called.
//
// A keepalive is one 0xff octet (RFC 3948 section 4) and it goes out on the
// same five-tuple as IKE and ESP, which is the whole reason this package has a
// single socket. Errors are logged and not returned: losing a keepalive is not
// a reason to abandon an exchange that may still be answered, and the counter
// on Socket.Stats is where the evidence lives anyway.
func startKeepalive(ctx context.Context, socket *Socket, period time.Duration, logf func(string, ...any)) func() {
	if period == 0 {
		period = DefaultKeepalivePeriod
	}
	if period < 0 {
		logf("NAT keepalive disabled by configuration")
		return func() {}
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	// One immediately, so the gap between IKE_SA_INIT and the first keepalive
	// is not itself a whole period.
	if err := socket.SendNATTKeepalive(ctx); err != nil {
		logf("NAT keepalive: %v", err)
	}
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := socket.SendNATTKeepalive(ctx); err != nil {
					logf("NAT keepalive: %v", err)
					return
				}
			}
		}
	}()
	var closed bool
	return func() {
		if closed {
			return
		}
		closed = true
		close(done)
		<-stopped
	}
}

func classifyInitFailure(err error) LiveOutcome {
	if errors.Is(err, ErrRetransmitExhausted) || errors.Is(err, context.DeadlineExceeded) {
		return OutcomeUnreachable
	}
	return OutcomeLocalFault
}

// classifyAuthFailure puts a failed ladder in exactly one bucket.
//
// Order matters and it is not the order the errors happen in. A card refusal is
// checked first because it is the strongest thing that can be true about the
// run: if the carrier's Challenge reached the card, then no later transport
// error changes the fact that it did, and reporting the transport error instead
// would bury the finding this whole card exists to produce.
func classifyAuthFailure(out LiveResult, err error) LiveOutcome {
	// Checked ahead of the card, and that ordering is the whole point of the
	// label. INTERNAL_ADDRESS_FAILURE can only arrive after the card answered
	// and the carrier accepted the answer, so it is strictly more progress than
	// OutcomeChallengeAnswered - and it names a different file to go and fix.
	// Reporting "challenge answered" for it, which is what this function did
	// before T081, hid the only failure class that is nobody's fault but ours.
	if errors.Is(err, ErrInternalAddressFailure) {
		return OutcomeAddressRejected
	}
	if out.CardAnsweredChallenge() {
		return OutcomeChallengeAnswered
	}
	if out.SawCarrierChallenge() {
		return OutcomeCardRefused
	}
	if errors.Is(err, ErrRetransmitExhausted) || errors.Is(err, context.DeadlineExceeded) {
		return OutcomeAuthNoReply
	}
	if len(out.AuthDetail.Rounds) > 0 {
		return OutcomeAuthRejected
	}
	return OutcomeLocalFault
}

// Explain says what the outcome means for goal oracle criterion 2b, in the
// terms the card asked for.
func (o LiveOutcome) Explain() string {
	switch o {
	case OutcomeUnreachable:
		return "class 1: IKE_SA_INIT was never answered. This is a network result, not a payload " +
			"bug, and no amount of editing our IKE_AUTH will change it."
	case OutcomeAuthNoReply:
		return "class 2: IKE_SA_INIT was answered and IKE_AUTH was not. The ePDG dropped our " +
			"request rather than rejecting it, which is what a malformed or unacceptable " +
			"IKE_AUTH usually looks like from the outside."
	case OutcomeAuthRejected:
		return "class 2: the ePDG answered IKE_AUTH but never issued an EAP-AKA Challenge. " +
			"The three payload decisions with no live evidence behind them are the AUTH " +
			"encoding, the IDr, and the EAP_ONLY_AUTHENTICATION notify."
	case OutcomeCardRefused:
		return "class 3: the carrier issued an EAP-AKA Challenge and the card refused it. " +
			"Criterion 2b's first half holds - a real ePDG put a real RAND/AUTN in front of " +
			"this eUICC - and its second half does not."
	case OutcomeChallengeAnswered:
		return "the carrier issued an EAP-AKA Challenge and the card computed a RES for it. " +
			"Both halves of criterion 2b's evidence exist; whether the ladder then completed " +
			"is a separate question."
	case OutcomeAddressRejected:
		return "authentication finished and the ePDG then refused to assign an internal address " +
			"(notify 36). Nothing here is a carrier verdict on the card: EAP-Success arrived one " +
			"message earlier, so the identity, the RES and the AUTH payload have all been " +
			"accepted. T081 measured three requests refused this way - mirror, dual and ipv6 - " +
			"so a fourth -cfg variant is a guess, not a diagnosis. See " +
			"notes/T081-cfg-request.md for what is still untried."
	case OutcomeEstablished:
		return "the ladder completed and a CHILD_SA came up."
	default:
		return "we failed before the network had a chance to answer."
	}
}

func orDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}
