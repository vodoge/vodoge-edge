package ike

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/boa-z/vowifi-go/engine/sim"
	"github.com/boa-z/vowifi-go/engine/swu/eapaka"

	"github.com/yuanshuai1122/vodoge-edge/vowifi/internal/capture"
)

// Errors surfaced while driving the EAP method.
var (
	// ErrEAPFailure is an EAP-Failure from the peer.
	ErrEAPFailure = errors.New("vowifi/ike: EAP failed")
	// ErrEAPUnexpected is an EAP packet that does not belong in this state.
	ErrEAPUnexpected = errors.New("vowifi/ike: unexpected EAP packet")
	// ErrAKASyncFailure means the USIM reported SQN desynchronisation and the
	// resynchronisation budget ran out. The AT_AUTS response was still sent.
	ErrAKASyncFailure = errors.New("vowifi/ike: EAP-AKA synchronisation failure")
	// ErrAKAAuthFailure means the USIM rejected the network's AUTN. The
	// EAP-Response/AKA-Authentication-Reject was still sent.
	ErrAKAAuthFailure = errors.New("vowifi/ike: EAP-AKA authentication reject")
	// ErrAKADeadlineExceeded is the hard stop described on WithAKADeadline.
	ErrAKADeadlineExceeded = errors.New("vowifi/ike: AKA provider exceeded its deadline")
	// ErrNoAKAProvider means nothing can answer an AKA challenge.
	ErrNoAKAProvider = errors.New("vowifi/ike: no AKA provider")
	// ErrNoEAPKeys means the EAP method finished without producing an MSK, so
	// there is nothing to compute the AUTH payload from.
	ErrNoEAPKeys = errors.New("vowifi/ike: EAP method produced no MSK")
	// ErrRecordedAKAMiss means a replay was asked for a RAND/AUTN pair that is
	// not in the recording.
	ErrRecordedAKAMiss = errors.New("vowifi/ike: no recorded AKA vector for this challenge")
)

// WithAKADeadline puts a hard upper bound on one CalculateAKA call.
//
// This is the seam T041c needs and it has to exist now, because there is
// physically nowhere else to put it. sim.AKAProvider is
//
//	CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error)
//
// (engine/sim/sim.go:116-118). No context, no deadline, no cancellation. Once
// the IKE state machine calls into a real card bridge it is blocked until that
// call returns, and on the edge box the call crosses into a Rust arbiter whose
// own upper bound is 300 seconds or unbounded (T058 is not done). An IKE_AUTH
// exchange that stalls for five minutes has long since been abandoned by the
// ePDG, so the tunnel is dead either way; the difference is whether our side
// notices.
//
// The honest limitation, stated rather than hidden: the abandoned call keeps
// running. Its goroutine cannot be cancelled, because the interface offers no
// way to ask. It writes to a buffered channel and exits on its own, and the
// RAND/AUTN it works on are private copies, so an abandoned call cannot scribble
// on a buffer the caller has moved on to. What it can still do is occupy the
// card. A real bridge therefore also needs its own serialisation, and T041c owns
// that; this wrapper only guarantees that the IKE side stops waiting.
func WithAKADeadline(ctx context.Context, provider sim.AKAProvider, timeout time.Duration) sim.AKAProvider {
	if provider == nil {
		return nil
	}
	if timeout <= 0 && ctx == nil {
		return provider
	}
	return &deadlineAKAProvider{ctx: ctx, provider: provider, timeout: timeout}
}

type deadlineAKAProvider struct {
	// Holding a context in a struct is normally wrong. Here it is the only
	// option: the interface being satisfied has no context parameter, and the
	// alternative is to let a cancelled IKE exchange keep waiting on a card.
	ctx      context.Context
	provider sim.AKAProvider
	timeout  time.Duration
}

type akaOutcome struct {
	result sim.AKAResult
	err    error
}

func (p *deadlineAKAProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	randCopy := append([]byte(nil), rand16...)
	autnCopy := append([]byte(nil), autn16...)
	// Buffered so the goroutine can finish and exit even after we gave up.
	ch := make(chan akaOutcome, 1)
	go func() {
		result, err := p.provider.CalculateAKA(randCopy, autnCopy)
		ch <- akaOutcome{result: result, err: err}
	}()

	var expiry <-chan time.Time
	if p.timeout > 0 {
		timer := time.NewTimer(p.timeout)
		defer timer.Stop()
		expiry = timer.C
	}
	var cancelled <-chan struct{}
	if p.ctx != nil {
		cancelled = p.ctx.Done()
	}
	select {
	case out := <-ch:
		return out.result, out.err
	case <-expiry:
		return sim.AKAResult{}, fmt.Errorf("%w after %s; the call is still running because "+
			"sim.AKAProvider cannot be cancelled", ErrAKADeadlineExceeded, p.timeout)
	case <-cancelled:
		return sim.AKAResult{}, p.ctx.Err()
	}
}

// RecordingAKAProvider wraps a provider and remembers every vector it produced,
// so a live run can be replayed offline without a card.
//
// The recorded vectors are RES/CK/IK for specific RAND/AUTN pairs. They are as
// sensitive as the session they authenticate, which is why capture only persists
// them under RecordSecrets.
type RecordingAKAProvider struct {
	Inner sim.AKAProvider

	mu      sync.Mutex
	vectors []capture.AKAVector
}

// CalculateAKA satisfies sim.AKAProvider.
func (p *RecordingAKAProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	result, err := p.Inner.CalculateAKA(rand16, autn16)
	vector := capture.AKAVector{
		RAND: append([]byte(nil), rand16...),
		AUTN: append([]byte(nil), autn16...),
		RES:  append([]byte(nil), result.RES...),
		CK:   append([]byte(nil), result.CK...),
		IK:   append([]byte(nil), result.IK...),
		AUTS: append([]byte(nil), result.AUTS...),
	}
	switch {
	case err == nil:
	case errors.Is(err, sim.ErrSyncFailure):
		vector.Failure = capture.AKAFailureSync
		if len(vector.AUTS) == 0 {
			var carrier interface{ AUTS() []byte }
			if errors.As(err, &carrier) {
				vector.AUTS = append([]byte(nil), carrier.AUTS()...)
			}
		}
	case errors.Is(err, sim.ErrAuthFailure):
		vector.Failure = capture.AKAFailureAuth
	default:
		vector.Failure = capture.AKAFailureOther
	}
	p.mu.Lock()
	p.vectors = append(p.vectors, vector)
	p.mu.Unlock()
	return result, err
}

// Vectors returns everything recorded so far.
func (p *RecordingAKAProvider) Vectors() []capture.AKAVector {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]capture.AKAVector, len(p.vectors))
	copy(out, p.vectors)
	return out
}

// RecordedAKAProvider answers from a recording instead of a card.
//
// It matches on RAND||AUTN rather than on call order, because a resynchronised
// challenge repeats the exchange with fresh values and the number of rounds a
// replay takes must not have to match by luck.
type RecordedAKAProvider struct {
	vectors []capture.AKAVector
}

// NewRecordedAKAProvider builds a provider over recorded vectors.
func NewRecordedAKAProvider(vectors []capture.AKAVector) *RecordedAKAProvider {
	out := make([]capture.AKAVector, len(vectors))
	copy(out, vectors)
	return &RecordedAKAProvider{vectors: out}
}

// CalculateAKA satisfies sim.AKAProvider.
func (p *RecordedAKAProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	for _, v := range p.vectors {
		if !bytes.Equal(v.RAND, rand16) || !bytes.Equal(v.AUTN, autn16) {
			continue
		}
		result := sim.AKAResult{
			RES:  append([]byte(nil), v.RES...),
			CK:   append([]byte(nil), v.CK...),
			IK:   append([]byte(nil), v.IK...),
			AUTS: append([]byte(nil), v.AUTS...),
		}
		switch v.Failure {
		case capture.AKAFailureSync:
			return result, sim.NewSyncFailureError(v.AUTS)
		case capture.AKAFailureAuth:
			return result, sim.NewMACFailureError()
		case capture.AKAFailureOther:
			return result, fmt.Errorf("%w: the recording stored a non-AKA failure", sim.ErrAKATemporaryFailure)
		default:
			return result, nil
		}
	}
	return sim.AKAResult{}, fmt.Errorf("%w: %d vector(s) recorded", ErrRecordedAKAMiss, len(p.vectors))
}

// EAPStep is one outbound EAP response plus what producing it revealed.
type EAPStep struct {
	Response      eapaka.Packet
	Raw           []byte
	Identity      string
	Keys          eapaka.Keys
	HaveKeys      bool
	SyncFailure   bool
	AuthFailure   bool
	BiddingDown   bool
	ClientError   bool
	Notification  bool
	KDFNegotiated bool
	Challenge     bool
	RAND          []byte
	AUTN          []byte
	IdentityState eapaka.EncryptedIdentityState
}

// EAPDriver turns inbound EAP-AKA requests into outbound responses by calling
// the mirror's exported eapaka constructors directly.
//
// It exists instead of RunIKE_AUTH_Full's internal loop because that loop is
// welded to BuildIKEAuthInitialPayloads, and because auth.go:326 declares
// "EAP success without CHILD_SA" an error - which is what a correct ePDG ladder
// looks like, since EAP-Success and the CHILD_SA arrive in different exchanges.
type EAPDriver struct {
	// PermanentIdentity is the NAI, used when the server asks for a permanent
	// id or asks for nothing in particular.
	PermanentIdentity string
	// Pseudonym and ReauthIdentity are the RFC 4187 section 4.1 alternatives.
	Pseudonym      string
	ReauthIdentity string
	// Provider answers AKA challenges. Wrap it in WithAKADeadline.
	Provider sim.AKAProvider

	identity   string
	keys       eapaka.Keys
	transcript [][]byte
}

// Identity reports the identity the method has settled on.
func (d *EAPDriver) Identity() string {
	if d.identity != "" {
		return d.identity
	}
	return strings.TrimSpace(d.PermanentIdentity)
}

// Keys returns the EAP keys derived so far.
func (d *EAPDriver) Keys() eapaka.Keys { return d.keys }

// Transcript returns the AT_CHECKCODE input: the identity request and response
// packets, in order, as they appeared on the wire (RFC 4187 section 10.13).
func (d *EAPDriver) Transcript() [][]byte {
	out := make([][]byte, len(d.transcript))
	copy(out, d.transcript)
	return out
}

// Respond produces the EAP response for one request.
func (d *EAPDriver) Respond(request eapaka.Packet, requestRaw []byte) (EAPStep, error) {
	if request.Code != eapaka.CodeRequest {
		return EAPStep{}, fmt.Errorf("%w: code %d is not a request", ErrEAPUnexpected, request.Code)
	}
	switch request.Subtype {
	case eapaka.SubtypeIdentity:
		return d.respondIdentity(request, requestRaw)
	case eapaka.SubtypeChallenge:
		return d.respondChallenge(request)
	default:
		return d.respondControl(request)
	}
}

func (d *EAPDriver) respondIdentity(request eapaka.Packet, requestRaw []byte) (EAPStep, error) {
	identity := eapIdentityFor(request, d.PermanentIdentity, d.Pseudonym, d.ReauthIdentity)
	if identity == "" {
		return EAPStep{}, fmt.Errorf("%w: no identity to answer with", ErrEAPUnexpected)
	}
	response, err := eapaka.BuildIdentityResponse(identity, request)
	if err != nil {
		return EAPStep{}, err
	}
	raw, err := response.MarshalBinary()
	if err != nil {
		return EAPStep{}, err
	}
	d.identity = identity
	// RFC 4187 section 10.13: the checkcode covers the identity round trip in
	// the order the packets appeared.
	if len(requestRaw) == 0 {
		if requestRaw, err = request.MarshalBinary(); err != nil {
			return EAPStep{}, err
		}
	}
	d.transcript = append(d.transcript,
		append([]byte(nil), requestRaw...),
		append([]byte(nil), raw...))
	return EAPStep{
		Response:    response,
		Raw:         raw,
		Identity:    identity,
		ClientError: response.Subtype == eapaka.SubtypeClientError,
	}, nil
}

func (d *EAPDriver) respondChallenge(request eapaka.Packet) (EAPStep, error) {
	// AKA' KDF renegotiation comes before anything touches the card: the server
	// is asking us to redo the challenge under a different KDF, and answering it
	// with a RES would be answering the wrong question.
	if response, negotiated, err := eapaka.BuildAKAPrimeKDFNegotiationResponse(request); err != nil {
		if !errors.Is(err, eapaka.ErrUnsupportedKDF) {
			return EAPStep{}, err
		}
	} else if negotiated {
		raw, err := response.MarshalBinary()
		if err != nil {
			return EAPStep{}, err
		}
		return EAPStep{Response: response, Raw: raw, KDFNegotiated: true}, nil
	}

	if d.Provider == nil {
		return EAPStep{}, ErrNoAKAProvider
	}
	identity := d.Identity()
	// BuildChallengeResponseFromProvider (eapaka/crypto.go:204) is the reason
	// the two failure paths are nearly free: it turns sim.ErrSyncFailure into an
	// AT_AUTS EAP-Response/AKA-Synchronization-Failure and sim.ErrAuthFailure
	// into an EAP-Response/AKA-Authentication-Reject, both already MAC-correct.
	// All this code has to do is classify the card error correctly and put the
	// resulting packet on the wire instead of aborting.
	result, err := eapaka.BuildChallengeResponseFromProvider(identity, request, d.Provider, d.transcript)
	if err != nil {
		return EAPStep{}, err
	}
	raw, err := result.Response.MarshalBinary()
	if err != nil {
		return EAPStep{}, err
	}
	step := EAPStep{
		Response:    result.Response,
		Raw:         raw,
		Identity:    identity,
		SyncFailure: result.SyncFailure,
		AuthFailure: result.AuthFailure,
		BiddingDown: result.BiddingDown,
		Challenge:   true,
		RAND:        append([]byte(nil), result.RAND...),
		AUTN:        append([]byte(nil), result.AUTN...),
	}
	if len(result.Keys.MSK) > 0 || len(result.Keys.KAut) > 0 {
		d.keys = result.Keys
		step.Keys = result.Keys
		step.HaveKeys = true
	}
	if !result.SyncFailure && !result.AuthFailure && step.HaveKeys {
		attrs, _, err := eapaka.DecryptChallengeEncryptedAttributes(request, d.keys)
		if err != nil {
			return EAPStep{}, err
		}
		if len(attrs) > 0 {
			state, err := eapaka.IdentityStateFromAttributes(attrs)
			if err != nil {
				return EAPStep{}, err
			}
			step.IdentityState = state
		}
	}
	return step, nil
}

func (d *EAPDriver) respondControl(request eapaka.Packet) (EAPStep, error) {
	response, handled, err := eapaka.BuildNotificationResponse(request)
	if err != nil && errors.Is(err, eapaka.ErrInvalidKeyMaterial) && len(d.keys.KAut) > 0 {
		response, handled, err = eapaka.BuildAuthenticatedNotificationResponse(request, d.keys.KAut)
	}
	if err != nil {
		return EAPStep{}, err
	}
	if handled {
		raw, err := response.MarshalBinary()
		if err != nil {
			return EAPStep{}, err
		}
		return EAPStep{Response: response, Raw: raw, Notification: true}, nil
	}
	response, err = eapaka.BuildClientErrorResponse(request, eapaka.ClientErrorUnableToProcessPacket)
	if err != nil {
		return EAPStep{}, err
	}
	raw, err := response.MarshalBinary()
	if err != nil {
		return EAPStep{}, err
	}
	return EAPStep{Response: response, Raw: raw, ClientError: true}, nil
}

// eapIdentityFor reimplements the mirror's identityForEAPRequest (auth.go:739),
// which is unexported. RFC 4187 section 4.1: AT_PERMANENT_ID_REQ wants the
// permanent NAI, AT_FULLAUTH_ID_REQ allows a pseudonym, AT_ANY_ID_REQ allows a
// fast re-authentication identity first.
func eapIdentityFor(request eapaka.Packet, permanent, pseudonym, reauth string) string {
	permanent = strings.TrimSpace(permanent)
	pseudonym = strings.TrimSpace(pseudonym)
	reauth = strings.TrimSpace(reauth)
	switch {
	case hasEAPAttribute(request, eapaka.AttributePermanentIDReq):
		return permanent
	case hasEAPAttribute(request, eapaka.AttributeFullAuthIDReq):
		return firstNonEmpty(pseudonym, permanent)
	case hasEAPAttribute(request, eapaka.AttributeAnyIDReq):
		return firstNonEmpty(reauth, pseudonym, permanent)
	default:
		return permanent
	}
}

func hasEAPAttribute(request eapaka.Packet, attributeType uint8) bool {
	_, ok := eapaka.FindAttribute(request.Attributes, attributeType)
	return ok
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
