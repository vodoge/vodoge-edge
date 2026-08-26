package ike

import (
	"crypto"
	"crypto/hmac"
	"errors"
	"fmt"

	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

// NotifyEAPOnlyAuthentication is the RFC 5998 status notification that tells the
// responder we are willing to authenticate it with the EAP method's MSK instead
// of a certificate.
//
// The mirror does not define it: grepping the whole of engine/ for
// EAP_ONLY_AUTHENTICATION returns nothing, and BuildIKEAuthInitialPayloads
// (auth.go:840-888) emits {IDi, CP, SA, TSi, TSr} with neither this notify nor
// an IDr. Without the notify an ePDG follows plain RFC 7296 section 2.16 and
// expects to prove its own identity with a certificate, which this stack cannot
// validate. That is why the whole IKE_AUTH loop is replaced rather than reused.
//
// 16417 is the IANA "IKEv2 Notify Message Types - Status Types" allocation made
// by RFC 5998 section 5. Nothing in this repository has yet seen it on a wire
// from a real ePDG, so it is a single named constant on purpose: if T041d finds
// a node that disagrees, exactly one line changes.
const NotifyEAPOnlyAuthentication uint16 = 16417

// AuthMethodSharedKeyMIC is RFC 7296 section 3.8 Auth Method 2, "Shared Key
// Message Integrity Code".
//
// This is the value we put in the AUTH payload for EAP-only authentication.
// RFC 7296 section 2.16 says that when the EAP method produces a shared key,
// both peers compute AUTH using the syntax for shared secrets from section 2.15
// with the MSK as the shared secret - and section 2.15 defines method 2 as
// exactly that syntax. RFC 5998 section 3 inherits it unchanged.
//
// There is no captured evidence from a live ePDG anywhere in this repository to
// confirm the choice, which is why it is a named constant, why AuthRunner lets a
// caller override it, and why every AUTH payload can be exported out of a pcap
// on its own (capture.Capture.AuthPayloads). If the first real contact rejects
// us, this byte is the first thing to look at.
const AuthMethodSharedKeyMIC uint8 = 2

// AuthKeyPad is the RFC 7296 section 2.15 constant used to stretch a shared
// secret into an AUTH key. It is ASCII, with no terminating NUL.
const AuthKeyPad = "Key Pad for IKEv2"

// authPayloadHeaderLength is the fixed part of an AUTH payload body: one octet
// of Auth Method followed by three RESERVED octets (RFC 7296 section 3.8). The
// generic payload header is not part of the body here because ikev2.Payload
// already owns it.
const authPayloadHeaderLength = 4

// Errors raised by this file.
var (
	ErrInvalidAuthPayload = errors.New("vowifi/ike: invalid AUTH payload")
	// ErrMissingResponderID is deliberately fatal, the same way
	// ErrMissingNATDetectionInputs is. Sending IKE_AUTH without an IDr is not a
	// smaller request, it is a different conversation: RFC 5998 EAP-only
	// authentication needs the responder to know which identity we intend to
	// verify later.
	ErrMissingResponderID = errors.New("vowifi/ike: IKE_AUTH needs an IDr")
	ErrMissingInitiatorID = errors.New("vowifi/ike: IKE_AUTH needs an IDi")
)

// AuthValue is a decoded AUTH payload.
type AuthValue struct {
	Method uint8
	Data   []byte
}

// AuthPayload encodes an AUTH payload body.
func AuthPayload(method uint8, data []byte) (ikev2.Payload, error) {
	if method == 0 {
		return ikev2.Payload{}, fmt.Errorf("%w: auth method is zero", ErrInvalidAuthPayload)
	}
	if len(data) == 0 {
		return ikev2.Payload{}, fmt.Errorf("%w: no authentication data", ErrInvalidAuthPayload)
	}
	body := make([]byte, authPayloadHeaderLength, authPayloadHeaderLength+len(data))
	body[0] = method
	body = append(body, data...)
	return ikev2.Payload{Type: ikev2.PayloadAUTH, Body: body}, nil
}

// ParseAuthPayload decodes an AUTH payload body.
func ParseAuthPayload(body []byte) (AuthValue, error) {
	if len(body) <= authPayloadHeaderLength {
		return AuthValue{}, fmt.Errorf("%w: body is %d octets, need more than %d",
			ErrInvalidAuthPayload, len(body), authPayloadHeaderLength)
	}
	if body[0] == 0 {
		return AuthValue{}, fmt.Errorf("%w: auth method is zero", ErrInvalidAuthPayload)
	}
	// RFC 7296 section 3.8 declares octets 1..3 RESERVED and says senders MUST
	// zero them; it does not say receivers must reject a non-zero value, so this
	// only reports the value rather than failing on it.
	return AuthValue{
		Method: body[0],
		Data:   append([]byte(nil), body[authPayloadHeaderLength:]...),
	}, nil
}

// AuthPayloadReserved returns the three RESERVED octets of an AUTH payload body,
// so a capture can show them instead of normalising them away.
func AuthPayloadReserved(body []byte) []byte {
	if len(body) < authPayloadHeaderLength {
		return nil
	}
	return append([]byte(nil), body[1:authPayloadHeaderLength]...)
}

// MACedIdentity is prf(SK_p, RestOfIDPayload) from RFC 7296 section 2.15.
//
// "RestOfIDPayload" is the ID payload body: the one-octet ID Type, three
// RESERVED octets, then the identification data - i.e. exactly what
// ikev2.Identity.MarshalBinary produces and exactly what travels in
// ikev2.Payload.Body. The generic payload header is excluded.
func MACedIdentity(prf crypto.Hash, skP []byte, id ikev2.Identity) ([]byte, error) {
	body, err := id.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return MACedIdentityBody(prf, skP, body)
}

// MACedIdentityBody is MACedIdentity over an ID payload body already on the
// wire. Received identities go through this one: re-encoding a parsed
// ikev2.Identity would drop any RESERVED octets the peer set, and the MAC is
// over the bytes that were actually sent.
func MACedIdentityBody(prf crypto.Hash, skP, idBody []byte) ([]byte, error) {
	if len(skP) == 0 {
		return nil, fmt.Errorf("%w: SK_p is empty", ErrInvalidAuthPayload)
	}
	if len(idBody) < 4 {
		return nil, fmt.Errorf("%w: ID payload body is %d octets", ErrInvalidAuthPayload, len(idBody))
	}
	return ikev2.PRF(prf, skP, idBody)
}

// InitiatorSignedOctets is RFC 7296 section 2.15:
//
//	InitiatorSignedOctets = RealMessage1 | NonceRData | MACedIDForI
//
// RealMessage1 is the entire IKE_SA_INIT request as it went out, including the
// IKE header, which is why ikev2.InitResult.RequestBytes has to be preserved by
// whoever runs IKE_SA_INIT. NonceRData is the responder nonce value only, not
// its payload header.
func InitiatorSignedOctets(initRequest, nonceR, macedIDForI []byte) []byte {
	out := make([]byte, 0, len(initRequest)+len(nonceR)+len(macedIDForI))
	out = append(out, initRequest...)
	out = append(out, nonceR...)
	out = append(out, macedIDForI...)
	return out
}

// ResponderSignedOctets is the mirror image:
//
//	ResponderSignedOctets = RealMessage2 | NonceIData | MACedIDForR
func ResponderSignedOctets(initResponse, nonceI, macedIDForR []byte) []byte {
	out := make([]byte, 0, len(initResponse)+len(nonceI)+len(macedIDForR))
	out = append(out, initResponse...)
	out = append(out, nonceI...)
	out = append(out, macedIDForR...)
	return out
}

// SharedKeyAuth is the RFC 7296 section 2.15 shared-secret AUTH:
//
//	AUTH = prf(prf(Shared Secret, "Key Pad for IKEv2"), <SignedOctets>)
//
// For EAP-only authentication the shared secret is the EAP method's MSK
// (RFC 7296 section 2.16, RFC 5998 section 3), which for EAP-AKA is the
// 64-octet MSK from RFC 4187 section 7.
func SharedKeyAuth(prf crypto.Hash, secret, signedOctets []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("%w: shared secret is empty", ErrInvalidAuthPayload)
	}
	if len(signedOctets) == 0 {
		return nil, fmt.Errorf("%w: signed octets are empty", ErrInvalidAuthPayload)
	}
	inner, err := ikev2.PRF(prf, secret, []byte(AuthKeyPad))
	if err != nil {
		return nil, err
	}
	return ikev2.PRF(prf, inner, signedOctets)
}

// EqualAuth compares two AUTH values in constant time.
func EqualAuth(a, b []byte) bool { return hmac.Equal(a, b) }

// AuthInitialPayloads describes the first IKE_AUTH request.
type AuthInitialPayloads struct {
	// InitiatorID becomes IDi. Required.
	InitiatorID ikev2.Identity
	// ResponderID becomes IDr. Required unless AllowMissingResponderID.
	ResponderID ikev2.Identity
	// AllowMissingResponderID drops IDr. Off by default; see
	// ErrMissingResponderID.
	AllowMissingResponderID bool
	// ChildSA is the ESP offer. Empty means DefaultESPProposal(ChildSPI).
	ChildSA ikev2.SecurityAssociation
	// ChildSPI is our inbound ESP SPI, four octets.
	ChildSPI []byte
	// TSi and TSr default to IPv4 any.
	TSi ikev2.TrafficSelectors
	TSr ikev2.TrafficSelectors
	// Configuration defaults to DefaultConfigVariant, which is the mirror's
	// SWu CFG_REQUEST plus the two P-CSCF attributes it never had.
	Configuration ikev2.Configuration
	// AllowMissingConfiguration drops the CP payload entirely when
	// Configuration is the zero value. Off by default, and the default is the
	// substitution above rather than an omission, for the same reason
	// AllowMissingResponderID exists: a request with no CP is not a smaller
	// request, it is a different question. RFC 7296 section 3.15 has the
	// initiator ask to be configured by sending the payload, so an IKE_AUTH
	// without one is a UE saying it needs no address - and 3GPP TS 24.302
	// section 7.2.2 says a UE on SWu does need one.
	//
	// It is reachable because the answer to it is worth more than a working
	// tunnel would be right now. See ConfigVariantNone.
	//
	// Configuration wins if it is set: an explicit payload is sent even with
	// this flag on, because a caller that built a request by hand asked for
	// that request. AuthDetail.SentCP records which of the two actually
	// happened.
	AllowMissingConfiguration bool
	// EAPOnlyAuthentication adds the RFC 5998 notify.
	EAPOnlyAuthentication bool
	// Extra payloads are appended last, for callers that need
	// MOBIKE_SUPPORTED or a vendor id.
	Extra []ikev2.Payload
}

// BuildAuthInitialPayloads renders the inner payloads of the first IKE_AUTH
// request.
//
// Payload order follows the RFC 5998 section 2 example with the mirror's CFG
// placement kept: IDi, IDr, CP, SA, TSi, TSr, N(EAP_ONLY_AUTHENTICATION).
// RFC 7296 section 2.5 lets a notify sit anywhere in the message, so the order
// is a compatibility choice rather than a correctness one, and it is spelled out
// here because a wrong guess stays invisible until an ePDG answers
// AUTHENTICATION_FAILED.
//
// IDr and CP are the two payloads that can be absent, and both absences are
// opt-in flags rather than a consequence of leaving a field empty. Every other
// payload in that list is always there.
func BuildAuthInitialPayloads(p AuthInitialPayloads) ([]ikev2.Payload, error) {
	if p.InitiatorID.Type == 0 || len(p.InitiatorID.Data) == 0 {
		return nil, fmt.Errorf("%w: IDi is empty", ErrMissingInitiatorID)
	}
	idi, err := ikev2.IdentityPayload(ikev2.PayloadIDi, p.InitiatorID)
	if err != nil {
		return nil, err
	}
	out := []ikev2.Payload{idi}

	haveIDr := p.ResponderID.Type != 0 && len(p.ResponderID.Data) > 0
	switch {
	case haveIDr:
		idr, err := ikev2.IdentityPayload(ikev2.PayloadIDr, p.ResponderID)
		if err != nil {
			return nil, err
		}
		out = append(out, idr)
	case p.AllowMissingResponderID:
		// Explicitly opted out.
	default:
		return nil, fmt.Errorf("%w: the mirror omits it too (auth.go:840-888); set ResponderID, "+
			"or AllowMissingResponderID to accept a request the responder cannot bind to an identity",
			ErrMissingResponderID)
	}

	// The CFG_REQUEST default is no longer the mirror's. T072 sent
	// ikev2.SWuConfigurationRequest() at T-Mobile US and got notify 36
	// (INTERNAL_ADDRESS_FAILURE) back on the message carrying AUTH, and that
	// request has no P-CSCF attribute at all - so even a tunnel that came up on
	// it would have had nowhere to send REGISTER. See config_payload.go.
	cfg := p.Configuration
	haveConfiguration := cfg.Type != 0 || len(cfg.Attributes) > 0
	switch {
	case haveConfiguration:
		// Sent as given, including when AllowMissingConfiguration is set.
	case p.AllowMissingConfiguration:
		// Explicitly opted out: no CP payload reaches the wire. Unlike the IDr
		// case this is not silent - AuthDetail.SentCP is false, the sidecar
		// records the variant name, and DescribeConfiguration of the zero value
		// reads "(no CP payload)" everywhere a request would otherwise print.
	default:
		derived, err := DefaultConfigVariant.Configuration()
		if err != nil {
			return nil, err
		}
		cfg = derived
		haveConfiguration = true
	}
	if haveConfiguration {
		cp, err := ikev2.ConfigurationPayload(cfg)
		if err != nil {
			return nil, err
		}
		out = append(out, cp)
	}

	childSA := p.ChildSA
	if len(childSA.Proposals) == 0 {
		if len(p.ChildSPI) != 4 {
			return nil, fmt.Errorf("%w: child SPI is %d octets, want 4", ErrInvalidAuthPayload, len(p.ChildSPI))
		}
		childSA = ikev2.DefaultESPProposal(p.ChildSPI)
	}
	sa, err := ikev2.SecurityAssociationPayload(childSA)
	if err != nil {
		return nil, err
	}
	out = append(out, sa)

	tsi := p.TSi
	if len(tsi.Selectors) == 0 {
		tsi = ikev2.IPv4AnyTrafficSelectors()
	}
	tsiPayload, err := ikev2.TrafficSelectorsPayload(ikev2.PayloadTSi, tsi)
	if err != nil {
		return nil, err
	}
	tsr := p.TSr
	if len(tsr.Selectors) == 0 {
		tsr = ikev2.IPv4AnyTrafficSelectors()
	}
	tsrPayload, err := ikev2.TrafficSelectorsPayload(ikev2.PayloadTSr, tsr)
	if err != nil {
		return nil, err
	}
	out = append(out, tsiPayload, tsrPayload)

	if p.EAPOnlyAuthentication {
		out = append(out, ikev2.NotifyWithZeroSPI(NotifyEAPOnlyAuthentication, nil))
	}
	out = append(out, p.Extra...)
	return out, nil
}

// IdentityFromString guesses an ikev2.Identity for a NAI-shaped string.
//
// A VoWiFi initiator identity is normally the EAP-AKA NAI, which is an RFC 822
// address; anything without an "@" is carried as a KEY_ID rather than silently
// mislabelled. Callers that know better should set the Identity directly.
func IdentityFromString(value string) (ikev2.Identity, error) {
	if value == "" {
		return ikev2.Identity{}, fmt.Errorf("%w: empty identity", ErrMissingInitiatorID)
	}
	for i := 0; i < len(value); i++ {
		if value[i] == '@' {
			return ikev2.Identity{Type: ikev2.IDRFC822Addr, Data: []byte(value)}, nil
		}
	}
	return ikev2.Identity{Type: ikev2.IDKeyID, Data: []byte(value)}, nil
}

// IdentityFQDN builds an ID_FQDN identity, which is the usual shape for an ePDG
// IDr (3GPP TS 24.302 section 7.2.2).
func IdentityFQDN(fqdn string) ikev2.Identity {
	return ikev2.Identity{Type: ikev2.IDFQDN, Data: []byte(fqdn)}
}
