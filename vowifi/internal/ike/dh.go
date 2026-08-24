// Package ike carries the VoDoge-side IKEv2 pieces that the read-only
// github.com/boa-z/vowifi-go mirror deliberately leaves injectable.
//
// Nothing in this package edits the mirror. The mirror declares
// swu.IKEInitRunner, swu.IKETransportFactory and swu.IKEESPTransportFactory, and
// falls back to its built-in implementations only when those fields are nil
// (engine/swu/ike_tunnel_manager.go:152-154, :168-171, :374-401). We fill the
// fields; the mirror stays byte-identical to vowifi-go.git@1e9c6e6.
package ike

import (
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// DH group identifiers as registered by IANA for IKEv2 Transform Type 4.
//
// Beware a naming trap that has already been written down wrong once: IKE group
// 2 is MODP-*1024* (RFC 2409 section 6.2, the Second Oakley Group). MODP-1536 is
// group *5* (RFC 3526 section 2). Both are implemented here; only the set in
// DefaultProposalGroups goes on the wire, and that set is the one T038 actually
// measured against seven live ePDGs.
const (
	GroupMODP1024 uint16 = 2  // RFC 2409 section 6.2
	GroupMODP1536 uint16 = 5  // RFC 3526 section 2
	GroupMODP2048 uint16 = 14 // RFC 3526 section 3
	GroupECP256   uint16 = 19 // RFC 5903 section 3.1 (NIST P-256)
	GroupECP384   uint16 = 20 // RFC 5903 section 3.2 (NIST P-384)
	GroupX25519   uint16 = 31 // RFC 8031
)

var (
	// ErrUnsupportedDHGroup is returned for a group we cannot key.
	ErrUnsupportedDHGroup = errors.New("vowifi/ike: unsupported dh group")
	// ErrInvalidPeerPublic is returned when the peer key exchange value is
	// structurally wrong (bad length, out of range, not on the curve).
	ErrInvalidPeerPublic = errors.New("vowifi/ike: invalid peer public value")
	// ErrPeerPublicNotInSubgroup is returned when a MODP peer public value sits
	// outside the prime-order subgroup. Kept distinct from ErrInvalidPeerPublic
	// on purpose: the alternative failure mode is "shared secret is silently
	// wrong", which only surfaces an exchange later as an AUTH mismatch.
	ErrPeerPublicNotInSubgroup = errors.New("vowifi/ike: peer public value outside prime-order subgroup")
	// ErrInvalidPrivateKey is returned by KeyPairFromPrivate for a scalar the
	// group cannot use. Offline replay depends on this path, so it fails loudly.
	ErrInvalidPrivateKey = errors.New("vowifi/ike: invalid dh private key")
)

// modpGroup is a safe-prime MODP group with generator 2.
type modpGroup struct {
	id     uint16
	prime  *big.Int
	q      *big.Int // (p-1)/2
	octets int
}

// RFC 2409 section 6.2, Second Oakley Group (IKE DH group 2), 1024 bits.
const modp1024Hex = `
	FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
	29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
	EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
	E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
	EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
	FFFFFFFF FFFFFFFF`

// RFC 3526 section 2, 1536-bit MODP Group (IKE DH group 5).
const modp1536Hex = `
	FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
	29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
	EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
	E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
	EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
	C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
	83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
	670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF`

// RFC 3526 section 3, 2048-bit MODP Group (IKE DH group 14).
//
// T038 offered {14, 2, 19, 31} to seven live ePDGs (T-Mobile 4, AT&T 3) and all
// seven picked 14. The mirror hardcodes group 31 in three places inside the
// RunIKE_SA_INIT call chain (init.go:159, init.go:342, sa.go:81), which is
// exactly why this package replaces that function instead of patching lines.
const modp2048Hex = `
	FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
	29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
	EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
	E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
	EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
	C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
	83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
	670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
	E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
	DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
	15728E5A 8AACAA68 FFFFFFFF FFFFFFFF`

func mustParsePrime(text string) *big.Int {
	clean := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "").Replace(text)
	raw, err := hex.DecodeString(clean)
	if err != nil {
		panic("vowifi/ike: malformed MODP prime literal: " + err.Error())
	}
	return new(big.Int).SetBytes(raw)
}

func newMODPGroup(id uint16, text string) *modpGroup {
	p := mustParsePrime(text)
	q := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	return &modpGroup{id: id, prime: p, q: q, octets: (p.BitLen() + 7) / 8}
}

var (
	modp1024 = newMODPGroup(GroupMODP1024, modp1024Hex)
	modp1536 = newMODPGroup(GroupMODP1536, modp1536Hex)
	modp2048 = newMODPGroup(GroupMODP2048, modp2048Hex)
)

func modpGroupFor(id uint16) (*modpGroup, bool) {
	switch id {
	case GroupMODP1024:
		return modp1024, true
	case GroupMODP1536:
		return modp1536, true
	case GroupMODP2048:
		return modp2048, true
	default:
		return nil, false
	}
}

func ecdhCurveFor(id uint16) (ecdh.Curve, int, bool) {
	switch id {
	case GroupECP256:
		return ecdh.P256(), 32, true
	case GroupECP384:
		return ecdh.P384(), 48, true
	case GroupX25519:
		return ecdh.X25519(), 32, true
	default:
		return nil, 0, false
	}
}

// SupportedDHGroups lists every group this package can key, most preferred
// first. Wire order for proposals comes from DefaultProposalGroups in suite.go.
func SupportedDHGroups() []uint16 {
	return []uint16{GroupMODP2048, GroupMODP1536, GroupMODP1024, GroupECP256, GroupECP384, GroupX25519}
}

// DHGroupSupported reports whether GenerateKeyPair can serve the group.
func DHGroupSupported(id uint16) bool {
	if _, ok := modpGroupFor(id); ok {
		return true
	}
	_, _, ok := ecdhCurveFor(id)
	return ok
}

// DHGroupName renders a group id for logs and errors.
func DHGroupName(id uint16) string {
	switch id {
	case GroupMODP1024:
		return "MODP-1024(group 2)"
	case GroupMODP1536:
		return "MODP-1536(group 5)"
	case GroupMODP2048:
		return "MODP-2048(group 14)"
	case GroupECP256:
		return "ECP-256(group 19)"
	case GroupECP384:
		return "ECP-384(group 20)"
	case GroupX25519:
		return "X25519(group 31)"
	default:
		return fmt.Sprintf("DH-group-%d", id)
	}
}

// KeyPair is one ephemeral Diffie-Hellman key for a single IKE_SA_INIT attempt.
//
// PrivateKey is reachable on purpose: byte-exact offline replay of a capture is
// impossible without pinning the scalar, and the first real ePDG contact happens
// once, at 3am, over a Dallas egress. See internal/capture.
type KeyPair struct {
	group   uint16
	private []byte
	public  []byte

	modp     *modpGroup
	modpX    *big.Int
	ecdhKey  *ecdh.PrivateKey
	ecdhCurv ecdh.Curve
	coordLen int
}

// Group returns the IANA DH group id.
func (k *KeyPair) Group() uint16 { return k.group }

// PublicKey returns the wire encoding of our KE payload value.
func (k *KeyPair) PublicKey() []byte { return append([]byte(nil), k.public...) }

// PrivateKey returns the raw scalar. Capture writes it only under an explicit
// opt-in; see capture.WriterOptions.RecordSecrets.
func (k *KeyPair) PrivateKey() []byte { return append([]byte(nil), k.private...) }

// GenerateKeyPair produces a fresh ephemeral key for group id.
func GenerateKeyPair(id uint16, random io.Reader) (*KeyPair, error) {
	if random == nil {
		return nil, fmt.Errorf("%w: random reader is nil", ErrInvalidPrivateKey)
	}
	if g, ok := modpGroupFor(id); ok {
		x, err := randomMODPExponent(g, random)
		if err != nil {
			return nil, err
		}
		return keyPairFromMODPExponent(g, x), nil
	}
	if curve, coord, ok := ecdhCurveFor(id); ok {
		priv, err := curve.GenerateKey(random)
		if err != nil {
			return nil, err
		}
		return keyPairFromECDH(id, curve, coord, priv)
	}
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedDHGroup, DHGroupName(id))
}

// KeyPairFromPrivate rebuilds a key pair from a recorded scalar. This is the
// replay path: same scalar, same public value, same bytes on the wire.
func KeyPairFromPrivate(id uint16, private []byte) (*KeyPair, error) {
	if len(private) == 0 {
		return nil, fmt.Errorf("%w: empty scalar for %s", ErrInvalidPrivateKey, DHGroupName(id))
	}
	if g, ok := modpGroupFor(id); ok {
		x := new(big.Int).SetBytes(private)
		if err := checkMODPExponent(g, x); err != nil {
			return nil, err
		}
		return keyPairFromMODPExponent(g, x), nil
	}
	if curve, coord, ok := ecdhCurveFor(id); ok {
		priv, err := curve.NewPrivateKey(private)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidPrivateKey, DHGroupName(id), err)
		}
		return keyPairFromECDH(id, curve, coord, priv)
	}
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedDHGroup, DHGroupName(id))
}

func keyPairFromECDH(id uint16, curve ecdh.Curve, coord int, priv *ecdh.PrivateKey) (*KeyPair, error) {
	pub, err := encodeECDHPublic(id, coord, priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		group:    id,
		private:  priv.Bytes(),
		public:   pub,
		ecdhKey:  priv,
		ecdhCurv: curve,
		coordLen: coord,
	}, nil
}

func keyPairFromMODPExponent(g *modpGroup, x *big.Int) *KeyPair {
	pub := new(big.Int).Exp(big.NewInt(2), x, g.prime)
	return &KeyPair{
		group:   g.id,
		private: leftPad(x.Bytes(), g.octets),
		public:  leftPad(pub.Bytes(), g.octets),
		modp:    g,
		modpX:   x,
	}
}

// ComputeSharedSecret validates the peer KE value and returns the IKEv2 shared
// secret, left-padded to the group's fixed length. The padding matters: RFC 7296
// section 2.14 feeds g^ir straight into SKEYSEED, and a secret that is short by
// one leading zero yields keys that differ from the peer's with no error
// reported anywhere until IKE_AUTH fails to decrypt.
func (k *KeyPair) ComputeSharedSecret(peer []byte) ([]byte, error) {
	if k == nil {
		return nil, ErrInvalidPrivateKey
	}
	if k.modp != nil {
		return k.modpSharedSecret(peer)
	}
	return k.ecdhSharedSecret(peer)
}

func (k *KeyPair) modpSharedSecret(peer []byte) ([]byte, error) {
	g := k.modp
	if len(peer) != g.octets {
		return nil, fmt.Errorf("%w: %s KE length %d, want %d", ErrInvalidPeerPublic, DHGroupName(g.id), len(peer), g.octets)
	}
	y := new(big.Int).SetBytes(peer)
	if y.Cmp(big.NewInt(2)) < 0 {
		return nil, fmt.Errorf("%w: %s KE value < 2", ErrInvalidPeerPublic, DHGroupName(g.id))
	}
	upper := new(big.Int).Sub(g.prime, big.NewInt(1))
	if y.Cmp(upper) >= 0 {
		return nil, fmt.Errorf("%w: %s KE value >= p-1", ErrInvalidPeerPublic, DHGroupName(g.id))
	}
	// All three MODP groups here are safe primes (p = 2q+1), so membership in
	// the order-q subgroup costs exactly one extra exponentiation.
	if check := new(big.Int).Exp(y, g.q, g.prime); check.Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("%w: %s", ErrPeerPublicNotInSubgroup, DHGroupName(g.id))
	}
	shared := new(big.Int).Exp(y, k.modpX, g.prime)
	if shared.Cmp(big.NewInt(1)) == 0 {
		return nil, fmt.Errorf("%w: %s degenerate shared secret", ErrInvalidPeerPublic, DHGroupName(g.id))
	}
	return leftPad(shared.Bytes(), g.octets), nil
}

func (k *KeyPair) ecdhSharedSecret(peer []byte) ([]byte, error) {
	raw, err := decodeECDHPublic(k.group, k.coordLen, peer)
	if err != nil {
		return nil, err
	}
	pub, err := k.ecdhCurv.NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidPeerPublic, DHGroupName(k.group), err)
	}
	secret, err := k.ecdhKey.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidPeerPublic, DHGroupName(k.group), err)
	}
	return secret, nil
}

// encodeECDHPublic converts the crypto/ecdh SEC1 form to the IKEv2 wire form.
//
// RFC 5903 section 7: the ECP key exchange value is x || y with no 0x04 prefix.
// crypto/ecdh hands back uncompressed SEC1 (0x04 || x || y), so the prefix comes
// off for groups 19/20. X25519 (RFC 8031) is already the bare 32-byte u value.
func encodeECDHPublic(id uint16, coord int, sec1 []byte) ([]byte, error) {
	if id == GroupX25519 {
		if len(sec1) != coord {
			return nil, fmt.Errorf("%w: X25519 public length %d", ErrInvalidPeerPublic, len(sec1))
		}
		return append([]byte(nil), sec1...), nil
	}
	if len(sec1) != 1+2*coord || sec1[0] != 4 {
		return nil, fmt.Errorf("%w: %s SEC1 public length %d", ErrInvalidPeerPublic, DHGroupName(id), len(sec1))
	}
	return append([]byte(nil), sec1[1:]...), nil
}

func decodeECDHPublic(id uint16, coord int, wire []byte) ([]byte, error) {
	if id == GroupX25519 {
		if len(wire) != coord {
			return nil, fmt.Errorf("%w: X25519 KE length %d, want %d", ErrInvalidPeerPublic, len(wire), coord)
		}
		return append([]byte(nil), wire...), nil
	}
	if len(wire) != 2*coord {
		return nil, fmt.Errorf("%w: %s KE length %d, want %d", ErrInvalidPeerPublic, DHGroupName(id), len(wire), 2*coord)
	}
	out := make([]byte, 0, 1+len(wire))
	out = append(out, 4)
	return append(out, wire...), nil
}

func randomMODPExponent(g *modpGroup, random io.Reader) (*big.Int, error) {
	buf := make([]byte, g.octets)
	for attempt := 0; attempt < 64; attempt++ {
		if _, err := io.ReadFull(random, buf); err != nil {
			return nil, err
		}
		x := new(big.Int).SetBytes(buf)
		if checkMODPExponent(g, x) == nil {
			return x, nil
		}
	}
	return nil, fmt.Errorf("%w: exhausted attempts drawing %s exponent", ErrInvalidPrivateKey, DHGroupName(g.id))
}

func checkMODPExponent(g *modpGroup, x *big.Int) error {
	if x.Cmp(big.NewInt(2)) < 0 {
		return fmt.Errorf("%w: %s exponent < 2", ErrInvalidPrivateKey, DHGroupName(g.id))
	}
	if x.Cmp(new(big.Int).Sub(g.prime, big.NewInt(2))) > 0 {
		return fmt.Errorf("%w: %s exponent > p-2", ErrInvalidPrivateKey, DHGroupName(g.id))
	}
	return nil
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return append([]byte(nil), b...)
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
