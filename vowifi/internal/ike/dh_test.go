package ike

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"math"
	"math/big"
	"testing"
)

// The goal charter warns about tests that only agree with their own mistake:
// "凡是「测试比对的常量」和「被测的常量」同源，那个测试就守不住任何东西".
//
// So none of the checks below re-state the prime. They verify the primes from
// sources the implementation does not touch:
//
//  1. RFC 2409 section 6.2 / RFC 3526 sections 2 and 3 all specify their prime
//     twice: once as hex, once as a closed form
//     p = 2^n - 2^(n-64) - 1 + 2^64 * ( floor(2^(n-130) * pi) + offset ).
//     We recover the bracketed term from the parsed prime and check that
//     (term - offset) / 2^(n-130) equals pi. The pi we compare against is Go's
//     own math.Pi, which is not ours.
//  2. p must be prime and (p-1)/2 must be prime (these are safe primes). A
//     transcription slip anywhere in 512 hex digits destroys that with
//     overwhelming probability, and big.Int.ProbablyPrime is stdlib, not ours.
//  3. Generator 2 must lie in the order-q subgroup.
type modpVector struct {
	name    string
	group   *modpGroup
	id      uint16
	bits    int
	offset  int64
	piShift int // n-130
}

func rfc3526Vectors() []modpVector {
	return []modpVector{
		// RFC 2409 section 6.2 (IKE DH group 2). Included because group 2 rides
		// in the wire proposal T038 measured; note it is MODP-1024, not 1536.
		{name: "MODP-1024/group2", group: modp1024, id: GroupMODP1024, bits: 1024, offset: 129093, piShift: 894},
		// RFC 3526 section 2 (IKE DH group 5).
		{name: "MODP-1536/group5", group: modp1536, id: GroupMODP1536, bits: 1536, offset: 741804, piShift: 1406},
		// RFC 3526 section 3 (IKE DH group 14) - the group all seven ePDGs in
		// T038 selected.
		{name: "MODP-2048/group14", group: modp2048, id: GroupMODP2048, bits: 2048, offset: 124476, piShift: 1918},
	}
}

func TestMODPPrimesMatchRFCClosedForm(t *testing.T) {
	for _, v := range rfc3526Vectors() {
		t.Run(v.name, func(t *testing.T) {
			p := v.group.prime
			if got := p.BitLen(); got != v.bits {
				t.Fatalf("bit length = %d, want %d", got, v.bits)
			}

			// The RFC primes begin and end with 64 one bits.
			high := new(big.Int).Rsh(p, uint(v.bits-64))
			low := new(big.Int).And(p, new(big.Int).SetUint64(math.MaxUint64))
			allOnes := new(big.Int).SetUint64(math.MaxUint64)
			if high.Cmp(allOnes) != 0 {
				t.Errorf("top 64 bits = %x, want all ones", high)
			}
			if low.Cmp(allOnes) != 0 {
				t.Errorf("bottom 64 bits = %x, want all ones", low)
			}

			// p - (2^n - 2^(n-64) - 1) must be an exact multiple of 2^64.
			base := new(big.Int).Lsh(big.NewInt(1), uint(v.bits))
			base.Sub(base, new(big.Int).Lsh(big.NewInt(1), uint(v.bits-64)))
			base.Sub(base, big.NewInt(1))
			rest := new(big.Int).Sub(p, base)
			term, rem := new(big.Int).QuoRem(rest, new(big.Int).Lsh(big.NewInt(1), 64), new(big.Int))
			if rem.Sign() != 0 {
				t.Fatalf("p - (2^n - 2^(n-64) - 1) is not a multiple of 2^64")
			}

			// (term - offset) / 2^(n-130) must equal pi.
			term.Sub(term, big.NewInt(v.offset))
			ratio := new(big.Float).SetPrec(256).SetInt(term)
			ratio.Quo(ratio, new(big.Float).SetPrec(256).SetInt(new(big.Int).Lsh(big.NewInt(1), uint(v.piShift))))
			pi := new(big.Float).SetPrec(256).SetFloat64(math.Pi)
			delta := new(big.Float).SetPrec(256).Sub(ratio, pi)
			delta.Abs(delta)
			// math.Pi carries ~53 bits; 1e-15 relative is the honest tolerance.
			if delta.Cmp(big.NewFloat(1e-15)) > 0 {
				got, _ := ratio.Float64()
				t.Fatalf("closed-form pi term = %.17g, want %.17g (delta %v)", got, math.Pi, delta)
			}
		})
	}
}

func TestMODPPrimesAreSafePrimes(t *testing.T) {
	for _, v := range rfc3526Vectors() {
		t.Run(v.name, func(t *testing.T) {
			p := v.group.prime
			if !p.ProbablyPrime(24) {
				t.Fatalf("p is not prime")
			}
			if !v.group.q.ProbablyPrime(24) {
				t.Fatalf("(p-1)/2 is not prime, so p is not a safe prime")
			}
			if want := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1); v.group.q.Cmp(want) != 0 {
				t.Fatalf("cached q != (p-1)/2")
			}
			// Generator 2 must generate the order-q subgroup: 2^q mod p == 1.
			if got := new(big.Int).Exp(big.NewInt(2), v.group.q, p); got.Cmp(big.NewInt(1)) != 0 {
				t.Fatalf("2^q mod p = %s, want 1", got)
			}
			if got := (p.BitLen() + 7) / 8; got != v.group.octets {
				t.Fatalf("octets = %d, want %d", v.group.octets, got)
			}
		})
	}
}

func TestMODPExchangeAgrees(t *testing.T) {
	for _, v := range rfc3526Vectors() {
		t.Run(v.name, func(t *testing.T) {
			a, err := GenerateKeyPair(v.id, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKeyPair(initiator) = %v", err)
			}
			b, err := GenerateKeyPair(v.id, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKeyPair(responder) = %v", err)
			}
			if len(a.PublicKey()) != v.group.octets {
				t.Fatalf("public length = %d, want %d", len(a.PublicKey()), v.group.octets)
			}
			ab, err := a.ComputeSharedSecret(b.PublicKey())
			if err != nil {
				t.Fatalf("initiator ComputeSharedSecret = %v", err)
			}
			ba, err := b.ComputeSharedSecret(a.PublicKey())
			if err != nil {
				t.Fatalf("responder ComputeSharedSecret = %v", err)
			}
			if !bytes.Equal(ab, ba) {
				t.Fatalf("shared secrets differ")
			}
			if len(ab) != v.group.octets {
				t.Fatalf("shared secret length = %d, want %d (RFC 7296 requires fixed-length padding)", len(ab), v.group.octets)
			}

			// Reconstructing from the recorded scalar must reproduce the exact
			// public value. Offline replay is worthless without this.
			replay, err := KeyPairFromPrivate(v.id, a.PrivateKey())
			if err != nil {
				t.Fatalf("KeyPairFromPrivate = %v", err)
			}
			if !bytes.Equal(replay.PublicKey(), a.PublicKey()) {
				t.Fatalf("replayed public value differs from the original")
			}
		})
	}
}

func TestMODPRejectsBadPeerPublic(t *testing.T) {
	g := modp2048
	k, err := GenerateKeyPair(GroupMODP2048, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair = %v", err)
	}
	cases := map[string]*big.Int{
		"zero":     big.NewInt(0),
		"one":      big.NewInt(1),
		"p minus1": new(big.Int).Sub(g.prime, big.NewInt(1)),
		"p":        new(big.Int).Set(g.prime),
	}
	for name, value := range cases {
		if _, err := k.ComputeSharedSecret(leftPad(value.Bytes(), g.octets)); err == nil {
			t.Errorf("%s: accepted an invalid peer public value", name)
		}
	}
	if _, err := k.ComputeSharedSecret(make([]byte, 16)); err == nil {
		t.Errorf("accepted a short KE payload")
	}

	// A quadratic non-residue is in range but outside the order-q subgroup.
	// Real ePDGs never send one; if one ever shows up we want a named error
	// rather than a shared secret that silently disagrees with the peer.
	nonResidue := findNonResidue(t, g)
	_, err = k.ComputeSharedSecret(leftPad(nonResidue.Bytes(), g.octets))
	if err == nil {
		t.Fatalf("accepted a peer public value outside the prime-order subgroup")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("outside prime-order subgroup")) {
		t.Fatalf("subgroup rejection reported as %q, want the dedicated error", err)
	}
}

func findNonResidue(t *testing.T, g *modpGroup) *big.Int {
	t.Helper()
	one := big.NewInt(1)
	for candidate := int64(3); candidate < 200; candidate++ {
		y := big.NewInt(candidate)
		if new(big.Int).Exp(y, g.q, g.prime).Cmp(one) != 0 {
			return y
		}
	}
	t.Fatalf("no small quadratic non-residue found")
	return nil
}

func TestECP256WireEncodingAndExchange(t *testing.T) {
	// RFC 5903 section 7: the group 19 key exchange value is x || y, 64 octets,
	// with no SEC1 0x04 prefix. Getting that wrong is a silent interop failure:
	// the peer parses our 65-byte blob as a 65-byte KE and derives other keys.
	a, err := GenerateKeyPair(GroupECP256, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair = %v", err)
	}
	pub := a.PublicKey()
	if len(pub) != 64 {
		t.Fatalf("group 19 KE length = %d, want 64", len(pub))
	}
	if pub[0] == 4 && len(pub) == 65 {
		t.Fatalf("group 19 KE still carries the SEC1 prefix")
	}

	// Independent on-curve check using crypto/elliptic parameters, i.e. a
	// different stdlib package from the crypto/ecdh one that produced the key.
	params := elliptic.P256().Params()
	x := new(big.Int).SetBytes(pub[:32])
	y := new(big.Int).SetBytes(pub[32:])
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, params.P)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mod(rhs, params.P)
	rhs.Mul(rhs, x)
	rhs.Sub(rhs, new(big.Int).Mul(big.NewInt(3), x))
	rhs.Add(rhs, params.B)
	rhs.Mod(rhs, params.P)
	if lhs.Cmp(rhs) != 0 {
		t.Fatalf("group 19 public value is not on NIST P-256")
	}

	b, err := GenerateKeyPair(GroupECP256, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair(responder) = %v", err)
	}
	ab, err := a.ComputeSharedSecret(b.PublicKey())
	if err != nil {
		t.Fatalf("initiator ComputeSharedSecret = %v", err)
	}
	ba, err := b.ComputeSharedSecret(a.PublicKey())
	if err != nil {
		t.Fatalf("responder ComputeSharedSecret = %v", err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatalf("group 19 shared secrets differ")
	}
	// RFC 5903 section 7: the shared secret is the x coordinate only.
	if len(ab) != 32 {
		t.Fatalf("group 19 shared secret length = %d, want 32", len(ab))
	}
	if _, err := a.ComputeSharedSecret(make([]byte, 64)); err == nil {
		t.Fatalf("accepted an off-curve group 19 peer value")
	}
	if _, err := a.ComputeSharedSecret(append([]byte{4}, b.PublicKey()...)); err == nil {
		t.Fatalf("accepted a SEC1-prefixed group 19 peer value")
	}
}

func TestX25519Exchange(t *testing.T) {
	a, err := GenerateKeyPair(GroupX25519, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair = %v", err)
	}
	b, err := GenerateKeyPair(GroupX25519, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair(responder) = %v", err)
	}
	if len(a.PublicKey()) != 32 {
		t.Fatalf("group 31 KE length = %d, want 32", len(a.PublicKey()))
	}
	ab, err := a.ComputeSharedSecret(b.PublicKey())
	if err != nil {
		t.Fatalf("ComputeSharedSecret = %v", err)
	}
	ba, err := b.ComputeSharedSecret(a.PublicKey())
	if err != nil {
		t.Fatalf("ComputeSharedSecret = %v", err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatalf("group 31 shared secrets differ")
	}
}

func TestDHGroupSupportSet(t *testing.T) {
	for _, id := range SupportedDHGroups() {
		if !DHGroupSupported(id) {
			t.Errorf("%s advertised but unsupported", DHGroupName(id))
		}
		if _, err := GenerateKeyPair(id, rand.Reader); err != nil {
			t.Errorf("%s: GenerateKeyPair = %v", DHGroupName(id), err)
		}
	}
	if DHGroupSupported(1) {
		t.Errorf("group 1 (MODP-768) must stay unsupported")
	}
	if _, err := GenerateKeyPair(1, rand.Reader); err == nil {
		t.Errorf("GenerateKeyPair(group 1) unexpectedly succeeded")
	}
}
