// Package drandbn254 checks a drand round signed on BN254, as drand's
// "evmnet" network signs it (scheme bls-bn254-unchained-on-g1): the
// signature is a G1 point over hash_to_curve(keccak256(round)), with RFC
// 9380's expand_message_xmd over Keccak-256 and the Shallue-van de
// Woestijne map, under the network's G2 public key. The curve operations
// are gno's crypto/bn254 natives (EIP-196/197); exponentiations go through
// crypto/modexp. This is autopatch's beacon spike (F0): the draws after a
// reveal need a randomness no one in the swarm controls.
package drandbn254

import (
	"crypto/bn254"
	"crypto/keccak256"
	"crypto/modexp"

	u256 "gno.land/p/onbloc/uint256/v0"
)

// DST is drand evmnet's hash-to-curve domain.
const DST = "BLS_SIG_BN254G1_XMD:KECCAK-256_SVDW_RO_NUL_"

var (
	p = u256.MustFromDecimal("21888242871839275222246405745257275088696311157297823662689037894645226208583")
	// The SvdW constants for BN254 G1 (A = 0, B = 3, Z = 1).
	c1 = u256.NewUint(4)                                                                                       // g(Z)
	c2 = u256.MustFromDecimal("10944121435919637611123202872628637544348155578648911831344518947322613104291") // -Z/2
	c3 = u256.MustFromDecimal("8815841940592487685674414971303048083897117035520822607866")                    // sqrt(-g(Z)(3Z²+4A))
	c4 = u256.MustFromDecimal("7296080957279758407415468581752425029565437052432607887563012631548408736189")  // -4g(Z)/(3Z²+4A)
	b  = u256.NewUint(3)
	// Exponents: p-2 (inverse), (p-1)/2 (is square), (p+1)/4 (square root; p = 3 mod 4).
	pMinus2  = bytes32(new(u256.Uint).Sub(p, u256.NewUint(2)))
	halfPm1  = bytes32(new(u256.Uint).Rsh(new(u256.Uint).Sub(p, u256.One()), 1))
	quarterP = bytes32(new(u256.Uint).Rsh(new(u256.Uint).Add(p, u256.One()), 2))
	pBytes   = bytes32(p)
	// negG2 is the negated G2 generator in EIP-197's order.
	negG2 = mustHex("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d")
)

// Verify reports whether sig (64 bytes: x|y) is the network's signature
// for round, under pub (128 bytes: x_imag|x_real|y_imag|y_real).
func Verify(pub []byte, round uint64, sig []byte) bool {
	if len(pub) != 128 || len(sig) != 64 {
		return false
	}
	// EIP-197 reads all zeros as the point at infinity: e(0, -g2) * e(H, 0)
	// is 1 for every message, so a zero key with a zero signature would
	// verify anything, and a ticket's draw would be known ahead (round 8,
	// minor 11).
	if allZero(pub) || allZero(sig) {
		return false
	}
	var r [8]byte
	for i := 0; i < 8; i++ {
		r[7-i] = byte(round >> (8 * i))
	}
	m := keccak256.Sum256(r[:])
	h := HashToG1(m[:])
	if h == nil {
		return false
	}
	// e(sig, -g2) * e(H(m), pub) == 1
	in := make([]byte, 0, 384)
	in = append(in, sig...)
	in = append(in, negG2...)
	in = append(in, h...)
	in = append(in, pub...)
	out := bn254.PairingCheck(in)
	return len(out) == 32 && out[31] == 1
}

// HashToG1 is RFC 9380's hash_to_curve for BN254 G1 with Keccak-256 and the
// SvdW map: 64 bytes, x|y.
func HashToG1(msg []byte) []byte {
	u := expandXMD(msg, 96)
	q0 := mapToCurve(fieldOf(u[:48]))
	q1 := mapToCurve(fieldOf(u[48:]))
	return bn254.G1Add(append(q0, q1...)) // the cofactor of BN254's G1 is 1
}

// expandXMD is expand_message_xmd with Keccak-256 (b = 32 bytes, r = 136).
func expandXMD(msg []byte, n int) []byte {
	dstPrime := append([]byte(DST), byte(len(DST)))
	in := make([]byte, 136)
	in = append(in, msg...)
	in = append(in, byte(n>>8), byte(n), 0)
	in = append(in, dstPrime...)
	b0 := keccak256.Sum256(in)
	b1 := keccak256.Sum256(append(append(append([]byte{}, b0[:]...), 1), dstPrime...))
	out := append([]byte{}, b1[:]...)
	prev := b1
	for i := 2; len(out) < n; i++ {
		x := make([]byte, 32)
		for j := 0; j < 32; j++ {
			x[j] = b0[j] ^ prev[j]
		}
		prev = keccak256.Sum256(append(append(x, byte(i)), dstPrime...))
		out = append(out, prev[:]...)
	}
	return out[:n]
}

// fieldOf reduces 48 bytes modulo p.
func fieldOf(b []byte) *u256.Uint {
	return new(u256.Uint).SetBytes(modexp.ModExp(b, []byte{1}, pBytes))
}

func mul(x, y *u256.Uint) *u256.Uint { return new(u256.Uint).MulMod(x, y, p) }

func add(x, y *u256.Uint) *u256.Uint {
	z := new(u256.Uint).Add(x, y) // both below p < 2^254: no overflow
	if !z.Lt(p) {
		z.Sub(z, p)
	}
	return z
}

func sub(x, y *u256.Uint) *u256.Uint {
	if x.Lt(y) {
		return new(u256.Uint).Sub(new(u256.Uint).Add(x, p), y)
	}
	return new(u256.Uint).Sub(x, y)
}

func pow(x *u256.Uint, e []byte) *u256.Uint {
	return new(u256.Uint).SetBytes(modexp.ModExp(bytes32(x), e, pBytes))
}

func isSquare(x *u256.Uint) bool {
	l := pow(x, halfPm1)
	return l.IsZero() || l.Eq(u256.One())
}

func sgn0(x *u256.Uint) uint64 { return x.Uint64() & 1 }

func g(x *u256.Uint) *u256.Uint { return add(mul(mul(x, x), x), b) }

// mapToCurve is the Shallue-van de Woestijne map (RFC 9380 6.6.1), as
// gnark-crypto writes it for BN254: 64 bytes, x|y.
func mapToCurve(u *u256.Uint) []byte {
	one := u256.One()
	tv1 := mul(mul(u, u), c1)
	tv2 := add(one, tv1)
	tv1 = sub(one, tv1)
	tv3 := pow(mul(tv1, tv2), pMinus2) // inv0
	tv4 := mul(mul(mul(u, tv1), tv3), c3)
	x1 := sub(c2, tv4)
	x2 := add(c2, tv4)
	x3 := mul(mul(mul(tv2, tv2), tv3), mul(mul(tv2, tv2), tv3))
	x3 = add(mul(x3, c4), one) // + Z
	x := x3
	if isSquare(g(x1)) {
		x = x1
	} else if isSquare(g(x2)) {
		x = x2
	}
	y := pow(g(x), quarterP)
	if sgn0(u) != sgn0(y) {
		y = sub(u256.Zero(), y)
	}
	return append(bytes32(x), bytes32(y)...)
}

// bytes32 is a value as 32 big-endian bytes.
func bytes32(x *u256.Uint) []byte {
	out := make([]byte, 32)
	for i := 0; i < 4; i++ {
		limb := new(u256.Uint).Rsh(x, uint(64*i)).Uint64()
		for j := 0; j < 8; j++ {
			out[31-8*i-j] = byte(limb >> (8 * j))
		}
	}
	return out
}

func mustHex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := range out {
		out[i] = unhex(s[2*i])<<4 | unhex(s[2*i+1])
	}
	return out
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	panic("not hex")
}

func keccak256Sum(b []byte) []byte {
	s := keccak256.Sum256(b)
	return s[:]
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
