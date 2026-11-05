// The F0 reference: verify a real drand evmnet round in Go, to pin down the
// encodings before writing the same in gno.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"golang.org/x/crypto/sha3"
)

const dst = "BLS_SIG_BN254G1_XMD:KECCAK-256_SVDW_RO_NUL_"

func keccak(parts ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// expandXMD is RFC 9380's expand_message_xmd with Keccak-256 (b=32, r=136).
func expandXMD(msg, dst []byte, n int) []byte {
	ell := (n + 31) / 32
	dstPrime := append(append([]byte{}, dst...), byte(len(dst)))
	zpad := make([]byte, 136)
	lib := []byte{byte(n >> 8), byte(n)}
	b0 := keccak(zpad, msg, lib, []byte{0}, dstPrime)
	b := keccak(b0, []byte{1}, dstPrime)
	out := append([]byte{}, b...)
	for i := 2; i <= ell; i++ {
		x := make([]byte, 32)
		for j := range x {
			x[j] = b0[j] ^ b[j]
		}
		b = keccak(x, []byte{byte(i)}, dstPrime)
		out = append(out, b...)
	}
	return out[:n]
}

func hashToG1(msg []byte) bn254.G1Affine {
	u := expandXMD(msg, []byte(dst), 96)
	var e [2]fp.Element
	p := fp.Modulus()
	for i := 0; i < 2; i++ {
		x := new(big.Int).SetBytes(u[i*48 : (i+1)*48])
		x.Mod(x, p)
		e[i].SetBigInt(x)
	}
	q0, q1 := bn254.MapToCurve1(&e[0]), bn254.MapToCurve1(&e[1])
	var s bn254.G1Jac
	s.FromAffine(&q0)
	var j1 bn254.G1Jac
	j1.FromAffine(&q1)
	s.AddAssign(&j1)
	var out bn254.G1Affine
	out.FromJacobian(&s)
	return out
}

func main() {
	printConsts()
	printNegG2()
	pkHex := "07e1d1d335df83fa98462005690372c643340060d205306a9aa8106b6bd0b3820557ec32c2ad488e4d4f6008f89a346f18492092ccc0d594610de2732c8b808f0095685ae3a85ba243747b1b2f426049010f6b73a0cf1d389351d5aaaa1047f6297d3a4f9749b33eb2d904c9d9ebf17224150ddd7abd7567a9bec6c74480ee0b"
	sigHex := "06fd5996329504d3a56b482d9222bf7205857d0a9559ddd216ca31a286f6a8cc0a120f021aac2f13553fb164f62bc3a5ca32c76dea88a777b39bcf3cac5fdbd6"
	pkb, _ := hex.DecodeString(pkHex)
	sigb, _ := hex.DecodeString(sigHex)
	var sig bn254.G1Affine
	sig.X.SetBytes(sigb[:32])
	sig.Y.SetBytes(sigb[32:])
	fmt.Println("sig on curve:", sig.IsOnCurve())
	_, _, _, g2 := bn254.Generators()
	var negG2 bn254.G2Affine
	negG2.Neg(&g2)
	round := make([]byte, 8)
	binary.BigEndian.PutUint64(round, 1000)
	for _, order := range []string{"x1x0y1y0 (imaginary first)", "x0x1y0y1 (real first)"} {
		var pk bn254.G2Affine
		c := func(i int) []byte { return pkb[i*32 : (i+1)*32] }
		if order[0:4] == "x1x0" {
			pk.X.A1.SetBytes(c(0)); pk.X.A0.SetBytes(c(1)); pk.Y.A1.SetBytes(c(2)); pk.Y.A0.SetBytes(c(3))
		} else {
			pk.X.A0.SetBytes(c(0)); pk.X.A1.SetBytes(c(1)); pk.Y.A0.SetBytes(c(2)); pk.Y.A1.SetBytes(c(3))
		}
		if !pk.IsOnCurve() {
			fmt.Println(order, ": the key isn't on the curve")
			continue
		}
		for name, msg := range map[string][]byte{"keccak256(round)": keccak(round), "round itself": round} {
			h := hashToG1(msg)
			ok, err := bn254.PairingCheck([]bn254.G1Affine{sig, h}, []bn254.G2Affine{negG2, pk})
			fmt.Printf("%s, message %s: verifies %v %v\n", order, name, ok, err)
			if ok {
				hb := h.RawBytes()
				fmt.Printf("  H(m) = %x\n", hb)
			}
		}
	}
}
