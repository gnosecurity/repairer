package drandbn254

import "testing"

// drand evmnet's public key and round 1000, as api.drand.sh serves them.
const (
	pubHex = "07e1d1d335df83fa98462005690372c643340060d205306a9aa8106b6bd0b3820557ec32c2ad488e4d4f6008f89a346f18492092ccc0d594610de2732c8b808f0095685ae3a85ba243747b1b2f426049010f6b73a0cf1d389351d5aaaa1047f6297d3a4f9749b33eb2d904c9d9ebf17224150ddd7abd7567a9bec6c74480ee0b"
	sigHex = "06fd5996329504d3a56b482d9222bf7205857d0a9559ddd216ca31a286f6a8cc0a120f021aac2f13553fb164f62bc3a5ca32c76dea88a777b39bcf3cac5fdbd6"
	// H(keccak256(1000)) from the Go reference (gnark-crypto).
	hHex = "0305acba00a19b010c9393b3046bac874f31a78f0edb159211a5e6edd27fcfb60d5997c2e6c22897ba8f18b291c80cd9df62ffca7217e615fc0bebe6f3b783da"
)

func TestHashToG1MatchesTheReference(t *testing.T) {
	var r [8]byte
	r[6], r[7] = 0x03, 0xe8 // 1000
	m := keccak256Sum(r[:])
	if got := hexOf(HashToG1(m)); got != hHex {
		t.Fatalf("H(m) = %s, the reference says %s", got, hHex)
	}
}

func TestRound1000(t *testing.T) {
	pub, sig := mustHex(pubHex), mustHex(sigHex)
	if !Verify(pub, 1000, sig) {
		t.Fatal("drand evmnet round 1000 didn't verify")
	}
	if Verify(pub, 1001, sig) {
		t.Fatal("round 1000's signature verified for round 1001")
	}
	bad := append([]byte{}, sig...)
	bad[63] ^= 1
	if Verify(pub, 1000, bad) {
		t.Fatal("a changed signature verified")
	}
	// The point at infinity, as all zeros, verifies nothing.
	if Verify(make([]byte, 128), 1000, make([]byte, 64)) || Verify(pub, 1000, make([]byte, 64)) {
		t.Fatal("an all-zero key or signature verified")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
