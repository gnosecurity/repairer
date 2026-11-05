package approve

import (
	"crypto/ed25519"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
)

// The fixture is a real statement: gnokey v1.7.0 signed it offline on the
// devbox with the public test key "owner", for chain id autopatch:test,
// account 0, sequence 1. The golden files are what gno v1.7.0's own
// Tx.GetSignBytes and GetSignBytesLegacy give for it.
const (
	fixtureChain = "autopatch:test"
	fixtureMemo  = "autopatch: yes to guard 3526eb39300e on tiers A,B until 2026-11-06"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixture(t *testing.T) ([]byte, GnokeyTx) {
	t.Helper()
	b := read(t, "yes-gnokey-v1.7.0.json")
	var tx GnokeyTx
	if err := json.Unmarshal(b, &tx); err != nil {
		t.Fatal(err)
	}
	return b, tx
}

func fixtureCall(tx GnokeyTx) Call {
	m := tx.Msg[0]
	return Call{Caller: m.Caller, Func: m.Func, Args: m.Args}
}

// The agent's rebuilt bytes equal gno's own, byte for byte, in both
// renderings.
func TestSignBytesMatchGno(t *testing.T) {
	_, tx := fixture(t)
	for _, c := range []struct {
		legacy bool
		golden string
	}{{false, "signbytes-current.txt"}, {true, "signbytes-legacy.txt"}} {
		got, err := SignBytes(fixtureChain, 1, fixtureCall(tx), fixtureMemo, c.legacy)
		if err != nil {
			t.Fatal(err)
		}
		if want := read(t, c.golden); string(got) != string(want) {
			t.Errorf("legacy=%v:\n got %s\nwant %s", c.legacy, got, want)
		}
	}
}

func TestVerifyGnokeyFixture(t *testing.T) {
	b, tx := fixture(t)
	pub := tx.Signatures[0].PubKey.Value
	st, err := VerifyGnokey(b, fixtureChain, 1, pub, fixtureMemo)
	if err != nil {
		t.Fatal(err)
	}
	if st.Call.Func != "Yes" || len(st.Call.Args) != 3 || st.Call.Args[1] != "A,B" {
		t.Fatalf("statement %+v", st)
	}
}

// Every way of changing what was signed, or where, is refused.
func TestVerifyGnokeyRefusals(t *testing.T) {
	b, tx := fixture(t)
	pub := tx.Signatures[0].PubKey.Value
	other := append([]byte(nil), pub...)
	other[5] ^= 1
	cases := []struct {
		name  string
		tx    []byte
		chain string
		seq   uint64
		pub   []byte
		memo  string
	}{
		{"another fleet", b, "autopatch:other", 1, pub, fixtureMemo},
		{"another sequence", b, fixtureChain, 2, pub, fixtureMemo},
		{"a memo the agent didn't write", b, fixtureChain, 1, pub, fixtureMemo + "!"},
		{"another key pinned", b, fixtureChain, 1, other, fixtureMemo},
		{"an argument changed", []byte(strings.Replace(string(b), `"A,B"`, `"A,B,C"`, 1)), fixtureChain, 1, pub, fixtureMemo},
		{"the function changed", []byte(strings.Replace(string(b), `"func":"Yes"`, `"func":"Off"`, 1)), fixtureChain, 1, pub, fixtureMemo},
		{"another realm", []byte(strings.Replace(string(b), `gno.land/r/autopatch/approve`, `gno.land/r/autopatch/approv`, 1)), fixtureChain, 1, pub, fixtureMemo},
		{"coins sent", []byte(strings.Replace(string(b), `"send":""`, `"send":"1ugnot"`, 1)), fixtureChain, 1, pub, fixtureMemo},
		{"not JSON", []byte("{"), fixtureChain, 1, pub, fixtureMemo},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := VerifyGnokey(c.tx, c.chain, c.seq, c.pub, c.memo); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// secp256k1's group order.
var order, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

func TestVerifySecp256k1Edges(t *testing.T) {
	_, tx := fixture(t)
	pub := tx.Signatures[0].PubKey.Value
	sig := tx.Signatures[0].Signature
	msg := read(t, "signbytes-current.txt")
	if !VerifySecp256k1(pub, msg, sig) {
		t.Fatal("the real signature fails")
	}
	// The same signature with s replaced by order-s is mathematically valid,
	// but high; gno refuses it, and so must the agent.
	s := new(big.Int).SetBytes(sig[32:])
	high := new(big.Int).Sub(order, s).FillBytes(make([]byte, 32))
	malleable := append(append([]byte(nil), sig[:32]...), high...)
	cases := map[string]struct{ pub, sig []byte }{
		"high s":              {pub, malleable},
		"r and s zero":        {pub, make([]byte, 64)},
		"r equal to order":    {pub, append(order.FillBytes(make([]byte, 32)), sig[32:]...)},
		"short signature":     {pub, sig[:63]},
		"uncompressed prefix": {append([]byte{4}, pub[1:]...), sig},
		"key not on curve":    {append([]byte{2}, make([]byte, 32)...), sig},
	}
	for name, c := range cases {
		if VerifySecp256k1(c.pub, msg, c.sig) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckSeq(t *testing.T) {
	for _, c := range []struct {
		last, seq uint64
		ok        bool
	}{{0, 1, true}, {5, 6, true}, {5, 5, false}, {5, 4, false}, {5, 1005, true}, {5, 1006, false}, {0, ^uint64(0), false}} {
		if err := CheckSeq(c.last, c.seq); (err == nil) != c.ok {
			t.Errorf("CheckSeq(%d, %d) = %v", c.last, c.seq, err)
		}
	}
}

func TestVerifyEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, []byte("Tested"))
	if !VerifyEd25519(pub, []byte("Tested"), sig) || VerifyEd25519(pub, []byte("tested"), sig) || VerifyEd25519(pub[:31], []byte("Tested"), sig) {
		t.Fatal("ed25519 check wrong")
	}
}

func TestChainID(t *testing.T) {
	a := ChainID([]byte{1, 2, 3}, "home")
	if !strings.HasPrefix(a, "autopatch:") || !strings.HasSuffix(a, "/home") || len(a) != len("autopatch:")+16+len("/home") {
		t.Fatalf("%q", a)
	}
	if a == ChainID([]byte{1, 2, 4}, "home") {
		t.Fatal("two owners' fleets named home share a chain id")
	}
}
