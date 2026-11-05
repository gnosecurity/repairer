package approve

import (
	"crypto/ed25519"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
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

func guardOne(t *testing.T) *guard.Guard {
	t.Helper()
	b, err := os.ReadFile("../guard/testdata/cve-2026-98432.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := guard.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// yes-guard-one.json is a Yes to guard one on tier A until 2026-11-06, mode
// undo, with the memo MemoYes writes (TestPrintFixtures wrote it), signed by
// gnokey v1.7.0 with the public test key "owner" for that key's fleet
// "test", sequence 7.
func TestVerifyYes(t *testing.T) {
	b := read(t, "yes-guard-one.json")
	var tx GnokeyTx
	if err := json.Unmarshal(b, &tx); err != nil {
		t.Fatal(err)
	}
	pub := tx.Signatures[0].PubKey.Value
	chain := ChainID(pub, "test")
	if chain != "autopatch:c9216f6e4272339f/test" {
		t.Fatalf("chain id %q", chain)
	}
	g := guardOne(t)
	y, err := VerifyYes(b, chain, 7, pub, g)
	if err != nil {
		t.Fatal(err)
	}
	if y.Hash != g.Hash() || len(y.Tiers) != 1 || y.Tiers[0] != "A" || y.Mode != "undo" || y.Until.Format(time.RFC3339) != "2026-11-06T00:00:00Z" {
		t.Fatalf("yes %+v", y)
	}

	g2 := *g
	g2.Version = 2
	edits := map[string][]byte{
		"tier B instead of A":   []byte(strings.Replace(string(b), `"A","1793923200"`, `"B","1793923200"`, 1)),
		"a later end":           []byte(strings.Replace(string(b), `"1793923200"`, `"1893923200"`, 1)),
		"keep instead of undo":  []byte(strings.Replace(string(b), `"undo"]`, `"keep"]`, 1)),
		"a memo in other words": []byte(strings.Replace(string(b), "mode undo", "mode undo ", 1)),
		"another function":      []byte(strings.Replace(string(b), `"func":"Yes"`, `"func":"Off"`, 1)),
	}
	for name, e := range edits {
		if _, err := VerifyYes(e, chain, 7, pub, g); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := VerifyYes(b, chain, 7, pub, &g2); err == nil {
		t.Error("a Yes to guard one accepted for another version of it")
	}
	if _, err := VerifyYes(b, ChainID(pub, "prod"), 7, pub, g); err == nil {
		t.Error("accepted for another fleet")
	}
}

func TestMemoLimits(t *testing.T) {
	g := guardOne(t)
	y := Yes{Hash: g.Hash(), Tiers: []string{"A"}, Until: time.Unix(1793923200, 0), Mode: "undo"}
	if _, err := MemoYes(g, y); err != nil {
		t.Fatal(err)
	}
	long := *g
	long.Blocks = nil
	for i := 0; i < 16; i++ {
		long.Blocks = append(long.Blocks, guard.Block{Drop: &guard.Drop{Family: "ipv4", Protocol: "udp", Ports: []string{"1000-1999", "3000-3010"}}})
	}
	y.Hash = long.Hash()
	if _, err := MemoYes(&long, y); err == nil || !strings.Contains(err.Error(), "smaller steps") {
		t.Fatalf("a too-long memo: %v", err)
	}
	for _, bad := range []Call{
		{Func: "Yes", Args: []string{"zz", "A", "1", "undo"}},
		{Func: "Yes", Args: []string{g.Hash(), "A,A", "1", "undo"}},
		{Func: "Yes", Args: []string{g.Hash(), "A", "01", "undo"}},
		{Func: "Yes", Args: []string{g.Hash(), "A", "1", "forever"}},
		{Func: "Yes", Args: []string{g.Hash(), "A", "1"}},
	} {
		if _, err := ParseYes(bad); err == nil {
			t.Errorf("%v accepted", bad.Args)
		}
	}
}

// policy-change.json is the owner's Policy statement for fixturePolicies'
// change (TestPrintFixtures wrote its memo), signed by gnokey v1.7.0 with
// the test key "owner", sequence 8.
func TestVerifyPolicy(t *testing.T) {
	b := read(t, "policy-change.json")
	var tx GnokeyTx
	if err := json.Unmarshal(b, &tx); err != nil {
		t.Fatal(err)
	}
	pub := tx.Signatures[0].PubKey.Value
	chain := ChainID(pub, "test")
	old, new := fixturePolicies(t)
	if err := VerifyPolicy(b, chain, 8, pub, old, new); err != nil {
		t.Fatal(err)
	}
	if want := "autopatch/1 Policy test " + new.Hash()[:16] + " replaces " + old.Hash()[:16] + ": delay 86400s->172800s; vetters +v2 3333333333333333333333333333333333333333333333333333333333333333; vetters needed 1->2"; tx.Memo != want {
		t.Fatalf("memo %q", tx.Memo)
	}
	// The same signature can't carry a different change.
	other := *new
	other.DelaySeconds = 3600
	if err := VerifyPolicy(b, chain, 8, pub, old, &other); err == nil {
		t.Error("accepted for another policy")
	}
	if err := VerifyPolicy(b, chain, 9, pub, old, new); err == nil {
		t.Error("accepted at another sequence")
	}
	if err := VerifyPolicy(b, chain, 8, pub, new, old); err == nil {
		t.Error("accepted backwards")
	}
}

func TestMemoPolicyRefusals(t *testing.T) {
	old, new := fixturePolicies(t)
	if _, err := MemoPolicy(old, old); err == nil {
		t.Error("a policy replacing nothing it names")
	}
	same := *new
	same.Signers = old.Signers
	same.DelaySeconds = old.DelaySeconds
	if _, err := MemoPolicy(old, &same); err == nil || !strings.Contains(err.Error(), "changes nothing") {
		t.Errorf("no change: %v", err)
	}
	moved := *new
	moved.Fleet = "prod"
	if _, err := MemoPolicy(old, &moved); err == nil {
		t.Error("moved to another fleet")
	}
	big := *new
	big.Signers.Vetters = nil
	for i := 0; i < 9; i++ {
		big.Signers.Vetters = append(big.Signers.Vetters, policy.Key{Name: "vetter" + strings.Repeat("x", i), Hex: strings.Repeat(string(rune('a'+i)), 64)})
	}
	if _, err := MemoPolicy(old, &big); err == nil || !strings.Contains(err.Error(), "smaller steps") {
		t.Errorf("a diff too big for a Ledger: %v", err)
	}
}

// A change of the pinned rig builds shows each build's whole hash, so the
// owner reads on the Ledger exactly which rig's Tested will count (round
// 9, minor 12).
func TestMemoPolicyRigs(t *testing.T) {
	old, _ := fixturePolicies(t)
	pinned := *old
	pinned.Replaces = old.Hash()
	pinned.Rigs = []string{strings.Repeat("a", 64)}
	m, err := MemoPolicy(old, &pinned)
	if err != nil || !strings.HasSuffix(m, ": rig build +"+strings.Repeat("a", 64)) {
		t.Fatalf("memo %q, %v", m, err)
	}
	moved := pinned
	moved.Replaces = pinned.Hash()
	moved.Rigs = []string{strings.Repeat("b", 64)}
	if m, err := MemoPolicy(&pinned, &moved); err != nil || !strings.Contains(m, "rig build -"+strings.Repeat("a", 64)+"; rig build +"+strings.Repeat("b", 64)) {
		t.Fatalf("memo %q, %v", m, err)
	}
}

// A tier's reboot mode, window and order show in the memo of the policy
// change, so the owner reads on the Ledger that machines will now reboot
// themselves, when, and after whom (B3).
func TestMemoPolicyReboots(t *testing.T) {
	old, _ := fixturePolicies(t)
	nw := *old
	nw.Replaces = old.Hash()
	nw.Tiers = append([]policy.Tier(nil), old.Tiers...)
	nw.Tiers[0].Reboot, nw.Tiers[0].RebootWindow = "window", "03:00-04:00"
	m, err := MemoPolicy(old, &nw)
	if err != nil || !strings.Contains(m, "reboots itself 03:00-04:00 UTC") {
		t.Fatalf("memo %q, %v", m, err)
	}
	after := nw
	after.Replaces = nw.Hash()
	after.Tiers = append(append([]policy.Tier(nil), nw.Tiers...),
		policy.Tier{Name: "B", Hosts: []string{"web"}, Admit: []string{"me"}, Reboot: "yes", RebootAfter: nw.Tiers[0].Hosts[0]})
	if m, err := MemoPolicy(&nw, &after); err != nil || !strings.Contains(m, "B hosts web admit me reboots on your Reboot after "+nw.Tiers[0].Hosts[0]) {
		t.Fatalf("memo %q, %v", m, err)
	}
}
