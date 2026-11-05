package signer

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
)

const ownerHex = "02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"

// The fleet of approve's signed fixtures (see agent/tick_test.go).
func fixturePolicies(t *testing.T) (*policy.Policy, *policy.Policy) {
	t.Helper()
	old, err := policy.Decode([]byte(`{"fleet":"test","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"` + ownerHex + `"},
		"vetters":[{"name":"v1","key":"2222222222222222222222222222222222222222222222222222222222222222"}],"vetters_needed":1},
		"tiers":[{"name":"A","hosts":["backup","mail"],"admit":["me","vetters"],"canaries":["backup"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	new, err := policy.Decode([]byte(`{"fleet":"test","replaces":"` + old.Hash() + `","delay_seconds":172800,
		"signers":{"me":{"name":"owner","key":"` + ownerHex + `"},
		"vetters":[{"name":"v1","key":"2222222222222222222222222222222222222222222222222222222222222222"},
		           {"name":"v2","key":"3333333333333333333333333333333333333333333333333333333333333333"}],"vetters_needed":2},
		"tiers":[{"name":"A","hosts":["backup","mail"],"admit":["me","vetters"],"canaries":["backup"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return old, new
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

func owner(t *testing.T) []byte {
	b, err := hex.DecodeString(ownerHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../approve/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The tool's statements are the ones the agent accepts: the real
// gnokey-signed fixtures pass the tool's own check, memo for memo.
func TestToolMatchesTheAgent(t *testing.T) {
	old, new := fixturePolicies(t)
	g := guardOne(t)
	y := approve.Yes{Tiers: []string{"A"}, Until: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), Mode: "undo"}
	st, err := PrepareYes(old, g, y, 7)
	if err != nil {
		t.Fatal(err)
	}
	var tx approve.GnokeyTx
	if err := json.Unmarshal(fixture(t, "yes-guard-one.json"), &tx); err != nil {
		t.Fatal(err)
	}
	if st.Memo != tx.Memo {
		t.Fatalf("the tool's memo\n%s\nthe signed one\n%s", st.Memo, tx.Memo)
	}
	if err := st.verify(fixture(t, "yes-guard-one.json"), owner(t)); err != nil {
		t.Fatal(err)
	}
	pst, err := PreparePolicy(old, new, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := pst.verify(fixture(t, "policy-change.json"), owner(t)); err != nil {
		t.Fatal(err)
	}
	// The same fixtures under another sequence or another Yes fail the check.
	st2, _ := PrepareYes(old, g, approve.Yes{Tiers: []string{"A"}, Until: y.Until, Mode: "keep"}, 7)
	if err := st2.verify(fixture(t, "yes-guard-one.json"), owner(t)); err == nil {
		t.Fatal("a keep accepted an undo's signature")
	}
	st3, _ := PrepareYes(old, g, y, 9)
	if err := st3.verify(fixture(t, "yes-guard-one.json"), owner(t)); err == nil {
		t.Fatal("another sequence accepted")
	}
}

func TestPrepareRefuses(t *testing.T) {
	old, _ := fixturePolicies(t)
	g := guardOne(t)
	if _, err := PrepareYes(old, g, approve.Yes{Tiers: []string{"Z"}, Until: time.Now().Add(time.Hour), Mode: "undo"}, 1); err == nil {
		t.Error("a tier the policy lacks")
	}
	if _, err := PrepareOff(old, g, []string{"nosuchhost"}, 1); err == nil {
		t.Error("a host the policy lacks")
	}
	if _, err := PrepareOff(old, g, []string{"mail", "mail"}, 1); err == nil {
		t.Error("a host twice")
	}
	st, err := PrepareOff(old, g, []string{"mail"}, 1)
	if err != nil || !strings.Contains(st.Memo, "Off "+g.Name()) || !strings.HasSuffix(st.Memo, "hosts mail") {
		t.Fatalf("%v %+v", err, st)
	}
}

func TestDefaultMode(t *testing.T) {
	p, err := policy.Decode([]byte(`{"fleet":"test","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"` + ownerHex + `"}},
		"tiers":[{"name":"A","hosts":["backup"],"admit":["me"]},{"name":"B","hosts":["validator"],"admit":["me"],"critical":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	kev := map[string]bool{"CVE-2026-98432": true}
	cases := []struct {
		tiers, flaws []string
		want         string
	}{
		{[]string{"A"}, []string{"CVE-2026-98432"}, "keep"},
		{[]string{"A", "B"}, []string{"CVE-2026-98432"}, "undo"}, // never keep on a critical tier
		{[]string{"A"}, []string{"CVE-2099-1"}, "undo"},
	}
	for _, c := range cases {
		if got := DefaultMode(p, c.tiers, c.flaws, kev); got != c.want {
			t.Errorf("%v %v: %s, want %s", c.tiers, c.flaws, got, c.want)
		}
	}
}

// reportFleet is a policy whose agents have real keys, and a way to write
// each one's signed report.
func reportFleet(t *testing.T) (*policy.Policy, map[string]ed25519.PrivateKey) {
	t.Helper()
	keys := map[string]ed25519.PrivateKey{}
	var agents []string
	for _, h := range []string{"backup", "mail"} {
		_, k, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		keys[h] = k
		agents = append(agents, `{"name":"`+h+`","key":"`+hex.EncodeToString(k.Public().(ed25519.PublicKey))+`","host":"`+h+`"}`)
	}
	p, err := policy.Decode([]byte(`{"fleet":"test","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"` + ownerHex + `"},"agents":[` + strings.Join(agents, ",") + `]},
		"tiers":[{"name":"A","hosts":["backup","mail"],"admit":["me"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return p, keys
}

func writeReport(t *testing.T, dir string, key ed25519.PrivateKey, body map[string]any) {
	t.Helper()
	writeReportAs(t, filepath.Join(dir, body["host"].(string)+".json"), key, body)
}

func writeReportAs(t *testing.T, path string, key ed25519.PrivateKey, body map[string]any) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	sr, err := json.Marshal(approve.SignReport(key, b))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, sr, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The pending-policy check reads every machine's fresh signed report. A
// missing, stale, forged or misaddressed report fails the check unless the
// owner names that machine; a pending policy is shown.
func TestCheckReports(t *testing.T) {
	p, keys := reportFleet(t)
	chain, _, _ := chainOf(p)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	body := func(host string, at time.Time) map[string]any {
		return map[string]any{"kind": "report", "chain": chain, "host": host, "time": at, "policy": p.Hash(), "owner_seq": 7}
	}
	dir := t.TempDir()
	writeReport(t, dir, keys["backup"], body("backup", now.Add(-5*time.Minute)))
	pending := body("mail", now.Add(-time.Minute))
	pending["pending"] = map[string]any{"hash": strings.Repeat("ab", 32), "first_seen": now.Add(-time.Hour)}
	pending["owner_seq"] = 9
	writeReport(t, dir, keys["mail"], pending)
	c, err := CheckReports(dir, p, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Pending || c.OwnerSeq != 9 || len(c.Lines) != 2 || !strings.Contains(c.Lines[1], "PENDING") {
		t.Fatalf("%+v", c)
	}

	bad := map[string]func(){
		"stale":            func() { writeReport(t, dir, keys["mail"], body("mail", now.Add(-20*time.Minute))) },
		"missing":          func() { os.Remove(filepath.Join(dir, "mail.json")) },
		"signed by backup": func() { writeReport(t, dir, keys["backup"], body("mail", now)) },
		"another host's":   func() { writeReportAs(t, filepath.Join(dir, "mail.json"), keys["mail"], body("backup", now)) },
		"from the future":  func() { writeReport(t, dir, keys["mail"], body("mail", now.Add(time.Hour))) },
	}
	for name, spoil := range bad {
		writeReport(t, dir, keys["backup"], body("backup", now))
		spoil()
		if _, err := CheckReports(dir, p, nil, now); err == nil || !strings.Contains(err.Error(), "mail") {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := CheckReports(dir, p, []string{"mail"}, now); err != nil {
			t.Errorf("%s, named: %v", name, err)
		}
	}
	writeReport(t, dir, keys["backup"], body("backup", now))
	writeReport(t, dir, keys["mail"], body("mail", now))
	if _, err := CheckReports(dir, p, []string{"mail"}, now); err == nil {
		t.Error("named a machine whose report is fresh")
	}
	if _, err := CheckReports(dir, p, []string{"nosuch"}, now); err == nil {
		t.Error("named a machine the policy lacks")
	}
}

// Keys are checked against the owner's own address book.
func TestCheckBook(t *testing.T) {
	_, new := fixturePolicies(t)
	book := Book{"owner": ownerHex, "v1": strings.Repeat("22", 32), "v2": strings.Repeat("33", 32)}
	if _, _, err := CheckBook(book, new, false); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Book{
		"a name with another key":  {"owner": ownerHex, "v1": strings.Repeat("22", 32), "v2": strings.Repeat("44", 32)},
		"a key under another name": {"owner": ownerHex, "v1": strings.Repeat("22", 32), "eve": strings.Repeat("33", 32)},
		"a name the book lacks":    {"owner": ownerHex, "v1": strings.Repeat("22", 32)},
	}
	for name, b := range cases {
		if _, _, err := CheckBook(b, new, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, notes, err := CheckBook(b, new, true); err != nil || len(notes) == 0 {
			t.Errorf("%s, confirmed: %v %v", name, err, notes)
		}
	}
	add, _, _ := CheckBook(cases["a name the book lacks"], new, true)
	if add["v2"] != strings.Repeat("33", 32) {
		t.Errorf("not added: %v", add)
	}
}

// With a real gnokey and a test keybase (GNOKEY_BIN, GNOKEY_HOME,
// GNOKEY_KEY, GNOKEY_PASSWORD), the tool signs each kind of statement and
// the result passes the agent's check. With GOLDEN_OUT it also writes the
// signed files there, as fixtures.
func TestGnokeyGolden(t *testing.T) {
	bin, home := os.Getenv("GNOKEY_BIN"), os.Getenv("GNOKEY_HOME")
	if bin == "" || home == "" {
		t.Skip("set GNOKEY_BIN, GNOKEY_HOME, GNOKEY_KEY and GNOKEY_PASSWORD to sign with a test keybase")
	}
	gk := Gnokey{Bin: bin, Home: home, Key: os.Getenv("GNOKEY_KEY"), Password: os.Getenv("GNOKEY_PASSWORD")}
	old, new := fixturePolicies(t)
	g := guardOne(t)
	yes, err := PrepareYes(old, g, approve.Yes{Tiers: []string{"A"}, Until: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), Mode: "keep", NoCanary: true}, 10)
	if err != nil {
		t.Fatal(err)
	}
	off, err := PrepareOff(old, g, []string{"mail"}, 11)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := PreparePolicy(old, new, 12)
	if err != nil {
		t.Fatal(err)
	}
	again, err := PrepareYes(old, g, approve.Yes{Tiers: []string{"A"}, Until: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), Mode: "undo", NoCanary: true}, 13)
	if err != nil {
		t.Fatal(err)
	}
	for name, st := range map[string]*Statement{"yes": yes, "off": off, "policy": pol, "yes again": again} {
		signed, err := gk.Sign(context.Background(), st, owner(t))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// Tampered after signing: the agent's check fails.
		bad := []byte(strings.Replace(string(signed), `"memo":"autopatch/1`, `"memo":"autopatch/2`, 1))
		if st.verify(bad, owner(t)) == nil {
			t.Fatalf("%s: a changed memo passed", name)
		}
	}
}

// TiersPolicies are the policies of the "tiers" fixture chain: T0, then T1
// (a longer delay) replacing it, then T2 (tier A spaced 15 minutes)
// replacing T1 while T1 is still pending.
func TiersPolicies(t *testing.T) []*policy.Policy {
	t.Helper()
	tiers := `"tiers":[{"name":"A","hosts":["backup","mail","web"],"admit":["me"],"canaries":["backup"]%s},
		{"name":"B","hosts":["sentry"],"admit":["me"],"critical":true},
		{"name":"C","hosts":["validator"],"admit":["me"],"critical":true}]`
	mk := func(replaces string, delay int, spacing string) *policy.Policy {
		p, err := policy.Decode([]byte(`{"fleet":"tiers","replaces":"` + replaces + `","delay_seconds":` + strconv.Itoa(delay) + `,
			"signers":{"me":{"name":"owner","key":"` + ownerHex + `"}},` + fmt.Sprintf(tiers, spacing) + `}`))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	t0 := mk("", 86400, "")
	t1 := mk(t0.Hash(), 172800, "")
	t2 := mk(t1.Hash(), 172800, `,"spacing_seconds":900`)
	return []*policy.Policy{t0, t1, t2}
}

// The "tiers" chain, signed with the test keybase into GOLDEN_OUT/tiers:
// 1 Yes(A, keep+nocanary), 2 Yes(B), 3 Yes(C), 4 Off(mail), 5 Yes(A,
// undo+nocanary), 6 On(mail), 7 Policy T1 over T0, 8 Policy T2 over the
// pending T1. The guard is guard one's drop half.
func TestGnokeyTiersChain(t *testing.T) {
	bin, home, out := os.Getenv("GNOKEY_BIN"), os.Getenv("GNOKEY_HOME"), os.Getenv("GOLDEN_OUT")
	if bin == "" || home == "" || out == "" {
		t.Skip("set GNOKEY_BIN, GNOKEY_HOME, GNOKEY_KEY, GNOKEY_PASSWORD and GOLDEN_OUT")
	}
	gk := Gnokey{Bin: bin, Home: home, Key: os.Getenv("GNOKEY_KEY"), Password: os.Getenv("GNOKEY_PASSWORD")}
	ps := TiersPolicies(t)
	b, err := os.ReadFile("../guard/testdata/cve-2026-98432-ipopt.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := guard.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	yes := func(tier, mode string, nocanary bool, seq uint64) *Statement {
		st, err := PrepareYes(ps[0], g, approve.Yes{Tiers: []string{tier}, Until: until, Mode: mode, NoCanary: nocanary}, seq)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	must := func(st *Statement, err error) *Statement {
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	chain := []*Statement{
		yes("A", "keep", true, 1),
		yes("B", "undo", false, 2),
		yes("C", "undo", false, 3),
		must(PrepareOff(ps[0], g, []string{"mail"}, 4)),
		yes("A", "undo", true, 5),
		must(PrepareOn(ps[0], g, []string{"mail"}, 6)),
		must(PreparePolicy(ps[0], ps[1], 7)),
		must(PreparePolicy(ps[1], ps[2], 8)),
	}
	dir := filepath.Join(out, "tiers")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i, st := range chain {
		signed, err := gk.Sign(context.Background(), st, owner(t))
		if err != nil {
			t.Fatalf("statement %d: %v", i+1, err)
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d.json", i+1)), signed, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for i, p := range ps {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("policy-%d.json", i)), p.Canonical(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
