package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
	"github.com/jaekwon/autopatch/signer"
)

// The tool end to end with a real gnokey and a test keybase (GNOKEY_BIN,
// GNOKEY_HOME, GNOKEY_KEY, GNOKEY_PASSWORD; the key must be the public test
// key "owner"): it checks the machines' signed reports, picks the next
// sequence above what the agents report, signs, and writes a message an
// agent accepts.
func TestSignYes(t *testing.T) {
	bin, home := os.Getenv("GNOKEY_BIN"), os.Getenv("GNOKEY_HOME")
	if bin == "" || home == "" {
		t.Skip("set GNOKEY_BIN, GNOKEY_HOME, GNOKEY_KEY and GNOKEY_PASSWORD")
	}
	testPassword = os.Getenv("GNOKEY_PASSWORD")
	dir := t.TempDir()
	_, mailKey, _ := ed25519.GenerateKey(nil)
	const ownerHex = "02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"
	p, err := policy.Decode([]byte(`{"fleet":"signtest","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"` + ownerHex + `"},
		"agents":[{"name":"mail","key":"` + hex.EncodeToString(mailKey.Public().(ed25519.PublicKey)) + `","host":"mail"}]},
		"tiers":[{"name":"A","hosts":["mail"],"admit":["me"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	pfile := filepath.Join(dir, "policy.json")
	os.WriteFile(pfile, p.Canonical(), 0o644)
	gfile := filepath.Join(dir, "guard.json")
	gb, _ := os.ReadFile("../../guard/testdata/cve-2026-98432.json")
	os.WriteFile(gfile, gb, 0o644)
	g, _ := guard.Parse(gb)
	reports := filepath.Join(dir, "reports")
	os.MkdirAll(reports, 0o755)
	owner, _ := hex.DecodeString(ownerHex)
	chain := approve.ChainID(owner, "signtest")
	body, _ := json.Marshal(map[string]any{"kind": "report", "chain": chain, "host": "mail", "time": time.Now().UTC(), "policy": p.Hash(), "owner_seq": 41})
	sr, _ := json.Marshal(approve.SignReport(mailKey, body))
	common := []string{"-policy", pfile, "-reports", reports, "-key", os.Getenv("GNOKEY_KEY"), "-gnokey", bin, "-home", home,
		"-config", filepath.Join(dir, "config"), "-yes"}
	until := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	yesArgs := append(append([]string{}, common...), "-tiers", "A", "-until", until, "-out", filepath.Join(dir, "msg.json"), gfile)

	// No report from mail: refused, and the error says how to go on.
	var out bytes.Buffer
	if err := run(context.Background(), "yes", yesArgs, &out); err == nil || !strings.Contains(err.Error(), "-unchecked") {
		t.Fatalf("signed without mail's report: %v", err)
	}
	os.WriteFile(filepath.Join(reports, "mail.json"), sr, 0o644)
	out.Reset()
	if err := run(context.Background(), "yes", yesArgs, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "as sequence 42") || !strings.Contains(out.String(), "mail: policy") {
		t.Fatalf("output:\n%s", out.String())
	}
	b, err := os.ReadFile(filepath.Join(dir, "msg.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m signer.Message
	if err := json.Unmarshal(b, &m); err != nil || m.Seq != 42 {
		t.Fatalf("%v %+v", err, m)
	}
	y, err := approve.VerifyYes(m.Tx, chain, 42, owner, g)
	if err != nil || y.Mode != "undo" || y.Tiers[0] != "A" {
		t.Fatalf("the agent's check: %v %+v", err, y)
	}
	// The tool remembers the sequence: the next statement is 43.
	out.Reset()
	offArgs := append(append([]string{}, common...), "-hosts", "mail", "-out", filepath.Join(dir, "off.json"), gfile)
	if err := run(context.Background(), "off", offArgs, &out); err != nil || !strings.Contains(out.String(), "as sequence 43") {
		t.Fatalf("%v\n%s", err, out.String())
	}

	// Mail reports the guard off. A keep Yes for this guard, which bites
	// later, comes with nocanary, and the tool says the Yes won't put the
	// guard back on mail.
	body, _ = json.Marshal(map[string]any{"kind": "report", "chain": chain, "host": "mail", "time": time.Now().UTC(), "policy": p.Hash(), "owner_seq": 43, "off": []string{g.Hash()}})
	sr, _ = json.Marshal(approve.SignReport(mailKey, body))
	os.WriteFile(filepath.Join(reports, "mail.json"), sr, 0o644)
	out.Reset()
	keepArgs := append(append([]string{}, common...), "-tiers", "A", "-until", until, "-mode", "keep", "-out", filepath.Join(dir, "keep.json"), gfile)
	if err := run(context.Background(), "yes", keepArgs, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, want := range []string{"as sequence 44", "mode keep+nocanary", "nocanary too", "no machine will boot with it first", "doesn't put the guard back on mail", "taken up to 43"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	for _, n := range []string{"42", "43", "44"} {
		if _, err := os.Stat(filepath.Join(dir, "config", "statements", "signtest", n+".json")); err != nil {
			t.Errorf("statement %s wasn't kept: %v", n, err)
		}
	}

	// A change of the owner's key, signed: after it, the tool won't sign
	// with the old key (round 6).
	newOwner, _ := secp256k1.GeneratePrivateKey()
	np, err := policy.Decode([]byte(strings.Replace(strings.Replace(string(p.Canonical()), ownerHex, hex.EncodeToString(newOwner.PubKey().SerializeCompressed()), 1),
		`"replaces":""`, `"replaces":"`+p.Hash()+`"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	npFile := filepath.Join(dir, "policy-new.json")
	os.WriteFile(npFile, np.Canonical(), 0o644)
	out.Reset()
	polArgs := append(append([]string{}, common...), "-confirm-keys", "-out", filepath.Join(dir, "pol.json"), npFile)
	if err := run(context.Background(), "policy", polArgs, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	out.Reset()
	if err := run(context.Background(), "yes", yesArgs, &out); err == nil || !strings.Contains(err.Error(), "change of your key") {
		t.Fatalf("signed with the old key after a change of key: %v", err)
	}

	// Cancelling that change puts the old key back: the tool signs with it
	// again. Mail shows the change nearly through its delay, and the tool
	// warns that a Cancel arriving later can't stop it there (round 8,
	// minor 7).
	body, _ = json.Marshal(map[string]any{"kind": "report", "chain": chain, "host": "mail", "time": time.Now().UTC(), "policy": p.Hash(), "owner_seq": 45,
		"pending": map[string]any{"hash": np.Hash(), "first_seen": time.Now().Add(-23 * time.Hour).UTC()}})
	sr, _ = json.Marshal(approve.SignReport(mailKey, body))
	os.WriteFile(filepath.Join(reports, "mail.json"), sr, 0o644)
	out.Reset()
	cancelArgs := append(append([]string{}, common...), "-out", filepath.Join(dir, "cancel.json"), np.Hash())
	if err := run(context.Background(), "cancel", cancelArgs, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "on mail the change takes effect in") {
		t.Errorf("no warning that the delay is nearly over:\n%s", out.String())
	}
	out.Reset()
	if err := run(context.Background(), "yes", yesArgs, &out); err != nil {
		t.Fatalf("the old key after the Cancel: %v\n%s", err, out.String())
	}
}

// standing lists the Yeses in force, each with only the tiers it is still
// the newest for, and leaves out ended ones: what to sign again for a
// machine added or rebuilt (round 8, new major 3).
func TestStanding(t *testing.T) {
	dir := t.TempDir()
	p, err := policy.Decode([]byte(`{"fleet":"standtest","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"}},
		"tiers":[{"name":"A","hosts":["mail"],"admit":["me"]},{"name":"B","hosts":["web"],"admit":["me"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	pfile := filepath.Join(dir, "policy.json")
	os.WriteFile(pfile, p.Canonical(), 0o644)
	kept := filepath.Join(dir, "config", "statements", "standtest")
	os.MkdirAll(kept, 0o700)
	g1, g2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	laterT := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	later := laterT.Format(time.RFC3339)
	unix := func(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }
	write := func(seq int, fn string, args ...string) {
		tx, _ := json.Marshal(map[string]any{"msg": []map[string]any{{"func": fn, "args": args}}})
		m, _ := json.Marshal(map[string]any{"seq": seq, "tx": json.RawMessage(tx)})
		os.WriteFile(filepath.Join(kept, strconv.Itoa(seq)+".json"), m, 0o600)
	}
	// Numbers whose files sort apart from their order: 10.json before 9.json.
	write(9, "Yes", g1, "A,B", unix(laterT), "undo")
	write(10, "Yes", g1, "A", unix(laterT), "keep+nocanary")
	write(11, "Yes", g2, "A", unix(time.Now().Add(-time.Hour)), "undo")
	write(12, "Off", g1, "mail")
	var out bytes.Buffer
	if err := run(context.Background(), "standing", []string{"-policy", pfile, "-config", filepath.Join(dir, "config")}, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"statement 9, guard aaaaaaaaaaaaaaaa, tiers B,",
		"-tiers B -until " + later + " -mode undo GUARD.json",
		"statement 10, guard aaaaaaaaaaaaaaaa, tiers A,",
		"-tiers A -until " + later + " -mode keep -nocanary GUARD.json",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "bbbbbbbbbbbbbbbb") || strings.Contains(got, "statement 12") {
		t.Errorf("an ended Yes or an Off listed:\n%s", got)
	}
}

// A policy whose tier admits the rig with no rig build pinned would count
// no Tested there: the tool won't sign it, and says why, before anything
// reaches gnokey (round 9, minor 12). Pinned, it goes on to the address
// book, which here has never seen the rig's key.
func TestPolicyRigsPinned(t *testing.T) {
	dir := t.TempDir()
	_, mailKey, _ := ed25519.GenerateKey(nil)
	const ownerHex = "02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"
	p, err := policy.Decode([]byte(`{"fleet":"pintest","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"` + ownerHex + `"},
		"agents":[{"name":"mail","key":"` + hex.EncodeToString(mailKey.Public().(ed25519.PublicKey)) + `","host":"mail"}]},
		"tiers":[{"name":"A","hosts":["mail"],"admit":["me"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	pfile := filepath.Join(dir, "policy.json")
	os.WriteFile(pfile, p.Canonical(), 0o644)
	reports := filepath.Join(dir, "reports")
	os.MkdirAll(reports, 0o755)
	owner, _ := hex.DecodeString(ownerHex)
	body, _ := json.Marshal(map[string]any{"kind": "report", "chain": approve.ChainID(owner, "pintest"), "host": "mail", "time": time.Now().UTC(), "policy": p.Hash(), "owner_seq": 1})
	sr, _ := json.Marshal(approve.SignReport(mailKey, body))
	os.WriteFile(filepath.Join(reports, "mail.json"), sr, 0o644)
	args := func(file string) []string {
		return []string{"-policy", pfile, "-reports", reports, "-key", "owner", "-gnokey", filepath.Join(dir, "no-gnokey"),
			"-config", filepath.Join(dir, "config"), "-yes", "-out", filepath.Join(dir, "out.json"), file}
	}
	withRig := func(rigs string) string {
		np, err := policy.Decode([]byte(`{"fleet":"pintest","replaces":"` + p.Hash() + `","delay_seconds":86400,
			"signers":{"me":{"name":"owner","key":"` + ownerHex + `"},
			"rig":[{"name":"rig1","key":"` + strings.Repeat("1", 64) + `"}],
			"agents":[{"name":"mail","key":"` + hex.EncodeToString(mailKey.Public().(ed25519.PublicKey)) + `","host":"mail"}]},` + rigs + `
			"tiers":[{"name":"A","hosts":["mail"],"admit":["me","rig"]}]}`))
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(dir, "new.json")
		os.WriteFile(f, np.Canonical(), 0o644)
		return f
	}
	var out bytes.Buffer
	if err := run(context.Background(), "policy", args(withRig("")), &out); err == nil || !strings.Contains(err.Error(), "tier A admits rig, but no rig build is pinned") {
		t.Fatalf("an unpinned policy: %v", err)
	}
	out.Reset()
	if err := run(context.Background(), "policy", args(withRig(`"rigs":["`+strings.Repeat("a", 64)+`"],`)), &out); err == nil || strings.Contains(err.Error(), "rig build") {
		t.Fatalf("a pinned policy should pass the rig check and stop at the address book: %v", err)
	}
}
