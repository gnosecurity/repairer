package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
}
