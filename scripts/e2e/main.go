// Command e2e makes the inputs for the end-to-end VM test and checks its
// outputs. It is test tooling, not part of the agent.
//
//	go run ./scripts/e2e gen DIR                a policy, two guards, and a bundle with the rig's Tested
//	go run ./scripts/e2e verify REPORT KEYHEX   check a signed report and print a summary
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jaekwon/autopatch/agent"
	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 2 && args[0] == "gen" {
		return gen(args[1])
	}
	if len(args) == 3 && args[0] == "verify" {
		return verify(args[1], args[2])
	}
	return fmt.Errorf("usage: gen DIR | verify REPORT KEYHEX")
}

func gen(dir string) error {
	_, rig, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	p, err := policy.Decode([]byte(`{"fleet":"e2e","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"},
		"rig":[{"name":"rig1","key":"` + hex.EncodeToString(rig.Public().(ed25519.PublicKey)) + `"}]},
		"tiers":[{"name":"A","hosts":["vm1"],"admit":["rig"]}],
		"health":[{"hosts":["vm1"],"kind":"tcp","target":"127.0.0.1:22","want":""}]}`))
	if err != nil {
		return err
	}
	now, err := guard.Decode([]byte(`{"id":"cve-2026-98432/linux-ipv4-ipopt","version":1,"flaws":["CVE-2026-98432"],
		"for":[{"os":"ubuntu","releases":["22.04","24.04","26.04"]}],
		"blocks":[{"drop":{"family":"ipv4","protocol":"tcp","ip_options":true}}],
		"breaks":"IP Record Route and Timestamp on TCP"}`))
	if err != nil {
		return err
	}
	later, err := guard.Decode([]byte(`{"id":"cve-2026-98432/linux-mptcp-off","version":1,"flaws":["CVE-2026-98432"],
		"for":[{"os":"ubuntu","releases":["22.04","24.04","26.04"]}],
		"blocks":[{"setting":{"name":"net.mptcp.enabled","value":"0"}}],
		"breaks":"new MPTCP sockets"}`))
	if err != nil {
		return err
	}
	bun := agent.Bundle{Guards: map[string][]byte{}}
	var names []string
	for _, g := range []*guard.Guard{now, later} {
		sg, err := approve.SignStatement(rig, approve.Statement{Version: approve.MemoVersion, Kind: approve.KindTested,
			Chain: "autopatch:vet", Guard: g.Hash(), Rig: strings.Repeat("0", 64)})
		if err != nil {
			return err
		}
		bun.Guards[g.Hash()] = g.Canonical()
		bun.Signed = append(bun.Signed, sg)
		names = append(names, g.Hash()+" "+g.Name())
	}
	b, err := json.Marshal(bun)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, data := range map[string][]byte{
		"policy.json": p.Canonical(),
		"bundle.json": b,
		"guards.txt":  []byte(strings.Join(names, "\n") + "\n"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func verify(path, key string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	body, err := approve.VerifyReport(b, key)
	if err != nil {
		return err
	}
	var r agent.FleetReport
	if err := json.Unmarshal(body, &r); err != nil {
		return err
	}
	fmt.Printf("report %d from %s at %s, signature good; policy %.16s\n", r.Seq, r.Host, r.Time.Format("15:04:05"), r.Policy)
	for _, g := range r.Guards {
		fmt.Printf("  on: %s %s by=%s later=%v boot_window=%v booted=%v stopped=%d\n", g.Name, g.Status, g.By, g.Later, g.BootWindow, g.Booted, g.Stopped)
	}
	for _, w := range r.OnTheWay {
		fmt.Printf("  on its way: %s baseline=%d tries=%d refused=%q last=%q\n", w.Name, w.Baseline, w.Tries, w.Refused, w.Last)
	}
	if r.Facts != nil {
		fmt.Printf("  facts: %s %s, kernel %s\n", r.Facts.OS.ID, r.Facts.OS.Version, r.Facts.Kernel.Running)
	}
	for _, e := range r.Errors {
		fmt.Printf("  error: %s\n", e)
	}
	return nil
}
