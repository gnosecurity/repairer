// Command e2e makes the inputs for the end-to-end VM test and checks its
// outputs. It is test tooling, not part of the agent.
//
//	go run ./scripts/e2e gen DIR                a policy, two guards, and a bundle with the rig's Tested
//	go run ./scripts/e2e verify REPORT KEYHEX   check a signed report and print a summary
//	go run ./scripts/e2e genreboot DIR MODE WINDOW KERNEL NOTAFTER
//	                                            B3's VM test: a policy whose tier reboots by MODE
//	                                            (window or yes), and the owner's signed Reboots of
//	                                            vm1 into KERNEL (Unix seconds NOTAFTER), sequences
//	                                            1 and 2 (reboot-1.json, reboot-2.json)
//	go run ./scripts/e2e gencheck DIR SINCE PKG  W1's VM test: the same fleet, and the owner's signed
//	                                            Checks in order (check-1.json ... check-4.json): new
//	                                            setuid files since SINCE (twice), processes running a
//	                                            deleted program, and package PKG's files
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/jaekwon/autopatch/agent"
	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/check"
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
	if len(args) == 2 && args[0] == "gen3" {
		return gen3(args[1])
	}
	if len(args) == 6 && args[0] == "genreboot" {
		return genReboot(args[1], args[2], args[3], args[4], args[5])
	}
	if len(args) == 4 && args[0] == "gencheck" {
		return genCheck(args[1], args[2], args[3])
	}
	return fmt.Errorf("usage: gen DIR | gen3 DIR | verify REPORT KEYHEX | genreboot DIR MODE WINDOW KERNEL NOTAFTER")
}

// gen3 makes C2's inputs: a policy for three machines (vm1 the canary,
// vm2 and vm3 five minutes apart) with their agents' keys, each machine's
// key seed, the guard, and the rig's Tested for it.
func gen3(dir string) error {
	_, rig, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	files := map[string][]byte{}
	var agents []string
	for _, h := range []string{"vm1", "vm2", "vm3"} {
		_, k, err := ed25519.GenerateKey(nil)
		if err != nil {
			return err
		}
		files[h+".seed"] = []byte(hex.EncodeToString(k.Seed()) + "\n")
		agents = append(agents, `{"name":"`+h+`","key":"`+hex.EncodeToString(k.Public().(ed25519.PublicKey))+`","host":"`+h+`"}`)
	}
	p, err := policy.Decode([]byte(`{"fleet":"c2","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"},
		"rig":[{"name":"rig1","key":"` + hex.EncodeToString(rig.Public().(ed25519.PublicKey)) + `"}],
		"agents":[` + strings.Join(agents, ",") + `]},
		"rigs":["` + strings.Repeat("0", 64) + `"],
		"tiers":[{"name":"A","hosts":["vm1","vm2","vm3"],"admit":["rig"],"canaries":["vm1"],"spacing_seconds":300}],
		"health":[{"hosts":["vm1","vm2","vm3"],"kind":"tcp","target":"127.0.0.1:22","want":""}]}`))
	if err != nil {
		return err
	}
	g, err := guard.Decode([]byte(`{"id":"cve-2026-98432/linux-ipv4-ipopt","version":1,"flaws":["CVE-2026-98432"],
		"for":[{"os":"ubuntu","releases":["22.04","24.04","26.04"]}],
		"blocks":[{"drop":{"family":"ipv4","protocol":"tcp","ip_options":true}}],
		"breaks":"IP Record Route and Timestamp on TCP"}`))
	if err != nil {
		return err
	}
	sg, err := approve.SignStatement(rig, approve.Statement{Version: approve.MemoVersion, Kind: approve.KindTested,
		Chain: "autopatch:vet", Guard: g.Hash(), Rig: strings.Repeat("0", 64), Image: "ubuntu 24.04"})
	if err != nil {
		return err
	}
	tested, err := json.Marshal(sg)
	if err != nil {
		return err
	}
	files["policy.json"], files["guard.json"], files["tested.json"] = p.Canonical(), g.Canonical(), tested
	files["guard.txt"] = []byte(g.Hash() + "\n")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func gen(dir string) error {
	_, rig, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	p, err := policy.Decode([]byte(`{"fleet":"e2e","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"},
		"rig":[{"name":"rig1","key":"` + hex.EncodeToString(rig.Public().(ed25519.PublicKey)) + `"}]},
		"rigs":["` + strings.Repeat("0", 64) + `"],
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
			Chain: "autopatch:vet", Guard: g.Hash(), Rig: strings.Repeat("0", 64), Image: "ubuntu 24.04"})
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
	if r.Tick != nil && r.Tick.Reboot != "" {
		fmt.Printf("  reboot: %s\n", r.Tick.Reboot)
	}
	for _, h := range r.Hits {
		fmt.Printf("  hit: %s ran=%s flag=%v count=%d gone=%d capped=%q error=%q paths=%s\n", h.Name, h.Ran.Format("15:04:05"),
			h.Flag, h.Count, h.Gone, h.Capped, h.Error, strings.Join(h.Paths, ","))
	}
	for _, sk := range r.Skipped {
		fmt.Printf("  skipped: %d %s: %s\n", sk.Seq, sk.What, sk.Why)
	}
	for _, e := range r.Errors {
		fmt.Printf("  error: %s\n", e)
	}
	return nil
}

// genReboot makes B3's VM test inputs: the owner's key is a test key from a
// fixed seed (public: this is test tooling), the policy's one tier holds
// vm1 and reboots by mode, and reboot-1.json and reboot-2.json are bundles
// carrying the owner's signed Reboots of vm1 into kernel, sequences 1 and
// 2, as gnokey would sign them (the second for when the system asks for a
// reboot once the kernel runs).
func genReboot(dir, mode, window, kernel, notAfter string) error {
	seed := sha256.Sum256([]byte("autopatch e2e owner"))
	owner := secp256k1.PrivKeyFromBytes(seed[:])
	pub := owner.PubKey().SerializeCompressed()
	tier := `"reboot":"` + mode + `"`
	if mode == "window" {
		tier += `,"reboot_window":"` + window + `"`
	}
	p, err := policy.Decode([]byte(`{"fleet":"e2e","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"` + hex.EncodeToString(pub) + `"}},
		"tiers":[{"name":"A","hosts":["vm1"],"admit":["me"],` + tier + `}],
		"health":[{"hosts":["vm1"],"kind":"tcp","target":"127.0.0.1:22","want":""}]}`))
	if err != nil {
		return err
	}
	n, err := strconv.ParseInt(notAfter, 10, 64)
	if err != nil {
		return err
	}
	r := approve.Reboot{Host: "vm1", Kernel: kernel, NotAfter: n}
	memo, err := approve.MemoReboot(r)
	if err != nil {
		return err
	}
	const caller = "g1ss6w8xfy7vnp595yely63jqa8553k03mjcglen"
	chain := approve.ChainID(pub, p.Fleet)
	bundles := map[string][]byte{}
	for _, seq := range []uint64{1, 2} {
		msg, err := approve.SignBytes(chain, seq, approve.Call{Caller: caller, Func: "Reboot", Args: r.Args()}, memo, false)
		if err != nil {
			return err
		}
		h := sha256.Sum256(msg)
		tx, err := json.Marshal(map[string]any{
			"msg": []any{map[string]any{"@type": "/vm.m_call", "caller": caller, "send": "", "max_deposit": "",
				"pkg_path": approve.Realm, "func": "Reboot", "args": r.Args()}},
			"fee":        map[string]any{"gas_wanted": "0", "gas_fee": "0ugnot"},
			"signatures": []any{map[string]any{"pub_key": map[string]any{"@type": "/tm.PubKeySecp256k1", "value": pub}, "signature": ecdsa.SignCompact(owner, h[:], true)[1:]}},
			"memo":       memo,
		})
		if err != nil {
			return err
		}
		if _, err := approve.VerifyReboot(tx, chain, seq, pub); err != nil {
			return fmt.Errorf("the Reboot doesn't verify: %w", err)
		}
		bun, err := json.Marshal(agent.Bundle{Messages: []agent.Message{{Seq: seq, Tx: tx}}})
		if err != nil {
			return err
		}
		bundles[fmt.Sprintf("reboot-%d.json", seq)] = bun
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	bundles["policy.json"] = p.Canonical()
	for name, data := range bundles {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// genCheck makes W1's VM test inputs: the fleet of genReboot (its owner key
// from the same fixed seed, a tier that waits for the owner), and bundles
// carrying the owner's signed Checks with their files, sequences 1 to 4.
func genCheck(dir, since, pkg string) error {
	seed := sha256.Sum256([]byte("autopatch e2e owner"))
	owner := secp256k1.PrivKeyFromBytes(seed[:])
	pub := owner.PubKey().SerializeCompressed()
	p, err := policy.Decode([]byte(`{"fleet":"e2e","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"` + hex.EncodeToString(pub) + `"}},
		"tiers":[{"name":"A","hosts":["vm1"],"admit":["me"]}],
		"health":[{"hosts":["vm1"],"kind":"tcp","target":"127.0.0.1:22","want":""}]}`))
	if err != nil {
		return err
	}
	mk := func(kind string, args check.Args, flag string) (*check.Check, error) {
		c := &check.Check{ID: "e2e/" + kind, Version: 1, Flaws: []string{"CVE-2026-98432"},
			For: []guard.Target{{OS: "ubuntu", Releases: []string{"24.04"}}}, Kind: kind, Args: args, Flag: flag}
		return c, c.Validate()
	}
	setuid, err := mk(check.NewSince, check.Args{What: "setuid", Since: since}, "a setuid or setgid file is new")
	if err != nil {
		return err
	}
	deleted, err := mk(check.DeletedExe, check.Args{}, "a process runs a deleted program")
	if err != nil {
		return err
	}
	files, err := mk(check.PackageFiles, check.Args{Package: pkg}, "a file of "+pkg+" differs from its package")
	if err != nil {
		return err
	}
	const caller = "g1ss6w8xfy7vnp595yely63jqa8553k03mjcglen"
	chain := approve.ChainID(pub, p.Fleet)
	out := map[string][]byte{"policy.json": p.Canonical()}
	for i, c := range []*check.Check{setuid, setuid, deleted, files} {
		seq := uint64(i + 1)
		memo, err := approve.MemoCheck(c)
		if err != nil {
			return err
		}
		msg, err := approve.SignBytes(chain, seq, approve.Call{Caller: caller, Func: "Check", Args: []string{c.Hash()}}, memo, false)
		if err != nil {
			return err
		}
		h := sha256.Sum256(msg)
		tx, err := json.Marshal(map[string]any{
			"msg": []any{map[string]any{"@type": "/vm.m_call", "caller": caller, "send": "", "max_deposit": "",
				"pkg_path": approve.Realm, "func": "Check", "args": []string{c.Hash()}}},
			"fee":        map[string]any{"gas_wanted": "0", "gas_fee": "0ugnot"},
			"signatures": []any{map[string]any{"pub_key": map[string]any{"@type": "/tm.PubKeySecp256k1", "value": pub}, "signature": ecdsa.SignCompact(owner, h[:], true)[1:]}},
			"memo":       memo,
		})
		if err != nil {
			return err
		}
		if err := approve.VerifyCheck(tx, chain, seq, pub, c); err != nil {
			return fmt.Errorf("the Check doesn't verify: %w", err)
		}
		bun, err := json.Marshal(agent.Bundle{Messages: []agent.Message{{Seq: seq, Tx: tx}}, Checks: map[string][]byte{c.Hash(): c.Canonical()}})
		if err != nil {
			return err
		}
		out[fmt.Sprintf("check-%d.json", seq)] = bun
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, data := range out {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
