package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/gnosecurity/repairer/approve"
	"github.com/gnosecurity/repairer/policy"
)

// ownerKey is a test owner's secp256k1 key, from a fixed seed, as a Ledger
// holds one.
func ownerKey() *secp256k1.PrivateKey {
	return secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{7}, 32))
}

// signStatement writes gnokey's signed transaction file for one call to
// the approve realm, signed by key for chain at seq, as gnokey sign does.
func signStatement(t *testing.T, key *secp256k1.PrivateKey, chain string, seq uint64, fn string, args []string, memo string) []byte {
	t.Helper()
	const caller = "g1ss6w8xfy7vnp595yely63jqa8553k03mjcglen"
	msg, err := approve.SignBytes(chain, seq, approve.Call{Caller: caller, Func: fn, Args: args}, memo, false)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(msg)
	sig := ecdsa.SignCompact(key, h[:], true)[1:] // r and s, low s, as gno writes them
	tx, err := json.Marshal(map[string]any{
		"msg": []any{map[string]any{"@type": "/vm.m_call", "caller": caller, "send": "", "max_deposit": "",
			"pkg_path": approve.Realm, "func": fn, "args": args}},
		"fee":        map[string]any{"gas_wanted": "0", "gas_fee": "0ugnot"},
		"signatures": []any{map[string]any{"pub_key": map[string]any{"@type": "/tm.PubKeySecp256k1", "value": key.PubKey().SerializeCompressed()}, "signature": sig}},
		"memo":       memo,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// orderAgent is rebootAgent's machine set up as a fleet whose owner key is
// ownerKey, with a way to tick it (delivering statements first) and to sign
// the owner's Reboots, sequence by sequence.
func orderAgent(t *testing.T, tier string) (a *Agent, sys *fakeSys, tick func(...Message) *TickResult, reboot func(host, kernel string, notAfter time.Time) Message, after func(time.Duration)) {
	t.Helper()
	a, sys, _, p0, after := rebootAgent(t, tier)
	key := ownerKey()
	pub := hex.EncodeToString(key.PubKey().SerializeCompressed())
	pj := strings.Replace(string(p0.Canonical()), "02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e", pub, 1)
	p, err := policy.Decode([]byte(pj))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Init("web", p.Canonical(), 0); err != nil {
		t.Fatal(err)
	}
	a.Health = func(context.Context, policy.Health) string { return "" } // every check passes
	owner, _ := hex.DecodeString(pub)
	chain := approve.ChainID(owner, p.Fleet)
	seq := uint64(0)
	reboot = func(host, kernel string, notAfter time.Time) Message {
		seq++
		r := approve.Reboot{Host: host, Kernel: kernel, NotAfter: notAfter.Unix()}
		memo, err := approve.MemoReboot(r)
		if err != nil {
			t.Fatal(err)
		}
		return Message{Seq: seq, Tx: signStatement(t, key, chain, seq, "Reboot", r.Args(), memo)}
	}
	tick = func(msgs ...Message) *TickResult {
		t.Helper()
		if len(msgs) > 0 {
			js, _ := json.Marshal(Bundle{Messages: msgs})
			if _, err := Intake(filepath.Join(a.StateDir, spoolDir), bytes.NewReader(js)); err != nil {
				t.Fatal(err)
			}
		}
		res, err := a.Tick(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	return a, sys, tick, reboot, after
}

// On a tier that waits for the owner, a signed Reboot for this host and the
// newest kernel reboots it at the next tick, once, after the report is
// written; the Reboot is spent then, even when the kernel then fails to
// boot, and only a new Reboot tries that kernel again.
func TestRebootOnYourWord(t *testing.T) {
	a, sys, tick, reboot, after := orderAgent(t, ``)
	if res := tick(); !strings.HasSuffix(res.Reboot, "this tier waits for your signed Reboot") {
		t.Fatalf("before the Reboot: %q", res.Reboot)
	}
	// When the machine is told to reboot, its report already says so.
	var reported []byte
	sys.onRun = func(line string) {
		if line == "systemctl reboot" {
			reported, _ = ReadReport(a.StateDir)
		}
	}
	res := tick(reboot("web", newRel, a.now().Add(time.Hour).Truncate(time.Minute)))
	if res.Reboot != "rebooting into "+newRel {
		t.Fatalf("on the Reboot: %q (%+v)", res.Reboot, res)
	}
	want := []string{"grub-set-default " + oldEntry, "grub-reboot " + newEntry, "systemctl reboot"}
	if got := ran(sys, "grub-", "systemctl reboot"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("ran %q, want %q", got, want)
	}
	var sr approve.SignedReport
	var body FleetReport
	if json.Unmarshal(reported, &sr) != nil || json.Unmarshal(sr.Body, &body) != nil || body.Tick == nil || body.Tick.Reboot != "rebooting into "+newRel {
		t.Fatalf("the report when it rebooted: %s", reported)
	}
	if st, _ := a.loadReboot(); st.Spent != 1 {
		t.Fatalf("the Reboot isn't spent: spent %d", st.Spent)
	}
	// It doesn't boot: the machine comes back on the old kernel.
	after(2 * time.Minute)
	bootInto(sys, oldRel)
	if res := tick(); res.Reboot != newRel+" didn't boot: back on "+oldRel {
		t.Fatalf("back on the old kernel: %q", res.Reboot)
	}
	if res := tick(); !strings.Contains(res.Reboot, "so it waits for your signed Reboot") || len(ran(sys, "grub-reboot")) != 1 {
		t.Fatalf("the spent Reboot was used again: %q", res.Reboot)
	}
	if f, _ := a.loadFleet(); len(f.Reboots) != 0 {
		t.Fatalf("the spent Reboot is still kept: %+v", f.Reboots)
	}
	// A new Reboot tries it again.
	if res := tick(reboot("web", newRel, a.now().Add(time.Hour).Truncate(time.Minute))); res.Reboot != "rebooting into "+newRel || len(ran(sys, "grub-reboot")) != 2 {
		t.Fatalf("a second Reboot: %q", res.Reboot)
	}
}

// A Reboot is used only for this host, for the newest kernel installed,
// before its deadline, and when the gates pass; otherwise it is kept and
// the report says why it waits. On a tier that never reboots by itself, the
// owner's Reboot still reboots it.
func TestRebootOrderWaits(t *testing.T) {
	t.Run("another host", func(t *testing.T) {
		a, sys, tick, reboot, _ := orderAgent(t, ``)
		res := tick(reboot("sentry", newRel, a.now().Add(time.Hour).Truncate(time.Minute)))
		f, _ := a.loadFleet()
		if len(f.Reboots) != 0 || len(ran(sys, "grub-reboot")) != 0 || !strings.Contains(strings.Join(res.Accepted, " "), "for another host") {
			t.Fatalf("%+v, kept %+v", res, f.Reboots)
		}
	})
	t.Run("past its deadline", func(t *testing.T) {
		a, sys, tick, reboot, after := orderAgent(t, ``)
		m := reboot("web", newRel, a.now().Add(10*time.Minute).Truncate(time.Minute))
		after(15 * time.Minute)
		res := tick(m)
		if !strings.Contains(res.Reboot, "your Reboot #1 into "+newRel+" passed its deadline unused") || len(ran(sys, "grub-reboot")) != 0 {
			t.Fatalf("%q", res.Reboot)
		}
		after(25 * time.Hour) // a day past it, it is dropped
		if res := tick(); strings.Contains(res.Reboot, "#1") {
			t.Fatalf("still noted: %q", res.Reboot)
		}
	})
	t.Run("another kernel", func(t *testing.T) {
		a, sys, tick, reboot, _ := orderAgent(t, ``)
		res := tick(reboot("web", "6.8.0-150-generic", a.now().Add(time.Hour).Truncate(time.Minute)))
		if !strings.Contains(res.Reboot, "your Reboot #1 names 6.8.0-150-generic, not "+newRel+", the kernel a reboot now would boot") || len(ran(sys, "grub-reboot")) != 0 {
			t.Fatalf("%q", res.Reboot)
		}
		// Once that kernel is installed and ready, the kept Reboot is used.
		sys.runOut["dpkg-query -W -f ${Package} ${Version} ${db:Status-Abbrev}\n linux-image-[0-9]*"] += "linux-image-6.8.0-150-generic 6.8.0-150.150 ii \n"
		sys.files["/boot/vmlinuz-6.8.0-150-generic"] = "kernel"
		sys.files["/boot/initrd.img-6.8.0-150-generic"] = "initrd"
		sys.files["/boot/grub/grub.cfg"] = strings.ReplaceAll(grubCfg, "6.8.0-149", "6.8.0-150")
		if res := tick(); res.Reboot != "rebooting into 6.8.0-150-generic" {
			t.Fatalf("once installed: %q", res.Reboot)
		}
	})
	t.Run("the gates", func(t *testing.T) {
		a, sys, tick, reboot, _ := orderAgent(t, ``)
		delete(sys.files, "/boot/initrd.img-"+newRel)
		res := tick(reboot("web", newRel, a.now().Add(time.Hour).Truncate(time.Minute)))
		if !strings.Contains(res.Reboot, "your Reboot #1 allows it; the gates hold it: newest kernel can boot") || len(ran(sys, "grub-reboot")) != 0 {
			t.Fatalf("%q", res.Reboot)
		}
		sys.files["/boot/initrd.img-"+newRel] = "initrd"
		if res := tick(); res.Reboot != "rebooting into "+newRel {
			t.Fatalf("once the gates pass: %q", res.Reboot)
		}
	})
	t.Run("the system asks", func(t *testing.T) {
		a, sys, tick, reboot, _ := orderAgent(t, ``)
		sys.runOut[dpkgQuery] = "linux-image-" + oldRel + " 6.8.0-142.142 ii \n"
		sys.files["/run/reboot-required"] = "*** System restart required ***\n"
		res := tick(reboot("web", oldRel, a.now().Add(time.Hour).Truncate(time.Minute)))
		if res.Reboot != "rebooting (the system asked)" || len(ran(sys, "systemctl reboot")) != 1 || len(ran(sys, "grub-reboot")) != 0 {
			t.Fatalf("%q", res.Reboot)
		}
	})
	t.Run("the running kernel", func(t *testing.T) {
		// Nothing owed, but the owner's Reboot names the running kernel: a
		// plain reboot (round 14, minor 2).
		a, sys, tick, reboot, _ := orderAgent(t, ``)
		sys.runOut[dpkgQuery] = "linux-image-" + oldRel + " 6.8.0-142.142 ii \n"
		res := tick(reboot("web", oldRel, a.now().Add(time.Hour).Truncate(time.Minute)))
		if res.Reboot != "rebooting (your Reboot #1)" || len(ran(sys, "systemctl reboot")) != 1 || len(ran(sys, "grub-reboot")) != 0 {
			t.Fatalf("%q", res.Reboot)
		}
	})
	t.Run("a tier that never reboots", func(t *testing.T) {
		a, _, tick, reboot, _ := orderAgent(t, `,"reboot":"never"`)
		if res := tick(reboot("web", newRel, a.now().Add(time.Hour).Truncate(time.Minute))); res.Reboot != "rebooting into "+newRel {
			t.Fatalf("%q", res.Reboot)
		}
	})
}

// A reboot the system won't start takes the one-shot boot back and marks
// the kernel failed; the next tick doesn't try again.
func TestRebootCommandFails(t *testing.T) {
	a, sys, f, p, _ := rebootAgent(t, `,"reboot":"window","reboot_window":"03:00-04:00"`)
	sys.failOn = "systemctl reboot"
	msg, reboot, err := a.rebootStep(ctx, f, p, nil)
	if err != nil || !reboot || msg != "rebooting into "+newRel {
		t.Fatalf("%q %v %v", msg, reboot, err)
	}
	if err := a.rebootNow(ctx); err == nil {
		t.Fatal("no error")
	}
	if got := ran(sys, "grub-editenv"); len(got) != 1 || got[0] != "grub-editenv - unset next_entry" {
		t.Fatalf("the one-shot boot wasn't taken back: %q", got)
	}
	if m := rstep(t, a, f, p, nil); !strings.Contains(m, "it failed before (systemctl reboot: ") || len(ran(sys, "grub-reboot")) != 1 {
		t.Fatalf("after: %q", m)
	}
}

// ParseReboot is strict: a host as policies name them, a kernel release,
// and a deadline in Unix seconds on a whole minute; the memo shows it all.
func TestParseReboot(t *testing.T) {
	ok := []string{"web", newRel, "1793955600"}
	r, err := approve.ParseReboot(approve.Call{Func: "Reboot", Args: ok})
	if err != nil || r.NotAfter != 1793955600 {
		t.Fatal(r, err)
	}
	memo, err := approve.MemoReboot(r)
	if err != nil || memo != "repairer/1 Reboot web into "+newRel+", once, not after 2026-11-06 09:00 UTC" {
		t.Fatalf("%q %v", memo, err)
	}
	for _, bad := range [][]string{
		{"web", newRel},
		{"web host", newRel, "1793955600"},
		{"web", "linux-6.8", "1793955600"},
		{"web", newRel + "; rm", "1793955600"},
		{"web", newRel, "1793955601"},
		{"web", newRel, "+1793955600"},
		{"web", newRel, "0"},
	} {
		if _, err := approve.ParseReboot(approve.Call{Func: "Reboot", Args: bad}); err == nil {
			t.Errorf("%q was taken", bad)
		}
	}
}
