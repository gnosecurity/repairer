package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
)

// join makes a second machine in the same fleet as tr: the same keys,
// policy and clock time, with its own state and fake machine.
func join(t *testing.T, tr *trial, host string) *trial {
	t.Helper()
	a, sys, timer := newAgent(t)
	o := &trial{t: t, a: a, sys: sys, timer: timer, clock: tr.clock, rig: tr.rig, keys: tr.keys, fail: map[string]string{}, p: tr.p}
	a.Now = func() time.Time { return o.clock }
	a.Health = func(_ context.Context, h policy.Health) string { return o.fail[h.Target] }
	if err := writeAtomic(filepath.Join(a.StateDir, keyFile), []byte(hex.EncodeToString(o.keys[host].Seed())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Init(host, tr.p.Canonical(), 0); err != nil {
		t.Fatal(err)
	}
	return o
}

// report reads a machine's signed report, checking its signature against
// the key the policy lists for the host.
func (tr *trial) report(host string) *FleetReport {
	tr.t.Helper()
	b, err := ReadReport(tr.a.StateDir)
	if err != nil {
		tr.t.Fatal(err)
	}
	var want string
	for _, k := range tr.p.Signers.Agents {
		if k.Host == host {
			want = k.Hex
		}
	}
	body, err := approve.VerifyReport(b, want)
	if err != nil {
		tr.t.Fatal(err)
	}
	var r FleetReport
	if err := json.Unmarshal(body, &r); err != nil {
		tr.t.Fatal(err)
	}
	return &r
}

// The whole canary loop through the lookout: mail waits and names its
// nonce in its signed report; the lookout carries the want to backup, the
// canary, which signs Healthy once its own window has passed; the lookout
// carries that back, and mail's baseline begins.
func TestCanaryLoop(t *testing.T) {
	backup := newTrial(t, "backup", "")
	mail := join(t, backup, "mail")
	g := ipoptGuard(t)
	both := func(d time.Duration) {
		backup.step(d)
		mail.step(d)
	}
	backup.tested(g)
	mail.tested(g)
	both(0)
	r := mail.report("mail")
	if len(r.Wants) != 1 || r.Wants[0].Guard != g.Hash() {
		t.Fatalf("mail's report wants %+v", r.Wants)
	}
	want := r.Wants[0]
	if r.Seq != 1 || r.Policy != backup.p.Hash() || r.Host != "mail" || r.Facts == nil {
		t.Fatalf("mail's report: seq %d policy %s host %s facts %v", r.Seq, r.Policy, r.Host, r.Facts != nil)
	}
	if rb := backup.report("backup"); len(rb.Wants) != 0 {
		t.Fatalf("a canary asked for wants: %+v", rb.Wants)
	}
	backup.deliver(Bundle{Wants: []Want{want}})
	both(time.Minute)
	if h := backup.report("backup").Healthy; len(h) != 0 {
		t.Fatalf("the canary answered before its guard was confirmed: %+v", h)
	}
	for i := 0; i < 12; i++ { // backup: baseline, apply, window
		both(time.Minute)
		if e := backup.entry(g); e != nil && e.Status == Pending {
			if h := backup.report("backup").Healthy; len(h) != 0 {
				t.Fatalf("the canary answered during its own window: %+v", h)
			}
		}
	}
	if e := backup.entry(g); e == nil || e.Status != Confirmed {
		t.Fatalf("backup: %+v", e)
	}
	h := backup.report("backup").Healthy
	if len(h) != 1 || h[0].Statement.State != approve.StateOn || h[0].Statement.Nonce != want.Nonce || h[0].Statement.Host != "backup" {
		t.Fatalf("backup's Healthy: %+v", h)
	}
	if res := mail.step(time.Minute); len(res.Waiting) != 1 {
		t.Fatalf("mail went on before the Healthy reached it: %+v", res)
	}
	mail.deliver(Bundle{Signed: h})
	if res := mail.step(time.Minute); len(res.Baseline) != 1 {
		t.Fatalf("the canary's Healthy didn't release mail: %+v", res)
	}
	if r2 := mail.report("mail"); r2.Seq <= r.Seq || len(r2.Wants) != 1 {
		t.Fatalf("mail's later report: seq %d, wants %+v", r2.Seq, r2.Wants)
	}
}

// A canary that refuses for a listed reason says so; the refusal releases
// a guard that bites now, but not one that bites later.
func TestCanaryRefusal(t *testing.T) {
	for _, c := range []struct {
		name    string
		g       func(*testing.T) *guard.Guard
		setup   func(*trial)
		code    string
		release bool
	}{
		{"a later guard refused for netns", mptcpGuard, func(tr *trial) { tr.sys.inUse["netns"] = "dockerd's namespaces" }, "netns", false},
		{"a now guard refused for a protected flow", func(t *testing.T) *guard.Guard { return portGuard(t, "test/tcp8443", "tcp", "8443") }, nil, "protected-flow", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			backup := newTrial(t, "backup", `,"protected":[{"hosts":["backup"],"proto":"tcp","port":8443}]`)
			mail := join(t, backup, "mail")
			if c.setup != nil {
				c.setup(backup)
			}
			g := c.g(t)
			backup.tested(g)
			mail.tested(g)
			backup.tick()
			mail.tick()
			want := mail.report("mail").Wants[0]
			backup.deliver(Bundle{Wants: []Want{want}})
			backup.step(time.Minute)
			h := backup.report("backup").Healthy
			if len(h) != 1 || h[0].Statement.State != approve.StateRefused || h[0].Statement.Why != c.code {
				t.Fatalf("backup's Healthy: %+v", h)
			}
			mail.deliver(Bundle{Signed: h})
			res := mail.step(time.Minute)
			if released := len(res.Baseline) == 1; released != c.release {
				t.Fatalf("released %v, want %v: %+v", released, c.release, res)
			}
		})
	}
}

// A canary signs "refused" only for a guard it admitted itself: a refusal
// left in its evidence from an admission that has lapsed signs nothing.
func TestCanaryRefusesOnlyWhatItAdmitted(t *testing.T) {
	backup := newTrial(t, "backup", "")
	g := ipoptGuard(t)
	ev := &Evidence{Guard: g.Canonical(), Refused: "something", RefusedCode: "in-use"} // no Tested, no Yes
	if err := backup.a.saveEvidence(g.Hash(), ev); err != nil {
		t.Fatal(err)
	}
	backup.deliver(Bundle{Wants: []Want{{Guard: g.Hash(), Nonce: strings.Repeat("ab", 16)}}})
	backup.tick()
	if h := backup.report("backup").Healthy; len(h) != 0 {
		t.Fatalf("signed for a guard it never admitted: %+v", h)
	}
}

// A machine that isn't a canary signs no Healthy, whatever it is asked.
func TestOnlyCanariesAnswer(t *testing.T) {
	backup := newTrial(t, "backup", "")
	mail := join(t, backup, "mail")
	g := ipoptGuard(t)
	ev := &Evidence{Guard: g.Canonical(), Yes: &approve.Yes{Hash: g.Hash(), Tiers: []string{"A"}, Until: mail.clock.Add(time.Hour), Mode: "keep", NoCanary: true}}
	if err := mail.a.saveEvidence(g.Hash(), ev); err != nil {
		t.Fatal(err)
	}
	mail.tick() // keep: on at once
	if e := mail.entry(g); e == nil || e.Status != Confirmed {
		t.Fatalf("%+v", e)
	}
	mail.deliver(Bundle{Wants: []Want{{Guard: g.Hash(), Nonce: strings.Repeat("ab", 16)}}})
	mail.step(time.Minute)
	if h := mail.report("mail").Healthy; len(h) != 0 {
		t.Fatalf("a machine that isn't a canary answered: %+v", h)
	}
}

// The spool belongs to the unprivileged half, so tick reads it as hostile:
// a symlink, a fifo and an oversized file are refused and the tick goes on.
func TestSpoolIsUntrusted(t *testing.T) {
	tr := newTrial(t, "backup", "")
	spool := filepath.Join(tr.a.StateDir, spoolDir)
	if err := os.MkdirAll(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte(`{"messages":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(spool, "1-link.json")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(spool, "2-fifo.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A valid bundle padded past the cap: refused for its size alone.
	big := append([]byte(`{"messages":[]}`), []byte(strings.Repeat(" ", MaxBundle))...)
	if err := os.WriteFile(filepath.Join(spool, "3-big.json"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	g := ipoptGuard(t)
	tr.tested(g) // a good bundle after the bad ones
	res := tr.tick()
	if len(res.Refused) != 3 || len(res.Baseline) != 1 {
		t.Fatalf("%+v", res)
	}
	if names, _ := filepath.Glob(filepath.Join(spool, "*")); len(names) != 0 {
		t.Fatalf("left in the spool: %v", names)
	}
	if _, err := os.Stat(secret); err != nil {
		t.Fatal("the link's target was touched")
	}
}

// Wants are kept only when well formed: a guard's full hash and a nonce of
// 32 lowercase hex digits. A bad one is dropped at intake, so it can't stop
// the canary from answering the good ones.
func TestWantsWellFormed(t *testing.T) {
	backup := newTrial(t, "backup", "")
	g := ipoptGuard(t)
	ev := &Evidence{Guard: g.Canonical(), Yes: &approve.Yes{Hash: g.Hash(), Tiers: []string{"A"}, Until: backup.clock.Add(time.Hour), Mode: "keep"}}
	if err := backup.a.saveEvidence(g.Hash(), ev); err != nil {
		t.Fatal(err)
	}
	backup.tick()
	good := Want{Guard: g.Hash(), Nonce: strings.Repeat("ab", 16)}
	backup.deliver(Bundle{Wants: []Want{
		{Guard: g.Hash(), Nonce: strings.Repeat("AB", 16)},
		{Guard: g.Hash(), Nonce: "abab"},
		{Guard: g.Hash()[:63], Nonce: strings.Repeat("cd", 16)},
		good,
	}})
	res := backup.step(time.Minute)
	if len(res.Refused) != 0 {
		t.Fatalf("%+v", res.Refused)
	}
	h := backup.report("backup").Healthy
	if len(h) != 1 || h[0].Statement.Nonce != good.Nonce || h[0].Statement.State != approve.StateOn {
		t.Fatalf("%+v", h)
	}
}

// init's halves: the unprivileged user owns only the spool, and reads only
// the report directory, whose group new reports keep.
func TestSetupHalves(t *testing.T) {
	tr := newTrial(t, "backup", "")
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	name := me.Username
	if me.Uid == "0" {
		name = "nobody" // the devbox runs tests as root
	}
	u, err := user.Lookup(name)
	if err != nil {
		t.Skip("no user to test with:", err)
	}
	if err := SetupHalves(tr.a.StateDir, name); err != nil {
		t.Fatal(err)
	}
	check := func(path string, mode os.FileMode, uid, gid string) {
		t.Helper()
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if fi.Mode()&(os.ModePerm|os.ModeSetgid) != mode || (uid != "" && strconv.Itoa(int(st.Uid)) != uid) || strconv.Itoa(int(st.Gid)) != gid && gid != "" {
			t.Fatalf("%s: mode %v uid %d gid %d", path, fi.Mode(), st.Uid, st.Gid)
		}
	}
	check(tr.a.StateDir, 0o711, "", "")
	check(filepath.Join(tr.a.StateDir, SpoolDir), 0o700, u.Uid, u.Gid)
	check(filepath.Join(tr.a.StateDir, OutDir), 0o750|os.ModeSetgid, strconv.Itoa(os.Geteuid()), u.Gid)
	tr.tick()
	check(filepath.Join(tr.a.StateDir, OutDir, reportFile), 0o640, "", u.Gid)
	if err := SetupHalves(tr.a.StateDir, "root"); err == nil {
		t.Fatal("root as the intake user")
	}
}
