package agent

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/nft"
)

var ctx = context.Background()

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

// otherGuard blocks a module and also turns MPTCP off, so it shares a
// setting with guard number one.
func otherGuard(t *testing.T) *guard.Guard {
	t.Helper()
	g, err := guard.Parse([]byte(`{"id": "test/ksmbd", "version": 1, "flaws": ["CVE-2099-1"],
		"for": [{"os": "ubuntu", "releases": ["24.04"]}],
		"blocks": [{"module": {"name": "ksmbd"}}, {"setting": {"name": "net.mptcp.enabled", "value": "0"}}],
		"breaks": "the in-kernel SMB server"}`))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func newAgent(t *testing.T) (*Agent, *fakeSys, *fakeTimer) {
	t.Helper()
	sys := newFakeSys()
	timer := &fakeTimer{sys: sys, armed: map[string]time.Duration{}}
	return &Agent{Sys: sys, Timer: timer, StateDir: t.TempDir()}, sys, timer
}

func load(t *testing.T, a *Agent) *State {
	t.Helper()
	s, st, err := a.open()
	if err != nil {
		t.Fatal(err)
	}
	s.close()
	return st
}

// index returns where a log line starting with prefix first appears, or -1.
func index(log []string, prefix string) int {
	for i, l := range log {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	return -1
}

func TestApplyConfirmUndoGuardOne(t *testing.T) {
	a, sys, timer := newAgent(t)
	g := guardOne(t)
	h := g.Hash()
	table := "ip " + nft.TableName(h)

	e, err := a.Apply(ctx, g, ApplyOptions{ConfirmWithin: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != Pending || e.Applied != 2 || e.Unprobed {
		t.Fatalf("entry %+v", e)
	}
	// The undo is armed before the first change, and the drop goes on
	// before the setting.
	arm, load_, set, probe := index(sys.log, "arm "), index(sys.log, "nft load ip"), index(sys.log, "setting net.mptcp.enabled=0"), index(sys.log, "probe")
	if !(arm >= 0 && arm < load_ && load_ < set && set < probe) {
		t.Fatalf("order arm %d, load %d, setting %d, probe %d in %q", arm, load_, set, probe, sys.log)
	}
	if timer.armed[h] != 10*time.Minute {
		t.Fatalf("armed for %v", timer.armed[h])
	}
	if sys.tables[table] == nil || sys.tables[table].packets != 1 || sys.settings["net.mptcp.enabled"] != "0" {
		t.Fatalf("live: table %+v, mptcp %s", sys.tables[table], sys.settings["net.mptcp.enabled"])
	}
	if _, ok := sys.files[SysctlFile]; ok {
		t.Fatal("a pending guard wrote a lasting setting")
	}
	if got := load(t, a).Originals.Settings["net.mptcp.enabled"]; got != "1" {
		t.Fatalf("original mptcp %q", got)
	}

	if _, err := a.Confirm(ctx, h[:12]); err != nil {
		t.Fatal(err)
	}
	if st := load(t, a); st.Guards[0].Status != Confirmed {
		t.Fatalf("status %s", st.Guards[0].Status)
	}
	if !strings.Contains(sys.files[SysctlFile], "net.mptcp.enabled = 0") {
		t.Fatalf("sysctl file %q", sys.files[SysctlFile])
	}
	if _, ok := timer.armed[h]; ok {
		t.Fatal("undo still armed after confirm")
	}

	if _, err := a.Undo(ctx, g.ID, false); err != nil {
		t.Fatal(err)
	}
	if sys.tables[table] != nil || sys.settings["net.mptcp.enabled"] != "1" {
		t.Fatalf("after undo: table %v, mptcp %s", sys.tables[table], sys.settings["net.mptcp.enabled"])
	}
	if _, ok := sys.files[SysctlFile]; ok {
		t.Fatal("sysctl file left behind")
	}
	if st := load(t, a); len(st.Guards) != 0 || len(st.Originals.Settings) != 0 {
		t.Fatalf("state %+v", st)
	}
}

func TestConfirmWithinZeroConfirmsAfterProbe(t *testing.T) {
	a, sys, _ := newAgent(t)
	e, err := a.Apply(ctx, guardOne(t), ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != Confirmed || index(sys.log, "probe") > index(sys.log, "write "+SysctlFile) {
		t.Fatalf("status %s, log %q", e.Status, sys.log)
	}
}

// A failure partway takes off what went on, disarms the undo and leaves no
// state.
func TestApplyFailureTakesItAllOff(t *testing.T) {
	for _, failOn := range []string{"setting net.mptcp.enabled=0", "probe", "nft load"} {
		t.Run(failOn, func(t *testing.T) {
			a, sys, timer := newAgent(t)
			sys.failOn = failOn
			g := guardOne(t)
			if _, err := a.Apply(ctx, g, ApplyOptions{ConfirmWithin: time.Minute}); err == nil {
				t.Fatal("apply succeeded")
			}
			if len(sys.tables) != 0 || sys.settings["net.mptcp.enabled"] != "1" {
				t.Fatalf("left on: tables %v, mptcp %s", sys.tables, sys.settings["net.mptcp.enabled"])
			}
			if len(timer.armed) != 0 {
				t.Fatal("undo left armed")
			}
			if st := load(t, a); len(st.Guards) != 0 || len(st.Originals.Settings) != 0 {
				t.Fatalf("state %+v", st)
			}
		})
	}
}

func TestProbeNotCountedByTheRuleFails(t *testing.T) {
	a, sys, _ := newAgent(t)
	// The probe is stopped, but the guard's counter doesn't move: something
	// other than the guard stopped it.
	g := guardOne(t)
	a.Sys = &noCountProbe{sys}
	if _, err := a.Apply(ctx, g, ApplyOptions{ConfirmWithin: time.Minute}); err == nil || !strings.Contains(err.Error(), "not by") {
		t.Fatalf("err %v", err)
	}
	if len(sys.tables) != 0 {
		t.Fatal("table left on")
	}
}

// noCountProbe stops the probe without the guard's rule counting it.
type noCountProbe struct{ *fakeSys }

func (n *noCountProbe) ProbeIPOptions(context.Context) error { return nil }

func TestArmFailureChangesNothing(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.failOn = "arm "
	if _, err := a.Apply(ctx, guardOne(t), ApplyOptions{ConfirmWithin: time.Minute}); err == nil {
		t.Fatal("apply succeeded without an undo")
	}
	if len(sys.tables) != 0 || sys.settings["net.mptcp.enabled"] != "1" || len(load(t, a).Guards) != 0 {
		t.Fatal("changed something")
	}
}

// A crash between steps: the boot takes off the steps that are on and the
// one that may be half on.
func TestBootUndoesAGuardHalfOn(t *testing.T) {
	a, sys, _ := newAgent(t)
	g := guardOne(t)
	// Write the state a crash would leave: the table on, the setting
	// captured and written, but the step not yet counted.
	s, st, err := a.open()
	if err != nil {
		t.Fatal(err)
	}
	e := &Entry{Hash: g.Hash(), Guard: g, Status: Applying, Applied: 1}
	st.Guards = append(st.Guards, e)
	st.Originals.Settings = map[string]string{"net.mptcp.enabled": "1"}
	if err := s.save(st); err != nil {
		t.Fatal(err)
	}
	s.close()
	sys.tables["ip "+nft.TableName(g.Hash())] = &fakeTable{rules: []string{g.Name()}, options: true}
	sys.settings["net.mptcp.enabled"] = "0"

	if err := a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sys.tables) != 0 || sys.settings["net.mptcp.enabled"] != "1" {
		t.Fatalf("after boot: tables %v, mptcp %s", sys.tables, sys.settings["net.mptcp.enabled"])
	}
	if st := load(t, a); len(st.Guards) != 0 || len(st.Originals.Settings) != 0 {
		t.Fatalf("state %+v", st)
	}
}

func reboot(sys *fakeSys) {
	sys.tables = map[string]*fakeTable{}
	sys.settings["net.mptcp.enabled"] = "1"
}

func TestBootKeepsConfirmedDropsPending(t *testing.T) {
	a, sys, _ := newAgent(t)
	one, other := guardOne(t), otherGuard(t)
	if _, err := a.Apply(ctx, one, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(ctx, other, ApplyOptions{ConfirmWithin: time.Hour}); err != nil {
		t.Fatal(err)
	}
	reboot(sys)
	if err := a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	st := load(t, a)
	if len(st.Guards) != 1 || st.Guards[0].Hash != one.Hash() {
		t.Fatalf("guards after boot %+v", st.Guards)
	}
	if sys.tables["ip "+nft.TableName(one.Hash())] == nil || sys.settings["net.mptcp.enabled"] != "0" {
		t.Fatal("the confirmed guard wasn't put back")
	}
	if _, ok := sys.files[modprobeFile(other.Hash(), "ksmbd")]; ok {
		t.Fatal("the pending guard's module block survived the boot")
	}
}

// A setting two guards share stays set until the last of them comes off,
// and then goes back to what it was before the first.
func TestSharedSetting(t *testing.T) {
	a, sys, _ := newAgent(t)
	one, other := guardOne(t), otherGuard(t)
	for _, g := range []*guard.Guard{one, other} {
		if _, err := a.Apply(ctx, g, ApplyOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Undo(ctx, one.ID, false); err != nil {
		t.Fatal(err)
	}
	if sys.settings["net.mptcp.enabled"] != "0" || !strings.Contains(sys.files[SysctlFile], "test/ksmbd v1") {
		t.Fatalf("mptcp %s, file %q", sys.settings["net.mptcp.enabled"], sys.files[SysctlFile])
	}
	if _, err := a.Undo(ctx, other.ID, false); err != nil {
		t.Fatal(err)
	}
	if sys.settings["net.mptcp.enabled"] != "1" {
		t.Fatalf("mptcp %s", sys.settings["net.mptcp.enabled"])
	}
	if _, ok := sys.files[SysctlFile]; ok {
		t.Fatal("sysctl file left behind")
	}
}

func TestRefusals(t *testing.T) {
	t.Run("another system", func(t *testing.T) {
		a, sys, _ := newAgent(t)
		sys.info = guard.System{OS: "fedora", Release: "43"}
		if _, err := a.Apply(ctx, guardOne(t), ApplyOptions{}); err == nil || !strings.Contains(err.Error(), "written for") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("fix running", func(t *testing.T) {
		a, sys, _ := newAgent(t)
		sys.info.Kernel = "6.8.0-149.149"
		if _, err := a.Apply(ctx, guardOne(t), ApplyOptions{}); err == nil || !strings.Contains(err.Error(), "already running") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("another version on", func(t *testing.T) {
		a, _, _ := newAgent(t)
		g := guardOne(t)
		if _, err := a.Apply(ctx, g, ApplyOptions{}); err != nil {
			t.Fatal(err)
		}
		g2 := *g
		g2.Version = 2
		if _, err := a.Apply(ctx, &g2, ApplyOptions{}); err == nil || !strings.Contains(err.Error(), "take it off") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("in use, then forced", func(t *testing.T) {
		a, sys, _ := newAgent(t)
		sys.inUse["module:ksmbd"] = "module ksmbd is loaded and used 1 times"
		if _, err := a.Apply(ctx, otherGuard(t), ApplyOptions{}); err == nil || !strings.Contains(err.Error(), "-force") {
			t.Fatalf("err %v", err)
		}
		if _, err := a.Apply(ctx, otherGuard(t), ApplyOptions{Force: true}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("same guard twice is a no-op", func(t *testing.T) {
		a, sys, _ := newAgent(t)
		if _, err := a.Apply(ctx, guardOne(t), ApplyOptions{}); err != nil {
			t.Fatal(err)
		}
		n := len(sys.log)
		if _, err := a.Apply(ctx, guardOne(t), ApplyOptions{}); err != nil {
			t.Fatal(err)
		}
		if len(sys.log) != n {
			t.Fatalf("changed something: %q", sys.log[n:])
		}
	})
}

func TestUndoIfUnconfirmed(t *testing.T) {
	a, sys, _ := newAgent(t)
	g := guardOne(t)
	if _, err := a.Apply(ctx, g, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if e, err := a.Undo(ctx, g.Hash(), true); err != nil || e != nil {
		t.Fatalf("undo of a confirmed guard by the timer: %v %v", e, err)
	}
	if sys.tables["ip "+nft.TableName(g.Hash())] == nil {
		t.Fatal("the timer took off a confirmed guard")
	}
	// A timer for a guard already gone is not an error.
	if _, err := a.Undo(ctx, strings.Repeat("0", 64), true); err != nil {
		t.Fatal(err)
	}
}

func TestCheckFindsAndRepairsDrift(t *testing.T) {
	a, sys, _ := newAgent(t)
	g := guardOne(t)
	if _, err := a.Apply(ctx, g, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if d, err := a.Check(ctx, false); err != nil || len(d) != 0 {
		t.Fatalf("drift on a fresh guard: %+v %v", d, err)
	}
	// A firewall reload flushed the table, and something reset the setting.
	reboot(sys)
	d, err := a.Check(ctx, false)
	if err != nil || len(d) != 2 {
		t.Fatalf("drift %+v %v", d, err)
	}
	d, err = a.Check(ctx, true)
	if err != nil || len(d) != 2 || !d[0].Repaired || !d[1].Repaired {
		t.Fatalf("repair %+v %v", d, err)
	}
	if tb := sys.tables["ip "+nft.TableName(g.Hash())]; tb == nil || tb.packets != 1 {
		t.Fatal("the table wasn't put back and probed")
	}
	if d, _ := a.Check(ctx, false); len(d) != 0 {
		t.Fatalf("still drifted: %+v", d)
	}
}

func TestServiceAndStrip(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.units["cups-browsed.service"] = &fakeUnit{enabled: "enabled", active: true}
	setuid := fs.FileMode(0o755) | fs.ModeSetuid
	sys.modes["/usr/bin/pkexec"] = setuid
	g, err := guard.Parse([]byte(`{"id": "test/cups-pkexec", "version": 1, "flaws": ["CVE-2024-47176", "CVE-2021-4034"],
		"for": [{"os": "ubuntu", "releases": ["24.04"]}],
		"blocks": [{"service": {"unit": "cups-browsed.service"}}, {"strip": {"path": "/usr/bin/pkexec"}}],
		"breaks": "printer discovery; pkexec"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(ctx, g, ApplyOptions{ConfirmWithin: time.Minute}); err != nil {
		t.Fatal(err)
	}
	u := sys.units["cups-browsed.service"]
	if u.active || u.enabled != "masked-runtime" || sys.modes["/usr/bin/pkexec"]&fs.ModeSetuid != 0 {
		t.Fatalf("pending: unit %+v, mode %v", u, sys.modes["/usr/bin/pkexec"])
	}
	if _, err := a.Confirm(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	if u.enabled != "masked" {
		t.Fatalf("confirmed: unit %+v", u)
	}
	if _, err := a.Undo(ctx, g.ID, false); err != nil {
		t.Fatal(err)
	}
	if !u.active || u.enabled != "enabled" || sys.modes["/usr/bin/pkexec"] != setuid {
		t.Fatalf("after undo: unit %+v, mode %v", u, sys.modes["/usr/bin/pkexec"])
	}
}

func TestStateRejectsTampering(t *testing.T) {
	a, _, _ := newAgent(t)
	g := guardOne(t)
	if _, err := a.Apply(ctx, g, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	path := a.StateDir + "/" + stateFile
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A guard changed inside the state no longer matches its hash.
	b = []byte(strings.Replace(string(b), `"ip_options": true`, `"ip_options": false, "ports": ["443"]`, 1))
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Status(ctx); err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("err %v", err)
	}
}

// A guard that went on under an older release stays readable, and can be
// taken off, after an upgrade that no longer allows one of its blocks.
func TestStateOutlivesTighterLists(t *testing.T) {
	a, sys, _ := newAgent(t)
	// A setting today's list doesn't allow, as if an older release had.
	g := &guard.Guard{ID: "test/old", Version: 1, Flaws: []string{"CVE-2099-2"},
		For:    []guard.Target{{OS: "ubuntu", Releases: []string{"24.04"}}},
		Blocks: []guard.Block{{Setting: &guard.Setting{Name: "net.ipv4.tcp_timestamps", Value: "0"}}},
		Breaks: "TCP timestamps"}
	if g.Validate() == nil {
		t.Fatal("the test needs a guard today's lists refuse")
	}
	s, st, err := a.open()
	if err != nil {
		t.Fatal(err)
	}
	st.Guards = []*Entry{{Hash: g.Hash(), Guard: g, Status: Confirmed, Applied: 1}}
	st.Originals.Settings = map[string]string{"net.ipv4.tcp_timestamps": "1"}
	if err := s.save(st); err != nil {
		t.Fatal(err)
	}
	s.close()
	sys.settings["net.ipv4.tcp_timestamps"] = "0"
	if _, err := a.Undo(ctx, g.ID, false); err != nil {
		t.Fatal(err)
	}
	if sys.settings["net.ipv4.tcp_timestamps"] != "1" {
		t.Fatal("not put back")
	}
}
