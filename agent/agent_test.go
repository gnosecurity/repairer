package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gnosecurity/repairer/guard"
	"github.com/gnosecurity/repairer/nft"
	"github.com/gnosecurity/repairer/policy"
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

// parse reads a guard written readably in a test; files the agent acts on
// must be canonical (guard.Parse).
func parse(t *testing.T, js string) *guard.Guard {
	t.Helper()
	g, err := guard.Decode([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// otherGuard blocks a module and also turns MPTCP off, so it shares a
// setting with guard number one.
func otherGuard(t *testing.T) *guard.Guard {
	return parse(t, `{"id": "test/ksmbd", "version": 1, "flaws": ["CVE-2099-1"],
		"for": [{"os": "ubuntu", "releases": ["24.04"]}],
		"blocks": [{"module": {"name": "ksmbd"}}, {"setting": {"name": "net.mptcp.enabled", "value": "0"}}],
		"breaks": "the in-kernel SMB server"}`)
}

// cupsGuard stops a service and strips a program.
func cupsGuard(t *testing.T, id string) *guard.Guard {
	return parse(t, `{"id": "`+id+`", "version": 1, "flaws": ["CVE-2024-47176", "CVE-2021-4034"],
		"for": [{"os": "ubuntu", "releases": ["24.04"]}],
		"blocks": [{"service": {"unit": "cups-browsed.service"}}, {"strip": {"path": "/usr/bin/pkexec"}}],
		"breaks": "printer discovery; pkexec"}`)
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

func table(sys *fakeSys, g *guard.Guard) *fakeTable {
	return sys.tables["ip "+nft.TableName(g.Hash())]
}

func TestApplyConfirmUndoGuardOne(t *testing.T) {
	a, sys, timer := newAgent(t)
	g := guardOne(t)
	h := g.Hash()

	e, err := a.Apply(ctx, g, ApplyOptions{ConfirmWithin: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != Pending || e.Applied != 2 || e.Unprobed {
		t.Fatalf("entry %+v", e)
	}
	// The undo is armed before the first change, and the drop goes on
	// before the setting.
	arm, ld, set, probe := index(sys.log, "arm "), index(sys.log, "nft load ip"), index(sys.log, "setting net.mptcp.enabled=0"), index(sys.log, "probe")
	if !(arm >= 0 && arm < ld && ld < set && set < probe) {
		t.Fatalf("order arm %d, load %d, setting %d, probe %d in %q", arm, ld, set, probe, sys.log)
	}
	if timer.armed[h] != 10*time.Minute {
		t.Fatalf("armed for %v", timer.armed[h])
	}
	if tb := table(sys, g); tb == nil || tb.rules[0].packets != 1 || sys.settings["net.mptcp.enabled"] != "0" {
		t.Fatalf("live: table %+v, mptcp %s", tb, sys.settings["net.mptcp.enabled"])
	}
	if len(nft.TableName(h)) != len("repairer_")+64 {
		t.Fatal("the table isn't named by the whole hash")
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
	if table(sys, g) != nil || sys.settings["net.mptcp.enabled"] != "1" {
		t.Fatalf("after undo: table %v, mptcp %s", table(sys, g), sys.settings["net.mptcp.enabled"])
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

// The probe must be counted by the guard's own rule, not by another rule
// of the same table that other traffic happens to hit.
func TestProbeCountsOnlyItsRule(t *testing.T) {
	a, sys, _ := newAgent(t)
	g := parse(t, `{"id": "test/two-drops", "version": 1, "flaws": ["CVE-2099-3"],
		"for": [{"os": "ubuntu", "releases": ["24.04"]}],
		"blocks": [{"drop": {"family": "ipv4", "protocol": "tcp", "ip_options": true}},
		           {"drop": {"family": "ipv4", "protocol": "udp", "ports": ["5353"]}}],
		"breaks": "IP options on TCP; mDNS"}`)
	sys.stoppedElsewhere = true
	sys.noise = 1 // mDNS traffic hits the udp rule meanwhile
	if _, err := a.Apply(ctx, g, ApplyOptions{ConfirmWithin: time.Minute}); err == nil || !strings.Contains(err.Error(), "not by") {
		t.Fatalf("err %v", err)
	}
	if len(sys.tables) != 0 {
		t.Fatal("table left on")
	}
	// Probed properly, the guard is still marked unprobed: its udp drop has
	// no probe.
	sys.stoppedElsewhere = false
	e, err := a.Apply(ctx, g, ApplyOptions{ConfirmWithin: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if !e.Unprobed {
		t.Fatal("a guard with an unprobed drop isn't marked unprobed")
	}
}

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
	// The state a crash would leave: the table on, the setting captured and
	// written, but that step not yet counted.
	s, st, err := a.open()
	if err != nil {
		t.Fatal(err)
	}
	st.Guards = append(st.Guards, &Entry{Hash: g.Hash(), Guard: g, Status: Applying, Applied: 1})
	st.Originals.Settings = map[string]string{"net.mptcp.enabled": "1"}
	if err := s.save(st); err != nil {
		t.Fatal(err)
	}
	s.close()
	sys.tables["ip "+nft.TableName(g.Hash())] = &fakeTable{rules: []fakeRule{{comment: g.Name()}}}
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
	for _, u := range sys.units {
		u.runMask = false
	}
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
	if table(sys, one) == nil || sys.settings["net.mptcp.enabled"] != "0" {
		t.Fatal("the confirmed guard wasn't put back")
	}
	if _, ok := sys.files[modprobeFile(other.Hash(), "ksmbd")]; ok {
		t.Fatal("the pending guard's module block survived the boot")
	}
}

// A confirmed guard that is no longer safe here (the kernel now has the
// module built in, so the block does nothing) is taken off at boot, and the
// boot says so.
func TestBootTakesOffWhatIsNoLongerSafe(t *testing.T) {
	a, sys, _ := newAgent(t)
	g := otherGuard(t)
	if _, err := a.Apply(ctx, g, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	sys.modules["ksmbd"] = "builtin"
	err := a.Boot(ctx)
	if err == nil || !strings.Contains(err.Error(), "taken off") {
		t.Fatalf("err %v", err)
	}
	if len(load(t, a).Guards) != 0 {
		t.Fatal("still on")
	}
	if _, ok := sys.files[modprobeFile(g.Hash(), "ksmbd")]; ok {
		t.Fatal("module block left behind")
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

// A guard that died before reaching a shared setting doesn't hold it: the
// guard that set it puts it back when it comes off.
func TestUnreachedStepsDontHold(t *testing.T) {
	a, sys, _ := newAgent(t)
	other := otherGuard(t) // its setting is its second step
	if _, err := a.Apply(ctx, guardOne(t), ApplyOptions{ConfirmWithin: time.Minute}); err != nil {
		t.Fatal(err)
	}
	s, st, err := a.open()
	if err != nil {
		t.Fatal(err)
	}
	st.Guards = append(st.Guards, &Entry{Hash: other.Hash(), Guard: other, Status: Applying, Applied: 0})
	if err := s.save(st); err != nil {
		t.Fatal(err)
	}
	s.close()
	if _, err := a.Undo(ctx, "cve-2026-98432/linux-ipv4-ipopt", true); err != nil {
		t.Fatal(err)
	}
	if sys.settings["net.mptcp.enabled"] != "1" {
		t.Fatal("a guard that never reached the setting kept it changed")
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
	t.Run("containers keep their own network settings", func(t *testing.T) {
		a, sys, _ := newAgent(t)
		sys.inUse["netns"] = "process 4242 (dockerd) lives in another network namespace"
		if _, err := a.Apply(ctx, guardOne(t), ApplyOptions{}); err == nil || !strings.Contains(err.Error(), "network namespace") {
			t.Fatalf("err %v", err)
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
	unsafeCases := []struct {
		name, block, want string
		setup             func(*fakeSys)
	}{
		{"module unknown to the kernel", `{"module": {"name": "nosuchmod"}}`, "no module named exactly", nil},
		{"module built in", `{"module": {"name": "foomod"}}`, "built into", func(s *fakeSys) { s.modules["foomod"] = "builtin" }},
		{"ports over the ephemeral range", `{"drop": {"family": "ipv4", "protocol": "udp", "ports": ["49152-50000"]}}`, "replies would be dropped", nil},
		{"ssh on another port", `{"drop": {"family": "ipv4", "protocol": "tcp", "ports": ["2222"]}}`, "ssh listens on port 2222", func(s *fakeSys) { s.sshPorts = []int{2222} }},
		{"strip through a symlink", `{"strip": {"path": "/usr/bin/X11/pkexec"}}`, "symlink", func(s *fakeSys) {
			s.addFile("/usr/bin/X11/pkexec", 0o4755).viaLink = true
		}},
		{"strip sudo by another name", `{"strip": {"path": "/usr/libexec/sudo-alt"}}`, "by another name", func(s *fakeSys) {
			s.addFile("/usr/libexec/sudo-alt", 0o4755).sameAs = "/usr/bin/sudo"
		}},
		{"strip a file root doesn't own", `{"strip": {"path": "/opt/app/helper"}}`, "owned by root", func(s *fakeSys) {
			s.addFile("/opt/app/helper", 0o4755).uid = 1000
		}},
	}
	for _, c := range unsafeCases {
		t.Run(c.name, func(t *testing.T) {
			a, sys, _ := newAgent(t)
			if c.setup != nil {
				c.setup(sys)
			}
			g := parse(t, `{"id": "test/unsafe", "version": 1, "flaws": ["CVE-2099-4"],
				"for": [{"os": "ubuntu", "releases": ["24.04"]}], "blocks": [`+c.block+`], "breaks": "x"}`)
			if _, err := a.Apply(ctx, g, ApplyOptions{}); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v", err)
			}
			if len(sys.log) != 0 {
				t.Fatalf("changed something: %q", sys.log)
			}
		})
	}
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
	if table(sys, g) == nil {
		t.Fatal("the timer took off a confirmed guard")
	}
	// A timer for a guard already gone is not an error.
	if _, err := a.Undo(ctx, strings.Repeat("0", 64), true); err != nil {
		t.Fatal(err)
	}
}

// A failed undo keeps the guard in the state, marked, so that status shows
// it and a later undo finishes the job.
func TestFailedUndoIsKeptAndRetried(t *testing.T) {
	a, sys, timer := newAgent(t)
	sys.units["cups-browsed.service"] = &fakeUnit{enabled: "enabled", active: true}
	sys.addFile("/usr/bin/pkexec", 0o4755)
	g := cupsGuard(t, "test/cups")
	if _, err := a.Apply(ctx, g, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	sys.failOn = "systemctl unmask"
	if _, err := a.Undo(ctx, g.ID, false); err == nil {
		t.Fatal("undo reported success")
	}
	st := load(t, a)
	if len(st.Guards) != 1 || st.Guards[0].Status != Applying || st.Guards[0].Failed == "" {
		t.Fatalf("state after a failed undo %+v", st.Guards)
	}
	if _, ok := timer.armed[g.Hash()]; ok {
		t.Fatal("confirmed guard got an undo armed")
	}
	sys.failOn = ""
	if _, err := a.Undo(ctx, g.ID, false); err != nil {
		t.Fatal(err)
	}
	u := sys.units["cups-browsed.service"]
	if len(load(t, a).Guards) != 0 || u.state() != "enabled" || !u.active || sys.strips["/usr/bin/pkexec"].mode != 0o4755 {
		t.Fatalf("after the retry: unit %+v, pkexec %v", u, sys.strips["/usr/bin/pkexec"].mode)
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
	if tb := table(sys, g); tb == nil || tb.rules[0].packets != 1 {
		t.Fatal("the table wasn't put back and probed")
	}
	if d, _ := a.Check(ctx, false); len(d) != 0 {
		t.Fatalf("still drifted: %+v", d)
	}
}

// check notices a masked service that is running anyway.
func TestCheckSeesARunningMaskedService(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.units["cups-browsed.service"] = &fakeUnit{enabled: "enabled", active: true}
	sys.addFile("/usr/bin/pkexec", 0o4755)
	if _, err := a.Apply(ctx, cupsGuard(t, "test/cups"), ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	sys.units["cups-browsed.service"].active = true
	d, err := a.Check(ctx, false)
	if err != nil || len(d) != 1 || !strings.Contains(d[0].What, "still active") {
		t.Fatalf("check %+v %v", d, err)
	}
}

// A check finds a guard that has become unsafe (ssh moved onto a port the
// guard drops) and, with repair, takes it off.
func TestCheckTakesOffWhatBecameUnsafe(t *testing.T) {
	a, sys, _ := newAgent(t)
	g := parse(t, `{"id": "test/port", "version": 1, "flaws": ["CVE-2099-5"],
		"for": [{"os": "ubuntu", "releases": ["24.04"]}],
		"blocks": [{"drop": {"family": "ipv4", "protocol": "tcp", "ports": ["8022"]}}], "breaks": "port 8022"}`)
	if _, err := a.Apply(ctx, g, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	sys.sshPorts = []int{22, 8022}
	d, err := a.Check(ctx, true)
	if err != nil || len(d) != 1 || !d[0].TakenOff || !strings.Contains(d[0].What, "ssh listens") {
		t.Fatalf("check %+v %v", d, err)
	}
	if table(sys, g) != nil || len(load(t, a).Guards) != 0 {
		t.Fatal("still on")
	}
}

func TestServiceAndStrip(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.units["cups-browsed.service"] = &fakeUnit{enabled: "enabled", active: true}
	setuid := fs.FileMode(0o755) | fs.ModeSetuid
	sys.addFile("/usr/bin/pkexec", setuid)
	g := cupsGuard(t, "test/cups")
	if _, err := a.Apply(ctx, g, ApplyOptions{ConfirmWithin: time.Minute}); err != nil {
		t.Fatal(err)
	}
	u := sys.units["cups-browsed.service"]
	// Masked before stopped, so nothing could start it in between.
	if u.active || u.state() != "masked-runtime" || index(sys.log, "systemctl mask --runtime --now") < 0 {
		t.Fatalf("pending: unit %+v, log %q", u, sys.log)
	}
	if sys.strips["/usr/bin/pkexec"].mode&fs.ModeSetuid != 0 {
		t.Fatal("pkexec still setuid")
	}
	if _, err := a.Confirm(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	if !u.etcMask {
		t.Fatalf("confirmed: unit %+v", u)
	}
	if _, err := a.Undo(ctx, g.ID, false); err != nil {
		t.Fatal(err)
	}
	if !u.active || u.state() != "enabled" || u.runMask || sys.strips["/usr/bin/pkexec"].mode != setuid {
		t.Fatalf("after undo: unit %+v, mode %v", u, sys.strips["/usr/bin/pkexec"].mode)
	}
}

// Undoing a pending service guard removes its runtime mask and starts the
// service again.
func TestUndoPendingService(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.units["cups-browsed.service"] = &fakeUnit{enabled: "enabled", active: true}
	sys.addFile("/usr/bin/pkexec", 0o4755)
	g := cupsGuard(t, "test/cups")
	if _, err := a.Apply(ctx, g, ApplyOptions{ConfirmWithin: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Undo(ctx, g.ID, true); err != nil {
		t.Fatal(err)
	}
	if u := sys.units["cups-browsed.service"]; u.runMask || !u.active {
		t.Fatalf("unit %+v", u)
	}
}

// A unit and a stripped file two guards share stay changed until the last
// guard comes off.
func TestSharedUnitAndStrip(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.units["cups-browsed.service"] = &fakeUnit{enabled: "enabled", active: true}
	sys.addFile("/usr/bin/pkexec", 0o4755)
	g1, g2 := cupsGuard(t, "test/cups-a"), cupsGuard(t, "test/cups-b")
	for _, g := range []*guard.Guard{g1, g2} {
		if _, err := a.Apply(ctx, g, ApplyOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Undo(ctx, g1.ID, false); err != nil {
		t.Fatal(err)
	}
	u := sys.units["cups-browsed.service"]
	if u.active || u.state() == "enabled" || sys.strips["/usr/bin/pkexec"].mode&fs.ModeSetuid != 0 {
		t.Fatalf("released while the other guard holds it: unit %+v, mode %v", u, sys.strips["/usr/bin/pkexec"].mode)
	}
	if _, err := a.Undo(ctx, g2.ID, false); err != nil {
		t.Fatal(err)
	}
	if !u.active || u.state() != "enabled" || sys.strips["/usr/bin/pkexec"].mode != 0o4755 {
		t.Fatalf("not put back: unit %+v, mode %v", u, sys.strips["/usr/bin/pkexec"].mode)
	}
}

// When an upgrade replaces a stripped file, undo leaves the new file's mode
// alone: the saved mode belongs to the old file.
func TestUndoLeavesAReplacedFileAlone(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.units["cups-browsed.service"] = &fakeUnit{enabled: "enabled", active: true}
	sys.addFile("/usr/bin/pkexec", 0o4755)
	g := cupsGuard(t, "test/cups")
	if _, err := a.Apply(ctx, g, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	fixed := sys.addFile("/usr/bin/pkexec", 0o755) // the vendor's fix dropped setuid
	if _, err := a.Undo(ctx, g.ID, false); err != nil {
		t.Fatal(err)
	}
	if fixed.mode != 0o755 {
		t.Fatalf("undo put %v on the vendor's new file", fixed.mode)
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

func TestSafeExecutable(t *testing.T) {
	if err := safeExecutable("/usr/bin/env"); err != nil {
		t.Fatalf("/usr/bin/env: %v", err)
	}
	mine := filepath.Join(t.TempDir(), "repairer-agent")
	if err := os.WriteFile(mine, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{mine, "bin/repairer-agent", "/tmp/repairer-agent", "/root/.cache/go-build/x/exe/repairer-agent"} {
		if err := safeExecutable(p); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}

func TestListsModule(t *testing.T) {
	dep := []byte("kernel/fs/smb/server/ksmbd.ko.zst: kernel/lib/crypto/libarc4.ko.zst\n" +
		"kernel/net/can/can-raw.ko.zst: kernel/net/can/can.ko.zst\n")
	for name, want := range map[string]bool{"ksmbd": true, "can_raw": true, "can": false, "net_pf_16_proto_12": false} {
		if got := listsModule(dep, name, true); got != want {
			t.Errorf("%s: %v", name, got)
		}
	}
	if !listsModule([]byte("kernel/fs/ext4/ext4.ko\n"), "ext4", false) {
		t.Error("builtin ext4 not found")
	}
}

func TestListeningSockets(t *testing.T) {
	tcp := []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0100007F:1F90 0100007F:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 20 4 30 10 -1\n")
	got := listeningSockets(tcp)
	if len(got) != 1 || got["12345"] != 22 {
		t.Fatalf("%v", got)
	}
}

func TestInstall(t *testing.T) {
	a, sys, _ := newAgent(t)
	if err := a.Install(ctx, "/usr/bin/env"); err != nil {
		t.Fatal(err)
	}
	boot := sys.files["/etc/systemd/system/repairer-boot.service"]
	fw := sys.files["/etc/systemd/system/repairer-firewall.service"]
	if !strings.Contains(boot, "ExecStart=/usr/bin/env boot -state-dir "+a.StateDir) || !strings.Contains(boot, "WantedBy=sysinit.target") {
		t.Fatalf("boot unit:\n%s", boot)
	}
	// The firewall unit only repairs: a firewall restart during a trial
	// must not run boot, which takes pending guards off.
	if !strings.Contains(fw, "PartOf=nftables.service firewalld.service") || strings.Contains(fw, " boot ") || !strings.Contains(fw, "check -state-dir "+a.StateDir+" -repair") {
		t.Fatalf("firewall unit:\n%s", fw)
	}
	if !strings.Contains(sys.files["/etc/systemd/system/repairer-check.timer"], "OnUnitActiveSec=1min") {
		t.Fatal("no minute timer")
	}
	if index(sys.log, "systemctl daemon-reload") < 0 || index(sys.log, "systemctl enable repairer-boot.service") < 0 {
		t.Fatalf("log %q", sys.log)
	}
	if err := a.Install(ctx, "/tmp/repairer-agent"); err == nil {
		t.Fatal("installed a binary from /tmp")
	}
}

func TestReportParsers(t *testing.T) {
	vers, newest := installedKernels([]byte("linux-image-6.8.0-142-generic 6.8.0-142.142 ii \nlinux-image-6.8.0-149-generic 6.8.0-149.149 ii \nlinux-image-6.8.0-147-generic 6.8.0-147.147 iF \n"))
	if strings.Join(vers, ",") != "6.8.0-142.142,6.8.0-149.149" || newest != "6.8.0-149-generic" {
		t.Fatalf("kernels %v %q (a half-configured kernel isn't installed)", vers, newest)
	}
	missing := dkmsMissing([]byte("amdgpu/6.12.12, 6.8.0-137-generic, x86_64: installed\nmlnx-ofed/24.10, 6.8.0-149-generic, x86_64: built\n"), "6.8.0-149-generic")
	if strings.Join(missing, ",") != "amdgpu,mlnx-ofed" {
		t.Fatalf("dkms missing %v", missing)
	}
	last, kept := unattended([]byte("2026-10-21 06:12:01,123 INFO Starting unattended upgrades script\n" +
		"2026-10-21 06:12:30,001 INFO Packages that are kept back: linux-image-generic openssl\n" +
		"2026-11-04 06:40:02,500 INFO Starting unattended upgrades script\n" +
		"2026-11-04 06:40:30,001 INFO Packages that are kept back: sudo\n"))
	if last.Format(time.RFC3339) != "2026-11-04T06:40:02Z" || strings.Join(kept, ",") != "sudo" {
		t.Fatalf("unattended %v %v", last, kept)
	}
	o := osFacts([]byte("ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n"))
	if o.ID != "ubuntu" || o.Version != "24.04" || o.Codename != "noble" {
		t.Fatalf("os %+v", o)
	}
	a, sys, _ := newAgent(t)
	sys.files["/usr/share/distro-info/ubuntu.csv"] = "version,codename,series,created,release,eol,eol-server,eol-esm\n" +
		"24.04 LTS,Noble Numbat,noble,2023-10-12,2024-04-25,2029-05-31,2029-05-31,2034-04-25\n" +
		"25.04,Plucky Puffin,plucky,2024-10-10,2025-04-17,2026-01-15\n"
	if e := a.eol(o); e != "2029-05-31" {
		t.Fatalf("eol %q", e)
	}
	if e := a.eol(OSFacts{ID: "ubuntu", Codename: "plucky"}); e != "2026-01-15" {
		t.Fatalf("plucky eol %q", e)
	}
	pk := sourcePackages([]byte("openssl 3.0.13-0ubuntu3.5 ii\nopenssl 3.0.13-0ubuntu3.5 ii\nlinux 6.8.0-149.149 ii\nfoo 1 rc\n"))
	if len(pk) != 2 || pk[0].Source != "linux" {
		t.Fatalf("packages %+v", pk)
	}
}

func TestProcAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F":                         "127.0.0.1",
		"00000000":                         "0.0.0.0",
		"0101A8C0":                         "192.168.1.1",
		"00000000000000000000000000000000": "::",
		"0000000000000000FFFF00000100007F": "127.0.0.1",
		"00000000000000000000000001000000": "::1",
	} {
		a, ok := procAddr(in)
		if !ok || a.String() != want {
			t.Errorf("procAddr(%s) = %v %v, want %s", in, a, ok, want)
		}
	}
}

func TestGates(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.units["ssh.socket"] = &fakeUnit{enabled: "enabled"}
	sys.listen = []Listen{{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Process: "sshd", PID: 100}, {Proto: "tcp", Addr: "0.0.0.0", Port: 8000, Process: "python3", PID: 200}}
	sys.files["/proc/100/cgroup"] = "0::/system.slice/ssh.service\n"
	sys.files["/proc/200/cgroup"] = "0::/user.slice/user-0.slice/session-12.scope\n"
	sys.files["/boot/vmlinuz-6.8.0-149-generic"] = "kernel"
	sys.runOut = map[string]string{
		"dpkg-query -W -f ${Package} ${Version} ${db:Status-Abbrev}\n linux-image-[0-9]*": "linux-image-6.8.0-149-generic 6.8.0-149.149 ii \n",
		"dkms status": "amdgpu/6.12, 6.8.0-147-generic, x86_64: installed\n",
	}
	got := map[string]Gate{}
	for _, g := range a.Gates(ctx) {
		got[strings.SplitN(g.Name, " (", 2)[0]] = g
	}
	if !got["ssh comes back"].OK {
		t.Error("ssh.socket enabled should pass")
	}
	if g := got["no hand-started listeners"]; g.OK || !strings.Contains(g.Why, "python3 (pid 200, port 8000)") {
		t.Errorf("hand-started: %+v", g)
	}
	if g := got["newest kernel can boot"]; g.OK || !strings.Contains(g.Why, "initrd.img-6.8.0-149-generic is missing") || !strings.Contains(g.Why, "amdgpu") {
		t.Errorf("kernel: %+v", g)
	}
	if inLoginSession([]byte("0::/system.slice/cron.service\n")) || !inLoginSession([]byte("0::/user.slice/user-1000.slice/session-3.scope\n")) {
		t.Error("inLoginSession wrong")
	}
	// Every kernel installed whole (round 14, new major 1): a newer kernel
	// half configured by a postinst that failed, or an older one missing its
	// initrd, holds every reboot; one removed with its config left doesn't.
	sys.files["/boot/initrd.img-6.8.0-149-generic"] = "initrd"
	sys.files["/boot/vmlinuz-6.8.0-147-generic"] = "kernel"
	sys.runOut["dkms status"] = ""
	sys.runOut["dpkg-query -W -f ${Package} ${Version} ${db:Status-Abbrev}\n linux-image-[0-9]*"] =
		"linux-image-6.8.0-140-generic 6.8.0-140.140 rc \nlinux-image-6.8.0-147-generic 6.8.0-147.147 ii \n" +
			"linux-image-6.8.0-149-generic 6.8.0-149.149 ii \nlinux-image-6.8.0-151-generic 6.8.0-151.151 iF \n"
	got = map[string]Gate{}
	for _, g := range a.Gates(ctx) {
		got[strings.SplitN(g.Name, " (", 2)[0]] = g
	}
	g := got["every kernel installed whole"]
	if g.OK || !strings.Contains(g.Why, "linux-image-6.8.0-151-generic is iF") || !strings.Contains(g.Why, "/boot/initrd.img-6.8.0-147-generic is missing") ||
		strings.Contains(g.Why, "140") || strings.Contains(g.Why, "149") {
		t.Errorf("kernels whole: %+v", g)
	}
	sys.files["/boot/initrd.img-6.8.0-147-generic"] = "initrd"
	sys.runOut["dpkg-query -W -f ${Package} ${Version} ${db:Status-Abbrev}\n linux-image-[0-9]*"] =
		"linux-image-6.8.0-147-generic 6.8.0-147.147 ii \nlinux-image-6.8.0-149-generic 6.8.0-149.149 ii \n"
	for _, g := range a.Gates(ctx) {
		if strings.HasPrefix(g.Name, "every kernel installed whole") && !g.OK {
			t.Errorf("whole kernels held: %+v", g)
		}
	}
}

func TestInitAndIntake(t *testing.T) {
	a, _, _ := newAgent(t)
	p, err := policy.Decode([]byte(`{"fleet":"home","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"}},
		"tiers":[{"name":"A","hosts":["backup","mail"],"admit":["me"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Init("kourt", p.Canonical(), 0); err == nil {
		t.Fatal("init for a host in no tier")
	}
	if _, err := a.Init("mail", []byte("{}"), 0); err == nil {
		t.Fatal("init with a policy that isn't canonical")
	}
	pub, err := a.Init("mail", p.Canonical(), 41)
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.agentKey()
	if err != nil || !bytes.Equal(pub, again) {
		t.Fatal("the agent's key changed")
	}
	f, err := a.loadFleet()
	if err != nil || f.Host != "mail" || f.LastSeq != 41 {
		t.Fatalf("fleet %+v %v", f, err)
	}
	if fi, err := os.Stat(filepath.Join(a.StateDir, keyFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file %v %v", fi, err)
	}

	spool := filepath.Join(a.StateDir, spoolDir)
	path, err := Intake(spool, strings.NewReader(`{"messages":[]}`))
	if err != nil || !strings.HasPrefix(path, spool) {
		t.Fatalf("intake %q %v", path, err)
	}
	if _, err := Intake(spool, strings.NewReader("not json")); err == nil {
		t.Fatal("took a bundle that isn't JSON")
	}
	if _, err := Intake(spool, strings.NewReader(`"`+strings.Repeat("x", MaxBundle)+`"`)); err == nil {
		t.Fatal("took a bundle over the cap")
	}
}

func TestTrackerSource(t *testing.T) {
	for _, c := range []struct{ os, src, want string }{
		{"ubuntu", "linux-signed", "linux"},
		{"ubuntu", "linux-signed-hwe-6.8", "linux-hwe-6.8"},
		{"ubuntu", "linux-aws", "linux-aws"},
		{"debian", "linux-signed-amd64", "linux"},
		{"debian", "linux", "linux"},
	} {
		if got := trackerSource(c.os, c.src); got != c.want {
			t.Errorf("%s %s: %s, want %s", c.os, c.src, got, c.want)
		}
	}
}

func TestAuthorizedKeys(t *testing.T) {
	sshKey := func(comment string) string {
		pub, _, _ := ed25519.GenerateKey(nil)
		wire := binary.BigEndian.AppendUint32(nil, 11)
		wire = append(wire, "ssh-ed25519"...)
		wire = binary.BigEndian.AppendUint32(wire, 32)
		wire = append(wire, pub...)
		return strings.TrimSpace("ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire) + " " + comment)
	}
	k1, k2 := sshKey("lookout-report"), sshKey("")
	lines, err := AuthorizedKeys("/usr/local/sbin/repairer-agent", "/var/lib/repairer", k1, k2, "203.0.113.9,198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	want := `restrict,from="203.0.113.9,198.51.100.0/24",command="/usr/local/sbin/repairer-agent report -state-dir /var/lib/repairer" ` + k1 + "\n" +
		`restrict,from="203.0.113.9,198.51.100.0/24",command="/usr/local/sbin/repairer-agent intake -state-dir /var/lib/repairer" ` + k2 + "\n"
	if lines != want {
		t.Fatalf("got\n%swant\n%s", lines, want)
	}
	for _, bad := range []string{
		`command="sh" ` + k1,               // options smuggled in the key
		k1 + "\n" + k2,                     // two lines
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB", // another key type
	} {
		if _, err := AuthorizedKeys("/a", "/b", bad, k2, ""); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := AuthorizedKeys("/a", "/b", k1, k1, ""); err == nil {
		t.Error("one key for both")
	}
	if _, err := AuthorizedKeys("/a", "/b", k1, k2, `1.2.3.4",command="sh`); err == nil {
		t.Error("a quote in from")
	}
}
