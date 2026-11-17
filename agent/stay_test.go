package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/gnosecurity/repairer/approve"
	"github.com/gnosecurity/repairer/guard"
)

const testStay = time.Hour

// stayTrial is a test machine whose tier keeps a guard on for an hour after
// its window fails, with g on trial.
func stayTrial(t *testing.T, g *guard.Guard, tierA string) *trial {
	t.Helper()
	tr := newTrialTier(t, "backup", tierA, "")
	tr.tested(g)
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(g)
	return tr
}

const stayTier = `"hosts":["backup","mail"],"stay_seconds":3600`

// flood fails the check for the three samples that fail a window.
func (tr *trial) flood() *TickResult {
	tr.t.Helper()
	tr.fail[site] = "i/o timeout"
	tr.step(time.Minute)
	tr.step(time.Minute)
	return tr.step(time.Minute)
}

// A flood during a window lifts no guard in a tier with a stay: the guard
// stays on, its undo moves past the stay, and the report says so. When the
// check comes back the window reaches its verdict: confirmed, no try
// counted, nothing recorded against the guard.
func TestStayOutlastsAFlood(t *testing.T) {
	g := ipoptGuard(t)
	tr := stayTrial(t, g, stayTier)
	res := tr.flood()
	if len(res.Undone) != 0 || len(res.Staying) != 1 || !strings.Contains(res.Staying[0], "3 times in a row") {
		t.Fatalf("a failed window with a stay: %+v", res)
	}
	e := tr.entry(g)
	if e == nil || e.Status != Pending || table(tr.sys, g) == nil {
		t.Fatalf("it came off: %+v", e)
	}
	if !e.StayUntil.Equal(tr.clock.Add(testStay)) || !e.ConfirmBy.Equal(e.StayUntil.Add(stayArm)) || tr.timer.armed[g.Hash()] != testStay+stayArm {
		t.Fatalf("the undo wasn't moved past the stay: %+v, armed %v", e, tr.timer.armed)
	}
	if gs := tr.reportOf().Guards; len(gs) != 1 || !gs[0].StayUntil.Equal(e.StayUntil) {
		t.Fatalf("the report: %+v", gs)
	}
	for i := 0; i < 30; i++ {
		if res := tr.step(time.Minute); len(res.Undone)+len(res.Confirmed) != 0 || len(res.Staying) != 1 || len(res.Drift) != 0 {
			t.Fatalf("minute %d of the flood: %+v", i+4, res)
		}
	}
	if !tr.entry(g).StayUntil.Equal(e.StayUntil) {
		t.Fatal("the stay grew")
	}
	delete(tr.fail, site)
	if res := tr.step(time.Minute); len(res.Confirmed) != 1 || len(res.Staying) != 0 {
		t.Fatalf("the check came back: %+v", res)
	}
	e = tr.entry(g)
	if e.Status != Confirmed || !e.StayUntil.IsZero() {
		t.Fatalf("after the flood: %+v", e)
	}
	if _, armed := tr.timer.armed[g.Hash()]; armed {
		t.Fatal("the undo is still armed")
	}
	if ev := tr.evidence(g); ev.Tries != 0 || len(ev.Broke) != 0 {
		t.Fatalf("the flood counted against the guard: %+v", ev)
	}
}

// A stay that runs out with the check still failing ends as the window would
// have: the guard off, its undo disarmed, a try counted and the check on
// record against it.
func TestStayRunsOut(t *testing.T) {
	g := ipoptGuard(t)
	tr := stayTrial(t, g, stayTier)
	tr.flood()
	for tr.clock.Add(time.Minute).Before(tr.entry(g).StayUntil) {
		if res := tr.step(time.Minute); len(res.Undone) != 0 {
			t.Fatalf("came off before the stay's end: %+v", res)
		}
	}
	res := tr.step(time.Minute)
	if len(res.Undone) != 1 || !strings.Contains(res.Undone[0], "3 times in a row") || len(res.Staying) != 0 {
		t.Fatalf("the stay's end: %+v", res)
	}
	if tr.entry(g) != nil || table(tr.sys, g) != nil {
		t.Fatal("still on after its stay")
	}
	if _, armed := tr.timer.armed[g.Hash()]; armed {
		t.Fatal("the undo is still armed")
	}
	if ev := tr.evidence(g); ev.Tries != 1 || len(ev.Broke) != 1 || !ev.RetryAt.Equal(tr.clock.Add(retries[0])) {
		t.Fatalf("after its stay: %+v", ev)
	}
}

// A window gets one stay: a check that comes back and fails again after the
// stay's end takes the guard off at once.
func TestOneStayAWindow(t *testing.T) {
	g := ipoptGuard(t)
	tr := stayTrial(t, g, `"hosts":["backup","mail"],"stay_seconds":120`)
	tr.flood() // three minutes in; the stay ends at five
	delete(tr.fail, site)
	tr.step(time.Minute)
	tr.step(time.Minute)
	res := tr.flood() // eight minutes in, the window still open
	if len(res.Undone) != 1 || len(res.Staying) != 0 || tr.entry(g) != nil {
		t.Fatalf("a second failure: %+v", res)
	}
}

// The owner's keep answers a stay: the guard is confirmed, whatever the
// checks say.
func TestKeepDuringAStay(t *testing.T) {
	g := ipoptGuard(t)
	tr := stayTrial(t, g, stayTier)
	tr.flood()
	ev := tr.evidence(g)
	ev.Yeses = map[string]*approve.Yes{"A": {Hash: g.Hash(), Tiers: []string{"A"}, Until: tr.clock.Add(2 * testStay), Mode: "keep"}}
	if err := tr.a.saveEvidence(g.Hash(), ev); err != nil {
		t.Fatal(err)
	}
	if res := tr.step(time.Minute); len(res.Undone)+len(res.Staying) != 0 {
		t.Fatalf("after the keep: %+v", res)
	}
	if e := tr.entry(g); e.Status != Confirmed || !e.Keep || !e.StayUntil.IsZero() {
		t.Fatalf("after the keep: %+v", e)
	}
	if _, armed := tr.timer.armed[g.Hash()]; armed {
		t.Fatal("the undo is still armed")
	}
}

// The owner's Off answers it too: the guard comes off, and no try is counted.
func TestOffDuringAStay(t *testing.T) {
	g := ipoptGuard(t)
	tr := stayTrial(t, g, stayTier)
	tr.flood()
	f, err := tr.a.loadFleet()
	if err != nil {
		t.Fatal(err)
	}
	f.Off = append(f.Off, g.Hash())
	if err := tr.a.saveFleet(f); err != nil {
		t.Fatal(err)
	}
	if res := tr.step(time.Minute); len(res.Staying) != 0 {
		t.Fatalf("after the Off: %+v", res)
	}
	if tr.entry(g) != nil || table(tr.sys, g) != nil {
		t.Fatal("still on after the Off")
	}
	if ev := tr.evidence(g); ev.Tries != 0 {
		t.Fatalf("the Off counted a try: %+v", ev)
	}
}

// The window after a boot stays the same way: the guard stays on through the
// flood and is confirmed once the check is back, or comes off when the stay
// runs out.
func TestStayAfterABoot(t *testing.T) {
	const mptcp = "net.mptcp.enabled"
	for _, comesBack := range []bool{true, false} {
		g := mptcpGuard(t)
		tr := stayTrial(t, g, stayTier)
		for i := 0; i < 10; i++ {
			tr.step(time.Minute)
		}
		if e := tr.entry(g); e.Status != Confirmed || !e.Later {
			t.Fatalf("after the first window: %+v", e)
		}
		tr.clock = tr.clock.Add(time.Hour)
		tr.sys.settings[mptcp] = "1" // a reboot loses it
		if err := tr.a.Boot(ctx); err != nil {
			t.Fatal(err)
		}
		tr.step(time.Minute) // back after the boot
		res := tr.flood()
		if len(res.Undone) != 0 || len(res.Staying) != 1 {
			t.Fatalf("a failed window after a boot: %+v", res)
		}
		e := tr.entry(g)
		if e == nil || e.Status != Pending || !e.BootWindow || tr.timer.armed[g.Hash()] != testStay+stayArm || tr.sys.settings[mptcp] != "0" {
			t.Fatalf("after the boot's window failed: %+v, armed %v", e, tr.timer.armed)
		}
		if comesBack {
			delete(tr.fail, site)
			confirmed := false
			for i := 0; i < 10 && !confirmed; i++ {
				res := tr.step(time.Minute)
				confirmed = len(res.Confirmed) == 1
			}
			if e := tr.entry(g); !confirmed || e.Status != Confirmed || !e.Booted || !e.StayUntil.IsZero() {
				t.Fatalf("the check came back: %+v", e)
			}
			continue
		}
		for tr.clock.Add(time.Minute).Before(e.StayUntil) {
			if res := tr.step(time.Minute); len(res.Undone) != 0 {
				t.Fatalf("came off before the stay's end: %+v", res)
			}
		}
		if res := tr.step(time.Minute); len(res.Undone) != 1 || tr.entry(g) != nil || tr.sys.settings[mptcp] != "1" {
			t.Fatalf("the stay's end: %+v", res)
		}
	}
}
