package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
)

// trial is a test machine in a fleet with real Ed25519 keys for the rig and
// both agents. Tier A is backup (the canary) and mail; the owner or the rig
// admits. One health check, a TCP connect, covers both machines.
type trial struct {
	t     *testing.T
	a     *Agent
	sys   *fakeSys
	timer *fakeTimer
	clock time.Time
	rig   ed25519.PrivateKey
	keys  map[string]ed25519.PrivateKey // agents' keys, by host
	fail  map[string]string             // health target: why it fails now
	p     *policy.Policy
}

const site = "203.0.113.5:443"

func newTrial(t *testing.T, host, extra string) *trial {
	t.Helper()
	return newTrialTier(t, host, `"hosts":["backup","mail"]`, extra)
}

// newTrialTier is newTrial with tier A's hosts (and anything else of the
// tier's) given.
func newTrialTier(t *testing.T, host, tierA, extra string, moreTargets ...string) *trial {
	t.Helper()
	a, sys, timer := newAgent(t)
	tr := &trial{t: t, a: a, sys: sys, timer: timer, clock: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC),
		keys: map[string]ed25519.PrivateKey{}, fail: map[string]string{}}
	a.Now = func() time.Time { return tr.clock }
	a.Health = func(_ context.Context, h policy.Health) string { return tr.fail[h.Target] }
	pub := func(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }
	newKey := func() ed25519.PrivateKey {
		_, k, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	tr.rig, tr.keys["backup"], tr.keys["mail"] = newKey(), newKey(), newKey()
	p, err := policy.Decode([]byte(`{"fleet":"test","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"},
		"rig":[{"name":"rig1","key":"` + pub(tr.rig) + `"}],
		"agents":[{"name":"backup","key":"` + pub(tr.keys["backup"]) + `","host":"backup"},
		          {"name":"mail","key":"` + pub(tr.keys["mail"]) + `","host":"mail"}]},
		"rigs":["` + strings.Repeat("c", 64) + `"],
		"tiers":[{"name":"A",` + tierA + `,"admit":["me","rig"],"canaries":["backup"]}],
		"health":[` + healthJSON(append([]string{site}, moreTargets...)) + `]` + extra + `}`))
	if err != nil {
		t.Fatal(err)
	}
	tr.p = p
	// The agent's own key is the one the policy lists for this host, as it
	// is once the owner has added the key init printed.
	if err := writeAtomic(filepath.Join(a.StateDir, keyFile), []byte(hex.EncodeToString(tr.keys[host].Seed())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Init(host, p.Canonical(), 0); err != nil {
		t.Fatal(err)
	}
	return tr
}

// healthJSON is one TCP check per target, on both machines.
func healthJSON(targets []string) string {
	var out []string
	for _, tg := range targets {
		out = append(out, `{"hosts":["backup","mail"],"kind":"tcp","target":"`+tg+`","want":""}`)
	}
	return strings.Join(out, ",")
}

// deliver hands the agent a bundle through intake, as the lookout would.
func (tr *trial) deliver(b Bundle) {
	tr.t.Helper()
	js, err := json.Marshal(b)
	if err != nil {
		tr.t.Fatal(err)
	}
	if _, err := Intake(filepath.Join(tr.a.StateDir, spoolDir), bytes.NewReader(js)); err != nil {
		tr.t.Fatal(err)
	}
}

// tested delivers the rig's Tested for a guard, with the guard's file.
func (tr *trial) tested(g *guard.Guard) {
	tr.t.Helper()
	sg, err := approve.SignStatement(tr.rig, approve.Statement{Version: approve.MemoVersion, Kind: approve.KindTested,
		Image: "ubuntu 24.04", Chain: "autopatch:vet", Guard: g.Hash(), Rig: strings.Repeat("c", 64)})
	if err != nil {
		tr.t.Fatal(err)
	}
	tr.deliver(Bundle{Guards: map[string][]byte{g.Hash(): g.Canonical()}, Signed: []approve.Signed{sg}})
}

// tick runs one tick, a minute after the last unless the clock was moved.
func (tr *trial) tick() *TickResult {
	tr.t.Helper()
	res, err := tr.a.Tick(ctx)
	if err != nil {
		tr.t.Fatal(err)
	}
	return res
}

func (tr *trial) step(d time.Duration) *TickResult {
	tr.t.Helper()
	tr.clock = tr.clock.Add(d)
	return tr.tick()
}

// chain is the fleet's chain id, which agents' and the model's statements
// name.
func (tr *trial) chain() string {
	owner, err := hex.DecodeString(tr.p.Signers.Me.Hex)
	if err != nil {
		tr.t.Fatal(err)
	}
	return approve.ChainID(owner, tr.p.Fleet)
}

func (tr *trial) entry(g *guard.Guard) *Entry {
	for _, e := range load(tr.t, tr.a).Guards {
		if e.Hash == g.Hash() {
			return e
		}
	}
	return nil
}

func (tr *trial) evidence(g *guard.Guard) *Evidence {
	tr.t.Helper()
	ev, err := tr.a.loadEvidence(g.Hash())
	if err != nil {
		tr.t.Fatal(err)
	}
	return ev
}

// putOn drives a guard from its Tested to on: three baseline samples a
// minute apart, then the apply on the third.
func (tr *trial) putOn(g *guard.Guard) {
	tr.t.Helper()
	for i := 0; i < 2; i++ {
		if res := tr.step(time.Minute); len(res.Baseline) != 1 || len(res.Applied) != 0 {
			tr.t.Fatalf("baseline sample %d: %+v", i+1, res)
		}
	}
	if res := tr.step(time.Minute); len(res.Applied) != 1 {
		tr.t.Fatalf("the third tick didn't put it on: %+v", res)
	}
	if e := tr.entry(g); e == nil || e.Status != Pending || tr.timer.armed[g.Hash()] != trialArm {
		tr.t.Fatalf("on trial: %+v, armed %v", e, tr.timer.armed)
	}
}

func ipoptGuard(t *testing.T) *guard.Guard {
	return parse(t, `{"id": "cve-2026-98432/linux-ipv4-ipopt", "version": 1, "flaws": ["CVE-2026-98432"],
		"for": [{"os": "ubuntu", "releases": ["22.04", "24.04", "26.04"]}],
		"blocks": [{"drop": {"family": "ipv4", "protocol": "tcp", "ip_options": true}}],
		"breaks": "IP Record Route and Timestamp on TCP"}`)
}

func mptcpGuard(t *testing.T) *guard.Guard {
	return parse(t, `{"id": "cve-2026-98432/linux-mptcp-off", "version": 1, "flaws": ["CVE-2026-98432"],
		"for": [{"os": "ubuntu", "releases": ["22.04", "24.04", "26.04"]}],
		"blocks": [{"setting": {"name": "net.mptcp.enabled", "value": "0"}}],
		"breaks": "new MPTCP sockets"}`)
}

func portGuard(t *testing.T, id, proto, port string) *guard.Guard {
	return parse(t, `{"id": "`+id+`", "version": 1, "flaws": ["CVE-2099-20"],
		"for": [{"os": "ubuntu", "releases": ["24.04"]}],
		"blocks": [{"drop": {"family": "ipv4", "protocol": "`+proto+`", "ports": ["`+port+`"]}}],
		"breaks": "the service on that port"}`)
}

// A guard goes on after a baseline of three samples over two minutes, and
// is confirmed when its ten-minute window passes with health holding. The
// guard file came with the rig's Tested.
func TestTrialConfirms(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g := ipoptGuard(t)
	tr.tested(g)
	if res := tr.tick(); len(res.Baseline) != 1 {
		t.Fatalf("first tick: %+v", res)
	}
	if ev := tr.evidence(g); ev.Guard == nil || len(ev.Signed) != 1 {
		t.Fatalf("the Tested and the guard's file weren't kept: %+v", ev)
	}
	tr.clock = tr.clock.Add(-time.Minute) // putOn's first step is the second sample
	tr.putOn(g)
	for i := 0; i < 9; i++ {
		if res := tr.step(time.Minute); len(res.Confirmed) != 0 {
			t.Fatalf("confirmed %d minutes into its window", i+1)
		}
	}
	if res := tr.step(time.Minute); len(res.Confirmed) != 1 {
		t.Fatalf("not confirmed after ten minutes: %+v", res)
	}
	if e := tr.entry(g); e.Status != Confirmed || e.By != "rig" || e.Later {
		t.Fatalf("after its window: %+v", e)
	}
	if _, armed := tr.timer.armed[g.Hash()]; armed {
		t.Fatal("the undo is still armed")
	}
	// After the window, a failure pages and never takes the guard off.
	tr.fail[site] = "connection refused"
	for i := 0; i < 5; i++ {
		tr.step(time.Minute)
	}
	if e := tr.entry(g); e == nil || e.Status != Confirmed {
		t.Fatalf("a failure after confirm took it off: %+v", e)
	}
}

// A check that held in the baseline and then fails three samples in a row
// takes the guard off; it is tried again after 15 minutes, 1 hour and 4
// hours, each with a fresh baseline, and then the owner is asked.
func TestTrialFailsAndRetries(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g := ipoptGuard(t)
	tr.tested(g)
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	for try, wait := range append(retries, 0) {
		tr.putOn(g)
		tr.fail[site] = "connection refused"
		tr.step(time.Minute)
		tr.step(time.Minute)
		res := tr.step(time.Minute)
		if len(res.Undone) != 1 || !strings.Contains(res.Undone[0], "3 times in a row") {
			t.Fatalf("try %d: three failures didn't take it off: %+v", try+1, res)
		}
		if tr.entry(g) != nil || table(tr.sys, g) != nil {
			t.Fatalf("try %d: still on", try+1)
		}
		ev := tr.evidence(g)
		if ev.Tries != try+1 {
			t.Fatalf("tries %d, want %d", ev.Tries, try+1)
		}
		delete(tr.fail, site)
		if wait == 0 {
			if !ev.Ask {
				t.Fatal("the retries are spent but the owner isn't asked")
			}
			break
		}
		if !ev.RetryAt.Equal(tr.clock.Add(wait)) {
			t.Fatalf("try %d: retry at %v, want %v later", try+1, ev.RetryAt, wait)
		}
		if res := tr.step(wait - time.Minute); len(res.Baseline)+len(res.Applied) != 0 {
			t.Fatalf("try %d: began before its wait: %+v", try+1, res)
		}
		if res := tr.step(time.Minute); len(res.Baseline) != 1 {
			t.Fatalf("try %d: the next try didn't begin: %+v", try+1, res)
		}
		tr.clock = tr.clock.Add(-time.Minute)
		tr.sys.tables = map[string]*fakeTable{}
	}
	if res := tr.step(24 * time.Hour); len(res.Baseline)+len(res.Applied) != 0 {
		t.Fatalf("tried again without the owner: %+v", res)
	}
}

// A check that failed in the baseline doesn't count against the guard; a
// failure that is still running when the window ends holds the verdict
// until it clears or reaches three.
func TestTrialBaselineAndStreak(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g := ipoptGuard(t)
	tr.tested(g)
	tr.fail[site] = "refused before the guard" // fails in the baseline
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(g)
	for i := 0; i < 9; i++ {
		tr.step(time.Minute)
	}
	if res := tr.step(time.Minute); len(res.Confirmed) != 1 {
		t.Fatalf("a check that failed in the baseline blocked the confirm: %+v", res)
	}

	// The window ends with a failure running: no verdict until it clears.
	tr2 := newTrial(t, "backup", "")
	tr2.tested(g)
	tr2.tick()
	tr2.clock = tr2.clock.Add(-time.Minute)
	tr2.putOn(g)
	for i := 0; i < 8; i++ {
		tr2.step(time.Minute)
	}
	tr2.fail[site] = "slow"
	tr2.step(time.Minute) // the 9th minute: one failure
	if res := tr2.step(time.Minute); len(res.Confirmed)+len(res.Undone) != 0 {
		t.Fatalf("a verdict with a failure running: %+v", res)
	}
	delete(tr2.fail, site)
	if res := tr2.step(time.Minute); len(res.Confirmed) != 1 {
		t.Fatalf("not confirmed once the failure cleared: %+v", res)
	}
}

// A window that ends without a verdict (here the undo timer fired first)
// counts as a failure.
func TestTrialWithoutVerdict(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g := ipoptGuard(t)
	tr.tested(g)
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(g)
	if _, err := tr.a.Undo(ctx, g.Hash(), true); err != nil { // the timer's undo
		t.Fatal(err)
	}
	res := tr.step(time.Minute)
	if len(res.Undone) != 1 || !strings.Contains(res.Undone[0], "without a verdict") {
		t.Fatalf("%+v", res)
	}
	if ev := tr.evidence(g); ev.Tries != 1 || ev.RetryAt.IsZero() {
		t.Fatalf("%+v", ev)
	}
}

// The owner's keep goes on at once, with no baseline and no window.
func TestTrialKeep(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g := ipoptGuard(t)
	ev := &Evidence{Guard: g.Canonical(), Yeses: map[string]*approve.Yes{"A": {Hash: g.Hash(), Tiers: []string{"A"}, Until: tr.clock.Add(time.Hour), Mode: "keep"}}}
	if err := tr.a.saveEvidence(g.Hash(), ev); err != nil {
		t.Fatal(err)
	}
	if res := tr.tick(); len(res.Applied) != 1 {
		t.Fatalf("%+v", res)
	}
	if e := tr.entry(g); e.Status != Confirmed || !e.Keep || e.By != "me" {
		t.Fatalf("%+v", e)
	}
}

// One change is in flight at a time: a second guard waits for the first
// one's window to end before its baseline begins.
func TestTrialOneAtATime(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g1, g2 := ipoptGuard(t), portGuard(t, "test/udp5353", "udp", "5353")
	tr.tested(g1)
	tr.tested(g2)
	first, second := g1, g2
	if g2.Hash() < g1.Hash() {
		first, second = g2, g1
	}
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(first)
	for i := 0; i < 10; i++ {
		res := tr.step(time.Minute)
		if len(res.Baseline)+len(res.Applied) != 0 {
			t.Fatalf("minute %d of the first window: %+v", i+1, res)
		}
	}
	if e := tr.entry(first); e.Status != Confirmed {
		t.Fatalf("first: %+v", e)
	}
	if res := tr.step(time.Minute); len(res.Baseline) != 1 || res.Baseline[0] != second.Name() {
		t.Fatalf("the second guard didn't begin: %+v", res)
	}
}

// A guard this machine refuses for a listed reason records the reason's
// code, counts no try, and is planned again after 15 minutes.
func TestTrialRefusal(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g := mptcpGuard(t)
	tr.sys.inUse["netns"] = "process 4242 (dockerd) lives in another network namespace"
	tr.tested(g)
	res := tr.tick()
	if len(res.Refused) != 1 || len(res.Baseline) != 0 {
		t.Fatalf("%+v", res)
	}
	ev := tr.evidence(g)
	if ev.RefusedCode != "netns" || ev.Tries != 0 || !ev.RetryAt.Equal(tr.clock.Add(refusedRecheck)) {
		t.Fatalf("%+v", ev)
	}
	delete(tr.sys.inUse, "netns")
	if res := tr.step(refusedRecheck); len(res.Baseline) != 1 {
		t.Fatalf("not planned again: %+v", res)
	}
}

// A drop that would cut a flow the policy protects on this host is refused
// as protected-flow; one narrowed by IP options isn't.
func TestTrialProtectedFlow(t *testing.T) {
	tr := newTrial(t, "backup", `,"protected":[{"hosts":["backup"],"proto":"tcp","port":8443}]`)
	cut := portGuard(t, "test/tcp8443", "tcp", "8443")
	tr.tested(cut)
	tr.tested(ipoptGuard(t))
	tr.tick()
	if ev := tr.evidence(cut); ev.RefusedCode != "protected-flow" {
		t.Fatalf("%+v", ev)
	}
	if ev := tr.evidence(ipoptGuard(t)); ev.Refused != "" {
		t.Fatalf("an IP-options drop refused: %+v", ev)
	}
}

// A guard that bites later gets one more window after its first boot. Health
// that holds through it sets Booted; a failure in it takes the guard off.
func TestTrialBootWindow(t *testing.T) {
	for _, failing := range []bool{false, true} {
		tr := newTrial(t, "backup", "")
		g := mptcpGuard(t)
		tr.tested(g)
		tr.tick()
		tr.clock = tr.clock.Add(-time.Minute)
		tr.putOn(g)
		for i := 0; i < 10; i++ {
			tr.step(time.Minute)
		}
		if e := tr.entry(g); e.Status != Confirmed || !e.Later || e.Booted {
			t.Fatalf("after the first window: %+v", e)
		}
		tr.clock = tr.clock.Add(time.Hour)
		tr.sys.settings["net.mptcp.enabled"] = "1" // a reboot loses it
		if err := tr.a.Boot(ctx); err != nil {
			t.Fatal(err)
		}
		e := tr.entry(g)
		if e.Status != Pending || !e.BootWindow || !e.AppliedAt.Equal(tr.clock) || tr.timer.armed[g.Hash()] != tr.a.bootArm() || tr.sys.settings["net.mptcp.enabled"] != "0" {
			t.Fatalf("after boot: %+v, armed %v, mptcp %s", e, tr.timer.armed, tr.sys.settings["net.mptcp.enabled"])
		}
		if failing {
			// It came back after the boot, then failed three times in a row.
			tr.step(time.Minute)
			tr.fail[site] = "the boot broke it"
			tr.step(time.Minute)
			tr.step(time.Minute)
			if res := tr.step(time.Minute); len(res.Undone) != 1 {
				t.Fatalf("a failure in the boot window: %+v", res)
			}
			if tr.entry(g) != nil || tr.sys.settings["net.mptcp.enabled"] != "1" {
				t.Fatal("still on after a failed boot window")
			}
			continue
		}
		// The window runs from its first sample with every check back: the
		// first tick after the boot, here.
		for i := 0; i < 10; i++ {
			if res := tr.step(time.Minute); len(res.Confirmed) != 0 {
				t.Fatalf("confirmed %d minutes after the boot", i+1)
			}
		}
		if res := tr.step(time.Minute); len(res.Confirmed) != 1 {
			t.Fatalf("the boot window didn't confirm: %+v", res)
		}
		if e := tr.entry(g); e.Status != Confirmed || !e.Booted || e.BootWindow {
			t.Fatalf("after the boot window: %+v", e)
		}
		if ev := tr.evidence(g); !strings.Contains(ev.Last, "after a boot") {
			t.Fatalf("last %q", ev.Last)
		}
		// Later boots open no window.
		if err := tr.a.Boot(ctx); err != nil {
			t.Fatal(err)
		}
		if e := tr.entry(g); e.Status != Confirmed {
			t.Fatalf("a second boot: %+v", e)
		}
	}
}

// A guard taken off by hand stays off until the owner's next Yes.
func TestTrialHandUndoHolds(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g := ipoptGuard(t)
	tr.tested(g)
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(g)
	if _, err := tr.a.Undo(ctx, g.Hash(), false); err != nil {
		t.Fatal(err)
	}
	if err := tr.a.Hold(g.Hash(), "taken off by hand"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		if res := tr.step(time.Hour); len(res.Baseline)+len(res.Applied)+len(res.Undone) != 0 {
			t.Fatalf("hour %d: %+v", i+1, res)
		}
	}
}

// A machine that isn't a canary waits for a canary's Healthy with its own
// nonce, delivered through the lookout, before its baseline begins.
func TestTrialWaitsForCanary(t *testing.T) {
	tr := newTrial(t, "mail", "")
	g := ipoptGuard(t)
	tr.tested(g)
	if res := tr.tick(); len(res.Waiting) != 1 || len(res.Baseline) != 0 {
		t.Fatalf("%+v", res)
	}
	nonce := tr.evidence(g).Nonce
	if len(nonce) != 32 {
		t.Fatalf("nonce %q", nonce)
	}
	healthy := func(key ed25519.PrivateKey, host, n string) approve.Signed {
		sg, err := approve.SignStatement(key, approve.Statement{Version: approve.MemoVersion, Kind: approve.KindHealthy,
			Chain: tr.chain(), Guard: g.Hash(), Host: host, State: approve.StateOn, Nonce: n})
		if err != nil {
			t.Fatal(err)
		}
		return sg
	}
	// An old nonce, mail's own key posing as the canary, and another fleet's
	// chain don't count.
	other := healthy(tr.keys["backup"], "backup", nonce)
	other.Statement.Chain = "autopatch:0123456789abcdef/other"
	if other, err := approve.SignStatement(tr.keys["backup"], other.Statement); err != nil {
		t.Fatal(err)
	} else {
		tr.deliver(Bundle{Signed: []approve.Signed{healthy(tr.keys["backup"], "backup", strings.Repeat("ef", 16)), healthy(tr.keys["mail"], "backup", nonce), other}})
	}
	if res := tr.step(time.Minute); len(res.Waiting) != 1 {
		t.Fatalf("%+v", res)
	}
	tr.deliver(Bundle{Signed: []approve.Signed{healthy(tr.keys["backup"], "backup", nonce)}})
	if res := tr.step(time.Minute); len(res.Baseline) != 1 {
		t.Fatalf("the canary's Healthy didn't release it: %+v", res)
	}
}

// After a boot, a check that is slow to come back (a model loading,
// signed_last20 refilling) doesn't count against a guard until it has passed
// once, or its grace has run out (round 5, new major 1).
func TestBootWindowGrace(t *testing.T) {
	for _, c := range []struct {
		name      string
		backAfter int // minutes after the boot the check passes; -1: never
		undone    bool
	}{
		{"back after 6 minutes", 6, false},
		{"never back", -1, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := newTrial(t, "backup", "")
			g := mptcpGuard(t)
			tr.tested(g)
			tr.tick()
			tr.clock = tr.clock.Add(-time.Minute)
			tr.putOn(g)
			for i := 0; i < 10; i++ {
				tr.step(time.Minute)
			}
			tr.clock = tr.clock.Add(time.Hour)
			tr.fail[site] = "still starting"
			if err := tr.a.Boot(ctx); err != nil {
				t.Fatal(err)
			}
			undoneAt := 0
			for m := 1; m <= 25 && undoneAt == 0; m++ {
				if m == c.backAfter {
					delete(tr.fail, site)
				}
				res := tr.step(time.Minute)
				if len(res.Undone) > 0 {
					undoneAt = m
				}
				if len(res.Confirmed) > 0 {
					if c.undone {
						t.Fatalf("confirmed at minute %d with the check never back", m)
					}
					if m != c.backAfter+10 {
						t.Fatalf("confirmed at minute %d, want %d (ten after it came back)", m, c.backAfter+10)
					}
					return
				}
			}
			switch {
			case !c.undone:
				t.Fatalf("a slow check took it off at minute %d", undoneAt)
			case undoneAt != 12: // grace 10 minutes, then three failures
				t.Fatalf("taken off at minute %d, want 12", undoneAt)
			}
		})
	}
}

// The later guards that came back at one boot are all watched, and share
// the boot as their suspect: one failure takes them all off (round 5).
func TestBootWindowGroup(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g1 := mptcpGuard(t)
	g2 := parse(t, `{"id": "test/ksmbd", "version": 1, "flaws": ["CVE-2099-30"],
		"for": [{"os": "ubuntu", "releases": ["24.04"]}],
		"blocks": [{"module": {"name": "ksmbd"}}], "breaks": "the in-kernel SMB server"}`)
	for _, g := range []*guard.Guard{g1, g2} {
		tr.tested(g)
	}
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	first, second := g1, g2
	if g2.Hash() < g1.Hash() {
		first, second = g2, g1
	}
	tr.putOn(first)
	for i := 0; i < 10; i++ {
		tr.step(time.Minute)
	}
	// The check fails through the second guard's baseline, so it doesn't
	// count for that guard: only the boot it shares with the first can take
	// it off.
	tr.fail[site] = "flaky before the second guard"
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(second)
	delete(tr.fail, site)
	for i := 0; i < 10; i++ {
		tr.step(time.Minute)
	}
	if tr.entry(first).Status != Confirmed || tr.entry(second).Status != Confirmed {
		t.Fatal("not both confirmed")
	}
	tr.clock = tr.clock.Add(time.Hour)
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	if !tr.entry(first).BootWindow || !tr.entry(second).BootWindow {
		t.Fatal("not both in a window after the boot")
	}
	tr.step(time.Minute) // both back
	tr.fail[site] = "broken after the boot"
	tr.step(time.Minute)
	tr.step(time.Minute)
	res := tr.step(time.Minute)
	if len(res.Undone) != 2 || tr.entry(first) != nil || tr.entry(second) != nil {
		t.Fatalf("one failure after the boot should take both off: %+v", res)
	}
}

// A window that passes starts the count of tries again (round 5).
func TestTriesReset(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g := ipoptGuard(t)
	tr.tested(g)
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(g)
	tr.fail[site] = "x"
	for i := 0; i < 3; i++ {
		tr.step(time.Minute)
	}
	delete(tr.fail, site)
	if tr.evidence(g).Tries != 1 {
		t.Fatal("no try counted")
	}
	tr.clock = tr.clock.Add(retries[0] - time.Minute)
	tr.putOn(g)
	for i := 0; i < 10; i++ {
		tr.step(time.Minute)
	}
	if ev := tr.evidence(g); tr.entry(g).Status != Confirmed || ev.Tries != 0 {
		t.Fatalf("tries %d after a window passed", ev.Tries)
	}
}

// A keep guard that bites later counts as booted once it is back on after
// a boot (round 5, new major 2); the owner's keep for a guard in its window
// confirms it at once (minor 5).
func TestKeepLater(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g := mptcpGuard(t)
	ev := &Evidence{Guard: g.Canonical(), Yeses: map[string]*approve.Yes{"A": {Hash: g.Hash(), Tiers: []string{"A"}, Until: tr.clock.Add(24 * time.Hour), Mode: "keep"}}}
	if err := tr.a.saveEvidence(g.Hash(), ev); err != nil {
		t.Fatal(err)
	}
	tr.tick()
	if e := tr.entry(g); e.Status != Confirmed || !e.Keep || e.Booted {
		t.Fatalf("%+v", e)
	}
	// After a boot, a kept later guard has no window; it counts as booted
	// once every check that held before the boot has passed since.
	tr.step(time.Minute) // a sample before the boot, the check passing
	tr.fail[site] = "still starting"
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	tr.step(time.Minute)
	if e := tr.entry(g); e.Status != Confirmed || e.Booted || e.BootWindow {
		t.Fatalf("booted before the check came back: %+v", e)
	}
	delete(tr.fail, site)
	tr.step(time.Minute)
	if e := tr.entry(g); e.Status != Confirmed || !e.Booted || e.BootWindow {
		t.Fatalf("a keep guard after a boot, the check back: %+v", e)
	}

	tr2 := newTrial(t, "backup", "")
	g2 := ipoptGuard(t)
	tr2.tested(g2)
	tr2.tick()
	tr2.clock = tr2.clock.Add(-time.Minute)
	tr2.putOn(g2)
	if on, err := tr2.a.SetKeep(ctx, g2.Hash(), true); err != nil || !on {
		t.Fatal(on, err)
	}
	if e := tr2.entry(g2); e.Status != Confirmed || !e.Keep {
		t.Fatalf("keep didn't confirm a guard in its window: %+v", e)
	}
	if _, armed := tr2.timer.armed[g2.Hash()]; armed {
		t.Fatal("its undo is still armed")
	}
}

// The tier's spacing: after the canary's Healthy, each machine that isn't
// a canary waits the spacing times its place (round 5, minor 2).
func TestSpacing(t *testing.T) {
	tier := &policy.Tier{Name: "A", Hosts: []string{"backup", "mail", "web", "db"}, Canaries: []string{"backup"}, SpacingSeconds: 900}
	for host, want := range map[string]time.Duration{"backup": 0, "mail": 0, "web": 15 * time.Minute, "db": 30 * time.Minute} {
		if got := spacing(tier, host); got != want {
			t.Errorf("%s: %v, want %v", host, got, want)
		}
	}
}

// Every report lists the checks failing now, so a failure after a confirm
// pages the owner.
func TestReportHealth(t *testing.T) {
	tr := newTrial(t, "backup", "")
	tr.fail[site] = "connection refused"
	tr.tick()
	if h := tr.reportOf().Tick.Health; h["tcp "+site+" "] != "connection refused" {
		t.Fatalf("health %v", h)
	}
}

func (tr *trial) reportOf() *FleetReport {
	tr.t.Helper()
	b, err := ReadReport(tr.a.StateDir)
	if err != nil {
		tr.t.Fatal(err)
	}
	body, err := approve.VerifyReport(b, hex.EncodeToString(tr.keys["backup"].Public().(ed25519.PublicKey)))
	if err != nil {
		tr.t.Fatal(err)
	}
	var r FleetReport
	if err := json.Unmarshal(body, &r); err != nil {
		tr.t.Fatal(err)
	}
	return &r
}

func ksmbdGuard(t *testing.T) *guard.Guard {
	return parse(t, `{"id": "test/ksmbd", "version": 1, "flaws": ["CVE-2099-31"],
		"for": [{"os": "ubuntu", "releases": ["24.04"]}],
		"blocks": [{"module": {"name": "ksmbd"}}], "breaks": "the in-kernel SMB server"}`)
}

// The guards a boot brings back share one baseline, the machine's last
// samples before the boot, and none is confirmed until all can be (round 6,
// new major 2). Y's own baseline missed the check (it was failing then);
// the shared one counts it. The check never comes back after the boot:
// both come off, neither is marked booted.
func TestBootGroupSharedBaseline(t *testing.T) {
	tr := newTrial(t, "backup", "")
	x, y := mptcpGuard(t), ksmbdGuard(t)
	if !x.BitesAtBoot() || !y.BitesAtBoot() {
		t.Fatal("both should bite at a boot")
	}
	tr.tested(x)
	tr.tested(y)
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	first, second := x, y
	if y.Hash() < x.Hash() {
		first, second = y, x
	}
	tr.putOn(first)
	for i := 0; i < 10; i++ {
		tr.step(time.Minute)
	}
	tr.fail[site] = "down during the second guard's baseline"
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(second)
	delete(tr.fail, site)
	for i := 0; i < 10; i++ {
		tr.step(time.Minute)
	}
	if tr.entry(first).Status != Confirmed || tr.entry(second).Status != Confirmed {
		t.Fatal("not both confirmed")
	}
	for i := 0; i < 3; i++ {
		tr.step(time.Minute) // samples before the boot: the check passing
	}
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	tr.fail[site] = "never back after the boot"
	var undone []string
	for m := 1; m <= 15 && len(undone) == 0; m++ {
		res := tr.step(time.Minute)
		undone = res.Undone
		if len(res.Confirmed) > 0 {
			t.Fatalf("confirmed at minute %d with the check down", m)
		}
	}
	if len(undone) != 2 {
		t.Fatalf("both should come off: %v", undone)
	}
	for _, g := range []*guard.Guard{x, y} {
		if e := tr.entry(g); e != nil {
			t.Fatalf("%s still on: %+v", g.Name(), e)
		}
	}
}

// For a later guard that hasn't booted yet, only the window after its
// boot starts the count of tries again (round 6, minor 1).
func TestTriesLaterGuard(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g := mptcpGuard(t)
	tr.tested(g)
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(g)
	tr.fail[site] = "x"
	for i := 0; i < 3; i++ {
		tr.step(time.Minute)
	}
	delete(tr.fail, site)
	tr.clock = tr.clock.Add(retries[0] - time.Minute)
	tr.putOn(g)
	for i := 0; i < 10; i++ {
		tr.step(time.Minute)
	}
	if ev := tr.evidence(g); tr.entry(g).Status != Confirmed || ev.Tries != 1 {
		t.Fatalf("a later guard's first window reset its tries: %d", ev.Tries)
	}
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 11; i++ {
		tr.step(time.Minute)
	}
	if ev := tr.evidence(g); !tr.entry(g).Booted || ev.Tries != 0 {
		t.Fatalf("after its boot window: booted %v, tries %d", tr.entry(g).Booted, ev.Tries)
	}
}

// Spacing waits only after a canary's Healthy (round 6, new major 3): with
// the owner's nocanary, mail (second in line after web) takes the guard at
// once; via the canary it waits its place.
func TestSpacingOnlyAfterTheCanary(t *testing.T) {
	g := ipoptGuard(t)
	for _, nocanary := range []bool{true, false} {
		tr := newTrialTier(t, "mail", `"hosts":["backup","web","mail"],"spacing_seconds":900`, "")
		if nocanary {
			ev := &Evidence{Guard: g.Canonical(), Yeses: map[string]*approve.Yes{"A": {Hash: g.Hash(), Tiers: []string{"A"}, Until: tr.clock.Add(24 * time.Hour), Mode: "undo", NoCanary: true}}}
			if err := tr.a.saveEvidence(g.Hash(), ev); err != nil {
				t.Fatal(err)
			}
			if res := tr.tick(); len(res.Baseline) != 1 {
				t.Fatalf("nocanary waited: %+v", res)
			}
			continue
		}
		tr.tested(g)
		tr.tick()
		nonce := tr.evidence(g).Nonce
		sg, _ := approve.SignStatement(tr.keys["backup"], approve.Statement{Version: approve.MemoVersion, Kind: approve.KindHealthy,
			Chain: tr.chain(), Guard: g.Hash(), Host: "backup", State: approve.StateOn, Nonce: nonce})
		tr.deliver(Bundle{Signed: []approve.Signed{sg}})
		if res := tr.step(time.Minute); len(res.Baseline) != 0 || !strings.Contains(strings.Join(res.Waiting, " "), "spacing") {
			t.Fatalf("via the canary, mail didn't wait its place: %+v", res)
		}
		if res := tr.step(15 * time.Minute); len(res.Baseline) != 1 {
			t.Fatalf("after the spacing: %+v", res)
		}
	}
}

// A keep goes on even while another guard's window is open (round 6).
func TestKeepDuringAWindow(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g1 := ipoptGuard(t)
	tr.tested(g1)
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(g1) // in its window now
	g2 := portGuard(t, "test/udp5353", "udp", "5353")
	ev := &Evidence{Guard: g2.Canonical(), Yeses: map[string]*approve.Yes{"A": {Hash: g2.Hash(), Tiers: []string{"A"}, Until: tr.clock.Add(time.Hour), Mode: "keep"}}}
	if err := tr.a.saveEvidence(g2.Hash(), ev); err != nil {
		t.Fatal(err)
	}
	if res := tr.step(time.Minute); len(res.Applied) != 1 || res.Applied[0] != g2.Name() {
		t.Fatalf("the keep waited for the window: %+v", res)
	}
	if tr.entry(g1).Status != Pending {
		t.Fatal("the first guard's window should still be open")
	}
}

// A strip bites at a program's next run, which a boot may not bring: it
// gets no window after a boot, and counts as booted once the checks that
// held before the boot have passed since (round 6).
func TestStripNoBootWindow(t *testing.T) {
	tr := newTrial(t, "backup", "")
	tr.sys.addFile("/usr/bin/pkexec", 0o4755)
	g := parse(t, `{"id": "test/pkexec", "version": 1, "flaws": ["CVE-2021-4034"],
		"for": [{"os": "ubuntu", "releases": ["24.04"]}],
		"blocks": [{"strip": {"path": "/usr/bin/pkexec"}}], "breaks": "pkexec"}`)
	if !g.Later() || g.BitesAtBoot() {
		t.Fatal("a strip bites later, but not at a boot")
	}
	tr.tested(g)
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(g)
	for i := 0; i < 10; i++ {
		tr.step(time.Minute)
	}
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	if e := tr.entry(g); e.Status != Confirmed || e.BootWindow {
		t.Fatalf("a strip got a window after the boot: %+v", e)
	}
	tr.step(time.Minute)
	if e := tr.entry(g); !e.Booted {
		t.Fatalf("not booted with the checks back: %+v", e)
	}
}

// bootUntilConfirmed drives a later guard from its Tested to confirmed
// (baseline, window), then returns.
func (tr *trial) onAndConfirmed(g *guard.Guard) {
	tr.t.Helper()
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(g)
	for i := 0; i < 10; i++ {
		tr.step(time.Minute)
	}
	if e := tr.entry(g); e == nil || e.Status != Confirmed {
		tr.t.Fatalf("%s not confirmed: %+v", g.Name(), e)
	}
}

// After a shared boot window fails, its guards are suspects: no try is
// counted, they come back one per boot, and the next boot judges each
// alone; the guilty one then fails alone and counts a try (round 7, new
// major 3).
func TestSuspectsComeBackOnePerBoot(t *testing.T) {
	tr := newTrial(t, "backup", "")
	x, y := mptcpGuard(t), ksmbdGuard(t)
	tr.tested(x)
	tr.tested(y)
	tr.tick()
	first, second := x, y
	if y.Hash() < x.Hash() {
		first, second = y, x
	}
	tr.onAndConfirmed(first)
	tr.onAndConfirmed(second)
	for i := 0; i < 3; i++ {
		tr.step(time.Minute)
	}
	// The boot breaks the check: both come off as suspects, no try counted.
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	tr.step(time.Minute)
	tr.fail[site] = "broken after the boot"
	for i := 0; i < 3; i++ {
		tr.step(time.Minute)
	}
	for _, g := range []*guard.Guard{x, y} {
		ev := tr.evidence(g)
		if tr.entry(g) != nil || !ev.Suspect || ev.Tries != 0 {
			t.Fatalf("%s after the shared failure: on %v, suspect %v, tries %d", g.Name(), tr.entry(g) != nil, ev.Suspect, ev.Tries)
		}
	}
	delete(tr.fail, site)
	// One comes back; the other waits for a boot to judge the first.
	var back, waiting *guard.Guard
	for i := 0; i < 30 && back == nil; i++ {
		tr.step(time.Minute)
		for _, g := range []*guard.Guard{x, y} {
			if e := tr.entry(g); e != nil && e.Status == Confirmed {
				back = g
			}
		}
	}
	if back == nil {
		t.Fatal("no suspect came back")
	}
	waiting = x
	if back == x {
		waiting = y
	}
	for i := 0; i < 30; i++ {
		res := tr.step(time.Minute)
		if tr.entry(waiting) != nil {
			t.Fatalf("both suspects on before a boot judged the first: %+v", res)
		}
	}
	// The boot judges the first alone, and it passes: booted, no longer a suspect.
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 11; i++ {
		tr.step(time.Minute)
	}
	if e := tr.entry(back); !e.Booted || tr.evidence(back).Suspect {
		t.Fatalf("the first after its solo boot: %+v", e)
	}
	// Now the second goes on; its solo boot fails: a try is counted.
	tr.onAndConfirmedWhenReady(t, waiting)
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	tr.step(time.Minute)
	tr.fail[site] = "broken after the boot"
	for i := 0; i < 3; i++ {
		tr.step(time.Minute)
	}
	if ev := tr.evidence(waiting); tr.entry(waiting) != nil || ev.Suspect || ev.Tries != 1 {
		t.Fatalf("the guilty one alone: suspect %v, tries %d", ev.Suspect, ev.Tries)
	}
}

// onAndConfirmedWhenReady waits for a guard's baseline to begin, then
// drives it through its window.
func (tr *trial) onAndConfirmedWhenReady(t *testing.T, g *guard.Guard) {
	t.Helper()
	for i := 0; i < 60; i++ {
		if e := tr.entry(g); e != nil && e.Status == Confirmed {
			return
		}
		tr.step(time.Minute)
	}
	t.Fatalf("%s never went on", g.Name())
}

// A keep that goes on during another guard's window shares it: if that
// window fails, no try is counted (round 7, minor 7).
func TestKeepSharesTheWindow(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g1 := ipoptGuard(t)
	tr.tested(g1)
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(g1)
	g2 := portGuard(t, "test/udp5353", "udp", "5353")
	ev := &Evidence{Guard: g2.Canonical(), Yeses: map[string]*approve.Yes{"A": {Hash: g2.Hash(), Tiers: []string{"A"}, Until: tr.clock.Add(time.Hour), Mode: "keep"}}}
	if err := tr.a.saveEvidence(g2.Hash(), ev); err != nil {
		t.Fatal(err)
	}
	tr.step(time.Minute) // the keep goes on during g1's window
	tr.fail[site] = "broken"
	for i := 0; i < 3; i++ {
		tr.step(time.Minute)
	}
	if ev := tr.evidence(g1); tr.entry(g1) != nil || !ev.Suspect || ev.Tries != 0 {
		t.Fatalf("g1 after a shared window failed: suspect %v tries %d", ev.Suspect, ev.Tries)
	}
	if e := tr.entry(g2); e == nil || e.Status != Confirmed {
		t.Fatal("the keep came off")
	}
}

// A restart during a lone guard's window after a boot counts a try (round
// 7, minor 5).
func TestRestartDuringBootWindow(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g := mptcpGuard(t)
	tr.tested(g)
	tr.tick()
	tr.onAndConfirmed(g)
	tr.step(time.Minute)
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	tr.step(time.Minute)
	if err := tr.a.Boot(ctx); err != nil { // restarted during its window
		t.Fatal(err)
	}
	res := tr.step(time.Minute)
	if ev := tr.evidence(g); tr.entry(g) != nil || ev.Tries != 1 || !strings.Contains(strings.Join(res.Undone, " "), "restarted") {
		t.Fatalf("on %v tries %d: %+v", tr.entry(g) != nil, ev.Tries, res.Undone)
	}
}

// After a long time off, the samples before the boot are stale: the group
// counts only checks that held in the guards' own baselines (round 7,
// minor 6). Here the check failed in the guard's baseline, so its failing
// after the boot doesn't count.
func TestStaleSamplesFallBack(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g := mptcpGuard(t)
	tr.tested(g)
	tr.tick()
	tr.fail[site] = "down during the baseline"
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(g)
	delete(tr.fail, site)
	for i := 0; i < 10; i++ {
		tr.step(time.Minute)
	}
	tr.step(time.Minute)                    // a pre-boot sample with the check passing...
	tr.clock = tr.clock.Add(48 * time.Hour) // ...two days before the boot
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	tr.fail[site] = "down after the boot"
	for i := 0; i < 25; i++ {
		if res := tr.step(time.Minute); len(res.Undone) > 0 {
			t.Fatalf("a check that didn't hold in the guard's own baseline counted: %+v", res.Undone)
		}
	}
	if e := tr.entry(g); e == nil || !e.Booted {
		t.Fatalf("not booted: %+v", e)
	}
}

// A kept guard watched at a boot counts as booted only when the boot's
// window for its other guards has its verdict (round 7, minor 4).
func TestObservedWaitsForTheVerdict(t *testing.T) {
	tr := newTrial(t, "backup", "")
	w := mptcpGuard(t)
	tr.tested(w)
	tr.tick()
	tr.onAndConfirmed(w)
	k := ksmbdGuard(t)
	ev := &Evidence{Guard: k.Canonical(), Yeses: map[string]*approve.Yes{"A": {Hash: k.Hash(), Tiers: []string{"A"}, Until: tr.clock.Add(24 * time.Hour), Mode: "keep"}}}
	if err := tr.a.saveEvidence(k.Hash(), ev); err != nil {
		t.Fatal(err)
	}
	tr.step(time.Minute) // the keep goes on
	tr.step(time.Minute)
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		tr.step(time.Minute)
		if e := tr.entry(k); e.Booted {
			t.Fatalf("the kept guard booted at minute %d, before the window's verdict", i+1)
		}
	}
	for i := 0; i < 8; i++ {
		tr.step(time.Minute)
	}
	if e := tr.entry(k); !e.Booted {
		t.Fatalf("the kept guard after the verdict: %+v", e)
	}
}

// fusermountStrip is a strip of fusermount3's setuid bit: what a unit that
// mounts a share as a plain user needs at boot.
func fusermountStrip(t *testing.T, tr *trial) *guard.Guard {
	tr.sys.addFile("/usr/bin/fusermount3", 0o4755)
	return parse(t, `{"id": "test/fusermount3", "version": 1, "flaws": ["CVE-2099-32"],
		"for": [{"os": "ubuntu", "releases": ["24.04"]}],
		"blocks": [{"strip": {"path": "/usr/bin/fusermount3"}}], "breaks": "fusermount3 for plain users"}`)
}

// The strip breaks a unit at a boot, and the unit stays failed, so at the
// next boot it was failing before too. The check is recorded against the
// strip, which is booted only at a boot the check comes back through; the
// canary answers nothing for it meanwhile (round 8, new major 1).
func TestStripBrokeAtBootNeverBooted(t *testing.T) {
	tr := newTrial(t, "backup", "")
	s := fusermountStrip(t, tr)
	tr.tested(s)
	tr.tick()
	tr.onAndConfirmed(s)
	tr.deliver(Bundle{Wants: []Want{{Guard: s.Hash(), Nonce: strings.Repeat("ab", 16)}}})
	tr.step(time.Minute)
	if h := tr.report("backup").Healthy; len(h) != 1 || h[0].Statement.State != approve.StateOn {
		t.Fatalf("before the boot: %+v", h)
	}
	key := "tcp " + site + " "
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	tr.fail[site] = "the backup share's mount failed"
	for i := 0; i < 40; i++ {
		tr.step(time.Minute)
	}
	if e := tr.entry(s); e == nil || e.Booted {
		t.Fatalf("booted with its unit failed: %+v", e)
	}
	if _, ok := tr.evidence(s).Broke[key]; !ok {
		t.Fatalf("not recorded: %+v", tr.evidence(s).Broke)
	}
	if h := tr.report("backup").Healthy; len(h) != 0 {
		t.Fatalf("the canary answered for it: %+v", h)
	}
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		tr.step(time.Minute)
		if e := tr.entry(s); e.Booted {
			t.Fatalf("booted at minute %d of the next boot, with its unit still failed", i+1)
		}
	}
	// Fixed by hand half an hour after the boot, the boot's window still
	// open: the check didn't come back through the boot by itself, so not
	// booted yet.
	delete(tr.fail, site)
	for i := 0; i < 60; i++ {
		tr.step(time.Minute)
		if e := tr.entry(s); e.Booted {
			t.Fatalf("booted %d minutes after a fix by hand, without a boot", i+1)
		}
	}
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		tr.step(time.Minute)
	}
	if e := tr.entry(s); e.Booted {
		t.Fatal("booted on the check's first passing samples, before it held for the window (round 9, minor 8)")
	}
	for i := 0; i < 10; i++ {
		tr.step(time.Minute)
	}
	if e := tr.entry(s); !e.Booted || len(tr.evidence(s).Broke) != 0 {
		t.Fatalf("after a boot the check came back through and held: %+v, broke %+v", e, tr.evidence(s).Broke)
	}
}

// A module block whose unit stays failed after the undo: the check it broke
// is failing with it off too, so it waits for the owner at once instead of
// retrying into the ask (round 8, new major 1; round 9, new major 4).
func TestModuleBlockBrokeAtBootReachesAsk(t *testing.T) {
	tr := newTrial(t, "backup", "")
	w := ksmbdGuard(t)
	tr.tested(w)
	tr.tick()
	tr.onAndConfirmed(w)
	tr.step(time.Minute)
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	tr.fail[site] = "the unit that needs the module hit its start limit"
	for i := 0; i < 15; i++ {
		tr.step(time.Minute)
	}
	if ev := tr.evidence(w); tr.entry(w) != nil || ev.Tries != 1 || len(ev.Broke) != 1 {
		t.Fatalf("after its boot: on %v, tries %d, broke %+v", tr.entry(w) != nil, ev.Tries, ev.Broke)
	}
	for i := 0; i < 8*60 && !tr.evidence(w).Ask; i++ {
		tr.step(time.Minute)
		if e := tr.entry(w); e != nil && e.Status == Confirmed {
			t.Fatalf("confirmed at minute %d with the check it broke still failing", i+1)
		}
	}
	if ev := tr.evidence(w); !ev.Ask || ev.Tries != 1 || !strings.Contains(ev.Last, "failing with it off too") {
		t.Fatalf("didn't ask at once: ask %v, tries %d, %q", ev.Ask, ev.Tries, ev.Last)
	}
	if r := tr.reportOf(); !strings.Contains(fmt.Sprint(r.OnTheWay), "failing with it off too") {
		t.Fatalf("the report doesn't say why: %+v", r.OnTheWay)
	}
	// The owner looks, fixes the unit, and says yes again (what a Yes does
	// to the evidence): the block goes on, and at a boot the check comes
	// back by itself, so the record clears.
	ev := tr.evidence(w)
	ev.Ask, ev.Tries, ev.RetryAt = false, 0, time.Time{}
	if err := tr.a.saveEvidence(w.Hash(), ev); err != nil {
		t.Fatal(err)
	}
	delete(tr.fail, site)
	tr.onAndConfirmedWhenReady(t, w)
	// The retries' failed windows didn't turn the boot's record into a
	// window's, so the running confirm didn't clear it.
	if b, ok := tr.evidence(w).Broke["tcp "+site+" "]; !ok || !b.AtBoot {
		t.Fatalf("what the boot broke, after the retries and a running confirm: %+v", tr.evidence(w).Broke)
	}
	tr.step(time.Minute)
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		tr.step(time.Minute)
	}
	if e := tr.entry(w); e == nil || !e.Booted || len(tr.evidence(w).Broke) != 0 {
		t.Fatalf("after a boot the check came back through: %+v, broke %+v", e, tr.evidence(w).Broke)
	}
}

// A guard that bites now breaks a check in its window, and the check stays
// failed after the undo: it doesn't confirm, and since the check fails with
// it off too, it waits for the owner (round 8, new major 1; round 9, new
// major 4).
func TestWindowRecordCountsOnRetry(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g := ipoptGuard(t)
	tr.tested(g)
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(g)
	tr.fail[site] = "broken by the guard, and stays broken"
	for i := 0; i < 3; i++ {
		tr.step(time.Minute)
	}
	if ev := tr.evidence(g); tr.entry(g) != nil || ev.Tries != 1 || len(ev.Broke) != 1 {
		t.Fatalf("after its window: on %v, tries %d, broke %+v", tr.entry(g) != nil, ev.Tries, ev.Broke)
	}
	for i := 0; i < 90; i++ {
		tr.step(time.Minute)
		if e := tr.entry(g); e != nil && e.Status == Confirmed {
			t.Fatalf("confirmed at minute %d with the check it broke failing", i+1)
		}
	}
	if ev := tr.evidence(g); !ev.Ask || ev.Tries != 1 {
		t.Fatalf("after the check stayed failed: ask %v, tries %d", ev.Ask, ev.Tries)
	}
}

// bothOn puts two guards on, the first by hash first.
func (tr *trial) bothOn(x, y *guard.Guard) {
	tr.t.Helper()
	first, second := x, y
	if y.Hash() < x.Hash() {
		first, second = y, x
	}
	tr.onAndConfirmed(first)
	tr.onAndConfirmed(second)
}

// A strip watched at a boot makes the boot's window shared: when a check
// breaks, the module block in the window is a suspect, not blamed alone,
// and the check is recorded against both (round 8, new major 1).
func TestWatchedGuardsShareTheBoot(t *testing.T) {
	tr := newTrial(t, "backup", "")
	s, w := fusermountStrip(t, tr), ksmbdGuard(t)
	tr.tested(s)
	tr.tested(w)
	tr.tick()
	tr.bothOn(s, w)
	tr.step(time.Minute)
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	tr.step(time.Minute)
	tr.fail[site] = "broken at the boot"
	for i := 0; i < 3; i++ {
		tr.step(time.Minute)
	}
	if ev := tr.evidence(w); tr.entry(w) != nil || !ev.Suspect || ev.Tries != 0 || len(ev.Broke) != 1 {
		t.Fatalf("the block: on %v, suspect %v, tries %d, broke %+v", tr.entry(w) != nil, ev.Suspect, ev.Tries, ev.Broke)
	}
	if e, ev := tr.entry(s), tr.evidence(s); e == nil || e.Booted || len(ev.Broke) != 1 {
		t.Fatalf("the strip: %+v, broke %+v", e, ev.Broke)
	}
}

// Two later guards share a boot's window, and the ticks stop until both
// undo timers fire: the shared window ended without a verdict, so neither
// counts a try (round 8, minor 6).
func TestSharedBootWindowTimerCountsNoTry(t *testing.T) {
	tr := newTrial(t, "backup", "")
	x, y := mptcpGuard(t), ksmbdGuard(t)
	tr.tested(x)
	tr.tested(y)
	tr.tick()
	tr.bothOn(x, y)
	tr.step(time.Minute)
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	tr.step(time.Minute)
	for _, g := range []*guard.Guard{x, y} {
		if _, err := tr.a.Undo(ctx, g.Hash(), true); err != nil { // the undo timers fire
			t.Fatal(err)
		}
	}
	tr.step(time.Minute)
	for _, g := range []*guard.Guard{x, y} {
		if ev := tr.evidence(g); tr.entry(g) != nil || !ev.Suspect || ev.Tries != 0 {
			t.Fatalf("%s: on %v, suspect %v, tries %d", g.Name(), tr.entry(g) != nil, ev.Suspect, ev.Tries)
		}
	}
}

// moduleGuard blocks a loadable module of the fake machine.
func moduleGuard(t *testing.T, tr *trial, name string) *guard.Guard {
	tr.sys.modules[name] = "loadable"
	return parse(t, `{"id": "test/`+name+`", "version": 1, "flaws": ["CVE-2099-33"],
		"for": [{"os": "ubuntu", "releases": ["24.04"]}],
		"blocks": [{"module": {"name": "`+name+`"}}], "breaks": "the `+name+` module"}`)
}

// sharedSuspects puts x and y on, boots, and fails the boot's shared window:
// both come off as suspects.
func (tr *trial) sharedSuspects(x, y *guard.Guard) {
	tr.t.Helper()
	tr.tested(x)
	tr.tested(y)
	tr.tick()
	tr.bothOn(x, y)
	tr.step(time.Minute)
	if err := tr.a.Boot(ctx); err != nil {
		tr.t.Fatal(err)
	}
	tr.step(time.Minute)
	tr.fail[site] = "broken after the boot"
	for i := 0; i < 3; i++ {
		tr.step(time.Minute)
	}
	for _, g := range []*guard.Guard{x, y} {
		if ev := tr.evidence(g); tr.entry(g) != nil || !ev.Suspect {
			tr.t.Fatalf("%s isn't a suspect: on %v", g.Name(), tr.entry(g) != nil)
		}
	}
	delete(tr.fail, site)
}

// A later guard root put on by hand never gets a window at a boot, so it
// doesn't fill the one-per-boot slot: the first suspect still comes back
// after its wait (round 8, new major 4).
func TestHandGuardLeavesTheSlot(t *testing.T) {
	tr := newTrial(t, "backup", "")
	hand := moduleGuard(t, tr, "cramfs")
	if _, err := tr.a.Apply(ctx, hand, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.a.Confirm(ctx, hand.Hash()); err != nil {
		t.Fatal(err)
	}
	x, y := mptcpGuard(t), ksmbdGuard(t)
	tr.sharedSuspects(x, y)
	for i := 0; i < 30; i++ {
		tr.step(time.Minute)
		if tr.entry(x) != nil || tr.entry(y) != nil {
			return
		}
	}
	t.Fatalf("no suspect came back beside a guard put on by hand: %+v", tr.step(time.Minute).Waiting)
}

// A new guard that bites at a boot goes ahead of the suspects still
// waiting: it waits at most one boot (round 8, minor 5).
func TestNewGuardAheadOfSuspects(t *testing.T) {
	tr := newTrial(t, "backup", "")
	x, y := mptcpGuard(t), ksmbdGuard(t)
	tr.sharedSuspects(x, y)
	var back, waiting *guard.Guard
	for i := 0; i < 30 && back == nil; i++ {
		tr.step(time.Minute)
		for _, g := range []*guard.Guard{x, y} {
			if e := tr.entry(g); e != nil && e.Status == Confirmed {
				back = g
			}
		}
	}
	if back == nil {
		t.Fatal("no suspect came back")
	}
	waiting = x
	if back == x {
		waiting = y
	}
	// A new guard whose hash sorts after the waiting suspect's.
	var z *guard.Guard
	for _, name := range []string{"cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf", "squashfs", "affs", "befs", "sysv"} {
		if g := moduleGuard(t, tr, name); g.Hash() > waiting.Hash() {
			z = g
			break
		}
	}
	if z == nil {
		t.Fatal("no guard sorts after the suspect")
	}
	tr.tested(z)
	tr.step(time.Minute)
	if err := tr.a.Boot(ctx); err != nil { // judges the first suspect alone
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		tr.step(time.Minute)
		if tr.entry(waiting) != nil {
			t.Fatalf("the suspect went on ahead of the new guard (minute %d)", i+1)
		}
		if e := tr.entry(z); e != nil {
			return
		}
	}
	t.Fatal("the new guard never went on")
}

// A keep joins a guard's window, and the ticks stop until the guard's undo
// timer fires: the shared window ended without a verdict, so no try is
// counted (round 8, minor 6).
func TestSharedWindowTimerCountsNoTry(t *testing.T) {
	tr := newTrial(t, "backup", "")
	g1 := ipoptGuard(t)
	tr.tested(g1)
	tr.tick()
	tr.clock = tr.clock.Add(-time.Minute)
	tr.putOn(g1)
	g2 := portGuard(t, "test/udp5353", "udp", "5353")
	ev := &Evidence{Guard: g2.Canonical(), Yeses: map[string]*approve.Yes{"A": {Hash: g2.Hash(), Tiers: []string{"A"}, Until: tr.clock.Add(time.Hour), Mode: "keep"}}}
	if err := tr.a.saveEvidence(g2.Hash(), ev); err != nil {
		t.Fatal(err)
	}
	tr.step(time.Minute)                                       // the keep goes on during g1's window
	if _, err := tr.a.Undo(ctx, g1.Hash(), true); err != nil { // g1's undo timer fires
		t.Fatal(err)
	}
	tr.step(time.Minute)
	if ev := tr.evidence(g1); tr.entry(g1) != nil || !ev.Suspect || ev.Tries != 0 {
		t.Fatalf("g1: on %v, suspect %v, tries %d", tr.entry(g1) != nil, ev.Suspect, ev.Tries)
	}
}

// What a boot broke stays recorded through a confirm on the running
// machine: if the check is failing again before the next boot, that boot
// still counts it against the guard (round 8, new major 1).
func TestBootRecordSurvivesARunningConfirm(t *testing.T) {
	tr := newTrial(t, "backup", "")
	w := ksmbdGuard(t)
	tr.tested(w)
	tr.tick()
	tr.onAndConfirmed(w)
	tr.step(time.Minute)
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	tr.fail[site] = "the unit failed at the boot"
	for i := 0; i < 15; i++ {
		tr.step(time.Minute)
	}
	if tr.evidence(w).Tries != 1 {
		t.Fatalf("tries %d", tr.evidence(w).Tries)
	}
	delete(tr.fail, site) // fixed by hand; the retry's window passes
	tr.onAndConfirmedWhenReady(t, w)
	if len(tr.evidence(w).Broke) != 1 {
		t.Fatalf("a running confirm cleared what the boot broke: %+v", tr.evidence(w).Broke)
	}
	tr.fail[site] = "failing again before the next boot"
	for i := 0; i < 3; i++ {
		tr.step(time.Minute)
	}
	if err := tr.a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		tr.step(time.Minute)
		if e := tr.entry(w); e != nil && e.Booted {
			t.Fatalf("booted at minute %d with the check it broke at a boot failing", i+1)
		}
	}
}

// Two later guards share a boot; the unit one of them broke stays failed.
// Both come off as suspects with a shared record, and since the check fails
// with them off, each waits for the owner at once: neither counts a try,
// and the innocent one isn't retried into the ask beside the guilty one
// (round 9, new major 4).
func TestSharedBootInnocentCountsNoTry(t *testing.T) {
	tr := newTrial(t, "backup", "")
	k, m := ksmbdGuard(t), mptcpGuard(t)
	tr.sharedSuspectsStuck(k, m)
	for i := 0; i < 6*60; i++ {
		tr.step(time.Minute)
		for _, g := range []*guard.Guard{k, m} {
			if e := tr.entry(g); e != nil {
				t.Fatalf("%s went on with the check it shared still failing", g.Name())
			}
		}
	}
	for _, g := range []*guard.Guard{k, m} {
		if ev := tr.evidence(g); ev.Tries != 0 || !ev.Ask || !ev.Broke["tcp "+site+" "].Shared {
			t.Fatalf("%s: tries %d, ask %v, broke %+v", g.Name(), ev.Tries, ev.Ask, ev.Broke)
		}
	}
}

// sharedSuspectsStuck is sharedSuspects with the broken check left failing.
func (tr *trial) sharedSuspectsStuck(x, y *guard.Guard) {
	tr.t.Helper()
	tr.tested(x)
	tr.tested(y)
	tr.tick()
	tr.bothOn(x, y)
	tr.step(time.Minute)
	if err := tr.a.Boot(ctx); err != nil {
		tr.t.Fatal(err)
	}
	tr.step(time.Minute)
	tr.fail[site] = "the unit hit its start limit"
	for i := 0; i < 3; i++ {
		tr.step(time.Minute)
	}
	for _, g := range []*guard.Guard{x, y} {
		if ev := tr.evidence(g); tr.entry(g) != nil || !ev.Suspect {
			tr.t.Fatalf("%s isn't a suspect", g.Name())
		}
	}
}

// A watched strip that never boots (its check never comes back) makes only
// its first boot shared: at a later boot, a module block that breaks
// another check fails alone and counts a try (round 9, minor 8).
func TestObservedSharesOnlyItsFirstBoot(t *testing.T) {
	const site2 = "203.0.113.6:443"
	tr := newTrialTier(t, "backup", `"hosts":["backup","mail"]`, "", site2)
	s := fusermountStrip(t, tr)
	tr.tested(s)
	tr.tick()
	tr.onAndConfirmed(s)
	tr.step(time.Minute)
	if err := tr.a.Boot(ctx); err != nil { // its first boot: it breaks site, for good
		t.Fatal(err)
	}
	tr.fail[site] = "the strip broke this"
	for i := 0; i < 15; i++ {
		tr.step(time.Minute)
	}
	w := ksmbdGuard(t)
	tr.tested(w)
	tr.onAndConfirmedWhenReady(t, w)
	tr.step(time.Minute)
	if err := tr.a.Boot(ctx); err != nil { // the strip's second boot, the block's first
		t.Fatal(err)
	}
	tr.step(time.Minute)
	tr.fail[site2] = "the block broke this"
	for i := 0; i < 3; i++ {
		tr.step(time.Minute)
	}
	if ev := tr.evidence(w); tr.entry(w) != nil || ev.Suspect || ev.Tries != 1 {
		t.Fatalf("the block at the strip's second boot: on %v, suspect %v, tries %d", tr.entry(w) != nil, ev.Suspect, ev.Tries)
	}
}
