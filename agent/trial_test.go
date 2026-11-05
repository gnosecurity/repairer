package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
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
		"tiers":[{"name":"A","hosts":["backup","mail"],"admit":["me","rig"],"canaries":["backup"]}],
		"health":[{"hosts":["backup","mail"],"kind":"tcp","target":"` + site + `","want":""}]` + extra + `}`))
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
		Chain: "autopatch:vet", Guard: g.Hash(), Rig: strings.Repeat("c", 64)})
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
	ev := &Evidence{Guard: g.Canonical(), Yes: &approve.Yes{Hash: g.Hash(), Tiers: []string{"A"}, Until: tr.clock.Add(time.Hour), Mode: "keep"}}
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
		if e.Status != Pending || !e.BootWindow || !e.AppliedAt.Equal(tr.clock) || tr.timer.armed[g.Hash()] != trialArm || tr.sys.settings["net.mptcp.enabled"] != "0" {
			t.Fatalf("after boot: %+v, armed %v, mptcp %s", e, tr.timer.armed, tr.sys.settings["net.mptcp.enabled"])
		}
		if failing {
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
		for i := 0; i < 9; i++ {
			tr.step(time.Minute)
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
