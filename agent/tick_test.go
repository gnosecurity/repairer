package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
)

// The fleet of approve's signed fixtures: fleet "test", owned by the public
// test key "owner". old is the policy in force; new adds a vetter and
// doubles the delay. approve/testdata holds the owner's Yes to guard one
// (sequence 7) and the Policy statement for this change (sequence 8).
func tickPolicies(t *testing.T) (*policy.Policy, *policy.Policy) {
	t.Helper()
	old, err := policy.Decode([]byte(`{"fleet":"test","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"},
		"vetters":[{"name":"v1","key":"2222222222222222222222222222222222222222222222222222222222222222"}],"vetters_needed":1},
		"tiers":[{"name":"A","hosts":["backup","mail"],"admit":["me","vetters"],"canaries":["backup"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	new, err := policy.Decode([]byte(`{"fleet":"test","replaces":"` + old.Hash() + `","delay_seconds":172800,
		"signers":{"me":{"name":"owner","key":"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"},
		"vetters":[{"name":"v1","key":"2222222222222222222222222222222222222222222222222222222222222222"},
		           {"name":"v2","key":"3333333333333333333333333333333333333333333333333333333333333333"}],"vetters_needed":2},
		"tiers":[{"name":"A","hosts":["backup","mail"],"admit":["me","vetters"],"canaries":["backup"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return old, new
}

func bundleOf(t *testing.T, msgs []Message, g *guard.Guard, p *policy.Policy) []byte {
	t.Helper()
	b := Bundle{Messages: msgs, Guards: map[string][]byte{}, Policies: map[string][]byte{}}
	if g != nil {
		b.Guards[g.Hash()] = g.Canonical()
	}
	if p != nil {
		b.Policies[p.Hash()] = p.Canonical()
	}
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func fixtureTx(t *testing.T, name string) json.RawMessage {
	t.Helper()
	b, err := os.ReadFile("../approve/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProcessSpool(t *testing.T) {
	a, _, _ := newAgent(t)
	clock := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	a.Now = func() time.Time { return clock }
	old, new := tickPolicies(t)
	if _, err := a.Init("mail", old.Canonical(), 6); err != nil {
		t.Fatal(err)
	}
	g := guardOne(t)
	spool := filepath.Join(a.StateDir, spoolDir)
	msgs := []Message{{Seq: 8, Tx: fixtureTx(t, "policy-change.json")}, {Seq: 7, Tx: fixtureTx(t, "yes-guard-one.json")}}
	bun := bundleOf(t, msgs, g, new)
	if _, err := Intake(spool, strings.NewReader(string(bun))); err != nil {
		t.Fatal(err)
	}
	res, err := a.Tick(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accepted) != 2 || !strings.HasPrefix(res.Accepted[0], "Yes ") || !strings.HasPrefix(res.Accepted[1], "Policy ") {
		t.Fatalf("accepted %q, refused %q", res.Accepted, res.Refused)
	}
	f, err := a.loadFleet()
	if err != nil || f.LastSeq != 8 || f.Pending == nil {
		t.Fatalf("fleet %+v %v", f, err)
	}
	ev, err := a.loadEvidence(g.Hash())
	if err != nil || ev.yesFor("A") == nil || ev.yesFor("A").Tiers[0] != "A" {
		t.Fatalf("evidence %+v %v", ev, err)
	}
	if names, _ := filepath.Glob(filepath.Join(spool, "*.json")); len(names) != 0 {
		t.Fatal("a processed bundle stayed in the spool")
	}

	// The same bundle again: both statements are stale.
	if _, err := Intake(spool, strings.NewReader(string(bun))); err != nil {
		t.Fatal(err)
	}
	res, _ = a.Tick(ctx)
	if len(res.Accepted) != 0 || len(res.Refused) != 0 {
		t.Fatalf("a replay: accepted %q refused %q", res.Accepted, res.Refused)
	}

	// The new policy waits out the old policy's delay, from first sight.
	clock = clock.Add(23 * time.Hour)
	if res, _ = a.Tick(ctx); res.Policy != "" {
		t.Fatal("the policy took effect before its delay")
	}
	clock = clock.Add(time.Hour)
	if res, _ = a.Tick(ctx); res.Policy != new.Hash() {
		t.Fatalf("the policy didn't take effect after its delay: %+v", res)
	}
	if f, _ = a.loadFleet(); f.Pending != nil {
		t.Fatal("still pending")
	}
	if p, _ := f.InstalledPolicy(); p.Hash() != new.Hash() {
		t.Fatal("the new policy isn't in force")
	}

	// A sequence that jumps more than 1,000 is refused before anything else.
	jump := bundleOf(t, []Message{{Seq: 5000, Tx: fixtureTx(t, "yes-guard-one.json")}}, g, nil)
	if _, err := Intake(spool, strings.NewReader(string(jump))); err != nil {
		t.Fatal(err)
	}
	if res, _ = a.Tick(ctx); len(res.Accepted) != 0 || !strings.Contains(res.Held, "waiting for statement 9") {
		t.Fatalf("a jump: %+v", res)
	}
}

// The "tiers" chain (gnokey-signed, approve/testdata/tiers): 1 Yes(A,
// keep+nocanary), 2 Yes(B), 3 Yes(C), 4 Off(mail), 5 Yes(A, undo+nocanary),
// 6 On(mail), 7 Policy T1 over T0, 8 Policy T2 over the pending T1.
func tiersChain(t *testing.T) (*policy.Policy, []Message, *guard.Guard, map[string][]byte) {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile("../approve/testdata/tiers/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t0, err := policy.Parse(read("policy-0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var msgs []Message
	for i := 1; i <= 12; i++ {
		msgs = append(msgs, Message{Seq: uint64(i), Tx: read(fmt.Sprintf("%d.json", i))})
	}
	gb, err := os.ReadFile("../guard/testdata/cve-2026-98432-ipopt.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := guard.Parse(gb)
	if err != nil {
		t.Fatal(err)
	}
	pols := map[string][]byte{}
	for i := 0; i < 3; i++ {
		p, _ := policy.Parse(read(fmt.Sprintf("policy-%d.json", i)))
		pols[p.Hash()] = p.Canonical()
	}
	unread := read("policy-unread.json") // a file this release can't read, under its own sha256
	sum := sha256.Sum256(unread)
	pols[hex.EncodeToString(sum[:])] = unread
	return t0, msgs, g, pols
}

// tiersAgent is a machine of the tiers fleet, with a clock that moves a
// minute a tick, and a way to deliver statements.
func tiersAgent(t *testing.T, host string) (*Agent, func(...Message) *TickResult) {
	a, tick, _ := tiersAgentClock(t, host)
	return a, tick
}

// tiersAgentClock is tiersAgent with a way to set the clock.
func tiersAgentClock(t *testing.T, host string) (*Agent, func(...Message) *TickResult, func(time.Time)) {
	t0, _, g, pols := tiersChain(t)
	a, _, _ := newAgent(t)
	clock := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	a.Now = func() time.Time { return clock }
	if _, err := a.Init(host, t0.Canonical(), 0); err != nil {
		t.Fatal(err)
	}
	return a, func(msgs ...Message) *TickResult {
		t.Helper()
		clock = clock.Add(time.Minute)
		if len(msgs) > 0 {
			b := Bundle{Messages: msgs, Guards: map[string][]byte{g.Hash(): g.Canonical()}, Policies: pols}
			js, _ := json.Marshal(b)
			if _, err := Intake(filepath.Join(a.StateDir, spoolDir), bytes.NewReader(js)); err != nil {
				t.Fatal(err)
			}
		}
		res, err := a.Tick(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}, func(at time.Time) { clock = at }
}

func isOn(t *testing.T, a *Agent, g *guard.Guard) bool {
	for _, e := range load(t, a).Guards {
		if e.Hash == g.Hash() {
			return true
		}
	}
	return false
}

// A Yes changes only the tiers it names: the Yes for tier C doesn't undo
// the one for tier B (round 5, new major 3).
func TestYesPerTier(t *testing.T) {
	_, msgs, g, _ := tiersChain(t)
	sentry, tick := tiersAgent(t, "sentry")
	res := tick(msgs[:3]...)
	if len(res.Accepted) != 3 || len(res.Applied) != 1 || !isOn(t, sentry, g) {
		t.Fatalf("the sentry, after Yes A, B and C: %+v", res)
	}
	ev, _ := sentry.loadEvidence(g.Hash())
	if ev.yesFor("B") == nil || ev.yesFor("C") == nil || ev.yesFor("A").Mode != "keep" {
		t.Fatalf("yeses %+v", ev.Yeses)
	}
	validator, vtick := tiersAgent(t, "validator")
	if res := vtick(msgs[:3]...); len(res.Applied) != 1 || !isOn(t, validator, g) {
		t.Fatalf("the validator: %+v", res)
	}
}

// Off takes the guard off the hosts it names; a later Yes for the tier
// doesn't put it back there (round 5, minor 1); On does. A machine the Off
// doesn't name keeps the guard.
func TestOffAndOn(t *testing.T) {
	_, msgs, g, _ := tiersChain(t)
	mail, tick := tiersAgent(t, "mail")
	if res := tick(msgs[:3]...); len(res.Applied) != 1 {
		t.Fatalf("the keep: %+v", res)
	}
	if res := tick(msgs[3]); len(res.Off) != 1 || isOn(t, mail, g) {
		t.Fatalf("Off: %+v", res)
	}
	if res := tick(msgs[4]); len(res.Accepted) != 1 || isOn(t, mail, g) {
		t.Fatalf("a Yes put the guard back where the owner took it off: %+v", res)
	}
	for i := 0; i < 3; i++ {
		if res := tick(); len(res.Applied)+len(res.Baseline) != 0 {
			t.Fatalf("back on with no On: %+v", res)
		}
	}
	if res := tick(msgs[5]); len(res.Accepted) != 1 || len(res.Applied) != 1 || !isOn(t, mail, g) {
		t.Fatalf("On didn't put it back: %+v", res)
	}

	backup, btick := tiersAgent(t, "backup")
	btick(msgs[:3]...)
	if res := btick(msgs[3]); len(res.Off) != 0 || !isOn(t, backup, g) || !strings.Contains(strings.Join(res.Accepted, " "), "for other hosts") {
		t.Fatalf("an Off for mail took it off backup: %+v", res)
	}
}

// Statements act in the order signed: a later one waits for every one
// before it, so none can be skipped (round 5, minor 3).
func TestStatementsInOrder(t *testing.T) {
	_, msgs, g, _ := tiersChain(t)
	mail, tick := tiersAgent(t, "mail")
	tick(msgs[:3]...)
	// The lookout withholds the Off (4) and delivers the Yes (5) and On (6).
	res := tick(msgs[4], msgs[5])
	if len(res.Accepted) != 0 || !strings.Contains(res.Held, "waiting for statement 4") {
		t.Fatalf("a later statement acted before 4: %+v", res)
	}
	f, _ := mail.loadFleet()
	if f.LastSeq != 3 {
		t.Fatalf("last %d", f.LastSeq)
	}
	// A second lookout delivers 4 to 6: they act in order, the Off then On.
	if res := tick(msgs[3], msgs[4], msgs[5]); len(res.Accepted) != 3 || !isOn(t, mail, g) {
		t.Fatalf("%+v", res)
	}
	if f, _ = mail.loadFleet(); f.LastSeq != 6 || containsHash(f.Off, g.Hash()) {
		t.Fatalf("fleet %+v", f)
	}
}

// A policy step may chain onto the one pending; the chain takes effect the
// delay after its last step was first seen (round 5, minor 4).
func TestPolicyChain(t *testing.T) {
	_, msgs, _, pols := tiersChain(t)
	backup, tick, setClock := tiersAgentClock(t, "backup")
	if res := tick(msgs[:8]...); len(res.Accepted) != 8 || res.Held != "" {
		t.Fatalf("%+v", res)
	}
	f, _ := backup.loadFleet()
	pend, _ := policy.Parse(f.Pending.Policy)
	if pend.Tiers[0].SpacingSeconds != 900 {
		t.Fatalf("pending %+v", pend.Tiers[0])
	}
	var t2 string
	for h, b := range pols {
		if p, err := policy.Parse(b); err == nil && p.Tiers[0].SpacingSeconds == 900 {
			t2 = h
		}
	}
	// The delay in force is a day (T0's), from the last step's first sight;
	// each tick moves the clock a minute.
	setClock(f.Pending.FirstSeen.Add(24*time.Hour - 2*time.Minute))
	if res := tick(); res.Policy != "" {
		t.Fatal("in force a minute before the day was out")
	}
	if res := tick(); res.Policy != t2 {
		t.Fatalf("T2 not in force a day after its first sight: %q", res.Policy)
	}
}

// A statement whose bundle lacks the guard's file uses the file the agent
// already holds, so it isn't held for nothing (round 5, minor 3).
func TestStatementUsesHeldGuardFile(t *testing.T) {
	_, msgs, g, _ := tiersChain(t)
	mail, tick := tiersAgent(t, "mail")
	tick(msgs[:3]...)
	js, _ := json.Marshal(Bundle{Messages: []Message{msgs[3]}}) // the Off, no guard file
	if _, err := Intake(filepath.Join(mail.StateDir, spoolDir), bytes.NewReader(js)); err != nil {
		t.Fatal(err)
	}
	if res := tick(); len(res.Off) != 1 || res.Held != "" || isOn(t, mail, g) {
		t.Fatalf("%+v", res)
	}
}

// A statement whose signature checks out is always taken; one this agent
// can't act on is listed as skipped, and the ones after it still act
// (round 6, new major 1): a Cancel (no agent acts on it yet), a memo in a
// newer format, a policy file this release can't read; then an Off.
func TestSkipsDontHold(t *testing.T) {
	_, msgs, g, _ := tiersChain(t)
	mail, tick := tiersAgent(t, "mail")
	tick(msgs[:8]...)
	if !isOn(t, mail, g) {
		t.Fatal("not on after 1 to 8")
	}
	res := tick(msgs[8:]...)
	f, _ := mail.loadFleet()
	if f.LastSeq != 12 || f.Held != "" || len(res.Off) != 1 || isOn(t, mail, g) {
		t.Fatalf("last %d held %q: %+v", f.LastSeq, f.Held, res)
	}
	var whys []string
	for _, sk := range f.Skipped {
		whys = append(whys, fmt.Sprintf("%d %s", sk.Seq, sk.Why))
	}
	got := strings.Join(whys, " | ")
	for _, want := range []string{"9 not a kind of statement this release acts on", "10 its memo is in a format newer", "11 a policy file this release can't read"} {
		if !strings.Contains(got, want) {
			t.Errorf("skipped %q lacks %q", got, want)
		}
	}
	// The report carries the skipped statements.
	if err := mail.writeReport(ctx, f, mustPolicy(t, f), res); err != nil {
		t.Fatal(err)
	}
}

func mustPolicy(t *testing.T, f *Fleet) *policy.Policy {
	p, err := f.InstalledPolicy()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Only a statement that doesn't check out holds the rest: a forged 4 holds
// 4 to 6, and the hold stays in the fleet file (so in every report) until
// the real 4 arrives.
func TestHoldUntilItChecksOut(t *testing.T) {
	_, msgs, g, _ := tiersChain(t)
	mail, tick := tiersAgent(t, "mail")
	tick(msgs[:3]...)
	forged := Message{Seq: 4, Tx: json.RawMessage(strings.Replace(string(msgs[3].Tx), "hosts mail", "hosts mai1", 1))}
	res := tick(forged, msgs[4], msgs[5])
	f, _ := mail.loadFleet()
	if f.LastSeq != 3 || !strings.Contains(f.Held, "held at statement 4") || !strings.Contains(f.Held, "doesn't check out") {
		t.Fatalf("last %d held %q: %+v", f.LastSeq, f.Held, res)
	}
	if res := tick(); !strings.Contains(res.Held, "held at statement 4") {
		t.Fatalf("the hold left a later report: %+v", res)
	}
	tick(msgs[3], msgs[4], msgs[5])
	if f, _ = mail.loadFleet(); f.LastSeq != 6 || f.Held != "" || !isOn(t, mail, g) {
		t.Fatalf("after the real 4: last %d held %q", f.LastSeq, f.Held)
	}
}

// A Yes whose guard file isn't here yet holds until a lookout brings it.
func TestYesWaitsForItsFile(t *testing.T) {
	_, msgs, g, _ := tiersChain(t)
	mail, tick := tiersAgent(t, "mail")
	js, _ := json.Marshal(Bundle{Messages: msgs[:1]}) // no guard file
	if _, err := Intake(filepath.Join(mail.StateDir, spoolDir), bytes.NewReader(js)); err != nil {
		t.Fatal(err)
	}
	tick()
	if f, _ := mail.loadFleet(); f.LastSeq != 0 || !strings.Contains(f.Held, "held at statement 1") {
		t.Fatalf("last %d held %q", f.LastSeq, f.Held)
	}
	tick(msgs[0])
	if f, _ := mail.loadFleet(); f.LastSeq != 1 || f.Held != "" || !isOn(t, mail, g) {
		t.Fatalf("with its file: last %d held %q", f.LastSeq, f.Held)
	}
}

// Every tick takes off whatever is on and on the Off list, and so does a
// boot (round 6, minor 4): an Off whose undo never ran doesn't stay on.
func TestOffEveryTickAndBoot(t *testing.T) {
	_, msgs, g, _ := tiersChain(t)
	for _, viaBoot := range []bool{false, true} {
		mail, tick := tiersAgent(t, "mail")
		tick(msgs[:3]...)
		f, _ := mail.loadFleet()
		f.Off = append(f.Off, g.Hash()) // the Off was taken, its undo never ran
		if err := mail.saveFleet(f); err != nil {
			t.Fatal(err)
		}
		if viaBoot {
			if err := mail.Boot(ctx); err != nil {
				t.Fatal(err)
			}
		} else {
			tick()
		}
		if isOn(t, mail, g) {
			t.Fatalf("still on (by boot: %v)", viaBoot)
		}
	}
}

// A guard's keep follows the newest Yes for its tier while it is in force
// (round 6, minor 5): keep from 1, then the undo Yes 5 clears it; and a
// hand hold is lifted only by On, not by a Yes.
func TestKeepFollowsYesAndHolds(t *testing.T) {
	_, msgs, g, _ := tiersChain(t)
	mail, tick := tiersAgent(t, "mail")
	tick(msgs[:3]...)
	keep := func() bool {
		for _, e := range load(t, mail).Guards {
			if e.Hash == g.Hash() {
				return e.Keep
			}
		}
		t.Fatal("not on")
		return false
	}
	if !keep() {
		t.Fatal("not kept after the keep Yes")
	}
	// Root takes it off by hand: held.
	if _, err := mail.Undo(ctx, g.Hash(), false); err != nil {
		t.Fatal(err)
	}
	if err := mail.Hold(g.Hash(), "taken off by hand"); err != nil {
		t.Fatal(err)
	}
	tick(msgs[3]) // Off(mail)
	tick(msgs[4]) // Yes(A, undo): lifts neither the Off nor the hold
	if isOn(t, mail, g) {
		t.Fatal("a Yes put back a guard held by hand")
	}
	tick(msgs[5]) // On(mail): lifts both
	if !isOn(t, mail, g) {
		t.Fatal("On didn't put it back")
	}
	if keep() {
		t.Fatal("still kept, though the newest Yes for the tier says undo")
	}
}

// Keep follows the newest Yes while the guard stays on: on backup (which
// the Off for mail doesn't touch), the keep from 1 is cleared by the undo
// Yes 5.
func TestKeepFollowsTheNewestYes(t *testing.T) {
	_, msgs, g, _ := tiersChain(t)
	backup, tick := tiersAgent(t, "backup")
	tick(msgs[:4]...)
	keep := func() bool {
		for _, e := range load(t, backup).Guards {
			if e.Hash == g.Hash() {
				return e.Keep
			}
		}
		t.Fatal("not on")
		return false
	}
	if !keep() {
		t.Fatal("not kept after the keep Yes")
	}
	tick(msgs[4])
	if keep() {
		t.Fatal("still kept after the undo Yes for its tier")
	}
}

// Only On lifts a hold made by hand: on backup, held by hand, a Yes for
// its tier leaves it off, and so does an On that names another host.
func TestHandHoldOnlyOn(t *testing.T) {
	_, msgs, g, _ := tiersChain(t)
	backup, tick := tiersAgent(t, "backup")
	tick(msgs[:4]...)
	if _, err := backup.Undo(ctx, g.Hash(), false); err != nil {
		t.Fatal(err)
	}
	if err := backup.Hold(g.Hash(), "taken off by hand"); err != nil {
		t.Fatal(err)
	}
	tick(msgs[4], msgs[5]) // Yes(A), then On(mail)
	tick()
	if isOn(t, backup, g) {
		t.Fatal("back on without an On for backup")
	}
}
