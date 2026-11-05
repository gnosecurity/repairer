package agent

import (
	"encoding/json"
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
	if err != nil || ev.Yes == nil || ev.Yes.Tiers[0] != "A" {
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
	if res, _ = a.Tick(ctx); len(res.Refused) != 1 || !strings.Contains(res.Refused[0], "jumps") {
		t.Fatalf("a jump: %+v", res)
	}
}
