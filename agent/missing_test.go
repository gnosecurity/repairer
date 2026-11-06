package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Without nft, a guard with drops is refused before anything happens: no
// step, no armed undo, nothing in the state. Before this check, apply got to
// its first drop, failed there, and couldn't take that drop back off without
// nft either, so the guard stayed half on with its undo armed, and the next
// apply refused until an undo. Debian's cloud images have no nft (a fresh
// Debian 12 VM showed it, scripts/rig/quickstart-e2e.sh).
func TestApplyRefusesDropsWithoutNft(t *testing.T) {
	a, sys, timer := newAgent(t)
	sys.missing = map[string]bool{"nft": true}
	g := guardOne(t)

	p, err := a.Plan(g)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.Problems, "; "), "nft") {
		t.Fatalf("the plan doesn't say nft is missing: %q", p.Problems)
	}

	_, err = a.Apply(context.Background(), g, ApplyOptions{})
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("apply without nft: %v; want a refusal", err)
	}
	if len(timer.armed) != 0 {
		t.Fatalf("an undo is armed: %v", timer.armed)
	}
	if st := load(t, a); len(st.Guards) != 0 {
		t.Fatalf("the state holds %d guard(s): %+v", len(st.Guards), st.Guards[0])
	}
	if v := sys.settings["net.mptcp.enabled"]; v != "1" {
		t.Fatalf("net.mptcp.enabled is %s; the refused guard changed it", v)
	}
}

// A guard with no drops doesn't need nft.
func TestPlanWithoutNftNeedsNoNftForSettings(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.missing = map[string]bool{"nft": true}
	g := guardOne(t)
	g.Blocks = g.Blocks[1:] // guard one without its drop: only the setting
	p, err := a.Plan(g)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(p.Problems, "; "), "nft") {
		t.Fatalf("a guard without drops was refused for nft: %q", p.Problems)
	}
}
