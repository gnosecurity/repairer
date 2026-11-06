package approve

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gnosecurity/repairer/guard"
	"github.com/gnosecurity/repairer/policy"
)

// fixturePolicies are the old and new policies of the Policy fixture: the
// new one adds a vetter, needs two of them, and doubles the delay.
func fixturePolicies(t *testing.T) (*policy.Policy, *policy.Policy) {
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

// TestPrintFixtures writes the memos the signed fixtures carry, when
// PRINT_FIXTURES names a directory; gnokey then signs them.
func TestPrintFixtures(t *testing.T) {
	dir := os.Getenv("PRINT_FIXTURES")
	if dir == "" {
		t.Skip("set PRINT_FIXTURES to a directory to write the fixtures' memos")
	}
	b, err := os.ReadFile("../guard/testdata/cve-2026-98432.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := guard.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	yes, err := MemoYes(g, Yes{Hash: g.Hash(), Tiers: []string{"A"}, Until: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), Mode: "undo"})
	if err != nil {
		t.Fatal(err)
	}
	old, new := fixturePolicies(t)
	pol, err := MemoPolicy(old, new)
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"yes-memo.txt": yes, "policy-memo.txt": pol,
		"policy-args.txt": new.Hash() + "\n" + old.Hash()} {
		if err := os.WriteFile(dir+"/"+name, []byte(strings.TrimSpace(v)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
