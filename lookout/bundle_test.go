package lookout

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jaekwon/autopatch/agent"
	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/guard"
)

// A store of 300 kept Tested statements still carries, to a machine that
// isn't a canary, the owner's next statement and the canary's Healthy for
// its want, and the bundle stays under the agent's 1 MB (round 7, new
// major 2). Pruning keeps every statement a machine may still need.
func TestBundleInOrderOfNeed(t *testing.T) {
	fl := newFleet(t)
	_, rig, _ := ed25519.GenerateKey(nil)
	store := &Store{Dir: t.TempDir()}
	var hashes []string
	for i := 0; i < 300; i++ {
		g, err := guard.Decode([]byte(fmt.Sprintf(`{"id":"test/g%d","version":1,"flaws":["CVE-2099-%d"],"for":[{"os":"ubuntu","releases":["24.04"]}],
			"blocks":[{"drop":{"family":"ipv4","protocol":"udp","ports":["%d"]}}],"breaks":"x"}`, i, 1000+i, 10000+i)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.AddGuard(g.Canonical()); err != nil {
			t.Fatal(err)
		}
		sg, _ := approve.SignStatement(rig, approve.Statement{Version: approve.MemoVersion, Kind: approve.KindTested, Chain: "autopatch:vet", Guard: g.Hash(), Rig: strings.Repeat("0", 64)})
		b, _ := json.Marshal(sg)
		if err := store.AddSigned(b); err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, g.Hash())
	}
	// The owner's statement 1 (any signed message the store keeps).
	msg, _ := os.ReadFile("../approve/testdata/tiers/1.json")
	m, _ := json.Marshal(agent.Message{Seq: 1, Tx: msg})
	if _, err := store.AddMessage(m); err != nil {
		t.Fatal(err)
	}
	// mail waits for the canary's Healthy on the newest guard; backup answered.
	want := agent.Want{Guard: hashes[299], Nonce: strings.Repeat("ab", 16)}
	owner, _ := hex.DecodeString(ownerHex)
	chain := approve.ChainID(owner, "home")
	healthy, _ := approve.SignStatement(fl.keys["backup"], approve.Statement{Version: approve.MemoVersion, Kind: approve.KindHealthy,
		Chain: chain, Guard: want.Guard, Host: "backup", State: approve.StateOn, Nonce: want.Nonce})
	sts := []HostStatus{
		{Host: "backup", Report: &agent.FleetReport{Host: "backup", Healthy: []approve.Signed{healthy}}},
		{Host: "mail", Report: &agent.FleetReport{Host: "mail", Wants: []agent.Want{want}}},
	}
	// A budget the kept statements overflow, so what goes first matters.
	defer func(b int) { bundleBudget = b }(bundleBudget)
	bundleBudget = 40 << 10
	b, err := store.Bundle("mail", sts, fl.p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > agent.MaxBundle {
		t.Fatalf("the bundle is %d bytes", len(b))
	}
	var bun agent.Bundle
	if err := json.Unmarshal(b, &bun); err != nil {
		t.Fatal(err)
	}
	if len(bun.Messages) != 1 {
		t.Fatalf("the owner's statement missing: %d messages", len(bun.Messages))
	}
	found := false
	for _, sg := range bun.Signed {
		if sg.Statement.Kind == approve.KindHealthy && sg.Statement.Nonce == want.Nonce {
			found = true
		}
	}
	if !found {
		t.Fatal("the canary's Healthy didn't make the bundle")
	}
	// Every machine reports guard 0 confirmed. Its statement stays: a
	// machine added or rebuilt later needs it too (round 8, new major 3).
	if n, err := store.Prune(); err != nil || n != 0 {
		t.Fatalf("pruned %d: %v", n, err)
	}
	bundleBudget = agent.MaxBundle - 64<<10
	tested := func(sts []HostStatus) map[string]bool {
		b, err := store.Bundle("mail", sts, fl.p)
		if err != nil {
			t.Fatal(err)
		}
		var bun agent.Bundle
		if err := json.Unmarshal(b, &bun); err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, sg := range bun.Signed {
			if sg.Statement.Kind == approve.KindTested {
				got[sg.Statement.Guard] = true
			}
		}
		return got
	}
	ubuntu := &agent.Report{OS: agent.OSFacts{ID: "ubuntu", Version: "24.04"}}
	rebuilt := []HostStatus{{Host: "mail", Report: &agent.FleetReport{Host: "mail", Facts: ubuntu}}} // empty state
	if got := tested(rebuilt); !got[hashes[0]] || len(got) != 300 {
		t.Fatalf("a rebuilt machine got %d Tested, guard 0's: %v", len(got), got[hashes[0]])
	}
	// A machine of another system gets none of them.
	debian := []HostStatus{{Host: "mail", Report: &agent.FleetReport{Host: "mail", Facts: &agent.Report{OS: agent.OSFacts{ID: "debian", Version: "12"}}}}}
	if got := tested(debian); len(got) != 0 {
		t.Fatalf("a Debian machine got %d statements for Ubuntu's guards", len(got))
	}
	// A guard whose vendor's fixes cover every release it names is forgotten.
	old, err := guard.Decode([]byte(`{"id":"test/old","version":1,"flaws":["CVE-2099-999"],"for":[{"os":"ubuntu","releases":["22.04","24.04"]}],
		"blocks":[{"drop":{"family":"ipv4","protocol":"udp","ports":["9999"]}}],"breaks":"x",
		"until":[{"os":"ubuntu","release":"22.04","kernel":"5.15.0-200.210"},{"os":"ubuntu","release":"24.04","kernel":"6.8.0-200.210"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddGuard(old.Canonical()); err != nil {
		t.Fatal(err)
	}
	sg, _ := approve.SignStatement(rig, approve.Statement{Version: approve.MemoVersion, Kind: approve.KindTested, Chain: "autopatch:vet", Guard: old.Hash(), Rig: strings.Repeat("0", 64)})
	raw, _ := json.Marshal(sg)
	if err := store.AddSigned(raw); err != nil {
		t.Fatal(err)
	}
	if n, err := store.Prune(); err != nil || n != 1 {
		t.Fatalf("pruned %d for a guard every release has a fix for: %v", n, err)
	}
	if !Retired(old) {
		t.Fatal("not retired")
	}
	if g, _ := guard.Decode([]byte(`{"id":"test/half","version":1,"flaws":["CVE-2099-998"],"for":[{"os":"ubuntu","releases":["22.04","24.04"]}],
		"blocks":[{"drop":{"family":"ipv4","protocol":"udp","ports":["9998"]}}],"breaks":"x",
		"until":[{"os":"ubuntu","release":"24.04","kernel":"6.8.0-200.210"}]}`)); Retired(g) {
		t.Fatal("retired with one release still unfixed")
	}
	_ = context.Background
}
