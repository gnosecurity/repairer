package agent

import (
	"context"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/policy"
)

// NewTestAgent is an agent on a machine in memory, for tests in other
// packages: its health checks fail as fail says, and its clock is now().
func NewTestAgent(t *testing.T, now func() time.Time, fail map[string]string) *Agent {
	a, _, _ := newAgent(t)
	a.Now = now
	a.Health = func(_ context.Context, h policy.Health) string { return fail[h.Target] }
	return a
}

// SetKey gives a test agent a known Ed25519 key (its seed in hex).
func SetKey(t *testing.T, a *Agent, seedHex string) {
	if err := writeAtomic(a.StateDir+"/"+keyFile, []byte(seedHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// GuardStatus says whether a guard is on a test agent's machine, and how.
func GuardStatus(t *testing.T, a *Agent, hash string) string {
	for _, e := range load(t, a).Guards {
		if e.Hash == hash {
			return e.Status
		}
	}
	return ""
}
