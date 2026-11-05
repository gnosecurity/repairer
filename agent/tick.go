package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
)

// Bundle is what the lookout hands an agent through intake: the owner's
// statements in sequence order, the guard and policy files they name, and
// Ed25519 statements from the other roles. The lookout chooses what to send
// but can forge none of it: tick checks every signature against keys in the
// policy in force.
type Bundle struct {
	Messages []Message                 `json:"messages,omitempty"`
	Guards   map[string][]byte         `json:"guards,omitempty"`   // guard hash to canonical file
	Policies map[string][]byte         `json:"policies,omitempty"` // policy hash to canonical file
	Signed   []approve.Signed          `json:"signed,omitempty"`
}

// Message is one owner statement: gnokey's signed transaction file and the
// sequence it was signed with.
type Message struct {
	Seq uint64          `json:"seq"`
	Tx  json.RawMessage `json:"tx"`
}

// Evidence is what the agent keeps for a guard: its canonical file, the
// owner's Yes if any, and checked Ed25519 statements.
type Evidence struct {
	Guard  []byte           `json:"guard"`
	Yes    *approve.Yes     `json:"yes,omitempty"`
	Signed []approve.Signed `json:"signed,omitempty"`
}

// TickResult says what a tick did, for the log and the report.
type TickResult struct {
	Accepted []string // owner statements taken, in order
	Refused  []string // statements refused, and why
	Policy   string   // a policy change that took effect
	Off      []string // guards the owner took off for good; Tick undoes them
}

// Tick is what the minute timer runs: take in the spool, take off what the
// owner turned off, then repair drift. (Admission, trials and the report
// join it next.)
func (a *Agent) Tick(ctx context.Context) (*TickResult, error) {
	res, err := a.ProcessSpool(ctx)
	if err != nil {
		return res, err
	}
	for _, h := range res.Off {
		if _, err := a.Undo(ctx, h, false); err != nil && !isNotOn(err) {
			res.Refused = append(res.Refused, "taking off "+h[:12]+": "+err.Error())
		}
	}
	return res, nil
}

// isNotOn reports Undo's error for a guard that isn't on: nothing to do.
func isNotOn(err error) bool { return strings.Contains(err.Error(), "is on") }

// ProcessSpool reads every bundle in the spool, oldest first, applies what
// verifies, and removes the bundles. Owner statements must arrive in
// sequence order; a statement at or below the last accepted is stale and
// skipped, and one more than MaxSeqJump above is refused.
func (a *Agent) ProcessSpool(ctx context.Context) (*TickResult, error) {
	s, _, err := a.open()
	if err != nil {
		return nil, err
	}
	defer s.close()
	f, err := a.loadFleet()
	if err != nil {
		return nil, err
	}
	res := &TickResult{}
	dir := filepath.Join(a.StateDir, spoolDir)
	names, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	sort.Strings(names) // intake names files by time
	for _, name := range names {
		b, err := os.ReadFile(name)
		if err != nil {
			return res, err
		}
		var bun Bundle
		if err := json.Unmarshal(b, &bun); err != nil {
			res.Refused = append(res.Refused, filepath.Base(name)+": not a bundle")
		} else {
			a.applyBundle(f, &bun, res)
		}
		if err := a.saveFleet(f); err != nil {
			return res, err
		}
		if err := os.Remove(name); err != nil {
			return res, err
		}
	}
	// A pending policy takes effect once its delay has passed.
	if f.Pending != nil {
		cur, err := f.InstalledPolicy()
		if err != nil {
			return res, err
		}
		if !a.now().Before(f.Pending.FirstSeen.Add(time.Duration(cur.DelaySeconds) * time.Second)) {
			f.Policy, f.Pending = f.Pending.Policy, nil
			p, _ := f.InstalledPolicy()
			res.Policy = p.Hash()
		}
	}
	return res, a.saveFleet(f)
}

func (a *Agent) applyBundle(f *Fleet, bun *Bundle, res *TickResult) {
	p, _ := f.InstalledPolicy()
	owner, _ := hex.DecodeString(p.Signers.Me.Hex)
	chain := approve.ChainID(owner, p.Fleet)
	msgs := append([]Message(nil), bun.Messages...)
	sort.Slice(msgs, func(i, j int) bool { return msgs[i].Seq < msgs[j].Seq })
	for _, m := range msgs {
		if m.Seq <= f.LastSeq {
			continue // stale: already accepted, or replayed
		}
		what, err := a.ownerMessage(f, p, bun, chain, owner, m, res)
		if err != nil {
			res.Refused = append(res.Refused, fmt.Sprintf("owner statement %d: %v", m.Seq, err))
			continue
		}
		f.LastSeq = m.Seq
		res.Accepted = append(res.Accepted, what)
	}
	for _, sg := range bun.Signed {
		if err := a.keepSigned(p, sg); err != nil {
			res.Refused = append(res.Refused, "statement: "+err.Error())
		}
	}
}

func (a *Agent) ownerMessage(f *Fleet, p *policy.Policy, bun *Bundle, chain string, owner []byte, m Message, res *TickResult) (string, error) {
	if err := approve.CheckSeq(f.LastSeq, m.Seq); err != nil {
		return "", err
	}
	var tx approve.GnokeyTx
	if err := json.Unmarshal(m.Tx, &tx); err != nil || len(tx.Msg) != 1 {
		return "", errors.New("not one message")
	}
	args := tx.Msg[0].Args
	switch fn := tx.Msg[0].Func; fn {
	case "Yes", "Off":
		if len(args) < 1 {
			return "", errors.New("no guard named")
		}
		g, err := guard.Parse(bun.Guards[args[0]])
		if err != nil {
			return "", fmt.Errorf("the guard it names: %w", err)
		}
		if fn == "Off" {
			memo, err := approve.MemoOff(g)
			if err != nil {
				return "", err
			}
			st, err := approve.VerifyGnokey(m.Tx, chain, m.Seq, owner, memo)
			if err != nil {
				return "", err
			}
			if len(st.Call.Args) != 1 || st.Call.Args[0] != g.Hash() {
				return "", errors.New("Off names another guard")
			}
			f.Off = append(f.Off, g.Hash())
			res.Off = append(res.Off, g.Hash())
			return "Off " + g.Name(), nil
		}
		y, err := approve.VerifyYes(m.Tx, chain, m.Seq, owner, g)
		if err != nil {
			return "", err
		}
		ev, _ := a.loadEvidence(g.Hash())
		ev.Guard, ev.Yes = g.Canonical(), &y
		return "Yes " + g.Name(), a.saveEvidence(g.Hash(), ev)
	case "Policy":
		if len(args) != 2 {
			return "", errors.New("Policy takes two hashes")
		}
		next, err := policy.Parse(bun.Policies[args[0]])
		if err != nil {
			return "", fmt.Errorf("the policy it names: %w", err)
		}
		if err := approve.VerifyPolicy(m.Tx, chain, m.Seq, owner, p, next); err != nil {
			return "", err
		}
		f.Pending = &PendingPolicy{Policy: next.Canonical(), FirstSeen: a.now().UTC()}
		return "Policy " + next.Hash()[:16] + " pending", nil
	}
	return "", fmt.Errorf("function %q isn't one this agent acts on yet", tx.Msg[0].Func)
}

// keepSigned checks an Ed25519 statement and keeps it with its guard's
// evidence if the policy gives its key the role that may sign its kind.
func (a *Agent) keepSigned(p *policy.Policy, sg approve.Signed) error {
	b, err := json.Marshal(sg)
	if err != nil {
		return err
	}
	if _, _, err := approve.ParseSigned(b); err != nil {
		return err
	}
	role := map[string][]policy.Key{
		approve.KindTested:  append(append([]policy.Key(nil), p.Signers.Rig...), p.Signers.Vetters...),
		approve.KindHealthy: p.Signers.Agents,
		approve.KindModel:   p.Signers.Model,
	}[sg.Statement.Kind]
	ok := false
	for _, k := range role {
		if k.Hex == sg.Key {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("%s from key %.16s…, which the policy doesn't give that role", sg.Statement.Kind, sg.Key)
	}
	ev, _ := a.loadEvidence(sg.Statement.Guard)
	for _, have := range ev.Signed {
		if have == sg {
			return nil
		}
	}
	ev.Signed = append(ev.Signed, sg)
	return a.saveEvidence(sg.Statement.Guard, ev)
}

func (a *Agent) evidencePath(hash string) string {
	return filepath.Join(a.StateDir, "evidence", hash+".json")
}

func (a *Agent) loadEvidence(hash string) (*Evidence, error) {
	ev := &Evidence{}
	b, err := os.ReadFile(a.evidencePath(hash))
	if err != nil {
		return ev, err
	}
	return ev, json.Unmarshal(b, ev)
}

func (a *Agent) saveEvidence(hash string, ev *Evidence) error {
	if !isHex64(hash) {
		return errors.New("evidence: not a guard hash")
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return writeAtomic(a.evidencePath(hash), b, 0o600)
}

func isHex64(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
