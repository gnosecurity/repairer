package lookout

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/jaekwon/autopatch/agent"
	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
)

// Store holds what the lookout carries: the owner's signed statements by
// sequence, the guard and policy files they name, and the rig's, vetters'
// and model's signed statements. The lookout can forge none of it; the
// agents check every signature.
type Store struct{ Dir string }

func (s *Store) path(parts ...string) string {
	return filepath.Join(append([]string{s.Dir}, parts...)...)
}

func (s *Store) put(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// AddMessage keeps an owner statement as autopatch-sign wrote it. A second
// statement with the same sequence is refused: the owner signs each number
// once.
func (s *Store) AddMessage(b []byte) (uint64, error) {
	var m agent.Message
	if err := json.Unmarshal(b, &m); err != nil || m.Seq == 0 || len(m.Tx) == 0 {
		return 0, errors.New("lookout: not a message from autopatch-sign")
	}
	p := s.path("messages", strconv.FormatUint(m.Seq, 10)+".json")
	if old, err := os.ReadFile(p); err == nil && string(old) != string(b) {
		return 0, fmt.Errorf("lookout: a different statement %d is already kept", m.Seq)
	}
	return m.Seq, s.put(p, b)
}

// AddGuard keeps a guard file, canonical, by its hash.
func (s *Store) AddGuard(b []byte) (string, error) {
	g, err := guard.Parse(b)
	if err != nil {
		return "", err
	}
	return g.Hash(), s.put(s.path("guards", g.Hash()+".json"), g.Canonical())
}

// AddPolicy keeps a policy file, canonical, by its hash.
func (s *Store) AddPolicy(b []byte) (string, error) {
	p, err := policy.Parse(b)
	if err != nil {
		return "", err
	}
	return p.Hash(), s.put(s.path("policies", p.Hash()+".json"), p.Canonical())
}

// AddSigned keeps another role's signed statement (Tested, ModelYes) whose
// signature verifies; the agents check its key's role.
func (s *Store) AddSigned(b []byte) error {
	sg, _, err := approve.ParseSigned(b)
	if err != nil {
		return err
	}
	if sg.Statement.Kind == approve.KindHealthy {
		return errors.New("lookout: Healthy comes from the canaries' reports")
	}
	name := sg.Statement.Guard + "-" + sg.Statement.Kind + "-" + sg.Key[:16] + ".json"
	out, _ := json.Marshal(sg)
	return s.put(s.path("signed", name), out)
}

// Limits on one bundle, under the agent's 1 MB.
const (
	maxBundleMessages = 50
	maxBundleSigned   = 200
)

// Bundle builds what to carry to one machine: the owner's statements after
// the last one it took, in order and without a gap; the guard and policy
// files they and the signed statements name; every signed statement; the
// canaries' Healthy answers from their reports; and, for a canary, the
// other machines' wants.
func (s *Store) Bundle(host string, sts []HostStatus, p *policy.Policy) ([]byte, error) {
	var me *agent.FleetReport
	for _, st := range sts {
		if st.Host == host {
			me = st.Report
		}
	}
	if me == nil {
		return nil, fmt.Errorf("lookout: no report from %s, so no way to know what it has", host)
	}
	b := agent.Bundle{Guards: map[string][]byte{}, Policies: map[string][]byte{}}
	addGuard := func(h string) {
		if g, err := os.ReadFile(s.path("guards", h+".json")); err == nil {
			b.Guards[h] = g
		}
	}
	for seq := me.OwnerSeq + 1; len(b.Messages) < maxBundleMessages; seq++ {
		raw, err := os.ReadFile(s.path("messages", strconv.FormatUint(seq, 10)+".json"))
		if err != nil {
			break // the next one isn't here: a gap holds the rest, as the agent would
		}
		var m agent.Message
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		b.Messages = append(b.Messages, m)
		var tx approve.GnokeyTx
		if json.Unmarshal(m.Tx, &tx) == nil && len(tx.Msg) == 1 && len(tx.Msg[0].Args) > 0 {
			switch tx.Msg[0].Func {
			case "Yes", "Off", "On":
				addGuard(tx.Msg[0].Args[0])
			case "Policy":
				if pb, err := os.ReadFile(s.path("policies", tx.Msg[0].Args[0]+".json")); err == nil {
					b.Policies[tx.Msg[0].Args[0]] = pb
				}
			}
		}
	}
	signed, _ := filepath.Glob(s.path("signed", "*.json"))
	sort.Strings(signed)
	for _, f := range signed {
		if len(b.Signed) >= maxBundleSigned {
			break
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var sg approve.Signed
		if err := json.Unmarshal(raw, &sg); err != nil {
			return nil, err
		}
		b.Signed = append(b.Signed, sg)
		addGuard(sg.Statement.Guard)
	}
	tier, _ := p.TierOf(host)
	canary := tier != nil && contains(tier.Canaries, host)
	for _, st := range sts {
		if st.Report == nil || st.Host == host {
			continue
		}
		if !canary && len(b.Signed) < maxBundleSigned {
			b.Signed = append(b.Signed, st.Report.Healthy...)
		}
		if canary {
			b.Wants = append(b.Wants, st.Report.Wants...)
		}
	}
	out, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	if len(out) > agent.MaxBundle {
		return nil, fmt.Errorf("lookout: the bundle for %s is %d bytes, more than an agent takes", host, len(out))
	}
	return out, nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
