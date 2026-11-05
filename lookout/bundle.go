package lookout

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

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

// AddFile keeps a file by what it is: a message from autopatch-sign, a
// signed statement, a guard, or a policy. It says what it kept.
func (s *Store) AddFile(b []byte) (string, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return "", errors.New("lookout: not JSON")
	}
	switch {
	case probe["seq"] != nil && probe["tx"] != nil:
		seq, err := s.AddMessage(b)
		return fmt.Sprintf("the owner's statement %d", seq), err
	case probe["statement"] != nil:
		return "a signed statement", s.AddSigned(b)
	case probe["blocks"] != nil:
		h, err := s.AddGuard(b)
		return "guard " + h, err
	case probe["tiers"] != nil:
		h, err := s.AddPolicy(b)
		return "policy " + h, err
	}
	return "", errors.New("lookout: not a message, a signed statement, a guard or a policy")
}

// Guard returns a kept guard file.
func (s *Store) Guard(hash string) ([]byte, error) {
	if !isHash(hash) {
		return nil, errors.New("lookout: not a guard hash")
	}
	return os.ReadFile(s.path("guards", hash+".json"))
}

func isHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// maxBundleMessages caps the owner's statements in one bundle; the rest
// come in the next.
const maxBundleMessages = 50

// bundleBudget is how much of the agent's 1 MB a bundle may fill (a var so
// tests can make it small).
var bundleBudget = agent.MaxBundle - 64<<10

// Bundle builds what to carry to one machine, in order of need, within the
// agent's 1 MB:
//  1. the owner's statements after the last one it took, in order,
//     stopping at a gap, with the files they name;
//  2. the canaries' Healthy answers to this machine's wants, and for a
//     canary, the other machines' wants;
//  3. signed statements (Tested, the model's yes) for guards not yet
//     confirmed here, newest first, with their files.
//
// What doesn't fit waits for the next delivery; a bundle is never refused
// for its size.
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
	used := 512
	fits := func(v any) bool {
		j, err := json.Marshal(v)
		if err != nil || used+len(j)+8 > bundleBudget {
			return false
		}
		used += len(j) + 8
		return true
	}
	addGuard := func(h string) bool {
		if _, ok := b.Guards[h]; ok {
			return true
		}
		g, err := os.ReadFile(s.path("guards", h+".json"))
		if err != nil {
			return true // the agent may hold it; a statement that needs it waits
		}
		if !fits(g) {
			return false
		}
		b.Guards[h] = g
		return true
	}
	messages := func() error {
		return s.addMessages(&b, me, fits, addGuard)
	}
	answers := func() error {
		s.addAnswers(&b, host, me, sts, p, fits)
		return nil
	}
	signed := func() error {
		s.addSignedFor(&b, me, fits, addGuard)
		return nil
	}
	// In order of need: what doesn't fit waits for the next delivery.
	for _, step := range []func() error{messages, answers, signed} {
		if err := step(); err != nil {
			return nil, err
		}
	}
	return json.Marshal(b)
}

// addMessages adds the owner's statements after the last one the machine
// took, in order, stopping at a gap, with the files they name.
func (s *Store) addMessages(b *agent.Bundle, me *agent.FleetReport, fits func(any) bool, addGuard func(string) bool) error {
	for seq := me.OwnerSeq + 1; len(b.Messages) < maxBundleMessages; seq++ {
		raw, err := os.ReadFile(s.path("messages", strconv.FormatUint(seq, 10)+".json"))
		if err != nil {
			break // the next one isn't here: a gap holds the rest, as the agent would
		}
		var m agent.Message
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		if !fits(m) {
			break
		}
		b.Messages = append(b.Messages, m)
		var tx approve.GnokeyTx
		if json.Unmarshal(m.Tx, &tx) == nil && len(tx.Msg) == 1 && len(tx.Msg[0].Args) > 0 {
			switch tx.Msg[0].Func {
			case "Yes", "Off", "On":
				addGuard(tx.Msg[0].Args[0])
			case "Policy":
				if pb, err := os.ReadFile(s.path("policies", tx.Msg[0].Args[0]+".json")); err == nil && fits(pb) {
					b.Policies[tx.Msg[0].Args[0]] = pb
				}
			}
		}
	}
	return nil
}

// addAnswers adds the canaries' Healthy answers to this machine's wants,
// and for a canary, the other machines' wants.
func (s *Store) addAnswers(b *agent.Bundle, host string, me *agent.FleetReport, sts []HostStatus, p *policy.Policy, fits func(any) bool) {
	mine := map[string]bool{}
	for _, w := range me.Wants {
		mine[w.Guard+"/"+w.Nonce] = true
	}
	tier, _ := p.TierOf(host)
	canary := tier != nil && contains(tier.Canaries, host)
	for _, st := range sts {
		if st.Report == nil || st.Host == host {
			continue
		}
		for _, h := range st.Report.Healthy {
			if mine[h.Statement.Guard+"/"+h.Statement.Nonce] && fits(h) {
				b.Signed = append(b.Signed, h)
			}
		}
		if canary {
			for _, w := range st.Report.Wants {
				if fits(w) {
					b.Wants = append(b.Wants, w)
				}
			}
		}
	}
}

// addSignedFor adds signed statements (Tested, the model's yes) for guards
// not yet confirmed on the machine, newest first, with their files.
func (s *Store) addSignedFor(b *agent.Bundle, me *agent.FleetReport, fits func(any) bool, addGuard func(string) bool) {
	confirmed := map[string]bool{}
	for _, g := range me.Guards {
		if g.Status == agent.Confirmed {
			confirmed[g.Hash] = true
		}
	}
	files, _ := filepath.Glob(s.path("signed", "*.json"))
	type kept struct {
		path string
		at   int64
	}
	var ks []kept
	for _, f := range files {
		if confirmed[strings.SplitN(filepath.Base(f), "-", 2)[0]] {
			continue
		}
		if fi, err := os.Stat(f); err == nil {
			ks = append(ks, kept{f, fi.ModTime().UnixNano()})
		}
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].at > ks[j].at })
	for _, k := range ks {
		raw, err := os.ReadFile(k.path)
		if err != nil {
			continue
		}
		var sg approve.Signed
		if err := json.Unmarshal(raw, &sg); err != nil {
			continue
		}
		if !addGuard(sg.Statement.Guard) || !fits(sg) {
			break
		}
		b.Signed = append(b.Signed, sg)
	}
}

// Prune forgets kept signed statements no machine needs: those for a guard
// every machine of the policy reports confirmed, or has on its Off list.
// It forgets nothing while any machine has no fresh report.
func (s *Store) Prune(sts []HostStatus) (int, error) {
	if len(sts) == 0 {
		return 0, nil
	}
	for _, st := range sts {
		if st.Report == nil || st.Silent {
			return 0, nil
		}
	}
	files, err := filepath.Glob(s.path("signed", "*.json"))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, f := range files {
		h := strings.SplitN(filepath.Base(f), "-", 2)[0]
		done := true
		for _, st := range sts {
			ok := contains(st.Report.Off, h)
			for _, g := range st.Report.Guards {
				if g.Hash == h && g.Status == agent.Confirmed {
					ok = true
				}
			}
			if !ok {
				done = false
				break
			}
		}
		if done && os.Remove(f) == nil {
			n++
		}
	}
	return n, nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
