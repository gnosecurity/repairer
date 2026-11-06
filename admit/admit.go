// Package admit decides whether a guard may go on a machine: which signed
// statements count under the owner's policy, for this machine's tier, and
// whether the machine must wait for a canary.
package admit

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jaekwon/repairer/approve"
	"github.com/jaekwon/repairer/guard"
	"github.com/jaekwon/repairer/policy"
)

// Evidence is what an agent holds for one guard, every signature already
// checked: the owner's Yes, if any, and Ed25519 statements with the keys
// that signed them.
type Evidence struct {
	Yes    *approve.Yes
	Signed []Signed
}

// Signed is a checked Ed25519 statement and its signer's key, in hex.
type Signed struct {
	Statement approve.Statement
	Key       string
}

// Machine is what the model's rule needs to know about the machine.
type Machine struct {
	// Listening are the ports anything listens on, loopback included, by
	// protocol: "tcp/22".
	Listening map[string]bool
	// ModelGuards are the guards on this machine that the model admitted,
	// with their flaws.
	ModelGuards [][]string
	// OS and Release are the machine's os-release ID and VERSION_ID: a
	// Tested counts only for the system it ran on. Unknown, none counts.
	OS, Release string
}

// Decision says whether the guard may go on, which role admitted it, and if
// not, why. Wait is set when everything is in place but a canary's Healthy.
type Decision struct {
	OK   bool
	By   string
	Why  string
	Wait bool
}

// MaxModelGuards is the most model-admitted guards one machine carries.
const MaxModelGuards = 3

// Admit applies the policy to one guard on one host. nonce is the fresh
// number this host's agent chose for a canary's Healthy.
func Admit(p *policy.Policy, host string, g *guard.Guard, ev Evidence, m Machine, nonce string, now time.Time) Decision {
	tier, ok := p.TierOf(host)
	if !ok {
		return Decision{Why: "this host is in no tier"}
	}
	h := g.Hash()
	by, why := "", []string{}
	// The owner's Yes first, whatever order the tier lists the roles in, so
	// that its keep and nocanary are never lost to another role's statement.
	roles := append([]string(nil), tier.Admit...)
	sort.SliceStable(roles, func(i, j int) bool { return roles[i] == "me" && roles[j] != "me" })
	auto := g.Auto()
	for _, role := range roles {
		if role != "me" && !auto {
			why = append(why, role+": a block outside the agent's auto lists needs the owner's yes")
			continue
		}
		switch role {
		case "me":
			if y := ev.Yes; y != nil && y.Hash == h && contains(y.Tiers, tier.Name) && now.Before(y.Until) {
				by = "me"
			} else {
				why = append(why, "no yes from the owner for tier "+tier.Name+" in force")
			}
		case "rig":
			if n := countKeys(testedOn(p, ev.Signed, m), approve.KindTested, h, p.Signers.Rig); n > 0 {
				by = "rig"
			} else {
				why = append(why, "the rig hasn't signed Tested on "+m.image()+" from a pinned rig build")
			}
		case "vetters":
			if n := countKeys(testedOn(p, ev.Signed, m), approve.KindTested, h, p.Signers.Vetters); n >= p.Signers.VettersNeeded {
				by = "vetters"
			} else {
				why = append(why, fmt.Sprintf("%d of %d vetters", n, p.Signers.VettersNeeded))
			}
		case "model":
			if countKeys(ev.Signed, approve.KindModel, h, p.Signers.Model) == 0 {
				why = append(why, "no yes from the model")
			} else if reason := modelRefuses(tier, g, m); reason != "" {
				why = append(why, "the model's yes doesn't count: "+reason)
			} else {
				by = "model"
			}
		}
		if by != "" {
			break
		}
	}
	if by == "" {
		return Decision{Why: strings.Join(why, "; ")}
	}
	if len(tier.Canaries) > 0 && !contains(tier.Canaries, host) && !(ev.Yes != nil && ev.Yes.NoCanary && by == "me") {
		if later := g.Later(); !canaryHealthy(p, tier, h, ev.Signed, nonce, later) {
			want := "a canary's Healthy"
			if later {
				want = "a canary's Healthy after a boot, since the guard bites later,"
			}
			return Decision{By: by, Wait: true, Why: "waiting for " + want + " (" + strings.Join(tier.Canaries, " or ") + ")"}
		}
	}
	return Decision{OK: true, By: by}
}

// modelRefuses applies rule 6: the model's yes counts only outside critical
// tiers, for a guard made of drops each narrowed by IP options, within the
// caps. A drop narrowed only by ports needs the owner: what serves a port
// can change after admission, in another network namespace or behind
// forwarding, and nothing re-checks it every minute yet (round 8, new
// major 2). Listening still refuses such a drop with its own reason.
func modelRefuses(tier *policy.Tier, g *guard.Guard, m Machine) string {
	if tier.Critical {
		return "tier " + tier.Name + " is critical"
	}
	for _, b := range g.Blocks {
		d := b.Drop
		if d == nil {
			return "it has a block that isn't a drop (" + b.Describe() + ")"
		}
		if d.IPOptions {
			continue
		}
		ranges, _ := d.PortRanges()
		for _, r := range ranges {
			for port := r[0]; port <= r[1]; port++ {
				if m.Listening[fmt.Sprintf("%s/%d", d.Protocol, port)] {
					return fmt.Sprintf("something listens on %s port %d", d.Protocol, port)
				}
			}
		}
		return "a drop narrowed only by ports needs your yes (" + b.Describe() + ")"
	}
	if len(m.ModelGuards) >= MaxModelGuards {
		return fmt.Sprintf("this machine already has %d guards the model admitted", len(m.ModelGuards))
	}
	for _, flaws := range m.ModelGuards {
		for _, f := range flaws {
			if contains(g.Flaws, f) {
				return "the model already admitted a guard for " + f
			}
		}
	}
	return ""
}

// testedOn keeps the statements that count on this machine: a Tested only
// for the system it ran on (round 8, minor 9) and from a rig build the
// policy pins (round 9, minor 12); other kinds as they are.
func testedOn(p *policy.Policy, ss []Signed, m Machine) []Signed {
	var out []Signed
	for _, s := range ss {
		st := s.Statement
		if st.Kind != approve.KindTested || (m.OS != "" && st.Image == m.image() && contains(p.Rigs, st.Rig)) {
			out = append(out, s)
		}
	}
	return out
}

func (m Machine) image() string { return m.OS + " " + m.Release }

// countKeys counts the distinct keys of a role that signed a statement of
// this kind for this guard. A key counts once however many statements it
// signed.
func countKeys(ss []Signed, kind, hash string, role []policy.Key) int {
	seen := map[string]bool{}
	for _, s := range ss {
		if s.Statement.Kind != kind || s.Statement.Guard != hash || seen[s.Key] {
			continue
		}
		for _, k := range role {
			if k.Hex == s.Key {
				seen[s.Key] = true
			}
		}
	}
	return len(seen)
}

// canaryHealthy reports whether an agent of one of the tier's canaries
// signed Healthy for this guard with this host's nonce. For a guard that
// bites now, "on" counts, and so does "refused" for one of the canary's own
// listed reasons, so a canary that can't take it doesn't hold its tier bare;
// each machine's own trial then tests it. A guard that bites later needs
// "booted": nothing stands in for the canary's boot.
func canaryHealthy(p *policy.Policy, tier *policy.Tier, hash string, ss []Signed, nonce string, later bool) bool {
	for _, s := range ss {
		st := s.Statement
		if st.Kind != approve.KindHealthy || st.Guard != hash || st.Nonce != nonce || !contains(tier.Canaries, st.Host) {
			continue
		}
		if later && st.State != approve.StateBooted {
			continue
		}
		for _, k := range p.Signers.Agents {
			if k.Hex == s.Key && k.Host == st.Host {
				return true
			}
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// KeyHex is a key's hex, as policies and statements write it.
func KeyHex(b []byte) string { return hex.EncodeToString(b) }
