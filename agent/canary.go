package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jaekwon/autopatch/admit"
	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
)

// Want asks a canary for its Healthy on a guard, with the nonce of the
// machine waiting for it. The lookout carries wants from waiting machines'
// reports to the canaries' bundles, and the Healthy back.
type Want struct {
	Guard string `json:"guard"`
	Nonce string `json:"nonce"`
}

func (w Want) valid() bool {
	b, err := hex.DecodeString(w.Nonce)
	return isHex64(w.Guard) && err == nil && len(b) == 16 && hex.EncodeToString(b) == w.Nonce
}

func (w Want) key() string { return w.Guard + "/" + w.Nonce }

const (
	wantsFile   = "wants.json"   // wants a canary keeps answering
	healthyFile = "healthy.json" // a canary's signed answers, for its report
	maxWants    = 1000
	wantLife    = 24 * time.Hour
)

type keptWant struct {
	Want
	FirstSeen time.Time `json:"first_seen"`
}

// keepWants adds wants from a bundle. Old ones expire after a day; the
// newest maxWants are kept.
func (a *Agent) keepWants(ws []Want) error {
	kept, err := a.loadWants()
	if err != nil {
		return err
	}
	for _, w := range ws {
		if _, ok := kept[w.key()]; ok || !w.valid() {
			continue
		}
		kept[w.key()] = keptWant{Want: w, FirstSeen: a.now().UTC()}
	}
	return a.saveWants(kept)
}

func (a *Agent) loadWants() (map[string]keptWant, error) {
	kept := map[string]keptWant{}
	b, err := os.ReadFile(filepath.Join(a.StateDir, wantsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return kept, nil
	}
	if err != nil {
		return nil, err
	}
	return kept, json.Unmarshal(b, &kept)
}

func (a *Agent) saveWants(kept map[string]keptWant) error {
	for k, w := range kept {
		if a.now().Sub(w.FirstSeen) > wantLife {
			delete(kept, k)
		}
	}
	if len(kept) > maxWants {
		ks := make([]string, 0, len(kept))
		for k := range kept {
			ks = append(ks, k)
		}
		sort.Slice(ks, func(i, j int) bool { return kept[ks[i]].FirstSeen.After(kept[ks[j]].FirstSeen) })
		for _, k := range ks[maxWants:] {
			delete(kept, k)
		}
	}
	b, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(a.StateDir, wantsFile), b, 0o600)
}

// loadHealthy reads a canary's signed answers, by want.
func (a *Agent) loadHealthy() (map[string]approve.Signed, error) {
	out := map[string]approve.Signed{}
	b, err := os.ReadFile(filepath.Join(a.StateDir, healthyFile))
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	return out, json.Unmarshal(b, &out)
}

// answerWants is a canary's part: for every want it keeps, it signs what is
// true here now, if anything. "on" and "booted" only for a guard the policy
// put on here and that is confirmed; "refused" only for a guard this
// machine admitted itself and refused for a listed reason. A machine that
// isn't a canary signs nothing, since only a canary's Healthy counts.
func (a *Agent) answerWants(ctx context.Context, f *Fleet, p *policy.Policy) error {
	tier, ok := p.TierOf(f.Host)
	if !ok || !contains(tier.Canaries, f.Host) {
		return nil
	}
	wants, err := a.loadWants()
	if err != nil {
		return err
	}
	out, err := a.loadHealthy()
	if err != nil {
		return err
	}
	entries, _, err := a.Status(ctx)
	if err != nil {
		return err
	}
	on := map[string]*Entry{}
	var modelGuards [][]string
	for _, e := range entries {
		on[e.Hash] = e
		if e.By == "model" {
			modelGuards = append(modelGuards, e.Guard.Flaws)
		}
	}
	owner, _ := hex.DecodeString(p.Signers.Me.Hex)
	chain := approve.ChainID(owner, p.Fleet)
	var priv []byte
	var listening map[string]bool
	keys := make([]string, 0, len(wants))
	for k := range wants {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		w := wants[k].Want
		state, why := "", ""
		if e := on[w.Guard]; e != nil {
			if e.Status == Confirmed && e.By != "" {
				state = approve.StateOn
				if e.Booted {
					state = approve.StateBooted
				}
			}
		} else if ev, err := a.loadEvidence(w.Guard); err == nil && ev.RefusedCode != "" && ev.Guard != nil && !containsHash(f.Off, w.Guard) {
			if g, err := guard.Parse(ev.Guard); err == nil {
				if listening == nil {
					if listening, err = a.Sys.ListeningAll(); err != nil {
						return err
					}
				}
				d := admit.Admit(p, f.Host, g, admit.Evidence{Yes: ev.Yes, Signed: admitSigned(ev.Signed)},
					admit.Machine{Listening: listening, ModelGuards: modelGuards}, ev.Nonce, a.now())
				if d.OK {
					state, why = approve.StateRefused, ev.RefusedCode
				}
			}
		}
		if state == "" {
			continue
		}
		if have, ok := out[k]; ok && have.Statement.State == state && have.Statement.Why == why {
			continue
		}
		if priv == nil {
			pk, err := a.privateKey()
			if err != nil {
				return err
			}
			priv = pk
		}
		sg, err := approve.SignStatement(priv, approve.Statement{Version: approve.MemoVersion, Kind: approve.KindHealthy,
			Chain: chain, Guard: w.Guard, Host: f.Host, State: state, Why: why, Nonce: w.Nonce})
		if err != nil {
			return err
		}
		out[k] = sg
	}
	for k := range out {
		if _, ok := wants[k]; !ok {
			delete(out, k) // its want expired
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(a.StateDir, healthyFile), b, 0o600)
}
