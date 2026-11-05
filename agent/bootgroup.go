package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/policy"
)

const (
	healthFile    = "health.json"    // the machine's last few health samples
	bootGroupFile = "bootgroup.json" // the window the guards a boot brought back share
	keptSamples   = 3
	freshSamples  = time.Hour // pre-boot samples older than this don't make the baseline
)

// sampleRecord is one tick's health sample: every check it ran, and the
// ones that failed.
type sampleRecord struct {
	At    time.Time         `json:"at"`
	Keys  []string          `json:"keys"`
	Fails map[string]string `json:"fails,omitempty"`
}

// recordHealth keeps the machine's last keptSamples samples, so that a boot
// can give the guards it brings back one baseline from just before it.
func (a *Agent) recordHealth(checks []policy.Health, fails map[string]string) error {
	var recs []sampleRecord
	if b, err := os.ReadFile(filepath.Join(a.StateDir, healthFile)); err == nil {
		json.Unmarshal(b, &recs)
	}
	r := sampleRecord{At: a.now().UTC(), Fails: fails}
	for _, h := range checks {
		r.Keys = append(r.Keys, checkKey(h))
	}
	recs = append(recs, r)
	if len(recs) > keptSamples {
		recs = recs[len(recs)-keptSamples:]
	}
	b, err := json.Marshal(recs)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(a.StateDir, healthFile), b, 0o600)
}

// bootGroup is the window every guard a boot brought back shares: one
// baseline (the machine's last samples before the boot), one record of
// which checks are back, and one verdict.
type bootGroup struct {
	At time.Time `json:"at"`
	// Before counts, per check, the pre-boot samples it failed; a check with
	// 0 held, and counts. With no samples at all, every check counts.
	Before  map[string]int `json:"before"`
	Sampled bool           `json:"sampled"`
	// Windowed guards are on trial (pending, undo armed); Observed ones
	// (keep, strips) can't come off, and count as booted once every check
	// that held has passed since the boot.
	Windowed []string `json:"windowed,omitempty"`
	Observed []string `json:"observed,omitempty"`
	// Cut are windows after an earlier boot that this boot cut short;
	// CutShared says whether that group had more than one guard.
	Cut       []string `json:"cut,omitempty"`
	CutShared bool     `json:"cut_shared,omitempty"`
	// Shared is set when a keep went on during the window, or the window
	// holds more than one guard: a failure then counts no try.
	Shared bool `json:"shared,omitempty"`
	// Armed: the check has passed since the boot, or its grace ran out.
	// Passed: it has passed since the boot.
	Armed   map[string]bool   `json:"armed,omitempty"`
	Passed  map[string]bool   `json:"passed,omitempty"`
	Streak  map[string]int    `json:"streak,omitempty"`
	Why     map[string]string `json:"why,omitempty"`
	Settled time.Time         `json:"settled,omitzero"`
}

func (a *Agent) openBootGroup(windowed, observed, cut []string, cutShared bool) error {
	g := bootGroup{At: a.now().UTC(), Before: map[string]int{}, Windowed: windowed, Observed: observed, Cut: cut, CutShared: cutShared}
	var recs []sampleRecord
	if b, err := os.ReadFile(filepath.Join(a.StateDir, healthFile)); err == nil {
		json.Unmarshal(b, &recs)
	}
	// Samples count only if the newest was taken within freshSamples of the
	// boot; after a long time off, they say little about the machine now.
	fresh := len(recs) > 0 && a.now().Sub(recs[len(recs)-1].At) <= freshSamples
	if fresh {
		for _, r := range recs {
			g.Sampled = true
			for _, k := range r.Keys {
				g.Before[k] += 0
				if _, failed := r.Fails[k]; failed {
					g.Before[k]++
				}
			}
		}
		return a.saveBootGroup(&g)
	}
	// No fresh samples: a check counts only if it held in the baseline of
	// every windowed guard that has one.
	for _, h := range windowed {
		ev, err := a.loadEvidence(h)
		if err != nil || ev.Trial == nil {
			continue
		}
		g.Sampled = true
		for k, n := range ev.Trial.Before {
			if old, seen := g.Before[k]; !seen || old == 0 {
				g.Before[k] = n
			}
		}
	}
	return a.saveBootGroup(&g)
}

func (a *Agent) loadBootGroup() (*bootGroup, error) {
	b, err := os.ReadFile(filepath.Join(a.StateDir, bootGroupFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var g bootGroup
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func (a *Agent) saveBootGroup(g *bootGroup) error {
	b, err := json.Marshal(g)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(a.StateDir, bootGroupFile), b, 0o600)
}

func (a *Agent) closeBootGroup() error {
	err := os.Remove(filepath.Join(a.StateDir, bootGroupFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// watchBootGroup reads this tick's sample for the guards a boot brought
// back. It reports whether the group is still open, which holds any other
// change but a keep.
func (a *Agent) watchBootGroup(ctx context.Context, f *Fleet, checks []policy.Health, sample map[string]string, entries []*Entry, evs map[string]*Evidence, res *TickResult) (bool, error) {
	g, err := a.loadBootGroup()
	if g == nil || err != nil {
		return false, err
	}
	on := map[string]*Entry{}
	for _, e := range entries {
		on[e.Hash] = e
	}
	// A windowed guard no longer pending ended its window some other way:
	// the undo timer, a restart, a hand, or the owner's Off.
	var windowed []string
	for _, h := range g.Windowed {
		switch e := on[h]; {
		case e != nil && e.Status == Pending && e.BootWindow:
			windowed = append(windowed, h)
		case e != nil && e.Status == Confirmed && !e.Booted:
			g.Observed = append(g.Observed, h) // kept during the window: watched, not judged
		case e == nil && !containsHash(f.Off, h):
			if ev := evs[h]; ev != nil && !ev.Held {
				a.failWindow(h, ev, "its window after the boot ended without a verdict", res)
			}
		}
	}
	g.Windowed = windowed
	for _, h := range g.Cut {
		if ev := evs[h]; ev != nil && !ev.Held && !containsHash(f.Off, h) {
			why := "the machine restarted during its window after a boot"
			if g.CutShared {
				a.suspectWindow(h, ev, why, res)
			} else {
				a.failWindow(h, ev, why, res)
			}
		}
	}
	g.Cut = nil
	// Each map on its own: an empty one reads back from disk as nil.
	if g.Armed == nil {
		g.Armed = map[string]bool{}
	}
	if g.Passed == nil {
		g.Passed = map[string]bool{}
	}
	if g.Streak == nil {
		g.Streak = map[string]int{}
	}
	if g.Why == nil {
		g.Why = map[string]string{}
	}
	if g.Before == nil {
		g.Before = map[string]int{}
	}
	now := a.now()
	var bad []string
	settled, allPassed := true, true
	for _, h := range checks {
		k := checkKey(h)
		if n, sampled := g.Before[k]; g.Sampled && (!sampled || n > 0) {
			continue // didn't hold before the boot, or wasn't checked then
		}
		why, failing := sample[k]
		if !failing {
			g.Passed[k] = true
		}
		if !g.Passed[k] {
			allPassed = false
		}
		if !g.Armed[k] {
			if failing && now.Sub(g.At) < time.Duration(h.Grace())*time.Second {
				settled = false
				continue
			}
			g.Armed[k] = true
		}
		if failing {
			g.Streak[k]++
			g.Why[k] = why
		} else {
			delete(g.Streak, k)
			delete(g.Why, k)
		}
		if g.Streak[k] >= failRun {
			bad = append(bad, k+": "+g.Why[k])
		}
	}
	if settled && g.Settled.IsZero() {
		g.Settled = now
	}
	stamp := now.UTC().Format(time.RFC3339)
	// The observed guards (keep, strips) count as booted once every check
	// that held has passed since the boot, and only when no windowed guard
	// of this boot is still waiting for its verdict; nothing takes them off.
	if allPassed && len(g.Windowed) == 0 {
		for _, h := range g.Observed {
			if err := a.MarkBooted(ctx, h); err != nil {
				return true, err
			}
			if ev := evs[h]; ev != nil {
				ev.Tries, ev.Last = 0, "booted "+stamp
				a.saveEvidence(h, ev)
			}
		}
		g.Observed = nil
	}
	switch {
	case len(bad) > 0:
		sort.Strings(bad)
		why := fmt.Sprintf("the window after the boot failed, %d times in a row: %s", failRun, strings.Join(bad, "; "))
		shared := len(g.Windowed) > 1 || g.Shared
		for _, h := range g.Windowed {
			if _, err := a.Undo(ctx, h, false); err != nil {
				res.Refused = append(res.Refused, h[:12]+": taking it off: "+err.Error())
				continue
			}
			ev := evs[h]
			if ev == nil {
				continue
			}
			if shared {
				a.suspectWindow(h, ev, why+" (shared with another guard of the boot)", res)
			} else {
				ev.Suspect = false // alone: this one broke it
				a.failWindow(h, ev, why, res)
			}
		}
		return false, a.closeBootGroup()
	case !g.Settled.IsZero() && !now.Before(g.Settled.Add(TrialWindow)) && len(g.Streak) == 0:
		for _, h := range g.Windowed {
			if _, err := a.Confirm(ctx, h); err != nil {
				res.Refused = append(res.Refused, h[:12]+": confirming: "+err.Error())
				continue
			}
			if ev := evs[h]; ev != nil {
				ev.Tries, ev.Suspect, ev.Last = 0, false, "confirmed after a boot "+stamp
				a.saveEvidence(h, ev)
			}
			res.Confirmed = append(res.Confirmed, on[h].Guard.Name())
		}
		g.Windowed = nil
	}
	if len(g.Windowed) == 0 && (len(g.Observed) == 0 || now.Sub(g.At) > time.Duration(policy.MaxGraceSeconds)*time.Second+2*TrialWindow) {
		return false, a.closeBootGroup() // done; observed guards whose checks never came back stay unbooted
	}
	return len(g.Windowed) > 0, a.saveBootGroup(g)
}
