package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/admit"
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
	Messages []Message         `json:"messages,omitempty"`
	Guards   map[string][]byte `json:"guards,omitempty"`   // guard hash to canonical file
	Policies map[string][]byte `json:"policies,omitempty"` // policy hash to canonical file
	Signed   []approve.Signed  `json:"signed,omitempty"`
	// Wants are other machines' requests for this canary's Healthy.
	Wants []Want `json:"wants,omitempty"`
}

// Message is one owner statement: gnokey's signed transaction file and the
// sequence it was signed with.
type Message struct {
	Seq uint64          `json:"seq"`
	Tx  json.RawMessage `json:"tx"`
}

// Evidence is what the agent keeps for a guard: its canonical file, the
// owner's Yes if any, checked Ed25519 statements, and how its way onto this
// machine is going.
type Evidence struct {
	Guard []byte `json:"guard"`
	// Yeses holds the owner's newest Yes for each tier it names, so that a
	// Yes changes only its own tiers.
	Yeses  map[string]*approve.Yes `json:"yeses,omitempty"`
	Signed []approve.Signed        `json:"signed,omitempty"`
	// Released is when this machine first found the guard admitted here;
	// the tier's spacing counts from it.
	Released time.Time `json:"released,omitzero"`
	// Nonce is this host's fresh number for a canary's Healthy.
	Nonce string `json:"nonce,omitempty"`
	// Trial is the health record of the guard's way on.
	Trial *Trial `json:"trial,omitempty"`
	// Tries counts windows that failed here; RetryAt is when the next try
	// may start; Ask is set once the retries are spent, for the owner, and
	// cleared by the owner's next Yes. Last is the last verdict, in words.
	Tries   int       `json:"tries,omitempty"`
	RetryAt time.Time `json:"retry_at,omitzero"`
	Ask     bool      `json:"ask,omitempty"`
	Last    string    `json:"last,omitempty"`
	// Refused is why this machine refused the guard when it last tried,
	// and RefusedCode the listed reason behind it, if any, which is all a
	// canary may sign.
	Refused     string `json:"refused,omitempty"`
	RefusedCode string `json:"refused_code,omitempty"`
}

// yesFor returns the owner's newest Yes for a tier, if any.
func (ev *Evidence) yesFor(tier string) *approve.Yes {
	if ev == nil || ev.Yeses == nil {
		return nil
	}
	return ev.Yeses[tier]
}

// Trial is the health record of a guard's way onto this machine.
type Trial struct {
	// Before counts, for every check sampled, the baseline samples it
	// failed; Samples is how many were taken, the first at Since. A check
	// that failed any of them didn't hold, and the windows don't count it.
	Before  map[string]int `json:"before,omitempty"`
	Samples int            `json:"samples"`
	Since   time.Time      `json:"since,omitzero"`
	// Window is when the window being watched began: when the guard went
	// on, or the boot that armed its undo again. Zero between windows.
	Window time.Time `json:"window,omitzero"`
	// Streak counts each check's failed samples in a row in this window,
	// and Why holds the last failure's reason.
	Streak map[string]int    `json:"streak,omitempty"`
	Why    map[string]string `json:"why,omitempty"`
	// After a boot, a check counts only once it is Armed: it has passed
	// since the boot, or its grace has run out. Settled is when every check
	// that held was armed; the window's length runs from then.
	Armed   map[string]bool `json:"armed,omitempty"`
	Settled time.Time       `json:"settled,omitzero"`
}

const (
	// TrialWindow is how long a guard is watched after it goes on, and
	// again after its first boot if it bites later. After it, a failure
	// pages the owner and never takes the guard off.
	TrialWindow = 10 * time.Minute
	// trialArm is how long the undo is armed for a window: five minutes
	// more than the window, as a backstop for a tick that doesn't come.
	trialArm = TrialWindow + 5*time.Minute
	// The baseline is baselineSamples samples over at least baselineSpan,
	// taken again if it grows older than baselineStale.
	baselineSamples = 3
	baselineSpan    = 2 * time.Minute
	baselineStale   = 10 * time.Minute
	// failRun failed samples in a row of a check that held fail a window.
	failRun = 3
	// refusedRecheck is how long a guard this machine refused waits before
	// it is planned again; a refusal counts no try.
	refusedRecheck = 15 * time.Minute
)

// retries are the waits after a failed window: 15 minutes, 1 hour, 4 hours;
// after those, the agent asks the owner.
var retries = []time.Duration{15 * time.Minute, time.Hour, 4 * time.Hour}

// TickResult says what a tick did, for the log and the report.
type TickResult struct {
	Accepted  []string // owner statements taken, in order
	Refused   []string // statements and guards refused, and why
	Policy    string   // a policy change that took effect
	Off       []string // guards the owner took off this host; Tick undoes them
	Baseline  []string // a guard whose baseline is being taken
	Applied   []string // guards put on
	Confirmed []string // windows that held
	Undone    []string // windows that failed, and why
	Waiting   []string // admitted but for a canary's Healthy
	Drift     []string // live state put back, or guards taken off as unsafe now
	// Held says why the owner's statements stopped at a sequence: a later
	// one waits until every one before it has been taken.
	Held string
	// Health holds the checks failing now, from this tick's one sample.
	Health map[string]string
}

// Tick is what the minute timer runs: take in the spool, take off what the
// owner turned off, move the one change in flight a step, answer canary
// wants, and sign the report. Two ticks never run at once.
func (a *Agent) Tick(ctx context.Context) (*TickResult, error) {
	lock, err := lockFile(filepath.Join(a.StateDir, "tick.lock"))
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	// First what the minute check always did: put back what drifted.
	drift, cerr := a.Check(ctx, true)
	if _, err := a.loadFleet(); errors.Is(err, errNoFleet) {
		res := &TickResult{}
		addDrift(res, drift)
		return res, cerr // no policy: the agent only keeps what root put on
	}
	res, err := a.ProcessSpool(ctx)
	addDrift(res, drift)
	if cerr != nil {
		res.Refused = append(res.Refused, "check: "+cerr.Error())
	}
	if err != nil {
		return res, err
	}
	for _, h := range res.Off {
		if _, err := a.Undo(ctx, h, false); err != nil && !isNotOn(err) {
			res.Refused = append(res.Refused, "taking off "+h[:12]+": "+err.Error())
		}
	}
	f, err := a.loadFleet()
	if err != nil {
		return res, err
	}
	p, err := f.InstalledPolicy()
	if err != nil {
		return res, err
	}
	// One health sample a tick serves the baseline, every window, and the
	// report: after a confirm, a failure pages and never takes a guard off.
	sample := a.runChecks(ctx, checksFor(p, f.Host))
	res.Health = sample
	err = a.advance(ctx, f, p, sample, res)
	if werr := a.answerWants(ctx, f, p); werr != nil {
		res.Refused = append(res.Refused, "answering canaries' wants: "+werr.Error())
	}
	return res, errors.Join(err, a.writeReport(ctx, f, p, res))
}

func addDrift(res *TickResult, drift []Drift) {
	if res == nil {
		return
	}
	for _, d := range drift {
		line := d.Guard + ": " + d.What
		switch {
		case d.Err != nil:
			line += " (" + d.Err.Error() + ")"
		case d.TakenOff:
			line += " (taken off)"
		case d.Repaired:
			line += " (put back)"
		}
		res.Drift = append(res.Drift, line)
	}
}

// advance moves this machine's change in flight a step: it watches the
// guards in their windows, or takes the next admitted guard's baseline and
// puts it on. One change is in flight at a time, so a failure has one
// suspect; the guards a boot brought back share that boot as theirs.
func (a *Agent) advance(ctx context.Context, f *Fleet, p *policy.Policy, sample map[string]string, res *TickResult) error {
	entries, _, err := a.Status(ctx)
	if err != nil {
		return err
	}
	evs, err := a.allEvidence()
	if err != nil {
		return err
	}
	on := map[string]*Entry{}
	for _, e := range entries {
		on[e.Hash] = e
	}
	checks := checksFor(p, f.Host)
	// A window that ended without a verdict (the undo timer fired first,
	// the machine restarted, or a hand took the guard off) is a failure.
	for _, h := range sortedKeys(evs) {
		ev := evs[h]
		t := ev.Trial
		switch {
		case t == nil || t.Window.IsZero():
		case containsHash(f.Off, h) || (on[h] != nil && on[h].Status == Confirmed):
			t.closeWindow() // the owner's Off, or a confirm by hand or by keep
			a.saveEvidence(h, ev)
		case on[h] == nil:
			a.failWindow(h, ev, "its window ended without a verdict (the undo timer, a restart, or a hand took it off)", res)
		}
	}
	var watching []*Entry
	for _, e := range entries {
		switch {
		case e.Status == Applying:
			return nil // half on: undo or boot deals with it first
		case e.Status == Pending && e.By == "":
			return nil // put on by hand: root confirms it, or its timer takes it off
		case e.Status == Pending:
			watching = append(watching, e)
		}
	}
	if len(watching) > 0 {
		var bootFailed *Entry
		for _, e := range watching {
			ev := evs[e.Hash]
			if ev == nil {
				ev = &Evidence{}
				evs[e.Hash] = ev
			}
			if a.watch(ctx, e, ev, checks, sample, res) == verdictFailed && e.BootWindow {
				bootFailed = e
			}
		}
		if bootFailed != nil {
			// The guards that came back at one boot share it as their suspect.
			for _, e := range watching {
				if e == bootFailed || !e.BootWindow {
					continue
				}
				if _, err := a.Undo(ctx, e.Hash, false); err != nil {
					res.Refused = append(res.Refused, e.Guard.Name()+": taking it off: "+err.Error())
					continue
				}
				a.failWindow(e.Hash, evs[e.Hash], "it came back at the same boot as "+bootFailed.Guard.Name()+", whose window failed", res)
			}
		}
		return nil
	}
	a.next(ctx, f, p, entries, evs, checks, sample, res)
	return nil
}

// Verdicts of a window, as watch returns them.
const (
	verdictNone      = ""
	verdictConfirmed = "confirmed"
	verdictFailed    = "failed"
)

// closeWindow forgets a window's running counts and keeps the baseline,
// which a later window after a boot compares with again.
func (t *Trial) closeWindow() {
	t.Window, t.Streak, t.Why, t.Armed, t.Settled = time.Time{}, nil, nil, nil, time.Time{}
}

// watch reads this tick's health sample for a guard in its window. A check
// that held in the baseline and now fails failRun samples in a row takes the
// guard off; a window that runs its length from when it settled, with no
// check failing, confirms it. In a window after a boot, a check counts only
// once it is armed: it has passed since the boot, or its grace has run out.
func (a *Agent) watch(ctx context.Context, e *Entry, ev *Evidence, checks []policy.Health, sample map[string]string, res *TickResult) string {
	if ev.Trial == nil { // the evidence was lost: count every check as held
		ev.Trial = &Trial{Before: map[string]int{}}
		for _, h := range checks {
			ev.Trial.Before[checkKey(h)] = 0
		}
	}
	t := ev.Trial
	now := a.now()
	if !t.Window.Equal(e.AppliedAt) {
		t.closeWindow()
		t.Window = e.AppliedAt
	}
	if t.Streak == nil { // also how an empty one reads back from disk
		t.Streak, t.Why = map[string]int{}, map[string]string{}
	}
	if t.Armed == nil {
		t.Armed = map[string]bool{}
	}
	var bad []string
	settled := true
	for _, h := range checks {
		k := checkKey(h)
		if n, sampled := t.Before[k]; !sampled || n > 0 {
			continue // didn't hold in the baseline, or added since
		}
		why, failing := sample[k]
		if !t.Armed[k] {
			if e.BootWindow && failing && now.Sub(t.Window) < time.Duration(h.Grace())*time.Second {
				settled = false
				continue // not back since the boot, and still in its grace
			}
			t.Armed[k] = true
		}
		if failing {
			t.Streak[k]++
			t.Why[k] = why
		} else {
			delete(t.Streak, k)
			delete(t.Why, k)
		}
		if t.Streak[k] >= failRun {
			bad = append(bad, k+": "+t.Why[k])
		}
	}
	if settled && t.Settled.IsZero() {
		t.Settled = now
		if !e.BootWindow {
			t.Settled = t.Window // a window on a running machine runs from the apply
		}
	}
	stamp := now.UTC().Format(time.RFC3339)
	switch {
	case len(bad) > 0:
		sort.Strings(bad)
		if _, err := a.Undo(ctx, e.Hash, false); err != nil {
			res.Refused = append(res.Refused, e.Guard.Name()+": taking it off after its health failed: "+err.Error())
			a.saveEvidence(e.Hash, ev)
			return verdictNone
		}
		a.failWindow(e.Hash, ev, fmt.Sprintf("health failed %d times in a row: %s", failRun, strings.Join(bad, "; ")), res)
		return verdictFailed
	case !t.Settled.IsZero() && !now.Before(t.Settled.Add(TrialWindow)) && len(t.Streak) == 0:
		if _, err := a.Confirm(ctx, e.Hash); err != nil {
			res.Refused = append(res.Refused, e.Guard.Name()+": confirming: "+err.Error())
			a.saveEvidence(e.Hash, ev)
			return verdictNone
		}
		t.closeWindow()
		ev.Tries = 0 // a window that passes starts the count again
		ev.Last = "confirmed " + stamp
		if e.BootWindow {
			ev.Last = "confirmed after a boot " + stamp
		}
		a.saveEvidence(e.Hash, ev)
		res.Confirmed = append(res.Confirmed, e.Guard.Name())
		return verdictConfirmed
	}
	a.saveEvidence(e.Hash, ev)
	return verdictNone
}

// failWindow counts a failed window: the guard is off, and it is tried
// again after the next wait, with a fresh baseline, or the owner is asked.
func (a *Agent) failWindow(h string, ev *Evidence, why string, res *TickResult) {
	ev.Tries++
	ev.Trial = nil
	ev.Last = why + " (" + a.now().UTC().Format(time.RFC3339) + ")"
	if ev.Tries > len(retries) {
		ev.Ask = true
	} else {
		ev.RetryAt = a.now().Add(retries[ev.Tries-1])
	}
	a.saveEvidence(h, ev)
	name := h[:12]
	if g, err := guard.Parse(ev.Guard); err == nil {
		name = g.Name()
	}
	res.Undone = append(res.Undone, name+": "+why)
}

// next starts the next admitted guard on its way: the owner's keep first (a
// flaw under attack), then a guard whose baseline has begun, then by hash.
// It refuses guards this machine can't take as it is now, takes one health
// sample a tick until the baseline is complete, and then puts the guard on.
func (a *Agent) next(ctx context.Context, f *Fleet, p *policy.Policy, entries []*Entry, evs map[string]*Evidence, checks []policy.Health, sample map[string]string, res *TickResult) {
	tier, _ := p.TierOf(f.Host)
	tierName := ""
	if tier != nil {
		tierName = tier.Name
	}
	on, ids := map[string]bool{}, map[string]bool{}
	var modelGuards [][]string
	for _, e := range entries {
		on[e.Hash], ids[e.Guard.ID] = true, true
		if e.By == "model" {
			modelGuards = append(modelGuards, e.Guard.Flaws)
		}
	}
	listening, err := a.Sys.ListeningAll()
	if err != nil {
		res.Refused = append(res.Refused, "listening sockets: "+err.Error())
		return
	}
	type candidate struct {
		h    string
		ev   *Evidence
		g    *guard.Guard
		by   string
		keep bool
	}
	var cands []candidate
	for _, h := range sortedKeys(evs) {
		ev := evs[h]
		if on[h] || containsHash(f.Off, h) || ev.Guard == nil || ev.Ask || a.now().Before(ev.RetryAt) {
			continue
		}
		g, err := guard.Parse(ev.Guard)
		if err != nil || g.Hash() != h || ids[g.ID] {
			continue // ids: another version is on; replacing one comes later
		}
		if ev.Nonce == "" {
			ev.Nonce = randomHex(16)
			a.saveEvidence(h, ev)
		}
		yes := ev.yesFor(tierName)
		d := admit.Admit(p, f.Host, g, admit.Evidence{Yes: yes, Signed: admitSigned(ev.Signed)},
			admit.Machine{Listening: listening, ModelGuards: modelGuards}, ev.Nonce, a.now())
		if !d.OK {
			if d.Wait {
				res.Waiting = append(res.Waiting, g.Name())
			}
			if ev.Trial != nil {
				ev.Trial = nil // no longer admitted: its baseline starts again
				a.saveEvidence(h, ev)
			}
			continue
		}
		// The tier's spacing: after this machine first finds the guard
		// admitted, it waits the spacing times its place among the tier's
		// machines that aren't canaries, so the tier doesn't fail, or
		// retry, all at once.
		if ev.Released.IsZero() {
			ev.Released = a.now()
			a.saveEvidence(h, ev)
		}
		if wait := spacing(tier, f.Host); a.now().Before(ev.Released.Add(wait)) {
			res.Waiting = append(res.Waiting, g.Name()+" (the tier's spacing)")
			continue
		}
		keep := d.By == "me" && yes != nil && yes.Mode == "keep"
		cands = append(cands, candidate{h, ev, g, d.By, keep})
	}
	rank := func(c candidate) int {
		switch {
		case c.keep:
			return 0
		case c.ev.Trial != nil && c.ev.Trial.Samples > 0:
			return 1
		}
		return 2
	}
	sort.SliceStable(cands, func(i, j int) bool { return rank(cands[i]) < rank(cands[j]) })
	for _, c := range cands {
		pl, err := a.Plan(c.g)
		if err != nil {
			res.Refused = append(res.Refused, c.g.Name()+": "+err.Error())
			continue
		}
		if r := refusal(c.g, pl, false); r != nil {
			a.refuse(c.h, c.ev, r, res)
			continue
		}
		if !c.keep && len(checks) > 0 {
			t := c.ev.Trial
			if t == nil || a.now().Sub(t.Since) > baselineStale {
				t = &Trial{Before: map[string]int{}}
				c.ev.Trial = t
			}
			if !a.baselined(t) {
				a.addSample(t, checks, sample)
				if !a.baselined(t) {
					a.saveEvidence(c.h, c.ev)
					res.Baseline = append(res.Baseline, c.g.Name())
					return // one change in flight: this guard's baseline
				}
			}
		}
		e, err := a.Apply(ctx, c.g, ApplyOptions{ConfirmWithin: trialArm, By: c.by, Keep: c.keep})
		var r *Refusal
		if errors.As(err, &r) { // the machine changed since the plan
			a.refuse(c.h, c.ev, r, res)
			continue
		}
		if err != nil {
			a.failWindow(c.h, c.ev, "putting it on failed: "+err.Error(), res)
			return
		}
		c.ev.Refused, c.ev.RefusedCode = "", ""
		if !c.keep {
			// The window is open from now, so that one ended by anything but
			// a verdict is seen as a failure, even before its first sample.
			if c.ev.Trial == nil {
				c.ev.Trial = &Trial{Before: map[string]int{}}
			}
			c.ev.Trial.Window = e.AppliedAt
		}
		if c.keep {
			c.ev.Trial = nil
			c.ev.Last = "on, kept, " + a.now().UTC().Format(time.RFC3339)
			// A baseline begun for another guard saw the machine without this one.
			for _, o := range cands {
				if o.h != c.h && o.ev.Trial != nil {
					o.ev.Trial = nil
					a.saveEvidence(o.h, o.ev)
				}
			}
		}
		a.saveEvidence(c.h, c.ev)
		res.Applied = append(res.Applied, c.g.Name())
		return // one change per tick
	}
}

// Hold keeps a guard off until the owner's next Yes for this host: what a
// hand that takes off a guard the agent put on is asking for.
func (a *Agent) Hold(hash, why string) error {
	ev, err := a.loadEvidence(hash)
	if errors.Is(err, os.ErrNotExist) {
		return nil // not a guard the agent put on
	}
	if err != nil {
		return err
	}
	ev.Ask, ev.Trial = true, nil
	ev.Last = why + " (" + a.now().UTC().Format(time.RFC3339) + ")"
	return a.saveEvidence(hash, ev)
}

// baselined reports whether a baseline is complete.
func (a *Agent) baselined(t *Trial) bool {
	return t.Samples >= baselineSamples && a.now().Sub(t.Since) >= baselineSpan
}

// spacing is how long a machine waits after first finding a guard admitted:
// the tier's spacing times its place among the tier's machines that aren't
// canaries. Canaries go first and don't wait.
func spacing(tier *policy.Tier, host string) time.Duration {
	if tier == nil || tier.SpacingSeconds <= 0 || contains(tier.Canaries, host) {
		return 0
	}
	place := 0
	for _, h := range tier.Hosts {
		if h == host {
			break
		}
		if !contains(tier.Canaries, h) {
			place++
		}
	}
	return time.Duration(place*tier.SpacingSeconds) * time.Second
}

// addSample adds this tick's health sample to a baseline.
func (a *Agent) addSample(t *Trial, checks []policy.Health, fails map[string]string) {
	if t.Samples == 0 {
		t.Since = a.now()
	}
	if t.Before == nil {
		t.Before = map[string]int{}
	}
	for _, h := range checks {
		k := checkKey(h)
		t.Before[k] += 0 // sampled, even when it passed
		if _, failing := fails[k]; failing {
			t.Before[k]++
		}
	}
	t.Samples++
}

// refuse records that this machine refused a guard as it is now. It counts
// no try; the guard is planned again after refusedRecheck.
func (a *Agent) refuse(h string, ev *Evidence, r *Refusal, res *TickResult) {
	ev.Refused, ev.RefusedCode = r.Error(), r.Code
	ev.RetryAt = a.now().Add(refusedRecheck)
	ev.Trial = nil
	a.saveEvidence(h, ev)
	res.Refused = append(res.Refused, r.Error())
}

// allEvidence reads every guard's evidence, by hash.
func (a *Agent) allEvidence() (map[string]*Evidence, error) {
	files, err := filepath.Glob(filepath.Join(a.StateDir, "evidence", "*.json"))
	if err != nil {
		return nil, err
	}
	out := map[string]*Evidence{}
	for _, file := range files {
		h := strings.TrimSuffix(filepath.Base(file), ".json")
		if !isHex64(h) {
			continue
		}
		ev, err := a.loadEvidence(h)
		if err != nil {
			return nil, fmt.Errorf("evidence %s: %w", h[:12], err)
		}
		out[h] = ev
	}
	return out, nil
}

func sortedKeys(m map[string]*Evidence) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func containsHash(xs []string, h string) bool {
	for _, x := range xs {
		if x == h {
			return true
		}
	}
	return false
}

func removeHash(xs []string, h string) []string {
	out := xs[:0]
	for _, x := range xs {
		if x != h {
			out = append(out, x)
		}
	}
	return out
}

func admitSigned(ss []approve.Signed) []admit.Signed {
	out := make([]admit.Signed, 0, len(ss))
	for _, s := range ss {
		out = append(out, admit.Signed{Statement: s.Statement, Key: s.Key})
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// isNotOn reports Undo's error for a guard that isn't on: nothing to do.
func isNotOn(err error) bool { return strings.Contains(err.Error(), "is on") }

// ProcessSpool reads every bundle in the spool, oldest first, applies what
// verifies, and removes the bundles. Owner statements must arrive in
// sequence order; a statement at or below the last accepted is stale and
// skipped, and one more than MaxSeqJump above is refused.
//
// It runs under the tick lock (Tick takes it, and so does Init), not the
// state lock, which the statements it applies take for themselves.
func (a *Agent) ProcessSpool(ctx context.Context) (*TickResult, error) {
	f, err := a.loadFleet()
	if err != nil {
		return nil, err
	}
	res := &TickResult{}
	dir := filepath.Join(a.StateDir, spoolDir)
	names, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	sort.Strings(names) // intake names files by time
	for _, name := range names {
		// The spool is the unprivileged half's: read each entry as an
		// untrusted file, never through a link, at most MaxBundle bytes.
		b, err := readSpoolFile(name)
		var bun Bundle
		switch {
		case err != nil:
			res.Refused = append(res.Refused, filepath.Base(name)+": "+err.Error())
		case json.Unmarshal(b, &bun) != nil:
			res.Refused = append(res.Refused, filepath.Base(name)+": not a bundle")
		default:
			a.applyBundle(ctx, f, &bun, res)
			if err := a.keepWants(bun.Wants); err != nil {
				res.Refused = append(res.Refused, "wants: "+err.Error())
			}
		}
		if err := a.saveFleet(f); err != nil {
			return res, err
		}
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			res.Refused = append(res.Refused, filepath.Base(name)+": can't remove it: "+err.Error())
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

func (a *Agent) applyBundle(ctx context.Context, f *Fleet, bun *Bundle, res *TickResult) {
	p, _ := f.InstalledPolicy()
	owner, _ := hex.DecodeString(p.Signers.Me.Hex)
	chain := approve.ChainID(owner, p.Fleet)
	msgs := append([]Message(nil), bun.Messages...)
	sort.Slice(msgs, func(i, j int) bool { return msgs[i].Seq < msgs[j].Seq })
	// The owner's statements act in the order signed: only the next number
	// is taken, and one that can't be taken holds every one after it, so no
	// statement can be skipped by delivering a later one first. Any lookout
	// can deliver the missing one; the report shows where they stopped.
	for _, m := range msgs {
		if m.Seq <= f.LastSeq {
			continue // already taken, or replayed
		}
		if m.Seq != f.LastSeq+1 {
			res.Held = fmt.Sprintf("waiting for statement %d before %d", f.LastSeq+1, m.Seq)
			break
		}
		what, err := a.ownerMessage(ctx, f, p, bun, chain, owner, m, res)
		if err != nil {
			res.Held = fmt.Sprintf("held at statement %d: %v", m.Seq, err)
			res.Refused = append(res.Refused, fmt.Sprintf("owner statement %d: %v", m.Seq, err))
			break
		}
		f.LastSeq = m.Seq
		res.Accepted = append(res.Accepted, what)
	}
	for _, sg := range bun.Signed {
		if err := a.keepSigned(p, sg, bun.Guards[sg.Statement.Guard]); err != nil {
			res.Refused = append(res.Refused, "statement: "+err.Error())
		}
	}
}

// guardFile finds the guard a statement names: in the bundle, or else in
// what this agent already holds, so a statement isn't held for a file the
// agent has.
func (a *Agent) guardFile(bun *Bundle, hash string) ([]byte, error) {
	if b := bun.Guards[hash]; b != nil {
		return b, nil
	}
	if ev, err := a.loadEvidence(hash); err == nil && ev.Guard != nil {
		return ev.Guard, nil
	}
	if entries, _, err := a.Status(context.Background()); err == nil {
		for _, e := range entries {
			if e.Hash == hash {
				return e.Guard.Canonical(), nil
			}
		}
	}
	return nil, errors.New("no file for guard " + hash[:min(16, len(hash))])
}

func (a *Agent) ownerMessage(ctx context.Context, f *Fleet, p *policy.Policy, bun *Bundle, chain string, owner []byte, m Message, res *TickResult) (string, error) {
	var tx approve.GnokeyTx
	if err := json.Unmarshal(m.Tx, &tx); err != nil || len(tx.Msg) != 1 {
		return "", errors.New("not one message")
	}
	args := tx.Msg[0].Args
	tier, _ := p.TierOf(f.Host)
	switch fn := tx.Msg[0].Func; fn {
	case "Yes", "Off", "On":
		if len(args) < 1 {
			return "", errors.New("no guard named")
		}
		file, err := a.guardFile(bun, args[0])
		if err != nil {
			return "", err
		}
		g, err := guard.Parse(file)
		if err != nil {
			return "", fmt.Errorf("the guard it names: %w", err)
		}
		h := g.Hash()
		ev, _ := a.loadEvidence(h)
		switch fn {
		case "Off":
			o, err := approve.VerifyOff(m.Tx, chain, m.Seq, owner, g)
			if err != nil {
				return "", err
			}
			if !o.Names(f.Host) {
				return "Off " + g.Name() + " for other hosts", nil
			}
			if !containsHash(f.Off, h) {
				f.Off = append(f.Off, h)
			}
			res.Off = append(res.Off, h)
			return "Off " + g.Name(), nil
		case "On":
			o, err := approve.VerifyOn(m.Tx, chain, m.Seq, owner, g)
			if err != nil {
				return "", err
			}
			if !o.Names(f.Host) {
				return "On " + g.Name() + " for other hosts", nil
			}
			// Back where the owner took it off, or held it after a hand
			// took it off or its retries ran out: admission decides again.
			f.Off = removeHash(f.Off, h)
			if ev.Guard == nil {
				ev.Guard = g.Canonical()
			}
			ev.Tries, ev.Ask, ev.RetryAt = 0, false, time.Time{}
			return "On " + g.Name(), a.saveEvidence(h, ev)
		}
		y, err := approve.VerifyYes(m.Tx, chain, m.Seq, owner, g)
		if err != nil {
			return "", err
		}
		ev.Guard = g.Canonical()
		if ev.Yeses == nil {
			ev.Yeses = map[string]*approve.Yes{}
		}
		for _, t := range y.Tiers {
			yy := y
			ev.Yeses[t] = &yy // the newest Yes for each tier it names
		}
		what := "Yes " + g.Name()
		if tier != nil && contains(y.Tiers, tier.Name) {
			// The owner's fresh word for this machine's tier: the retries
			// start again. It never lifts an Off; only On does.
			ev.Tries, ev.Ask, ev.RetryAt = 0, false, time.Time{}
			if y.Mode == "keep" {
				if kept, err := a.SetKeep(ctx, h); err != nil {
					return "", err
				} else if kept {
					what += " (keep: confirmed now)"
				}
			}
		}
		return what, a.saveEvidence(h, ev)
	case "Policy":
		if len(args) != 2 {
			return "", errors.New("Policy takes two hashes")
		}
		next, err := policy.Parse(bun.Policies[args[0]])
		if err != nil {
			return "", fmt.Errorf("the policy it names: %w", err)
		}
		// A step replaces the policy in force, or chains onto the one
		// pending; its memo is the diff against the one it replaces.
		old := p
		if f.Pending != nil && args[1] != p.Hash() {
			pend, err := policy.Parse(f.Pending.Policy)
			if err != nil {
				return "", err
			}
			if pend.Signers.Me.Hex != p.Signers.Me.Hex || pend.Fleet != p.Fleet {
				return "", errors.New("the pending step changes the owner's key or the fleet; it must take effect before the next step")
			}
			old = pend
		}
		if err := approve.VerifyPolicy(m.Tx, chain, m.Seq, owner, old, next); err != nil {
			return "", err
		}
		f.Pending = &PendingPolicy{Policy: next.Canonical(), FirstSeen: a.now().UTC()}
		return "Policy " + next.Hash()[:16] + " pending", nil
	}
	return "", fmt.Errorf("function %q isn't one this agent acts on yet", tx.Msg[0].Func)
}

// keepSigned checks an Ed25519 statement and keeps it with its guard's
// evidence if the policy gives its key the role that may sign its kind,
// with the guard's file if the bundle carries it and it is that guard.
func (a *Agent) keepSigned(p *policy.Policy, sg approve.Signed, file []byte) error {
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
	if k := sg.Statement.Kind; k != approve.KindTested {
		owner, _ := hex.DecodeString(p.Signers.Me.Hex)
		if sg.Statement.Chain != approve.ChainID(owner, p.Fleet) {
			return fmt.Errorf("%s for another fleet (%s)", k, sg.Statement.Chain)
		}
	}
	ev, _ := a.loadEvidence(sg.Statement.Guard)
	if ev.Guard == nil && file != nil {
		if g, err := guard.Parse(file); err == nil && g.Hash() == sg.Statement.Guard {
			ev.Guard = g.Canonical()
		}
	}
	for _, have := range ev.Signed {
		if have == sg {
			return a.saveEvidence(sg.Statement.Guard, ev)
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
