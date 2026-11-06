package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gnosecurity/repairer/admit"
	"github.com/gnosecurity/repairer/approve"
	"github.com/gnosecurity/repairer/check"
	"github.com/gnosecurity/repairer/guard"
	"github.com/gnosecurity/repairer/policy"
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
	Checks   map[string][]byte `json:"checks,omitempty"`   // was-I-hit check hash to canonical file
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
	// cleared by the owner's next Yes for this tier, or On. Last is the last
	// verdict, in words.
	Tries   int       `json:"tries,omitempty"`
	RetryAt time.Time `json:"retry_at,omitzero"`
	Ask     bool      `json:"ask,omitempty"`
	Last    string    `json:"last,omitempty"`
	// Suspect is set when the guard came off with others in a window they
	// shared (a boot's, or one a keep joined): no try is counted, and after
	// a boot's, such guards come back one per boot, so the next boot judges
	// each alone. The owner's On, or Yes for this tier, clears it.
	Suspect bool `json:"suspect,omitempty"`
	// Held is set when root took the guard off by hand: it stays off until
	// the owner's On names this host. A Yes doesn't lift it.
	Held bool `json:"held,omitempty"`
	// Refused is why this machine refused the guard when it last tried,
	// and RefusedCode the listed reason behind it, if any, which is all a
	// canary may sign.
	Refused     string `json:"refused,omitempty"`
	RefusedCode string `json:"refused_code,omitempty"`
	// Broke holds what a window or a boot this guard was part of broke: the
	// checks that had held and then failed. Such a check counts in the
	// guard's later windows even when their baseline has it failing (a unit
	// can stay failed after the guard comes off), and while it fails the
	// guard is never confirmed, booted or answered for (round 8, new major
	// 1). A record made in a shared window counts only at the guard's solo
	// boot, where it is judged alone; and when a recorded check is failing
	// with the guard off, the guard waits for the owner at once instead of
	// retrying (round 9, new major 4). A record from a window clears at a
	// confirm with the check passing; one from a boot, only at a boot the
	// check came back through and held.
	Broke map[string]Broken `json:"broke,omitempty"`
}

// Broken is one check a guard's window or boot broke. Shared says the
// window had other suspects.
type Broken struct {
	Why    string    `json:"why"`
	At     time.Time `json:"at"`
	AtBoot bool      `json:"at_boot,omitempty"`
	Shared bool      `json:"shared,omitempty"`
}

// counts says whether a record counts in a window: always if the guard
// earned it alone; one from a shared window, only when this window is the
// guard's alone (its solo boot).
func (b Broken) counts(solo bool) bool { return !b.Shared || solo }

// noteBroke records checks (key to why) a window or a boot broke.
func (ev *Evidence) noteBroke(broke map[string]string, at time.Time, atBoot, shared bool) {
	if len(broke) == 0 {
		return
	}
	if ev.Broke == nil {
		ev.Broke = map[string]Broken{}
	}
	for k, why := range broke {
		// What a boot broke stays a boot's: a later window failing on the
		// same check doesn't let it clear before a boot shows it back.
		old, had := ev.Broke[k]
		ev.Broke[k] = Broken{Why: why, At: at.UTC(), AtBoot: atBoot || old.AtBoot, Shared: shared && (!had || old.Shared)}
	}
}

// brokeFailing lists the checks recorded against the guard that fail in a
// sample.
func (ev *Evidence) brokeFailing(sample map[string]string) []string {
	var out []string
	for k := range ev.Broke {
		if _, failing := sample[k]; failing {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
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
	// Shared is set when a keep went on during the window: a failure then
	// has two suspects, and counts no try.
	Shared bool `json:"shared,omitempty"`
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
	// Reboot says where a reboot into a newer kernel stands (B3).
	Reboot string `json:",omitempty"`
	// Hits names the was-I-hit checks run this tick (W1); their results
	// are in the report.
	Hits []string `json:",omitempty"`
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
	f, err := a.loadFleet()
	if err != nil {
		return res, err
	}
	p, err := f.InstalledPolicy()
	if err != nil {
		return res, err
	}
	res.Held = f.Held
	// Every tick takes off whatever is on and on this host's Off list, so a
	// tick that died halfway can't leave one on.
	if entries, _, err := a.Status(ctx); err == nil {
		for _, e := range entries {
			if containsHash(f.Off, e.Hash) {
				if _, err := a.Undo(ctx, e.Hash, false); err != nil && !isNotOn(err) {
					res.Refused = append(res.Refused, "taking off "+e.Guard.Name()+": "+err.Error())
				}
			}
		}
	}
	a.followKeep(ctx, f, p, res)
	// One health sample a tick serves the baseline, every window, and the
	// report: after a confirm, a failure pages and never takes a guard off.
	sample := a.runChecks(ctx, checksFor(p, f.Host))
	res.Health = sample
	if err := a.recordHealth(checksFor(p, f.Host), sample); err != nil {
		res.Refused = append(res.Refused, "keeping the health samples: "+err.Error())
	}
	err = a.advance(ctx, f, p, sample, res)
	if werr := a.answerWants(ctx, f, p, sample); werr != nil {
		res.Refused = append(res.Refused, "answering canaries' wants: "+werr.Error())
	}
	rb, reboot, rerr := a.rebootStep(ctx, f, p, sample)
	res.Reboot = rb
	if rerr != nil {
		res.Refused = append(res.Refused, "reboot: "+rerr.Error())
	}
	// One queued Check a tick, after the guards' step; none before a reboot.
	if !reboot {
		if name, err := a.runQueued(ctx, f); err != nil {
			res.Refused = append(res.Refused, "a check: "+err.Error())
		} else if name != "" {
			res.Hits = append(res.Hits, name)
		}
	}
	werr := a.writeReport(ctx, f, p, res)
	if reboot {
		// Last, once the report and the fleet file are written; the reboot's
		// own record is already on disk, so a failed report doesn't stop it.
		err = errors.Join(err, a.rebootNow(ctx))
	}
	return res, errors.Join(err, werr)
}

// followKeep makes each guard's keep follow the owner's newest Yes for this
// machine's tier while that Yes is in force: a keep confirms a guard in its
// window and spares it the boot window; an undo gives the window back. A
// keep that couldn't be set is tried again next tick.
func (a *Agent) followKeep(ctx context.Context, f *Fleet, p *policy.Policy, res *TickResult) {
	tier, ok := p.TierOf(f.Host)
	if !ok {
		return
	}
	entries, _, err := a.Status(ctx)
	if err != nil {
		return
	}
	for _, e := range entries {
		ev, err := a.loadEvidence(e.Hash)
		if err != nil {
			continue
		}
		y := ev.yesFor(tier.Name)
		want := y != nil && y.Mode == "keep" && a.now().Before(y.Until)
		if y == nil || e.Keep == want {
			continue // no Yes of the owner's for this tier: keep stays as admission set it
		}
		if _, err := a.SetKeep(ctx, e.Hash, want); err != nil {
			res.Refused = append(res.Refused, e.Guard.Name()+": setting its keep: "+err.Error())
		}
	}
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
			why := "its window ended without a verdict (the undo timer, a restart, or a hand took it off)"
			if t.Shared {
				a.suspectWindow(h, ev, why+" (a keep went on during its window)", res) // round 8, minor 6
			} else {
				a.failWindow(h, ev, why, res)
			}
		}
	}
	// The guards a boot brought back share one window (bootgroup.go).
	busy, err := a.watchBootGroup(ctx, f, checks, sample, entries, evs, res)
	if err != nil {
		res.Refused = append(res.Refused, "the window after the boot: "+err.Error())
	}
	for _, e := range entries {
		switch {
		case e.Status == Applying:
			return nil // half on: undo or boot deals with it first
		case e.Status == Pending && e.By == "":
			return nil // put on by hand: root confirms it, or its timer takes it off
		case e.Status == Pending && e.BootWindow:
			busy = true // the boot group's
		case e.Status == Pending:
			ev := evs[e.Hash]
			if ev == nil {
				ev = &Evidence{}
				evs[e.Hash] = ev
			}
			a.watch(ctx, e, ev, checks, sample, res)
			busy = true
		}
	}
	// A reboot under way, or in its health window, is a change in flight
	// too: no guard's trial starts then (round 14, minor 3).
	if st, err := a.loadReboot(); err == nil && (st.Phase == Rebooting || st.Phase == Booted) {
		busy = true
	}
	// One change in flight at a time, but a keep goes on even while a
	// window is open: a keep guard is never blamed.
	a.next(ctx, f, p, entries, evs, checks, sample, busy, res)
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
	broke := map[string]string{}
	settled := true
	for _, h := range checks {
		k := checkKey(h)
		b, recorded := ev.Broke[k]
		recorded = recorded && b.counts(false) // a running window is never a solo boot
		if n, sampled := t.Before[k]; !recorded && (!sampled || n > 0) {
			continue // didn't hold in the baseline, or added since, and this guard never broke it
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
			broke[k] = t.Why[k]
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
		ev.noteBroke(broke, now, e.BootWindow, t.Shared)
		why := fmt.Sprintf("health failed %d times in a row: %s", failRun, strings.Join(bad, "; "))
		if t.Shared {
			a.suspectWindow(e.Hash, ev, why+" (a keep went on during its window)", res)
		} else {
			a.failWindow(e.Hash, ev, why, res)
		}
		return verdictFailed
	case !t.Settled.IsZero() && !now.Before(t.Settled.Add(TrialWindow)) && len(t.Streak) == 0:
		if _, err := a.Confirm(ctx, e.Hash); err != nil {
			res.Refused = append(res.Refused, e.Guard.Name()+": confirming: "+err.Error())
			a.saveEvidence(e.Hash, ev)
			return verdictNone
		}
		t.closeWindow()
		for k, b := range ev.Broke {
			if _, failing := sample[k]; !failing && !b.AtBoot {
				delete(ev.Broke, k) // passed through a whole window with the guard on
			}
		}
		if !e.Later || e.Keep {
			ev.Tries = 0 // fully on: the count starts again (a later guard's, at its boot)
		}
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

// suspectWindow is a failed window the guard shared with another change:
// it is off and tried again after the first wait, but no try is counted,
// since it may not be the one that broke something.
func (a *Agent) suspectWindow(h string, ev *Evidence, why string, res *TickResult) {
	ev.Suspect, ev.Trial = true, nil
	ev.Last = why + " (" + a.now().UTC().Format(time.RFC3339) + ")"
	ev.RetryAt = a.now().Add(retries[0])
	a.saveEvidence(h, ev)
	name := h[:12]
	if g, err := guard.Parse(ev.Guard); err == nil {
		name = g.Name()
	}
	res.Undone = append(res.Undone, name+": "+why+"; no try counted")
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
func (a *Agent) next(ctx context.Context, f *Fleet, p *policy.Policy, entries []*Entry, evs map[string]*Evidence, checks []policy.Health, sample map[string]string, keepOnly bool, res *TickResult) {
	tier, _ := p.TierOf(f.Host)
	tierName := ""
	if tier != nil {
		tierName = tier.Name
	}
	on, ids := map[string]bool{}, map[string]bool{}
	var modelGuards [][]string
	// The boot slot: after a shared window after a boot failed, its guards
	// come back one per boot. A suspect that bites at a boot goes on only
	// when no other unbooted guard that bites at a boot is on, and while
	// one is on, no other such guard goes on. Only guards a boot opens a
	// window for count: one root put on by hand never boots here, and would
	// hold the slot for good (round 8, new major 4).
	unbooted, suspectUnbooted := 0, false
	for _, e := range entries {
		on[e.Hash], ids[e.Guard.ID] = true, true
		if e.By == "model" {
			modelGuards = append(modelGuards, e.Guard.Flaws)
		}
		if e.Later && !e.Booted && !e.Keep && e.By != "" && e.Guard.BitesAtBoot() {
			unbooted++
			if ev := evs[e.Hash]; ev != nil && ev.Suspect {
				suspectUnbooted = true
			}
		}
	}
	listening, err := a.Sys.ListeningAll()
	if err != nil {
		res.Refused = append(res.Refused, "listening sockets: "+err.Error())
		return
	}
	info, err := a.Sys.Info()
	if err != nil {
		res.Refused = append(res.Refused, "the system: "+err.Error())
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
		if on[h] || containsHash(f.Off, h) || ev.Guard == nil || ev.Ask || ev.Held || a.now().Before(ev.RetryAt) {
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
			admit.Machine{Listening: listening, ModelGuards: modelGuards, OS: info.OS, Release: info.Release}, ev.Nonce, a.now())
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
		keep := d.By == "me" && yes != nil && yes.Mode == "keep"
		if keepOnly && !keep {
			continue
		}
		// A check this guard broke before is failing with it off too: a unit
		// stuck failed, or a flood. Retrying would only reach the ask later;
		// the owner hears now (round 9, new major 4).
		if failing := ev.brokeFailing(sample); !keep && len(failing) > 0 {
			ev.Ask, ev.Trial = true, nil
			ev.Last = "waiting for you: " + strings.Join(failing, ", ") + ", which it broke before, is failing with it off too (a unit stuck failed, or a flood); " +
				"put it back with your Yes (keep, or nocanary) or On once you've looked (" + a.now().UTC().Format(time.RFC3339) + ")"
			a.saveEvidence(h, ev)
			res.Waiting = append(res.Waiting, g.Name()+" ("+ev.Last+")")
			continue
		}
		if !keep && g.Later() && g.BitesAtBoot() && ((ev.Suspect && unbooted > 0) || suspectUnbooted) {
			res.Waiting = append(res.Waiting, g.Name()+" (one guard per boot after a shared window failed)")
			continue
		}
		// The tier's spacing, only after a canary's Healthy released the
		// guard (never for keep or "no canary"): this machine waits the
		// spacing times its place among the tier's machines that aren't
		// canaries, so the tier doesn't fail, or retry, all at once.
		viaCanary := tier != nil && len(tier.Canaries) > 0 && !contains(tier.Canaries, f.Host) && !(d.By == "me" && yes != nil && yes.NoCanary)
		if viaCanary && !keep {
			if ev.Released.IsZero() {
				ev.Released = a.now()
				a.saveEvidence(h, ev)
			}
			if wait := spacing(tier, f.Host); a.now().Before(ev.Released.Add(wait)) {
				res.Waiting = append(res.Waiting, g.Name()+" (the tier's spacing)")
				continue
			}
		}
		cands = append(cands, candidate{h, ev, g, d.By, keep})
	}
	// Guards that aren't suspects go ahead of suspects, so a new guard
	// waits at most one boot behind them (round 8, minor 5).
	rank := func(c candidate) int {
		switch {
		case c.keep:
			return 0
		case c.ev.Trial != nil && c.ev.Trial.Samples > 0:
			return 1
		case !c.ev.Suspect:
			return 2
		}
		return 3
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
		if c.keep && keepOnly {
			a.shareOpenWindows(entries, evs)
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

// Hold keeps a guard off until the owner's On names this host (a Yes
// doesn't lift it): what a hand that takes off a guard the agent put on is
// asking for.
func (a *Agent) Hold(hash, why string) error {
	ev, err := a.loadEvidence(hash)
	if errors.Is(err, os.ErrNotExist) {
		return nil // not a guard the agent put on
	}
	if err != nil {
		return err
	}
	ev.Held, ev.Trial = true, nil
	ev.Last = why + " (" + a.now().UTC().Format(time.RFC3339) + ")"
	return a.saveEvidence(hash, ev)
}

// shareOpenWindows marks every open window shared, because a keep went on
// during it: if one of them fails, no try is counted.
func (a *Agent) shareOpenWindows(entries []*Entry, evs map[string]*Evidence) {
	for _, e := range entries {
		if e.Status != Pending || e.BootWindow {
			continue
		}
		if ev := evs[e.Hash]; ev != nil && ev.Trial != nil {
			ev.Trial.Shared = true
			a.saveEvidence(e.Hash, ev)
		}
	}
	if g, err := a.loadBootGroup(); err == nil && g != nil {
		g.Shared = true
		a.saveBootGroup(g)
	}
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

func sortedKeys[V any](m map[string]V) []string {
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
// verifies, and removes the bundles. Owner statements are taken strictly in
// sequence order (applyBundle says how a statement holds the rest).
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
	// The owner's statements act in the order signed, and none can be
	// skipped by delivering a later one first. A statement whose signature
	// checks out is always taken: acted on if this agent can, else listed as
	// skipped, with why. Only one that doesn't check out yet (its file
	// isn't here, or it isn't signed by the key in force) holds the rest;
	// the hold stays in every report until it clears.
	for _, m := range msgs {
		if m.Seq <= f.LastSeq {
			continue // already taken, or replayed
		}
		if m.Seq != f.LastSeq+1 {
			// Only a later statement whose signature checks out says one is
			// missing; a forged one can't plant a false wait in the reports.
			var tx approve.GnokeyTx
			if json.Unmarshal(m.Tx, &tx) == nil {
				if _, err := approve.VerifyGnokey(m.Tx, chain, m.Seq, owner, tx.Memo); err == nil {
					f.Held = fmt.Sprintf("waiting for statement %d (have up to %d, and %d is here)", f.LastSeq+1, f.LastSeq, m.Seq)
				}
			}
			break
		}
		what, skip, hold := a.ownerMessage(ctx, f, p, bun, chain, owner, m, res)
		if hold != nil {
			f.Held = fmt.Sprintf("held at statement %d: %v", m.Seq, hold)
			break
		}
		f.LastSeq, f.Held = m.Seq, ""
		if skip != "" {
			f.Skipped = append(f.Skipped, Skipped{Seq: m.Seq, What: what, Why: skip})
			if len(f.Skipped) > maxSkipped {
				f.Skipped = f.Skipped[len(f.Skipped)-maxSkipped:]
			}
			res.Accepted = append(res.Accepted, what+" (skipped: "+skip+")")
			continue
		}
		res.Accepted = append(res.Accepted, what)
	}
	res.Held = f.Held
	for _, sg := range bun.Signed {
		if err := a.keepSigned(p, sg, bun.Guards[sg.Statement.Guard]); err != nil {
			res.Refused = append(res.Refused, "statement: "+err.Error())
		}
	}
}

// guardFile finds the guard a statement names: the agent's own copy
// first, else the bundle's, but only if that file is the guard the hash
// names (a guard's hash is over its exact canonical bytes). A wrong file is
// treated as no file, so a lookout can't make the agent skip a statement by
// attaching another guard to it.
func (a *Agent) guardFile(bun *Bundle, hash string) ([]byte, error) {
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
	if b := bun.Guards[hash]; b != nil && fileHash(b) == hash {
		return b, nil
	}
	return nil, errors.New("no file for guard " + hash[:min(16, len(hash))])
}

// fileHash is a canonical file's hash: sha256 of its bytes without a final
// newline. Guards and policies are named this way.
func fileHash(b []byte) string {
	b = bytes.TrimSuffix(b, []byte("\n"))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ownerMessage takes one owner statement. It returns what the statement
// is; skip, when the statement was taken but this agent can't act on it;
// or hold, when it doesn't check out yet and must hold the ones after it.
func (a *Agent) ownerMessage(ctx context.Context, f *Fleet, p *policy.Policy, bun *Bundle, chain string, owner []byte, m Message, res *TickResult) (what, skip string, hold error) {
	var tx approve.GnokeyTx
	if err := json.Unmarshal(m.Tx, &tx); err != nil || len(tx.Msg) != 1 {
		return "", "", errors.New("not one message")
	}
	// Is it the owner's? The signature, over the memo the statement
	// carries, says so; acting on it also needs the memo rebuilt from the
	// file it names, below.
	if _, err := approve.VerifyGnokey(m.Tx, chain, m.Seq, owner, tx.Memo); err != nil {
		return "", "", fmt.Errorf("its signature doesn't check out: %w", err)
	}
	fn, args := tx.Msg[0].Func, tx.Msg[0].Args
	what = fn
	tier, _ := p.TierOf(f.Host)
	switch fn {
	case "Off", "On":
		// Off and On act on their signed guard hash and hosts whenever the
		// signature checks out: a memo this agent can't rebuild (a newer
		// format, a guard file it can't read or doesn't have) is noted,
		// never a reason to skip. Skipping an Off would leave a guard on.
		o, err := approve.ParseOff(approve.Call{Func: "Off", Args: args})
		if err != nil {
			return what, "its arguments: " + err.Error(), nil
		}
		what += " " + o.Hash[:16]
		if file, err := a.guardFile(bun, o.Hash); err == nil {
			if g, err := guard.Parse(file); err == nil {
				what = fn + " " + g.Name()
				verify := approve.VerifyOff
				if fn == "On" {
					verify = approve.VerifyOn
				}
				if _, err := verify(m.Tx, chain, m.Seq, owner, g); err != nil {
					what += " (its memo isn't the one this agent writes; acted on as signed)"
				}
			}
		}
		if !o.Names(f.Host) {
			return what + " for other hosts", "", nil
		}
		ev, _ := a.loadEvidence(o.Hash)
		if fn == "Off" {
			if !containsHash(f.Off, o.Hash) {
				f.Off = append(f.Off, o.Hash)
			}
			res.Off = append(res.Off, o.Hash)
			return what, "", nil
		}
		// On: back where the owner took it off, or held it after a hand
		// took it off or its retries ran out; admission decides again.
		f.Off = removeHash(f.Off, o.Hash)
		if ev.Guard != nil || ev.Ask || ev.Held || ev.Suspect {
			ev.Tries, ev.Ask, ev.Held, ev.Suspect, ev.RetryAt = 0, false, false, false, time.Time{}
			if err := a.saveEvidence(o.Hash, ev); err != nil {
				return what, "", err // a disk that won't write: try again next tick
			}
		}
		return what, "", nil
	case "Yes":
		if !strings.HasPrefix(tx.Memo, approve.MemoVersion+" ") {
			return what, "its memo is in a format newer than this agent", nil
		}
		if len(args) < 1 {
			return what, "no guard named", nil
		}
		file, err := a.guardFile(bun, args[0])
		if err != nil {
			return "", "", err // the file isn't here yet: any lookout can bring it
		}
		g, err := guard.Parse(file)
		if err != nil {
			return what, "a guard file this release can't read: " + err.Error(), nil
		}
		what = "Yes " + g.Name()
		y, err := approve.VerifyYes(m.Tx, chain, m.Seq, owner, g)
		if err != nil {
			return what, "its memo isn't what this agent writes for that guard: " + err.Error(), nil
		}
		h := g.Hash()
		ev, _ := a.loadEvidence(h)
		ev.Guard = g.Canonical()
		if ev.Yeses == nil {
			ev.Yeses = map[string]*approve.Yes{}
		}
		for _, t := range y.Tiers {
			yy := y
			ev.Yeses[t] = &yy // the newest Yes for each tier it names
		}
		if tier != nil && contains(y.Tiers, tier.Name) {
			// The owner's fresh word for this machine's tier: the retries
			// start again, and a suspect may go on beside other guards
			// (round 8, new major 4). It never lifts an Off or a hold by
			// hand; On does.
			ev.Tries, ev.Ask, ev.Suspect, ev.RetryAt = 0, false, false, time.Time{}
		}
		if err := a.saveEvidence(h, ev); err != nil {
			return "", "", err
		}
		return what, "", nil
	case "Policy":
		if len(args) != 2 {
			return what, "Policy takes two hashes", nil
		}
		if !strings.HasPrefix(tx.Memo, approve.MemoVersion+" ") {
			return what, "its memo is in a format newer than this agent", nil
		}
		// The bundle's file counts only if it is the policy the hash names.
		file := bun.Policies[args[0]]
		if file == nil || fileHash(file) != args[0] {
			return "", "", errors.New("the policy file it names isn't here yet")
		}
		next, err := policy.Parse(file)
		if err != nil {
			return what, "a policy file this release can't read: " + err.Error(), nil
		}
		what = "Policy " + next.Hash()[:16]
		// A step replaces the policy in force, or chains onto the one
		// pending; its memo is the diff against the one it replaces.
		old := p
		if args[1] != p.Hash() {
			if f.Pending == nil {
				return what, "it replaces a policy this machine has moved past", nil
			}
			pend, err := policy.Parse(f.Pending.Policy)
			if err != nil || pend.Hash() != args[1] {
				return what, "it replaces a policy this machine has moved past", nil
			}
			if pend.Signers.Me.Hex != p.Signers.Me.Hex || pend.Fleet != p.Fleet {
				return what, "the pending step changes the owner's key or the fleet; it must take effect before the next step", nil
			}
			old = pend
		}
		if err := approve.VerifyPolicy(m.Tx, chain, m.Seq, owner, old, next); err != nil {
			return what, "its memo isn't the diff this agent writes: " + err.Error(), nil
		}
		f.Pending = &PendingPolicy{Policy: next.Canonical(), FirstSeen: a.now().UTC()}
		return what + " pending", "", nil
	case "Cancel":
		// Cancel drops a pending policy change, by its hash; the memo is
		// rebuilt from the fleet and the hash it names.
		if len(args) != 1 {
			return what, "Cancel takes one hash", nil
		}
		memo, err := approve.MemoCancel(p.Fleet, args[0])
		if err != nil {
			return what, err.Error(), nil
		}
		what = "Cancel " + args[0][:min(16, len(args[0]))]
		if _, err := approve.VerifyGnokey(m.Tx, chain, m.Seq, owner, memo); err != nil {
			return what, "its memo isn't the one this agent writes: " + err.Error(), nil
		}
		if f.Pending == nil {
			return what, "no policy change is pending here", nil
		}
		if pend, err := policy.Parse(f.Pending.Policy); err != nil || pend.Hash() != args[0] {
			return what, "the pending change here is another policy", nil
		}
		f.Pending = nil
		return what, "", nil
	case "Check":
		// A Check runs a was-I-hit check once, here if it is for this
		// system; the memo is rebuilt from the check's file, which the
		// statement waits for, as a Policy waits for its file.
		h, err := approve.ParseCheck(approve.Call{Func: "Check", Args: args})
		if err != nil {
			return what, err.Error(), nil
		}
		what = "Check " + h[:16]
		file := bun.Checks[h]
		if file == nil || fileHash(file) != h {
			return "", "", errors.New("the check file it names isn't here yet")
		}
		c, err := check.Parse(file)
		if err != nil {
			return what, "a check file this release can't read: " + err.Error(), nil
		}
		what = "Check " + c.Name()
		if err := approve.VerifyCheck(m.Tx, chain, m.Seq, owner, c); err != nil {
			return what, "its memo isn't what this agent writes for that check: " + err.Error(), nil
		}
		info, err := a.Sys.Info()
		if err != nil {
			return "", "", err
		}
		if !c.ForSystem(info.OS, info.Release) {
			return what + " (not for " + info.OS + " " + info.Release + ")", "", nil
		}
		// Queued, saved with the statement's sequence; it runs at a tick,
		// after the guards' step (round 15, new major 4).
		if len(f.Checks) >= maxChecks {
			return what, fmt.Sprintf("%d checks wait to run here already", maxChecks), nil
		}
		f.Checks = append(f.Checks, QueuedCheck{Seq: m.Seq, File: file})
		return what, "", nil
	case "Reboot":
		// A Reboot lets one host reboot into one kernel, once, before its
		// deadline; the memo is rebuilt from its arguments.
		r, err := approve.VerifyReboot(m.Tx, chain, m.Seq, owner)
		if err != nil {
			return what, err.Error(), nil
		}
		what = "Reboot " + r.Host + " into " + r.Kernel
		if r.Host != f.Host {
			return what + " for another host", "", nil
		}
		f.Reboots = append(f.Reboots, RebootOrder{Seq: m.Seq, Kernel: r.Kernel, NotAfter: time.Unix(r.NotAfter, 0).UTC()})
		if n := len(f.Reboots); n > maxReboots {
			f.Reboots = f.Reboots[n-maxReboots:]
		}
		return what, "", nil
	}
	return what, "not a kind of statement this release acts on", nil
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
