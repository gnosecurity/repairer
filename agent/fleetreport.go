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

	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
)

const (
	// OutDir holds what the unprivileged half may read: the signed report.
	OutDir     = "out"
	reportFile = "report.json"
	factsFile  = "facts.json"
	// FactsEvery is how often the full facts (packages, kernels, sockets)
	// are gathered again; the rest of the report is fresh every tick.
	FactsEvery = time.Hour
)

// FleetReport is what an agent signs for the lookout every tick: where it
// stands with the owner's statements, every guard on it and on its way, the
// wants it has for canaries, a canary's answers, and the machine's facts.
type FleetReport struct {
	Version string    `json:"v"`
	Kind    string    `json:"kind"` // "report"
	Chain   string    `json:"chain"`
	Host    string    `json:"host"`
	Seq     uint64    `json:"seq"`
	Time    time.Time `json:"time"`
	// Policy is the hash of the policy in force, and Pending a signed change
	// counting down its delay, so the owner's tool and a second lookout see
	// it on every machine.
	Policy   string         `json:"policy"`
	Pending  *PendingReport `json:"pending,omitempty"`
	OwnerSeq uint64         `json:"owner_seq"`
	Off      []string       `json:"off,omitempty"`
	Guards   []GuardState   `json:"guards,omitempty"`
	OnTheWay []OnTheWay     `json:"on_the_way,omitempty"`
	// Wants are this machine's requests for a canary's Healthy; Healthy are
	// a canary's signed answers to other machines' wants.
	Wants   []Want           `json:"wants,omitempty"`
	Healthy []approve.Signed `json:"healthy,omitempty"`
	Tick    *TickResult      `json:"tick,omitempty"`
	// Held says why the owner's statements stop where they do; Skipped
	// lists statements taken but not acted on, and why.
	Held    string    `json:"held,omitempty"`
	Skipped []Skipped `json:"skipped,omitempty"`
	Errors  []string  `json:"errors,omitempty"`
	Facts   *Report   `json:"facts,omitempty"`
}

// PendingReport is a policy change waiting out its delay.
type PendingReport struct {
	Hash      string    `json:"hash"`
	FirstSeen time.Time `json:"first_seen"`
}

// GuardState is a guard on this machine, from its live state.
type GuardState struct {
	Hash       string `json:"hash"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	By         string `json:"by,omitempty"`
	Keep       bool   `json:"keep,omitempty"`
	Later      bool   `json:"later,omitempty"`
	BootWindow bool   `json:"boot_window,omitempty"`
	Booted     bool   `json:"booted,omitempty"`
	Stopped    int64  `json:"stopped_packets"` // -1: a table is unreadable
	Failed     string `json:"failed,omitempty"`
}

// OnTheWay is a guard with evidence here that isn't on: waiting, refused,
// between tries, or waiting for the owner.
type OnTheWay struct {
	Hash        string    `json:"hash"`
	Name        string    `json:"name,omitempty"`
	Tries       int       `json:"tries,omitempty"`
	RetryAt     time.Time `json:"retry_at,omitzero"`
	Ask         bool      `json:"ask,omitempty"`
	Held        bool      `json:"held,omitempty"` // taken off by hand: off until the owner's On
	Last        string    `json:"last,omitempty"`
	Refused     string    `json:"refused,omitempty"`
	RefusedCode string    `json:"refused_code,omitempty"`
	Baseline    int       `json:"baseline_samples,omitempty"`
}

// writeReport builds this tick's report, signs it with the agent's key and
// writes it where the unprivileged half's `report` reads it.
func (a *Agent) writeReport(ctx context.Context, f *Fleet, p *policy.Policy, res *TickResult) error {
	priv, err := a.privateKey()
	if err != nil {
		return err
	}
	owner, _ := hex.DecodeString(p.Signers.Me.Hex)
	f.ReportSeq++
	r := &FleetReport{Version: approve.MemoVersion, Kind: "report", Chain: approve.ChainID(owner, p.Fleet),
		Host: f.Host, Seq: f.ReportSeq, Time: a.now().UTC(), Policy: p.Hash(), OwnerSeq: f.LastSeq, Off: f.Off, Tick: res,
		Held: f.Held, Skipped: f.Skipped}
	if f.Pending != nil {
		if np, err := policy.Parse(f.Pending.Policy); err == nil {
			r.Pending = &PendingReport{Hash: np.Hash(), FirstSeen: f.Pending.FirstSeen}
		}
	}
	fail := func(what string, err error) {
		if err != nil {
			r.Errors = append(r.Errors, what+": "+err.Error())
		}
	}
	entries, hits, err := a.Status(ctx)
	fail("guards", err)
	on := map[string]bool{}
	for _, e := range entries {
		on[e.Hash] = true
		r.Guards = append(r.Guards, GuardState{Hash: e.Hash, Name: e.Guard.Name(), Status: e.Status, By: e.By, Keep: e.Keep,
			Later: e.Later, BootWindow: e.BootWindow, Booted: e.Booted, Stopped: hits[e.Hash], Failed: e.Failed})
	}
	evs, err := a.allEvidence()
	fail("evidence", err)
	tier, _ := p.TierOf(f.Host)
	canary := tier != nil && contains(tier.Canaries, f.Host)
	for _, h := range sortedKeys(evs) {
		ev := evs[h]
		if on[h] {
			continue
		}
		w := OnTheWay{Hash: h, Tries: ev.Tries, RetryAt: ev.RetryAt, Ask: ev.Ask, Held: ev.Held, Last: ev.Last, Refused: ev.Refused, RefusedCode: ev.RefusedCode}
		if g, err := guard.Parse(ev.Guard); err == nil {
			w.Name = g.Name()
		}
		if ev.Trial != nil {
			w.Baseline = ev.Trial.Samples
		}
		r.OnTheWay = append(r.OnTheWay, w)
		if !canary && ev.Nonce != "" && !ev.Ask && !ev.Held && !containsHash(f.Off, h) {
			r.Wants = append(r.Wants, Want{Guard: h, Nonce: ev.Nonce})
		}
	}
	healthy, err := a.loadHealthy()
	fail("healthy", err)
	for _, k := range sortedSigned(healthy) {
		r.Healthy = append(r.Healthy, healthy[k])
	}
	r.Facts, err = a.facts(ctx)
	fail("facts", err)

	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	sr, err := json.Marshal(approve.SignReport(priv, body))
	if err != nil {
		return err
	}
	if err := a.saveFleet(f); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(a.StateDir, OutDir, reportFile), append(sr, '\n'), 0o640)
}

// facts returns the machine's full facts, gathered again once they are
// FactsEvery old.
func (a *Agent) facts(ctx context.Context) (*Report, error) {
	path := filepath.Join(a.StateDir, factsFile)
	if b, err := os.ReadFile(path); err == nil {
		var r Report
		if json.Unmarshal(b, &r) == nil && a.now().Sub(r.Time) < FactsEvery && !r.Time.After(a.now()) {
			return &r, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	r := a.Report(ctx)
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return r, writeAtomic(path, b, 0o600)
}

// ReadReport returns the last signed report, as `report` prints it.
func ReadReport(stateDir string) ([]byte, error) {
	return os.ReadFile(filepath.Join(stateDir, OutDir, reportFile))
}

func sortedSigned(m map[string]approve.Signed) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
