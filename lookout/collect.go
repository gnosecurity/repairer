package lookout

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jaekwon/autopatch/agent"
	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/policy"
)

// Silent is how long a machine may go without a fresh report before the
// lookout raises an alert.
const Silent = 15 * time.Minute

// Collector fetches each machine's signed report and keeps the newest one
// that verifies against the machine's agent key in the policy. It trusts
// nothing in a report that the signature doesn't cover, and refuses a
// report older than one it already has, so an old report can't be replayed
// to hide a change.
type Collector struct {
	Policy *policy.Policy
	Dir    string // <Dir>/<host>.json: the newest verified report, as signed
	// Fetch gets a machine's signed report: over ssh, with a key that runs
	// only `autopatch-agent report` there.
	Fetch func(ctx context.Context, host string) ([]byte, error)
	Now   func() time.Time
}

// HostStatus is what the lookout knows of one machine after a collection.
type HostStatus struct {
	Host   string             `json:"host"`
	Seq    uint64             `json:"seq,omitempty"`
	Time   time.Time          `json:"time,omitzero"`   // the newest report's own time
	Silent bool               `json:"silent"`          // no fresh report for Silent
	Error  string             `json:"error,omitempty"` // why this round's fetch didn't count
	Report *agent.FleetReport `json:"-"`
}

// Collect fetches every machine's report once.
func (c *Collector) Collect(ctx context.Context) []HostStatus {
	var out []HostStatus
	owner, _ := hex.DecodeString(c.Policy.Signers.Me.Hex)
	chain := approve.ChainID(owner, c.Policy.Fleet)
	for _, k := range c.Policy.Signers.Agents {
		st := HostStatus{Host: k.Host}
		if err := c.collectOne(ctx, k, chain, &st); err != nil {
			st.Error = err.Error()
		}
		if old, err := c.Load(k.Host); err == nil {
			st.Seq, st.Time, st.Report = old.Seq, old.Time, old
		}
		st.Silent = st.Report == nil || c.Now().Sub(st.Time) > Silent
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func (c *Collector) collectOne(ctx context.Context, k policy.Key, chain string, st *HostStatus) error {
	b, err := c.Fetch(ctx, k.Host)
	if err != nil {
		return fmt.Errorf("fetching: %w", err)
	}
	body, err := approve.VerifyReport(b, k.Hex)
	if err != nil {
		return err
	}
	var r agent.FleetReport
	if err := json.Unmarshal(body, &r); err != nil {
		return fmt.Errorf("reading the report: %w", err)
	}
	switch {
	case r.Kind != "report" || r.Host != k.Host || r.Chain != chain:
		return errors.New("the report is for another machine or fleet")
	case r.Time.After(c.Now().Add(time.Minute)):
		return errors.New("the report is from the future")
	}
	if old, err := c.Load(k.Host); err == nil && r.Seq <= old.Seq {
		if r.Seq == old.Seq {
			return nil // nothing new
		}
		return fmt.Errorf("report %d is older than %d, which the lookout already has", r.Seq, old.Seq)
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(c.Dir, "."+k.Host+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.Dir, k.Host+".json"))
}

// Kept is what the lookout holds of every machine now, without fetching.
func (c *Collector) Kept() []HostStatus {
	var out []HostStatus
	for _, k := range c.Policy.Signers.Agents {
		st := HostStatus{Host: k.Host}
		if r, err := c.Load(k.Host); err == nil {
			st.Seq, st.Time, st.Report = r.Seq, r.Time, r
		} else if !os.IsNotExist(err) {
			st.Error = err.Error()
		}
		st.Silent = st.Report == nil || c.Now().Sub(st.Time) > Silent
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// Load reads the newest verified report kept for a machine. The file was
// verified when it was kept; it is verified again here, against the key
// the policy names now.
func (c *Collector) Load(host string) (*agent.FleetReport, error) {
	b, err := os.ReadFile(filepath.Join(c.Dir, host+".json"))
	if err != nil {
		return nil, err
	}
	for _, k := range c.Policy.Signers.Agents {
		if k.Host != host {
			continue
		}
		body, err := approve.VerifyReport(b, k.Hex)
		if err != nil {
			return nil, err
		}
		var r agent.FleetReport
		return &r, json.Unmarshal(body, &r)
	}
	return nil, fmt.Errorf("no agent key for %s in the policy", host)
}

// Machines turns the kept reports' facts into machines to match flaws on.
func Machines(sts []HostStatus) []Machine {
	var out []Machine
	for _, st := range sts {
		if st.Report == nil || st.Report.Facts == nil {
			continue
		}
		f := st.Report.Facts
		var m Machine
		m.Host = st.Host
		m.OS.ID, m.OS.Version, m.OS.Codename, m.OS.EOL = f.OS.ID, f.OS.Version, f.OS.Codename, f.OS.EOL
		m.Kernel.Running, m.Kernel.Release, m.Kernel.Source, m.Kernel.Installed = f.Kernel.Running, f.Kernel.Release, f.Kernel.Source, f.Kernel.Installed
		for _, p := range f.Packages {
			m.Packages = append(m.Packages, struct {
				Source  string `json:"source"`
				Version string `json:"version"`
			}{p.Source, p.Version})
		}
		out = append(out, m)
	}
	return out
}
