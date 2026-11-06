// Package lookout is the watcher's side of repairer: it reads the
// machines' signed reports and the public flaw feeds, and says which
// machines a flaw reaches and what would fix it. It holds no key an agent
// trusts and changes nothing on any machine.
package lookout

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gnosecurity/repairer/guard"
)

// Machine is what the lookout matches flaws against: a machine's facts, as
// its agent reports them (the field names follow agent.Report).
type Machine struct {
	Host string `json:"host"`
	OS   struct {
		ID       string `json:"id"`       // ubuntu, debian
		Version  string `json:"version"`  // 24.04, 12
		Codename string `json:"codename"` // noble, bookworm
		EOL      string `json:"eol"`      // end of standard support, YYYY-MM-DD
	} `json:"os"`
	Kernel struct {
		Running   string   `json:"running"` // the running image's package version, 6.8.0-142.142
		Release   string   `json:"release"` // uname -r
		Source    string   `json:"source"`  // the running image's source package; "" means linux
		Installed []string `json:"installed"`
	} `json:"kernel"`
	Packages []struct {
		Source  string `json:"source"`
		Version string `json:"version"`
	} `json:"packages"`
}

// ReadMachines reads a list of machines' facts.
func ReadMachines(b []byte) ([]Machine, error) {
	var ms []Machine
	if err := json.Unmarshal(b, &ms); err != nil {
		return nil, fmt.Errorf("lookout: machines: %w", err)
	}
	return ms, nil
}

// States of a flaw on a machine, in plain words.
const (
	NotAffected  = "not affected"
	Fixed        = "fixed"
	RebootOwed   = "fixed on disk; a reboot is owed"
	FixAvailable = "fix available"
	FixPending   = "fix pending (in -proposed)"
	NoFixYet     = "no fix yet"
	NoFixComing  = "no fix coming"
	ReleaseEnded = "release past its end of support; no fix will come"
	Unknown      = "unknown"
)

// Finding is one flaw on one machine.
type Finding struct {
	Host    string `json:"host"`
	Flaw    string `json:"flaw"`
	Package string `json:"package"` // the source package
	Version string `json:"version"` // what the machine runs
	State   string `json:"state"`
	Fix     string `json:"fix,omitempty"` // the fixed version, if one is known
	// Exposed is true when the machine runs the flaw now, fix or no fix.
	Exposed bool `json:"exposed"`
	// Exploited is true when the flaw is on CISA's list of exploited flaws.
	Exploited bool `json:"exploited,omitempty"`
}

func exposed(state string) bool {
	switch state {
	case NotAffected, Fixed, Unknown:
		return false
	}
	return true
}

// versionOf returns what a machine runs of a source package: the running
// kernel for the kernel's source, else the installed version.
func (m *Machine) versionOf(pkg string) (string, bool) {
	if pkg == m.kernelSource() {
		return m.Kernel.Running, m.Kernel.Running != ""
	}
	for _, p := range m.Packages {
		if p.Source == pkg {
			return p.Version, true
		}
	}
	return "", false
}

func (m *Machine) kernelSource() string {
	if m.Kernel.Source != "" {
		return m.Kernel.Source
	}
	return "linux"
}

// ended reports whether the machine's release is past its end of support.
func (m *Machine) ended(now time.Time) bool {
	end, err := time.Parse("2006-01-02", m.OS.EOL)
	return err == nil && !now.Before(end)
}

// judge turns a fixed version into a state for what the machine runs: for
// the kernel, a fix installed but not running is a reboot owed.
func (m *Machine) judge(pkg, running, fix string, released bool) string {
	if guard.CompareVersions(running, fix) >= 0 {
		return Fixed
	}
	if pkg == m.kernelSource() {
		for _, v := range m.Kernel.Installed {
			if guard.CompareVersions(v, fix) >= 0 {
				return RebootOwed
			}
		}
	}
	if released {
		return FixAvailable
	}
	return FixPending
}

// SortFindings orders findings by host, then flaw, then package.
func SortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Flaw != b.Flaw {
			return a.Flaw < b.Flaw
		}
		return a.Package < b.Package
	})
}

// Summary says in one line per state which machines a flaw reaches.
func Summary(fs []Finding) string {
	by := map[string][]string{}
	for _, f := range fs {
		by[f.State] = append(by[f.State], f.Host)
	}
	var states []string
	for s := range by {
		states = append(states, s)
	}
	sort.Strings(states)
	var b strings.Builder
	for _, s := range states {
		sort.Strings(by[s])
		fmt.Fprintf(&b, "%s: %s\n", s, strings.Join(by[s], " "))
	}
	return b.String()
}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }
