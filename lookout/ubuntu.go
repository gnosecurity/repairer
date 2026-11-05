package lookout

import (
	"encoding/json"
	"fmt"
	"time"
)

// UbuntuCVE is Ubuntu's record of one flaw (ubuntu.com/security/cves/<id>.json):
// for each source package, a status per release codename.
type UbuntuCVE struct {
	ID       string `json:"id"`
	Priority string `json:"priority"`
	Packages []struct {
		Name     string `json:"name"`
		Statuses []struct {
			Codename    string `json:"release_codename"`
			Status      string `json:"status"`
			Description string `json:"description"` // the fixed version, for pending and released
		} `json:"statuses"`
	} `json:"packages"`
}

// ParseUbuntuCVE reads Ubuntu's record of one flaw.
func ParseUbuntuCVE(b []byte) (*UbuntuCVE, error) {
	var c UbuntuCVE
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("lookout: an Ubuntu CVE record: %w", err)
	}
	if c.ID == "" {
		return nil, fmt.Errorf("lookout: an Ubuntu CVE record without an id")
	}
	return &c, nil
}

// Match says what the flaw is on each Ubuntu machine, for every source
// package the record names and the machine runs. A release the record no
// longer lists counts as reached when it is past its end of support: no
// fix will come for it.
func (c *UbuntuCVE) Match(ms []Machine, now time.Time) []Finding {
	var out []Finding
	for i := range ms {
		m := &ms[i]
		if m.OS.ID != "ubuntu" {
			continue
		}
		for _, p := range c.Packages {
			running, ok := m.versionOf(p.Name)
			if !ok {
				continue
			}
			f := Finding{Host: m.Host, Flaw: c.ID, Package: p.Name, Version: running, State: Unknown}
			listed := false
			for _, s := range p.Statuses {
				if s.Codename != m.OS.Codename {
					continue
				}
				listed = true
				switch s.Status {
				case "DNE", "not-affected":
					f.State = NotAffected
				case "released":
					f.Fix = s.Description
					f.State = m.judge(p.Name, running, s.Description, true)
				case "pending":
					f.Fix = s.Description
					f.State = m.judge(p.Name, running, s.Description, false)
				case "needed", "needs-triage", "deferred", "active":
					f.State = NoFixYet
				case "ignored":
					f.State = NoFixComing
				}
			}
			if !listed && m.ended(now) {
				f.State = ReleaseEnded
			}
			if f.State == NotAffected {
				continue
			}
			f.Exposed = exposed(f.State)
			out = append(out, f)
		}
	}
	SortFindings(out)
	return out
}
