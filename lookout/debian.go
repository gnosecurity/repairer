package lookout

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// DebianEntry is Debian's tracker on one flaw in one source package, per
// release codename.
type DebianEntry struct {
	Releases map[string]struct {
		Status       string `json:"status"` // resolved, open, undetermined
		FixedVersion string `json:"fixed_version"`
		Urgency      string `json:"urgency"`
	} `json:"releases"`
}

// DebianTracker holds the tracker's entries for the flaws asked for, by
// flaw and then source package.
type DebianTracker map[string]map[string]DebianEntry

// ReadDebianTracker reads Debian's tracker JSON (about 88 MB) as a stream,
// keeping only the flaws in want, so the whole file is never in memory.
func ReadDebianTracker(r io.Reader, want map[string]bool) (DebianTracker, error) {
	dec := json.NewDecoder(r)
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("lookout: the Debian tracker isn't an object: %v", err)
	}
	out := DebianTracker{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		pkg, _ := t.(string)
		var flaws map[string]json.RawMessage
		if err := dec.Decode(&flaws); err != nil {
			return nil, fmt.Errorf("lookout: the Debian tracker, package %s: %w", pkg, err)
		}
		for id, raw := range flaws {
			if !want[id] {
				continue
			}
			var e DebianEntry
			if err := json.Unmarshal(raw, &e); err != nil {
				return nil, fmt.Errorf("lookout: the Debian tracker, %s %s: %w", pkg, id, err)
			}
			if out[id] == nil {
				out[id] = map[string]DebianEntry{}
			}
			out[id][pkg] = e
		}
	}
	return out, nil
}

// Match says what each flaw is on each Debian machine. A fixed version of
// "0" means the release was never affected.
func (d DebianTracker) Match(ms []Machine, now time.Time) []Finding {
	var out []Finding
	for i := range ms {
		m := &ms[i]
		if m.OS.ID != "debian" {
			continue
		}
		for id, pkgs := range d {
			for pkg, e := range pkgs {
				running, ok := m.versionOf(pkg)
				if !ok {
					continue
				}
				f := Finding{Host: m.Host, Flaw: id, Package: pkg, Version: running, State: Unknown}
				r, listed := e.Releases[m.OS.Codename]
				switch {
				case !listed && m.ended(now):
					f.State = ReleaseEnded
				case !listed:
				case r.Status == "resolved" && r.FixedVersion == "0":
					f.State = NotAffected
				case r.Status == "resolved":
					f.Fix = r.FixedVersion
					f.State = m.judge(pkg, running, r.FixedVersion, true)
				case r.Status == "open":
					f.State = NoFixYet
				}
				if f.State == NotAffected {
					continue
				}
				f.Exposed = exposed(f.State)
				out = append(out, f)
			}
		}
	}
	SortFindings(out)
	return out
}
