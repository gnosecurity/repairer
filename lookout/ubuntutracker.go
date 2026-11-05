package lookout

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
)

// UbuntuTrackerURL is Ubuntu's CVE tracker. It is fetched over https, so
// what it says (the fixed versions that a guard's end and the findings
// lean on) comes from Canonical's server, not from whoever is on the path:
// git:// would be faster and isn't checked.
const UbuntuTrackerURL = "https://git.launchpad.net/ubuntu-cve-tracker"

// UbuntuTracker is a whole copy of Ubuntu's CVE tracker, the source of its
// per-flaw records, which know a fix waiting in -proposed: a bare git
// repository holding only the newest commit (about 220 MB). Reading one
// flaw's record from it says nothing to anyone about what the fleet runs,
// where fetching that record from ubuntu.com would.
type UbuntuTracker struct {
	Dir    string // the bare repository
	Remote string // empty means UbuntuTrackerURL
	Git    string // the git program; empty means "git" on the PATH
}

func (u *UbuntuTracker) copy() gitCopy {
	remote := u.Remote
	if remote == "" {
		remote = UbuntuTrackerURL
	}
	return gitCopy{dir: u.Dir, remote: remote, git: u.Git}
}

func (u *UbuntuTracker) remote() string { return u.copy().remote }

// Synced is where the time of the last good sync is kept, beside the copy.
func (u *UbuntuTracker) Synced() string { return u.copy().synced() }

// Sync clones the tracker the first time and fetches its newest commit
// after, within ctx's deadline.
func (u *UbuntuTracker) Sync(ctx context.Context) error {
	if err := u.copy().sync(ctx); err != nil {
		return fmt.Errorf("lookout: Ubuntu's tracker: %w", err)
	}
	return nil
}

// trackerID is a flaw's name as the tracker files it.
var trackerID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// MaxTrackerRecord bounds one record read from the copy (the kernel's run to
// about 110 KB).
const MaxTrackerRecord = 4 << 20

// Record is Ubuntu's record of one flaw from the copy (active, or retired
// once every release is settled), or nil when the tracker has none.
func (u *UbuntuTracker) Record(ctx context.Context, id string) (*UbuntuCVE, error) {
	if !trackerID.MatchString(id) {
		return nil, fmt.Errorf("lookout: %q isn't a CVE name", id)
	}
	for _, dir := range []string{"active", "retired"} {
		b, found, err := u.copy().blob(ctx, dir+"/"+id, MaxTrackerRecord)
		if err != nil {
			return nil, fmt.Errorf("lookout: Ubuntu's tracker: %w", err)
		}
		if found {
			return ParseTracker(id, b)
		}
	}
	return nil, nil
}

// trackerStatuses are the states a tracker line can give a package on a
// release.
var trackerStatuses = map[string]bool{"DNE": true, "needs-triage": true, "needed": true, "active": true,
	"pending": true, "released": true, "ignored": true, "not-affected": true, "deferred": true}

// trackerLine is "<release>_<source package>: <status>[ (<note>)]". A
// release may be a pocket ("esm-infra/focal", "trusty/esm"); a source
// package has no "_".
var trackerLine = regexp.MustCompile(`^([A-Za-z0-9./+-]+?)_([a-z0-9][a-z0-9.+-]*): ([A-Za-z-]+)(?: \((.*)\))?\s*$`)

// ParseTracker reads one tracker record into the shape of Ubuntu's own
// JSON (ubuntu.com/security/cves/<id>.json), which the JSON is made from.
// Like the JSON, each release gets its first status that isn't "ignored"
// among its own line and its ESM pockets' lines, in the record's order: a
// release past standard support shows what Ubuntu Pro still does for it.
// The development release's lines are left out, as the JSON leaves them.
func ParseTracker(id string, b []byte) (*UbuntuCVE, error) {
	c := &UbuntuCVE{ID: id}
	type status = struct {
		Codename    string `json:"release_codename"`
		Status      string `json:"status"`
		Description string `json:"description"`
	}
	byPkg := map[string]int{}  // package → its place in c.Packages
	chosen := map[string]int{} // package\x00release → its place in the package's statuses
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), MaxTrackerRecord)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "Candidate: "); ok && strings.TrimSpace(v) != id {
			return nil, fmt.Errorf("lookout: the tracker's record for %s names %q", id, strings.TrimSpace(v))
		}
		if v, ok := strings.CutPrefix(line, "Priority: "); ok {
			c.Priority = strings.TrimSpace(v)
			continue
		}
		m := trackerLine.FindStringSubmatch(line)
		if m == nil || !trackerStatuses[m[3]] {
			continue
		}
		pocket, pkg, st, note := m[1], m[2], m[3], m[4]
		release := pocket
		if a, b, ok := strings.Cut(pocket, "/"); ok {
			release = b // esm-infra/focal
			if !strings.HasPrefix(a, "esm") {
				release = a // trusty/esm
			}
		}
		if release == "devel" {
			continue
		}
		i, ok := byPkg[pkg]
		if !ok {
			i = len(c.Packages)
			byPkg[pkg] = i
			c.Packages = append(c.Packages, struct {
				Name     string `json:"name"`
				Statuses []struct {
					Codename    string `json:"release_codename"`
					Status      string `json:"status"`
					Description string `json:"description"`
				} `json:"statuses"`
			}{Name: pkg})
		}
		p := &c.Packages[i]
		k := pkg + "\x00" + release
		s := status{Codename: release, Status: st, Description: note}
		if j, ok := chosen[k]; ok {
			if p.Statuses[j].Status == "ignored" && st != "ignored" {
				p.Statuses[j] = s // a pocket still served
			}
			continue
		}
		chosen[k] = len(p.Statuses)
		p.Statuses = append(p.Statuses, s)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("lookout: the tracker's record for %s: %w", id, err)
	}
	return c, nil
}
