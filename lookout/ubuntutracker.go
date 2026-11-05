package lookout

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
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

func (u *UbuntuTracker) git() string {
	if u.Git != "" {
		return u.Git
	}
	return "git"
}

func (u *UbuntuTracker) remote() string {
	if u.Remote != "" {
		return u.Remote
	}
	return UbuntuTrackerURL
}

// Synced is where the time of the last good sync is kept, beside the copy.
func (u *UbuntuTracker) Synced() string { return u.Dir + ".synced" }

// Sync clones the tracker the first time and fetches its newest commit
// after, within ctx's deadline. The copy's HEAD names the branch
// "tracker", whatever Ubuntu calls its own.
func (u *UbuntuTracker) Sync(ctx context.Context) error {
	run := func(args ...string) error {
		out, err := exec.CommandContext(ctx, u.git(), args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("git %s: %v: %s", args[0], err, lastLine(out))
		}
		return nil
	}
	if _, err := os.Stat(filepath.Join(u.Dir, "HEAD")); err != nil {
		tmp := u.Dir + ".new"
		os.RemoveAll(tmp)
		if err := run("clone", "--quiet", "--bare", "--depth", "1", "--", u.remote(), tmp); err != nil {
			os.RemoveAll(tmp)
			return fmt.Errorf("lookout: cloning Ubuntu's tracker: %w", err)
		}
		for _, a := range [][]string{{"update-ref", "refs/heads/tracker", "HEAD"}, {"symbolic-ref", "HEAD", "refs/heads/tracker"}} {
			if err := run(append([]string{"--git-dir", tmp}, a...)...); err != nil {
				os.RemoveAll(tmp)
				return fmt.Errorf("lookout: Ubuntu's tracker: %w", err)
			}
		}
		if err := os.Rename(tmp, u.Dir); err != nil {
			return err
		}
	} else {
		if err := run("--git-dir", u.Dir, "fetch", "--quiet", "--depth", "1", "--", u.remote(), "+HEAD:refs/heads/tracker"); err != nil {
			return fmt.Errorf("lookout: fetching Ubuntu's tracker: %w", err)
		}
		// Older commits' objects go as git sees fit, so the copy stays
		// about one commit's size.
		_ = run("--git-dir", u.Dir, "gc", "--auto", "--quiet")
	}
	return os.WriteFile(u.Synced(), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
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
	if _, err := os.Stat(filepath.Join(u.Dir, "HEAD")); err != nil {
		return nil, errors.New("lookout: no copy of Ubuntu's tracker yet")
	}
	for _, dir := range []string{"active", "retired"} {
		cmd := exec.CommandContext(ctx, u.git(), "--git-dir", u.Dir, "cat-file", "blob", "HEAD:"+dir+"/"+id)
		var out, errOut bytes.Buffer
		lim := &limited{w: &out, n: MaxTrackerRecord}
		cmd.Stdout, cmd.Stderr = lim, &errOut
		err := cmd.Run()
		switch {
		case lim.over:
			return nil, fmt.Errorf("lookout: the tracker's record for %s is over %d bytes", id, MaxTrackerRecord)
		case err != nil && notThere(errOut.String()):
			continue // not in this directory
		case err != nil:
			return nil, fmt.Errorf("lookout: reading the tracker's record for %s: %v: %s", id, err, lastLine(errOut.Bytes()))
		}
		return ParseTracker(id, out.Bytes())
	}
	return nil, nil
}

// notThere says whether git's complaint is only that the path isn't in the
// commit.
func notThere(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "does not exist") || strings.Contains(s, "not a valid object name") || strings.Contains(s, "invalid object name")
}

// limited keeps at most n bytes and notes when more came.
type limited struct {
	w    interface{ Write([]byte) (int, error) }
	n    int
	over bool
}

func (l *limited) Write(p []byte) (int, error) {
	if len(p) > l.n {
		l.over = true
		return 0, errors.New("lookout: a tracker record past its size limit")
	}
	l.n -= len(p)
	return l.w.Write(p)
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

func lastLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
