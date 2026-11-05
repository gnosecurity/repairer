package lookout

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// KernelVulnsURL is the Linux kernel's own record of its flaws (vulns.git,
// kept by the kernel's CVE team): every CVE it assigns, within hours of the
// fix, with the files the fix touches, the release that fixes each stable
// series, and a CVSS vector with its reasons.
const KernelVulnsURL = "https://git.kernel.org/pub/scm/linux/security/vulns.git"

// KernelNewWindow is how long a kernel flaw counts as new on the page.
const KernelNewWindow = 14 * 24 * time.Hour

// KernelVulns is a whole copy of vulns.git (about 75 MB, one commit deep)
// and the time each of its records was first seen. Distros rate a kernel
// flaw days after the kernel names it; this copy shows the flaws a network
// can reach as soon as the kernel does, so a guard can be thought about
// first (the Hunt track). A distro's kernel carries fixes the upstream
// version number doesn't show, so this copy says nothing about whether a
// machine has the fix: that is the distros' feeds' word.
type KernelVulns struct {
	Dir    string // the bare repository
	Remote string // empty means KernelVulnsURL
	Git    string // the git program; empty means "git" on the PATH
}

func (k *KernelVulns) copy() gitCopy {
	remote := k.Remote
	if remote == "" {
		remote = KernelVulnsURL
	}
	return gitCopy{dir: k.Dir, remote: remote, git: k.Git}
}

// Synced is where the time of the last good sync is kept, beside the copy.
func (k *KernelVulns) Synced() string { return k.copy().synced() }

func (k *KernelVulns) seenPath() string { return k.Dir + ".seen.json" }

// seen is when each record was first seen; the zero time means "before
// the lookout began watching".
func (k *KernelVulns) seen() map[string]time.Time {
	m := map[string]time.Time{}
	if b, err := os.ReadFile(k.seenPath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// Sync fetches the copy, then notes each record not seen before with the
// time it was first seen. At the first sync every record is old: new means
// new since the lookout began watching.
func (k *KernelVulns) Sync(ctx context.Context) error {
	if err := k.copy().sync(ctx); err != nil {
		return fmt.Errorf("lookout: the kernel's vulns.git: %w", err)
	}
	names, err := k.copy().names(ctx, "cve/published")
	if err != nil {
		return fmt.Errorf("lookout: the kernel's vulns.git: %w", err)
	}
	seen := k.seen()
	first, changed := len(seen) == 0, false
	now := time.Now().UTC().Truncate(time.Second)
	for _, n := range names {
		id, ok := strings.CutSuffix(filepath.Base(n), ".json")
		if !ok || !trackerID.MatchString(id) {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		if first {
			seen[id] = time.Time{}
		} else {
			seen[id] = now
		}
		changed = true
	}
	if !changed {
		return nil
	}
	b, err := json.Marshal(seen)
	if err != nil {
		return err
	}
	return os.WriteFile(k.seenPath(), b, 0o600)
}

// New is the kernel flaws first seen at or after since, by name. A record
// gone from the published ones since (rejected) is left out.
func (k *KernelVulns) New(ctx context.Context, since time.Time) ([]*KernelCVE, error) {
	var ids []string
	seen := k.seen()
	for id, t := range seen {
		if !t.IsZero() && !t.Before(since) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var out []*KernelCVE
	for _, id := range ids {
		b, found, err := k.copy().blob(ctx, "cve/published/"+id[4:8]+"/"+id+".json", 4<<20)
		if err != nil {
			return nil, fmt.Errorf("lookout: the kernel's vulns.git: %w", err)
		}
		if !found {
			continue
		}
		c, err := ParseKernelCVE(b)
		if err != nil {
			return nil, err
		}
		c.FirstSeen = seen[id]
		out = append(out, c)
	}
	return out, nil
}

// KernelCVE is the kernel's record of one flaw, as much of it as the
// lookout uses.
type KernelCVE struct {
	ID         string            `json:"id"`
	Title      string            `json:"title"`
	Files      []string          `json:"files,omitempty"`      // the files the fix touches
	Vector     string            `json:"cvss,omitempty"`       // CVSS 3.1, when the kernel gave one
	Introduced string            `json:"introduced,omitempty"` // the first release affected
	Fixed      map[string]string `json:"fixed,omitempty"`      // stable series ("6.1") → its first release with the fix
	Mainline   string            `json:"mainline,omitempty"`   // the first mainline release with the fix
	FirstSeen  time.Time         `json:"first_seen"`
}

// Network says whether the kernel rates the flaw reachable over a network.
func (c *KernelCVE) Network() bool { return strings.Contains(c.Vector, "/AV:N/") }

// ParseKernelCVE reads a vulns.git record (CVE JSON 5).
func ParseKernelCVE(b []byte) (*KernelCVE, error) {
	var d struct {
		Meta struct {
			ID    string `json:"cveId"`
			State string `json:"state"`
		} `json:"cveMetadata"`
		Containers struct {
			CNA struct {
				Title    string `json:"title"`
				Affected []struct {
					DefaultStatus string   `json:"defaultStatus"`
					Files         []string `json:"programFiles"`
					Versions      []struct {
						Version         string `json:"version"`
						LessThan        string `json:"lessThan"`
						LessThanOrEqual string `json:"lessThanOrEqual"`
						Status          string `json:"status"`
						VersionType     string `json:"versionType"`
					} `json:"versions"`
				} `json:"affected"`
				Metrics []struct {
					V31 struct {
						Vector string `json:"vectorString"`
					} `json:"cvssV3_1"`
				} `json:"metrics"`
			} `json:"cna"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("lookout: a kernel CVE record: %w", err)
	}
	if !trackerID.MatchString(d.Meta.ID) || d.Meta.State != "PUBLISHED" {
		return nil, fmt.Errorf("lookout: a kernel CVE record named %q, %s", d.Meta.ID, d.Meta.State)
	}
	cna := d.Containers.CNA
	c := &KernelCVE{ID: d.Meta.ID, Title: cna.Title, Fixed: map[string]string{}}
	files := map[string]bool{}
	for _, a := range cna.Affected {
		if a.DefaultStatus != "affected" {
			continue // the same ranges by git commit
		}
		for _, f := range a.Files {
			if !files[f] {
				files[f] = true
				c.Files = append(c.Files, f)
			}
		}
		for _, v := range a.Versions {
			switch {
			case v.Status == "affected" && v.LessThan == "" && v.LessThanOrEqual == "":
				if c.Introduced == "" || versionLess(v.Version, c.Introduced) {
					c.Introduced = v.Version
				}
			case v.Status == "unaffected" && v.LessThanOrEqual == "*":
				c.Mainline = v.Version
			case v.Status == "unaffected" && strings.HasSuffix(v.LessThanOrEqual, ".*"):
				c.Fixed[strings.TrimSuffix(v.LessThanOrEqual, ".*")] = v.Version
			}
		}
	}
	for _, m := range cna.Metrics {
		if m.V31.Vector != "" {
			c.Vector = m.V31.Vector
		}
	}
	return c, nil
}

// Status says what the kernel's record says of an upstream release
// ("6.1.180"): whether it has the flaw, and the release that fixes it, in
// its own stable series when there is one, else mainline's.
func (c *KernelCVE) Status(release string) (affected bool, fix string) {
	if c.Introduced != "" && versionLess(release, c.Introduced) {
		return false, ""
	}
	if f, ok := c.Fixed[series(release)]; ok {
		if !versionLess(release, f) {
			return false, ""
		}
		return true, f
	}
	if c.Mainline != "" && !versionLess(release, c.Mainline) {
		return false, ""
	}
	return true, c.Mainline
}

// series is a release's stable series: "6.1" for "6.1.180".
func series(release string) string {
	p := versionParts(release)
	if len(p) < 2 {
		return release
	}
	return strconv.Itoa(p[0]) + "." + strconv.Itoa(p[1])
}

// versionParts reads the leading dotted numbers of a release.
func versionParts(v string) []int {
	var out []int
	for _, s := range strings.Split(v, ".") {
		n := 0
		digits := 0
		for _, r := range s {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
			digits++
		}
		if digits == 0 {
			break
		}
		out = append(out, n)
		if digits < len(s) {
			break // "180-1": the rest isn't the release's
		}
	}
	return out
}

// KernelReleaseLess orders kernel releases by their dotted numbers.
func KernelReleaseLess(a, b string) bool { return versionLess(a, b) }

// versionLess compares kernel releases by their dotted numbers; missing
// parts are zeros ("7.3" is "7.3.0").
func versionLess(a, b string) bool {
	x, y := versionParts(a), versionParts(b)
	for i := 0; i < len(x) || i < len(y); i++ {
		var p, q int
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p != q {
			return p < q
		}
	}
	return false
}
