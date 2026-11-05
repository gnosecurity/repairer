package lookout

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Feed addresses. Every feed is fetched whole (or, for OSV, every changed
// record), so no request says what the fleet runs.
const (
	KEVURL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DebianURL = "https://security-tracker.debian.org/tracker/data/json"
	OSVBase   = "https://osv-vulnerabilities.storage.googleapis.com"
)

// Feeds is the lookout's copy of the public flaw feeds and what it found
// with them.
type Feeds struct {
	Dir     string // <Dir>/feeds, <Dir>/osv-ubuntu, <Dir>/osv-debian, <Dir>/ubuntu-cves, <Dir>/findings.json
	Fetcher *Fetcher
	// Base addresses, for tests; empty means the real ones.
	KEV, Debian, OSV string
}

func (f *Feeds) url(test, real string) string {
	if test != "" {
		return test
	}
	return real
}

func (f *Feeds) osv(eco string) *OSVSync {
	return &OSVSync{Fetcher: f.Fetcher, Base: f.url(f.OSV, OSVBase), Ecosystem: eco, Dir: filepath.Join(f.Dir, "osv-"+strings.ToLower(eco))}
}

// Refresh fetches what changed in every feed. Every request is the same
// whatever the fleet runs: whole feeds, and every changed OSV record. It
// never asks for one flaw's record because it matters here; that would
// tell the feed what the fleet runs. Ubuntu's own per-flaw records, which
// know a fix in -proposed, are read when present in <Dir>/ubuntu-cves (put
// there from a whole copy of Ubuntu's tracker); fetching that whole copy
// is still to come.
func (f *Feeds) Refresh(ctx context.Context) []error {
	var errs []error
	if _, err := f.Fetcher.Get(ctx, "kev.json", f.url(f.KEV, KEVURL), 64<<20); err != nil {
		errs = append(errs, fmt.Errorf("CISA's list: %w", err))
	}
	if _, err := f.Fetcher.Get(ctx, "debian-tracker.json", f.url(f.Debian, DebianURL), 512<<20); err != nil {
		errs = append(errs, fmt.Errorf("Debian's tracker: %w", err))
	}
	for _, eco := range []string{"Ubuntu", "Debian"} {
		if _, err := f.osv(eco).Sync(ctx); err != nil {
			errs = append(errs, fmt.Errorf("OSV %s: %w", eco, err))
		}
	}
	return errs
}

// LoadOSV loads one ecosystem's whole OSV set from its all.zip, the first
// time; Refresh keeps it up to date after.
func (f *Feeds) LoadOSV(eco, zipPath string) (int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, err
	}
	defer zr.Close()
	s := f.osv(eco)
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return 0, err
	}
	n := 0
	var newest time.Time
	for _, zf := range zr.File {
		name := filepath.Base(zf.Name)
		if !strings.HasSuffix(name, ".json") || !osvIDRe.MatchString(strings.TrimSuffix(name, ".json")) || zf.UncompressedSize64 > 16<<20 {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return n, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 16<<20))
		rc.Close()
		if err != nil {
			return n, err
		}
		var r OSVRecord
		if json.Unmarshal(b, &r) != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, r.Modified); err == nil && t.After(newest) {
			newest = t
		}
		if err := os.WriteFile(filepath.Join(s.Dir, name), b, 0o600); err != nil {
			return n, err
		}
		n++
	}
	if !newest.IsZero() {
		return n, s.setLast(newest)
	}
	return n, nil
}

// Find matches every feed against the machines, marks what CISA lists as
// exploited, and keeps the findings that leave a machine exposed, the
// exploited first, in <Dir>/findings.json.
func (f *Feeds) Find(ms []Machine, watch []string, now time.Time) ([]Finding, error) {
	var all []Finding
	for _, eco := range []string{"Ubuntu", "Debian"} {
		fs, err := f.osv(eco).Match(ms)
		if err != nil {
			return nil, err
		}
		all = append(all, fs...)
	}
	// Ubuntu's own record wins over OSV's for the flaws it covers: it knows
	// a fix in -proposed.
	ubuntu := map[string]bool{}
	for _, id := range watch {
		b, err := os.ReadFile(filepath.Join(f.Dir, "ubuntu-cves", id+".json"))
		if err != nil {
			continue
		}
		c, err := ParseUbuntuCVE(b)
		if err != nil {
			continue
		}
		ubuntu[c.ID] = true
		all = append(all, c.Match(ms, now)...)
	}
	want := map[string]bool{}
	for _, id := range watch {
		want[id] = true
	}
	if fh, err := f.Fetcher.Open("debian-tracker.json"); err == nil {
		d, err := ReadDebianTracker(fh, want)
		fh.Close()
		if err == nil {
			all = append(all, d.Match(ms, now)...)
		}
	}
	if b, err := os.ReadFile(f.Fetcher.Path("kev.json")); err == nil {
		if k, err := ParseKEV(b); err == nil {
			k.Mark(all)
		}
	}
	// One finding per machine, flaw and package: Ubuntu's record for the
	// flaws it covers, else the first.
	seen := map[string]int{}
	var out []Finding
	for _, x := range all {
		if !x.Exposed {
			continue
		}
		k := x.Host + "\x00" + x.Flaw + "\x00" + x.Package
		if i, ok := seen[k]; ok {
			if ubuntu[x.Flaw] && x.State == FixPending {
				out[i] = x
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, x)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Exploited && !out[j].Exploited })
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(f.Dir, "findings.json"), b, 0o600); err != nil {
		return nil, err
	}
	return out, nil
}

// Findings reads the last findings Find kept.
func (f *Feeds) Findings() ([]Finding, error) {
	b, err := os.ReadFile(filepath.Join(f.Dir, "findings.json"))
	if err != nil {
		return nil, err
	}
	var out []Finding
	return out, json.Unmarshal(b, &out)
}

// Watch is the flaws worth Ubuntu's own record: those the kept guards are
// for, and those on CISA's list that OSV finds on a machine.
func (f *Feeds) Watch(store *Store, ms []Machine) []string {
	set := map[string]bool{}
	files, _ := filepath.Glob(store.path("guards", "*.json"))
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var g struct {
			Flaws []string `json:"flaws"`
		}
		if json.Unmarshal(b, &g) == nil {
			for _, fl := range g.Flaws {
				set[fl] = true
			}
		}
	}
	if b, err := os.ReadFile(f.Fetcher.Path("kev.json")); err == nil {
		if k, err := ParseKEV(b); err == nil {
			for _, eco := range []string{"Ubuntu", "Debian"} {
				if fs, err := f.osv(eco).Match(ms); err == nil {
					for _, x := range fs {
						if k[x.Flaw] {
							set[x.Flaw] = true
						}
					}
				}
			}
		}
	}
	var out []string
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
