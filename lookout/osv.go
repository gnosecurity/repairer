package lookout

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/guard"
)

// OSVRecord is the part of an OSV record (ossf.github.io/osv-schema) the
// lookout reads: what it is about, and which packages of which releases it
// reaches.
type OSVRecord struct {
	ID       string   `json:"id"`
	Modified string   `json:"modified"`
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

// flaw is the name a finding gives the record: its CVE when it has one.
func (r *OSVRecord) flaw() string {
	for _, a := range append(append([]string{}, r.Upstream...), r.Aliases...) {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return r.ID
}

// Ecosystem is a machine's OSV ecosystem: "Ubuntu:24.04:LTS", "Ubuntu:25.10",
// "Debian:12". Ubuntu's long-term releases are the .04 of even years.
func (m *Machine) Ecosystem() string {
	switch m.OS.ID {
	case "ubuntu":
		eco := "Ubuntu:" + m.OS.Version
		if y, err := strconv.Atoi(strings.Split(m.OS.Version, ".")[0]); err == nil && y%2 == 0 && strings.HasSuffix(m.OS.Version, ".04") {
			eco += ":LTS"
		}
		return eco
	case "debian":
		return "Debian:" + strings.Split(m.OS.Version, ".")[0]
	}
	return ""
}

// Match says what the record is on each machine it reaches.
func (r *OSVRecord) Match(ms []Machine) []Finding {
	var out []Finding
	for i := range ms {
		m := &ms[i]
		eco := m.Ecosystem()
		for _, a := range r.Affected {
			if a.Package.Ecosystem != eco {
				continue
			}
			running, ok := m.versionOf(a.Package.Name)
			if !ok {
				continue
			}
			hit, fix := false, ""
			for _, v := range a.Versions {
				if v == running {
					hit = true
				}
			}
			for _, rg := range a.Ranges {
				if rg.Type != "ECOSYSTEM" {
					continue
				}
				in, f := inRange(running, rg.Events)
				hit = hit || in
				if f != "" {
					fix = f
				}
			}
			f := Finding{Host: m.Host, Flaw: r.flaw(), Package: a.Package.Name, Version: running, Fix: fix}
			switch {
			case fix != "":
				f.State = m.judge(a.Package.Name, running, fix, true)
			case hit:
				f.State = NoFixYet
			default:
				continue
			}
			if f.State == Fixed {
				continue
			}
			f.Exposed = exposed(f.State)
			out = append(out, f)
		}
	}
	SortFindings(out)
	return out
}

// inRange says whether v falls in a range's events (introduced, fixed,
// last_affected, in dpkg's order) and returns the range's fix, if any.
func inRange(v string, events []struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}) (bool, string) {
	in, fix := false, ""
	for _, e := range events {
		switch {
		case e.Introduced != "":
			if e.Introduced == "0" || guard.CompareVersions(v, e.Introduced) >= 0 {
				in = true
			}
		case e.Fixed != "":
			fix = e.Fixed
			if guard.CompareVersions(v, e.Fixed) >= 0 {
				in = false
			}
		case e.LastAffected != "":
			if guard.CompareVersions(v, e.LastAffected) > 0 {
				in = false
			}
		}
	}
	return in, fix
}

// OSVSync keeps a copy of one ecosystem's OSV records: after one whole
// download, it reads the modified list and fetches every record that
// changed, all of them and never only the fleet's, so the requests say
// nothing about what the fleet runs.
type OSVSync struct {
	Fetcher   *Fetcher
	Base      string // https://osv-vulnerabilities.storage.googleapis.com
	Ecosystem string // Ubuntu, Debian
	Dir       string // <Dir>/<id>.json
	// Max caps the records fetched in one sync; the rest come next time.
	Max int
}

var osvIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Sync brings the copy up to date and returns how many records it fetched.
// The first sync of an empty copy takes only the last day's changes; load
// the whole set with Load first.
func (s *OSVSync) Sync(ctx context.Context) (int, error) {
	list := "osv-" + strings.ToLower(s.Ecosystem) + "-modified.csv"
	if _, err := s.Fetcher.Get(ctx, list, s.Base+"/"+s.Ecosystem+"/modified_id.csv", 256<<20); err != nil {
		return 0, err
	}
	since := s.last()
	if since.IsZero() {
		since = time.Now().Add(-24 * time.Hour)
	}
	f, err := s.Fetcher.Open(list)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	type change struct {
		at time.Time
		id string
	}
	var todo []change
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		at, id, ok := strings.Cut(sc.Text(), ",")
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, at)
		if err != nil || !osvIDRe.MatchString(id) {
			continue
		}
		if !t.After(since) {
			break // newest first: the rest are older
		}
		todo = append(todo, change{t, id})
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	sort.Slice(todo, func(i, j int) bool { return todo[i].at.Before(todo[j].at) }) // oldest first, so last() moves forward
	max := s.Max
	if max == 0 {
		max = 5000
	}
	n := 0
	for _, c := range todo {
		if n >= max {
			break
		}
		fetcher := &Fetcher{Dir: s.Dir, Client: s.Fetcher.Client}
		if _, err := fetcher.Get(ctx, c.id+".json", s.Base+"/"+s.Ecosystem+"/"+c.id+".json", 16<<20); err != nil {
			return n, fmt.Errorf("lookout: OSV record %s: %w", c.id, err)
		}
		os.Remove(filepath.Join(s.Dir, c.id+".json.meta")) // records are fetched by time, not by ETag
		if err := s.setLast(c.at); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (s *OSVSync) last() time.Time {
	b, err := os.ReadFile(filepath.Join(s.Dir, ".last"))
	if err != nil {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
	return t
}

func (s *OSVSync) setLast(t time.Time) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.Dir, ".last"), []byte(t.UTC().Format(time.RFC3339Nano)+"\n"), 0o600)
}

// Match reads every kept record and says what each is on the machines.
func (s *OSVSync) Match(ms []Machine) ([]Finding, error) {
	files, err := filepath.Glob(filepath.Join(s.Dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, file := range files {
		fh, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		var r OSVRecord
		err = json.NewDecoder(io.LimitReader(fh, 16<<20)).Decode(&r)
		fh.Close()
		if err != nil {
			continue // a record that doesn't parse says nothing
		}
		out = append(out, r.Match(ms)...)
	}
	SortFindings(out)
	return out, nil
}
