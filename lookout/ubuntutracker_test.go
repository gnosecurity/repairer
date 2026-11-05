package lookout

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// statusSet is a package's statuses as "release status (description)".
func statusSet(c *UbuntuCVE, pkg string) []string {
	var out []string
	for _, p := range c.Packages {
		if p.Name == pkg {
			for _, s := range p.Statuses {
				out = append(out, s.Codename+" "+s.Status+" ("+s.Description+")")
			}
		}
	}
	sort.Strings(out)
	return out
}

// The tracker's record of CVE-2026-98432 (testdata/uct-CVE-2026-98432, cut
// from the real one) says what Ubuntu's JSON for it says (made from it):
// for each release its first status that isn't "ignored" among its own
// line and its ESM pockets' (focal, past standard support, is "needed" by
// esm-infra/focal), no development release, upstream kept.
func TestParseTrackerAgreesWithUbuntusJSON(t *testing.T) {
	c, err := ParseTracker("CVE-2026-98432", read(t, "uct-CVE-2026-98432"))
	if err != nil {
		t.Fatal(err)
	}
	j, err := ParseUbuntuCVE(read(t, "ubuntu-cve-2026-98432.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(statusSet(c, "linux"), "\n"), strings.Join(statusSet(j, "linux"), "\n"); got != want {
		t.Errorf("linux from the tracker:\n%s\nfrom the JSON:\n%s", got, want)
	}
	if c.Priority != "critical" || c.ID != "CVE-2026-98432" {
		t.Errorf("priority %q, id %q", c.Priority, c.ID)
	}
	hwe := strings.Join(statusSet(c, "linux-hwe-6.8"), "\n")
	if !strings.Contains(hwe, "jammy pending (6.8.0-149.149~22.04.1)") || !strings.Contains(hwe, "noble DNE ()") || strings.Contains(hwe, "devel") {
		t.Errorf("linux-hwe-6.8:\n%s", hwe)
	}
}

// Lines that aren't a release's status are skipped: a package's own
// priority, its patches and tags; a pocket can't override a status that
// isn't "ignored"; a record filed under another name is refused.
func TestParseTrackerLines(t *testing.T) {
	c, err := ParseTracker("CVE-2026-1", []byte(strings.Join([]string{
		"Candidate: CVE-2026-1",
		"Priority: high",
		"Priority_openssl: low",
		"Patches_openssl:",
		" upstream: https://example.org/fix",
		"Tags_openssl: apparmor",
		"noble_openssl: released (3.0.13-0ubuntu3.6)",
		"esm-apps/noble_openssl: needed",
		"focal_openssl: ignored (end of standard support)",
		"esm-infra/focal_openssl: pending (1.1.1f-1ubuntu2.25)",
		"devel_openssl: needs-triage",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(statusSet(c, "openssl"), "|")
	if want := "focal pending (1.1.1f-1ubuntu2.25)|noble released (3.0.13-0ubuntu3.6)"; got != want || c.Priority != "high" || len(c.Packages) != 1 {
		t.Errorf("got %q, priority %q, %d packages", got, c.Priority, len(c.Packages))
	}
	if _, err := ParseTracker("CVE-2026-2", []byte("Candidate: CVE-2026-1\n")); err == nil {
		t.Error("a record filed under another name")
	}
}

// git runs git in dir for a test, or skips the test where git isn't.
func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func needGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git isn't installed")
	}
}

// A tracker published by Ubuntu as a git repository (here a local one):
// the first sync clones it bare, one commit deep; a later one fetches what
// changed; a record is read from active/ and, once retired, from retired/;
// a flaw it doesn't know is nil, a name that isn't a CVE's is refused, and
// the sync's time is kept beside the copy.
func TestUbuntuTrackerSync(t *testing.T) {
	needGit(t)
	src, dir := t.TempDir(), t.TempDir()
	gitIn(t, src, "init", "-q")
	if err := os.MkdirAll(filepath.Join(src, "active"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := read(t, "uct-CVE-2026-98432")
	write := func(path string, b []byte) {
		if err := os.WriteFile(filepath.Join(src, path), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("active/CVE-2026-98432", rec)
	gitIn(t, src, "add", "-A")
	gitIn(t, src, "commit", "-q", "-m", "one")
	u := &UbuntuTracker{Dir: filepath.Join(dir, "uct.git"), Remote: "file://" + src}
	ctx := context.Background()
	if _, err := u.Record(ctx, "CVE-2026-98432"); err == nil {
		t.Error("a record read before any copy")
	}
	if err := u.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	noble := func() string {
		t.Helper()
		c, err := u.Record(ctx, "CVE-2026-98432")
		if err != nil || c == nil {
			t.Fatalf("the record: %v %v", c, err)
		}
		for _, s := range statusSet(c, "linux") {
			if strings.HasPrefix(s, "noble ") {
				return s
			}
		}
		return ""
	}
	if s := noble(); s != "noble pending (6.8.0-149.149)" {
		t.Fatalf("after the clone: %q", s)
	}
	write("active/CVE-2026-98432", []byte(strings.Replace(string(rec), "noble_linux: pending (6.8.0-149.149)", "noble_linux: released (6.8.0-149.149)", 1)))
	gitIn(t, src, "commit", "-q", "-a", "-m", "two")
	if err := u.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if s := noble(); s != "noble released (6.8.0-149.149)" {
		t.Fatalf("after the fetch: %q", s)
	}
	if err := os.MkdirAll(filepath.Join(src, "retired"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitIn(t, src, "mv", "active/CVE-2026-98432", "retired/CVE-2026-98432")
	gitIn(t, src, "commit", "-q", "-m", "three")
	if err := u.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if s := noble(); s != "noble released (6.8.0-149.149)" {
		t.Fatalf("once retired: %q", s)
	}
	if c, err := u.Record(ctx, "CVE-2026-99999"); c != nil || err != nil {
		t.Errorf("a flaw the tracker doesn't know: %v %v", c, err)
	}
	if _, err := u.Record(ctx, "../../etc/passwd"); err == nil {
		t.Error("a name that isn't a CVE's")
	}
	if b, err := os.ReadFile(u.Synced()); err != nil || !strings.HasPrefix(string(b), time.Now().UTC().Format("2006-01-02")) {
		t.Errorf("the sync's time: %q %v", b, err)
	}
	// A broken copy is an error, not a flaw Ubuntu doesn't know.
	if err := os.RemoveAll(filepath.Join(u.Dir, "objects")); err != nil {
		t.Fatal(err)
	}
	if c, err := u.Record(ctx, "CVE-2026-98432"); err == nil {
		t.Errorf("a broken copy read as %v", c)
	}
}

// Find reads Ubuntu's own records from the tracker's copy: the flaw a kept
// guard is for comes out as it does from Ubuntu's JSON (a fix pending on
// noble, the end of 25.04's support), with no file in <Dir>/ubuntu-cves;
// and a copy a day old is a problem.
func TestFeedsReadTheTracker(t *testing.T) {
	needGit(t)
	src, dir := t.TempDir(), t.TempDir()
	gitIn(t, src, "init", "-q")
	if err := os.MkdirAll(filepath.Join(src, "active"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "active", "CVE-2026-98432"), read(t, "uct-CVE-2026-98432"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, src, "add", "-A")
	gitIn(t, src, "commit", "-q", "-m", "one")
	f := &Feeds{Dir: dir, Fetcher: &Fetcher{Dir: filepath.Join(dir, "feeds")},
		Tracker: &UbuntuTracker{Dir: filepath.Join(dir, "uct.git"), Remote: "file://" + src}}
	if err := f.Tracker.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	ms, err := ReadMachines(read(t, "machines-2026-11-04.json"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := f.Find(ms, []string{"CVE-2026-98432"}, time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, x := range fs {
		if x.Flaw == "CVE-2026-98432" {
			states[x.Host] = x.State
		}
	}
	if states["u2404-b"] != FixPending || states["u2504-a"] != ReleaseEnded {
		t.Fatalf("noble %q, plucky %q (all %v)", states["u2404-b"], states["u2504-a"], states)
	}
	later := time.Now().Add(StaleFeed + time.Hour)
	stale := false
	for _, p := range f.Problems(later) {
		if strings.HasPrefix(p, "Ubuntu's tracker: the copy is") {
			stale = true
		}
	}
	if !stale {
		t.Errorf("a day-old copy of the tracker isn't a problem: %v", f.Problems(later))
	}
}

// The tracker's versions decide findings and a guard's end, so the copy
// comes over https, whose server is checked, never git://.
func TestTrackerOverHTTPS(t *testing.T) {
	if !strings.HasPrefix(UbuntuTrackerURL, "https://") || (&UbuntuTracker{}).remote() != UbuntuTrackerURL {
		t.Fatalf("the tracker comes from %q", (&UbuntuTracker{}).remote())
	}
}

// Against a real copy of Ubuntu's tracker (UCT_COPY, a bare clone made by
// Sync): CVE-2026-98432's record reads, with the kernel pending on noble.
func TestUbuntuTrackerReal(t *testing.T) {
	dir := os.Getenv("UCT_COPY")
	if dir == "" {
		t.Skip("set UCT_COPY to a copy of Ubuntu's tracker")
	}
	c, err := (&UbuntuTracker{Dir: dir}).Record(context.Background(), "CVE-2026-98432")
	if err != nil || c == nil {
		t.Fatalf("%v %v", c, err)
	}
	found := false
	for _, s := range statusSet(c, "linux") {
		found = found || strings.HasPrefix(s, "noble pending (") || strings.HasPrefix(s, "noble released (")
	}
	if !found || len(c.Packages) < 10 {
		t.Fatalf("%d packages; linux: %v", len(c.Packages), statusSet(c, "linux"))
	}
	t.Logf("%d packages; linux: %v", len(c.Packages), statusSet(c, "linux"))
}
