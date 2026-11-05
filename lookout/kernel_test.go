package lookout

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// The kernel's record of CVE-2026-98432 (testdata/vulns-CVE-2026-98432.json,
// from vulns.git): its title, the two files the fix touches, a network
// vector, introduced in 4.4, the first fixed release of each stable series,
// and mainline's.
func TestParseKernelCVE(t *testing.T) {
	c, err := ParseKernelCVE(read(t, "vulns-CVE-2026-98432.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixed []string
	for s, v := range c.Fixed {
		fixed = append(fixed, s+":"+v)
	}
	sort.Strings(fixed)
	want := "5.10:5.10.272 5.15:5.15.223 6.12:6.12.113 6.18:6.18.56 6.1:6.1.190 6.6:6.6.159 7.2:7.2.10" // sorted as text
	switch {
	case c.ID != "CVE-2026-98432" || !strings.HasPrefix(c.Title, "ipv4: free inet_opt and ireq_opt"):
		t.Errorf("id %q, title %q", c.ID, c.Title)
	case strings.Join(c.Files, " ") != "net/ipv4/af_inet.c net/ipv4/tcp_ipv4.c":
		t.Errorf("files %v", c.Files)
	case c.Introduced != "4.4" || c.Mainline != "7.3" || strings.Join(fixed, " ") != want:
		t.Errorf("introduced %q, mainline %q, fixed %s", c.Introduced, c.Mainline, strings.Join(fixed, " "))
	case !c.Network():
		t.Errorf("not a network flaw: %q", c.Vector)
	}
	if _, err := ParseKernelCVE([]byte(`{"cveMetadata":{"cveId":"CVE-2026-0001","state":"REJECTED"}}`)); err == nil {
		t.Error("a rejected record")
	}
}

// What the record says of upstream releases: before 4.4 not affected; in a
// series with a fix, affected below it and fixed at or after it; in a
// series with none (6.8, 5.4), affected until mainline's 7.3; at or after
// 7.3, not.
func TestKernelStatus(t *testing.T) {
	c, err := ParseKernelCVE(read(t, "vulns-CVE-2026-98432.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		release  string
		affected bool
		fix      string
	}{
		{"4.3.21", false, ""}, {"4.4", true, "7.3"}, {"5.4.300", true, "7.3"},
		{"6.1.180", true, "6.1.190"}, {"6.1.190", false, ""}, {"6.1.201", false, ""},
		{"6.8.12", true, "7.3"}, {"6.12.112", true, "6.12.113"}, {"7.2.9", true, "7.2.10"},
		{"7.3", false, ""}, {"7.3.1", false, ""}, {"7.4", false, ""},
		{"6.1.180-1", true, "6.1.190"}, // a Debian package's version: the upstream part
	} {
		a, f := c.Status(x.release)
		if a != x.affected || f != x.fix {
			t.Errorf("%s: affected %v, fix %q; want %v, %q", x.release, a, f, x.affected, x.fix)
		}
	}
}

// A copy of vulns.git (here a local repository): at the first sync every
// record is old; records published after it are new, for KernelNewWindow,
// and only those a network can reach go on the page; a record gone from the
// published ones is left out; a copy a day old is a problem.
func TestKernelVulnsNew(t *testing.T) {
	needGit(t)
	src, dir := t.TempDir(), t.TempDir()
	gitIn(t, src, "init", "-q")
	rec := read(t, "vulns-CVE-2026-98432.json")
	put := func(id string, b []byte) {
		p := filepath.Join(src, "cve", "published", id[4:8], id+".json")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("CVE-2026-98432", rec)
	gitIn(t, src, "add", "-A")
	gitIn(t, src, "commit", "-q", "-m", "one")
	f := &Feeds{Dir: dir, Fetcher: &Fetcher{Dir: filepath.Join(dir, "feeds")},
		Kernel: &KernelVulns{Dir: filepath.Join(dir, "vulns.git"), Remote: "file://" + src}}
	ctx := context.Background()
	if err := f.Kernel.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if news, err := f.KernelNew(ctx, now); err != nil || len(news) != 0 {
		t.Fatalf("new at the first sync: %v %v", news, err)
	}
	local := strings.Replace(string(rec), "CVSS:3.1/AV:N/", "CVSS:3.1/AV:L/", 1)
	put("CVE-2026-0001", []byte(strings.Replace(string(rec), "CVE-2026-98432", "CVE-2026-0001", -1)))
	put("CVE-2026-0002", []byte(strings.Replace(local, "CVE-2026-98432", "CVE-2026-0002", -1)))
	put("CVE-2026-0003", []byte(strings.Replace(string(rec), "CVE-2026-98432", "CVE-2026-0003", -1)))
	gitIn(t, src, "add", "-A")
	gitIn(t, src, "commit", "-q", "-m", "two")
	if err := f.Kernel.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	gitIn(t, src, "rm", "-q", "cve/published/2026/CVE-2026-0003.json") // rejected after it was seen
	gitIn(t, src, "commit", "-q", "-m", "three")
	if err := f.Kernel.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	news, err := f.KernelNew(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(news) != 1 || news[0].ID != "CVE-2026-0001" || news[0].FirstSeen.IsZero() {
		t.Fatalf("new and reachable over a network: %+v", news)
	}
	all, err := f.Kernel.New(ctx, now.Add(-time.Hour))
	if err != nil || len(all) != 2 {
		t.Fatalf("new: %d, %v", len(all), err)
	}
	if news, err := f.KernelNew(ctx, now.Add(KernelNewWindow+time.Hour)); err != nil || len(news) != 0 {
		t.Errorf("past the window: %v %v", news, err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "kernel-new.json")); err != nil || !strings.Contains(string(b), "[]") && !strings.Contains(string(b), "null") {
		t.Errorf("the page's list after the window: %s %v", b, err)
	}
	stale := false
	for _, p := range f.Problems(time.Now().Add(StaleFeed + time.Hour)) {
		stale = stale || strings.HasPrefix(p, "the kernel's vulns.git: the copy is")
	}
	if !stale {
		t.Error("a day-old copy of vulns.git isn't a problem")
	}
}

// vulns.git comes over https.
func TestKernelVulnsOverHTTPS(t *testing.T) {
	if !strings.HasPrefix(KernelVulnsURL, "https://") || (&KernelVulns{}).copy().remote != KernelVulnsURL {
		t.Fatal(KernelVulnsURL)
	}
}

// Against a real copy of vulns.git (VULNS_COPY, a bare clone made by Sync):
// CVE-2026-98432's record reads.
func TestKernelVulnsReal(t *testing.T) {
	dir := os.Getenv("VULNS_COPY")
	if dir == "" {
		t.Skip("set VULNS_COPY to a copy of the kernel's vulns.git")
	}
	b, found, err := (&KernelVulns{Dir: dir}).copy().blob(context.Background(), "cve/published/2026/CVE-2026-98432.json", 4<<20)
	if err != nil || !found {
		t.Fatalf("%v %v", found, err)
	}
	c, err := ParseKernelCVE(b)
	if err != nil || !c.Network() || c.Fixed["6.1"] == "" {
		t.Fatalf("%+v %v", c, err)
	}
}

// A distro's version is read only as far as its upstream part: Ubuntu's
// "6.8.0-149.149" is 6.8.0, not 6.8.0.149.
func TestVersionParts(t *testing.T) {
	for v, want := range map[string]string{"6.8.0-149.149": "[6 8 0]", "6.1.180-1": "[6 1 180]", "7.3": "[7 3]", "5.10.272": "[5 10 272]", "x": "[]"} {
		if got := fmt.Sprint(versionParts(v)); got != want {
			t.Errorf("%s: %s, want %s", v, got, want)
		}
	}
}

// A file in a copy past the size given is an error, not read.
func TestGitCopyLimit(t *testing.T) {
	needGit(t)
	src, dir := t.TempDir(), t.TempDir()
	gitIn(t, src, "init", "-q")
	if err := os.WriteFile(filepath.Join(src, "big"), make([]byte, 5000), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, src, "add", "-A")
	gitIn(t, src, "commit", "-q", "-m", "one")
	g := gitCopy{dir: filepath.Join(dir, "c.git"), remote: "file://" + src}
	if err := g.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.blob(context.Background(), "big", 4096); err == nil {
		t.Error("a file past the limit was read")
	}
	if b, found, err := g.blob(context.Background(), "big", 8192); err != nil || !found || len(b) != 5000 {
		t.Errorf("under the limit: %d %v %v", len(b), found, err)
	}
}
