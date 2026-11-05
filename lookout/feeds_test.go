package lookout

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The fetcher asks only for what changed: a second fetch of an unchanged
// feed is answered 304 and keeps the copy; a feed too big is refused and
// the old copy stays.
func TestFetcher(t *testing.T) {
	var mu sync.Mutex
	body, etag, asked := "v1", `"a"`, []string{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, r.Header.Get("If-None-Match")+"|"+r.Header.Get("User-Agent"))
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		fmt.Fprint(w, body)
	}))
	defer ts.Close()
	f := &Fetcher{Dir: t.TempDir()}
	ctx := context.Background()
	if changed, err := f.Get(ctx, "kev.json", ts.URL, 100); err != nil || !changed {
		t.Fatal(changed, err)
	}
	if changed, err := f.Get(ctx, "kev.json", ts.URL, 100); err != nil || changed {
		t.Fatalf("an unchanged feed: %v %v", changed, err)
	}
	mu.Lock()
	body, etag = strings.Repeat("x", 200), `"b"`
	mu.Unlock()
	if _, err := f.Get(ctx, "kev.json", ts.URL, 100); err == nil {
		t.Fatal("a feed over its cap")
	}
	if b, _ := os.ReadFile(f.Path("kev.json")); string(b) != "v1" {
		t.Fatalf("the old copy was lost: %q", b)
	}
	if !strings.Contains(asked[1], `"a"|Go-http-client/1.1`) {
		t.Fatalf("requests %q", asked)
	}
	if _, err := f.Get(ctx, "../etc/passwd", ts.URL, 100); err == nil {
		t.Fatal("a feed name with a path")
	}
}

func machines(t *testing.T) []Machine {
	ms, err := ReadMachines([]byte(`[
		{"host":"noble-a","os":{"id":"ubuntu","version":"24.04","codename":"noble","eol":"2029-05-31"},
		 "kernel":{"running":"6.8.0-142.142","installed":["6.8.0-142.142"]},"packages":[{"source":"openssl","version":"3.0.13-0ubuntu3.5"}]},
		{"host":"noble-b","os":{"id":"ubuntu","version":"24.04","codename":"noble","eol":"2029-05-31"},
		 "kernel":{"running":"6.8.0-142.142","installed":["6.8.0-142.142","6.8.0-149.149"]}},
		{"host":"questing","os":{"id":"ubuntu","version":"25.10","codename":"questing","eol":"2026-07-09"},
		 "kernel":{"running":"6.17.0-20.20","installed":["6.17.0-20.20"]}},
		{"host":"d12","os":{"id":"debian","version":"12.11","codename":"bookworm","eol":"2028-06-30"},
		 "kernel":{"running":"6.1.180-1","installed":["6.1.180-1"]}}]`))
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

// OSV records: a range with a fix gives fix available (or a reboot owed
// when the fix is installed but not running); a range without one gives no
// fix yet; machines are matched by their own ecosystem.
func TestOSVMatch(t *testing.T) {
	ms := machines(t)
	if ms[0].Ecosystem() != "Ubuntu:24.04:LTS" || ms[2].Ecosystem() != "Ubuntu:25.10" || ms[3].Ecosystem() != "Debian:12" {
		t.Fatalf("ecosystems %s %s %s", ms[0].Ecosystem(), ms[2].Ecosystem(), ms[3].Ecosystem())
	}
	var fixed, open OSVRecord
	if err := jsonUnmarshal(`{"id":"UBUNTU-CVE-2026-98432","upstream":["CVE-2026-98432"],"affected":[
		{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.8.0-149.149"}]}]},
		{"package":{"ecosystem":"Debian:12","name":"linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.1.190-1"}]}]}]}`, &fixed); err != nil {
		t.Fatal(err)
	}
	if err := jsonUnmarshal(`{"id":"UBUNTU-CVE-2099-1","aliases":["CVE-2099-1"],"affected":[
		{"package":{"ecosystem":"Ubuntu:25.10","name":"linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]},
		{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"openssl"},"versions":["3.0.13-0ubuntu3.5"]}]}`, &open); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range append(fixed.Match(ms), open.Match(ms)...) {
		got[f.Host+" "+f.Flaw+" "+f.Package] = f.State
	}
	want := map[string]string{
		"noble-a CVE-2026-98432 linux": FixAvailable,
		"noble-b CVE-2026-98432 linux": RebootOwed,
		"d12 CVE-2026-98432 linux":     FixAvailable,
		"questing CVE-2099-1 linux":    NoFixYet,
		"noble-a CVE-2099-1 openssl":   NoFixYet,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("findings %v", got)
	}
}

// The sync reads the modified list (newest first) and fetches every record
// changed since its last sync, oldest first, and no other.
func TestOSVSync(t *testing.T) {
	now := time.Now().UTC()
	list := fmt.Sprintf("%s,REC-3\n%s,REC-2\n%s,REC-1\n",
		now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(-2*time.Hour).Format(time.RFC3339Nano), now.Add(-48*time.Hour).Format(time.RFC3339Nano))
	var mu sync.Mutex
	var fetched []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/Ubuntu/modified_id.csv":
			fmt.Fprint(w, list)
		default:
			fetched = append(fetched, r.URL.Path)
			fmt.Fprintf(w, `{"id":%q}`, strings.TrimSuffix(filepath.Base(r.URL.Path), ".json"))
		}
	}))
	defer ts.Close()
	dir := t.TempDir()
	s := &OSVSync{Fetcher: &Fetcher{Dir: filepath.Join(dir, "feeds")}, Base: ts.URL, Ecosystem: "Ubuntu", Dir: filepath.Join(dir, "osv-ubuntu")}
	n, err := s.Sync(context.Background())
	if err != nil || n != 2 || strings.Join(fetched, " ") != "/Ubuntu/REC-2.json /Ubuntu/REC-3.json" {
		t.Fatalf("first sync: %d %v %v", n, err, fetched)
	}
	fetched = nil
	if n, err := s.Sync(context.Background()); err != nil || n != 0 || len(fetched) != 0 {
		t.Fatalf("nothing new: %d %v %v", n, err, fetched)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "REC-3.json")); err != nil {
		t.Fatal(err)
	}
}

// The hourly feed step against stand-in feeds: OSV says CVE-2026-98432 has
// no fix for noble, but Ubuntu's own record (present locally; the lookout
// never fetches one flaw's record because it matters here) knows the fix
// is in -proposed, and wins; CISA's list marks an exploited flaw, which
// comes first. Every request is the same whatever the fleet runs.
func TestFeedsRefreshAndFind(t *testing.T) {
	now := time.Now().UTC()
	ubuntuCVE := read(t, "ubuntu-cve-2026-98432.json")
	debian := read(t, "debian-tracker-small.json")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev":
			fmt.Fprint(w, `{"vulnerabilities":[{"cveID":"CVE-2099-7"}]}`)
		case "/debian":
			w.Write(debian)
		case "/osv/Ubuntu/modified_id.csv":
			fmt.Fprintf(w, "%s,UBUNTU-CVE-2026-98432\n%s,UBUNTU-CVE-2099-7\n", now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(-2*time.Minute).Format(time.RFC3339Nano))
		case "/osv/Debian/modified_id.csv":
			fmt.Fprint(w, "")
		case "/osv/Ubuntu/UBUNTU-CVE-2026-98432.json":
			fmt.Fprint(w, `{"id":"UBUNTU-CVE-2026-98432","upstream":["CVE-2026-98432"],"affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`)
		case "/osv/Ubuntu/UBUNTU-CVE-2099-7.json":
			fmt.Fprint(w, `{"id":"UBUNTU-CVE-2099-7","upstream":["CVE-2099-7"],"affected":[{"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.15.0-300.300"}]}]}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	dir := t.TempDir()
	var paths []string
	ts.Config.Handler = logPaths(ts.Config.Handler, &paths)
	f := &Feeds{Dir: dir, Fetcher: &Fetcher{Dir: filepath.Join(dir, "feeds")},
		KEV: ts.URL + "/kev", Debian: ts.URL + "/debian", OSV: ts.URL + "/osv"}
	if err := os.MkdirAll(filepath.Join(dir, "ubuntu-cves"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ubuntu-cves", "CVE-2026-98432.json"), ubuntuCVE, 0o600); err != nil {
		t.Fatal(err)
	}
	store := &Store{Dir: filepath.Join(dir, "store")}
	if _, err := store.AddGuard(read(t, "cve-2026-98432-ipopt.json")); err != nil {
		t.Fatal(err)
	}
	ms, err := ReadMachines(read(t, "machines-2026-11-04.json"))
	if err != nil {
		t.Fatal(err)
	}
	if errs := f.Refresh(context.Background()); len(errs) != 0 {
		t.Fatal(errs)
	}
	watch := f.Watch(store, ms)
	if strings.Join(watch, " ") != "CVE-2026-98432 CVE-2099-7" {
		t.Fatalf("watch %v", watch)
	}
	for _, p := range paths {
		if strings.Contains(p, "CVE-2026-98432") && !strings.HasPrefix(p, "/osv/") {
			t.Fatalf("a request named a flaw that matters here: %s", p)
		}
	}
	fs, err := f.Find(ms, watch, time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 || fs[0].Flaw != "CVE-2099-7" || !fs[0].Exploited || fs[0].Host != "u2204-a" {
		t.Fatalf("the exploited flaw first: %+v", fs[:min(len(fs), 1)])
	}
	states := map[string]string{}
	for _, x := range fs {
		if x.Flaw == "CVE-2026-98432" {
			states[x.Host] = x.State
		}
	}
	if states["u2404-b"] != FixPending || states["u2504-a"] != ReleaseEnded {
		t.Fatalf("noble %q, plucky %q", states["u2404-b"], states["u2504-a"])
	}
	kept, err := f.Findings()
	if err != nil || len(kept) != len(fs) {
		t.Fatalf("kept %d of %d: %v", len(kept), len(fs), err)
	}
}

func logPaths(h http.Handler, paths *[]string) http.Handler {
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*paths = append(*paths, r.URL.Path)
		mu.Unlock()
		h.ServeHTTP(w, r)
	})
}

// An OSV record that fails with anything but a 404 is tried once more, then
// skipped and listed, so it can't stall every record after it (round 8,
// minor 8).
func TestOSVSkipsARecordThatFailsTwice(t *testing.T) {
	now := time.Now().UTC()
	list := fmt.Sprintf("%s,REC-3\n%s,REC-2\n", now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(-2*time.Hour).Format(time.RFC3339Nano))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Ubuntu/modified_id.csv":
			fmt.Fprint(w, list)
		case "/Ubuntu/REC-2.json":
			http.Error(w, "no", http.StatusForbidden)
		default:
			fmt.Fprintf(w, `{"id":%q}`, strings.TrimSuffix(filepath.Base(r.URL.Path), ".json"))
		}
	}))
	defer ts.Close()
	dir := t.TempDir()
	f := &Feeds{Dir: dir, Fetcher: &Fetcher{Dir: filepath.Join(dir, "copies")}, OSV: ts.URL}
	s := f.osv("Ubuntu")
	if n, err := s.Sync(context.Background()); err == nil || n != 0 {
		t.Fatalf("the first failure: %d %v", n, err)
	}
	if n, err := s.Sync(context.Background()); err != nil || n != 2 {
		t.Fatalf("the second: %d %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "REC-3.json")); err != nil {
		t.Fatal("the record after the failing one wasn't fetched")
	}
	if sk := s.Skipped(); len(sk) != 1 || sk[0].ID != "REC-2" {
		t.Fatalf("skipped %+v", sk)
	}
	found := false
	for _, p := range f.Problems(time.Now()) {
		found = found || strings.Contains(p, "record REC-2 skipped")
	}
	if !found {
		t.Fatalf("not listed: %v", f.Problems(time.Now()))
	}
}

// A feed whose copy is more than a day old is a problem the page shows; a
// copy the feed says is current (304) counts as fresh (round 8, minor 8).
func TestFeedProblems(t *testing.T) {
	dir := t.TempDir()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprint(w, `{"vulnerabilities":[]}`)
	}))
	defer ts.Close()
	f := &Feeds{Dir: dir, Fetcher: &Fetcher{Dir: filepath.Join(dir, "copies")}, KEV: ts.URL}
	if _, err := f.Fetcher.Get(context.Background(), "kev.json", ts.URL, 1<<20); err != nil {
		t.Fatal(err)
	}
	stale := func() bool {
		for _, p := range f.Problems(time.Now()) {
			if strings.HasPrefix(p, "CISA's list: the copy is") {
				return true
			}
		}
		return false
	}
	if stale() {
		t.Fatal("a fresh copy counted as stale")
	}
	old := time.Now().Add(-48 * time.Hour)
	os.Chtimes(filepath.Join(dir, "copies", "kev.json"), old, old)
	if !stale() {
		t.Fatalf("a copy two days old: %v", f.Problems(time.Now()))
	}
	if _, err := f.Fetcher.Get(context.Background(), "kev.json", ts.URL, 1<<20); err != nil { // 304
		t.Fatal(err)
	}
	if stale() {
		t.Fatal("a copy the feed says is current still counted as stale")
	}
	never := false
	for _, p := range f.Problems(time.Now()) {
		never = never || p == "Debian's tracker: never fetched"
	}
	if !never {
		t.Fatalf("a feed never fetched: %v", f.Problems(time.Now()))
	}
}
