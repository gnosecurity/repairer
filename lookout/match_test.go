package lookout

import (
	"os"
	"strings"
	"testing"
	"time"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The build spec's first test for the lookout: with the 11-04 audit as
// fixtures (machine names replaced; the repo is public), it names the right
// machines for CVE-2026-98432. On 11-04 Ubuntu's fixed kernels were only in
// -proposed, so every machine on a supported release was exposed with its
// fix pending, and the 25.04 machine, past its end of support, would never
// get one.
func TestCVE202698432On1104(t *testing.T) {
	ms, err := ReadMachines(read(t, "machines-2026-11-04.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseUbuntuCVE(read(t, "ubuntu-cve-2026-98432.json"))
	if err != nil {
		t.Fatal(err)
	}
	fs := c.Match(ms, time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC))
	got := Summary(fs)
	want := FixPending + ": u2204-a u2404-a u2404-b u2404-c u2404-d u2404-e u2404-f u2404-g u2404-h u2604-a u2604-b u2604-c u2604-d\n" +
		ReleaseEnded + ": u2504-a\n"
	if got != want {
		t.Fatalf("got\n%swant\n%s", got, want)
	}
	for _, f := range fs {
		if !f.Exposed || f.Package != "linux" {
			t.Errorf("%+v", f)
		}
		if f.Host == "u2404-b" && (f.Fix != "6.8.0-149.149" || f.Version != "6.8.0-142.142") {
			t.Errorf("noble's fix: %+v", f)
		}
	}
}

// The same machines on the day the fixes were released: a machine whose
// newest installed kernel is fixed owes a reboot, one running it is fixed,
// and the rest have a fix available.
func TestKernelStates(t *testing.T) {
	ms, err := ReadMachines(read(t, "machines-2026-11-04.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseUbuntuCVE([]byte(strings.ReplaceAll(string(read(t, "ubuntu-cve-2026-98432.json")), `"pending"`, `"released"`)))
	if err != nil {
		t.Fatal(err)
	}
	ms[0].Kernel.Installed = append(ms[0].Kernel.Installed, "5.15.0-203.213") // u2204-a installed the fix
	for i := range ms {
		if ms[i].Host == "u2604-a" {
			ms[i].Kernel.Running = "7.0.0-43.43" // and u2604-a rebooted into it
		}
	}
	states := map[string]string{}
	for _, f := range c.Match(ms, time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)) {
		states[f.Host] = f.State
	}
	for host, want := range map[string]string{"u2204-a": RebootOwed, "u2604-a": Fixed, "u2404-b": FixAvailable, "u2504-a": ReleaseEnded} {
		if states[host] != want {
			t.Errorf("%s: %q, want %q", host, states[host], want)
		}
	}
}

// Debian's tracker, read as a stream: a bookworm machine below the fixed
// kernel has a fix available, one that installed it owes a reboot; a
// package the tracker marks never affected is left out; an open flaw has no
// fix yet. CISA's list marks what is exploited.
func TestDebian(t *testing.T) {
	f, err := os.Open("testdata/debian-tracker-small.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := ReadDebianTracker(f, map[string]bool{"CVE-2026-98432": true, "CVE-2099-0001": true})
	if err != nil {
		t.Fatal(err)
	}
	ms, err := ReadMachines([]byte(`[
		{"host":"d12-a","os":{"id":"debian","version":"12","codename":"bookworm","eol":"2028-06-30"},
		 "kernel":{"running":"6.1.180-1","installed":["6.1.180-1"]},"packages":[{"source":"openssl","version":"3.0.15-1~deb12u1"}]},
		{"host":"d12-b","os":{"id":"debian","version":"12","codename":"bookworm","eol":"2028-06-30"},
		 "kernel":{"running":"6.1.180-1","installed":["6.1.180-1","6.1.190-1"]}},
		{"host":"d13-a","os":{"id":"debian","version":"13","codename":"trixie","eol":"2030-08-09"},
		 "kernel":{"running":"6.12.115-2","installed":["6.12.115-2"]}}]`))
	if err != nil {
		t.Fatal(err)
	}
	fs := d.Match(ms, time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	KEV{"CVE-2099-0001": true}.Mark(fs)
	got := map[string]string{}
	for _, f := range fs {
		got[f.Host+" "+f.Flaw+" "+f.Package] = f.State
		if f.Flaw == "CVE-2099-0001" && !f.Exploited {
			t.Errorf("not marked exploited: %+v", f)
		}
	}
	want := map[string]string{
		"d12-a CVE-2026-98432 linux": FixAvailable,
		"d12-b CVE-2026-98432 linux": RebootOwed,
		"d13-a CVE-2026-98432 linux": Fixed,
		"d12-a CVE-2099-0001 linux":  NoFixYet,
		"d12-b CVE-2099-0001 linux":  NoFixYet,
		"d13-a CVE-2099-0001 linux":  Unknown, // the tracker doesn't list trixie for it
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("extra findings: %v", got)
	}
}

// With DEBIAN_TRACKER set to the real tracker file (about 88 MB), the
// stream reader finds the kernel's entry without holding the file.
func TestDebianTrackerReal(t *testing.T) {
	path := os.Getenv("DEBIAN_TRACKER")
	if path == "" {
		t.Skip("set DEBIAN_TRACKER to the tracker's JSON")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := ReadDebianTracker(f, map[string]bool{"CVE-2026-98432": true})
	if err != nil {
		t.Fatal(err)
	}
	if got := d["CVE-2026-98432"]["linux"].Releases["bookworm"].FixedVersion; got != "6.1.190-1" {
		t.Fatalf("bookworm's fixed kernel %q", got)
	}
}
