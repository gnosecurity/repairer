package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jaekwon/autopatch/guard"
)

// Report is what an agent tells its lookout about its machine: the facts
// behind November's failures (fixes installed but not running, updates that
// stopped, a release past its end, doors left open) and its guards. Each fact
// is gathered on its own; one that can't be read is named in Errors and the
// rest still arrive.
type Report struct {
	Host    string    `json:"host"`
	Time    time.Time `json:"time"`
	OS      OSFacts   `json:"os"`
	Kernel  Kernel    `json:"kernel"`
	Reboot  *Reboot   `json:"reboot_required,omitempty"`
	Updates Updates   `json:"updates"`
	// Packages are the installed source packages and their versions, which
	// the lookout matches against the feeds. They never leave the lookout.
	Packages []Pkg        `json:"packages,omitempty"`
	Disk     []Disk       `json:"disk"`
	Listen   []Listen     `json:"listen"`
	Guards   []GuardFacts `json:"guards"`
	Errors   []string     `json:"errors,omitempty"`
}

// OSFacts is the release and how long it is supported.
type OSFacts struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Codename string `json:"codename"`
	// EOL is the end of standard support, from distro-info, as YYYY-MM-DD.
	EOL string `json:"eol,omitempty"`
}

// Kernel is the running build against what is installed.
type Kernel struct {
	Running   string   `json:"running"` // e.g. 6.8.0-142.142
	Flavour   string   `json:"flavour,omitempty"`
	Release   string   `json:"release"`   // uname -r
	Installed []string `json:"installed"` // linux-image versions dpkg calls installed
	Newest    string   `json:"newest"`
	// DKMS lists modules not built for the newest installed kernel.
	DKMSMissing []string `json:"dkms_missing,omitempty"`
}

// Reboot is a reboot the system has asked for, and since when.
type Reboot struct {
	Since    time.Time `json:"since"`
	Packages []string  `json:"packages,omitempty"`
}

// Updates is the state of the update path: dpkg left half done, packages
// kept back, the last run of unattended-upgrades.
type Updates struct {
	DpkgAudit      []string  `json:"dpkg_audit,omitempty"`
	LastUnattended time.Time `json:"last_unattended,omitzero"`
	KeptBack       []string  `json:"kept_back,omitempty"`
}

// Pkg is an installed source package.
type Pkg struct {
	Source  string `json:"source"`
	Version string `json:"version"`
}

// Disk is free space on a mount the update path needs.
type Disk struct {
	Path string `json:"path"`
	Free uint64 `json:"free_bytes"`
}

// Listen is a socket listening on an address outside loopback.
type Listen struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"`
	PID     int    `json:"pid,omitempty"`
}

// GuardFacts is a guard on the machine, from live state.
type GuardFacts struct {
	Hash    string   `json:"hash"`
	Name    string   `json:"name"`
	Status  string   `json:"status"`
	Stopped int64    `json:"stopped_packets"`
	Drift   []string `json:"drift,omitempty"`
	Failed  string   `json:"failed,omitempty"`
}

// Report gathers the machine's facts. It only reads.
func (a *Agent) Report(ctx context.Context) *Report {
	r := &Report{Time: a.now().UTC()}
	fail := func(what string, err error) {
		if err != nil {
			r.Errors = append(r.Errors, what+": "+err.Error())
		}
	}
	h, err := os.Hostname()
	fail("hostname", err)
	r.Host = h

	if b, err := a.Sys.ReadFile("/etc/os-release"); err == nil {
		r.OS = osFacts(b)
	} else {
		fail("os-release", err)
	}
	r.OS.EOL = a.eol(r.OS)

	sys, err := a.Sys.Info()
	fail("kernel", err)
	r.Kernel.Running, r.Kernel.Flavour = sys.Kernel, sys.Flavour
	if b, err := a.Sys.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		r.Kernel.Release = strings.TrimSpace(string(b))
	}
	if out, err := a.Sys.Run(ctx, nil, "dpkg-query", "-W", "-f", "${Package} ${Version} ${db:Status-Abbrev}\n", "linux-image-[0-9]*"); err == nil {
		r.Kernel.Installed, r.Kernel.Newest = installedKernels(out)
	} else {
		fail("installed kernels", err)
	}
	if out, err := a.Sys.Run(ctx, nil, "dkms", "status"); err == nil {
		r.Kernel.DKMSMissing = dkmsMissing(out, r.Kernel.Newest)
	}

	if fi, err := os.Stat("/var/run/reboot-required"); err == nil {
		rb := &Reboot{Since: fi.ModTime().UTC()}
		if b, err := a.Sys.ReadFile("/var/run/reboot-required.pkgs"); err == nil {
			rb.Packages = uniqueLines(b)
		}
		r.Reboot = rb
	}

	if out, err := a.Sys.Run(ctx, nil, "dpkg", "--audit"); err == nil {
		r.Updates.DpkgAudit = firstLines(out, 20)
	} else {
		r.Updates.DpkgAudit = append([]string{"dpkg --audit failed"}, firstLines(out, 19)...)
	}
	if b, err := a.Sys.ReadFile("/var/log/unattended-upgrades/unattended-upgrades.log"); err == nil {
		r.Updates.LastUnattended, r.Updates.KeptBack = unattended(b)
	}
	if out, err := a.Sys.Run(ctx, nil, "dpkg-query", "-W", "-f", "${source:Package} ${source:Version} ${db:Status-Abbrev}\n"); err == nil {
		r.Packages = sourcePackages(out)
	} else {
		fail("packages", err)
	}

	for _, p := range []string{"/", "/boot", "/var"} {
		var st syscall.Statfs_t
		if err := syscall.Statfs(p, &st); err == nil {
			r.Disk = append(r.Disk, Disk{Path: p, Free: uint64(st.Bavail) * uint64(st.Bsize)})
		}
	}

	if l, err := a.Sys.Listening(); err == nil {
		r.Listen = l
	} else {
		fail("listening sockets", err)
	}

	entries, hits, err := a.Status(ctx)
	fail("guards", err)
	drifts, _ := a.Check(ctx, false)
	for _, e := range entries {
		gf := GuardFacts{Hash: e.Hash, Name: e.Guard.Name(), Status: e.Status, Stopped: hits[e.Hash], Failed: e.Failed}
		for _, d := range drifts {
			if d.Guard == gf.Name {
				gf.Drift = append(gf.Drift, d.What)
			}
		}
		r.Guards = append(r.Guards, gf)
	}
	return r
}

func osFacts(b []byte) OSFacts {
	var o OSFacts
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "ID":
			o.ID = v
		case "VERSION_ID":
			o.Version = v
		case "VERSION_CODENAME":
			o.Codename = v
		}
	}
	return o
}

// eol reads the end of standard support from distro-info's CSV: for Ubuntu,
// eol-server where it is set (LTS), else eol.
func (a *Agent) eol(o OSFacts) string {
	b, err := a.Sys.ReadFile("/usr/share/distro-info/" + o.ID + ".csv")
	if err != nil || o.Codename == "" {
		return ""
	}
	cr := csv.NewReader(bytes.NewReader(b))
	cr.FieldsPerRecord = -1 // only LTS rows carry eol-server and later columns
	rows, err := cr.ReadAll()
	if err != nil || len(rows) < 2 {
		return ""
	}
	col := map[string]int{}
	for i, name := range rows[0] {
		col[name] = i
	}
	get := func(row []string, name string) string {
		if i, ok := col[name]; ok && i < len(row) {
			return row[i]
		}
		return ""
	}
	for _, row := range rows[1:] {
		if get(row, "series") == o.Codename {
			if v := get(row, "eol-server"); v != "" {
				return v
			}
			return get(row, "eol")
		}
	}
	return ""
}

// installedKernels reads dpkg-query lines "linux-image-X version ii " and
// returns the installed versions, oldest first, and the newest's package.
func installedKernels(out []byte) (versions []string, newest string) {
	type k struct{ pkg, ver string }
	var ks []k
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[2] != "ii" {
			continue
		}
		ks = append(ks, k{f[0], f[1]})
	}
	sort.Slice(ks, func(i, j int) bool { return guard.CompareVersions(ks[i].ver, ks[j].ver) < 0 })
	for _, x := range ks {
		versions = append(versions, x.ver)
	}
	if len(ks) > 0 {
		newest = strings.TrimPrefix(ks[len(ks)-1].pkg, "linux-image-")
	}
	return versions, newest
}

// dkmsMissing lists DKMS modules that `dkms status` doesn't show as
// installed for kernel release rel (the newest installed kernel's uname -r,
// which its package name carries: linux-image-6.8.0-149-generic).
func dkmsMissing(out []byte, rel string) []string {
	if rel == "" {
		return nil
	}
	modules := map[string]bool{}
	built := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		// e.g. "amdgpu/6.12.12-2147987, 6.8.0-137-generic, x86_64: installed"
		name, rest, ok := strings.Cut(line, ",")
		if !ok {
			continue
		}
		name, _, _ = strings.Cut(name, "/") // "amdgpu/6.12.12" is module amdgpu, version 6.12.12
		modules[name] = true
		if strings.Contains(rest, " "+rel+",") && strings.HasSuffix(strings.TrimSpace(line), "installed") {
			built[name] = true
		}
	}
	var missing []string
	for m := range modules {
		if !built[m] {
			missing = append(missing, m)
		}
	}
	sort.Strings(missing)
	return missing
}

// unattended reads unattended-upgrades' log for its last run and the
// packages it kept back then.
func unattended(b []byte) (last time.Time, kept []string) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 19 {
			continue
		}
		t, err := time.Parse("2006-01-02 15:04:05", line[:19])
		if err != nil {
			continue
		}
		if strings.Contains(line, "Starting unattended upgrades script") {
			last, kept = t.UTC(), nil
		}
		if i := strings.Index(line, "kept back:"); i >= 0 {
			kept = append(kept, strings.Fields(line[i+len("kept back:"):])...)
		}
	}
	return last, kept
}

// sourcePackages reads dpkg-query lines "source version status" for
// installed packages and returns each source once, sorted.
func sourcePackages(out []byte) []Pkg {
	seen := map[Pkg]bool{}
	var pkgs []Pkg
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[2] != "ii" {
			continue
		}
		p := Pkg{Source: f[0], Version: f[1]}
		if !seen[p] {
			seen[p] = true
			pkgs = append(pkgs, p)
		}
	}
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Source != pkgs[j].Source {
			return pkgs[i].Source < pkgs[j].Source
		}
		return pkgs[i].Version < pkgs[j].Version
	})
	return pkgs
}

func uniqueLines(b []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l = strings.TrimSpace(l); l != "" && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

func firstLines(b []byte, n int) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l = strings.TrimSpace(l); l != "" && len(out) < n {
			out = append(out, l)
		}
	}
	return out
}
