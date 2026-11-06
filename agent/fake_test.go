package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strings"
	"time"

	"github.com/gnosecurity/repairer/guard"
)

// fakeSys is a machine in memory. It records every change in order, and
// can be told to fail a given call.
type fakeSys struct {
	info     guard.System
	files    map[string]string
	strips   map[string]*fakeFile
	settings map[string]string
	tables   map[string]*fakeTable // "ip repairer_…"
	units    map[string]*fakeUnit
	inUse    map[string]string
	modules  map[string]string // name: "loadable" or "builtin"
	sshPorts []int
	listen   []Listen
	runOut   map[string]string // output for a program and its args, joined by spaces
	runErr   map[string]string // stderr for a program and its args, which then exits 1 (RunCapped)
	special  map[string]string // a path that is a "fifo" or a "link" (OpenFile)
	missing  map[string]bool   // programs not installed (Has, Run)
	read     map[string]int    // bytes read through OpenFile, by path
	ephLo    int
	ephHi    int
	log      []string
	failOn   string            // a log line prefix whose call fails
	failWith string            // added to that failure's message
	onRun    func(line string) // called before each call is recorded
	probeErr error
	// noise counts a packet on this rule of every table during a probe,
	// as other traffic would.
	noise int
	// stoppedElsewhere makes the probe's packet stopped by something other
	// than any guard rule.
	stoppedElsewhere bool
	nextIno          uint64
}

type fakeTable struct {
	rules []fakeRule
}

type fakeRule struct {
	comment string
	text    string
	packets uint64
}

// fakeUnit keeps systemd's two masks apart: a lasting one in /etc and a
// runtime one in /run. Each mask or unmask call changes only its own.
type fakeUnit struct {
	enabled string // "enabled" or "disabled" when not masked
	etcMask bool
	runMask bool
	active  bool
}

func (u *fakeUnit) state() string {
	switch {
	case u.etcMask:
		return "masked"
	case u.runMask:
		return "masked-runtime"
	}
	return u.enabled
}

// fakeFile is a file a strip may touch.
type fakeFile struct {
	mode    fs.FileMode
	uid     uint32
	ino     uint64
	viaLink bool   // the path goes through a symlink
	sameAs  string // the never-strip path it is, by another name
}

func newFakeSys() *fakeSys {
	return &fakeSys{
		info:     guard.System{OS: "ubuntu", Release: "24.04", Kernel: "6.8.0-142.142", Flavour: "generic"},
		files:    map[string]string{},
		strips:   map[string]*fakeFile{},
		settings: map[string]string{"net.mptcp.enabled": "1", "kernel.io_uring_disabled": "0"},
		tables:   map[string]*fakeTable{},
		units:    map[string]*fakeUnit{},
		inUse:    map[string]string{},
		runOut:   map[string]string{},
		runErr:   map[string]string{},
		special:  map[string]string{},
		modules:  map[string]string{"ksmbd": "loadable", "sctp": "loadable", "ext4": "builtin"},
		sshPorts: []int{22},
		ephLo:    32768,
		ephHi:    60999,
		noise:    -1,
		nextIno:  100,
	}
}

func (f *fakeSys) addFile(path string, mode fs.FileMode) *fakeFile {
	f.nextIno++
	ff := &fakeFile{mode: mode, ino: f.nextIno}
	f.strips[path] = ff
	return ff
}

func (f *fakeSys) record(line string) error {
	if f.onRun != nil {
		f.onRun(line)
	}
	f.log = append(f.log, line)
	if f.failOn != "" && strings.HasPrefix(line, f.failOn) {
		return fmt.Errorf("fake failure at %q%s", line, f.failWith)
	}
	return nil
}

var (
	tableOpenRe = regexp.MustCompile(`(?m)^table (ip6?) (\S+) \{$`)
	deleteRe    = regexp.MustCompile(`(?m)^delete table (ip6?) (\S+)$`)
	ruleRe      = regexp.MustCompile(`(?m)^\t\t(.*) comment "([^"]*)"$`)
)

// Has reports a program installed unless the test made it missing.
func (f *fakeSys) Has(prog string) bool { return !f.missing[prog] }

func (f *fakeSys) Run(_ context.Context, stdin []byte, prog string, args ...string) ([]byte, error) {
	if f.missing[prog] {
		return nil, fmt.Errorf("run %s: not found in /usr/sbin, /usr/bin, /sbin, /bin", prog)
	}
	line := prog + " " + strings.Join(args, " ")
	if prog == "nft" && len(args) == 2 && args[0] == "-f" {
		// A script: deletes first, then the table it defines.
		script := string(stdin)
		if m := tableOpenRe.FindStringSubmatch(script); m != nil {
			line = "nft load " + m[1] + " " + m[2]
		} else if m := deleteRe.FindStringSubmatch(script); m != nil {
			line = "nft delete " + m[1] + " " + m[2]
		}
		if err := f.record(line); err != nil {
			return nil, err
		}
		for _, m := range deleteRe.FindAllStringSubmatch(script, -1) {
			delete(f.tables, m[1]+" "+m[2])
		}
		if m := tableOpenRe.FindStringSubmatch(script); m != nil {
			t := &fakeTable{}
			for _, r := range ruleRe.FindAllStringSubmatch(script, -1) {
				t.rules = append(t.rules, fakeRule{text: r[1], comment: r[2]})
			}
			f.tables[m[1]+" "+m[2]] = t
		}
		return nil, nil
	}
	if prog == "nft" && len(args) == 5 && args[0] == "-j" {
		t, ok := f.tables[args[3]+" "+args[4]]
		if !ok {
			return nil, fmt.Errorf("nft: no such table %s %s", args[3], args[4])
		}
		items := []any{
			map[string]any{"chain": map[string]any{"table": args[4], "name": "in", "hook": "prerouting", "prio": -300}},
		}
		for _, r := range t.rules {
			items = append(items, map[string]any{"rule": map[string]any{
				"table": args[4], "chain": "in", "comment": r.comment,
				"expr": []any{map[string]any{"counter": map[string]any{"packets": r.packets}}},
			}})
		}
		return json.Marshal(map[string]any{"nftables": items})
	}
	if prog == "systemctl" {
		unit := args[len(args)-1]
		u := f.units[unit]
		switch args[0] {
		case "is-enabled":
			if u == nil {
				return []byte("not-found\n"), fmt.Errorf("not found")
			}
			return []byte(u.state() + "\n"), nil
		case "is-active":
			if u != nil && u.active {
				return []byte("active\n"), nil
			}
			return []byte("inactive\n"), fmt.Errorf("inactive")
		}
		if err := f.record(line); err != nil {
			return nil, err
		}
		if u == nil || args[0] == "daemon-reload" || args[0] == "enable" {
			return nil, nil
		}
		verb := strings.Join(args[:len(args)-1], " ")
		switch verb {
		case "stop":
			u.active = false
		case "start":
			if u.etcMask || u.runMask {
				return nil, fmt.Errorf("Unit %s is masked.", unit)
			}
			u.active = true
		case "mask --runtime --now":
			u.runMask, u.active = true, false
		case "mask --now":
			u.etcMask, u.active = true, false
		case "unmask --runtime":
			u.runMask = false
		case "unmask":
			u.etcMask = false
		default:
			return nil, fmt.Errorf("fake systemctl: no %q", verb)
		}
		return nil, nil
	}
	if out, ok := f.runOut[line]; ok {
		return []byte(out), nil
	}
	return nil, f.record(line)
}

// RunCapped answers from runOut and runErr, keeping limit bytes of the
// output; every call is recorded.
func (f *fakeSys) RunCapped(_ context.Context, limit int64, prog string, args ...string) (Output, error) {
	line := prog + " " + strings.Join(args, " ")
	if err := f.record(line); err != nil {
		return Output{}, err
	}
	o := Output{Out: []byte(f.runOut[line])}
	if int64(len(o.Out)) > limit {
		o.Out, o.OutCapped = o.Out[:max(limit, 0)], true
		return o, fmt.Errorf("%s: signal: killed", prog)
	}
	if e, ok := f.runErr[line]; ok {
		o.Err = []byte(e)
		if len(o.Err) > maxStderr {
			o.Err, o.ErrCapped = o.Err[:maxStderr], true
		}
		return o, fmt.Errorf("%s: exit status 1", prog)
	}
	return o, nil
}

func (f *fakeSys) OpenFile(name string) (io.ReadCloser, error) {
	if k := f.special[name]; k != "" {
		return nil, fmt.Errorf("%s: %w (%s)", name, ErrNotRegular, k)
	}
	s, ok := f.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(&fakeReader{f: f, name: name, r: strings.NewReader(s)}), nil
}

// fakeReader counts what is read of a fake file.
type fakeReader struct {
	f    *fakeSys
	name string
	r    io.Reader
}

func (r *fakeReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if r.f.read == nil {
		r.f.read = map[string]int{}
	}
	r.f.read[r.name] += n
	return n, err
}

func (f *fakeSys) ReadFile(name string) ([]byte, error) {
	s, ok := f.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(s), nil
}

func (f *fakeSys) WriteFile(name string, data []byte, _ fs.FileMode) error {
	if err := f.record("write " + name); err != nil {
		return err
	}
	f.files[name] = string(data)
	return nil
}

// fakeInfo describes a file of the fake machine.
type fakeInfo struct {
	mode fs.FileMode
	size int64
}

func (i fakeInfo) Name() string       { return "" }
func (i fakeInfo) Size() int64        { return i.size }
func (i fakeInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return false }
func (i fakeInfo) Sys() any           { return nil }

func (f *fakeSys) Stat(name string) (fs.FileInfo, error) {
	s, ok := f.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return fakeInfo{0o644, int64(len(s))}, nil
}

func (f *fakeSys) Remove(name string) error {
	if _, ok := f.files[name]; !ok {
		return nil
	}
	if err := f.record("remove " + name); err != nil {
		return err
	}
	delete(f.files, name)
	return nil
}

func (f *fakeSys) ReadSetting(name string) (string, error) {
	v, ok := f.settings[name]
	if !ok {
		return "", fs.ErrNotExist
	}
	return v, nil
}

func (f *fakeSys) WriteSetting(name, value string) error {
	if err := f.record("setting " + name + "=" + value); err != nil {
		return err
	}
	f.settings[name] = value
	return nil
}

func (f *fakeSys) InUse(what string) (string, error) { return f.inUse[what], nil }

func (f *fakeSys) ProbeIPOptions(context.Context) error {
	if err := f.record("probe"); err != nil {
		return err
	}
	for _, t := range f.tables {
		if f.noise >= 0 && f.noise < len(t.rules) {
			t.rules[f.noise].packets++
		}
	}
	if f.probeErr != nil {
		return f.probeErr
	}
	if f.stoppedElsewhere {
		return nil
	}
	for k, t := range f.tables {
		if !strings.HasPrefix(k, "ip ") {
			continue
		}
		for i, r := range t.rules {
			if strings.Contains(r.text, "ip protocol tcp ip hdrlength gt 5") {
				t.rules[i].packets++
				return nil
			}
		}
	}
	return fmt.Errorf("probe: a TCP connection request carrying IPv4 options got through")
}

func (f *fakeSys) Info() (guard.System, error) { return f.info, nil }

func (f *fakeSys) Module(name string) (bool, bool, error) {
	switch f.modules[strings.ReplaceAll(name, "-", "_")] {
	case "loadable":
		return true, false, nil
	case "builtin":
		return false, true, nil
	}
	return false, false, nil
}

func (f *fakeSys) RemoteAccessPorts() ([]int, error) { return f.sshPorts, nil }

func (f *fakeSys) EphemeralPorts() (int, int, error) { return f.ephLo, f.ephHi, nil }

func (f *fakeSys) Listening() ([]Listen, error) { return f.listen, nil }

func (f *fakeSys) ListeningAll() (map[string]bool, error) {
	out := map[string]bool{}
	for _, l := range f.listen {
		out[fmt.Sprintf("%s/%d", l.Proto, l.Port)] = true
	}
	return out, nil
}

func (f *fakeSys) FileID(path string) (FileID, error) {
	ff, ok := f.strips[path]
	if !ok {
		return FileID{}, fs.ErrNotExist
	}
	if ff.viaLink {
		return FileID{}, fmt.Errorf("%s goes through a symlink", path)
	}
	return FileID{Mode: ff.mode, Regular: true, UID: ff.uid, Dev: 1, Ino: ff.ino}, nil
}

func (f *fakeSys) ChmodIf(path string, want FileID, mode fs.FileMode) (bool, error) {
	ff, ok := f.strips[path]
	if !ok || ff.viaLink || ff.uid != 0 || ff.ino != want.Ino {
		return false, nil
	}
	if err := f.record(fmt.Sprintf("chmod %s %v", path, mode)); err != nil {
		return false, err
	}
	ff.mode = mode
	return true, nil
}

func (f *fakeSys) SameFile(a, b string) (bool, error) {
	ff, ok := f.strips[a]
	return ok && ff.sameAs == b, nil
}

// fakeTimer records arming and disarming in the machine's log, so tests can
// check that the undo is armed before the first change.
type fakeTimer struct {
	sys   *fakeSys
	armed map[string]time.Duration
}

func (t *fakeTimer) Arm(_ context.Context, hash string, d time.Duration) error {
	if err := t.sys.record("arm " + hash[:12]); err != nil {
		return err
	}
	t.armed[hash] = d
	return nil
}

func (t *fakeTimer) Disarm(_ context.Context, hash string) error {
	t.sys.record("disarm " + hash[:12])
	delete(t.armed, hash)
	return nil
}
