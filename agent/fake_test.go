package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/guard"
)

// fakeSys is a machine in memory. It records every change in order, and
// can be told to fail a given call.
type fakeSys struct {
	info     guard.System
	files    map[string]string
	modes    map[string]fs.FileMode
	settings map[string]string
	tables   map[string]*fakeTable // "ip autopatch_…"
	units    map[string]*fakeUnit
	inUse    map[string]string
	log      []string
	failOn   string // a log line prefix whose call fails
	probeErr error
}

type fakeTable struct {
	rules   []string // comments
	options bool     // has a drop of IPv4 options
	packets uint64
}

type fakeUnit struct {
	enabled string // "enabled", "disabled", "masked", "masked-runtime"
	active  bool
	runtime bool // masked at runtime only
}

func newFakeSys() *fakeSys {
	return &fakeSys{
		info:     guard.System{OS: "ubuntu", Release: "24.04", Kernel: "6.8.0-142.142", Flavour: "generic"},
		files:    map[string]string{},
		modes:    map[string]fs.FileMode{},
		settings: map[string]string{"net.mptcp.enabled": "1", "kernel.io_uring_disabled": "0"},
		tables:   map[string]*fakeTable{},
		units:    map[string]*fakeUnit{},
		inUse:    map[string]string{},
	}
}

func (f *fakeSys) record(line string) error {
	f.log = append(f.log, line)
	if f.failOn != "" && strings.HasPrefix(line, f.failOn) {
		return fmt.Errorf("fake failure at %q", line)
	}
	return nil
}

var (
	tableOpenRe = regexp.MustCompile(`(?m)^table (ip6?) (\S+) \{$`)
	deleteRe    = regexp.MustCompile(`(?m)^delete table (ip6?) (\S+)$`)
	commentRe   = regexp.MustCompile(`comment "([^"]*)"`)
)

func (f *fakeSys) Run(_ context.Context, stdin []byte, prog string, args ...string) ([]byte, error) {
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
			t := &fakeTable{options: strings.Contains(script, "hdrlength gt 5")}
			for _, c := range commentRe.FindAllStringSubmatch(script, -1) {
				t.rules = append(t.rules, c[1])
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
		for _, c := range t.rules {
			items = append(items, map[string]any{"rule": map[string]any{
				"table": args[4], "chain": "in", "comment": c,
				"expr": []any{map[string]any{"counter": map[string]any{"packets": t.packets}}},
			}})
		}
		return json.Marshal(map[string]any{"nftables": items})
	}
	if prog == "systemctl" {
		u := f.units[args[len(args)-1]]
		switch args[0] {
		case "is-enabled":
			if u == nil {
				return []byte("not-found\n"), fmt.Errorf("not found")
			}
			return []byte(u.enabled + "\n"), nil
		case "is-active":
			if u != nil && u.active {
				return []byte("active\n"), nil
			}
			return []byte("inactive\n"), fmt.Errorf("inactive")
		}
		if err := f.record(line); err != nil {
			return nil, err
		}
		if u == nil {
			return nil, nil
		}
		switch strings.Join(args[:len(args)-1], " ") {
		case "stop":
			u.active = false
		case "start":
			u.active = true
		case "mask --runtime":
			if u.enabled != "masked" {
				u.runtime, u.enabled = true, "masked-runtime"
			}
		case "mask":
			u.runtime, u.enabled = false, "masked"
		case "unmask --runtime":
			if u.runtime {
				u.runtime, u.enabled = false, "enabled"
			}
		case "unmask":
			if u.enabled == "masked" || u.enabled == "masked-runtime" {
				u.runtime, u.enabled = false, "enabled"
			}
		}
		return nil, nil
	}
	return nil, f.record(line)
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

type fakeInfo struct{ mode fs.FileMode }

func (i fakeInfo) Name() string       { return "" }
func (i fakeInfo) Size() int64        { return 0 }
func (i fakeInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return false }
func (i fakeInfo) Sys() any           { return nil }

func (f *fakeSys) Lstat(name string) (fs.FileInfo, error) {
	m, ok := f.modes[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return fakeInfo{m}, nil
}

func (f *fakeSys) Chmod(name string, mode fs.FileMode) error {
	if err := f.record(fmt.Sprintf("chmod %s %v", name, mode)); err != nil {
		return err
	}
	f.modes[name] = mode
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
	if f.probeErr != nil {
		return f.probeErr
	}
	for k, t := range f.tables {
		if strings.HasPrefix(k, "ip ") && t.options {
			t.packets++
			return nil
		}
	}
	return fmt.Errorf("probe: a TCP connection request carrying IPv4 options got through")
}

func (f *fakeSys) Info() (guard.System, error) { return f.info, nil }

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
