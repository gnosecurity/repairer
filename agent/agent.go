// Package agent puts guards on one machine and takes them off.
//
// Every change is written ahead in the state file and has its undo armed
// before it is made. A guard goes on live and pending: a reboot or the undo
// timer takes it off unless it is confirmed. Confirming makes it stay across
// reboots. The boot command takes off whatever was never confirmed and puts
// back what was, if it is still allowed and safe.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/nft"
	"github.com/jaekwon/autopatch/policy"
)

// Files the agent owns. The sysctl file sorts after 99-sysctl.conf, so its
// settings win over the system's own.
const (
	SysctlFile  = "/etc/sysctl.d/99-zz-autopatch.conf"
	modprobeDir = "/etc/modprobe.d"
)

// Agent acts for the guards on one machine.
type Agent struct {
	Sys      System
	Timer    Timer
	StateDir string
	Now      func() time.Time
	// Health runs a policy health check; nil means LiveHealth.
	Health HealthChecker
}

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// step is one unit of putting a guard on: a whole table of drops for one
// family, or one other block. Tables go first, so a guard blocks its
// trigger before anything else.
type step struct {
	family string        // a table step: "ip" or "ip6"
	drops  []*guard.Drop // a table step's drops, in rule order
	block  guard.Block   // any other step
}

func steps(g *guard.Guard) []step {
	var out []step
	tables := nft.Tables(g)
	for _, f := range []string{"ip", "ip6"} {
		if ds := tables[f]; len(ds) > 0 {
			out = append(out, step{family: f, drops: ds})
		}
	}
	for _, b := range g.Blocks {
		if b.Drop == nil {
			out = append(out, step{block: b})
		}
	}
	return out
}

func (s step) describe() string {
	if s.drops != nil {
		var w []string
		for _, d := range s.drops {
			w = append(w, guard.Block{Drop: d}.Describe())
		}
		return strings.Join(w, "; ")
	}
	return s.block.Describe()
}

// sameResource reports whether two steps change the same thing, which
// only settings, units and stripped files can share.
func sameResource(x, y step) bool {
	a, b := x.block, y.block
	switch {
	case a.Setting != nil && b.Setting != nil:
		return a.Setting.Name == b.Setting.Name
	case a.Service != nil && b.Service != nil:
		return a.Service.Unit == b.Service.Unit
	case a.Strip != nil && b.Strip != nil:
		return a.Strip.Path == b.Strip.Path
	}
	return false
}

func modprobeFile(hash, module string) string {
	return modprobeDir + "/autopatch-" + hash + "-" + module + ".conf"
}

func modprobeText(module string) string {
	return "# autopatch: this module is blocked by a guard.\ninstall " + module + " /bin/false\nblacklist " + module + "\n"
}

// probeRule returns the position, among the guard's IPv4 drops, of the drop
// the agent has a probe for, or -1. The agent's one probe today is a TCP
// connection request carrying IPv4 options, on any port.
func probeRule(g *guard.Guard) int {
	for i, d := range nft.Tables(g)["ip"] {
		if d.IPOptions && d.Protocol == "tcp" && len(d.Ports) == 0 {
			return i
		}
	}
	return -1
}

// unprobed reports whether any of the guard's drops goes unprobed: every
// drop but the one probeRule names.
func unprobed(g *guard.Guard) bool {
	n := 0
	for _, b := range g.Blocks {
		if b.Drop != nil {
			n++
		}
	}
	if probeRule(g) >= 0 {
		n--
	}
	return n > 0
}

// Plan is what a guard would do on this machine.
type Plan struct {
	Hash   string
	System guard.System
	// Steps say what each step does, when it bites, and whether it may go
	// on without the owner's yes.
	Steps []string
	// Problems are reasons it can't go on here now.
	Problems []string
	// InUse are problems that -force may override: something uses what a
	// block would take away, or a setting can't reach everything.
	InUse []string
	// Codes are the listed reasons (approve.RefusalCodes) behind Problems
	// and InUse, each once: the only reasons a canary may sign.
	Codes []string
	// Unprobed reports whether some drop has no probe.
	Unprobed bool
}

func (p *Plan) code(c string) {
	if c == "" {
		return
	}
	for _, x := range p.Codes {
		if x == c {
			return
		}
	}
	p.Codes = append(p.Codes, c)
}

// Refusal is Apply's error when this machine won't take a guard as it is
// now. Code is the first listed reason behind it, or "" when none is.
type Refusal struct {
	Code string
	msg  string
}

func (r *Refusal) Error() string { return r.msg }

// refusal says why a plan can't go on, or returns nil.
func refusal(g *guard.Guard, p *Plan, force bool) *Refusal {
	code := ""
	if len(p.Codes) > 0 {
		code = p.Codes[0]
	}
	if len(p.Problems) > 0 {
		return &Refusal{Code: code, msg: fmt.Sprintf("%s can't go on here: %s", g.Name(), strings.Join(p.Problems, "; "))}
	}
	if len(p.InUse) > 0 && !force {
		return &Refusal{Code: code, msg: fmt.Sprintf("%s would take away something in use, or can't reach everything (-force overrides): %s", g.Name(), strings.Join(p.InUse, "; "))}
	}
	return nil
}

// Plan says what the guard would do here, and changes nothing.
func (a *Agent) Plan(g *guard.Guard) (*Plan, error) {
	sys, err := a.Sys.Info()
	if err != nil {
		return nil, err
	}
	p := &Plan{Hash: g.Hash(), System: sys, Unprobed: unprobed(g)}
	if !g.Fits(sys) {
		p.Problems = append(p.Problems, fmt.Sprintf("written for %s, and this is %s %s", targets(g), sys.OS, sys.Release))
	}
	if fixed, decided := g.FixRunning(sys); decided && fixed {
		p.Problems = append(p.Problems, fmt.Sprintf("the fix is already running (kernel %s)", sys.Kernel))
	}
	for _, s := range steps(g) {
		auto, effect := true, guard.Now
		if s.drops == nil {
			auto, effect = s.block.Auto(), s.block.Effect()
		}
		line := s.describe() + " (bites: " + string(effect)
		if !auto {
			line += "; needs the owner's yes"
		}
		p.Steps = append(p.Steps, line+")")
		for _, what := range inUseChecks(s) {
			used, err := a.Sys.InUse(what)
			if err != nil {
				p.Problems = append(p.Problems, fmt.Sprintf("can't tell whether %s is in use: %v", what, err))
			} else if used != "" {
				p.InUse = append(p.InUse, used)
				if what == "netns" {
					p.code("netns")
				} else {
					p.code("in-use")
				}
			}
		}
	}
	for _, pr := range a.problems(g) {
		p.Problems = append(p.Problems, pr.why)
		p.code(pr.code)
	}
	return p, nil
}

func targets(g *guard.Guard) string {
	var w []string
	for _, t := range g.For {
		w = append(w, t.OS+" "+strings.Join(t.Releases, "/"))
	}
	return strings.Join(w, ", ")
}

func inUseChecks(s step) []string {
	switch {
	case s.block.Setting != nil:
		if c := guard.SettingInUseCheck(s.block.Setting.Name); c != "" {
			return []string{c}
		}
	case s.block.Module != nil:
		return []string{"module:" + s.block.Module.Name}
	}
	return nil
}

// unsafe returns why a guard would be unsafe on this machine as it is now.
func (a *Agent) unsafe(g *guard.Guard) []string {
	var out []string
	for _, p := range a.problems(g) {
		out = append(out, p.why)
	}
	return out
}

// problem is one reason a guard can't go on here, with its listed code
// (approve.RefusalCodes) when it has one.
type problem struct{ code, why string }

// problems returns why a guard would be unsafe on this machine as it is
// now, beyond what the guard's own fields can show: a module named by alias
// or built in, a drop that would cut ssh, the machine's own replies or a
// flow the policy protects here, a strip of a file that is sudo by another
// name or that someone else could swap.
func (a *Agent) problems(g *guard.Guard) []problem {
	var out []problem
	var sshPorts []int
	var flows []policy.Flow
	lo, hi := 0, 0
	for _, b := range g.Blocks {
		if b.Drop != nil && len(b.Drop.Ports) > 0 && lo == 0 {
			var err error
			if lo, hi, err = a.Sys.EphemeralPorts(); err != nil {
				out = append(out, problem{"", "can't read the ephemeral port range: " + err.Error()})
				lo, hi = 1, 65535 // refuse every port drop
			}
			if sshPorts, err = a.Sys.RemoteAccessPorts(); err != nil {
				out = append(out, problem{"", "can't tell which ports ssh listens on: " + err.Error()})
			}
			if flows, err = a.protectedFlows(); err != nil {
				out = append(out, problem{"", "can't read the policy's protected flows: " + err.Error()})
			}
		}
	}
	for _, b := range g.Blocks {
		switch {
		case b.Drop != nil:
			ranges, _ := b.Drop.PortRanges()
			for _, r := range ranges {
				if r[0] <= hi && lo <= r[1] {
					out = append(out, problem{"protected-flow", fmt.Sprintf("ports %d-%d overlap %d-%d, the ports this machine's own connections use, so their replies would be dropped", r[0], r[1], lo, hi)})
				}
				for _, p := range sshPorts {
					if b.Drop.Protocol == "tcp" && r[0] <= p && p <= r[1] {
						out = append(out, problem{"protected-flow", fmt.Sprintf("ssh listens on port %d", p)})
					}
				}
				// A drop narrowed by IP options matches no ordinary flow.
				for _, f := range flows {
					if !b.Drop.IPOptions && b.Drop.Protocol == f.Proto && r[0] <= f.Port && f.Port <= r[1] {
						out = append(out, problem{"protected-flow", fmt.Sprintf("the policy protects %s port %d here", f.Proto, f.Port)})
					}
				}
			}
		case b.Module != nil:
			loadable, builtin, err := a.Sys.Module(b.Module.Name)
			switch {
			case err != nil:
				out = append(out, problem{"", "module " + b.Module.Name + ": " + err.Error()})
			case builtin:
				out = append(out, problem{"", "module " + b.Module.Name + " is built into this kernel; a block can't stop it"})
			case !loadable:
				out = append(out, problem{"", "this kernel has no module named exactly " + b.Module.Name + " (aliases are refused)"})
			}
		case b.Strip != nil:
			id, err := a.Sys.FileID(b.Strip.Path)
			if err != nil {
				out = append(out, problem{"", err.Error()})
				continue
			}
			if !id.Regular || id.UID != 0 {
				out = append(out, problem{"never-touch", b.Strip.Path + " is not a regular file owned by root"})
			}
			for _, never := range guard.NeverStripPaths() {
				same, err := a.Sys.SameFile(b.Strip.Path, never)
				if err != nil {
					out = append(out, problem{"", "can't compare " + b.Strip.Path + " with " + never + ": " + err.Error()})
					break
				}
				if same {
					out = append(out, problem{"never-touch", b.Strip.Path + " is " + never + " by another name"})
					break
				}
			}
		}
	}
	return out
}

// protectedFlows are the policy's protected flows for this host, or none
// when no policy is installed (a guard put on by hand).
func (a *Agent) protectedFlows() ([]policy.Flow, error) {
	f, err := a.loadFleet()
	if errors.Is(err, errNoFleet) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p, err := f.InstalledPolicy()
	if err != nil {
		return nil, err
	}
	var out []policy.Flow
	for _, fl := range p.Protected {
		for _, h := range fl.Hosts {
			if h == f.Host {
				out = append(out, fl)
			}
		}
	}
	return out, nil
}

// ApplyOptions say how a guard goes on.
type ApplyOptions struct {
	// ConfirmWithin is how long the guard stays on before its undo runs,
	// unless confirmed. Zero confirms it as soon as its probe passes.
	ConfirmWithin time.Duration
	// Force puts a block on even when something uses what it takes away.
	Force bool
	// By is the role that admitted the guard; "" for a guard put on by hand.
	By string
	// Keep is the owner's keep: confirmed as soon as its probe passes, with
	// no trial and no window after a boot.
	Keep bool
}

// minArm is the shortest time an undo is armed for, to cover the apply.
const minArm = 2 * time.Minute

// Apply puts a guard on: write ahead, arm the undo, apply each step, probe.
// On any failure it takes off what it put on.
func (a *Agent) Apply(ctx context.Context, g *guard.Guard, o ApplyOptions) (*Entry, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	s, st, err := a.open()
	if err != nil {
		return nil, err
	}
	defer s.close()

	h := g.Hash()
	if e := st.find(h); e != nil {
		if e.Status == Applying {
			return nil, fmt.Errorf("%s is half on (%s); run undo or boot first", g.Name(), halfOn(e))
		}
		return e, nil // already on
	}
	for _, e := range st.Guards {
		if e.Guard.ID == g.ID {
			return nil, fmt.Errorf("%s is on; take it off before putting on %s", e.Guard.Name(), g.Name())
		}
	}
	p, err := a.Plan(g)
	if err != nil {
		return nil, err
	}
	if r := refusal(g, p, o.Force); r != nil {
		return nil, r
	}
	if o.Keep {
		o.ConfirmWithin = 0
	}

	arm := max(o.ConfirmWithin, minArm)
	start := a.now()
	e := &Entry{Hash: h, Guard: g, Status: Applying, AppliedAt: start, ConfirmBy: start.Add(arm), Unprobed: p.Unprobed,
		By: o.By, Keep: o.Keep, Later: g.Later()}
	st.Guards = append(st.Guards, e)
	if err := s.save(st); err != nil {
		return nil, err
	}
	if err := a.Timer.Arm(ctx, h, arm); err != nil {
		st.remove(h)
		return nil, errors.Join(fmt.Errorf("arming the undo: %w", err), s.save(st))
	}
	fail := func(err error) (*Entry, error) {
		uerr := a.takeOff(ctx, st, e)
		ferr := a.writeSysctlFile(st)
		serr := s.save(st)
		if uerr == nil {
			a.Timer.Disarm(ctx, h)
		} // else the armed undo, then boot, try again
		return nil, errors.Join(err, uerr, ferr, serr)
	}
	for i, stp := range steps(g) {
		if err := a.capture(ctx, st, stp); err != nil {
			return fail(err)
		}
		if err := s.save(st); err != nil {
			return fail(err)
		}
		if err := a.applyStep(ctx, st, e, stp, false); err != nil {
			return fail(fmt.Errorf("putting on %q: %w", stp.describe(), err))
		}
		e.Applied = i + 1
		if err := s.save(st); err != nil {
			return fail(err)
		}
	}
	if r := probeRule(g); r >= 0 {
		if err := a.probe(ctx, e, r); err != nil {
			return fail(err)
		}
	}
	e.Status = Pending
	if err := s.save(st); err != nil {
		return fail(err)
	}
	if o.ConfirmWithin == 0 {
		return e, a.confirm(ctx, s, st, e)
	}
	return e, nil
}

func halfOn(e *Entry) string {
	if e.Failed != "" {
		return "taking it off failed: " + e.Failed
	}
	return "a run died while putting it on"
}

// capture records what a step's resource was before the first guard
// changed it.
func (a *Agent) capture(ctx context.Context, st *State, s step) error {
	o := &st.Originals
	switch b := s.block; {
	case b.Setting != nil:
		if _, ok := o.Settings[b.Setting.Name]; ok {
			return nil
		}
		v, err := a.Sys.ReadSetting(b.Setting.Name)
		if err != nil {
			return fmt.Errorf("reading %s: %w", b.Setting.Name, err)
		}
		if o.Settings == nil {
			o.Settings = map[string]string{}
		}
		o.Settings[b.Setting.Name] = v
	case b.Strip != nil:
		if _, ok := o.Modes[b.Strip.Path]; ok {
			return nil
		}
		id, err := a.Sys.FileID(b.Strip.Path)
		if err != nil {
			return err
		}
		if !id.Regular || id.UID != 0 {
			return fmt.Errorf("%s is not a regular file owned by root", b.Strip.Path)
		}
		if o.Modes == nil {
			o.Modes = map[string]SavedMode{}
		}
		o.Modes[b.Strip.Path] = SavedMode{Mode: uint32(id.Mode), Dev: id.Dev, Ino: id.Ino}
	case b.Service != nil:
		if _, ok := o.Units[b.Service.Unit]; ok {
			return nil
		}
		enabled, _ := a.Sys.Run(ctx, nil, "systemctl", "is-enabled", b.Service.Unit)
		active, _ := a.Sys.Run(ctx, nil, "systemctl", "is-active", b.Service.Unit)
		if o.Units == nil {
			o.Units = map[string]UnitState{}
		}
		o.Units[b.Service.Unit] = UnitState{
			Enabled: strings.TrimSpace(string(enabled)),
			Active:  strings.TrimSpace(string(active)) == "active",
		}
	}
	return nil
}

// applyStep puts one step on. Pending guards change only what a reboot
// clears, where the system allows it (a runtime mask); lasting ones also
// change what stays.
func (a *Agent) applyStep(ctx context.Context, st *State, e *Entry, s step, lasting bool) error {
	switch b := s.block; {
	case s.drops != nil:
		script, err := nft.Script(s.family, nft.TableName(e.Hash), e.Guard.Name(), s.drops)
		if err != nil {
			return err
		}
		_, err = a.Sys.Run(ctx, []byte(script), "nft", "-f", "-")
		return err
	case b.Setting != nil:
		return a.Sys.WriteSetting(b.Setting.Name, b.Setting.Value)
	case b.Module != nil:
		if err := a.Sys.WriteFile(modprobeFile(e.Hash, b.Module.Name), []byte(modprobeText(b.Module.Name)), 0o644); err != nil {
			return err
		}
		// Unload it if it is loaded and unused; the in-use check passed.
		a.Sys.Run(ctx, nil, "modprobe", "-r", b.Module.Name)
		return nil
	case b.Service != nil:
		// Mask first, then stop (--now), so that nothing can start it in
		// between.
		args := []string{"mask", "--runtime", "--now", b.Service.Unit}
		if lasting {
			args = []string{"mask", "--now", b.Service.Unit}
		}
		_, err := a.Sys.Run(ctx, nil, "systemctl", args...)
		return err
	case b.Strip != nil:
		id, err := a.Sys.FileID(b.Strip.Path)
		if err != nil {
			return err
		}
		if saved, ok := st.Originals.Modes[b.Strip.Path]; ok && (saved.Dev != id.Dev || saved.Ino != id.Ino) {
			// An upgrade replaced the file, and with it, maybe, the setuid
			// bit. What goes back at undo is now the new file's mode.
			st.Originals.Modes[b.Strip.Path] = SavedMode{Mode: uint32(id.Mode), Dev: id.Dev, Ino: id.Ino}
		}
		ok, err := a.Sys.ChmodIf(b.Strip.Path, id, id.Mode&^(fs.ModeSetuid|fs.ModeSetgid))
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%s changed while being stripped", b.Strip.Path)
		}
		return nil
	}
	return errors.New("empty step")
}

// reached returns how many of an entry's steps may be on: those below
// Applied, and the one at Applied if the entry is Applying.
func reached(e *Entry, n int) int {
	r := e.Applied
	if e.Status == Applying && r < n {
		r++
	}
	return r
}

// othersHold reports whether a guard other than e may have on a step that
// changes what s changes, so that taking e off must leave it changed. Only
// steps another guard has reached count.
func othersHold(st *State, e *Entry, s step) bool {
	for _, o := range st.Guards {
		if o == e {
			continue
		}
		os := steps(o.Guard)
		for i := 0; i < reached(o, len(os)); i++ {
			if sameResource(os[i], s) {
				return true
			}
		}
	}
	return false
}

// undoStep takes one step off. It is safe to run on a step that is only
// partly on, or not on at all.
func (a *Agent) undoStep(ctx context.Context, st *State, e *Entry, s step) error {
	o := &st.Originals
	switch b := s.block; {
	case s.drops != nil:
		_, err := a.Sys.Run(ctx, []byte(nft.DeleteScript(s.family, nft.TableName(e.Hash))), "nft", "-f", "-")
		return err
	case b.Setting != nil:
		if othersHold(st, e, s) {
			return nil
		}
		if v, ok := o.Settings[b.Setting.Name]; ok {
			if err := a.Sys.WriteSetting(b.Setting.Name, v); err != nil {
				return err
			}
			delete(o.Settings, b.Setting.Name)
		}
		return nil
	case b.Module != nil:
		return a.Sys.Remove(modprobeFile(e.Hash, b.Module.Name))
	case b.Service != nil:
		if othersHold(st, e, s) {
			return nil
		}
		unit := b.Service.Unit
		was, ok := o.Units[unit]
		var errs []error
		switch {
		case ok && was.Enabled == "masked":
			// Masked for good before any guard: leave it.
		case ok && was.Enabled == "masked-runtime":
			// Someone masked it for this boot before any guard. Take off
			// only the lasting mask a confirm may have added.
			if _, err := a.Sys.Run(ctx, nil, "systemctl", "unmask", unit); err != nil {
				errs = append(errs, err)
			}
		default:
			if _, err := a.Sys.Run(ctx, nil, "systemctl", "unmask", "--runtime", unit); err != nil {
				errs = append(errs, err)
			}
			if _, err := a.Sys.Run(ctx, nil, "systemctl", "unmask", unit); err != nil {
				errs = append(errs, err)
			}
			if len(errs) == 0 && ok && was.Active {
				if _, err := a.Sys.Run(ctx, nil, "systemctl", "start", unit); err != nil {
					errs = append(errs, err)
				}
			}
		}
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
		delete(o.Units, unit)
		return nil
	case b.Strip != nil:
		if othersHold(st, e, s) {
			return nil
		}
		saved, ok := o.Modes[b.Strip.Path]
		if !ok {
			return nil
		}
		// The mode goes back only onto the same file. If an upgrade has
		// replaced it, the package's mode stands.
		if _, err := a.Sys.ChmodIf(b.Strip.Path, FileID{Dev: saved.Dev, Ino: saved.Ino}, fs.FileMode(saved.Mode)); err != nil {
			return err
		}
		delete(o.Modes, b.Strip.Path)
		return nil
	}
	return errors.New("empty step")
}

// takeOff takes off every step of e that may be on, in reverse. If all
// went, it removes e from the state. If any failed, e stays, Applying with
// every step counted and the failure noted, so that undo and boot try again
// and status shows it.
func (a *Agent) takeOff(ctx context.Context, st *State, e *Entry) error {
	ss := steps(e.Guard)
	var errs []error
	for i := reached(e, len(ss)) - 1; i >= 0; i-- {
		if err := a.undoStep(ctx, st, e, ss[i]); err != nil {
			errs = append(errs, fmt.Errorf("taking off %q: %w", ss[i].describe(), err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		e.Status, e.Applied, e.Failed = Applying, len(ss), err.Error()
		return err
	}
	st.remove(e.Hash)
	return nil
}

// writeSysctlFile writes the confirmed guards' settings where the system
// sets them at boot, or removes the file when there are none.
func (a *Agent) writeSysctlFile(st *State) error {
	byName := map[string][]string{}
	value := map[string]string{}
	for _, e := range st.Guards {
		if e.Status != Confirmed {
			continue
		}
		for _, b := range e.Guard.Blocks {
			if b.Setting != nil {
				byName[b.Setting.Name] = append(byName[b.Setting.Name], e.Guard.Name())
				value[b.Setting.Name] = b.Setting.Value
			}
		}
	}
	if len(byName) == 0 {
		return a.Sys.Remove(SysctlFile)
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# Written by autopatch for its confirmed guards; it rewrites this file.\n")
	for _, n := range names {
		fmt.Fprintf(&b, "# %s\n%s = %s\n", strings.Join(byName[n], ", "), n, value[n])
	}
	return a.Sys.WriteFile(SysctlFile, []byte(b.String()), 0o644)
}

// probe runs the agent's own probe and checks that the one rule it targets
// (rule, among the guard's IPv4 drops) counted it.
func (a *Agent) probe(ctx context.Context, e *Entry, rule int) error {
	table := nft.TableName(e.Hash)
	before, err := a.rulePackets(ctx, "ip", table, rule)
	if err != nil {
		return err
	}
	if err := a.Sys.ProbeIPOptions(ctx); err != nil {
		return err
	}
	after, err := a.rulePackets(ctx, "ip", table, rule)
	if err != nil {
		return err
	}
	if after <= before {
		return fmt.Errorf("probe: the probe was stopped, but not by %s's rule", e.Guard.Name())
	}
	return nil
}

// rulePackets returns the packets one rule of a guard table has counted.
// The agent writes the rules in order, and nft lists them in that order.
func (a *Agent) rulePackets(ctx context.Context, family, table string, rule int) (uint64, error) {
	lt, err := a.liveTable(ctx, family, table)
	if err != nil {
		return 0, err
	}
	if rule >= len(lt.Rules) {
		return 0, fmt.Errorf("table %s has %d rules, not %d", table, len(lt.Rules), rule+1)
	}
	return lt.Rules[rule].Packets, nil
}

func (a *Agent) liveTable(ctx context.Context, family, table string) (*nft.LiveTable, error) {
	out, err := a.Sys.Run(ctx, nil, "nft", "-j", "list", "table", family, table)
	if err != nil {
		return nil, err
	}
	return nft.ParseList(out, table)
}

// Confirm keeps a pending guard on for good: across reboots, with its undo
// disarmed.
func (a *Agent) Confirm(ctx context.Context, key string) (*Entry, error) {
	s, st, err := a.open()
	if err != nil {
		return nil, err
	}
	defer s.close()
	e, err := st.lookup(key)
	if err != nil {
		return nil, err
	}
	switch e.Status {
	case Confirmed:
		return e, nil
	case Applying:
		return nil, fmt.Errorf("%s is half on (%s); run undo or boot first", e.Guard.Name(), halfOn(e))
	}
	return e, a.confirm(ctx, s, st, e)
}

func (a *Agent) confirm(ctx context.Context, s *store, st *State, e *Entry) error {
	// Lasting forms first: a runtime mask becomes a mask.
	for _, stp := range steps(e.Guard) {
		if stp.block.Service != nil {
			if err := a.applyStep(ctx, st, e, stp, true); err != nil {
				return err
			}
		}
	}
	e.Status = Confirmed
	e.ConfirmBy = time.Time{}
	if e.BootWindow {
		e.BootWindow, e.Booted = false, true
	}
	if err := a.writeSysctlFile(st); err != nil {
		return err
	}
	// Saved before disarming: if the timer fires in between, it finds the
	// guard confirmed and leaves it.
	if err := s.save(st); err != nil {
		return err
	}
	return a.Timer.Disarm(ctx, e.Hash)
}

// Undo takes a guard off. With ifUnconfirmed, a confirmed guard stays on:
// that is how the undo timer calls it.
func (a *Agent) Undo(ctx context.Context, key string, ifUnconfirmed bool) (*Entry, error) {
	s, st, err := a.open()
	if err != nil {
		return nil, err
	}
	defer s.close()
	e, err := st.lookup(key)
	if err != nil {
		if ifUnconfirmed {
			return nil, nil // already off
		}
		return nil, err
	}
	if ifUnconfirmed && e.Status == Confirmed {
		return nil, nil
	}
	uerr := a.takeOff(ctx, st, e)
	ferr := a.writeSysctlFile(st)
	serr := s.save(st)
	if uerr == nil && serr == nil {
		a.Timer.Disarm(ctx, e.Hash)
	}
	return e, errors.Join(uerr, ferr, serr)
}

// Boot runs early at every boot. It takes off what was never confirmed (or
// failed to come off before), and puts back what was confirmed, unless this
// release no longer allows it or it is unsafe on the machine now; those it
// takes off too. It does as much as it can and reports every failure.
func (a *Agent) Boot(ctx context.Context) error {
	s, st, err := a.open()
	if err != nil {
		return err
	}
	defer s.close()
	var errs []error
	var windows []string
	for _, e := range append([]*Entry(nil), st.Guards...) {
		if e.Status == Confirmed {
			why := ""
			if err := e.Guard.Validate(); err != nil {
				why = "this release no longer allows it: " + err.Error()
			} else if probs := a.unsafe(e.Guard); len(probs) > 0 {
				why = "it is unsafe on this machine now: " + strings.Join(probs, "; ")
			}
			if why == "" {
				for _, stp := range steps(e.Guard) {
					if err := a.applyStep(ctx, st, e, stp, true); err != nil {
						errs = append(errs, fmt.Errorf("%s: putting back %q: %w", e.Guard.Name(), stp.describe(), err))
					}
				}
				// A guard that bites later gets one more window after its
				// first boot, with its undo armed: the boot is when it
				// bites. A keep guard has no window: back on after a boot is
				// what it can show, and it counts as booted.
				if e.Later && !e.Booted && e.By != "" {
					if e.Keep {
						e.Booted = true
					} else {
						now := a.now()
						e.Status, e.BootWindow, e.AppliedAt, e.ConfirmBy = Pending, true, now, now.Add(a.bootArm())
						windows = append(windows, e.Hash)
					}
				}
				continue
			}
			errs = append(errs, fmt.Errorf("%s: taken off because %s", e.Guard.Name(), why))
		}
		if err := a.takeOff(ctx, st, e); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Guard.Name(), err))
		}
	}
	errs = append(errs, a.writeSysctlFile(st), s.save(st))
	for _, h := range windows { // armed after the save, as Apply does
		if err := a.Timer.Arm(ctx, h, a.bootArm()); err != nil {
			errs = append(errs, fmt.Errorf("arming the undo for %s's window after boot: %w", h[:12], err))
		}
	}
	return errors.Join(errs...)
}

// bootArm is how long a window after a boot keeps its undo armed: the
// longest grace among this machine's checks, the window, and five minutes.
func (a *Agent) bootArm() time.Duration {
	grace := policy.DefaultGrace
	if f, err := a.loadFleet(); err == nil {
		if p, err := f.InstalledPolicy(); err == nil {
			for _, h := range checksFor(p, f.Host) {
				grace = max(grace, h.Grace())
			}
		}
	}
	return time.Duration(grace)*time.Second + trialArm
}

// SetKeep marks a guard on this machine as the owner's keep: a guard in its
// window is confirmed now, and it gets no window after a boot. It reports
// whether the guard is on here.
func (a *Agent) SetKeep(ctx context.Context, hash string) (bool, error) {
	s, st, err := a.open()
	if err != nil {
		return false, err
	}
	defer s.close()
	e := st.find(hash)
	if e == nil {
		return false, nil
	}
	if e.Status == Applying {
		return true, nil // half on: undo or boot deals with it first
	}
	e.Keep = true
	if e.Status == Pending {
		return true, a.confirm(ctx, s, st, e)
	}
	return true, s.save(st)
}

// Drift is a difference between what a guard set and what is live, or a
// guard that is no longer safe here.
type Drift struct {
	Guard    string
	What     string
	Repaired bool // put back
	TakenOff bool // taken off as no longer allowed or safe, or after a failed undo
	Err      error
}

// Check compares each guard's live state with what the agent set. With
// repair, it puts drifted steps back and probes again, retries failed undos,
// and takes off guards that are no longer allowed or safe here.
func (a *Agent) Check(ctx context.Context, repair bool) ([]Drift, error) {
	s, st, err := a.open()
	if err != nil {
		return nil, err
	}
	defer s.close()
	var out []Drift
	for _, e := range append([]*Entry(nil), st.Guards...) {
		name := e.Guard.Name()
		if e.Status == Applying {
			d := Drift{Guard: name, What: "half on: " + halfOn(e)}
			if repair {
				d.Err = a.takeOff(ctx, st, e)
				d.TakenOff = d.Err == nil
			}
			out = append(out, d)
			continue
		}
		why := ""
		if err := e.Guard.Validate(); err != nil {
			why = "this release no longer allows it: " + err.Error()
		} else if probs := a.unsafe(e.Guard); len(probs) > 0 {
			why = "unsafe on this machine now: " + strings.Join(probs, "; ")
		}
		if why != "" {
			d := Drift{Guard: name, What: why}
			if repair {
				d.Err = a.takeOff(ctx, st, e)
				d.TakenOff = d.Err == nil
			}
			out = append(out, d)
			continue
		}
		if e.Status == Pending && a.now().After(e.ConfirmBy.Add(time.Minute)) {
			out = append(out, Drift{Guard: name, What: "pending past its confirm time; its undo should have run"})
		}
		ss := steps(e.Guard)
		for i := 0; i < e.Applied && i < len(ss); i++ {
			what := a.verify(ctx, st, e, ss[i])
			if what == "" {
				continue
			}
			d := Drift{Guard: name, What: what}
			if repair {
				d.Err = a.applyStep(ctx, st, e, ss[i], e.Status == Confirmed)
				if r := probeRule(e.Guard); d.Err == nil && ss[i].family == "ip" && r >= 0 {
					d.Err = a.probe(ctx, e, r)
				}
				d.Repaired = d.Err == nil
			}
			out = append(out, d)
		}
	}
	if repair {
		if err := errors.Join(a.writeSysctlFile(st), s.save(st)); err != nil {
			return out, err
		}
	}
	return out, nil
}

// verify says how a step's live state differs from what the agent set, or
// "" if it doesn't.
func (a *Agent) verify(ctx context.Context, st *State, e *Entry, s step) string {
	switch b := s.block; {
	case s.drops != nil:
		table := nft.TableName(e.Hash)
		lt, err := a.liveTable(ctx, s.family, table)
		if err != nil {
			return "the guard's " + s.family + " table is missing or unreadable"
		}
		if lt.Hook != "prerouting" || lt.Priority != nft.Priority || len(lt.Rules) != len(s.drops) {
			return "the guard's " + s.family + " table isn't as the agent wrote it"
		}
		for _, r := range lt.Rules {
			if r.Comment != e.Guard.Name() {
				return "the guard's " + s.family + " table holds a rule the agent didn't write"
			}
		}
	case b.Setting != nil:
		if v, err := a.Sys.ReadSetting(b.Setting.Name); err != nil || v != b.Setting.Value {
			return fmt.Sprintf("%s is %q, not %s", b.Setting.Name, v, b.Setting.Value)
		}
	case b.Module != nil:
		if got, err := a.Sys.ReadFile(modprobeFile(e.Hash, b.Module.Name)); err != nil || string(got) != modprobeText(b.Module.Name) {
			return "the block on module " + b.Module.Name + " is missing or changed"
		}
	case b.Service != nil:
		out, _ := a.Sys.Run(ctx, nil, "systemctl", "is-enabled", b.Service.Unit)
		if en := strings.TrimSpace(string(out)); en != "masked" && en != "masked-runtime" {
			return b.Service.Unit + " is " + en + ", not masked"
		}
		out, _ = a.Sys.Run(ctx, nil, "systemctl", "is-active", b.Service.Unit)
		if act := strings.TrimSpace(string(out)); act == "active" || act == "activating" || act == "reloading" {
			return b.Service.Unit + " is masked but still " + act
		}
	case b.Strip != nil:
		id, err := a.Sys.FileID(b.Strip.Path)
		if err != nil {
			return err.Error()
		}
		if id.Mode&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
			return b.Strip.Path + " has its setuid or setgid bit again (an upgrade puts it back)"
		}
	}
	return ""
}

// Status lists the guards on this machine with the packets each guard's
// drops have stopped (-1 where a table can't be read).
func (a *Agent) Status(ctx context.Context) ([]*Entry, map[string]int64, error) {
	s, st, err := a.open()
	if err != nil {
		return nil, nil, err
	}
	defer s.close()
	hits := map[string]int64{}
	for _, e := range st.Guards {
		var n int64
		for f := range nft.Tables(e.Guard) {
			lt, err := a.liveTable(ctx, f, nft.TableName(e.Hash))
			if err != nil {
				n = -1
				break
			}
			for _, r := range lt.Rules {
				n += int64(r.Packets)
			}
		}
		hits[e.Hash] = n
	}
	return st.Guards, hits, nil
}

func (a *Agent) open() (*store, *State, error) {
	s, err := openStore(a.StateDir)
	if err != nil {
		return nil, nil, err
	}
	st, err := s.load()
	if err != nil {
		s.close()
		return nil, nil, err
	}
	return s, st, nil
}

// lookup finds a guard by its full hash, a hash prefix of 8 or more hex
// digits, or its ID.
func (st *State) lookup(key string) (*Entry, error) {
	var found []*Entry
	for _, e := range st.Guards {
		if e.Hash == key || e.Guard.ID == key || (len(key) >= 8 && strings.HasPrefix(e.Hash, key)) {
			found = append(found, e)
		}
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("no guard %q is on", key)
	case 1:
		return found[0], nil
	}
	return nil, fmt.Errorf("%q names more than one guard; give more of the hash", key)
}
