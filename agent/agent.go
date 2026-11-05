// Package agent puts guards on one machine and takes them off.
//
// Every change is written ahead in the state file and has its undo armed
// before it is made. A guard goes on live and pending: a reboot or the undo
// timer takes it off unless it is confirmed. Confirming makes it stay across
// reboots. The boot command takes off whatever was never confirmed and puts
// back what was.
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
)

// Files the agent owns.
const (
	SysctlFile  = "/etc/sysctl.d/90-autopatch.conf"
	modprobeDir = "/etc/modprobe.d"
)

// Agent acts for the guards on one machine.
type Agent struct {
	Sys      System
	Timer    Timer
	StateDir string
	Now      func() time.Time
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
	drops  []*guard.Drop // a table step's drops
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

func modprobeFile(hash, module string) string {
	return modprobeDir + "/autopatch-" + hash[:12] + "-" + module + ".conf"
}

func modprobeText(module string) string {
	return "# autopatch: this module is blocked by a guard.\ninstall " + module + " /bin/false\nblacklist " + module + "\n"
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
	// block would take away.
	InUse []string
	// Probed reports whether the agent can probe the guard's drops; true
	// for a guard without drops.
	Probed bool
}

// Plan says what the guard would do here, and changes nothing.
func (a *Agent) Plan(g *guard.Guard) (*Plan, error) {
	sys, err := a.Sys.Info()
	if err != nil {
		return nil, err
	}
	hasDrops, probeable := probeKind(g)
	p := &Plan{Hash: g.Hash(), System: sys, Probed: !hasDrops || probeable}
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
			}
		}
		if s.block.Strip != nil {
			if fi, err := a.Sys.Lstat(s.block.Strip.Path); err != nil {
				p.Problems = append(p.Problems, err.Error())
			} else if !fi.Mode().IsRegular() {
				p.Problems = append(p.Problems, s.block.Strip.Path+" is not a regular file")
			}
		}
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

// probeKind reports whether the guard has drops, and whether the agent has
// its own probe for them: today, inbound IPv4 TCP (or any protocol)
// carrying IP options, on any port.
func probeKind(g *guard.Guard) (hasDrops, probeable bool) {
	for _, b := range g.Blocks {
		if d := b.Drop; d != nil {
			hasDrops = true
			if d.Family == "ipv4" && d.IPOptions && (d.Protocol == "tcp" || d.Protocol == "") && len(d.Ports) == 0 {
				probeable = true
			}
		}
	}
	return hasDrops, probeable
}

// ApplyOptions say how a guard goes on.
type ApplyOptions struct {
	// ConfirmWithin is how long the guard stays on before its undo runs,
	// unless confirmed. Zero confirms it as soon as its probe passes.
	ConfirmWithin time.Duration
	// Force puts a block on even when something uses what it takes away.
	Force bool
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
			return nil, fmt.Errorf("%s is half on from a run that died; run boot or undo first", g.Name())
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
	if len(p.Problems) > 0 {
		return nil, fmt.Errorf("%s can't go on here: %s", g.Name(), strings.Join(p.Problems, "; "))
	}
	if len(p.InUse) > 0 && !o.Force {
		return nil, fmt.Errorf("%s would take away something in use (-force overrides): %s", g.Name(), strings.Join(p.InUse, "; "))
	}

	arm := max(o.ConfirmWithin, minArm)
	start := a.now()
	e := &Entry{Hash: h, Guard: g, Status: Applying, AppliedAt: start, ConfirmBy: start.Add(arm)}
	st.Guards = append(st.Guards, e)
	if err := s.save(st); err != nil {
		return nil, err
	}
	if err := a.Timer.Arm(ctx, h, arm); err != nil {
		st.remove(h)
		return nil, errors.Join(fmt.Errorf("arming the undo: %w", err), s.save(st))
	}
	fail := func(err error) (*Entry, error) {
		uerr := a.undoSteps(ctx, st, e)
		st.remove(h)
		ferr := a.writeSysctlFile(st)
		serr := s.save(st)
		a.Timer.Disarm(ctx, h)
		return nil, errors.Join(err, uerr, ferr, serr)
	}
	for i, stp := range steps(g) {
		if err := a.capture(ctx, st, stp); err != nil {
			return fail(err)
		}
		if err := s.save(st); err != nil {
			return fail(err)
		}
		if err := a.applyStep(ctx, e, stp, false); err != nil {
			return fail(fmt.Errorf("putting on %q: %w", stp.describe(), err))
		}
		e.Applied = i + 1
		if err := s.save(st); err != nil {
			return fail(err)
		}
	}
	switch hasDrops, probeable := probeKind(g); {
	case probeable:
		if err := a.probe(ctx, e); err != nil {
			return fail(err)
		}
	case hasDrops:
		e.Unprobed = true
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
		fi, err := a.Sys.Lstat(b.Strip.Path)
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", b.Strip.Path)
		}
		if o.Modes == nil {
			o.Modes = map[string]uint32{}
		}
		o.Modes[b.Strip.Path] = uint32(fi.Mode())
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
// clears, where the system allows it (a runtime mask); confirmed ones also
// change what lasts.
func (a *Agent) applyStep(ctx context.Context, e *Entry, s step, lasting bool) error {
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
		if _, err := a.Sys.Run(ctx, nil, "systemctl", "stop", b.Service.Unit); err != nil {
			return err
		}
		args := []string{"mask", "--runtime", b.Service.Unit}
		if lasting {
			args = []string{"mask", b.Service.Unit}
		}
		_, err := a.Sys.Run(ctx, nil, "systemctl", args...)
		return err
	case b.Strip != nil:
		fi, err := a.Sys.Lstat(b.Strip.Path)
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", b.Strip.Path)
		}
		return a.Sys.Chmod(b.Strip.Path, fi.Mode()&^(fs.ModeSetuid|fs.ModeSetgid))
	}
	return errors.New("empty step")
}

// othersHold reports whether a guard other than e also changes what step s
// changes, so that taking e off must leave it changed.
func othersHold(st *State, e *Entry, s step) bool {
	for _, o := range st.Guards {
		if o == e {
			continue
		}
		for _, b := range o.Guard.Blocks {
			switch {
			case s.block.Setting != nil && b.Setting != nil && b.Setting.Name == s.block.Setting.Name,
				s.block.Service != nil && b.Service != nil && b.Service.Unit == s.block.Service.Unit,
				s.block.Strip != nil && b.Strip != nil && b.Strip.Path == s.block.Strip.Path:
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
		was, ok := o.Units[b.Service.Unit]
		if ok && (was.Enabled == "masked" || was.Enabled == "masked-runtime") {
			delete(o.Units, b.Service.Unit) // it was masked before any guard
			return nil
		}
		a.Sys.Run(ctx, nil, "systemctl", "unmask", "--runtime", b.Service.Unit)
		if _, err := a.Sys.Run(ctx, nil, "systemctl", "unmask", b.Service.Unit); err != nil {
			return err
		}
		if ok && was.Active {
			if _, err := a.Sys.Run(ctx, nil, "systemctl", "start", b.Service.Unit); err != nil {
				return err
			}
		}
		delete(o.Units, b.Service.Unit)
		return nil
	case b.Strip != nil:
		if othersHold(st, e, s) {
			return nil
		}
		if m, ok := o.Modes[b.Strip.Path]; ok {
			if err := a.Sys.Chmod(b.Strip.Path, fs.FileMode(m)); err != nil {
				return err
			}
			delete(o.Modes, b.Strip.Path)
		}
		return nil
	}
	return errors.New("empty step")
}

// undoSteps takes off, in reverse, every step of e that may be on: those
// below Applied, and the one at Applied if e died while applying it.
func (a *Agent) undoSteps(ctx context.Context, st *State, e *Entry) error {
	ss := steps(e.Guard)
	n := e.Applied
	if e.Status == Applying && n < len(ss) {
		n++
	}
	var errs []error
	for i := n - 1; i >= 0; i-- {
		if err := a.undoStep(ctx, st, e, ss[i]); err != nil {
			errs = append(errs, fmt.Errorf("taking off %q: %w", ss[i].describe(), err))
		}
	}
	return errors.Join(errs...)
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

// probe runs the agent's own probe and checks that the guard's own rule
// counted it.
func (a *Agent) probe(ctx context.Context, e *Entry) error {
	table := nft.TableName(e.Hash)
	before, err := a.packets(ctx, "ip", table)
	if err != nil {
		return err
	}
	if err := a.Sys.ProbeIPOptions(ctx); err != nil {
		return err
	}
	after, err := a.packets(ctx, "ip", table)
	if err != nil {
		return err
	}
	if after <= before {
		return fmt.Errorf("probe: the probe was stopped, but not by %s's rule", e.Guard.Name())
	}
	return nil
}

// packets returns the packets counted by a guard table's rules.
func (a *Agent) packets(ctx context.Context, family, table string) (uint64, error) {
	lt, err := a.liveTable(ctx, family, table)
	if err != nil {
		return 0, err
	}
	var n uint64
	for _, r := range lt.Rules {
		n += r.Packets
	}
	return n, nil
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
		return nil, fmt.Errorf("%s is half on from a run that died; run boot or undo first", e.Guard.Name())
	}
	return e, a.confirm(ctx, s, st, e)
}

func (a *Agent) confirm(ctx context.Context, s *store, st *State, e *Entry) error {
	// Lasting forms first: a runtime mask becomes a mask.
	for _, stp := range steps(e.Guard) {
		if stp.block.Service != nil {
			if err := a.applyStep(ctx, e, stp, true); err != nil {
				return err
			}
		}
	}
	e.Status = Confirmed
	e.ConfirmBy = time.Time{}
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
	uerr := a.undoSteps(ctx, st, e)
	st.remove(e.Hash)
	ferr := a.writeSysctlFile(st)
	if err := s.save(st); err != nil {
		return e, errors.Join(uerr, ferr, err)
	}
	a.Timer.Disarm(ctx, e.Hash)
	return e, errors.Join(uerr, ferr)
}

// Boot runs early at every boot: it takes off what was never confirmed and
// puts back what was. It does as much as it can and reports every failure.
func (a *Agent) Boot(ctx context.Context) error {
	s, st, err := a.open()
	if err != nil {
		return err
	}
	defer s.close()
	var errs []error
	for _, e := range append([]*Entry(nil), st.Guards...) {
		if e.Status == Confirmed {
			for _, stp := range steps(e.Guard) {
				if err := a.applyStep(ctx, e, stp, true); err != nil {
					errs = append(errs, fmt.Errorf("%s: putting back %q: %w", e.Guard.Name(), stp.describe(), err))
				}
			}
			continue
		}
		if err := a.undoSteps(ctx, st, e); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Guard.Name(), err))
		}
		st.remove(e.Hash)
	}
	errs = append(errs, a.writeSysctlFile(st), s.save(st))
	return errors.Join(errs...)
}

// Drift is a difference between what a guard set and what is live.
type Drift struct {
	Guard    string
	What     string
	Repaired bool
	Err      error
}

// Check compares each guard's live state with what the agent set. With
// repair, it puts drifted steps back and probes again.
func (a *Agent) Check(ctx context.Context, repair bool) ([]Drift, error) {
	s, st, err := a.open()
	if err != nil {
		return nil, err
	}
	defer s.close()
	var out []Drift
	for _, e := range st.Guards {
		if e.Status == Applying {
			out = append(out, Drift{Guard: e.Guard.Name(), What: "half on from a run that died; run boot or undo"})
			continue
		}
		if e.Status == Pending && a.now().After(e.ConfirmBy.Add(time.Minute)) {
			out = append(out, Drift{Guard: e.Guard.Name(), What: "pending past its confirm time; its undo should have run"})
		}
		ss := steps(e.Guard)
		for i := 0; i < e.Applied && i < len(ss); i++ {
			what := a.verify(ctx, e, ss[i])
			if what == "" {
				continue
			}
			d := Drift{Guard: e.Guard.Name(), What: what}
			if repair {
				d.Err = a.applyStep(ctx, e, ss[i], e.Status == Confirmed)
				if _, probeable := probeKind(e.Guard); d.Err == nil && ss[i].drops != nil && probeable {
					d.Err = a.probe(ctx, e)
				}
				d.Repaired = d.Err == nil
			}
			out = append(out, d)
		}
	}
	return out, nil
}

// verify says how a step's live state differs from what the agent set, or
// "" if it doesn't.
func (a *Agent) verify(ctx context.Context, e *Entry, s step) string {
	switch b := s.block; {
	case s.drops != nil:
		lt, err := a.liveTable(ctx, s.family, nft.TableName(e.Hash))
		if err != nil {
			return "table " + nft.TableName(e.Hash) + " is missing or unreadable"
		}
		if lt.Hook != "prerouting" || lt.Priority != nft.Priority || len(lt.Rules) != len(s.drops) {
			return "table " + nft.TableName(e.Hash) + " isn't as the agent wrote it"
		}
		for _, r := range lt.Rules {
			if r.Comment != e.Guard.Name() {
				return "table " + nft.TableName(e.Hash) + " holds a rule the agent didn't write"
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
		if st := strings.TrimSpace(string(out)); st != "masked" && st != "masked-runtime" {
			return b.Service.Unit + " is " + st + ", not masked"
		}
	case b.Strip != nil:
		fi, err := a.Sys.Lstat(b.Strip.Path)
		if err != nil {
			return b.Strip.Path + ": " + err.Error()
		}
		if fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
			return b.Strip.Path + " has its setuid or setgid bit again (an upgrade puts it back)"
		}
	}
	return ""
}

// Status lists the guards on this machine with the packets each guard's
// drops have stopped (-1 where the table can't be read).
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
			p, err := a.packets(ctx, f, nft.TableName(e.Hash))
			if err != nil {
				n = -1
				break
			}
			n += int64(p)
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
