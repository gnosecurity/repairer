package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/policy"
)

// Reboots by tier (B3; AUTOPATCH.md, "Reboots and kernels"). A reboot is
// owed when the newest installed kernel isn't the one running. The tier
// says who may reboot: "window", the agent itself inside the tier's window,
// once a day, never while a guard is on trial; "yes", only on the owner's
// signed Reboot; "never". Every reboot is a one-shot boot: GRUB's saved
// default is pinned to the running kernel, the new one is booted once with
// grub-reboot, and it becomes the default only after health holds through
// a trial window. A boot that panics (panic= on the command line) comes
// back on the old default; the agent marks that kernel failed and never
// tries it again by itself. The owner's signed Reboot(host, kernel, not
// after) lets one reboot into that kernel happen at the next tick the gates
// pass, whatever the tier says, once.

const rebootFile = "reboot.json"

// RebootDeadline is how long after rebooting the agent waits to find the
// new kernel running; back by then on another kernel, the new one didn't
// boot.
var RebootDeadline = 15 * time.Minute

// Phases of a reboot into a newer kernel.
const (
	Rebooting = "rebooting" // grub-reboot set, the machine told to reboot
	Booted    = "booted"    // running the new kernel, in its health window
	Settled   = "settled"   // health held: the new kernel is the default
	BootFail  = "failed"    // didn't boot, or health failed after it
)

// rebootState is the agent's record of its reboots, in reboot.json.
type rebootState struct {
	Kernel  string    `json:"kernel,omitempty"` // the release it booted into, or tried to
	Entry   string    `json:"entry,omitempty"`  // the GRUB entry booted once
	Phase   string    `json:"phase,omitempty"`
	Since   time.Time `json:"since,omitempty"` // when the phase began
	Why     string    `json:"why,omitempty"`
	Day     string    `json:"day,omitempty"`     // the UTC day of the last reboot it began
	Failing []string  `json:"failing,omitempty"` // checks failing just before it rebooted
	Failed  []string  `json:"failed,omitempty"`  // kernels that didn't boot or didn't hold
	// Spent is the owner sequence of the newest Reboot a reboot began on:
	// that one and every older one are spent. It is kept here, written
	// before the machine reboots, so no Reboot is used twice.
	Spent uint64 `json:"spent,omitempty"`
}

// maxFailed is how many failed kernels reboot.json remembers.
const maxFailed = 8

func (a *Agent) loadReboot() (*rebootState, error) {
	b, err := os.ReadFile(filepath.Join(a.StateDir, rebootFile))
	if errors.Is(err, fs.ErrNotExist) {
		return &rebootState{}, nil
	}
	if err != nil {
		return nil, err
	}
	var st rebootState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (a *Agent) saveReboot(st *rebootState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(a.StateDir, rebootFile), b, 0o600)
}

func (st *rebootState) failed(rel string) bool { return contains(st.Failed, rel) }

// fail ends the reboot into st.Kernel: it didn't boot, or didn't hold.
func (st *rebootState) fail(now time.Time, why string) {
	st.Phase, st.Since, st.Why = BootFail, now, why
	if !st.failed(st.Kernel) {
		st.Failed = append(st.Failed, st.Kernel)
		if n := len(st.Failed); n > maxFailed {
			st.Failed = st.Failed[n-maxFailed:]
		}
	}
}

// order finds the owner's Reboot that lets this machine reboot into newest
// now, if one does. It drops the spent ones, those for the kernel running,
// and those a day past their deadline; notes says why the others wait.
func (st *rebootState) order(f *Fleet, now time.Time, newest, running string) (use *RebootOrder, notes []string) {
	var keep []RebootOrder
	for _, o := range f.Reboots {
		switch {
		case o.Seq <= st.Spent || o.Kernel == running || now.After(o.NotAfter.Add(24*time.Hour)):
			continue
		case now.After(o.NotAfter):
			notes = append(notes, fmt.Sprintf("your Reboot #%d into %s passed its deadline unused", o.Seq, o.Kernel))
		case o.Kernel != newest:
			notes = append(notes, fmt.Sprintf("your Reboot #%d names %s, but the newest kernel installed is %s", o.Seq, o.Kernel, newest))
		default:
			o := o
			use = &o // the newest one, as the list is oldest first
		}
		keep = append(keep, o)
	}
	f.Reboots = keep
	return use, notes
}

// running is the release of the running kernel (uname -r).
func (a *Agent) running() string {
	b, _ := a.Sys.ReadFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(b))
}

// newestKernel is the release of the newest installed kernel package.
func (a *Agent) newestKernel(ctx context.Context) (string, error) {
	out, err := a.Sys.Run(ctx, nil, "dpkg-query", "-W", "-f", "${Package} ${Version} ${db:Status-Abbrev}\n", "linux-image-[0-9]*")
	if err != nil {
		return "", err
	}
	_, rel := installedKernels(out)
	return rel, nil
}

// grubReady says why GRUB can't boot a new kernel once and come back from
// a panic, or nil: the default must be the saved entry, and the kernel
// command line must reboot on a panic.
func (a *Agent) grubReady(ctx context.Context) error {
	def := ""
	files := []string{"/etc/default/grub"}
	if out, err := a.Sys.Run(ctx, nil, "ls", "/etc/default/grub.d"); err == nil {
		for _, n := range strings.Fields(string(out)) {
			if strings.HasSuffix(n, ".cfg") {
				files = append(files, "/etc/default/grub.d/"+n)
			}
		}
	}
	for _, f := range files { // the last setting wins, as grub-mkconfig reads them
		b, err := a.Sys.ReadFile(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if v, ok := strings.CutPrefix(line, "GRUB_DEFAULT="); ok {
				def = strings.Trim(v, `"'`)
			}
		}
	}
	if def != "saved" {
		return fmt.Errorf("GRUB_DEFAULT is %q, not saved: a one-shot boot needs it", def)
	}
	cmd, _ := a.Sys.ReadFile("/proc/cmdline")
	for _, w := range strings.Fields(string(cmd)) {
		if v, ok := strings.CutPrefix(w, "panic="); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return nil
			}
		}
	}
	return errors.New("the kernel command line has no panic=N: a new kernel that panicked would hang instead of coming back")
}

var menuID = regexp.MustCompile(`\$menuentry_id_option '([^']+)'`)

// grubEntry finds release rel's normal (not recovery) menu entry in
// grub.cfg, as grub-reboot and grub-set-default take it: "submenu>entry".
func grubEntry(cfg []byte, rel string) (string, error) {
	var submenus []string // the ids of the submenus open at this line
	depth := []bool{}     // for each open brace: whether it opened a submenu
	sc := bufio.NewScanner(bytes.NewReader(cfg))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "submenu ") && strings.HasSuffix(line, "{"):
			id := ""
			if m := menuID.FindStringSubmatch(line); m != nil {
				id = m[1]
			}
			submenus = append(submenus, id)
			depth = append(depth, true)
		case strings.HasPrefix(line, "menuentry ") && strings.HasSuffix(line, "{"):
			if m := menuID.FindStringSubmatch(line); m != nil && strings.Contains(m[1], "-"+rel+"-") && !strings.Contains(m[1], "recovery") {
				path := append(append([]string{}, submenus...), m[1])
				return strings.Join(path, ">"), nil
			}
			depth = append(depth, false)
		case line == "}":
			if n := len(depth); n > 0 {
				if depth[n-1] && len(submenus) > 0 {
					submenus = submenus[:len(submenus)-1]
				}
				depth = depth[:n-1]
			}
		case strings.HasSuffix(line, "{"):
			depth = append(depth, false) // if, function and the like
		}
	}
	return "", fmt.Errorf("no menu entry for %s in grub.cfg", rel)
}

// rebootStep moves a reboot into a newer kernel a step, after the guards'
// step: it follows a reboot in flight, or readies one when one is owed and
// the owner's Reboot or the tier allows it now. It says what it did, or why
// it waits, and whether to reboot: Tick runs rebootNow once its report is
// written.
func (a *Agent) rebootStep(ctx context.Context, f *Fleet, p *policy.Policy, sample map[string]string) (string, bool, error) {
	st, err := a.loadReboot()
	if err != nil {
		return "", false, err
	}
	now := a.now().UTC()
	running := a.running()
	switch st.Phase {
	case Rebooting:
		if running == st.Kernel {
			st.Phase, st.Since = Booted, now
			return "booted into " + running + "; its health window runs", false, a.saveReboot(st)
		}
		if now.Sub(st.Since) < RebootDeadline {
			return "rebooting into " + st.Kernel, false, nil
		}
		st.fail(now, st.Kernel+" didn't boot: back on "+running)
		return st.Why, false, a.saveReboot(st)
	case Booted:
		if running != st.Kernel {
			st.fail(now, "back on "+running+" before "+st.Kernel+" settled")
			return st.Why, false, a.saveReboot(st)
		}
		if now.Sub(st.Since) < TrialWindow {
			return "booted into " + running + "; its health window runs", false, nil
		}
		var fresh []string // checks failing now that held before the reboot
		for _, name := range sortedKeys(sample) {
			if !contains(st.Failing, name) {
				fresh = append(fresh, name+": "+sample[name])
			}
		}
		if len(fresh) > 0 {
			st.fail(now, "health failed on "+running+": "+strings.Join(fresh, "; ")+"; the old kernel is still the default")
			return st.Why, false, a.saveReboot(st)
		}
		if _, err := a.Sys.Run(ctx, nil, "grub-set-default", st.Entry); err != nil {
			return "", false, fmt.Errorf("making %s the default: %w", st.Kernel, err)
		}
		st.Phase, st.Since, st.Why = Settled, now, ""
		return "rebooted into " + running + "; it is the default now", false, a.saveReboot(st)
	}

	newest, err := a.newestKernel(ctx)
	if err != nil || newest == "" {
		return "", false, nil
	}
	use, notes := st.order(f, now, newest, running)
	say := func(s string) string {
		if s == "" {
			return strings.Join(notes, "; ")
		}
		return strings.Join(append([]string{s}, notes...), "; ")
	}
	if newest == running {
		return say(""), false, nil // nothing owed
	}
	owed := "a reboot into " + newest + " is owed"
	if use != nil {
		owed += fmt.Sprintf("; your Reboot #%d allows it", use.Seq)
	} else {
		if st.failed(newest) {
			why := ""
			if st.Kernel == newest && st.Why != "" {
				why = " (" + st.Why + ")"
			}
			return say(owed + "; it failed before" + why + ", so it waits for your signed Reboot"), false, nil
		}
		tier, ok := p.TierOf(f.Host)
		if !ok {
			return say(owed + "; this host is in no tier"), false, nil
		}
		switch tier.RebootMode() {
		case "never":
			return say(owed + "; this tier never reboots by itself"), false, nil
		case "yes":
			return say(owed + "; this tier waits for your signed Reboot"), false, nil
		case "window":
			if !tier.InWindow(now) {
				return say(owed + "; it waits for the window " + tier.RebootWindow + " UTC"), false, nil
			}
			if st.Day == now.Format("2006-01-02") {
				return say(owed + "; this machine rebooted today"), false, nil
			}
		}
		if tier.RebootAfter != "" {
			return say(owed + "; ordered reboots (after " + tier.RebootAfter + ") wait for your signed Reboot"), false, nil
		}
	}
	entries, _, err := a.Status(ctx)
	if err != nil {
		return "", false, err
	}
	for _, e := range entries {
		if e.Status == Pending {
			return say(owed + "; it waits for " + e.Guard.Name() + "'s trial"), false, nil
		}
	}
	var bad []string
	for _, g := range a.Gates(ctx) {
		if !g.OK {
			bad = append(bad, g.Name+": "+g.Why)
		}
	}
	if len(bad) > 0 {
		return say(owed + "; the gates hold it: " + strings.Join(bad, "; ")), false, nil
	}
	if err := a.grubReady(ctx); err != nil {
		return say(owed + "; " + err.Error()), false, nil
	}
	cfg, err := a.Sys.ReadFile("/boot/grub/grub.cfg")
	if err != nil {
		return say(owed + "; can't read grub.cfg: " + err.Error()), false, nil
	}
	newEntry, err := grubEntry(cfg, newest)
	if err != nil {
		return say(owed + "; " + err.Error()), false, nil
	}
	oldEntry, err := grubEntry(cfg, running)
	if err != nil {
		return say(owed + "; " + err.Error()), false, nil
	}
	spent := st.Spent
	if use != nil {
		spent = max(spent, use.Seq)
		f.Reboots = slices.DeleteFunc(f.Reboots, func(o RebootOrder) bool { return o.Seq <= spent })
	}
	*st = rebootState{Kernel: newest, Entry: newEntry, Phase: Rebooting, Since: now, Day: now.Format("2006-01-02"),
		Failing: sortedKeys(sample), Failed: st.Failed, Spent: spent}
	if err := a.saveReboot(st); err != nil {
		return "", false, err
	}
	// The running kernel is the default, so a boot that panics comes back
	// to it; the new one boots once.
	for _, c := range [][]string{{"grub-set-default", oldEntry}, {"grub-reboot", newEntry}} {
		if _, err := a.Sys.Run(ctx, nil, c[0], c[1:]...); err != nil {
			st.fail(now, c[0]+": "+err.Error())
			return "", false, errors.Join(fmt.Errorf("rebooting into %s: %s: %w", newest, c[0], err), a.saveReboot(st))
		}
	}
	return "rebooting into " + newest, true, nil
}

// rebootNow reboots the machine into the kernel rebootStep readied. If the
// reboot can't be asked for, the one-shot boot is taken back and the reboot
// marked failed.
func (a *Agent) rebootNow(ctx context.Context) error {
	if _, err := a.Sys.Run(ctx, nil, "systemctl", "reboot"); err != nil {
		_, uerr := a.Sys.Run(ctx, nil, "grub-editenv", "-", "unset", "next_entry")
		st, lerr := a.loadReboot()
		if lerr != nil {
			return errors.Join(err, uerr, lerr)
		}
		st.fail(a.now().UTC(), "systemctl reboot: "+err.Error())
		return errors.Join(fmt.Errorf("rebooting into %s: %w", st.Kernel, err), uerr, a.saveReboot(st))
	}
	return nil
}
