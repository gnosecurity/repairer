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
	"strconv"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/policy"
)

// Reboots by tier (B3; AUTOPATCH.md, "Reboots and kernels"). A reboot is
// owed when the newest installed kernel isn't the one running. The tier
// says who may reboot: "window", the agent itself inside the tier's window,
// at most once in 20 hours, never while a guard is on trial; "yes", only on
// the owner's signed Reboot; "never". Every reboot first pins the kernel
// that last held here as GRUB's saved default; a new kernel is then booted
// once with grub-reboot, and becomes the default only after health holds
// through a trial window, judged as a boot's window is. A boot that panics
// (panic= on the command line) comes back on the pinned kernel; a kernel
// that didn't boot or didn't hold is marked failed and never tried again
// by itself, and a machine left on one owes a reboot back to the kernel
// that last held. The owner's signed Reboot(host, kernel, not after) lets
// one reboot into that kernel happen at the next tick the gates pass,
// whatever the tier says, once. With no newer kernel, a plain reboot is owed
// when the system asks for one (/run/reboot-required, left by packages such
// as libc6), when this machine is a canary of its tier holding an admitted
// guard that takes effect only after a boot, which the rest of the tier
// waits for (rule 4; once for each such guard), or on the owner's Reboot
// naming the running kernel: the same rules, and the health window after
// it. Whether the machine went down is told by the kernel's boot id, which
// changes on every boot.

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
	Kernel  string    `json:"kernel,omitempty"` // the release it rebooted into, or tried to
	Entry   string    `json:"entry,omitempty"`  // a new kernel's GRUB entry: booted once, the default once it holds
	Phase   string    `json:"phase,omitempty"`
	Since   time.Time `json:"since,omitempty"` // when the phase began
	Why     string    `json:"why,omitempty"`
	Began   time.Time `json:"began,omitzero"`    // when the last reboot began: a window tier waits 20 hours after it
	Failing []string  `json:"failing,omitempty"` // checks failing just before it rebooted: not the reboot's fault
	Failed  []string  `json:"failed,omitempty"`  // kernels that didn't boot or didn't hold
	// Spent is the owner sequence of the newest Reboot a reboot began on:
	// that one and every older one are spent. It is kept here, written
	// before the machine reboots, so no Reboot is used twice.
	Spent   uint64 `json:"spent,omitempty"`
	Boot    string `json:"boot,omitempty"`     // the boot id when the reboot began
	NewBoot string `json:"new_boot,omitempty"` // the boot id it came up on: another during the window fails it
	Same    bool   `json:"same,omitempty"`     // a reboot into a kernel that ran here: plain, or back
	For     string `json:"for,omitempty"`      // why that one: the system asked, a canary's boot, back
	// Held is the kernel that last held here: the running one before the
	// first reboot, then each that settled. Every reboot pins it as GRUB's
	// default, never a kernel in Failed (round 14, new major 3).
	Held string `json:"held,omitempty"`
	// The health window, judged as a boot's (bootgroup.go): the checks
	// armed (passed since the boot, or out of their grace), each one's
	// failures in a row, and when every check was armed (round 14, new major
	// 2).
	Armed    map[string]bool `json:"armed,omitempty"`
	Streak   map[string]int  `json:"streak,omitempty"`
	ArmedAll time.Time       `json:"armed_all,omitzero"`
	// Canary are the later guards this reboot is a canary's boot for;
	// CanaryBoots those it has booted with once, listed when the boot is
	// seen (round 14, minor 2).
	Canary      []string `json:"canary,omitempty"`
	CanaryBoots []string `json:"canary_boots,omitempty"`
}

// rebootGap is how long a window tier waits after a reboot began before it
// begins another: a window that wraps midnight holds one reboot, not two.
var rebootGap = 20 * time.Hour

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

// fail ends the reboot into st.Kernel: it didn't boot, didn't hold, or the
// machine didn't go down. A new kernel is marked failed, so only the owner's
// Reboot tries it again; a reboot the system asked for marks nothing.
func (st *rebootState) fail(now time.Time, why string) {
	st.Phase, st.Since, st.Why = BootFail, now, why
	if !st.Same && !st.failed(st.Kernel) {
		st.Failed = append(st.Failed, st.Kernel)
		if n := len(st.Failed); n > maxFailed {
			st.Failed = st.Failed[n-maxFailed:]
		}
	}
}

// order finds the owner's Reboot that lets this machine reboot into target
// now, if one does. It drops the spent ones and those a day past their
// deadline; notes says why the others wait.
func (st *rebootState) order(f *Fleet, now time.Time, target string) (use *RebootOrder, notes []string) {
	var keep []RebootOrder
	for _, o := range f.Reboots {
		switch {
		case o.Seq <= st.Spent || now.After(o.NotAfter.Add(24*time.Hour)):
			continue
		case now.After(o.NotAfter):
			notes = append(notes, fmt.Sprintf("your Reboot #%d into %s passed its deadline unused", o.Seq, o.Kernel))
		case o.Kernel != target:
			notes = append(notes, fmt.Sprintf("your Reboot #%d names %s, not %s, the kernel a reboot now would boot", o.Seq, o.Kernel, target))
		default:
			o := o
			use = &o // the newest one, as the list is oldest first
		}
		keep = append(keep, o)
	}
	f.Reboots = keep
	return use, notes
}

// judge reads one tick's sample into a reboot's health window, as a boot's
// window is read (bootgroup.go): a check arms once it passes since the boot
// or its grace runs out, and failRun failures in a row of an armed check, at
// any tick, fail the reboot. A check failing before the reboot isn't its
// fault. It says the checks that failed.
func (st *rebootState) judge(checks []policy.Health, sample map[string]string, now time.Time) []string {
	if st.Armed == nil {
		st.Armed = map[string]bool{}
	}
	if st.Streak == nil {
		st.Streak = map[string]int{}
	}
	all := true
	var bad []string
	for _, h := range checks {
		k := checkKey(h)
		if contains(st.Failing, k) {
			continue
		}
		why, failing := sample[k]
		if !st.Armed[k] {
			if failing && now.Sub(st.Since) < time.Duration(h.Grace())*time.Second {
				all = false
				continue
			}
			st.Armed[k] = true
		}
		if !failing {
			delete(st.Streak, k)
			continue
		}
		if st.Streak[k]++; st.Streak[k] >= failRun {
			bad = append(bad, k+": "+why)
		}
	}
	if all && st.ArmedAll.IsZero() {
		st.ArmedAll = now
	}
	return bad
}

// running is the release of the running kernel (uname -r).
func (a *Agent) running() string {
	b, _ := a.Sys.ReadFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(b))
}

// bootID is the running boot's id, new at every boot.
func (a *Agent) bootID() string {
	b, _ := a.Sys.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}

// rebootAsked says why the system asks for a reboot, as " (pkg, pkg)", or
// "" if it doesn't: packages leave /run/reboot-required, and their names in
// /run/reboot-required.pkgs.
func (a *Agent) rebootAsked() string {
	if _, err := a.Sys.ReadFile("/run/reboot-required"); err != nil {
		return ""
	}
	b, _ := a.Sys.ReadFile("/run/reboot-required.pkgs")
	seen := map[string]bool{}
	var pkgs []string
	for _, p := range strings.Fields(string(b)) {
		if !seen[p] && len(pkgs) < 8 {
			seen[p] = true
			pkgs = append(pkgs, p)
		}
	}
	if len(pkgs) == 0 {
		return " (no package named)"
	}
	return " (" + strings.Join(pkgs, ", ") + ")"
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
// a panic, or nil: the default must be the saved entry and GRUB mustn't
// save each boot's entry as the default (GRUB_SAVEDEFAULT), or a trial
// kernel would become the default as it boots; GRUB must be able to clear
// the one-shot entry as it boots it, so its environment file must be on a
// plain ext2/3/4 or FAT filesystem, where GRUB writes it in place (it can't
// on btrfs, ZFS, LVM or RAID, and a one-shot entry it can't clear boots a
// panicking kernel again and again; other filesystems aren't trusted); and
// the kernel command line must reboot on a panic.
func (a *Agent) grubReady(ctx context.Context) error {
	def, savedef := "", ""
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
			if v, ok := strings.CutPrefix(line, "GRUB_SAVEDEFAULT="); ok {
				savedef = strings.Trim(v, `"'`)
			}
		}
	}
	if def != "saved" {
		return fmt.Errorf("GRUB_DEFAULT is %q, not saved: a one-shot boot needs it", def)
	}
	if savedef == "true" {
		return errors.New("GRUB_SAVEDEFAULT is true: GRUB would make the new kernel the default as it boots, before its health held")
	}
	out, err := a.Sys.Run(ctx, nil, "findmnt", "-n", "-o", "FSTYPE,SOURCE", "--target", "/boot/grub")
	f := strings.Fields(string(out))
	if err != nil || len(f) < 2 {
		return fmt.Errorf("can't tell which filesystem holds /boot/grub: %v", err)
	}
	switch fs, src := f[0], f[1]; {
	case fs != "ext2" && fs != "ext3" && fs != "ext4" && fs != "vfat":
		return fmt.Errorf("/boot/grub is on %s, not ext2/3/4 or FAT: GRUB may not clear a one-shot boot there, and a kernel that panics would boot again and again", fs)
	case strings.HasPrefix(src, "/dev/mapper/") || strings.HasPrefix(src, "/dev/md") || strings.HasPrefix(src, "/dev/dm-"):
		return fmt.Errorf("/boot/grub is on %s (LVM or RAID), where GRUB can't clear a one-shot boot: a kernel that panics would boot again and again", src)
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
// The entry's id is 10_linux's "gnulinux-<rel>-advanced-<root>", matched
// from its start, so 6.8.0-147-generic never matches 6.8.0-147-generic-64k;
// more than one match refuses (round 14, minor 6).
func grubEntry(cfg []byte, rel string) (string, error) {
	var found []string
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
			if m := menuID.FindStringSubmatch(line); m != nil && strings.HasPrefix(m[1], "gnulinux-"+rel+"-advanced-") {
				found = append(found, strings.Join(append(append([]string{}, submenus...), m[1]), ">"))
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
	switch len(found) {
	case 0:
		return "", fmt.Errorf("no menu entry for %s in grub.cfg", rel)
	case 1:
		return found[0], nil
	}
	return "", fmt.Errorf("%d menu entries for %s in grub.cfg: which one boots is unclear", len(found), rel)
}

// rebootStep moves a reboot a step, after the guards' step: it follows a
// reboot in flight, or readies one when one is owed and the owner's Reboot
// or the tier allows it now. It says what it did, or why it waits, and
// whether to reboot: Tick runs rebootNow once its report is written.
func (a *Agent) rebootStep(ctx context.Context, f *Fleet, p *policy.Policy, sample map[string]string) (string, bool, error) {
	st, err := a.loadReboot()
	if err != nil {
		return "", false, err
	}
	now := a.now().UTC()
	running := a.running()
	what := func() string { // the reboot in flight, in words
		if st.Same {
			return "(" + st.For + ")"
		}
		return "into " + st.Kernel
	}
	switch st.Phase {
	case Rebooting:
		// Up on a new boot: on the kernel it rebooted into, or back on
		// another one because that kernel didn't boot. A record from before
		// boot ids goes by the kernel alone.
		booted := a.bootID() != st.Boot || (st.Boot == "" && running == st.Kernel)
		switch {
		case booted && running == st.Kernel:
			// GRUB clears the one-shot entry as it boots it; if it didn't,
			// clear it now, so a panic from here on comes back to the pinned
			// kernel. A canary's boot counts once the boot is seen.
			st.Phase, st.Since, st.NewBoot = Booted, now, a.bootID()
			st.Armed, st.Streak, st.ArmedAll = nil, nil, time.Time{}
			st.judge(checksFor(p, f.Host), sample, now) // the window's first sample: it arms what passes
			st.CanaryBoots = lastN(append(st.CanaryBoots, st.Canary...), 32)
			st.Canary = nil
			msg := "booted into " + running + "; its health window runs"
			if st.Same {
				msg = "rebooted " + what() + "; its health window runs"
			}
			return msg, false, errors.Join(a.oneShotGone(ctx), a.saveReboot(st))
		case booted:
			st.fail(now, st.Kernel+" didn't boot: back on "+running)
			return st.Why, false, errors.Join(a.oneShotGone(ctx), a.saveReboot(st))
		case now.Sub(st.Since) < RebootDeadline:
			return "rebooting " + what(), false, nil
		}
		// Still the same boot by the deadline: the machine never went down.
		// The one-shot boot is taken back, so a later reboot doesn't try the
		// kernel unasked, and the reboot waits for the owner.
		st.fail(now, "the machine didn't go down to reboot "+what())
		return st.Why, false, errors.Join(a.oneShotGone(ctx), a.saveReboot(st))
	case Booted:
		switch {
		case running != st.Kernel:
			st.fail(now, "back on "+running+" before "+st.Kernel+" settled")
			return st.Why, false, a.saveReboot(st)
		case st.NewBoot != "" && a.bootID() != st.NewBoot:
			st.fail(now, st.Kernel+" restarted during its health window")
			return st.Why, false, a.saveReboot(st)
		}
		if bad := st.judge(checksFor(p, f.Host), sample, now); len(bad) > 0 {
			why := "health failed on " + running + ": " + strings.Join(bad, "; ") + "; a reboot back to " + st.Held + " is owed"
			if st.Same {
				why = "health failed after the reboot " + what() + ": " + strings.Join(bad, "; ")
			}
			st.fail(now, why)
			return st.Why, false, a.saveReboot(st)
		}
		if st.ArmedAll.IsZero() || now.Sub(st.ArmedAll) < TrialWindow {
			msg := "booted into " + running + "; its health window runs"
			if st.Same {
				msg = "rebooted " + what() + "; its health window runs"
			}
			return msg, false, a.saveReboot(st) // the window's streaks, each tick
		}
		if !st.Same {
			if _, err := a.Sys.Run(ctx, nil, "grub-set-default", st.Entry); err != nil {
				return "", false, fmt.Errorf("making %s the default: %w", st.Kernel, err)
			}
		}
		st.Held = st.Kernel
		st.Phase, st.Since, st.Why, st.Armed, st.Streak = Settled, now, "", nil, nil
		if st.Same {
			return "rebooted " + what() + "; health held", false, a.saveReboot(st)
		}
		return "rebooted into " + running + "; it is the default now", false, a.saveReboot(st)
	}

	newest, err := a.newestKernel(ctx)
	if err != nil || newest == "" {
		return "", false, nil
	}
	held := st.Held
	if held == "" {
		held = running // before the first reboot, the running kernel is the one that holds
	}
	// What is owed, in order: back to the kernel that last held, from one
	// that failed its trial; a reboot into the newest kernel; or, with none
	// newer, a plain reboot the system asks for, a canary's boot for its
	// later guards, or the owner's Reboot of the running kernel.
	var target, owed string
	var why, whys []string // a reboot into a kernel that ran here: its reasons, for the record and in words
	var entries []*Entry
	var later, laterNames []string // later guards this canary must boot with
	same, back := false, false
	switch {
	case st.failed(running) && held != running:
		target, same, back = held, true, true
		why = []string{"back to " + held}
		owed = "a reboot back to " + held + " is owed: " + running + " failed its trial"
	case newest != running:
		target = newest
		owed = "a reboot into " + newest + " is owed"
	default:
		target, same = running, true
		if asked := a.rebootAsked(); asked != "" {
			why, whys = append(why, "the system asked"), append(whys, "the system asks for one"+asked)
		}
		if tier, ok := p.TierOf(f.Host); ok && contains(tier.Canaries, f.Host) {
			if entries, _, err = a.Status(ctx); err != nil {
				return "", false, err
			}
			for _, e := range entries {
				if e.Later && !e.Booted && e.By != "" && e.Status == Confirmed && !contains(st.CanaryBoots, e.Hash) {
					later, laterNames = append(later, e.Hash), append(laterNames, e.Guard.Name())
				}
			}
		}
		if len(later) > 0 {
			why = append(why, "a canary's boot for "+strings.Join(laterNames, ", "))
			whys = append(whys, "this canary boots with "+strings.Join(laterNames, ", ")+" before the rest of its tier takes it")
		}
	}
	use, notes := st.order(f, now, target)
	say := func(s string) string {
		if s == "" {
			return strings.Join(notes, "; ")
		}
		return strings.Join(append([]string{s}, notes...), "; ")
	}
	if same && !back {
		if len(why) == 0 {
			if use == nil {
				return say(""), false, nil // nothing owed
			}
			why, whys = []string{fmt.Sprintf("your Reboot #%d", use.Seq)}, []string{fmt.Sprintf("your Reboot #%d names the running kernel", use.Seq)}
		}
		owed = "a reboot is owed: " + strings.Join(whys, ", and ")
	}
	if use != nil {
		owed += fmt.Sprintf("; your Reboot #%d allows it", use.Seq)
	} else {
		if !same && st.failed(target) {
			why := ""
			if st.Kernel == target && st.Why != "" {
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
			// Once in 20 hours, so a window across midnight holds one reboot;
			// going back from a kernel that failed its trial doesn't wait.
			if !back && !st.Began.IsZero() && now.Sub(st.Began) < rebootGap {
				return say(owed + "; this machine rebooted less than 20 hours ago"), false, nil
			}
		}
		if tier.RebootAfter != "" {
			return say(owed + "; ordered reboots (after " + tier.RebootAfter + ") wait for your signed Reboot"), false, nil
		}
	}
	if entries == nil {
		if entries, _, err = a.Status(ctx); err != nil {
			return "", false, err
		}
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
	// Every reboot, a plain one too, pins the kernel that last held as
	// GRUB's default, so GRUB boots exactly it, or the new kernel once
	// (round 14, new major 1).
	if err := a.grubReady(ctx); err != nil {
		return say(owed + "; " + err.Error()), false, nil
	}
	cfg, err := a.Sys.ReadFile("/boot/grub/grub.cfg")
	if err != nil {
		return say(owed + "; can't read grub.cfg: " + err.Error()), false, nil
	}
	pinEntry, err := grubEntry(cfg, held)
	if err != nil {
		return say(owed + "; the kernel that last held, " + held + ", has no GRUB entry to fall back on: " + err.Error()), false, nil
	}
	for _, fl := range []string{"/boot/vmlinuz-" + held, "/boot/initrd.img-" + held} {
		if fi, err := a.Sys.Stat(fl); err != nil || fi.Size() == 0 {
			return say(owed + "; the kernel that last held, " + held + ", is gone (" + fl + "): there is nothing to fall back on"), false, nil
		}
	}
	var newEntry string
	if !same {
		if newEntry, err = grubEntry(cfg, target); err != nil {
			return say(owed + "; " + err.Error()), false, nil
		}
	}
	spent := st.Spent
	if use != nil {
		spent = max(spent, use.Seq) // order drops it from the fleet file at the next tick
	}
	*st = rebootState{Kernel: target, Entry: newEntry, Phase: Rebooting, Since: now, Began: now,
		Failing: sortedKeys(sample), Failed: st.Failed, Spent: spent, Boot: a.bootID(), Same: same,
		For: strings.Join(why, "; "), Held: held, Canary: later, CanaryBoots: st.CanaryBoots}
	if err := a.saveReboot(st); err != nil {
		return "", false, err
	}
	// The kernel that last held is the default, so a boot that panics comes
	// back to it; a new kernel boots once.
	cmds := [][]string{{"grub-set-default", pinEntry}}
	if !same {
		cmds = append(cmds, []string{"grub-reboot", newEntry})
	}
	for _, c := range cmds {
		if _, err := a.Sys.Run(ctx, nil, c[0], c[1:]...); err != nil {
			st.fail(now, c[0]+": "+err.Error())
			return "", false, errors.Join(fmt.Errorf("rebooting %s: %s: %w", what(), c[0], err), a.saveReboot(st))
		}
	}
	return "rebooting " + what(), true, nil
}

// lastN keeps the last n of xs.
func lastN(xs []string, n int) []string {
	if len(xs) > n {
		return xs[len(xs)-n:]
	}
	return xs
}

// oneShotGone clears GRUB's one-shot entry, if one is set.
func (a *Agent) oneShotGone(ctx context.Context) error {
	_, err := a.Sys.Run(ctx, nil, "grub-editenv", "-", "unset", "next_entry")
	return err
}

// rebootNow reboots the machine into the kernel rebootStep readied. If the
// reboot can't be asked for, the one-shot boot is taken back and the reboot
// marked failed.
func (a *Agent) rebootNow(ctx context.Context) error {
	if _, err := a.Sys.Run(ctx, nil, "systemctl", "reboot"); err != nil {
		uerr := a.oneShotGone(ctx)
		st, lerr := a.loadReboot()
		if lerr != nil {
			return errors.Join(err, uerr, lerr)
		}
		st.fail(a.now().UTC(), "systemctl reboot: "+err.Error())
		return errors.Join(fmt.Errorf("rebooting %s: %w", map[bool]string{true: "(" + st.For + ")", false: "into " + st.Kernel}[st.Same], err), uerr, a.saveReboot(st))
	}
	return nil
}
