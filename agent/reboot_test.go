package agent

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
)

// A grub.cfg as Ubuntu writes it: the top entry, then a submenu holding
// each kernel and its recovery entry.
const grubCfg = `### BEGIN /etc/grub.d/10_linux ###
function gfxmode {
	set gfxpayload="${1}"
}
menuentry 'Ubuntu' --class ubuntu $menuentry_id_option 'gnulinux-simple-0d5a' {
	linux	/boot/vmlinuz-6.8.0-149-generic root=UUID=0d5a ro panic=10
}
submenu 'Advanced options for Ubuntu' $menuentry_id_option 'gnulinux-advanced-0d5a' {
	menuentry 'Ubuntu, with Linux 6.8.0-149-generic' --class ubuntu $menuentry_id_option 'gnulinux-6.8.0-149-generic-advanced-0d5a' {
		linux	/boot/vmlinuz-6.8.0-149-generic root=UUID=0d5a ro panic=10
	}
	menuentry 'Ubuntu, with Linux 6.8.0-149-generic (recovery mode)' --class ubuntu $menuentry_id_option 'gnulinux-6.8.0-149-generic-recovery-0d5a' {
		linux	/boot/vmlinuz-6.8.0-149-generic root=UUID=0d5a ro single
	}
	menuentry 'Ubuntu, with Linux 6.8.0-142-generic' --class ubuntu $menuentry_id_option 'gnulinux-6.8.0-142-generic-advanced-0d5a' {
		linux	/boot/vmlinuz-6.8.0-142-generic root=UUID=0d5a ro panic=10
	}
}
### END /etc/grub.d/10_linux ###
`

const (
	oldRel   = "6.8.0-142-generic"
	newRel   = "6.8.0-149-generic"
	oldEntry = "gnulinux-advanced-0d5a>gnulinux-6.8.0-142-generic-advanced-0d5a"
	newEntry = "gnulinux-advanced-0d5a>gnulinux-6.8.0-149-generic-advanced-0d5a"
)

// rebootAgent is a machine running 6.8.0-142 with 6.8.0-149 installed and
// ready to boot, GRUB set for one-shot boots, in a tier whose reboot
// settings the test gives; the clock starts at 03:10 UTC.
func rebootAgent(t *testing.T, tier string) (*Agent, *fakeSys, *Fleet, *policy.Policy, func(time.Duration)) {
	t.Helper()
	a, sys, _ := newAgent(t)
	clock := time.Date(2026, 11, 5, 3, 10, 0, 0, time.UTC)
	a.Now = func() time.Time { return clock }
	sys.files["/proc/sys/kernel/osrelease"] = oldRel + "\n"
	sys.files["/proc/sys/kernel/random/boot_id"] = "boot-1\n"
	sys.files["/etc/default/grub"] = "# comment\nGRUB_DEFAULT=saved\nGRUB_TIMEOUT=0\n"
	sys.files["/proc/cmdline"] = "BOOT_IMAGE=/boot/vmlinuz-" + oldRel + " root=UUID=0d5a ro panic=10\n"
	sys.files["/boot/grub/grub.cfg"] = grubCfg
	for _, rel := range []string{oldRel, newRel} {
		sys.files["/boot/vmlinuz-"+rel] = "kernel"
		sys.files["/boot/initrd.img-"+rel] = "initrd"
	}
	sys.units["ssh.socket"] = &fakeUnit{enabled: "enabled"}
	sys.runOut = map[string]string{
		dpkgQuery:                "linux-image-" + oldRel + " 6.8.0-142.142 ii \nlinux-image-" + newRel + " 6.8.0-149.149 ii \n",
		"dkms status":            "",
		"ls /etc/default/grub.d": "",
		"findmnt -n -o FSTYPE,SOURCE --target /boot/grub": "ext4   /dev/vda1\n",
	}
	p, err := policy.Decode([]byte(`{"fleet":"test","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"}},
		"tiers":[{"name":"A","hosts":["web"],"admit":["me"]` + tier + `},{"name":"B","hosts":["sentry"],"admit":["me"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return a, sys, &Fleet{Host: "web"}, p, func(d time.Duration) { clock = clock.Add(d) }
}

// dpkgQuery is the call that lists the installed kernels.
const dpkgQuery = "dpkg-query -W -f ${Package} ${Version} ${db:Status-Abbrev}\n linux-image-[0-9]*"

// bootInto is the machine coming up again, on kernel rel: a new boot id.
func bootInto(sys *fakeSys, rel string) {
	sys.files["/proc/sys/kernel/osrelease"] = rel + "\n"
	sys.files["/proc/sys/kernel/random/boot_id"] = "boot-after-" + strings.TrimSpace(sys.files["/proc/sys/kernel/random/boot_id"]) + "\n"
}

// rstep runs the reboot step and then, as Tick does, the reboot it asks for.
func rstep(t *testing.T, a *Agent, f *Fleet, p *policy.Policy, sample map[string]string) string {
	t.Helper()
	msg, reboot, err := a.rebootStep(context.Background(), f, p, sample)
	if err != nil {
		t.Fatal(err)
	}
	if reboot {
		if err := a.rebootNow(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	return msg
}

// ran says the commands the agent ran, in order, among those named.
func ran(sys *fakeSys, prefixes ...string) []string {
	var out []string
	for _, l := range sys.log {
		for _, p := range prefixes {
			if strings.HasPrefix(l, p) {
				out = append(out, l)
			}
		}
	}
	return out
}

// A window tier reboots once inside its window: the running kernel pinned
// as GRUB's default, the new one booted once, then a reboot; booted into
// the new kernel, it waits out the trial window, and with health held makes
// the new kernel the default.
func TestRebootInTheWindow(t *testing.T) {
	a, sys, f, p, after := rebootAgent(t, `,"reboot":"window","reboot_window":"03:00-04:00"`)
	if m := rstep(t, a, f, p, nil); m != "rebooting into "+newRel {
		t.Fatalf("in the window: %q", m)
	}
	want := []string{"grub-set-default " + oldEntry, "grub-reboot " + newEntry, "systemctl reboot"}
	if got := ran(sys, "grub-", "systemctl reboot"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("ran %q, want %q", got, want)
	}
	after(time.Minute) // the machine hasn't gone down yet
	if m := rstep(t, a, f, p, nil); m != "rebooting into "+newRel || len(ran(sys, "grub-", "systemctl reboot")) != 3 {
		t.Fatalf("before it goes down: %q", m)
	}
	after(2 * time.Minute)
	bootInto(sys, newRel)
	if m := rstep(t, a, f, p, nil); !strings.HasPrefix(m, "booted into "+newRel) {
		t.Fatalf("after the boot: %q", m)
	}
	if got := ran(sys, "grub-editenv"); len(got) != 1 { // a one-shot entry GRUB left is cleared
		t.Fatalf("the one-shot entry wasn't cleared on the new kernel: %q", got)
	}
	after(TrialWindow - time.Minute)
	if m := rstep(t, a, f, p, nil); !strings.HasPrefix(m, "booted into ") || len(ran(sys, "grub-set-default "+newEntry)) != 0 {
		t.Fatalf("inside the health window: %q", m)
	}
	after(time.Minute)
	if m := rstep(t, a, f, p, nil); m != "rebooted into "+newRel+"; it is the default now" || len(ran(sys, "grub-set-default "+newEntry)) != 1 {
		t.Fatalf("health held: %q (%v)", m, sys.log)
	}
	if m := rstep(t, a, f, p, nil); m != "" {
		t.Fatalf("nothing owed now: %q", m)
	}
}

// A new kernel that doesn't boot: the machine comes back on the pinned
// default. The first tick on the new boot marks the kernel failed and takes
// the one-shot entry back, and the agent never tries the kernel again by
// itself, not even in the next day's window.
func TestRebootThatDidntBoot(t *testing.T) {
	a, sys, f, p, after := rebootAgent(t, `,"reboot":"window","reboot_window":"03:00-04:00"`)
	rstep(t, a, f, p, nil)
	after(time.Minute)
	if m := rstep(t, a, f, p, nil); m != "rebooting into "+newRel {
		t.Fatalf("before it goes down: %q", m)
	}
	after(2 * time.Minute)
	bootInto(sys, oldRel)
	if m := rstep(t, a, f, p, nil); m != newRel+" didn't boot: back on "+oldRel {
		t.Fatalf("back on the old kernel: %q", m)
	}
	if got := ran(sys, "grub-editenv"); len(got) != 1 || got[0] != "grub-editenv - unset next_entry" {
		t.Fatalf("the one-shot boot wasn't taken back: %q", got)
	}
	after(24 * time.Hour)
	if m := rstep(t, a, f, p, nil); !strings.Contains(m, "it failed before ("+newRel+" didn't boot: back on "+oldRel+"), so it waits for your signed Reboot") || len(ran(sys, "grub-reboot")) != 1 {
		t.Fatalf("the next day's window: %q", m)
	}
}

// A machine that never goes down (the same boot past the deadline): the
// reboot is marked failed, waiting for the owner, and its one-shot entry is
// taken back so a later reboot doesn't try the kernel unasked.
func TestRebootNeverWentDown(t *testing.T) {
	a, sys, f, p, after := rebootAgent(t, `,"reboot":"window","reboot_window":"03:00-04:00"`)
	rstep(t, a, f, p, nil)
	after(RebootDeadline - time.Minute)
	if m := rstep(t, a, f, p, nil); m != "rebooting into "+newRel {
		t.Fatalf("before the deadline: %q", m)
	}
	after(2 * time.Minute)
	if m := rstep(t, a, f, p, nil); m != "the machine didn't go down to reboot into "+newRel {
		t.Fatalf("past the deadline: %q", m)
	}
	if got := ran(sys, "grub-editenv"); len(got) != 1 {
		t.Fatalf("the one-shot boot wasn't taken back: %q", got)
	}
}

// With no newer kernel, a reboot the system asks for (/run/reboot-required)
// follows the same rules: the tier's word, then the gates, then a plain
// reboot with no GRUB change; on the new boot the health window, then done.
// A health failure after it is reported and marks no kernel failed.
func TestRebootTheSystemAsks(t *testing.T) {
	a, sys, f, p, after := rebootAgent(t, `,"reboot":"window","reboot_window":"03:00-04:00"`)
	sys.runOut[dpkgQuery] = "linux-image-" + oldRel + " 6.8.0-142.142 ii \n"
	if m := rstep(t, a, f, p, nil); m != "" {
		t.Fatalf("nothing asked: %q", m)
	}
	sys.files["/run/reboot-required"] = "*** System restart required ***\n"
	sys.files["/run/reboot-required.pkgs"] = "libc6\nsystemd\nlibc6\n"
	if m := rstep(t, a, f, p, nil); m != "rebooting (the system asked)" {
		t.Fatalf("asked: %q", m)
	}
	if got := ran(sys, "grub-", "systemctl reboot"); strings.Join(got, "|") != "systemctl reboot" {
		t.Fatalf("ran %q: a plain reboot changes nothing in GRUB", got)
	}
	after(time.Minute)
	if m := rstep(t, a, f, p, nil); m != "rebooting (the system asked)" {
		t.Fatalf("before it goes down: %q", m)
	}
	bootInto(sys, oldRel)
	delete(sys.files, "/run/reboot-required") // /run is new at every boot
	delete(sys.files, "/run/reboot-required.pkgs")
	if m := rstep(t, a, f, p, nil); m != "rebooted (the system asked); its health window runs" {
		t.Fatalf("after the boot: %q", m)
	}
	after(TrialWindow)
	if m := rstep(t, a, f, p, map[string]string{"site": "http 502"}); m != "health failed after the reboot: site: http 502" {
		t.Fatalf("health failed: %q", m)
	}
	if st, _ := a.loadReboot(); len(st.Failed) != 0 {
		t.Fatalf("a kernel marked failed: %v", st.Failed)
	}
	if m := rstep(t, a, f, p, nil); m != "" {
		t.Fatalf("nothing owed after: %q", m)
	}
	// A tier that waits for the owner says what the system asked for.
	b, bsys, bf, bp, _ := rebootAgent(t, ``)
	bsys.runOut[dpkgQuery] = "linux-image-" + oldRel + " 6.8.0-142.142 ii \n"
	bsys.files["/run/reboot-required"] = "*** System restart required ***\n"
	bsys.files["/run/reboot-required.pkgs"] = "libc6\nsystemd\n"
	if m := rstep(t, b, bf, bp, nil); m != "a reboot is owed: the system asks for one (libc6, systemd); this tier waits for your signed Reboot" {
		t.Fatalf("a yes tier: %q", m)
	}
}

// A check failing at the end of the health window that held before the
// reboot fails the new kernel: it isn't made the default, so the next
// reboot goes back. A check that was already failing doesn't count.
func TestRebootHealthFails(t *testing.T) {
	a, sys, f, p, after := rebootAgent(t, `,"reboot":"window","reboot_window":"03:00-04:00"`)
	rstep(t, a, f, p, map[string]string{"backup": "was down already"})
	bootInto(sys, newRel)
	after(time.Minute)
	rstep(t, a, f, p, nil)
	after(TrialWindow)
	m := rstep(t, a, f, p, map[string]string{"backup": "was down already", "site": "http 502"})
	if !strings.Contains(m, "health failed on "+newRel+": site: http 502") || strings.Contains(m, "backup") || len(ran(sys, "grub-set-default "+newEntry)) != 0 {
		t.Fatalf("health failed: %q", m)
	}
}

// What holds a reboot, each with its reason: the tier's mode, the window,
// a reboot already today, an ordered tier, GRUB not set for one-shot boots
// or panics, and the gates. None of them runs grub-reboot.
func TestRebootHeld(t *testing.T) {
	cases := []struct {
		name, tier, want string
		set              func(*fakeSys)
	}{
		{"never", `,"reboot":"never"`, "this tier never reboots by itself", nil},
		{"yes", ``, "this tier waits for your signed Reboot", nil},
		{"outside the window", `,"reboot":"window","reboot_window":"04:00-05:00"`, "it waits for the window 04:00-05:00 UTC", nil},
		{"ordered", `,"reboot":"window","reboot_window":"03:00-04:00","reboot_after":"sentry"`, "ordered reboots (after sentry) wait for your signed Reboot", nil},
		{"GRUB's default", `,"reboot":"window","reboot_window":"03:00-04:00"`, `GRUB_DEFAULT is "0", not saved`, func(s *fakeSys) {
			s.files["/etc/default/grub"] = "GRUB_DEFAULT=saved\n"
			s.files["/etc/default/grub.d/50-cloudimg-settings.cfg"] = "GRUB_DEFAULT=0\n"
			s.runOut["ls /etc/default/grub.d"] = "50-cloudimg-settings.cfg\n"
		}},
		{"no panic=", `,"reboot":"window","reboot_window":"03:00-04:00"`, "no panic=N", func(s *fakeSys) {
			s.files["/proc/cmdline"] = "BOOT_IMAGE=/boot/vmlinuz root=UUID=0d5a ro\n"
		}},
		{"GRUB saves each boot's entry", `,"reboot":"window","reboot_window":"03:00-04:00"`, "GRUB_SAVEDEFAULT is true", func(s *fakeSys) {
			s.files["/etc/default/grub"] = "GRUB_DEFAULT=saved\nGRUB_SAVEDEFAULT=true\n"
		}},
		{"grubenv on btrfs", `,"reboot":"window","reboot_window":"03:00-04:00"`, "/boot/grub is on btrfs, not ext2/3/4 or FAT", func(s *fakeSys) {
			s.runOut["findmnt -n -o FSTYPE,SOURCE --target /boot/grub"] = "btrfs  /dev/vda2\n"
		}},
		{"grubenv on LVM", `,"reboot":"window","reboot_window":"03:00-04:00"`, "/dev/mapper/vg0-root (LVM or RAID)", func(s *fakeSys) {
			s.runOut["findmnt -n -o FSTYPE,SOURCE --target /boot/grub"] = "ext4   /dev/mapper/vg0-root\n"
		}},
		{"no initrd", `,"reboot":"window","reboot_window":"03:00-04:00"`, "the gates hold it: newest kernel can boot", func(s *fakeSys) {
			delete(s.files, "/boot/initrd.img-"+newRel)
		}},
		{"no menu entry", `,"reboot":"window","reboot_window":"03:00-04:00"`, "no menu entry for " + newRel, func(s *fakeSys) {
			s.files["/boot/grub/grub.cfg"] = strings.ReplaceAll(grubCfg, "6.8.0-149", "6.8.0-150")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, sys, f, p, _ := rebootAgent(t, c.tier)
			if c.set != nil {
				c.set(sys)
			}
			m := rstep(t, a, f, p, nil)
			if !strings.Contains(m, c.want) || !strings.HasPrefix(m, "a reboot into "+newRel+" is owed") {
				t.Errorf("%q, want %q", m, c.want)
			}
			if got := ran(sys, "grub-reboot", "systemctl reboot"); len(got) != 0 {
				t.Errorf("rebooted: %v", got)
			}
		})
	}
	// Rebooted once today already: not again, though another kernel came.
	a, sys, f, p, after := rebootAgent(t, `,"reboot":"window","reboot_window":"03:00-04:00"`)
	rstep(t, a, f, p, nil)
	bootInto(sys, newRel)
	after(time.Minute)
	rstep(t, a, f, p, nil)
	after(TrialWindow)
	rstep(t, a, f, p, nil)
	sys.runOut[dpkgQuery] += "linux-image-6.8.0-150-generic 6.8.0-150.150 ii \n"
	if m := rstep(t, a, f, p, nil); !strings.Contains(m, "this machine rebooted today") {
		t.Errorf("a second reboot the same day: %q", m)
	}
}

// grub.cfg's entries are found by release, inside their submenu, never the
// recovery entry; a top-level entry has no submenu in its path.
func TestGrubEntry(t *testing.T) {
	for rel, want := range map[string]string{newRel: newEntry, oldRel: oldEntry} {
		if got, err := grubEntry([]byte(grubCfg), rel); err != nil || got != want {
			t.Errorf("%s: %q %v", rel, got, err)
		}
	}
	flat := "menuentry 'Debian GNU/Linux, with Linux 6.1.0-28-amd64' --class debian $menuentry_id_option 'gnulinux-6.1.0-28-amd64-advanced-77aa' {\n}\n"
	if got, err := grubEntry([]byte(flat), "6.1.0-28-amd64"); err != nil || got != "gnulinux-6.1.0-28-amd64-advanced-77aa" {
		t.Errorf("a top-level entry: %q %v", got, err)
	}
	if _, err := grubEntry([]byte(grubCfg), "6.8.0-14-generic"); err == nil {
		t.Error("6.8.0-14 matched an entry of 6.8.0-142 or -149")
	}
	// A recovery entry listed first is passed over.
	recFirst := strings.Replace(grubCfg, "\tmenuentry 'Ubuntu, with Linux 6.8.0-149-generic' --class ubuntu $menuentry_id_option 'gnulinux-6.8.0-149-generic-advanced-0d5a' {\n\t\tlinux\t/boot/vmlinuz-6.8.0-149-generic root=UUID=0d5a ro panic=10\n\t}\n", "", 1)
	recFirst = strings.Replace(recFirst, "\t}\n\tmenuentry 'Ubuntu, with Linux 6.8.0-142-generic'", "\t}\n\tmenuentry 'Ubuntu, with Linux 6.8.0-149-generic' --class ubuntu $menuentry_id_option 'gnulinux-6.8.0-149-generic-advanced-0d5a' {\n\t}\n\tmenuentry 'Ubuntu, with Linux 6.8.0-142-generic'", 1)
	if !strings.Contains(recFirst, "recovery-0d5a' {\n\t\tlinux\t/boot/vmlinuz-6.8.0-149-generic root=UUID=0d5a ro single\n\t}\n\tmenuentry 'Ubuntu, with Linux 6.8.0-149-generic'") {
		t.Fatalf("the fixture didn't move the recovery entry first:\n%s", recFirst)
	}
	if got, err := grubEntry([]byte(recFirst), newRel); err != nil || got != newEntry {
		t.Errorf("recovery first: %q %v", got, err)
	}
}

// A canary holding an admitted guard that takes effect only after a boot
// reboots once for it in its window, a plain reboot, so the rest of its tier
// can take the guard (rule 4); once for each such guard. A machine that
// isn't a canary doesn't.
func TestRebootTheCanaryBoots(t *testing.T) {
	gb, err := os.ReadFile("../guard/testdata/cve-2026-98432-mptcp.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := guard.Parse(gb)
	if err != nil {
		t.Fatal(err)
	}
	holdLater := func(a *Agent) {
		s, st, err := a.open()
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		st.Guards = append(st.Guards, &Entry{Hash: g.Hash(), Guard: g, Status: Confirmed, Later: true, By: "rig"})
		if err := s.save(st); err != nil {
			t.Fatal(err)
		}
	}
	for _, canary := range []bool{true, false} {
		tier := `,"reboot":"window","reboot_window":"03:00-04:00"`
		if canary {
			tier += `,"canaries":["web"]`
		}
		a, sys, f, p, after := rebootAgent(t, tier)
		sys.runOut[dpkgQuery] = "linux-image-" + oldRel + " 6.8.0-142.142 ii \n"
		holdLater(a)
		m := rstep(t, a, f, p, nil)
		if !canary {
			if m != "" || len(ran(sys, "systemctl reboot")) != 0 {
				t.Fatalf("not a canary: %q", m)
			}
			continue
		}
		want := "a canary's boot for " + g.Name()
		if m != "rebooting ("+want+")" || strings.Join(ran(sys, "grub-", "systemctl reboot"), "|") != "systemctl reboot" {
			t.Fatalf("the canary: %q, ran %q", m, ran(sys, "grub-", "systemctl reboot"))
		}
		bootInto(sys, oldRel)
		if m := rstep(t, a, f, p, nil); m != "rebooted ("+want+"); its health window runs" {
			t.Fatalf("after the boot: %q", m)
		}
		after(TrialWindow)
		if m := rstep(t, a, f, p, nil); m != "rebooted ("+want+"); health held" {
			t.Fatalf("health held: %q", m)
		}
		after(24 * time.Hour) // the guard still hasn't booted here, but the canary rebooted for it once
		if m := rstep(t, a, f, p, nil); m != "" || len(ran(sys, "systemctl reboot")) != 1 {
			t.Fatalf("a second reboot for the same guard: %q", m)
		}
	}
	// Only an admitted guard, on and not yet booted, counts: not one put on
	// by hand, one already booted, or one still on trial.
	for name, e := range map[string]*Entry{
		"by hand":        {Hash: g.Hash(), Guard: g, Status: Confirmed, Later: true},
		"booted already": {Hash: g.Hash(), Guard: g, Status: Confirmed, Later: true, By: "rig", Booted: true},
		"on trial":       {Hash: g.Hash(), Guard: g, Status: Pending, Later: true, By: "rig"},
	} {
		a, sys, f, p, _ := rebootAgent(t, `,"reboot":"window","reboot_window":"03:00-04:00","canaries":["web"]`)
		sys.runOut[dpkgQuery] = "linux-image-" + oldRel + " 6.8.0-142.142 ii \n"
		s, st, err := a.open()
		if err != nil {
			t.Fatal(err)
		}
		st.Guards = append(st.Guards, e)
		if err := s.save(st); err != nil {
			t.Fatal(err)
		}
		s.close()
		if m := rstep(t, a, f, p, nil); strings.HasPrefix(m, "rebooting") || len(ran(sys, "systemctl reboot")) != 0 {
			t.Errorf("%s: %q", name, m)
		}
	}
	// A canary whose tier waits for the owner says so.
	a, sys, f, p, _ := rebootAgent(t, `,"canaries":["web"]`)
	sys.runOut[dpkgQuery] = "linux-image-" + oldRel + " 6.8.0-142.142 ii \n"
	holdLater(a)
	if m := rstep(t, a, f, p, nil); m != "a reboot is owed: this canary boots with "+g.Name()+" before the rest of its tier takes it; this tier waits for your signed Reboot" {
		t.Fatalf("a yes tier: %q", m)
	}
}
