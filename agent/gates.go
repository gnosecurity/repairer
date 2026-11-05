package agent

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

// Gate is one check that must pass before the machine reboots. These are the
// checks mithrandir ran by hand on 2026-11-04 (AUTOPATCH-BRIEF.md), each a
// way a reboot went wrong or would have.
type Gate struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Why  string `json:"why,omitempty"`
}

// Minimum free space before a reboot into a new kernel.
const (
	minBootFree = 100 << 20 // a kernel and its initrd
	minRootFree = 1 << 30
)

// Gates checks, without changing anything, whether this machine can reboot
// into its newest installed kernel and come back as it is now.
func (a *Agent) Gates(ctx context.Context) []Gate {
	var gs []Gate
	add := func(name string, ok bool, why string) { gs = append(gs, Gate{name, ok, why}) }

	// 1. ssh comes back.
	enabled := false
	for _, u := range []string{"ssh.service", "ssh.socket", "sshd.service"} {
		out, _ := a.Sys.Run(ctx, nil, "systemctl", "is-enabled", u)
		if st := strings.TrimSpace(string(out)); st == "enabled" || st == "enabled-runtime" || st == "static" || st == "alias" {
			enabled = true
		}
	}
	add("ssh comes back", enabled, map[bool]string{false: "neither ssh.service nor ssh.socket is enabled"}[enabled])

	// 2. Nothing listening was started by hand in a login session: it
	// wouldn't come back (the matrix boxes' processes on 11-04).
	var hand []string
	if ls, err := a.Sys.Listening(); err == nil {
		seen := map[int]bool{}
		for _, l := range ls {
			if l.PID == 0 || seen[l.PID] {
				continue
			}
			seen[l.PID] = true
			if cg, err := a.Sys.ReadFile("/proc/" + strconv.Itoa(l.PID) + "/cgroup"); err == nil && inLoginSession(cg) {
				hand = append(hand, fmt.Sprintf("%s (pid %d, port %d)", l.Process, l.PID, l.Port))
			}
		}
	}
	add("no hand-started listeners", len(hand) == 0, strings.Join(hand, "; "))

	// 3. Containers come back.
	if out, err := a.Sys.Run(ctx, nil, "docker", "ps", "--format", "{{.Names}}"); err == nil {
		var none []string
		for _, name := range strings.Fields(string(out)) {
			pol, _ := a.Sys.Run(ctx, nil, "docker", "inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", name)
			if p := strings.TrimSpace(string(pol)); p == "" || p == "no" {
				none = append(none, name)
			}
		}
		add("containers restart", len(none) == 0, map[bool]string{true: "", false: "no restart policy: " + strings.Join(none, ", ")}[len(none) == 0])
	}

	// 4. Room on disk.
	for _, d := range []struct {
		path string
		min  uint64
	}{{"/boot", minBootFree}, {"/", minRootFree}} {
		var st syscall.Statfs_t
		if err := syscall.Statfs(d.path, &st); err == nil {
			free := uint64(st.Bavail) * uint64(st.Bsize)
			add("room on "+d.path, free >= d.min, map[bool]string{true: "", false: fmt.Sprintf("%d MB free", free>>20)}[free >= d.min])
		}
	}

	// 5. The newest kernel can boot: its image and initrd are there, and
	// every DKMS module is built for it (11-04: a kernel whose postinst
	// failed left no initrd, and GRUB_DEFAULT=0 would have booted it).
	out, err := a.Sys.Run(ctx, nil, "dpkg-query", "-W", "-f", "${Package} ${Version} ${db:Status-Abbrev}\n", "linux-image-[0-9]*")
	if err != nil {
		add("newest kernel can boot", false, "can't list installed kernels: "+err.Error())
		return gs
	}
	_, rel := installedKernels(out)
	if rel == "" {
		add("newest kernel can boot", false, "no installed kernel found")
		return gs
	}
	var why []string
	for _, f := range []string{"/boot/vmlinuz-" + rel, "/boot/initrd.img-" + rel} {
		if fi, err := a.Sys.Stat(f); err != nil || fi.Size() == 0 {
			why = append(why, f+" is missing or empty")
		}
	}
	if dk, err := a.Sys.Run(ctx, nil, "dkms", "status"); err == nil {
		if m := dkmsMissing(dk, rel); len(m) > 0 {
			why = append(why, "DKMS not built for "+rel+": "+strings.Join(m, ", "))
		}
	}
	add("newest kernel can boot ("+rel+")", len(why) == 0, strings.Join(why, "; "))

	// 6. Every kernel is installed whole: no linux-image package half
	// installed or half configured (a postinst that failed), and every
	// installed one has its vmlinuz and initrd, since GRUB lists each vmlinuz
	// in /boot and a boot may land on any of them (round 14, new major 1).
	var half []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		switch krel := strings.TrimPrefix(f[0], "linux-image-"); f[2] {
		case "ii":
			for _, fl := range []string{"/boot/vmlinuz-" + krel, "/boot/initrd.img-" + krel} {
				if fi, err := a.Sys.Stat(fl); err != nil || fi.Size() == 0 {
					half = append(half, fl+" is missing or empty")
				}
			}
		case "rc", "un", "pn": // removed, or never installed
		default:
			half = append(half, f[0]+" is "+f[2]+", not fully installed")
		}
	}
	add("every kernel installed whole", len(half) == 0, strings.Join(half, "; "))
	return gs
}

// inLoginSession reports whether a process's cgroup is inside a login
// session (systemd puts what a user starts by hand under user.slice, in a
// session-N.scope), rather than in a service that comes back by itself.
func inLoginSession(cgroup []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(cgroup))
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "/user.slice/") && strings.Contains(line, "/session-") && strings.HasSuffix(strings.TrimSpace(line), ".scope") {
			return true
		}
	}
	return false
}
