package guard

import (
	"fmt"
	"strings"
)

// Effect says when a block starts to bite. A block that bites later than
// now keeps its undo armed until that event has passed, and needs a canary
// boot before it goes on anywhere automatically.
type Effect string

const (
	Now          Effect = "now"
	NewSockets   Effect = "new sockets"
	NewProcesses Effect = "new processes"
	NextLoad     Effect = "next load or boot"
	NextRun      Effect = "next run"
)

// Later reports whether the effect is anything but immediate.
func (e Effect) Later() bool { return e != Now }

// settingRule is an allow-list entry: the one value a guard may set and
// what to check before setting it.
type settingRule struct {
	Value  string
	Effect Effect
	// InUse names the check that refuses the setting while something uses
	// the feature, or while it can't reach everything: "userns", "io_uring"
	// or "netns".
	InUse string
}

// settings is the allow-list of kernel settings a guard may change. Every
// entry can be undone without a reboot, and none turns a kernel bug into a
// reboot (no panic_on_* settings).
var settings = map[string]settingRule{
	// CVE-2026-98432: the published exploit goes through MPTCP listeners.
	// net.* settings live in each network namespace; the netns check
	// refuses them while containers have namespaces of their own.
	"net.mptcp.enabled": {Value: "0", Effect: NewSockets, InUse: "netns"},
	// CVE-2019-11477 (SACK Panic): the stopgap was SACK off.
	"net.ipv4.tcp_sack": {Value: "0", Effect: Now, InUse: "netns"},
	// User namespaces: the door for many local root exploits.
	"kernel.unprivileged_userns_clone": {Value: "0", Effect: NewProcesses, InUse: "userns"},
	"user.max_user_namespaces":         {Value: "0", Effect: NewProcesses, InUse: "userns"},
	// io_uring: the door for many others.
	"kernel.io_uring_disabled": {Value: "2", Effect: NewProcesses, InUse: "io_uring"},
	// 2, not 1: 1 can't be undone without a reboot.
	"kernel.unprivileged_bpf_disabled": {Value: "2", Effect: Now},
	"vm.unprivileged_userfaultfd":      {Value: "0", Effect: Now},
	"dev.tty.ldisc_autoload":           {Value: "0", Effect: Now},
}

// SettingInUseCheck returns the name of the in-use check for an allowed
// setting, or "".
func SettingInUseCheck(name string) string { return settings[name].InUse }

// moduleAuto lists modules rarely needed on servers, with histories of
// flaws, spelled with '_'. Blocking one of these can go on automatically; blocking another
// module that isn't on the never list needs the owner's yes.
var moduleAuto = map[string]bool{
	"ksmbd": true, "nlmon": true, "act_pedit": true, "dccp": true, "sctp": true,
	"rds": true, "tipc": true, "n_hdlc": true, "cramfs": true, "freevxfs": true,
	"jffs2": true, "hfs": true, "hfsplus": true, "udf": true, "firewire_core": true,
	"ax25": true, "netrom": true, "rose": true, "x25": true, "appletalk": true,
	"atm": true, "can": true, "can_raw": true, "can_bcm": true, "can_gw": true,
}

// neverBlockPrefixes are module families a guard never blocks: the
// firewall, storage, networking, virtualization and graphics a server needs
// to boot, be reached and do its job.
var neverBlockPrefixes = []string{
	"nf_", "nft_", "nfnetlink", "x_tables", "ip_tables", "ip6_tables", "iptable_", "ip6table_",
	"xt_", "ebt", "br_netfilter", "bridge", "overlay", "ext4", "xfs", "btrfs", "zfs", "vfat",
	"fat", "squashfs", "loop", "dm_", "dm-", "md_", "raid", "nvme", "virtio", "sd_mod", "ahci",
	"libata", "scsi", "e1000", "igb", "ixgbe", "i40e", "ice", "mlx", "ena", "vmxnet",
	"hv_", "xen", "tun", "tap", "veth", "wireguard", "bonding", "8021q", "kvm", "vfio",
	"amdgpu", "nvidia", "i915", "drm", "ttm", "ib_", "rdma", "nbd", "ceph", "rbd", "fuse",
	"af_packet", "unix", "ipv6", "tls", "crypto", "sha", "aes", "efivarfs", "autofs",
	"ip_set", "ipt_", "ip6t_", "arp_", "arptable", "ip_vs", "ipip", "ip_tunnel", "ip6_tunnel",
	"sit", "gre", "ip_gre", "ip6_gre", "vxlan", "geneve", "macvlan", "ipvlan", "dummy",
}

// aliasPrefixes are how module aliases begin, other than those with a ':'
// (pci:, usb:, platform:), which the name pattern already refuses. A guard
// names a module itself, never an alias: an alias such as
// net-pf-16-proto-12 stands for a module the never list protects
// (nfnetlink), and modprobe runs an install line for the alias before it
// looks the alias up. The agent also refuses any name the running kernel
// has no module by.
var aliasPrefixes = []string{
	"net_pf_", "fs_", "char_major_", "block_major_", "binfmt_", "tty_ldisc_", "rtnl_",
	"netdev_",
}

func looksLikeAlias(name string) bool {
	n := strings.ReplaceAll(name, "-", "_")
	for _, p := range aliasPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

func neverBlock(name string) bool {
	n := strings.ReplaceAll(name, "-", "_")
	for _, p := range neverBlockPrefixes {
		if strings.HasPrefix(n, strings.ReplaceAll(p, "-", "_")) {
			return true
		}
	}
	return false
}

// serviceAuto lists optional network services with histories of flaws.
// Stopping one of these can go on automatically; stopping another unit that
// isn't on the never list needs the owner's yes.
var serviceAuto = map[string]bool{
	"cups-browsed.service": true, "cups.service": true, "cups.socket": true,
	"avahi-daemon.service": true, "avahi-daemon.socket": true, "rpcbind.service": true,
	"rpcbind.socket": true, "ModemManager.service": true, "bluetooth.service": true,
	"ksmbd.service": true, "smbd.service": true, "nmbd.service": true,
	"telnet.socket": true, "xinetd.service": true, "vsftpd.service": true,
	"tftpd-hpa.service": true, "snmpd.service": true,
}

// neverStopPrefixes are units a guard never stops: the firewall, ssh,
// logging, time, the update path (updaters, certificate renewal), the
// machine's own plumbing, and the agent itself.
var neverStopPrefixes = []string{
	"ssh", "sshd", "systemd-", "dbus", "polkit", "cron", "anacron", "rsyslog", "syslog",
	"auditd", "journald", "ufw", "nftables", "firewalld", "iptables", "ip6tables",
	"netfilter-persistent", "fail2ban", "apparmor", "selinux", "chrony", "ntp", "ntpsec",
	"openntpd", "unattended-upgrades", "apt-daily", "apt-", "dnf-", "yum-", "packagekit",
	"snapd", "certbot", "letsencrypt", "acme", "networking", "NetworkManager", "network",
	"wpa_supplicant", "resolvconf", "cloud-", "droplet-agent", "do-agent", "qemu-guest-agent",
	"google-", "amazon-", "waagent", "walinuxagent", "getty", "serial-getty", "console-",
	"multipathd", "lvm2", "mdmonitor", "udisks2", "autopatch", "tmkms",
	"ua-", "ubuntu-advantage", "esm-cache", "fwupd", "dropbear", "tailscale", "sssd",
	"canonical-livepatch", "amazon-ssm-agent", "ssm-agent", "wg-quick", "openvpn",
	"teleport", "cloudflared", "cockpit", "zerotier", "netbird",
}

// neverStop reports whether a unit is on the never-touch list. A snap's
// units are named snap.<snap>.<app>, so the snap's name is checked too.
func neverStop(unit string) bool {
	names := []string{unit}
	if rest, ok := strings.CutPrefix(unit, "snap."); ok {
		snap, _, _ := strings.Cut(rest, ".")
		names = append(names, snap)
	}
	for _, n := range names {
		for _, p := range neverStopPrefixes {
			if strings.HasPrefix(n, p) {
				return true
			}
		}
	}
	return false
}

// neverStripPaths are programs a guard never strips: how owners become root.
var neverStripPaths = map[string]bool{
	"/usr/bin/sudo": true, "/usr/bin/sudoedit": true, "/usr/bin/su": true, "/bin/su": true,
	"/usr/bin/doas": true, "/usr/bin/passwd": true, "/bin/sudo": true,
	"/usr/lib/openssh/ssh-keysign": true, "/usr/libexec/openssh/ssh-keysign": true,
	"/usr/lib/cargo/bin/sudo": true, "/usr/lib/cargo/bin/su": true, "/usr/bin/sudo.ws": true,
	"/usr/bin/sudo-rs": true, "/usr/bin/su-rs": true, "/bin/doas": true, "/bin/passwd": true,
}

// NeverStripPaths lists the programs a guard never strips. The agent also
// refuses any path that is the same file as one of these.
func NeverStripPaths() []string {
	out := make([]string, 0, len(neverStripPaths))
	for p := range neverStripPaths {
		out = append(out, p)
	}
	return out
}

func neverStrip(p string) bool { return neverStripPaths[p] }

// Effect says when the block starts to bite.
func (b Block) Effect() Effect {
	switch {
	case b.Setting != nil:
		return settings[b.Setting.Name].Effect
	case b.Module != nil:
		return NextLoad
	case b.Strip != nil:
		return NextRun
	}
	return Now // drop, service
}

// Later reports whether any of the guard's blocks bites later than now. A
// guard that mixes the two counts as later as a whole, and waits for a
// canary's boot; the realm and the rig refuse a mix, so that an urgent drop
// never waits for one.
func (g *Guard) Later() bool {
	for _, b := range g.Blocks {
		if b.Effect().Later() {
			return true
		}
	}
	return false
}

// Timing says when the guard bites, in words: "bites now", "bites later",
// or "mixes blocks that bite now with ones that bite later", which the rig
// and the realm refuse.
func (g *Guard) Timing() string {
	now, later := false, false
	for _, b := range g.Blocks {
		if b.Effect().Later() {
			later = true
		} else {
			now = true
		}
	}
	switch {
	case now && later:
		return "mixes blocks that bite now with ones that bite later"
	case later:
		return "bites later"
	}
	return "bites now"
}

// BitesAtBoot reports whether some block bites when a boot brings things up:
// a module at its next load, a setting for new sockets or processes. A
// strip bites at a program's next run, which a boot may not bring.
func (g *Guard) BitesAtBoot() bool {
	for _, b := range g.Blocks {
		switch b.Effect() {
		case NextLoad, NewSockets, NewProcesses:
			return true
		}
	}
	return false
}

// Auto reports whether every block may go on without the owner's yes.
func (g *Guard) Auto() bool {
	for _, b := range g.Blocks {
		if !b.Auto() {
			return false
		}
	}
	return true
}

// Auto reports whether the block may go on without the owner's yes, under
// the agent's own lists. A block that bites later never goes on
// automatically before a canary boot, whatever this says.
func (b Block) Auto() bool {
	switch {
	case b.Module != nil:
		// modprobe treats '-' and '_' in module names alike.
		return moduleAuto[strings.ReplaceAll(b.Module.Name, "-", "_")]
	case b.Service != nil:
		return serviceAuto[b.Service.Unit]
	}
	return true // drop, setting (allow-listed), strip
}

// Describe says what the block does, in plain words.
func (b Block) Describe() string {
	switch {
	case b.Drop != nil:
		d := b.Drop
		var w []string
		w = append(w, "drop inbound", d.Family)
		if d.Protocol != "" {
			w = append(w, d.Protocol)
		} else {
			w = append(w, "packets")
		}
		if d.SYN {
			w = append(w, "connection requests")
		}
		if d.IPOptions {
			w = append(w, "carrying IP options")
		}
		if len(d.Ports) > 0 {
			w = append(w, "to port "+strings.Join(d.Ports, ", "))
		}
		return strings.Join(w, " ")
	case b.Setting != nil:
		return fmt.Sprintf("set %s = %s", b.Setting.Name, b.Setting.Value)
	case b.Module != nil:
		return "block kernel module " + b.Module.Name
	case b.Service != nil:
		return "stop and mask " + b.Service.Unit
	case b.Strip != nil:
		return "remove the setuid and setgid bits from " + b.Strip.Path
	}
	return "?"
}
