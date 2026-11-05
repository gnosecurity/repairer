package agent

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/check"
	"github.com/jaekwon/autopatch/guard"
)

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// mkCheck builds a valid check of a kind with its args.
func mkCheck(t *testing.T, kind string, args check.Args) *check.Check {
	t.Helper()
	c := &check.Check{ID: "cve-2026-98432/hit", Version: 1, Flaws: []string{"CVE-2026-98432"},
		For: []guard.Target{{OS: "ubuntu", Releases: []string{"24.04"}}}, Kind: kind, Args: args, Flag: "signs of it"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

const since = "1793923200" // 2026-11-06 00:00 UTC

// package-files hashes each file its md5sums list: a changed file is
// flagged with its path; a file gone is counted apart; a multi-arch package
// is found by the machine's architecture.
func TestHitPackageFiles(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.files["/var/lib/dpkg/info/openssh-server.md5sums"] = md5hex("sshd binary") + "  usr/sbin/sshd\n" +
		md5hex("helper") + "  usr/lib/openssh/sftp-server\n" + md5hex("doc") + "  usr/share/doc/openssh-server/README\n"
	sys.files["/usr/sbin/sshd"] = "sshd binary"
	sys.files["/usr/lib/openssh/sftp-server"] = "helper, replaced"
	r := a.runCheck(ctx, mkCheck(t, check.PackageFiles, check.Args{Package: "openssh-server"}))
	if !r.Flag || r.Count != 1 || strings.Join(r.Paths, ",") != "/usr/lib/openssh/sftp-server" || r.Gone != 1 || r.Error != "" {
		t.Fatalf("%+v", r)
	}
	sys.runOut["dpkg --print-architecture"] = "amd64\n"
	sys.files["/var/lib/dpkg/info/libc6:amd64.md5sums"] = md5hex("libc") + "  usr/lib/x86_64-linux-gnu/libc.so.6\n"
	sys.files["/usr/lib/x86_64-linux-gnu/libc.so.6"] = "libc"
	if r := a.runCheck(ctx, mkCheck(t, check.PackageFiles, check.Args{Package: "libc6"})); r.Flag || r.Count != 0 || r.Error != "" {
		t.Fatalf("libc6: %+v", r)
	}
	if r := a.runCheck(ctx, mkCheck(t, check.PackageFiles, check.Args{Package: "nosuch"})); r.Error == "" || r.Flag {
		t.Fatalf("no such package: %+v", r)
	}
	old := HitFiles
	HitFiles = 2
	defer func() { HitFiles = old }()
	if r := a.runCheck(ctx, mkCheck(t, check.PackageFiles, check.Args{Package: "openssh-server"})); r.Capped != "files" {
		t.Fatalf("past the file cap: %+v", r)
	}
}

// deleted-exe names each deleted program once.
func TestHitDeletedExe(t *testing.T) {
	a, sys, _ := newAgent(t)
	key := strings.Join([]string{"find", "/proc", "-mindepth", "2", "-maxdepth", "2", "-path", "/proc/[0-9]*/exe", "-lname", "* (deleted)", "-printf", `%l\n`}, " ")
	r := a.runCheck(ctx, mkCheck(t, check.DeletedExe, check.Args{}))
	if r.Flag || r.Count != 0 {
		t.Fatalf("a clean machine: %+v", r)
	}
	sys.runOut[key] = "/usr/sbin/sshd (deleted)\n/tmp/.x (deleted)\n/usr/sbin/sshd (deleted)\n"
	r = a.runCheck(ctx, mkCheck(t, check.DeletedExe, check.Args{}))
	if !r.Flag || r.Count != 2 || strings.Join(r.Paths, ",") != "/usr/sbin/sshd,/tmp/.x" {
		t.Fatalf("%+v", r)
	}
}

// new-since asks find for each of what's places that exist, by change
// time; setuid adds the permission test; keys under /home only in .ssh.
func TestHitNewSince(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.files["/tmp"] = ""
	sys.files["/usr"] = ""
	sys.runOut["find /tmp -xdev -type f -perm /6000 -newerct @"+since+" -print"] = "/tmp/.s\n"
	sys.runOut["find /usr -xdev -type f -perm /6000 -newerct @"+since+" -print"] = ""
	r := a.runCheck(ctx, mkCheck(t, check.NewSince, check.Args{What: "setuid", Since: since}))
	if !r.Flag || r.Count != 1 || r.Paths[0] != "/tmp/.s" || r.Error != "" {
		t.Fatalf("setuid: %+v", r)
	}
	if got := ran(sys, "find /bin", "find /opt"); len(got) != 0 {
		t.Fatalf("ran find on places that don't exist: %q", got)
	}
	sys.files["/home"] = ""
	sys.files["/root/.ssh"] = ""
	sys.runOut["find /home -xdev -maxdepth 3 -path /home/*/.ssh/* -newerct @"+since+" -print"] = "/home/jae/.ssh/authorized_keys\n"
	r = a.runCheck(ctx, mkCheck(t, check.NewSince, check.Args{What: "keys", Since: since}))
	if r.Count != 1 || r.Paths[0] != "/home/jae/.ssh/authorized_keys" {
		t.Fatalf("keys: %+v", r)
	}
	if got := ran(sys, "find /root/.ssh -xdev -newerct"); len(got) != 1 {
		t.Fatalf("root's keys not looked at: %q", ran(sys, "find"))
	}
}

// foreign-modules lists loaded modules no package owns, leaving out those
// DKMS built for the running kernel.
func TestHitForeignModules(t *testing.T) {
	a, sys, _ := newAgent(t)
	rel := "6.8.0-142-generic"
	sys.files["/proc/sys/kernel/osrelease"] = rel + "\n"
	sys.files["/proc/modules"] = "nf_tables 368640 1 - Live 0x0\nrootkit 16384 0 - Live 0x0\nnvidia 54001664 0 - Live 0x0\n"
	nf := "/lib/modules/" + rel + "/kernel/net/netfilter/nf_tables.ko.zst"
	rk := "/lib/modules/" + rel + "/extra/rootkit.ko"
	nv := "/lib/modules/" + rel + "/updates/dkms/nvidia.ko.zst"
	sys.runOut["modinfo -n nf_tables rootkit nvidia"] = nf + "\n" + rk + "\n" + nv + "\n"
	sys.runOut["dpkg -S "+nf+" "+rk+" "+nv] = "linux-modules-" + rel + ": " + nf + "\n"
	sys.runOut["dkms status"] = "nvidia/550.120, " + rel + ", x86_64: installed\n"
	r := a.runCheck(ctx, mkCheck(t, check.ForeignModules, check.Args{}))
	if !r.Flag || r.Count != 1 || r.Paths[0] != rk {
		t.Fatalf("%+v", r)
	}
}

// log-match counts the lines since since that hold the pattern: the auth
// log in either time format, its first rotation included, or a unit's
// journal; never the lines themselves.
func TestHitLogMatch(t *testing.T) {
	a, sys, _ := newAgent(t)
	a.Now = func() time.Time { return time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC) }
	sys.files["/var/log/auth.log.1"] = "Nov  5 23:59:59 web sshd[1]: Accepted publickey for root\n" +
		"Nov  6 00:00:01 web sshd[2]: Accepted publickey for jae\n"
	sys.files["/var/log/auth.log"] = "2026-11-06T09:00:00.123456+00:00 web sshd[3]: Accepted publickey for root\n" +
		"2026-11-06T09:00:01.000000+00:00 web sshd[3]: Failed password for root\n"
	r := a.runCheck(ctx, mkCheck(t, check.LogMatch, check.Args{Source: "auth", Pattern: "Accepted publickey", Since: since}))
	if !r.Flag || r.Count != 2 || len(r.Paths) != 0 || r.Error != "" {
		t.Fatalf("auth: %+v", r)
	}
	sys.runOut["journalctl --no-pager -q -o cat -u ssh.service --since @"+since] = "Accepted publickey for root\nother\nAccepted publickey for jae\n"
	r = a.runCheck(ctx, mkCheck(t, check.LogMatch, check.Args{Source: "unit:ssh.service", Pattern: "Accepted publickey", Since: since}))
	if r.Count != 2 {
		t.Fatalf("a unit's journal: %+v", r)
	}
	delete(sys.files, "/var/log/auth.log")
	delete(sys.files, "/var/log/auth.log.1")
	if r := a.runCheck(ctx, mkCheck(t, check.LogMatch, check.Args{Source: "auth", Pattern: "x", Since: since})); r.Error == "" || r.Flag {
		t.Fatalf("no auth log: %+v", r)
	}
}

// logTime reads both syslog time formats; a traditional time ahead of now
// is last year's.
func TestLogTime(t *testing.T) {
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	if got, ok := logTime("Dec 31 23:00:00 host x", now); !ok || got.Year() != 2025 {
		t.Fatalf("%v %v", got, ok)
	}
	if got, ok := logTime("2026-01-01T10:00:00+00:00 host x", now); !ok || got.Hour() != 10 {
		t.Fatalf("%v %v", got, ok)
	}
	if _, ok := logTime("garbage", now); ok {
		t.Fatal("garbage read as a time")
	}
}
