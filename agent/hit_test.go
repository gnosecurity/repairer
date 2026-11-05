package agent

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/check"
	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
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

// checkAgent is a machine "web" of a fleet whose owner key is ownerKey,
// with a way to tick it (a bundle of statements and check files first) and
// to sign the owner's Check of a check, sequence by sequence.
func checkAgent(t *testing.T) (*Agent, *fakeSys, func([]Message, ...*check.Check) *TickResult, func(*check.Check, string) Message) {
	t.Helper()
	a, sys, _ := newAgent(t)
	key := ownerKey()
	pub := hex.EncodeToString(key.PubKey().SerializeCompressed())
	p, err := policy.Decode([]byte(`{"fleet":"test","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"` + pub + `"}},
		"tiers":[{"name":"A","hosts":["web"],"admit":["me"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Init("web", p.Canonical(), 0); err != nil {
		t.Fatal(err)
	}
	owner, _ := hex.DecodeString(pub)
	chain := approve.ChainID(owner, p.Fleet)
	seq := uint64(0)
	// sign signs the owner's Check of c, over memo, or over the memo this
	// agent writes for c when memo is "".
	sign := func(c *check.Check, memo string) Message {
		seq++
		if memo == "" {
			var err error
			if memo, err = approve.MemoCheck(c); err != nil {
				t.Fatal(err)
			}
		}
		return Message{Seq: seq, Tx: signStatement(t, key, chain, seq, "Check", []string{c.Hash()}, memo)}
	}
	tick := func(msgs []Message, checks ...*check.Check) *TickResult {
		t.Helper()
		if len(msgs) > 0 || len(checks) > 0 {
			bun := Bundle{Messages: msgs, Checks: map[string][]byte{}}
			for _, c := range checks {
				bun.Checks[c.Hash()] = c.Canonical()
			}
			js, _ := json.Marshal(bun)
			if _, err := Intake(filepath.Join(a.StateDir, spoolDir), bytes.NewReader(js)); err != nil {
				t.Fatal(err)
			}
		}
		res, err := a.Tick(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	return a, sys, tick, sign
}

// The owner's Check runs a check once, through intake and the tick, and the
// signed report carries its result until the next Check of that check. A
// Check waits for its file, as a Policy does, holding the statements after
// it; one for another system is taken and not run; one whose memo isn't the
// one this agent writes is skipped. (The lookout sends every statement after
// the last one taken again, with the files it names.)
func TestCheckOnYourWord(t *testing.T) {
	a, sys, tick, sign := checkAgent(t)
	c := mkCheck(t, check.DeletedExe, check.Args{})
	key := strings.Join([]string{"find", "/proc", "-mindepth", "2", "-maxdepth", "2", "-path", "/proc/[0-9]*/exe", "-lname", "* (deleted)", "-printf", `%l\n`}, " ")
	sys.runOut[key] = "/tmp/.x (deleted)\n"
	m1 := sign(c, "")
	if res := tick([]Message{m1}); res.Held == "" || len(res.Hits) != 0 {
		t.Fatalf("without its file: %+v", res)
	}
	res := tick([]Message{m1}, c) // the lookout sends it again with the file: taken
	if strings.Join(res.Hits, ",") != c.Name() || res.Held != "" {
		t.Fatalf("with its file: %+v", res)
	}
	raw, err := ReadReport(a.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	var sr approve.SignedReport
	var body FleetReport
	if json.Unmarshal(raw, &sr) != nil || json.Unmarshal(sr.Body, &body) != nil || len(body.Hits) != 1 {
		t.Fatalf("the report: %s", raw)
	}
	if h := body.Hits[0]; !h.Flag || h.Count != 1 || h.Paths[0] != "/tmp/.x" || h.Check != c.Hash() {
		t.Fatalf("the result: %+v", h)
	}
	// The next tick doesn't run it again; a new Check does, replacing the
	// result.
	if res := tick(nil); len(res.Hits) != 0 {
		t.Fatalf("ran again unasked: %+v", res)
	}
	sys.runOut[key] = ""
	if res := tick([]Message{sign(c, "")}, c); len(res.Hits) != 1 {
		t.Fatalf("a second Check: %+v", res)
	}
	if hits, _ := a.loadHits(); len(hits) != 1 || hits[0].Flag {
		t.Fatalf("the result wasn't replaced: %+v", hits)
	}
	// Another system's check is taken and not run.
	deb := mkCheck(t, check.DeletedExe, check.Args{})
	deb.For = []guard.Target{{OS: "debian", Releases: []string{"12"}}}
	if res := tick([]Message{sign(deb, "")}, deb); len(res.Hits) != 0 || len(res.Accepted) != 1 {
		t.Fatalf("another system's: %+v", res)
	}
	// A memo this agent doesn't write for the check: skipped, nothing run.
	if res := tick([]Message{sign(c, "autopatch/1 Check a check that reads nothing")}, c); len(res.Hits) != 0 {
		t.Fatalf("a memo that hides what it reads: %+v", res)
	}
	f, _ := a.loadFleet()
	if n := len(f.Skipped); n == 0 || !strings.Contains(f.Skipped[n-1].Why, "its memo isn't what this agent writes") {
		t.Fatalf("skipped: %+v", f.Skipped)
	}
}
