package agent

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gnosecurity/repairer/approve"
	"github.com/gnosecurity/repairer/check"
	"github.com/gnosecurity/repairer/guard"
	"github.com/gnosecurity/repairer/policy"
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

// foreign-modules asks modinfo of each loaded module alone: one it can't
// find is foreign; one loaded unsigned is foreign unless DKMS built it here
// and its file is DKMS's; one loaded out of tree whose file is in tree
// isn't that file; the rest are foreign unless a package owns their file
// (round 15, new major 5).
func TestHitForeignModules(t *testing.T) {
	a, sys, _ := newAgent(t)
	rel := "6.8.0-142-generic"
	sys.files["/proc/sys/kernel/osrelease"] = rel + "\n"
	sys.files["/proc/modules"] = "nf_tables 368640 1 - Live 0x0\n" +
		"rootkit 16384 0 - Live 0x0 (OE)\n" + // insmod'ed from /dev/shm: modinfo doesn't know it
		"nvidia 54001664 0 - Live 0x0 (POE)\n" + // DKMS's, unsigned
		"floppy 16384 0 - Live 0x0 (OE)\n" + // an in-tree name, loaded unsigned
		"nf_x 16384 0 - Live 0x0 (O)\n" + // signed, out of tree, under an in-tree module's name
		"zfs 6000000 0 - Live 0x0 (PO)\n" + // packaged, out of tree
		"extra 16384 0 - Live 0x0\n" + // a file no package owns
		"-b/tmp 4096 0 - Live 0x0\n"
	mod := func(name, file, intree string) {
		sys.runOut["modinfo -- "+name] = "filename:       " + file + "\nintree:         " + intree + "\nname:           " + name + "\n"
	}
	k := "/lib/modules/" + rel + "/kernel/"
	mod("nf_tables", k+"net/netfilter/nf_tables.ko.zst", "Y")
	sys.runErr["modinfo -- rootkit"] = "modinfo: ERROR: Module rootkit not found.\n"
	mod("nvidia", "/lib/modules/"+rel+"/updates/dkms/nvidia.ko.zst", "")
	mod("floppy", k+"drivers/block/floppy.ko.zst", "Y")
	mod("nf_x", k+"net/netfilter/nf_x.ko.zst", "Y")
	mod("zfs", k+"zfs/zfs.ko.zst", "")
	mod("extra", "/lib/modules/"+rel+"/extra/extra.ko", "")
	sys.runOut["dpkg -S -- "+k+"net/netfilter/nf_tables.ko.zst "+k+"zfs/zfs.ko.zst /lib/modules/"+rel+"/extra/extra.ko"] =
		"linux-modules-" + rel + ": " + k + "net/netfilter/nf_tables.ko.zst\nlinux-modules-" + rel + ": " + k + "zfs/zfs.ko.zst\n"
	sys.runOut["dkms status"] = "nvidia/550.120, " + rel + ", x86_64: installed\n"
	r := a.runCheck(ctx, mkCheck(t, check.ForeignModules, check.Args{}))
	want := []string{
		"/proc/modules: rootkit (no module file)",
		k + "drivers/block/floppy.ko.zst (floppy loaded unsigned)",
		k + "net/netfilter/nf_x.ko.zst (nf_x loaded out of tree; this file is in tree)",
		"/proc/modules: -b/tmp", // a module named like an option is a sign, and never an argument
		"/lib/modules/" + rel + "/extra/extra.ko",
	}
	if !r.Flag || r.Count != len(want) || strings.Join(r.Paths, "|") != strings.Join(want, "|") || r.Error != "" {
		t.Fatalf("%+v", r)
	}
	// DKMS's name, its file elsewhere: not DKMS's.
	mod("nvidia", k+"drivers/video/nvidia.ko.zst", "")
	if r := a.runCheck(ctx, mkCheck(t, check.ForeignModules, check.Args{})); !strings.Contains(strings.Join(r.Paths, "|"), "nvidia.ko.zst (nvidia loaded unsigned)") {
		t.Fatalf("DKMS's name, not its file: %+v", r)
	}
	// modinfo failing otherwise is no clean answer.
	sys.runErr["modinfo -- nf_tables"] = "modinfo: ERROR: could not open modules.dep\n"
	delete(sys.runOut, "modinfo -- nf_tables")
	if r := a.runCheck(ctx, mkCheck(t, check.ForeignModules, check.Args{})); r.Error == "" {
		t.Fatalf("modinfo failing: %+v", r)
	}
}

// log-match counts the lines since since that hold the pattern: the auth
// log in either time format, its first rotation included, or a unit's
// journal; never the lines themselves.
func TestHitLogMatch(t *testing.T) {
	a, sys, _ := newAgent(t)
	a.Now = func() time.Time { return time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC) }
	a.Zone = time.UTC
	sys.files["/var/log/auth.log.1"] = "Nov  5 23:59:59 web sshd[1]: Accepted publickey for root\n" +
		"Nov  6 00:00:01 web sshd[2]: Accepted publickey for jae\n"
	sys.files["/var/log/auth.log"] = "2026-11-06T09:00:00.123456+00:00 web sshd[3]: Accepted publickey for root\n" +
		"2026-11-06T09:00:01.000000+00:00 web sshd[3]: Failed password for root\n"
	r := a.runCheck(ctx, mkCheck(t, check.LogMatch, check.Args{Source: "auth", Pattern: "Accepted publickey", Since: since}))
	if !r.Flag || r.Count != 2 || len(r.Paths) != 0 || r.Error != "" {
		t.Fatalf("auth: %+v", r)
	}
	sys.runOut["journalctl --no-pager -q -o cat -n 100000 -u ssh.service --since @"+since] = "Accepted publickey for root\nother\nAccepted publickey for jae\n"
	sys.runOut[journalOldest] = "1791855437.087344 web kernel: Linux version 6.8.0-142-generic\n"
	r = a.runCheck(ctx, mkCheck(t, check.LogMatch, check.Args{Source: "unit:ssh.service", Pattern: "Accepted publickey", Since: since}))
	if r.Count != 2 || r.Capped != "" {
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
	if got, ok := logTime("Dec 31 23:00:00 host x", now, time.UTC); !ok || got.Year() != 2025 {
		t.Fatalf("%v %v", got, ok)
	}
	if got, ok := logTime("2026-01-01T10:00:00+00:00 host x", now, time.UTC); !ok || got.Hour() != 10 {
		t.Fatalf("%v %v", got, ok)
	}
	if _, ok := logTime("garbage", now, time.UTC); ok {
		t.Fatal("garbage read as a time")
	}
	// A traditional time is the machine's own: 20:00 at UTC-7 is 03:00 UTC
	// the next day (round 15, new major 6).
	pdt := time.FixedZone("PDT", -7*3600)
	if got, ok := logTime("Oct  9 20:00:00 db sshd[1]: x", time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), pdt); !ok ||
		!got.Equal(time.Date(2026, 10, 10, 3, 0, 0, 0, time.UTC)) {
		t.Fatalf("at UTC-7: %v %v", got, ok)
	}
}

// journalOldest is the call that finds the journal's oldest entry.
const journalOldest = "journalctl --no-pager -q -o short-unix"

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
	// Another check's file under this check's hash is no file for it: held.
	other := mkCheck(t, check.NewSince, check.Args{What: "keys", Since: since})
	js, _ := json.Marshal(Bundle{Messages: []Message{m1}, Checks: map[string][]byte{c.Hash(): other.Canonical()}})
	if _, err := Intake(filepath.Join(a.StateDir, spoolDir), bytes.NewReader(js)); err != nil {
		t.Fatal(err)
	}
	if res := tick(nil); res.Held == "" || len(res.Hits) != 0 {
		t.Fatalf("another check's file: %+v", res)
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
	if res := tick([]Message{sign(c, "repairer/1 Check a check that reads nothing")}, c); len(res.Hits) != 0 {
		t.Fatalf("a memo that hides what it reads: %+v", res)
	}
	f, _ := a.loadFleet()
	if n := len(f.Skipped); n == 0 || !strings.Contains(f.Skipped[n-1].Why, "its memo isn't what this agent writes") {
		t.Fatalf("skipped: %+v", f.Skipped)
	}
}

// A find that couldn't read part of its places never reads as clean; a
// find over /proc that only met processes ending during its walk does; a
// path is cut to its length and made printable.
func TestHitPartialAndClipped(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.files["/tmp"] = ""
	sys.failOn = "find /tmp"
	r := a.runCheck(ctx, mkCheck(t, check.NewSince, check.Args{What: "setuid", Since: since}))
	if r.Error == "" || r.Flag && r.Error == "" {
		t.Fatalf("an unread place read as clean: %+v", r)
	}
	vanished := "find: '/proc/4242/exe': No such file or directory\n"
	denied := "find: '/proc/1/exe': Permission denied\n"
	for _, c := range []struct {
		o    Output
		want bool
	}{
		{Output{Err: []byte(vanished + vanished)}, true},
		{Output{Err: []byte("/usr/bin/find: '/proc/2/exe': No such file or directory\n")}, true}, // find names itself by its path (seen in hit-e2e run 3)
		{Output{Err: []byte("/usr/bin/find: '/home/x': No such file or directory\n")}, false},
		{Output{Err: []byte("/usr/bin/sh: '/proc/2/exe': No such file or directory\n")}, false},
		{Output{Err: []byte(denied)}, false},
		{Output{Err: []byte(strings.Repeat(vanished, 500) + denied)}, false}, // read whole: an error after many others counts
		{Output{Err: []byte(vanished), ErrCapped: true}, false},              // what was cut off could be anything
		{Output{}, false},
	} {
		if onlyVanished(c.o) != c.want {
			t.Fatalf("onlyVanished(%.60q...) = %v", c.o.Err, !c.want)
		}
	}
	if got := clip("/tmp/a\nb"+strings.Repeat("x", 300), maxHitPath); len(got) != maxHitPath || strings.ContainsRune(got, '\n') {
		t.Fatalf("clip: %q", got)
	}
	var hr HitResult
	hr.add("/tmp/" + strings.Repeat("y", 400))
	if len(hr.Paths[0]) != maxHitPath {
		t.Fatalf("a result's path wasn't clipped: %d bytes", len(hr.Paths[0]))
	}
	// processes that ended while find walked /proc aren't a failure
	sys.failOn = ""
	key := strings.Join([]string{"find", "/proc", "-mindepth", "2", "-maxdepth", "2", "-path", "/proc/[0-9]*/exe", "-lname", "* (deleted)", "-printf", `%l\n`}, " ")
	sys.runErr[key] = vanished
	if r := a.runCheck(ctx, mkCheck(t, check.DeletedExe, check.Args{})); r.Error != "" || r.Flag {
		t.Fatalf("vanished processes: %+v", r)
	}
	sys.runErr[key] = vanished + denied
	if r := a.runCheck(ctx, mkCheck(t, check.DeletedExe, check.Args{})); r.Error == "" {
		t.Fatalf("an unreadable /proc read as clean: %+v", r)
	}
	// a journal read to its cap says so
	sys.runOut["journalctl --no-pager -q -o cat -n 100000 -u ssh.service --since @"+since] = strings.Repeat("line\n", maxJournal)
	if r := a.runCheck(ctx, mkCheck(t, check.LogMatch, check.Args{Source: "unit:ssh.service", Pattern: "x", Since: since})); r.Capped != "lines" {
		t.Fatalf("a journal at its cap: %+v", r)
	}
}

// A check's caps hold while it reads, not after: a file is hashed as it
// streams and stops at the bytes left; a FIFO or link where a package put a
// file is a change, never opened; a program's output stops at the bytes left
// (round 15, new major 4).
func TestHitReadsBounded(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.files["/var/lib/dpkg/info/openssh-server.md5sums"] = md5hex("sshd") + "  usr/sbin/sshd\n" + md5hex("big") + "  usr/lib/big\n" +
		md5hex("helper") + "  usr/lib/openssh/sftp-server\n"
	sys.files["/usr/sbin/sshd"] = "sshd"
	sys.files["/usr/lib/big"] = strings.Repeat("x", 4000)
	sys.special["/usr/lib/openssh/sftp-server"] = "fifo"
	old := HitBytes
	defer func() { HitBytes = old }()
	HitBytes = 1000
	r := a.runCheck(ctx, mkCheck(t, check.PackageFiles, check.Args{Package: "openssh-server"}))
	if r.Capped != "bytes" || r.Count != 0 || sys.read["/usr/lib/big"] > 1000 {
		t.Fatalf("a file past the bytes left: %+v, %d bytes of it read", r, sys.read["/usr/lib/big"])
	}
	HitBytes = 1 << 20
	if r := a.runCheck(ctx, mkCheck(t, check.PackageFiles, check.Args{Package: "openssh-server"})); r.Capped != "" || r.Count != 2 ||
		strings.Join(r.Paths, ",") != "/usr/lib/big,/usr/lib/openssh/sftp-server" {
		t.Fatalf("a FIFO where a file was: %+v", r)
	}
	// The auth log as a FIFO: not clean, and never waited on.
	sys.special["/var/log/auth.log"] = "fifo"
	sys.files["/var/log/auth.log.1"] = "2026-11-05T00:00:00+00:00 web sshd[1]: x\n"
	if r := a.runCheck(ctx, mkCheck(t, check.LogMatch, check.Args{Source: "auth", Pattern: "x", Since: since})); r.Error == "" {
		t.Fatalf("a FIFO for the auth log: %+v", r)
	}
	// A journal printing past the bytes left is killed there.
	HitBytes = 100
	sys.runOut["journalctl --no-pager -q -o cat -n 100000 -u ssh.service --since @"+since] = strings.Repeat("Accepted publickey\n", 20)
	if r := a.runCheck(ctx, mkCheck(t, check.LogMatch, check.Args{Source: "unit:ssh.service", Pattern: "Accepted", Since: since})); r.Capped != "bytes" || r.Count != 5 {
		t.Fatalf("a journal past the bytes left: %+v", r)
	}
}

// package-files also hashes the package's conffiles, which dpkg's md5sums
// leave out, and counts the changed ones apart: they don't flag, as the
// owner's own edits look the same (round 15, minor 5).
func TestHitConffiles(t *testing.T) {
	a, sys, _ := newAgent(t)
	sys.files["/var/lib/dpkg/info/openssh-server.md5sums"] = md5hex("sshd") + "  usr/sbin/sshd\n"
	sys.files["/usr/sbin/sshd"] = "sshd"
	sys.runOut["dpkg-query -W -f ${Conffiles}\n -- openssh-server"] = " /etc/pam.d/sshd " + md5hex("@include common-auth") + "\n" +
		" /etc/ssh/moduli " + md5hex("moduli") + "\n /etc/init.d/ssh " + md5hex("init") + "\n /etc/old " + md5hex("old") + " obsolete\n"
	sys.files["/etc/pam.d/sshd"] = "auth sufficient pam_permit.so"
	sys.files["/etc/ssh/moduli"] = "moduli"
	r := a.runCheck(ctx, mkCheck(t, check.PackageFiles, check.Args{Package: "openssh-server"}))
	if r.Flag || r.Count != 0 || r.Conf != 2 || strings.Join(r.ConfPaths, ",") != "/etc/pam.d/sshd,/etc/init.d/ssh (gone)" || r.Error != "" {
		t.Fatalf("%+v", r)
	}
}

// log-match reads the auth log's rotations, gunzipped, to the first that
// begins before since; when they don't reach back to since, the result says
// so ("history"); a matching line whose time can't be read is counted, and
// said (round 15, new major 6).
func TestHitLogHistory(t *testing.T) {
	a, sys, _ := newAgent(t)
	a.Now = func() time.Time { return time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC) }
	a.Zone = time.UTC
	gz := func(s string) string {
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		z.Write([]byte(s))
		z.Close()
		return b.String()
	}
	const sinceOct = "1791590400" // 2026-10-10 00:00 UTC
	sys.files["/var/log/auth.log"] = "Nov  2 00:00:00 web sshd[9]: Accepted publickey for root\n"
	sys.files["/var/log/auth.log.1"] = "Oct 26 00:00:00 web sshd[8]: Failed password for root\n"
	sys.files["/var/log/auth.log.2.gz"] = gz("Oct 19 00:00:00 web sshd[7]: Failed password for root\n")
	sys.files["/var/log/auth.log.3.gz"] = gz("Oct 12 00:00:00 web sshd[6]: x\nOct 14 03:00:00 web sshd[6]: Accepted publickey for root\n")
	args := check.Args{Source: "auth", Pattern: "Accepted publickey for root", Since: sinceOct}
	r := a.runCheck(ctx, mkCheck(t, check.LogMatch, args))
	if r.Count != 2 || r.Capped != "history" || r.Error != "" {
		t.Fatalf("since before the oldest rotation: %+v", r)
	}
	sys.files["/var/log/auth.log.4.gz"] = gz("Oct  5 00:00:00 web sshd[5]: x\nAccepted publickey for root, at no time it can read\n")
	r = a.runCheck(ctx, mkCheck(t, check.LogMatch, args))
	if r.Count != 3 || r.Untimed != 1 || r.Capped != "" || r.Error != "" {
		t.Fatalf("back to since: %+v", r)
	}
	// Older than since: not read.
	sys.files["/var/log/auth.log.5.gz"] = "not gzip at all"
	if r := a.runCheck(ctx, mkCheck(t, check.LogMatch, args)); r.Count != 3 || r.Error != "" {
		t.Fatalf("read past since: %+v", r)
	}
	// The journal doesn't reach back to since.
	sys.runOut["journalctl --no-pager -q -o cat -n 100000 -u ssh.service --since @"+sinceOct] = "Accepted publickey for root\n"
	sys.runOut[journalOldest] = "1793000000.000001 web kernel: Linux version\n" // 2026-10-26
	if r := a.runCheck(ctx, mkCheck(t, check.LogMatch, check.Args{Source: "unit:ssh.service", Pattern: "Accepted", Since: sinceOct})); r.Capped != "history" || r.Count != 1 {
		t.Fatalf("a journal that starts after since: %+v", r)
	}
	// journalctl's error is reported, what it printed counted (round 15, minor 4).
	sys.runErr["journalctl --no-pager -q -o cat -n 100000 -u ssh.service --since @"+sinceOct] = "Failed to open journal file: Bad message\n"
	if r := a.runCheck(ctx, mkCheck(t, check.LogMatch, check.Args{Source: "unit:ssh.service", Pattern: "Accepted", Since: sinceOct})); r.Error == "" || r.Count != 1 {
		t.Fatalf("journalctl's error: %+v", r)
	}
}

// A line longer than any log line caps the result: what follows it is
// unread (round 15, minor 4).
func TestHitLongLine(t *testing.T) {
	a, sys, _ := newAgent(t)
	a.Now = func() time.Time { return time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC) }
	a.Zone = time.UTC
	sys.files["/var/log/auth.log"] = "2026-11-06T09:00:00+00:00 web x\n" + strings.Repeat("y", maxLine+1) + "\n2026-11-06T09:00:01+00:00 web Accepted\n"
	if r := a.runCheck(ctx, mkCheck(t, check.LogMatch, check.Args{Source: "auth", Pattern: "Accepted", Since: since})); r.Capped != "line length" {
		t.Fatalf("%+v", r)
	}
	key := strings.Join([]string{"find", "/proc", "-mindepth", "2", "-maxdepth", "2", "-path", "/proc/[0-9]*/exe", "-lname", "* (deleted)", "-printf", `%l\n`}, " ")
	sys.runOut[key] = "/tmp/a (deleted)\n" + strings.Repeat("z", maxLine+1) + "\n/tmp/b (deleted)\n"
	if r := a.runCheck(ctx, mkCheck(t, check.DeletedExe, check.Args{})); r.Capped != "line length" {
		t.Fatalf("a program's line: %+v", r)
	}
}

// The owner's Checks are queued as taken, saved with the statement's
// sequence, and run one a tick, after the guards' step, oldest first; one
// the agent stopped in is reported unfinished and never runs again; past
// maxChecks waiting, a Check is skipped (round 15, new major 4, minor 3).
func TestCheckQueue(t *testing.T) {
	a, sys, tick, sign := checkAgent(t)
	key := strings.Join([]string{"find", "/proc", "-mindepth", "2", "-maxdepth", "2", "-path", "/proc/[0-9]*/exe", "-lname", "* (deleted)", "-printf", `%l\n`}, " ")
	sys.files["/root/.ssh"] = ""
	c1 := mkCheck(t, check.DeletedExe, check.Args{})
	c2 := mkCheck(t, check.NewSince, check.Args{What: "keys", Since: since})
	c3 := mkCheck(t, check.NewSince, check.Args{What: "units", Since: since})
	sys.files["/etc/systemd/system"] = ""
	res := tick([]Message{sign(c1, ""), sign(c2, ""), sign(c3, "")}, c1, c2, c3)
	if len(res.Accepted) != 3 || strings.Join(res.Hits, ",") != c1.Name() {
		t.Fatalf("first tick: %+v", res)
	}
	if f, _ := a.loadFleet(); len(f.Checks) != 2 || f.LastSeq != 3 {
		t.Fatalf("the queue: %+v", f.Checks)
	}
	started := false // the queue on disk says c2 started while it runs
	sys.onRun = func(line string) {
		if strings.HasPrefix(line, "find /root/.ssh") {
			f, _ := a.loadFleet()
			started = len(f.Checks) > 0 && !f.Checks[0].Started.IsZero()
		}
	}
	if res := tick(nil); strings.Join(res.Hits, ",") != c2.Name() || !started {
		t.Fatalf("second tick: %+v, marked started %v", res, started)
	}
	sys.onRun = nil
	// The agent stops while c3 runs: the queue says it started.
	f, _ := a.loadFleet()
	f.Checks[0].Started = a.now().UTC()
	if err := a.saveFleet(f); err != nil {
		t.Fatal(err)
	}
	sys.log = nil
	if res := tick(nil); strings.Join(res.Hits, ",") != c3.Name() || len(ran(sys, "find /etc/systemd/system")) != 0 {
		t.Fatalf("a check the agent stopped in ran again: %+v %q", res, sys.log)
	}
	hits, _ := a.loadHits()
	if hits[0].Check != c3.Hash() || !strings.Contains(hits[0].Error, "didn't finish") {
		t.Fatalf("unfinished: %+v", hits[0])
	}
	if f, _ := a.loadFleet(); len(f.Checks) != 0 {
		t.Fatalf("left queued: %+v", f.Checks)
	}
	// A result kept before the agent stopped stands.
	f, _ = a.loadFleet()
	f.Checks = []QueuedCheck{{Seq: 9, File: c1.Canonical(), Started: a.now().UTC().Add(-time.Second)}}
	if err := a.saveFleet(f); err != nil {
		t.Fatal(err)
	}
	if err := a.keepHit(&HitResult{Check: c1.Hash(), Name: c1.Name(), Ran: a.now().UTC(), Count: 1, Flag: true}); err != nil {
		t.Fatal(err)
	}
	tick(nil)
	if hits, _ := a.loadHits(); hits[0].Check != c1.Hash() || hits[0].Error != "" || !hits[0].Flag {
		t.Fatalf("a kept result replaced: %+v", hits[0])
	}
	// Past maxChecks waiting, skipped.
	sys.runOut[key] = ""
	var msgs []Message
	for i := 0; i < maxChecks+1; i++ {
		msgs = append(msgs, sign(c1, ""))
	}
	tick(msgs, c1)
	f, _ = a.loadFleet()
	if len(f.Checks) != maxChecks-1 || !strings.Contains(f.Skipped[len(f.Skipped)-1].Why, "checks wait to run here already") {
		t.Fatalf("the queue's cap: %d queued, %+v", len(f.Checks), f.Skipped)
	}
}
