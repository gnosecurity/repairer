package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/check"
)

// Was-I-hit checks (W1; AUTOPATCH.md, "Was-I-hit checks"). A check runs
// read-only through the agent's own code and its fixed programs (find,
// dpkg, modinfo, journalctl) with fixed arguments, capped in time, files
// and bytes; its result is a flag, a count and paths from the kind's fixed
// places, never a file's contents or a log line.

// Caps on one check's run.
var (
	HitTime  = 60 * time.Second
	HitFiles = 10000
	HitBytes = int64(64 << 20)
)

// What a result carries: up to maxHitPaths paths of at most maxHitPath
// bytes each, printable, and an error of at most maxHitError bytes; the
// journal is read to at most maxJournal lines.
const (
	maxHitPaths = 100
	maxHitPath  = 256
	maxHitError = 300
	maxJournal  = 100000
)

// plainModule is a kernel module's name as the kernel's own modules are
// named; a loaded module named otherwise is a sign by itself.
var plainModule = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// HitResult is what a check found here.
type HitResult struct {
	Check  string    `json:"check"` // the check's hash
	Name   string    `json:"name"`
	Ran    time.Time `json:"ran"`
	Flag   bool      `json:"flag"`
	Count  int       `json:"count"`
	Paths  []string  `json:"paths,omitempty"`
	Gone   int       `json:"gone,omitempty"`   // package-files: files its md5sums list that are gone
	Capped string    `json:"capped,omitempty"` // the cap that stopped it: a partial answer, not a clean one
	Error  string    `json:"error,omitempty"`  // why it couldn't run
}

func (r *HitResult) add(path string) {
	r.Count++
	if len(r.Paths) < maxHitPaths {
		r.Paths = append(r.Paths, clip(path, maxHitPath))
	}
}

// clip makes s printable and at most n bytes, so a file named to mislead
// can't fill or garble a report.
func clip(s string, n int) string {
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	if len(b) > n {
		return string(b[:n-3]) + "..."
	}
	return string(b)
}

// runCheck answers a check here.
func (a *Agent) runCheck(ctx context.Context, c *check.Check) *HitResult {
	r := &HitResult{Check: c.Hash(), Name: c.Name(), Ran: a.now().UTC()}
	ctx, cancel := context.WithTimeout(ctx, HitTime)
	defer cancel()
	var err error
	switch c.Kind {
	case check.PackageFiles:
		err = a.hitPackageFiles(ctx, c.Args.Package, r)
	case check.DeletedExe:
		err = a.hitDeletedExe(ctx, r)
	case check.NewSince:
		err = a.hitNewSince(ctx, c.Args.What, c.SinceUnix(), r)
	case check.ForeignModules:
		err = a.hitForeignModules(ctx, r)
	case check.LogMatch:
		err = a.hitLogMatch(ctx, c.Args.Source, c.Args.Pattern, c.SinceUnix(), r)
	default:
		err = fmt.Errorf("kind %q isn't one this release runs", c.Kind)
	}
	if ctx.Err() != nil && r.Capped == "" {
		r.Capped = "time"
	}
	if err != nil && r.Capped == "" {
		r.Error = clip(err.Error(), maxHitError)
	}
	r.Flag = r.Count > 0
	return r
}

// hitPackageFiles hashes every file the package's md5sums list and counts
// those that differ; those gone are counted apart (dpkg's path excludes
// remove some on minimal images).
func (a *Agent) hitPackageFiles(ctx context.Context, pkg string, r *HitResult) error {
	sums, err := a.Sys.ReadFile("/var/lib/dpkg/info/" + pkg + ".md5sums")
	if err != nil && !strings.Contains(pkg, ":") {
		arch, aerr := a.Sys.Run(ctx, nil, "dpkg", "--print-architecture")
		if aerr != nil {
			return aerr
		}
		sums, err = a.Sys.ReadFile("/var/lib/dpkg/info/" + pkg + ":" + strings.TrimSpace(string(arch)) + ".md5sums")
	}
	if err != nil {
		return fmt.Errorf("no md5sums for package %s", pkg)
	}
	var read int64
	files := 0
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		sum, path, ok := strings.Cut(sc.Text(), "  ")
		if !ok || len(sum) != 32 || path == "" {
			continue
		}
		if files++; files > HitFiles {
			r.Capped = "files"
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		b, err := a.Sys.ReadFile("/" + path)
		if err != nil {
			r.Gone++
			continue
		}
		if read += int64(len(b)); read > HitBytes {
			r.Capped = "bytes"
			return nil
		}
		got := md5.Sum(b)
		if hex.EncodeToString(got[:]) != strings.ToLower(sum) {
			r.add("/" + path)
		}
	}
	return nil
}

// hitDeletedExe finds processes whose program was deleted or replaced
// after they started.
func (a *Agent) hitDeletedExe(ctx context.Context, r *HitResult) error {
	out, err := a.Sys.Run(ctx, nil, "find", "/proc", "-mindepth", "2", "-maxdepth", "2", "-path", "/proc/[0-9]*/exe",
		"-lname", "* (deleted)", "-printf", `%l\n`)
	if err != nil && !onlyVanished(err) {
		return err // what it found still counts, and the result says it couldn't read all
	}
	seen := map[string]bool{}
	for _, l := range lines(out) {
		p := strings.TrimSuffix(l, " (deleted)")
		if !seen[p] {
			seen[p] = true
			r.add(p)
		}
	}
	return nil
}

// newSinceRoots are where new-since looks, for each what.
var newSinceRoots = map[string][]string{
	"units":  {"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/usr/local/lib/systemd/system"},
	"keys":   {"/root/.ssh", "/home", "/etc/ssh"},
	"cron":   {"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron"},
	"setuid": {"/usr", "/bin", "/sbin", "/opt", "/tmp", "/var/tmp", "/home"},
}

// hitNewSince lists the files under what's places whose status changed
// after since (the inode's change time, which touch can't set back).
func (a *Agent) hitNewSince(ctx context.Context, what string, since int64, r *HitResult) error {
	var paths []string
	var firstErr error
	for _, root := range newSinceRoots[what] {
		if _, err := a.Sys.Stat(root); err != nil {
			continue
		}
		args := []string{root, "-xdev"}
		switch what {
		case "keys":
			if root == "/home" {
				args = append(args, "-maxdepth", "3", "-path", "/home/*/.ssh/*")
			}
		case "setuid":
			args = append(args, "-type", "f", "-perm", "/6000")
		}
		args = append(args, "-newerct", fmt.Sprintf("@%d", since), "-print")
		out, err := a.Sys.Run(ctx, nil, "find", args...)
		paths = append(paths, lines(out)...)
		if err != nil && ctx.Err() == nil && firstErr == nil {
			firstErr = fmt.Errorf("find %s: %w", root, err) // part unread: never a clean answer
		}
		if len(paths) > HitFiles {
			r.Capped = "files"
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		r.add(p)
	}
	return firstErr
}

// onlyVanished says whether find's failure was only processes that ended
// while it walked /proc.
func onlyVanished(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "No such file or directory") && !strings.Contains(msg, "Permission denied")
}

// hitForeignModules lists loaded kernel modules whose file no installed
// package owns, leaving out those DKMS built for the running kernel.
func (a *Agent) hitForeignModules(ctx context.Context, r *HitResult) error {
	mods, err := a.Sys.ReadFile("/proc/modules")
	if err != nil {
		return err
	}
	var names []string
	for _, l := range lines(mods) {
		f := strings.Fields(l)
		switch {
		case len(f) == 0:
		case plainModule.MatchString(f[0]):
			names = append(names, f[0])
		default: // a name no kernel module has: a sign by itself, never an argument
			r.add("/proc/modules: " + f[0])
		}
	}
	if len(names) == 0 {
		return nil
	}
	if len(names) > HitFiles {
		names, r.Capped = names[:HitFiles], "files"
	}
	out, err := a.Sys.Run(ctx, nil, "modinfo", append([]string{"-n", "--"}, names...)...)
	if err != nil && len(out) == 0 {
		return fmt.Errorf("modinfo: %w", err)
	}
	var files []string
	for _, l := range lines(out) {
		if strings.HasPrefix(l, "/") {
			files = append(files, l)
		}
	}
	if len(files) == 0 {
		return nil
	}
	owned := map[string]bool{}
	dout, _ := a.Sys.Run(ctx, nil, "dpkg", append([]string{"-S", "--"}, files...)...) // exits 1 when some path is no package's
	for _, l := range lines(dout) {
		if _, p, ok := strings.Cut(l, ": "); ok {
			for _, q := range strings.Split(p, ", ") {
				owned[q] = true
			}
		}
	}
	dkms := map[string]bool{}
	if ds, err := a.Sys.Run(ctx, nil, "dkms", "status"); err == nil {
		rel := a.running()
		for _, l := range lines(ds) {
			name, rest, ok := strings.Cut(l, ",")
			if ok && strings.Contains(rest, " "+rel+",") && strings.HasSuffix(l, "installed") {
				name, _, _ = strings.Cut(name, "/")
				dkms[strings.ReplaceAll(name, "-", "_")] = true
			}
		}
	}
	for _, f := range files {
		base := f[strings.LastIndex(f, "/")+1:]
		base, _, _ = strings.Cut(base, ".ko")
		if !owned[f] && !dkms[strings.ReplaceAll(base, "-", "_")] {
			r.add(f)
		}
	}
	return nil
}

// hitLogMatch counts the log lines since since that hold pattern: the auth
// log (its file and first rotation), or a unit's journal.
func (a *Agent) hitLogMatch(ctx context.Context, source, pattern string, since int64, r *HitResult) error {
	if unit, ok := strings.CutPrefix(source, "unit:"); ok {
		out, err := a.Sys.Run(ctx, nil, "journalctl", "--no-pager", "-q", "-o", "cat", "-n", strconv.Itoa(maxJournal), "-u", unit, "--since", fmt.Sprintf("@%d", since))
		if err != nil && len(out) == 0 {
			return fmt.Errorf("journalctl: %w", err)
		}
		if int64(len(out)) > HitBytes {
			out, r.Capped = out[:HitBytes], "bytes"
		}
		if ls := lines(out); len(ls) >= maxJournal {
			r.Capped = "lines" // the newest maxJournal lines since since: not every line
		}
		for _, l := range lines(out) {
			if strings.Contains(l, pattern) {
				r.Count++
			}
		}
		return nil
	}
	if source != "auth" {
		return fmt.Errorf("source %q", source)
	}
	after := time.Unix(since, 0).UTC()
	var read int64
	found := false
	for _, f := range []string{"/var/log/auth.log.1", "/var/log/auth.log"} {
		b, err := a.Sys.ReadFile(f)
		if err != nil {
			continue
		}
		found = true
		if read += int64(len(b)); read > HitBytes {
			r.Capped = "bytes"
			break
		}
		for _, l := range lines(b) {
			if !strings.Contains(l, pattern) {
				continue
			}
			if t, ok := logTime(l, a.now()); ok && !t.Before(after) {
				r.Count++
			}
		}
	}
	if !found {
		return errors.New("no auth log here (/var/log/auth.log)")
	}
	return nil
}

// logTime reads a syslog line's time: RFC 3339 (rsyslog's high-precision
// format) or the traditional "Nov  5 16:31:39", whose year is taken as the
// latest that isn't after now.
func logTime(line string, now time.Time) (time.Time, bool) {
	if i := strings.IndexByte(line, ' '); i > 0 {
		if t, err := time.Parse(time.RFC3339Nano, line[:i]); err == nil {
			return t, true
		}
	}
	if len(line) < 15 {
		return time.Time{}, false
	}
	t, err := time.Parse("Jan _2 15:04:05", line[:15])
	if err != nil {
		return time.Time{}, false
	}
	t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, true
}

func lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out
}

const (
	hitsFile = "hits.json" // the newest result of each check run here
	maxHits  = 16
)

// keepHit keeps a check's result, replacing the one before for that check;
// the newest maxHits checks' results are kept.
func (a *Agent) keepHit(r *HitResult) error {
	hits, err := a.loadHits()
	if err != nil {
		return err
	}
	out := []HitResult{*r}
	for _, h := range hits {
		if h.Check != r.Check && len(out) < maxHits {
			out = append(out, h)
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(a.StateDir, hitsFile), b, 0o600)
}

// loadHits reads the kept results, newest first.
func (a *Agent) loadHits() ([]HitResult, error) {
	b, err := os.ReadFile(filepath.Join(a.StateDir, hitsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var hits []HitResult
	return hits, json.Unmarshal(b, &hits)
}
