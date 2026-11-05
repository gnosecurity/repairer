package agent

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
// dpkg, dpkg-query, modinfo, dkms, journalctl) with fixed arguments, capped
// in time, files and bytes. Files are read as they stream, never through a
// link at their last component nor from a FIFO or device, and a program's
// output stops at the bytes left, the program killed there (round 15, new
// major 4). Its result is a flag, a count and paths from the kind's fixed
// places, never a file's contents or a log line.

// Caps on one check's run.
var (
	HitTime  = 60 * time.Second
	HitFiles = 10000
	HitBytes = int64(64 << 20)
)

// What a result carries: up to maxHitPaths paths of at most maxHitPath
// bytes each, printable, and an error of at most maxHitError bytes; the
// journal is read to at most maxJournal lines, a line to maxLine bytes, and
// the auth log's rotations to auth.log.<maxRotation>.gz.
const (
	maxHitPaths = 100
	maxHitPath  = 256
	maxHitError = 300
	maxJournal  = 100000
	maxLine     = 1 << 20
	maxRotation = 52
)

// plainModule is a kernel module's name as the kernel's own modules are
// named; a loaded module named otherwise is a sign by itself.
var plainModule = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// HitResult is what a check found here.
type HitResult struct {
	Check string    `json:"check"` // the check's hash
	Name  string    `json:"name"`
	Ran   time.Time `json:"ran"`
	Flag  bool      `json:"flag"`
	Count int       `json:"count"`
	Paths []string  `json:"paths,omitempty"`
	Gone  int       `json:"gone,omitempty"` // package-files: files its md5sums list that are gone
	// Conf counts package-files' configuration files (dpkg's conffiles)
	// changed since the package put them, apart from Count, as an owner's
	// own edits look the same; ConfPaths names them (round 15, minor 5).
	Conf      int      `json:"conf,omitempty"`
	ConfPaths []string `json:"conf_paths,omitempty"`
	// Untimed counts log-match's matching lines whose time couldn't be
	// read: they are counted, as they may be since (round 15, new major 6).
	Untimed int    `json:"untimed,omitempty"`
	Capped  string `json:"capped,omitempty"` // the cap that stopped it: a partial answer, not a clean one
	Error   string `json:"error,omitempty"`  // why it couldn't run
}

func (r *HitResult) add(path string) {
	r.Count++
	if len(r.Paths) < maxHitPaths {
		r.Paths = append(r.Paths, clip(path, maxHitPath))
	}
}

func (r *HitResult) addConf(path string) {
	r.Conf++
	if len(r.ConfPaths) < maxHitPaths {
		r.ConfPaths = append(r.ConfPaths, clip(path, maxHitPath))
	}
}

// cap marks the result stopped at a cap, the first one met.
func (r *HitResult) cap(why string) {
	if r.Capped == "" {
		r.Capped = why
	}
}

// lines reads a program's output into lines; a line past maxLine caps the
// result, as what follows it is unread (round 15, minor 4).
func (r *HitResult) lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	if sc.Err() != nil {
		r.cap("line length")
	}
	return out
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

// hitBudget is what is left of one check's caps on bytes and files.
type hitBudget struct {
	bytes int64
	files int
}

// took counts n bytes read; past the cap it marks the result and says no.
func (b *hitBudget) took(n int64, r *HitResult) bool {
	if b.bytes -= n; b.bytes < 0 {
		r.cap("bytes")
		return false
	}
	return true
}

// file counts one file; past the cap it marks the result and says no.
func (b *hitBudget) file(r *HitResult) bool {
	if b.files--; b.files < 0 {
		r.cap("files")
		return false
	}
	return true
}

// left is what a program may still print.
func (b *hitBudget) left() int64 { return max(b.bytes, 0) }

// ctxReader ends a read at the check's deadline, between chunks of at most
// a megabyte.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > 1<<20 {
		p = p[:1<<20]
	}
	return c.r.Read(p)
}

// countReader counts the bytes read through it.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// errCapped ends a kind's walk at a cap the result already names.
var errCapped = errors.New("capped")

// readFile reads a regular file whole, within the budget: past it, the
// part read comes back and the result is capped.
func (a *Agent) readFile(ctx context.Context, b *hitBudget, name string, r *HitResult) ([]byte, error) {
	f, err := a.Sys.OpenFile(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	left := b.left()
	data, err := io.ReadAll(ctxReader{ctx, io.LimitReader(f, left+1)})
	if int64(len(data)) > left { // more than is left: what fits, and the cap
		b.took(int64(len(data)), r)
		return data[:left], nil
	}
	b.took(int64(len(data)), r)
	return data, err
}

// hashFile hashes a regular file as it streams, within the budget.
func (a *Agent) hashFile(ctx context.Context, b *hitBudget, name string, r *HitResult) (string, error) {
	f, err := a.Sys.OpenFile(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	n, err := io.Copy(h, ctxReader{ctx, io.LimitReader(f, b.left()+1)})
	if !b.took(n, r) {
		return "", errCapped
	}
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// runCheck answers a check here.
func (a *Agent) runCheck(ctx context.Context, c *check.Check) *HitResult {
	r := &HitResult{Check: c.Hash(), Name: c.Name(), Ran: a.now().UTC()}
	ctx, cancel := context.WithTimeout(ctx, HitTime)
	defer cancel()
	b := &hitBudget{bytes: HitBytes, files: HitFiles}
	var err error
	switch c.Kind {
	case check.PackageFiles:
		err = a.hitPackageFiles(ctx, b, c.Args.Package, r)
	case check.DeletedExe:
		err = a.hitDeletedExe(ctx, b, r)
	case check.NewSince:
		err = a.hitNewSince(ctx, b, c.Args.What, c.SinceUnix(), r)
	case check.ForeignModules:
		err = a.hitForeignModules(ctx, b, r)
	case check.LogMatch:
		err = a.hitLogMatch(ctx, b, c.Args.Source, c.Args.Pattern, c.SinceUnix(), r)
	default:
		err = fmt.Errorf("kind %q isn't one this release runs", c.Kind)
	}
	if ctx.Err() != nil {
		r.cap("time")
	}
	if errors.Is(err, errCapped) {
		err = nil
	}
	if err != nil && r.Capped == "" {
		r.Error = clip(err.Error(), maxHitError)
	}
	r.Flag = r.Count > 0
	return r
}

// hitPackageFiles hashes every file the package's md5sums list and counts
// those that differ, a link, FIFO or device where the package put a file
// among them; those gone are counted apart (dpkg's path excludes remove
// some on minimal images), and so are its changed conffiles, which dpkg's
// md5sums leave out (round 15, minor 5).
func (a *Agent) hitPackageFiles(ctx context.Context, b *hitBudget, pkg string, r *HitResult) error {
	name := pkg
	sums, err := a.readFile(ctx, b, "/var/lib/dpkg/info/"+pkg+".md5sums", r)
	if errors.Is(err, fs.ErrNotExist) && !strings.Contains(pkg, ":") {
		arch, aerr := a.Sys.RunCapped(ctx, 64, "dpkg", "--print-architecture")
		if aerr != nil {
			return aerr
		}
		name = pkg + ":" + strings.TrimSpace(string(arch.Out))
		sums, err = a.readFile(ctx, b, "/var/lib/dpkg/info/"+name+".md5sums", r)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("no md5sums for package %s", pkg)
	}
	if err != nil {
		return err
	}
	var firstErr error
	for _, l := range r.lines(sums) {
		sum, path, ok := strings.Cut(l, "  ")
		if !ok || len(sum) != 32 || path == "" {
			continue
		}
		if !b.file(r) || ctx.Err() != nil {
			return firstErr
		}
		got, err := a.hashFile(ctx, b, "/"+path, r)
		switch {
		case errors.Is(err, errCapped) || ctx.Err() != nil:
			return firstErr
		case errors.Is(err, fs.ErrNotExist):
			r.Gone++
		case errors.Is(err, ErrNotRegular):
			r.add("/" + path)
		case err != nil:
			if firstErr == nil {
				firstErr = err // part unread: never a clean answer
			}
		case got != strings.ToLower(sum):
			r.add("/" + path)
		}
	}
	if r.Capped != "" {
		return firstErr
	}
	// The conffiles, as dpkg-query lists them: " <path> <md5>[ obsolete]".
	o, err := a.Sys.RunCapped(ctx, min(b.left(), 1<<20), "dpkg-query", "-W", "-f", "${Conffiles}\n", "--", name)
	if o.OutCapped {
		r.cap("bytes")
		return firstErr
	}
	if err != nil {
		return errors.Join(firstErr, fmt.Errorf("dpkg-query: %w: %s", err, firstLine(o.Err)))
	}
	for _, l := range r.lines(o.Out) {
		f := strings.Fields(l)
		if len(f) < 2 || len(f[1]) != 32 || len(f) > 2 && f[2] == "obsolete" {
			continue
		}
		if !b.file(r) || ctx.Err() != nil {
			return firstErr
		}
		got, err := a.hashFile(ctx, b, f[0], r)
		switch {
		case errors.Is(err, errCapped) || ctx.Err() != nil:
			return firstErr
		case errors.Is(err, fs.ErrNotExist):
			r.addConf(f[0] + " (gone)")
		case errors.Is(err, ErrNotRegular):
			r.addConf(f[0])
		case err != nil:
			if firstErr == nil {
				firstErr = err
			}
		case got != strings.ToLower(f[1]):
			r.addConf(f[0])
		}
	}
	return firstErr
}

// firstLine is a program's first line of errors, for a result's error.
func firstLine(b []byte) string {
	l, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return l
}

// hitDeletedExe finds processes whose program was deleted or replaced
// after they started.
func (a *Agent) hitDeletedExe(ctx context.Context, b *hitBudget, r *HitResult) error {
	o, err := a.Sys.RunCapped(ctx, b.left(), "find", "/proc", "-mindepth", "2", "-maxdepth", "2", "-path", "/proc/[0-9]*/exe",
		"-lname", "* (deleted)", "-printf", `%l\n`)
	b.took(int64(len(o.Out)), r)
	if o.OutCapped {
		r.cap("bytes")
	}
	seen := map[string]bool{}
	for _, l := range r.lines(o.Out) {
		p := strings.TrimSuffix(l, " (deleted)")
		if !seen[p] {
			seen[p] = true
			r.add(p)
		}
	}
	if err != nil && !o.OutCapped && ctx.Err() == nil && !onlyVanished(o) {
		return fmt.Errorf("find /proc: %w: %s", err, firstLine(o.Err)) // what it found still counts, and the result says it couldn't read all
	}
	return nil
}

// newSinceRoots are where new-since looks, for each what.
var newSinceRoots = map[string][]string{
	"units":  {"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/usr/local/lib/systemd/system"},
	"keys":   {"/root/.ssh", "/home", "/etc/ssh"},
	"cron":   {"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron"},
	"setuid": {"/usr", "/bin", "/sbin", "/opt", "/etc", "/root", "/home", "/srv", "/var", "/var/tmp", "/tmp", "/dev/shm"},
}

// hitNewSince lists the files under what's places whose status changed
// after since (the inode's change time, which touch can't set back).
func (a *Agent) hitNewSince(ctx context.Context, b *hitBudget, what string, since int64, r *HitResult) error {
	seen := map[string]bool{}
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
		o, err := a.Sys.RunCapped(ctx, b.left(), "find", args...)
		b.took(int64(len(o.Out)), r)
		if o.OutCapped {
			r.cap("bytes")
		}
		for _, p := range r.lines(o.Out) {
			if !seen[p] { // a place inside another, on the same filesystem
				seen[p] = true
				paths = append(paths, p)
			}
		}
		if err != nil && ctx.Err() == nil && !o.OutCapped && firstErr == nil {
			firstErr = fmt.Errorf("find %s: %w: %s", root, err, firstLine(o.Err)) // part unread: never a clean answer
		}
		if len(paths) > HitFiles {
			r.cap("files")
		}
		if r.Capped != "" || ctx.Err() != nil {
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
// while it walked /proc: its errors, read whole, each say so of a path in
// /proc (round 15, minor 4). find names itself as it was run, by its path:
// "/usr/bin/find: '/proc/2/exe': No such file or directory".
func onlyVanished(o Output) bool {
	if o.ErrCapped {
		return false
	}
	ls := lines(o.Err)
	for _, l := range ls {
		prog, rest, _ := strings.Cut(l, ": ")
		if filepath.Base(prog) != "find" || !strings.HasPrefix(rest, "'/proc/") || !strings.HasSuffix(rest, "': No such file or directory") {
			return false
		}
	}
	return len(ls) > 0
}

// hitForeignModules lists loaded kernel modules that don't come from an
// installed package, nor from DKMS for the running kernel. modinfo is asked
// of each module alone: one it can't find is foreign; one loaded unsigned
// (taint E) is foreign unless DKMS built it here and its file is DKMS's; one
// loaded out of tree (taint O) whose file is in tree isn't that file; the
// rest are foreign unless dpkg owns their file or DKMS built it (round 15,
// new major 5). A module loaded under a DKMS module's own name, from
// elsewhere, can't be told apart: a limit the plan says.
func (a *Agent) hitForeignModules(ctx context.Context, b *hitBudget, r *HitResult) error {
	mods, err := a.readFile(ctx, b, "/proc/modules", r)
	if err != nil {
		return err
	}
	rel := a.running()
	dkms := map[string]bool{}
	if o, err := a.Sys.RunCapped(ctx, 1<<20, "dkms", "status"); err == nil {
		for _, l := range lines(o.Out) {
			name, rest, ok := strings.Cut(l, ",")
			if ok && strings.Contains(rest, " "+rel+",") && strings.HasSuffix(l, "installed") {
				name, _, _ = strings.Cut(name, "/")
				dkms[strings.ReplaceAll(name, "-", "_")] = true
			}
		}
	}
	fromDKMS := func(name, file string) bool {
		return dkms[strings.ReplaceAll(name, "-", "_")] &&
			(strings.HasPrefix(file, "/lib/modules/"+rel+"/updates/dkms/") || strings.HasPrefix(file, "/usr/lib/modules/"+rel+"/updates/dkms/"))
	}
	var files []string
	for _, l := range r.lines(mods) {
		f := strings.Fields(l)
		switch {
		case len(f) == 0:
			continue
		case !plainModule.MatchString(f[0]): // a name no kernel module has: a sign by itself, never an argument
			r.add("/proc/modules: " + f[0])
			continue
		}
		if !b.file(r) || ctx.Err() != nil {
			return nil
		}
		name, taint := f[0], ""
		if t := f[len(f)-1]; len(f) > 6 && strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
			taint = strings.Trim(t, "()")
		}
		o, err := a.Sys.RunCapped(ctx, 64<<10, "modinfo", "--", name)
		file, intree := modinfoFile(o.Out)
		switch {
		case file == "" && err != nil && bytes.Contains(o.Err, []byte("not found")):
			r.add("/proc/modules: " + name + " (no module file)")
		case file == "" && err != nil:
			return fmt.Errorf("modinfo %s: %w: %s", name, err, firstLine(o.Err))
		case file == "" || file == "(builtin)":
			r.add("/proc/modules: " + name + " (no module file)")
		case strings.Contains(taint, "E") && !fromDKMS(name, file):
			r.add(file + " (" + name + " loaded unsigned)")
		case strings.Contains(taint, "O") && intree:
			r.add(file + " (" + name + " loaded out of tree; this file is in tree)")
		case fromDKMS(name, file):
		default:
			files = append(files, file)
		}
	}
	if len(files) == 0 {
		return nil
	}
	o, _ := a.Sys.RunCapped(ctx, b.left(), "dpkg", append([]string{"-S", "--"}, files...)...) // exits 1 when some path is no package's
	if !b.took(int64(len(o.Out)), r) || o.OutCapped {
		r.cap("bytes")
		return nil
	}
	owned := map[string]bool{}
	for _, l := range r.lines(o.Out) {
		if _, p, ok := strings.Cut(l, ": "); ok {
			for _, q := range strings.Split(p, ", ") {
				owned[q] = true
			}
		}
	}
	for _, f := range files {
		if !owned[f] {
			r.add(f)
		}
	}
	return nil
}

// modinfoFile reads the first module modinfo describes: its file, and
// whether it was built in the kernel's tree.
func modinfoFile(out []byte) (file string, intree bool) {
	for _, l := range lines(out) {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch v = strings.TrimSpace(v); strings.TrimSpace(k) {
		case "filename":
			if file != "" {
				return file, intree // the next module's
			}
			file = v
		case "intree":
			intree = v == "Y"
		}
	}
	return file, intree
}

// hitLogMatch counts the log lines since since that hold pattern: the auth
// log, or a unit's journal.
func (a *Agent) hitLogMatch(ctx context.Context, b *hitBudget, source, pattern string, since int64, r *HitResult) error {
	if unit, ok := strings.CutPrefix(source, "unit:"); ok {
		return a.hitJournal(ctx, b, unit, pattern, since, r)
	}
	if source != "auth" {
		return fmt.Errorf("source %q", source)
	}
	// The auth log and its rotations, newest first, to the first that
	// begins at or before since (round 15, new major 6).
	after := time.Unix(since, 0)
	names := []string{"/var/log/auth.log", "/var/log/auth.log.1"}
	for n := 2; n <= maxRotation; n++ {
		names = append(names, fmt.Sprintf("/var/log/auth.log.%d.gz", n))
	}
	var oldest time.Time
	var firstErr error
	found := false
	for i, name := range names {
		first, err := a.scanLog(ctx, b, name, pattern, after, r)
		if errors.Is(err, fs.ErrNotExist) {
			if i >= 2 {
				break // the rotations end
			}
			continue
		}
		found = true
		if err != nil && firstErr == nil {
			firstErr = err // part unread: never a clean answer
		}
		if !first.IsZero() && (oldest.IsZero() || first.Before(oldest)) {
			oldest = first
		}
		if r.Capped != "" || ctx.Err() != nil || !first.IsZero() && !first.After(after) {
			break // what is older is before since, or past a cap
		}
	}
	if !found {
		return errors.New("no auth log here (/var/log/auth.log)")
	}
	if r.Capped == "" && ctx.Err() == nil && (oldest.IsZero() || oldest.After(after)) {
		r.cap("history") // the logs here don't reach back to since
	}
	return firstErr
}

// scanLog counts one auth log file's lines holding pattern since after,
// reading it as it streams (gunzipped when its name ends .gz) within the
// budget; a matching line whose time can't be read counts, as it may be
// since. It says the file's first time read: its oldest.
func (a *Agent) scanLog(ctx context.Context, b *hitBudget, name, pattern string, after time.Time, r *HitResult) (time.Time, error) {
	f, err := a.Sys.OpenFile(name)
	if err != nil {
		return time.Time{}, err
	}
	defer f.Close()
	var in io.Reader = f
	if strings.HasSuffix(name, ".gz") {
		z, err := gzip.NewReader(ctxReader{ctx, f})
		if err != nil {
			return time.Time{}, fmt.Errorf("%s: %w", name, err)
		}
		defer z.Close()
		in = z
	}
	cr := &countReader{r: ctxReader{ctx, io.LimitReader(in, b.left()+1)}}
	sc := bufio.NewScanner(cr)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	now, zone := a.now(), a.zone()
	var first time.Time
	for sc.Scan() {
		l := sc.Text()
		t, ok := time.Time{}, false
		if first.IsZero() {
			if t, ok = logTime(l, now, zone); ok {
				first = t
			}
		}
		if !strings.Contains(l, pattern) {
			continue
		}
		if !ok {
			t, ok = logTime(l, now, zone)
		}
		switch {
		case !ok:
			r.Count++
			r.Untimed++
		case !t.Before(after):
			r.Count++
		}
	}
	if !b.took(cr.n, r) || ctx.Err() != nil {
		return first, nil
	}
	if err := sc.Err(); errors.Is(err, bufio.ErrTooLong) {
		r.cap("line length")
	} else if err != nil {
		return first, fmt.Errorf("%s: %w", name, err)
	}
	return first, nil
}

// hitJournal counts a unit's journal lines since since that hold pattern,
// and says when the journal doesn't reach back to since (round 15, new
// major 6).
func (a *Agent) hitJournal(ctx context.Context, b *hitBudget, unit, pattern string, since int64, r *HitResult) error {
	o, err := a.Sys.RunCapped(ctx, b.left(), "journalctl", "--no-pager", "-q", "-o", "cat", "-n", strconv.Itoa(maxJournal), "-u", unit, "--since", fmt.Sprintf("@%d", since))
	b.took(int64(len(o.Out)), r)
	if o.OutCapped {
		r.cap("bytes")
	}
	ls := r.lines(o.Out)
	if len(ls) >= maxJournal {
		r.cap("lines") // the newest maxJournal lines since since: not every line
	}
	for _, l := range ls {
		if strings.Contains(l, pattern) {
			r.Count++
		}
	}
	if err != nil && !o.OutCapped && ctx.Err() == nil {
		return fmt.Errorf("journalctl: %w: %s", err, firstLine(o.Err)) // reported, what it read counted (round 15, minor 4)
	}
	if r.Capped != "" || ctx.Err() != nil {
		return nil
	}
	// The journal's oldest entry, its first line: killed once it printed it.
	h, _ := a.Sys.RunCapped(ctx, 4096, "journalctl", "--no-pager", "-q", "-o", "short-unix")
	if oldest, ok := journalTime(h.Out); !ok || oldest > since {
		r.cap("history")
	}
	return nil
}

// journalTime reads the time of journalctl's first short-unix line.
func journalTime(out []byte) (int64, bool) {
	l, _, _ := strings.Cut(string(out), "\n")
	secs, _, _ := strings.Cut(strings.TrimSpace(l), ".")
	n, err := strconv.ParseInt(secs, 10, 64)
	return n, err == nil && n > 0
}

// zone is the machine's own time zone, which syslog's traditional time is
// written in.
func (a *Agent) zone() *time.Location {
	if a.Zone != nil {
		return a.Zone
	}
	return time.Local
}

// logTime reads a syslog line's time: RFC 3339 (rsyslog's high-precision
// format) or the traditional "Nov  5 16:31:39", written in the machine's
// zone, whose year is taken as the latest that isn't after now.
func logTime(line string, now time.Time, zone *time.Location) (time.Time, bool) {
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
	n := now.In(zone)
	t = time.Date(n.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, zone)
	if t.After(n.Add(24 * time.Hour)) {
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

// runQueued runs the oldest queued Check, and says its name. It is marked
// started, on disk, before it runs: one found started is one the agent
// stopped in (killed, or the machine down), reported unfinished unless its
// result was kept, and never run again.
func (a *Agent) runQueued(ctx context.Context, f *Fleet) (string, error) {
	if len(f.Checks) == 0 {
		return "", nil
	}
	q := &f.Checks[0]
	c, err := check.Parse(q.File)
	if err != nil { // read when taken: a file this release can't read again
		f.Checks = f.Checks[1:]
		return "", errors.Join(fmt.Errorf("statement %d's check file: %w", q.Seq, err), a.saveFleet(f))
	}
	if !q.Started.IsZero() {
		if !a.hitKept(c.Hash(), q.Started) {
			r := &HitResult{Check: c.Hash(), Name: c.Name(), Ran: q.Started,
				Error: "it didn't finish: the agent stopped while it ran, so it won't run again unless you sign another Check"}
			if err := a.keepHit(r); err != nil {
				return "", err
			}
		}
		f.Checks = f.Checks[1:]
		return c.Name(), a.saveFleet(f)
	}
	q.Started = a.now().UTC()
	if err := a.saveFleet(f); err != nil {
		return "", err
	}
	if err := a.keepHit(a.runCheck(ctx, c)); err != nil {
		return "", err // kept started: reported unfinished at the next tick
	}
	f.Checks = f.Checks[1:]
	return c.Name(), a.saveFleet(f)
}

// hitKept says whether a result of the check was kept since a time.
func (a *Agent) hitKept(hash string, since time.Time) bool {
	hits, _ := a.loadHits()
	for _, h := range hits {
		if h.Check == hash && !h.Ran.Before(since) {
			return true
		}
	}
	return false
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
