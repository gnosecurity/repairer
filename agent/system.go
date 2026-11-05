package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/guard"
)

// System is everything the agent reads from and does to a machine. Linux
// acts on the real one; tests use a fake.
type System interface {
	// Run runs a program, without a shell, and returns its standard output.
	Run(ctx context.Context, stdin []byte, prog string, args ...string) ([]byte, error)
	ReadFile(name string) ([]byte, error)
	// WriteFile replaces a file: temp file, sync, rename.
	WriteFile(name string, data []byte, perm fs.FileMode) error
	// Remove removes a file; a file already gone is not an error.
	Remove(name string) error
	Lstat(name string) (fs.FileInfo, error)
	Chmod(name string, mode fs.FileMode) error
	// ReadSetting and WriteSetting read and write a kernel setting live.
	ReadSetting(name string) (string, error)
	WriteSetting(name, value string) error
	// InUse says what uses a feature, or "" if nothing does. what is
	// "userns", "io_uring" or "module:<name>".
	InUse(what string) (string, error)
	// ProbeIPOptions checks on loopback that plain TCP connects and that a
	// TCP connection request carrying IPv4 options does not.
	ProbeIPOptions(ctx context.Context) error
	// Info describes the running system.
	Info() (guard.System, error)
}

// Linux is the System of a real Linux machine.
type Linux struct {
	// Root prefixes every file path except those under /proc and /sys. It
	// is "" on a real machine; tests set it to a temporary directory.
	Root string
}

// progDirs are where Linux looks for the programs it runs, in order. The
// agent never runs a program found anywhere else.
var progDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

func (l Linux) path(name string) string {
	if strings.HasPrefix(name, "/proc/") || strings.HasPrefix(name, "/sys/") || l.Root == "" {
		return name
	}
	return filepath.Join(l.Root, name)
}

func (l Linux) Run(ctx context.Context, stdin []byte, prog string, args ...string) ([]byte, error) {
	if strings.ContainsRune(prog, '/') {
		return nil, fmt.Errorf("run %s: give a program name, not a path", prog)
	}
	var path string
	for _, d := range progDirs {
		if fi, err := os.Stat(filepath.Join(d, prog)); err == nil && fi.Mode().IsRegular() {
			path = filepath.Join(d, prog)
			break
		}
	}
	if path == "" {
		return nil, fmt.Errorf("run %s: not found in %s", prog, strings.Join(progDirs, ", "))
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=" + strings.Join(progDirs, ":"), "LC_ALL=C"}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 500 {
			msg = msg[:500] + "…"
		}
		return out.Bytes(), fmt.Errorf("%s %s: %w: %s", prog, strings.Join(args, " "), err, msg)
	}
	return out.Bytes(), nil
}

func (l Linux) ReadFile(name string) ([]byte, error) { return os.ReadFile(l.path(name)) }

func (l Linux) WriteFile(name string, data []byte, perm fs.FileMode) error {
	return writeAtomic(l.path(name), data, perm)
}

func (l Linux) Remove(name string) error {
	if err := os.Remove(l.path(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (l Linux) Lstat(name string) (fs.FileInfo, error) { return os.Lstat(l.path(name)) }

func (l Linux) Chmod(name string, mode fs.FileMode) error { return os.Chmod(l.path(name), mode) }

func settingPath(name string) string {
	return "/proc/sys/" + strings.ReplaceAll(name, ".", "/")
}

func (l Linux) ReadSetting(name string) (string, error) {
	b, err := os.ReadFile(settingPath(name))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (l Linux) WriteSetting(name, value string) error {
	f, err := os.OpenFile(settingPath(name), os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(value)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func (l Linux) InUse(what string) (string, error) {
	switch {
	case what == "userns":
		return userNamespacesInUse()
	case what == "io_uring":
		return ioUringInUse()
	case strings.HasPrefix(what, "module:"):
		return moduleInUse(strings.TrimPrefix(what, "module:"))
	}
	return "", fmt.Errorf("no in-use check named %q", what)
}

// userNamespacesInUse names a process living in a user namespace other than
// the first process's.
func userNamespacesInUse() (string, error) {
	initNS, err := os.Readlink("/proc/1/ns/user")
	if err != nil {
		return "", err
	}
	return scanProcs(func(pid string) string {
		ns, err := os.Readlink("/proc/" + pid + "/ns/user")
		if err == nil && ns != initNS {
			return "process " + pid + " (" + comm(pid) + ") uses a user namespace"
		}
		return ""
	})
}

// ioUringInUse names a process holding an io_uring.
func ioUringInUse() (string, error) {
	return scanProcs(func(pid string) string {
		fds, err := os.ReadDir("/proc/" + pid + "/fd")
		if err != nil {
			return ""
		}
		for _, fd := range fds {
			if t, err := os.Readlink("/proc/" + pid + "/fd/" + fd.Name()); err == nil && t == "anon_inode:[io_uring]" {
				return "process " + pid + " (" + comm(pid) + ") uses io_uring"
			}
		}
		return ""
	})
}

func scanProcs(look func(pid string) string) (string, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if found := look(e.Name()); found != "" {
			return found, nil
		}
	}
	return "", nil
}

func comm(pid string) string {
	b, _ := os.ReadFile("/proc/" + pid + "/comm")
	return strings.TrimSpace(string(b))
}

// moduleInUse says whether a loaded module is used by anything.
func moduleInUse(name string) (string, error) {
	dir := "/sys/module/" + strings.ReplaceAll(name, "-", "_")
	b, err := os.ReadFile(dir + "/refcnt")
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil // not loaded, or built in without a count
	}
	if err != nil {
		return "", err
	}
	if n, _ := strconv.Atoi(strings.TrimSpace(string(b))); n > 0 {
		return fmt.Sprintf("module %s is loaded and used %d times", name, n), nil
	}
	return "", nil
}

func (l Linux) Info() (guard.System, error) {
	var s guard.System
	b, err := l.ReadFile("/etc/os-release")
	if err != nil {
		return s, fmt.Errorf("reading /etc/os-release: %w", err)
	}
	s.OS, s.Release = parseOSRelease(b)
	switch s.OS {
	case "ubuntu":
		if sig, err := os.ReadFile("/proc/version_signature"); err == nil {
			s.Kernel, s.Flavour = parseVersionSignature(string(sig))
		}
	case "debian":
		if out, err := l.Run(context.Background(), nil, "uname", "-v"); err == nil {
			s.Kernel = parseDebianUnameV(string(out))
		}
	}
	return s, nil
}

func parseOSRelease(b []byte) (id, version string) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		}
	}
	return id, version
}

// parseVersionSignature reads Ubuntu's /proc/version_signature, such as
// "Ubuntu 6.8.0-142.142-generic 6.8.12", into the running build's version
// and flavour: "6.8.0-142.142" and "generic".
func parseVersionSignature(s string) (kernel, flavour string) {
	f := strings.Fields(s)
	if len(f) < 2 || f[0] != "Ubuntu" {
		return "", ""
	}
	i := strings.LastIndexByte(f[1], '-')
	if i < 0 {
		return "", ""
	}
	kernel, flavour = f[1][:i], f[1][i+1:]
	if !versionRe.MatchString(kernel) || flavour == "" {
		return "", ""
	}
	return kernel, flavour
}

var (
	debianUnameRe = regexp.MustCompile(`\bDebian ([0-9][A-Za-z0-9.+~:-]*)`)
	versionRe     = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~:-]*$`)
)

// parseDebianUnameV reads the package version from Debian's `uname -v`,
// such as "#1 SMP PREEMPT_DYNAMIC Debian 6.1.153-1 (2025-09-20)".
func parseDebianUnameV(s string) string {
	m := debianUnameRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

// writeAtomic writes a file by temp file, sync and rename, then syncs the
// directory, so a crash leaves the old file or the new one, never half.
func writeAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once renamed
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
