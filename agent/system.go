package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jaekwon/autopatch/guard"
)

// System is everything the agent reads from and does to a machine. Linux
// acts on the real one; tests use a fake.
type System interface {
	// Run runs a program, without a shell, and returns its standard output.
	Run(ctx context.Context, stdin []byte, prog string, args ...string) ([]byte, error)
	ReadFile(name string) ([]byte, error)
	// OpenFile opens a regular file to read, never through a link at its
	// last component and never waiting on a FIFO or a device: anything but
	// a regular file is refused with ErrNotRegular (W1, round 15).
	OpenFile(name string) (io.ReadCloser, error)
	// RunCapped runs a program as Run does, keeping at most limit bytes of
	// what it prints: past them it kills the program and says so. What it
	// prints on stderr comes back whole, to maxStderr bytes (W1, round 15).
	RunCapped(ctx context.Context, limit int64, prog string, args ...string) (Output, error)
	// WriteFile replaces a file: temp file, sync, rename.
	WriteFile(name string, data []byte, perm fs.FileMode) error
	// Remove removes a file; a file already gone is not an error.
	Remove(name string) error
	// Stat describes a file, following symlinks.
	Stat(name string) (fs.FileInfo, error)
	// ReadSetting and WriteSetting read and write a kernel setting live, in
	// the agent's own network namespace for net.* settings.
	ReadSetting(name string) (string, error)
	WriteSetting(name, value string) error
	// InUse says what uses a feature, or "" if nothing does. what is
	// "userns", "io_uring", "netns" or "module:<name>".
	InUse(what string) (string, error)
	// ProbeIPOptions checks on loopback that plain TCP connects and that a
	// TCP connection request carrying IPv4 options does not.
	ProbeIPOptions(ctx context.Context) error
	// Info describes the running system.
	Info() (guard.System, error)
	// Module reports whether the running kernel has a loadable module by
	// exactly this name, or has one built in. Aliases are not names.
	Module(name string) (loadable, builtin bool, err error)
	// RemoteAccessPorts are the TCP ports sshd or dropbear listen on.
	RemoteAccessPorts() ([]int, error)
	// EphemeralPorts is the range the machine's own connections use.
	EphemeralPorts() (lo, hi int, err error)
	// FileID describes a file through a handle opened without following
	// symlinks. A path that goes through a symlink anywhere is an error.
	FileID(path string) (FileID, error)
	// ChmodIf sets a file's mode through a handle opened without following
	// symlinks, only if it is still the root-owned regular file want
	// names. It reports whether it changed the mode.
	ChmodIf(path string, want FileID, mode fs.FileMode) (bool, error)
	// SameFile reports whether two paths, following symlinks, are the same
	// file. A path that doesn't exist is the same as nothing.
	SameFile(a, b string) (bool, error)
	// Listening lists TCP and UDP sockets listening on an address other than
	// loopback, with the process that holds each.
	Listening() ([]Listen, error)
	// ListeningAll is every port anything listens on, loopback included, as
	// "tcp/22" and "udp/53".
	ListeningAll() (map[string]bool, error)
}

// FileID is what the agent knows of a file it strips.
type FileID struct {
	Mode    fs.FileMode // permission and setuid, setgid, sticky bits
	Regular bool
	UID     uint32
	Dev     uint64
	Ino     uint64
}

// Linux is the System of a real Linux machine.
type Linux struct {
	// Root prefixes every file path except those under /proc and /sys. It
	// is "" on a real machine; tests set it to a temporary directory.
	Root string

	withLoopback bool // Listening includes loopback (ListeningAll)
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

// progPath finds a program in progDirs.
func progPath(prog string) (string, error) {
	if strings.ContainsRune(prog, '/') {
		return "", fmt.Errorf("run %s: give a program name, not a path", prog)
	}
	for _, d := range progDirs {
		if fi, err := os.Stat(filepath.Join(d, prog)); err == nil && fi.Mode().IsRegular() {
			return filepath.Join(d, prog), nil
		}
	}
	return "", fmt.Errorf("run %s: not found in %s", prog, strings.Join(progDirs, ", "))
}

func (l Linux) Run(ctx context.Context, stdin []byte, prog string, args ...string) ([]byte, error) {
	path, err := progPath(prog)
	if err != nil {
		return nil, err
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

// Output is what a program RunCapped ran printed.
type Output struct {
	Out       []byte // stdout, to the limit
	Err       []byte // stderr, to maxStderr
	OutCapped bool   // stdout reached the limit: the program was killed there
	ErrCapped bool   // stderr went past maxStderr: the rest is dropped
}

// maxStderr is how much of a program's stderr RunCapped keeps.
const maxStderr = 64 << 10

// capWriter keeps what is written to it up to its limit, and calls stop
// once, at the first byte past it.
type capWriter struct {
	buf    bytes.Buffer
	limit  int64
	capped bool
	stop   func()
}

func (w *capWriter) Write(p []byte) (int, error) {
	if left := w.limit - int64(w.buf.Len()); int64(len(p)) > left {
		w.buf.Write(p[:max(left, 0)])
		if !w.capped && w.stop != nil {
			w.stop()
		}
		w.capped = true
		return len(p), nil
	}
	return w.buf.Write(p)
}

func (l Linux) RunCapped(ctx context.Context, limit int64, prog string, args ...string) (Output, error) {
	path, err := progPath(prog)
	if err != nil {
		return Output{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=" + strings.Join(progDirs, ":"), "LC_ALL=C"}
	cmd.WaitDelay = time.Second // a child left holding the pipes can't hold the agent
	out, errw := &capWriter{limit: limit, stop: cancel}, &capWriter{limit: maxStderr}
	cmd.Stdout, cmd.Stderr = out, errw
	err = cmd.Run()
	o := Output{Out: out.buf.Bytes(), Err: errw.buf.Bytes(), OutCapped: out.capped, ErrCapped: errw.capped}
	if err != nil {
		return o, fmt.Errorf("%s: %w", prog, err)
	}
	return o, nil
}

func (l Linux) ReadFile(name string) ([]byte, error) { return os.ReadFile(l.path(name)) }

// ErrNotRegular is OpenFile's refusal of anything but a regular file.
var ErrNotRegular = errors.New("not a regular file")

func (l Linux) OpenFile(name string) (io.ReadCloser, error) {
	p := l.path(name)
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w (%v)", name, ErrNotRegular, fi.Mode().Type())
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() { // swapped since the Lstat
		f.Close()
		return nil, fmt.Errorf("%s: %w", name, ErrNotRegular)
	}
	return f, nil
}

func (l Linux) WriteFile(name string, data []byte, perm fs.FileMode) error {
	return writeAtomic(l.path(name), data, perm)
}

func (l Linux) Stat(name string) (fs.FileInfo, error) { return os.Stat(l.path(name)) }

func (l Linux) Remove(name string) error {
	if err := os.Remove(l.path(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

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
		// The setting is global: anyone in a user namespace uses it.
		return otherNamespace("/proc/1/ns/user", "user", "uses a user namespace")
	case what == "netns":
		// net.* settings live in each network namespace: the agent's write
		// reaches only its own.
		return otherNamespace("/proc/self/ns/net", "net", "lives in another network namespace, which keeps its own net.* settings; the guard's setting covers only the agent's")
	case what == "io_uring":
		return ioUringInUse()
	case strings.HasPrefix(what, "module:"):
		return moduleInUse(strings.TrimPrefix(what, "module:"))
	}
	return "", fmt.Errorf("no in-use check named %q", what)
}

// otherNamespace names a process in a namespace of the given kind other
// than the one at ref.
func otherNamespace(ref, kind, says string) (string, error) {
	refNS, err := os.Readlink(ref)
	if err != nil {
		return "", err
	}
	return scanProcs(func(pid string) string {
		ns, err := os.Readlink("/proc/" + pid + "/ns/" + kind)
		if err == nil && ns != refNS {
			return "process " + pid + " (" + comm(pid) + ") " + says
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
		return "", nil // not loaded
	}
	if err != nil {
		return "", err
	}
	if n, _ := strconv.Atoi(strings.TrimSpace(string(b))); n > 0 {
		return fmt.Sprintf("module %s is loaded and used %d times", name, n), nil
	}
	return "", nil
}

// Module looks the name up in the running kernel's modules.dep and
// modules.builtin, which list modules by file, never by alias.
func (l Linux) Module(name string) (loadable, builtin bool, err error) {
	rel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false, false, err
	}
	dir := "/lib/modules/" + strings.TrimSpace(string(rel))
	want := strings.ReplaceAll(name, "-", "_")
	dep, err := l.ReadFile(dir + "/modules.dep")
	if err != nil {
		return false, false, fmt.Errorf("reading the kernel's module list: %w", err)
	}
	if listsModule(dep, want, true) {
		return true, false, nil
	}
	if b, err := l.ReadFile(dir + "/modules.builtin"); err == nil && listsModule(b, want, false) {
		return false, true, nil
	}
	return false, false, nil
}

// listsModule reports whether a modules.dep (path, a colon, dependencies)
// or modules.builtin (one path a line) lists a module file by this name.
func listsModule(list []byte, want string, dep bool) bool {
	sc := bufio.NewScanner(bytes.NewReader(list))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		p := sc.Text()
		if dep {
			p, _, _ = strings.Cut(p, ":")
		}
		if moduleName(p) == want {
			return true
		}
	}
	return false
}

// moduleName is a module file's name as modprobe knows it:
// kernel/fs/smb/server/ksmbd.ko.zst is ksmbd.
func moduleName(path string) string {
	b := filepath.Base(strings.TrimSpace(path))
	for _, ext := range []string{".zst", ".xz", ".gz"} {
		b = strings.TrimSuffix(b, ext)
	}
	return strings.ReplaceAll(strings.TrimSuffix(b, ".ko"), "-", "_")
}

// RemoteAccessPorts reads the listening TCP sockets and returns the ports
// whose socket belongs to sshd or dropbear.
func (l Linux) RemoteAccessPorts() ([]int, error) {
	listening := map[string]int{} // socket inode to port
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		for inode, port := range listeningSockets(b) {
			listening[inode] = port
		}
	}
	seen := map[int]bool{}
	var ports []int
	_, err := scanProcs(func(pid string) string {
		c := comm(pid)
		if c != "sshd" && c != "dropbear" && !strings.HasPrefix(c, "sshd-") {
			return ""
		}
		fds, err := os.ReadDir("/proc/" + pid + "/fd")
		if err != nil {
			return ""
		}
		for _, fd := range fds {
			t, err := os.Readlink("/proc/" + pid + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(t, "socket:[") {
				continue
			}
			if p, ok := listening[strings.TrimSuffix(strings.TrimPrefix(t, "socket:["), "]")]; ok && !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
		return ""
	})
	return ports, err
}

// Listening reads /proc/net/{tcp,tcp6,udp,udp6} for sockets listening on
// an address other than loopback (TCP in LISTEN, UDP bound and unconnected),
// and names each one's process.
func (l Linux) Listening() ([]Listen, error) {
	type sock struct {
		Listen
		inode string
	}
	var socks []sock
	for _, src := range []struct{ proto, file, state string }{
		{"tcp", "/proc/net/tcp", "0A"}, {"tcp", "/proc/net/tcp6", "0A"},
		{"udp", "/proc/net/udp", "07"}, {"udp", "/proc/net/udp6", "07"},
	} {
		b, err := os.ReadFile(src.file)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 10 || f[3] != src.state {
				continue
			}
			hexAddr, hexPort, ok := strings.Cut(f[1], ":")
			if !ok {
				continue
			}
			addr, ok := procAddr(hexAddr)
			port, err := strconv.ParseUint(hexPort, 16, 16)
			if !ok || err != nil || (addr.IsLoopback() && !l.withLoopback) {
				continue
			}
			socks = append(socks, sock{Listen{Proto: src.proto, Addr: addr.String(), Port: int(port)}, f[9]})
		}
	}
	type proc struct {
		pid  int
		name string
	}
	owner := map[string]proc{}
	scanProcs(func(pid string) string {
		fds, err := os.ReadDir("/proc/" + pid + "/fd")
		if err != nil {
			return ""
		}
		for _, fd := range fds {
			if t, err := os.Readlink("/proc/" + pid + "/fd/" + fd.Name()); err == nil && strings.HasPrefix(t, "socket:[") {
				n, _ := strconv.Atoi(pid)
				owner[strings.TrimSuffix(strings.TrimPrefix(t, "socket:["), "]")] = proc{n, comm(pid)}
			}
		}
		return ""
	})
	seen := map[Listen]bool{}
	var out []Listen
	for _, s := range socks {
		s.Process, s.PID = owner[s.inode].name, owner[s.inode].pid
		if !seen[s.Listen] {
			seen[s.Listen] = true
			out = append(out, s.Listen)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto+out[i].Addr < out[j].Proto+out[j].Addr
	})
	return out, nil
}

// ListeningAll is every listening port, loopback included.
func (l Linux) ListeningAll() (map[string]bool, error) {
	l.withLoopback = true
	ls, err := l.Listening()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, x := range ls {
		out[fmt.Sprintf("%s/%d", x.Proto, x.Port)] = true
	}
	return out, nil
}

// procAddr reads an address as /proc/net writes it: IPv4 as one 32-bit word
// in host (little-endian) order, IPv6 as four such words.
func procAddr(h string) (netip.Addr, bool) {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.Addr{}, false
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	if len(b) == 4 {
		return netip.AddrFrom4([4]byte(b)), true
	}
	return netip.AddrFrom16([16]byte(b)).Unmap(), true
}

// listeningSockets reads /proc/net/tcp or tcp6 and returns each listening
// socket's inode with its port.
func listeningSockets(b []byte) map[string]int {
	out := map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != "0A" { // 0A: TCP_LISTEN
			continue
		}
		_, hexPort, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil {
			continue
		}
		out[f[9]] = int(port)
	}
	return out
}

func (l Linux) EphemeralPorts() (lo, hi int, err error) {
	v, err := l.ReadSetting("net.ipv4.ip_local_port_range")
	if err != nil {
		return 0, 0, err
	}
	f := strings.Fields(v)
	if len(f) != 2 {
		return 0, 0, fmt.Errorf("ip_local_port_range %q", v)
	}
	lo, err1 := strconv.Atoi(f[0])
	hi, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("ip_local_port_range %q", v)
	}
	return lo, hi, nil
}

func (l Linux) SameFile(a, b string) (bool, error) {
	fa, err := os.Stat(l.path(a))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	fb, err := os.Stat(l.path(b))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(fa, fb), nil
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
