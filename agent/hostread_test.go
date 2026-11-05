//go:build hostread

package agent

import (
	"os"
	"slices"
	"testing"
)

// TestHostRead runs the agent's machine checks against the real machine
// they run on. It only reads: run it as root (to see every process's
// sockets) with `go test -tags hostread -run HostRead ./agent`.
func TestHostRead(t *testing.T) {
	l := Linux{}
	if loadable, builtin, err := l.Module("ksmbd"); err != nil || !(loadable || builtin) {
		t.Errorf("ksmbd: loadable %v builtin %v err %v", loadable, builtin, err)
	}
	if loadable, builtin, err := l.Module("net-pf-16-proto-12"); err != nil || loadable || builtin {
		t.Errorf("an alias passed as a module: %v %v %v", loadable, builtin, err)
	}
	lo, hi, err := l.EphemeralPorts()
	if err != nil || lo < 1024 || hi <= lo {
		t.Errorf("ephemeral %d-%d %v", lo, hi, err)
	}
	ports, err := l.RemoteAccessPorts()
	if err != nil || !slices.Contains(ports, 22) {
		t.Errorf("ssh ports %v %v", ports, err)
	}
	t.Logf("ephemeral %d-%d, ssh on %v", lo, hi, ports)
	if fi, err := os.Lstat("/bin"); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		// Merged /usr: /bin/su is /usr/bin/su by another name.
		if same, err := l.SameFile("/bin/su", "/usr/bin/su"); err != nil || !same {
			t.Errorf("/bin/su vs /usr/bin/su: %v %v", same, err)
		}
		if _, err := l.FileID("/bin/su"); err == nil {
			t.Error("FileID followed /bin, a symlink")
		}
	}
	id, err := l.FileID("/usr/bin/su")
	if err != nil || !id.Regular || id.UID != 0 || id.Mode&os.ModeSetuid == 0 {
		t.Errorf("/usr/bin/su: %+v %v", id, err)
	}
}
