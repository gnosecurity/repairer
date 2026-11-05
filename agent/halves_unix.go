//go:build unix

package agent

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// SetupHalves gives the unprivileged half what it needs and nothing more:
// it may pass through the state directory (0711), write the spool (its own,
// 0700), and read the signed report (out/, group-readable, setgid so each
// new report keeps the group). Everything else stays root's alone.
func SetupHalves(stateDir, name string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return err
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("user %s: ids %q %q", name, u.Uid, u.Gid)
	}
	if uid == 0 {
		return fmt.Errorf("the intake user must not be root")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(stateDir, 0o711); err != nil {
		return err
	}
	spool := filepath.Join(stateDir, spoolDir)
	if err := os.MkdirAll(spool, 0o700); err != nil {
		return err
	}
	if err := os.Lchown(spool, uid, gid); err != nil {
		return err
	}
	if err := os.Chmod(spool, 0o700); err != nil {
		return err
	}
	out := filepath.Join(stateDir, OutDir)
	if err := os.MkdirAll(out, 0o750); err != nil {
		return err
	}
	if err := os.Lchown(out, os.Geteuid(), gid); err != nil {
		return err
	}
	return os.Chmod(out, 0o750|os.ModeSetgid)
}
