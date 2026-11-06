package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Timer arms and disarms a guard's undo. The undo runs outside the agent,
// so it fires even if the agent dies halfway through putting a guard on.
type Timer interface {
	Arm(ctx context.Context, hash string, after time.Duration) error
	Disarm(ctx context.Context, hash string) error
}

// SystemdTimer arms the undo as a transient systemd timer that runs
// "repairer-agent undo -if-unconfirmed <hash>".
type SystemdTimer struct {
	Sys      System
	Self     string // the agent's own executable, an absolute path
	StateDir string // absolute
	Root     string // absolute, or ""
}

// undoUnit names a guard's undo units by the guard's whole hash, so no
// other guard can share the name.
func undoUnit(hash string) string { return "repairer-undo-" + hash }

func (t SystemdTimer) Arm(ctx context.Context, hash string, after time.Duration) error {
	if err := safeExecutable(t.Self); err != nil {
		return fmt.Errorf("the undo would run %s as root later: %w", t.Self, err)
	}
	if !filepath.IsAbs(t.StateDir) || (t.Root != "" && !filepath.IsAbs(t.Root)) {
		return fmt.Errorf("the undo needs absolute paths, not %q and %q", t.StateDir, t.Root)
	}
	// A unit left from an earlier timer for this guard (one that failed)
	// would make systemd-run refuse the name.
	t.Sys.Run(ctx, nil, "systemctl", "stop", undoUnit(hash)+".timer")
	t.Sys.Run(ctx, nil, "systemctl", "reset-failed", undoUnit(hash)+".timer", undoUnit(hash)+".service")
	secs := int(after.Round(time.Second) / time.Second)
	if secs < 1 {
		secs = 1
	}
	args := []string{
		"--unit=" + undoUnit(hash),
		fmt.Sprintf("--on-active=%ds", secs),
		"--timer-property=AccuracySec=1s",
		"--description=repairer: take guard " + hash[:12] + " off unless confirmed",
		t.Self, "undo", "-state-dir", t.StateDir,
	}
	if t.Root != "" {
		args = append(args, "-root", t.Root)
	}
	args = append(args, "-if-unconfirmed", hash)
	_, err := t.Sys.Run(ctx, nil, "systemd-run", args...)
	return err
}

func (t SystemdTimer) Disarm(ctx context.Context, hash string) error {
	_, err := t.Sys.Run(ctx, nil, "systemctl", "stop", undoUnit(hash)+".timer")
	if err != nil && !strings.Contains(err.Error(), "not loaded") {
		return err
	}
	// A timer that already fired leaves a finished service behind.
	t.Sys.Run(ctx, nil, "systemctl", "reset-failed", undoUnit(hash)+".service")
	return nil
}

// safeExecutable refuses a program that root would run later unless only
// root can change it: a root-owned file, writable by no one else, in a
// root-owned directory writable by no one else, and not in a temporary
// directory (where `go run` builds and then deletes).
func safeExecutable(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s is not an absolute path", path)
	}
	for _, tmp := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"} {
		if strings.HasPrefix(path, tmp) {
			return fmt.Errorf("it is under %s", tmp)
		}
	}
	if strings.Contains(path, "/go-build") {
		return fmt.Errorf("it is a go run build, which is deleted when go run exits")
	}
	for _, p := range []string{path, filepath.Dir(path)} {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s can be changed by someone other than root", p)
		}
	}
	return nil
}
