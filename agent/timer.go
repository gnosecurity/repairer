package agent

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Timer arms and disarms a guard's undo. The undo runs outside the agent,
// so it fires even if the agent dies halfway through putting a guard on.
type Timer interface {
	Arm(ctx context.Context, hash string, after time.Duration) error
	Disarm(ctx context.Context, hash string) error
}

// SystemdTimer arms the undo as a transient systemd timer that runs
// "autopatch-agent undo -if-unconfirmed <hash>".
type SystemdTimer struct {
	Sys      System
	Self     string // the agent's own executable
	StateDir string
	Root     string
}

func undoUnit(hash string) string { return "autopatch-undo-" + hash[:12] }

func (t SystemdTimer) Arm(ctx context.Context, hash string, after time.Duration) error {
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
		"--description=autopatch: take guard " + hash[:12] + " off unless confirmed",
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
