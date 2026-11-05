//go:build integration

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/nft"
)

type nopTimer struct{}

func (nopTimer) Arm(_ context.Context, _ string, _ time.Duration) error { return nil }
func (nopTimer) Disarm(_ context.Context, _ string) error               { return nil }

// TestIntegrationGuardOne puts guard number one on for real: nftables, the
// kernel setting and the agent's own probe, then takes it off. Run it with
// scripts/netns-test.sh, which gives it a network namespace of its own.
func TestIntegrationGuardOne(t *testing.T) {
	if os.Getenv("AUTOPATCH_NETNS") != "1" {
		t.Skip("run by scripts/netns-test.sh, inside a fresh network namespace")
	}
	root := t.TempDir()
	osr, err := os.ReadFile("/etc/os-release")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), osr, 0o644); err != nil {
		t.Fatal(err)
	}
	sys := Linux{Root: root}
	a := &Agent{Sys: sys, Timer: nopTimer{}, StateDir: t.TempDir()}
	g := guardOne(t)
	table := nft.TableName(g.Hash())

	mptcpBefore, err := sys.ReadSetting("net.mptcp.enabled")
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.ProbeIPOptions(ctx); err == nil || !strings.Contains(err.Error(), "got through") {
		t.Fatalf("before the guard, the probe should get through: %v", err)
	}

	// Force: inside the test's own network namespace, every other process
	// on the host is in "another" one, which the netns check reports.
	e, err := a.Apply(ctx, g, ApplyOptions{ConfirmWithin: 10 * time.Minute, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != Pending || e.Unprobed {
		t.Fatalf("entry %+v", e)
	}
	lt, err := a.liveTable(ctx, "ip", table)
	if err != nil {
		t.Fatal(err)
	}
	if len(lt.Rules) != 1 || lt.Rules[0].Packets < 1 || lt.Hook != "prerouting" || lt.Priority != -300 {
		t.Fatalf("live table %+v", lt)
	}
	t.Logf("the guard's rule stopped %d probe packet(s)", lt.Rules[0].Packets)
	if v, _ := sys.ReadSetting("net.mptcp.enabled"); v != "0" {
		t.Fatalf("mptcp %q", v)
	}
	if _, err := a.Confirm(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(root, SysctlFile)); err != nil || !strings.Contains(string(b), "net.mptcp.enabled = 0") {
		t.Fatalf("sysctl file %q %v", b, err)
	}
	if d, err := a.Check(ctx, false); err != nil || len(d) != 0 {
		t.Fatalf("drift %+v %v", d, err)
	}

	// A firewall flush, as `nft flush ruleset` or a reload of
	// nftables.service would do: check finds it and puts it back.
	if _, err := sys.Run(ctx, nil, "nft", "flush", "ruleset"); err != nil {
		t.Fatal(err)
	}
	if d, err := a.Check(ctx, true); err != nil || len(d) != 1 || !d[0].Repaired {
		t.Fatalf("repair %+v %v", d, err)
	}

	if _, err := a.Undo(ctx, g.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := a.liveTable(ctx, "ip", table); err == nil {
		t.Fatal("table still there after undo")
	}
	if v, _ := sys.ReadSetting("net.mptcp.enabled"); v != mptcpBefore {
		t.Fatalf("mptcp %q, was %q", v, mptcpBefore)
	}
	if _, err := os.Stat(filepath.Join(root, SysctlFile)); err == nil {
		t.Fatal("sysctl file left behind")
	}
	if err := sys.ProbeIPOptions(ctx); err == nil || !strings.Contains(err.Error(), "got through") {
		t.Fatalf("after undo, the probe should get through again: %v", err)
	}
}
