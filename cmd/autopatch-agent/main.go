// Command autopatch-agent puts guards (stopgaps written as data) on this
// machine and takes them off.
//
//	autopatch-agent fmt     GUARD.json   print the guard in the canonical form the agent accepts
//	autopatch-agent plan    GUARD.json   what the guard would do here; changes nothing
//	autopatch-agent apply   GUARD.json   put it on, pending, with its undo armed
//	autopatch-agent confirm HASH|ID      keep it on across reboots
//	autopatch-agent undo    HASH|ID      take it off
//	autopatch-agent status               the guards on, and what they stopped
//	autopatch-agent report               this machine's facts for the lookout, as JSON
//	autopatch-agent gates                whether this machine can reboot into its newest kernel
//	autopatch-agent check                compare live state with what was set
//	autopatch-agent boot                 at boot: drop the unconfirmed, restore the rest
//	autopatch-agent install              write and turn on the boot unit, firewall unit and check timer
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jaekwon/autopatch/agent"
	"github.com/jaekwon/autopatch/guard"
)

const usage = `usage: autopatch-agent <command> [flags] [args]

  fmt     GUARD.json   print the guard in canonical form, the only form apply accepts
  plan    GUARD.json   what the guard would do here; changes nothing
  apply   GUARD.json   put it on, pending; -confirm-within 10m (0: confirm once its probe passes)
  confirm HASH|ID      keep a pending guard on, across reboots
  undo    HASH|ID      take a guard off (-if-unconfirmed: only if not confirmed)
  status               the guards on this machine, and the packets they stopped
  report               this machine's facts for the lookout, as JSON (reads only)
  gates                whether this machine can reboot into its newest kernel and come back (reads only)
  check                compare live state with what the guards set (-repair: put it back)
  boot                 at boot: take off what was never confirmed, put back what was
  install              write and turn on the boot unit, the firewall unit and the check timer

Every command takes -state-dir (default /var/lib/autopatch).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(context.Background(), os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "autopatch-agent:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/var/lib/autopatch", "where the agent keeps its state")
	root := fs.String("root", "", "prefix for files the agent writes (tests only)")
	within := fs.Duration("confirm-within", 10*time.Minute, "apply: how long until the undo runs unless confirmed")
	force := fs.Bool("force", false, "apply: put blocks on even when something uses what they take away")
	ifUnconfirmed := fs.Bool("if-unconfirmed", false, "undo: leave a confirmed guard on")
	repair := fs.Bool("repair", false, "check: put drifted steps back")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	// The undo timer runs later, from /, so every path it gets is absolute.
	var err error
	if *stateDir, err = filepath.Abs(*stateDir); err != nil {
		return err
	}
	if *root != "" {
		if *root, err = filepath.Abs(*root); err != nil {
			return err
		}
	}
	sys := agent.Linux{Root: *root}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	a := &agent.Agent{
		Sys:      sys,
		Timer:    agent.SystemdTimer{Sys: sys, Self: self, StateDir: *stateDir, Root: *root},
		StateDir: *stateDir,
	}
	changes := cmd != "fmt" && cmd != "plan" && cmd != "status" && cmd != "report" && cmd != "gates" && !(cmd == "check" && !*repair)
	if changes && os.Geteuid() != 0 && *root == "" {
		return errors.New(cmd + " changes the machine; run it as root")
	}
	arg := func() (string, error) {
		if fs.NArg() != 1 {
			return "", fmt.Errorf("%s takes one argument", cmd)
		}
		return fs.Arg(0), nil
	}

	switch cmd {
	case "fmt":
		path, err := arg()
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		g, err := guard.Decode(b)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", g.Canonical())
		fmt.Fprintf(os.Stderr, "%s, hash %s\n", g.Name(), g.Hash())
		return nil
	case "plan", "apply":
		path, err := arg()
		if err != nil {
			return err
		}
		g, err := readGuard(path)
		if err != nil {
			return err
		}
		if cmd == "plan" {
			return printPlan(a, g)
		}
		e, err := a.Apply(ctx, g, agent.ApplyOptions{ConfirmWithin: *within, Force: *force})
		if err != nil {
			return err
		}
		fmt.Printf("%s is on (%s), hash %s\n", g.Name(), e.Status, e.Hash)
		if e.Unprobed {
			fmt.Println("  not every drop was probed: the agent has no probe for some of them yet")
		}
		if e.Status == agent.Pending {
			fmt.Printf("  it comes off at %s unless you run: autopatch-agent confirm %s\n",
				e.ConfirmBy.UTC().Format(time.RFC3339), e.Hash[:12])
		}
		return nil
	case "confirm":
		key, err := arg()
		if err != nil {
			return err
		}
		e, err := a.Confirm(ctx, key)
		if err != nil {
			return err
		}
		fmt.Printf("%s is confirmed: it stays on across reboots\n", e.Guard.Name())
		return nil
	case "undo":
		key, err := arg()
		if err != nil {
			return err
		}
		e, err := a.Undo(ctx, key, *ifUnconfirmed)
		if e != nil {
			fmt.Printf("%s is off\n", e.Guard.Name())
		}
		return err
	case "status":
		entries, hits, err := a.Status(ctx)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fmt.Println("no guards on")
		}
		for _, e := range entries {
			fmt.Printf("%s  %s  %s", e.Hash[:12], e.Guard.Name(), e.Status)
			if n := hits[e.Hash]; n >= 0 {
				fmt.Printf("  stopped %d packets", n)
			} else {
				fmt.Print("  a table is unreadable")
			}
			if e.Unprobed {
				fmt.Print("  (a drop has no probe)")
			}
			fmt.Println()
			if e.Failed != "" {
				fmt.Println("  taking it off failed; undo or boot will try again: " + e.Failed)
			}
		}
		return nil
	case "check":
		drifts, err := a.Check(ctx, *repair)
		if err != nil {
			return err
		}
		left := 0
		for _, d := range drifts {
			if !d.Repaired && !d.TakenOff {
				left++
			}
			line := d.Guard + ": " + d.What
			switch {
			case d.Repaired:
				line += " (put back)"
			case d.TakenOff:
				line += " (taken off)"
			case d.Err != nil:
				line += " (repair failed: " + d.Err.Error() + ")"
			}
			fmt.Println(line)
		}
		switch {
		case left > 0:
			return fmt.Errorf("%d differences left", left)
		case len(drifts) > 0:
			fmt.Printf("%d differences, all repaired or taken off\n", len(drifts))
		default:
			fmt.Println("every guard is as set")
		}
		return nil
	case "report":
		b, err := json.MarshalIndent(a.Report(ctx), "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", b)
		return nil
	case "gates":
		failed := 0
		for _, g := range a.Gates(ctx) {
			mark := "ok  "
			if !g.OK {
				mark, failed = "FAIL", failed+1
			}
			line := mark + " " + g.Name
			if g.Why != "" {
				line += ": " + g.Why
			}
			fmt.Println(line)
		}
		if failed > 0 {
			return fmt.Errorf("%d gates fail; don't reboot", failed)
		}
		return nil
	case "boot":
		return a.Boot(ctx)
	case "install":
		if err := a.Install(ctx, self); err != nil {
			return err
		}
		fmt.Println("installed: autopatch-boot, autopatch-firewall and autopatch-check.timer")
		return nil
	}
	fs.Usage()
	return fmt.Errorf("unknown command %q", cmd)
}

func readGuard(path string) (*guard.Guard, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, guard.MaxSize+1))
	if err != nil {
		return nil, err
	}
	return guard.Parse(b)
}

func printPlan(a *agent.Agent, g *guard.Guard) error {
	p, err := a.Plan(g)
	if err != nil {
		return err
	}
	fmt.Printf("%s, hash %s\n", g.Name(), p.Hash)
	fmt.Printf("this machine: %s %s, kernel %s %s\n", p.System.OS, p.System.Release, p.System.Kernel, p.System.Flavour)
	for _, s := range p.Steps {
		fmt.Println("  " + s)
	}
	fmt.Println("  breaks: " + g.Breaks)
	if p.Unprobed {
		fmt.Println("  not every drop can be probed: the agent has no probe for some of them yet")
	}
	for _, u := range p.InUse {
		fmt.Println("  in use: " + u)
	}
	for _, pr := range p.Problems {
		fmt.Println("  can't go on: " + pr)
	}
	return nil
}
