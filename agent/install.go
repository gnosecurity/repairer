package agent

import (
	"context"
	"fmt"
	"strings"
)

// Units the agent installs. Three jobs, kept apart:
//   - repairer-boot runs once, early at every boot: it takes off what was
//     never confirmed and puts back what was.
//   - repairer-firewall is tied to nftables.service and firewalld.service,
//     whose restarts and reloads flush the ruleset. It only repairs, so a
//     firewall restart during a guard's trial doesn't take the guard off.
//   - repairer-check.timer repairs drift every minute, whatever caused it.
const (
	unitDir      = "/etc/systemd/system"
	bootUnit     = "repairer-boot.service"
	firewallUnit = "repairer-firewall.service"
	checkUnit    = "repairer-check.service"
	checkTimer   = "repairer-check.timer"
)

// UnitFiles returns the agent's systemd units, running the agent at self.
func UnitFiles(self, stateDir string) map[string]string {
	run := self + " %s -state-dir " + stateDir
	return map[string]string{
		bootUnit: `[Unit]
Description=repairer: put back confirmed guards, take off unconfirmed ones
Documentation=https://github.com/jaekwon/repairer
DefaultDependencies=no
Wants=network-pre.target
After=local-fs.target nftables.service firewalld.service
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + fmt.Sprintf(run, "boot") + `

[Install]
WantedBy=sysinit.target
`,
		firewallUnit: `[Unit]
Description=repairer: put guards back after a firewall restart or reload
Documentation=https://github.com/jaekwon/repairer
After=repairer-boot.service nftables.service firewalld.service
PartOf=nftables.service firewalld.service
ReloadPropagatedFrom=nftables.service firewalld.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + fmt.Sprintf(run, "check") + ` -repair
ExecReload=` + fmt.Sprintf(run, "check") + ` -repair

[Install]
WantedBy=multi-user.target
`,
		checkUnit: `[Unit]
Description=repairer: put back what drifted, take in signed messages, move guards on, report
Documentation=https://github.com/jaekwon/repairer
After=repairer-boot.service

[Service]
Type=oneshot
ExecStart=` + fmt.Sprintf(run, "tick") + `
`,
		checkTimer: `[Unit]
Description=repairer: check guards every minute
Documentation=https://github.com/jaekwon/repairer

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=5s

[Install]
WantedBy=timers.target
`,
	}
}

// Install writes the agent's units and turns them on. self must be the
// agent's root-only path, since systemd runs it as root.
func (a *Agent) Install(ctx context.Context, self string) error {
	if err := safeExecutable(self); err != nil {
		return fmt.Errorf("install: %s: %w", self, err)
	}
	for name, text := range UnitFiles(self, a.StateDir) {
		if err := a.Sys.WriteFile(unitDir+"/"+name, []byte(text), 0o644); err != nil {
			return err
		}
	}
	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", bootUnit, firewallUnit, checkTimer},
		{"start", firewallUnit, checkTimer},
	} {
		if _, err := a.Sys.Run(ctx, nil, "systemctl", args...); err != nil {
			return fmt.Errorf("install: systemctl %s: %w", strings.Join(args, " "), err)
		}
	}
	return nil
}
