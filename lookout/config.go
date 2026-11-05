package lookout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Config is the lookout's own setup: where its state lives, the policy
// it reads agent keys from, the ssh keys it holds, and how to reach each
// machine. Each key can do one thing on an agent: report or intake.
type Config struct {
	State      string            `json:"state"`       // the lookout's own directory
	Policy     string            `json:"policy"`      // the policy file in force
	ReportKey  string            `json:"report_key"`  // ssh key whose line runs only `report`
	IntakeKey  string            `json:"intake_key"`  // ssh key whose line runs only `intake`
	KnownHosts string            `json:"known_hosts"` // the machines' host keys, pinned
	Hosts      map[string]string `json:"hosts"`       // policy host name: user@address
}

// targetRe is a machine's address: user@host, or ssh://user@host:port.
var targetRe = regexp.MustCompile(`^([a-z_][a-z0-9_-]{0,31}@[A-Za-z0-9.-]{1,253}|ssh://[a-z_][a-z0-9_-]{0,31}@[A-Za-z0-9.-]{1,253}:[0-9]{1,5})$`)

// ReadConfig reads and checks a lookout's config.
func ReadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("lookout: %s: %w", path, err)
	}
	if c.State == "" || c.Policy == "" || c.ReportKey == "" || c.IntakeKey == "" || c.KnownHosts == "" {
		return nil, errors.New("lookout: the config needs state, policy, report_key, intake_key and known_hosts")
	}
	for h, t := range c.Hosts {
		if !targetRe.MatchString(t) {
			return nil, fmt.Errorf("lookout: host %s: %q isn't user@host or ssh://user@host:port", h, t)
		}
	}
	return &c, nil
}

// SSH runs one of the agent's two commands on a machine. The command is
// fixed by the key's line on the machine (restrict,command=...), so the
// lookout sends none; host keys are pinned; nothing is forwarded.
type SSH struct {
	Key        string
	KnownHosts string
	Timeout    time.Duration
}

// Run connects to target with the key and returns what the forced command
// prints, giving it stdin.
func (s SSH) Run(ctx context.Context, target string, stdin []byte) ([]byte, error) {
	if !targetRe.MatchString(target) {
		return nil, fmt.Errorf("lookout: %q isn't user@address", target)
	}
	if s.Timeout == 0 {
		s.Timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh",
		"-i", s.Key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+s.KnownHosts,
		"-o", "ConnectTimeout=10", "-o", "ClearAllForwardings=yes", "-T", "--", target)
	var out, errb bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(stdin), &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ssh %s: %v: %s", target, err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}
