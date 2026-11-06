package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jaekwon/repairer/policy"
)

// HealthChecker runs one of the policy's health checks and says why it
// fails, or "" when it holds.
type HealthChecker func(ctx context.Context, h policy.Health) string

// LiveHealth runs health checks for real: a TCP connect, an HTTP status, a
// systemd unit being active, or a JSON field's value.
func (a *Agent) LiveHealth(ctx context.Context, h policy.Health) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	switch h.Kind {
	case "tcp":
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", h.Target)
		if err != nil {
			return err.Error()
		}
		c.Close()
		return ""
	case "unit":
		out, _ := a.Sys.Run(ctx, nil, "systemctl", "is-active", h.Target)
		if st := strings.TrimSpace(string(out)); st != "active" {
			return h.Target + " is " + st
		}
		return ""
	case "http", "json":
		req, err := http.NewRequestWithContext(ctx, "GET", h.Target, nil)
		if err != nil {
			return err.Error()
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err.Error()
		}
		defer resp.Body.Close()
		if h.Kind == "http" {
			if strconv.Itoa(resp.StatusCode) != h.Want {
				return fmt.Sprintf("status %d, not %s", resp.StatusCode, h.Want)
			}
			return ""
		}
		field, want, ok := strings.Cut(h.Want, "=")
		if !ok {
			return "want is field=value"
		}
		var doc map[string]any
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
			return "not JSON: " + err.Error()
		}
		var v any = doc
		for _, k := range strings.Split(field, ".") {
			m, ok := v.(map[string]any)
			if !ok {
				return field + " is missing"
			}
			v = m[k]
		}
		if got := fmt.Sprint(v); got != want {
			return fmt.Sprintf("%s is %s, not %s", field, got, want)
		}
		return ""
	}
	return "unknown check kind " + h.Kind
}

// checksFor returns the policy's health checks for one host.
func checksFor(p *policy.Policy, host string) []policy.Health {
	var out []policy.Health
	for _, h := range p.Health {
		for _, x := range h.Hosts {
			if x == host {
				out = append(out, h)
			}
		}
	}
	return out
}

// checkKey names a check, to compare a baseline with a later run.
func checkKey(h policy.Health) string { return h.Kind + " " + h.Target + " " + h.Want }

// runChecks runs this host's checks and returns the failing ones by key.
func (a *Agent) runChecks(ctx context.Context, checks []policy.Health) map[string]string {
	run := a.Health
	if run == nil {
		run = a.LiveHealth
	}
	fails := map[string]string{}
	for _, h := range checks {
		if why := run(ctx, h); why != "" {
			fails[checkKey(h)] = why
		}
	}
	return fails
}
