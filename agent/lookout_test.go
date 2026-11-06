package agent_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gnosecurity/repairer/agent"
	"github.com/gnosecurity/repairer/approve"
	"github.com/gnosecurity/repairer/guard"
	"github.com/gnosecurity/repairer/lookout"
	"github.com/gnosecurity/repairer/policy"
)

// C2's test, in memory: three machines and a lookout, a minute at a time.
// The rig's Tested reaches the lookout; the lookout collects every signed
// report, and carries to each machine what it may take, including the
// waiting machines' wants to the canary and the canary's Healthy back. The
// canary goes first; the others follow only after its window, spaced by
// the tier's spacing.
func TestCanaryFirstThroughTheLookout(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	hosts := []string{"backup", "mail", "web"}
	seeds := map[string]string{}
	var agentKeys []string
	for _, h := range hosts {
		_, k, _ := ed25519.GenerateKey(nil)
		seeds[h] = hex.EncodeToString(k.Seed())
		agentKeys = append(agentKeys, `{"name":"`+h+`","key":"`+hex.EncodeToString(k.Public().(ed25519.PublicKey))+`","host":"`+h+`"}`)
	}
	_, rig, _ := ed25519.GenerateKey(nil)
	p, err := policy.Decode([]byte(`{"fleet":"home","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"},
		"rig":[{"name":"rig1","key":"` + hex.EncodeToString(rig.Public().(ed25519.PublicKey)) + `"}],
		"agents":[` + strings.Join(agentKeys, ",") + `]},
		"rigs":["` + strings.Repeat("0", 64) + `"],
		"tiers":[{"name":"A","hosts":["backup","mail","web"],"admit":["rig"],"canaries":["backup"],"spacing_seconds":300}],
		"health":[{"hosts":["backup","mail","web"],"kind":"tcp","target":"203.0.113.5:443","want":""}]}`))
	if err != nil {
		t.Fatal(err)
	}
	agents := map[string]*agent.Agent{}
	for _, h := range hosts {
		a := agent.NewTestAgent(t, clock, map[string]string{})
		agent.SetKey(t, a, seeds[h])
		if _, err := a.Init(h, p.Canonical(), 0); err != nil {
			t.Fatal(err)
		}
		agents[h] = a
	}

	// The rig's Tested and the guard reach the lookout.
	g, err := guard.Decode([]byte(`{"id":"cve-2026-98432/linux-ipv4-ipopt","version":1,"flaws":["CVE-2026-98432"],
		"for":[{"os":"ubuntu","releases":["24.04"]}],"blocks":[{"drop":{"family":"ipv4","protocol":"tcp","ip_options":true}}],"breaks":"IP options on TCP"}`))
	if err != nil {
		t.Fatal(err)
	}
	store := &lookout.Store{Dir: t.TempDir()}
	if _, err := store.AddGuard(g.Canonical()); err != nil {
		t.Fatal(err)
	}
	sg, _ := approve.SignStatement(rig, approve.Statement{Version: approve.MemoVersion, Kind: approve.KindTested, Image: "ubuntu 24.04", Chain: "repairer:vet", Guard: g.Hash(), Rig: strings.Repeat("0", 64)})
	raw, _ := json.Marshal(sg)
	if err := store.AddSigned(raw); err != nil {
		t.Fatal(err)
	}
	col := &lookout.Collector{Policy: p, Dir: t.TempDir(), Now: clock,
		Fetch: func(_ context.Context, host string) ([]byte, error) { return agent.ReadReport(agents[host].StateDir) }}

	on := map[string]time.Time{}
	for minute := 0; minute < 60; minute++ {
		for _, h := range hosts {
			if _, err := agents[h].Tick(context.Background()); err != nil {
				t.Fatalf("%s at minute %d: %v", h, minute, err)
			}
			if _, seen := on[h]; !seen && agent.GuardStatus(t, agents[h], g.Hash()) != "" {
				on[h] = now
			}
		}
		sts := col.Collect(context.Background())
		for _, st := range sts {
			if st.Error != "" {
				t.Fatalf("collecting %s: %s", st.Host, st.Error)
			}
		}
		for _, h := range hosts {
			b, err := store.Bundle(h, sts, p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := agent.Intake(filepath.Join(agents[h].StateDir, agent.SpoolDir), bytes.NewReader(b)); err != nil {
				t.Fatal(err)
			}
		}
		now = now.Add(time.Minute)
	}
	start := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	for _, h := range hosts {
		if on[h].IsZero() {
			t.Fatalf("%s never took the guard; on: %v", h, on)
		}
		t.Logf("%s on at minute %d", h, int(on[h].Sub(start).Minutes()))
	}
	// The canary first; the others only after its ten-minute window, and
	// web, second in line, five minutes after mail.
	if !on["backup"].Before(on["mail"]) || on["mail"].Sub(on["backup"]) < 10*time.Minute {
		t.Fatalf("mail went on before the canary's window ended: %v", on)
	}
	if d := on["web"].Sub(on["mail"]); d < 5*time.Minute {
		t.Fatalf("web went on %v after mail; the spacing is 5 minutes", d)
	}
	for _, h := range hosts {
		if s := agent.GuardStatus(t, agents[h], g.Hash()); s != "confirmed" {
			t.Errorf("%s: %s after an hour", h, s)
		}
	}
}
