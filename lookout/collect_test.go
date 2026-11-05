package lookout

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/agent"
	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/policy"
)

const ownerHex = "02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"

type fleet struct {
	p    *policy.Policy
	keys map[string]ed25519.PrivateKey
	now  time.Time
	got  map[string][]byte // what each machine's report command prints
}

func newFleet(t *testing.T) *fleet {
	t.Helper()
	fl := &fleet{keys: map[string]ed25519.PrivateKey{}, now: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC), got: map[string][]byte{}}
	var agents []string
	for _, h := range []string{"backup", "mail"} {
		_, k, _ := ed25519.GenerateKey(nil)
		fl.keys[h] = k
		agents = append(agents, `{"name":"`+h+`","key":"`+hex.EncodeToString(k.Public().(ed25519.PublicKey))+`","host":"`+h+`"}`)
	}
	p, err := policy.Decode([]byte(`{"fleet":"home","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"` + ownerHex + `"},"agents":[` + strings.Join(agents, ",") + `]},
		"tiers":[{"name":"A","hosts":["backup","mail"],"admit":["me"],"canaries":["backup"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	fl.p = p
	return fl
}

// report has a machine sign a report, as its agent would.
func (fl *fleet) report(t *testing.T, host, signer string, seq uint64, at time.Time) {
	t.Helper()
	owner, _ := hex.DecodeString(ownerHex)
	r := agent.FleetReport{Version: approve.MemoVersion, Kind: "report", Chain: approve.ChainID(owner, "home"), Host: host, Seq: seq, Time: at,
		Policy: fl.p.Hash(), Facts: &agent.Report{}}
	r.Facts.OS.ID, r.Facts.OS.Codename, r.Facts.Kernel.Running = "ubuntu", "noble", "6.8.0-142.142"
	body, _ := json.Marshal(r)
	sr, _ := json.Marshal(approve.SignReport(fl.keys[signer], body))
	fl.got[host] = sr
}

func (fl *fleet) collector(t *testing.T) *Collector {
	return &Collector{Policy: fl.p, Dir: t.TempDir(), Now: func() time.Time { return fl.now },
		Fetch: func(_ context.Context, host string) ([]byte, error) {
			if b, ok := fl.got[host]; ok {
				return b, nil
			}
			return nil, errors.New("connection refused")
		}}
}

func statusOf(sts []HostStatus, host string) HostStatus {
	for _, s := range sts {
		if s.Host == host {
			return s
		}
	}
	return HostStatus{}
}

// The collector keeps each machine's newest report that its own agent key
// signed; it refuses a report signed by another machine's key, an older
// report than it has, and one from the future; a machine with no fresh
// report for 15 minutes is silent.
func TestCollect(t *testing.T) {
	fl := newFleet(t)
	c := fl.collector(t)
	fl.report(t, "backup", "backup", 5, fl.now)
	fl.report(t, "mail", "backup", 9, fl.now) // signed by backup's key
	sts := c.Collect(context.Background())
	if b := statusOf(sts, "backup"); b.Error != "" || b.Seq != 5 || b.Silent {
		t.Fatalf("backup: %+v", b)
	}
	if m := statusOf(sts, "mail"); m.Error == "" || m.Report != nil || !m.Silent {
		t.Fatalf("mail's forged report: %+v", m)
	}
	if ms := Machines(sts); len(ms) != 1 || ms[0].Host != "backup" || ms[0].Kernel.Running != "6.8.0-142.142" {
		t.Fatalf("machines %+v", ms)
	}

	fl.report(t, "backup", "backup", 4, fl.now) // an old report, replayed
	if b := statusOf(c.Collect(context.Background()), "backup"); !strings.Contains(b.Error, "older") || b.Seq != 5 {
		t.Fatalf("a replayed report: %+v", b)
	}
	fl.report(t, "backup", "backup", 6, fl.now.Add(time.Hour))
	if b := statusOf(c.Collect(context.Background()), "backup"); !strings.Contains(b.Error, "future") {
		t.Fatalf("a report from the future: %+v", b)
	}

	delete(fl.got, "backup") // backup stops answering
	fl.now = fl.now.Add(16 * time.Minute)
	if b := statusOf(c.Collect(context.Background()), "backup"); !b.Silent || b.Seq != 5 {
		t.Fatalf("silent: %+v", b)
	}
}
