package policy

import (
	"strings"
	"testing"
)

// example is a fleet's policy with test keys, written readably.
const example = `{
  "fleet": "home",
  "replaces": "",
  "delay_seconds": 86400,
  "signers": {
    "me": {"name": "jae-ledger", "key": "02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"},
    "rig": [{"name": "rig1", "key": "1111111111111111111111111111111111111111111111111111111111111111"}],
    "vetters": [{"name": "v1", "key": "2222222222222222222222222222222222222222222222222222222222222222"},
                {"name": "v2", "key": "3333333333333333333333333333333333333333333333333333333333333333"},
                {"name": "v3", "key": "4444444444444444444444444444444444444444444444444444444444444444"}],
    "vetters_needed": 2,
    "model": [{"name": "aibox-model", "key": "5555555555555555555555555555555555555555555555555555555555555555"}],
    "agents": [{"name": "backup", "key": "6666666666666666666666666666666666666666666666666666666666666666", "host": "backup"},
               {"name": "sentry", "key": "7777777777777777777777777777777777777777777777777777777777777777", "host": "sentry"}]
  },
  "rigs": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
  "tiers": [
    {"name": "A", "hosts": ["backup", "mail", "mysites"], "admit": ["me", "rig", "vetters", "model"], "canaries": ["backup", "mail"], "spacing_seconds": 900},
    {"name": "B", "hosts": ["sentry", "validator"], "admit": ["me"], "critical": true}
  ],
  "protected": [{"hosts": ["sentry"], "proto": "tcp", "port": 26656}],
  "health": [{"hosts": ["mysites"], "kind": "http", "target": "https://gno.shop/", "want": "200"},
             {"hosts": ["validator"], "kind": "json", "target": "https://mithrandir.online/live/status.json", "want": "signed_last20=20"}]
}`

func TestExample(t *testing.T) {
	p, err := Decode([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(example)); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("a readable spelling was taken as canonical: %v", err)
	}
	c, err := Parse(append(p.Canonical(), '\n'))
	if err != nil || c.Hash() != p.Hash() {
		t.Fatalf("canonical: %v", err)
	}
	if tier, ok := p.TierOf("validator"); !ok || tier.Name != "B" || !tier.Critical {
		t.Fatalf("validator's tier %+v", tier)
	}
}

func TestRefusals(t *testing.T) {
	cases := []struct{ name, from, to, want string }{
		{"a key twice", `"2222222222222222222222222222222222222222222222222222222222222222"`, `"1111111111111111111111111111111111111111111111111111111111111111"`, "listed twice"},
		{"the model in a critical tier", `"admit": ["me"], "critical": true`, `"admit": ["me", "model"], "critical": true`, "critical"},
		{"a host in two tiers", `"hosts": ["sentry", "validator"]`, `"hosts": ["sentry", "validator", "mail"]`, "tiers A and B"},
		{"a canary from another tier", `"canaries": ["backup", "mail"]`, `"canaries": ["backup", "sentry"]`, "isn't in tier"},
		{"three canaries", `"canaries": ["backup", "mail"]`, `"canaries": ["backup", "mail", "mysites"]`, "more than two"},
		{"an unknown role", `"admit": ["me"], "critical"`, `"admit": ["me", "friend"], "critical"`, "not a role"},
		{"more vetters needed than listed", `"vetters_needed": 2`, `"vetters_needed": 4`, "vetters_needed"},
		{"a rig build in capitals", `"rigs": ["` + strings.Repeat("a", 64) + `"]`, `"rigs": ["` + strings.Repeat("A", 64) + `"]`, "64 lowercase hex"},
		{"a short rig build", `"rigs": ["` + strings.Repeat("a", 64) + `"]`, `"rigs": ["aaaa"]`, "64 lowercase hex"},
		{"a rig build twice", `"rigs": ["` + strings.Repeat("a", 64) + `"]`, `"rigs": ["` + strings.Repeat("a", 64) + `", "` + strings.Repeat("a", 64) + `"]`, "rig aaaaaaaaaaaaaaaa is listed twice"},
		{"a short owner key", `"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"`, `"02db41"`, "33 bytes"},
		{"an uncompressed owner key", `"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"`, `"04db41e6e79e9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"`, "compressed"},
		{"uppercase hex", `"1111111111111111111111111111111111111111111111111111111111111111"`, `"AAAA111111111111111111111111111111111111111111111111111111111111"`, "hex"},
		{"an agent key without a host", `"host": "backup"`, `"host": ""`, "names its host"},
		{"a flow on an unknown host", `"protected": [{"hosts": ["sentry"]`, `"protected": [{"hosts": ["kourt"]`, "in no tier"},
		{"a delay of a minute", `"delay_seconds": 86400`, `"delay_seconds": 60`, "delay"},
		{"one builder", `"model": [`, `"builders": [{"name": "b1", "key": "8888888888888888888888888888888888888888888888888888888888888888"}], "model": [`, "two builders"},
		{"an unknown field", `"fleet": "home",`, `"fleet": "home", "trust": "all",`, "unknown field"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(example, c.from) {
				t.Fatalf("fixture lacks %q", c.from)
			}
			_, err := Decode([]byte(strings.Replace(example, c.from, c.to, 1)))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
		})
	}
}

// A tier that admits the rig or vetters needs a pinned rig build, or no
// Tested would count there: the signing tool and an agent's init refuse
// such a policy (round 9, minor 12). Admitting only the owner and the
// model needs none.
func TestRigsPinned(t *testing.T) {
	p, err := Decode([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.RigsPinned(); err != nil {
		t.Fatal(err)
	}
	p.Rigs = nil
	if err := p.RigsPinned(); err == nil || !strings.Contains(err.Error(), "tier A admits rig") {
		t.Fatalf("no rig build pinned: %v", err)
	}
	p.Tiers[0].Admit = []string{"me", "model"}
	if err := p.RigsPinned(); err != nil {
		t.Fatalf("neither rig nor vetters: %v", err)
	}
}
