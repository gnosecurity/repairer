package admit

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gnosecurity/repairer/approve"
	"github.com/gnosecurity/repairer/guard"
	"github.com/gnosecurity/repairer/policy"
)

type keyring map[string]ed25519.PrivateKey

func (k keyring) hex(name string) string {
	return hex.EncodeToString(k[name].Public().(ed25519.PublicKey))
}

func newKeys(t *testing.T, names ...string) keyring {
	t.Helper()
	k := keyring{}
	for _, n := range names {
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		k[n] = priv
	}
	return k
}

func fleet(t *testing.T, k keyring) *policy.Policy {
	t.Helper()
	p, err := policy.Decode([]byte(`{"fleet":"home","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"},
		"rig":[{"name":"rig","key":"` + k.hex("rig") + `"}],
		"vetters":[{"name":"v1","key":"` + k.hex("v1") + `"},{"name":"v2","key":"` + k.hex("v2") + `"},{"name":"v3","key":"` + k.hex("v3") + `"}],"vetters_needed":2,
		"model":[{"name":"model","key":"` + k.hex("model") + `"}],
		"agents":[{"name":"backup","key":"` + k.hex("backup") + `","host":"backup"},{"name":"mail","key":"` + k.hex("mail") + `","host":"mail"}]},
		"rigs":["` + strings.Repeat("c", 64) + `"],
		"tiers":[{"name":"A","hosts":["backup","mail","mysites"],"admit":["me","rig","vetters","model"],"canaries":["backup"]},
		         {"name":"B","hosts":["sentry"],"admit":["me","model"],"critical":false},
		         {"name":"C","hosts":["validator"],"admit":["me"],"critical":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func sign(t *testing.T, k keyring, who string, st approve.Statement) Signed {
	t.Helper()
	st.Version = approve.MemoVersion
	s, err := approve.SignStatement(k[who], st)
	if err != nil {
		t.Fatal(err)
	}
	return Signed{Statement: s.Statement, Key: s.Key}
}

func guardOne(t *testing.T) *guard.Guard {
	t.Helper()
	b, err := os.ReadFile("../guard/testdata/cve-2026-98432.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := guard.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func dropOnly(t *testing.T, flaw string, block string) *guard.Guard {
	t.Helper()
	g, err := guard.Decode([]byte(`{"id":"test/drop","version":1,"flaws":["` + flaw + `"],"for":[{"os":"ubuntu","releases":["24.04"]}],"blocks":[` + block + `],"breaks":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

var (
	onUbuntu = Machine{OS: "ubuntu", Release: "24.04"}
	now      = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	nonce    = strings.Repeat("ab", 16)
)

func TestOwnerYes(t *testing.T) {
	k := newKeys(t, "rig", "v1", "v2", "v3", "model", "backup", "mail")
	p, g := fleet(t, k), guardOne(t)
	yes := &approve.Yes{Hash: g.Hash(), Tiers: []string{"A"}, Until: now.Add(time.Hour), Mode: "undo"}
	if d := Admit(p, "backup", g, Evidence{Yes: yes}, onUbuntu, nonce, now); !d.OK || d.By != "me" {
		t.Fatalf("canary with the owner's yes: %+v", d)
	}
	if d := Admit(p, "sentry", g, Evidence{Yes: yes}, onUbuntu, nonce, now); d.OK {
		t.Fatal("a yes for tier A admitted a tier B machine")
	}
	if d := Admit(p, "backup", g, Evidence{Yes: yes}, onUbuntu, nonce, now.Add(2*time.Hour)); d.OK {
		t.Fatal("an expired yes admitted")
	}
	// A non-canary waits for the canary, unless the yes says no canary.
	if d := Admit(p, "mysites", g, Evidence{Yes: yes}, onUbuntu, nonce, now); d.OK || !d.Wait {
		t.Fatalf("mysites without a canary's Healthy: %+v", d)
	}
	nc := *yes
	nc.NoCanary = true
	if d := Admit(p, "mysites", g, Evidence{Yes: &nc}, onUbuntu, nonce, now); !d.OK {
		t.Fatalf("nocanary: %+v", d)
	}
}

func TestRigAndVetters(t *testing.T) {
	k := newKeys(t, "rig", "v1", "v2", "v3", "model", "backup", "mail", "stranger")
	p, g := fleet(t, k), guardOne(t)
	rigHash := strings.Repeat("c", 64)
	tested := func(who string) Signed {
		return sign(t, k, who, approve.Statement{Kind: approve.KindTested, Image: "ubuntu 24.04", Chain: "repairer:vet", Guard: g.Hash(), Rig: rigHash})
	}
	if d := Admit(p, "backup", g, Evidence{Signed: []Signed{tested("rig")}}, onUbuntu, nonce, now); !d.OK || d.By != "rig" {
		t.Fatalf("rig: %+v", d)
	}
	unpinned := sign(t, k, "rig", approve.Statement{Kind: approve.KindTested, Image: "ubuntu 24.04", Chain: "repairer:vet", Guard: g.Hash(), Rig: strings.Repeat("d", 64)})
	if d := Admit(p, "backup", g, Evidence{Signed: []Signed{unpinned}}, onUbuntu, nonce, now); d.OK || !strings.Contains(d.Why, "from a pinned rig build") {
		t.Fatalf("a Tested from a rig build the policy doesn't pin: %+v", d) // round 9, minor 12
	}
	if d := Admit(p, "backup", g, Evidence{Signed: []Signed{tested("stranger")}}, onUbuntu, nonce, now); d.OK {
		t.Fatal("a stranger's Tested admitted")
	}
	one := []Signed{tested("v1"), tested("v1")}
	if d := Admit(p, "backup", g, Evidence{Signed: one}, onUbuntu, nonce, now); d.OK {
		t.Fatal("one vetter counted twice")
	}
	if d := Admit(p, "backup", g, Evidence{Signed: []Signed{tested("v1"), tested("v3")}}, onUbuntu, nonce, now); !d.OK || d.By != "vetters" {
		t.Fatalf("two vetters: %+v", d)
	}
	vetted := func(who string) Signed {
		return sign(t, k, who, approve.Statement{Kind: approve.KindTested, Image: "ubuntu 24.04", Chain: "repairer:vet", Guard: g.Hash(), Rig: strings.Repeat("d", 64)})
	}
	if d := Admit(p, "backup", g, Evidence{Signed: []Signed{vetted("v1"), vetted("v3")}}, onUbuntu, nonce, now); d.OK {
		t.Fatal("two vetters' Tested from a rig build the policy doesn't pin admitted")
	}
	// A Tested counts only on the system the rig ran: not on another
	// release the guard is written for, not where the system is unknown
	// (round 8, minor 9).
	for _, m := range []Machine{{OS: "ubuntu", Release: "22.04"}, {OS: "debian", Release: "12"}, {}} {
		if d := Admit(p, "backup", g, Evidence{Signed: []Signed{tested("rig")}}, m, nonce, now); d.OK {
			t.Fatalf("a Tested on ubuntu 24.04 admitted on %q %q", m.OS, m.Release)
		}
	}
}

func TestModelRule6(t *testing.T) {
	k := newKeys(t, "rig", "v1", "v2", "v3", "model", "backup", "mail")
	p := fleet(t, k)
	modelYes := func(g *guard.Guard) Evidence {
		return Evidence{Signed: []Signed{sign(t, k, "model", approve.Statement{Kind: approve.KindModel, Chain: "repairer:x/home", Guard: g.Hash()})}}
	}
	opts := dropOnly(t, "CVE-2099-10", `{"drop":{"family":"ipv4","protocol":"tcp","ip_options":true}}`)
	port := dropOnly(t, "CVE-2099-11", `{"drop":{"family":"ipv4","protocol":"tcp","ports":["8080"]}}`)
	if d := Admit(p, "backup", opts, modelYes(opts), onUbuntu, nonce, now); !d.OK || d.By != "model" {
		t.Fatalf("a narrowed drop: %+v", d)
	}
	if d := Admit(p, "backup", guardOne(t), modelYes(guardOne(t)), onUbuntu, nonce, now); d.OK {
		t.Fatal("the model admitted a guard with a setting")
	}
	if d := Admit(p, "validator", opts, modelYes(opts), onUbuntu, nonce, now); d.OK {
		t.Fatal("the model counted in a critical tier")
	}
	listening := Machine{OS: "ubuntu", Release: "24.04", Listening: map[string]bool{"tcp/8080": true}}
	if d := Admit(p, "backup", port, modelYes(port), listening, nonce, now); d.OK || !strings.Contains(d.Why, "listens on tcp port 8080") {
		t.Fatalf("a drop on a listening port: %+v", d)
	}
	// Nothing listens here now, but a port served later, in a container or
	// another namespace, would be cut: the model's yes doesn't count for a
	// drop narrowed only by ports (round 8, new major 2).
	if d := Admit(p, "backup", port, modelYes(port), onUbuntu, nonce, now); d.OK || !strings.Contains(d.Why, "narrowed only by ports needs your yes") {
		t.Fatalf("a drop narrowed only by ports, on the model's yes: %+v", d)
	}
	full := Machine{OS: "ubuntu", Release: "24.04", ModelGuards: [][]string{{"a"}, {"b"}, {"c"}}}
	if d := Admit(p, "backup", opts, modelYes(opts), full, nonce, now); d.OK {
		t.Fatal("a fourth model guard")
	}
	same := Machine{OS: "ubuntu", Release: "24.04", ModelGuards: [][]string{{"CVE-2099-10"}}}
	if d := Admit(p, "backup", opts, modelYes(opts), same, nonce, now); d.OK {
		t.Fatal("a second model guard for one flaw")
	}
}

func TestCanary(t *testing.T) {
	k := newKeys(t, "rig", "v1", "v2", "v3", "model", "backup", "mail")
	p := fleet(t, k)
	g := dropOnly(t, "CVE-2099-14", `{"drop":{"family":"ipv4","protocol":"tcp","ip_options":true}}`) // bites now
	rig := sign(t, k, "rig", approve.Statement{Kind: approve.KindTested, Image: "ubuntu 24.04", Chain: "repairer:vet", Guard: g.Hash(), Rig: strings.Repeat("c", 64)})
	healthy := func(who, host, state, why, n string) Signed {
		return sign(t, k, who, approve.Statement{Kind: approve.KindHealthy, Chain: "repairer:x/home", Guard: g.Hash(), Host: host, State: state, Why: why, Nonce: n})
	}
	cases := []struct {
		name string
		h    Signed
		ok   bool
	}{
		{"the canary's Healthy", healthy("backup", "backup", "on", "", nonce), true},
		{"the canary booted with it", healthy("backup", "backup", "booted", "", nonce), true},
		{"the canary refused it here, for a listed reason", healthy("backup", "backup", "refused", "netns", nonce), true},
		{"an old nonce", healthy("backup", "backup", "on", "", strings.Repeat("cd", 16)), false},
		{"a machine that isn't a canary", healthy("mail", "mail", "on", "", nonce), false},
		{"a canary's host signed by another agent's key", healthy("mail", "backup", "on", "", nonce), false},
	}
	for _, c := range cases {
		d := Admit(p, "mysites", g, Evidence{Signed: []Signed{rig, c.h}}, onUbuntu, nonce, now)
		if d.OK != c.ok {
			t.Errorf("%s: %+v", c.name, d)
		}
	}
}

// A guard that bites later (here, guard one, whose MPTCP setting bites only
// for new sockets) needs a canary's Healthy after a boot: neither "on" nor a
// refusal stands in for it (round 4, new major 2).
func TestCanaryLater(t *testing.T) {
	k := newKeys(t, "rig", "v1", "v2", "v3", "model", "backup", "mail")
	p, g := fleet(t, k), guardOne(t)
	if !g.Later() {
		t.Fatal("guard one should bite later")
	}
	rig := sign(t, k, "rig", approve.Statement{Kind: approve.KindTested, Image: "ubuntu 24.04", Chain: "repairer:vet", Guard: g.Hash(), Rig: strings.Repeat("c", 64)})
	healthy := func(state, why string) Signed {
		return sign(t, k, "backup", approve.Statement{Kind: approve.KindHealthy, Chain: "repairer:x/home", Guard: g.Hash(), Host: "backup", State: state, Why: why, Nonce: nonce})
	}
	for state, ok := range map[string]bool{"on": false, "refused": false, "booted": true} {
		why := ""
		if state == "refused" {
			why = "netns"
		}
		d := Admit(p, "mysites", g, Evidence{Signed: []Signed{rig, healthy(state, why)}}, onUbuntu, nonce, now)
		if d.OK != ok || (!ok && !d.Wait) {
			t.Errorf("%s: %+v", state, d)
		}
	}
	// The owner's nocanary still lets it go at once.
	yes := &approve.Yes{Hash: g.Hash(), Tiers: []string{"A"}, Until: now.Add(time.Hour), Mode: "undo", NoCanary: true}
	if d := Admit(p, "mysites", g, Evidence{Yes: yes}, onUbuntu, nonce, now); !d.OK {
		t.Fatalf("nocanary: %+v", d)
	}
}

// A refusal must give one of the listed reasons, or it can't be signed.
func TestRefusalReasons(t *testing.T) {
	k := newKeys(t, "backup")
	st := approve.Statement{Version: approve.MemoVersion, Kind: approve.KindHealthy, Chain: "repairer:x/home", Guard: strings.Repeat("a", 64), Host: "backup", State: "refused", Nonce: nonce}
	for why, ok := range map[string]bool{"in-use": true, "netns": true, "never-touch": true, "protected-flow": true, "": false, "containers keep their own MPTCP": false, "no Tested": false} {
		st.Why = why
		if _, err := approve.SignStatement(k["backup"], st); (err == nil) != ok {
			t.Errorf("refused for %q: %v", why, err)
		}
	}
	st.State, st.Why = "on", "netns"
	if _, err := approve.SignStatement(k["backup"], st); err == nil {
		t.Error("an on with a reason")
	}
}

// The owner's Yes counts first, whatever order the tier lists the roles in,
// so its keep and nocanary hold even when the rig has signed Tested.
func TestOwnerFirst(t *testing.T) {
	k := newKeys(t, "rig", "v1", "v2", "v3", "model", "backup", "mail")
	p := fleet(t, k)
	p.Tiers[0].Admit = []string{"rig", "vetters", "model", "me"}
	g := dropOnly(t, "CVE-2099-12", `{"drop":{"family":"ipv4","protocol":"tcp","ip_options":true}}`)
	rig := sign(t, k, "rig", approve.Statement{Kind: approve.KindTested, Image: "ubuntu 24.04", Chain: "repairer:vet", Guard: g.Hash(), Rig: strings.Repeat("c", 64)})
	yes := &approve.Yes{Hash: g.Hash(), Tiers: []string{"A"}, Until: now.Add(time.Hour), Mode: "keep", NoCanary: true}
	if d := Admit(p, "mysites", g, Evidence{Yes: yes, Signed: []Signed{rig}}, onUbuntu, nonce, now); !d.OK || d.By != "me" {
		t.Fatalf("the owner's yes with the rig's Tested: %+v", d)
	}
}

// A block outside the agent's auto lists (a module not on them) needs the
// owner's yes; the rig's Tested isn't enough.
func TestNotAutoNeedsOwner(t *testing.T) {
	k := newKeys(t, "rig", "v1", "v2", "v3", "model", "backup", "mail")
	p := fleet(t, k)
	g, err := guard.Decode([]byte(`{"id":"test/mod","version":1,"flaws":["CVE-2099-13"],"for":[{"os":"ubuntu","releases":["24.04"]}],"blocks":[{"module":{"name":"cifs"}}],"breaks":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if g.Auto() {
		t.Fatal("cifs is on the auto list; pick another module")
	}
	rig := sign(t, k, "rig", approve.Statement{Kind: approve.KindTested, Image: "ubuntu 24.04", Chain: "repairer:vet", Guard: g.Hash(), Rig: strings.Repeat("c", 64)})
	if d := Admit(p, "backup", g, Evidence{Signed: []Signed{rig}}, onUbuntu, nonce, now); d.OK || !strings.Contains(d.Why, "owner's yes") {
		t.Fatalf("the rig admitted a block outside the auto lists: %+v", d)
	}
	yes := &approve.Yes{Hash: g.Hash(), Tiers: []string{"A"}, Until: now.Add(time.Hour), Mode: "undo"}
	if d := Admit(p, "backup", g, Evidence{Yes: yes}, onUbuntu, nonce, now); !d.OK {
		t.Fatalf("the owner's yes: %+v", d)
	}
}

func TestSignedStatements(t *testing.T) {
	k := newKeys(t, "a")
	st := approve.Statement{Version: approve.MemoVersion, Kind: approve.KindTested, Image: "ubuntu 24.04", Chain: "repairer:vet", Guard: strings.Repeat("a", 64), Rig: strings.Repeat("b", 64)}
	s, err := approve.SignStatement(k["a"], st)
	if err != nil {
		t.Fatal(err)
	}
	noImage := st
	noImage.Image = ""
	if _, err := approve.SignStatement(k["a"], noImage); err == nil {
		t.Error("signed a Tested that names no system")
	}
	b := []byte(`{"statement":{"v":"repairer/1","kind":"Tested","chain":"repairer:vet","guard":"` + st.Guard + `","rig":"` + st.Rig + `","image":"ubuntu 24.04"},"key":"` + s.Key + `","sig":"` + s.Sig + `"}`)
	if _, key, err := approve.ParseSigned(b); err != nil || hex.EncodeToString(key) != s.Key {
		t.Fatalf("round trip: %v", err)
	}
	for name, e := range map[string]string{
		"another guard":   strings.Replace(string(b), `"guard":"aaaa`, `"guard":"baaa`, 1),
		"a fleet":         strings.Replace(string(b), `repairer:vet`, `repairer:x/home`, 1),
		"an extra field":  strings.Replace(string(b), `"key":`, `"note":"x","key":`, 1),
		"another version": strings.Replace(string(b), `repairer/1`, `repairer/2`, 1),
		"another system":  strings.Replace(string(b), `ubuntu 24.04`, `ubuntu 22.04`, 1),
		"no system":       strings.Replace(string(b), `,"image":"ubuntu 24.04"`, ``, 1),
	} {
		if _, _, err := approve.ParseSigned([]byte(e)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
