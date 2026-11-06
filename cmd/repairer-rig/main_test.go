package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaekwon/repairer/approve"
	"github.com/jaekwon/repairer/guard"
)

func TestSign(t *testing.T) {
	g, err := os.ReadFile("../../guard/testdata/cve-2026-98432-ipopt.json")
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(nil)
	seed := []byte(hex.EncodeToString(key.Seed()))
	rig := strings.Repeat("ab", 32)
	good := `{"rig":"two-vm/1","image":"ubuntu 24.04","guard":"73804a3fcab787f11c404c13c46b06eb8452aa585fb7f92429fa7ab98635ed6c","checks":{
		"applies":{"pass":true,"evidence":["applied"]},"one_timing":{"pass":true,"evidence":["bites now"]},"probe_blocked":{"pass":true,"evidence":["stopped"]},
		"twice_no_change":{"pass":true,"evidence":[]},"traffic":{"pass":true,"evidence":["ssh login: ok"]},
		"traffic_lan":{"pass":true,"evidence":["all 20 checks between the two machines pass"]},
		"survives":{"pass":true,"evidence":[]},"undo_exact":{"pass":true,"evidence":[]},"nothing_else":{"pass":true,"evidence":[]},
		"extra":{"pass":null,"evidence":["not run"]}}}`
	sg, err := Sign(seed, rig, g, []byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if sg.Statement.Kind != approve.KindTested || sg.Statement.Rig != rig || sg.Statement.Image != "ubuntu 24.04" || sg.Key != hex.EncodeToString(key.Public().(ed25519.PublicKey)) {
		t.Fatalf("%+v", sg)
	}
	for name, bad := range map[string]string{
		"a failed check":                       strings.Replace(good, `"undo_exact":{"pass":true`, `"undo_exact":{"pass":false`, 1),
		"a required not run":                   strings.Replace(good, `"survives":{"pass":true`, `"survives":{"pass":null`, 1),
		"a missing check":                      strings.Replace(good, `"nothing_else":{"pass":true,"evidence":[]},`, ``, 1),
		"another guard":                        strings.Replace(good, `73804a3f`, `00000000`, 1),
		"an extra failed one":                  strings.Replace(good, `"extra":{"pass":null`, `"extra":{"pass":false`, 1),
		"the single-VM rig (no traffic_lan)":   strings.Replace(good, `"traffic_lan":{"pass":true,"evidence":["all 20 checks between the two machines pass"]},`, ``, 1),
		"a system the guard isn't written for": strings.Replace(good, `ubuntu 24.04`, `debian 11`, 1),
		"no system":                            strings.Replace(good, `"image":"ubuntu 24.04",`, ``, 1),
	} {
		if _, err := Sign(seed, rig, g, []byte(bad)); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	// A guard that mixes a drop (now) with a setting (later) is refused
	// (round 8, minor 9).
	mixed, err := os.ReadFile("../../guard/testdata/cve-2026-98432.json")
	if err != nil {
		t.Fatal(err)
	}
	mg, err := guard.Parse(mixed)
	if err != nil {
		t.Fatal(err)
	}
	m := strings.Replace(good, "73804a3fcab787f11c404c13c46b06eb8452aa585fb7f92429fa7ab98635ed6c", mg.Hash(), 1)
	if _, err := Sign(seed, rig, mixed, []byte(m)); err == nil || !strings.Contains(err.Error(), "mixes") {
		t.Errorf("a mixed guard: %v", err)
	}
}

// The rig hash covers the files a run uses, directly in the scripts
// directory, and changes with any of them, the image or the agent; a
// folder there (planted/, the rig's own test guards) neither breaks it nor
// changes it.
func TestRigHash(t *testing.T) {
	dir := t.TempDir()
	scripts := filepath.Join(dir, "rig")
	os.MkdirAll(filepath.Join(scripts, "planted"), 0o755)
	write := func(p, s string) { os.WriteFile(p, []byte(s), 0o644) }
	write(filepath.Join(scripts, "rig.sh"), "run")
	write(filepath.Join(scripts, "debs.tsv"), "debian 12\tnftables")
	write(filepath.Join(scripts, "planted", "p1.json"), "a planted guard")
	image, agent := filepath.Join(dir, "image"), filepath.Join(dir, "agent")
	write(image, "image")
	write(agent, "agent")
	h0, err := rigHash(scripts, image, agent)
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(scripts, "planted", "p1.json"), "another planted guard")
	if h, err := rigHash(scripts, image, agent); err != nil || h != h0 {
		t.Fatalf("a planted guard changed the rig hash: %v", err)
	}
	for _, f := range []string{filepath.Join(scripts, "debs.tsv"), image, agent} {
		write(f, "changed")
		if h, err := rigHash(scripts, image, agent); err != nil || h == h0 {
			t.Fatalf("%s changed and the hash didn't: %v", f, err)
		}
		h0, _ = rigHash(scripts, image, agent)
	}
}
