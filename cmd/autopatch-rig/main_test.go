package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/jaekwon/autopatch/approve"
)

func TestSign(t *testing.T) {
	g, err := os.ReadFile("../../guard/testdata/cve-2026-98432-ipopt.json")
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(nil)
	seed := []byte(hex.EncodeToString(key.Seed()))
	rig := strings.Repeat("ab", 32)
	good := `{"rig":"single-vm/1","image":"ubuntu-24.04","guard":"73804a3fcab787f11c404c13c46b06eb8452aa585fb7f92429fa7ab98635ed6c","checks":{
		"applies":{"pass":true,"evidence":["applied"]},"probe_blocked":{"pass":true,"evidence":["stopped"]},
		"twice_no_change":{"pass":true,"evidence":[]},"traffic":{"pass":true,"evidence":["ssh login: ok"]},
		"survives":{"pass":true,"evidence":[]},"undo_exact":{"pass":true,"evidence":[]},"nothing_else":{"pass":true,"evidence":[]},
		"traffic_needing_a_client_vm":{"pass":null,"evidence":["not run"]}}}`
	sg, err := Sign(seed, rig, g, []byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if sg.Statement.Kind != approve.KindTested || sg.Statement.Rig != rig || sg.Key != hex.EncodeToString(key.Public().(ed25519.PublicKey)) {
		t.Fatalf("%+v", sg)
	}
	for name, bad := range map[string]string{
		"a failed check":      strings.Replace(good, `"undo_exact":{"pass":true`, `"undo_exact":{"pass":false`, 1),
		"a required not run":  strings.Replace(good, `"survives":{"pass":true`, `"survives":{"pass":null`, 1),
		"a missing check":     strings.Replace(good, `"nothing_else":{"pass":true,"evidence":[]},`, ``, 1),
		"another guard":       strings.Replace(good, `73804a3f`, `00000000`, 1),
		"an extra failed one": strings.Replace(good, `"traffic_needing_a_client_vm":{"pass":null`, `"traffic_needing_a_client_vm":{"pass":false`, 1),
	} {
		if _, err := Sign(seed, rig, g, []byte(bad)); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}
