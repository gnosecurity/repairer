package signer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/approve"
)

// fakeGnokey is a gnokey stand-in. maketx fails unless it is told not to
// broadcast and given the dead remote; sign fails unless the fee was set to
// zero, and then writes back a given signed file in place of signing.
func fakeGnokey(t *testing.T, signedFile string) string {
	t.Helper()
	script := `#!/bin/sh
args="$*"
case "$args" in *"-remote 127.0.0.1:1"*) ;; *) echo "a reachable remote" >&2; exit 3;; esac
if [ "$1 $2" = "maketx call" ]; then
  case "$args" in *"-broadcast=false"*) ;; *) echo "would broadcast" >&2; exit 3;; esac
  echo '{"msg":[{"@type":"/vm.m_call","caller":"g1ss6w8xfy7vnp595yely63jqa8553k03mjcglen","send":"","max_deposit":"","pkg_path":"gno.land/r/autopatch/approve","func":"Yes","args":[]}],"fee":{"gas_wanted":"1","gas_fee":"1ugnot"},"signatures":null,"memo":"x"}'
  exit 0
fi
while [ $# -gt 0 ]; do [ "$1" = "-tx-path" ] && p="$2"; shift; done
grep -q '"gas_fee":"0ugnot"' "$p" || { echo "fee not zero" >&2; exit 4; }
cp "` + signedFile + `" "$p"
`
	path := filepath.Join(t.TempDir(), "gnokey")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSignChecksWhatGnokeyWrote(t *testing.T) {
	old, _ := fixturePolicies(t)
	g := guardOne(t)
	abs, err := filepath.Abs("../approve/testdata/yes-guard-one.json")
	if err != nil {
		t.Fatal(err)
	}
	gk := Gnokey{Bin: fakeGnokey(t, abs), Key: "owner"}
	y := approve.Yes{Tiers: []string{"A"}, Until: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), Mode: "undo"}
	// The statement the signed file is: accepted.
	st, _ := PrepareYes(old, g, y, 7)
	if _, err := gk.Sign(context.Background(), st, owner(t)); err != nil {
		t.Fatal(err)
	}
	// Any other statement: the file gnokey wrote back is refused.
	y.Mode = "keep"
	st2, _ := PrepareYes(old, g, y, 7)
	if _, err := gk.Sign(context.Background(), st2, owner(t)); err == nil || !strings.Contains(err.Error(), "wouldn't pass an agent") {
		t.Fatalf("a file for another statement: %v", err)
	}
}
