#!/bin/bash
# realm-e2e.sh BIN: the Guards realm on a local chain, end to end. Starts
# gnodev (BIN holds gnodev and gnokey built from gno 5d7d8f5f9) with the
# beacon package and a test build of the realm whose windows are blocks, not
# hours; funds five checkers' accounts from gnodev's public test1 key; each
# stakes a ticket; test1 files guard one's drop for ubuntu 24.04; the draw
# waits for drand evmnet's real round and submits its signature; the three
# drawn checkers commit and open their transcripts; the agreement waits out
# its objection window and is finalized; the level param says "tested". Then
# a ticket nobody drew is unstaked and withdrawn, which takes a new version
# of the stake tree. Prints the gas each call used. Touches only a temporary
# directory, 127.0.0.1, and api.drand.sh (to read public beacon rounds).
set -euo pipefail
B=${1:?the directory with gnodev and gnokey}
repo=$(cd "$(dirname "$0")/.." && pwd)
D=$(mktemp -d)
trap 'kill $(cat "$D/pid" 2>/dev/null) 2>/dev/null || true; rm -rf "$D"' EXIT
export GNOHOME=$D/home
GNOROOT=${GNOROOT:-/root/src/gno-f0}
DRAND=https://api.drand.sh/04f1e9062b8a81f848fded9c12306733282b2727ecced50032187751166ec8c3
ws=$D/ws
mkdir -p "$ws"
printf '[workspace]\n' > "$ws/gnowork.toml"
for p in gno.land/p/nt/ufmt/v0 gno.land/p/nt/avl/v0 gno.land/p/onbloc/uint256/v0; do
  mkdir -p "$ws/$p" && cp "$GNOROOT/examples/$p"/*.gno "$GNOROOT/examples/$p/gnomod.toml" "$ws/$p/"
done
mkdir -p "$ws/p/drandbn254" "$ws/r/guards"
cp "$repo"/gno/p/drandbn254/*.gno "$repo"/gno/p/drandbn254/gnomod.toml "$ws/p/drandbn254/"
cp "$repo"/gno/r/guards/*.gno "$repo"/gno/r/guards/gnomod.toml "$ws/r/guards/"
find "$ws" -name '*_test.gno' -delete
# The test build: windows of a few blocks (gnodev makes a block per
# transaction), a floor of 1 ugnot, a draw three beacon rounds out.
python3 -I - "$ws/r/guards/guards.gno" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
for name, v in [("MinTicketAge", "3"), ("RevealWindow", "50"), ("CheckWindow", "50"), ("DrawDeadline", "40"),
                ("UnbondBlocks", "60"), ("DrawDelay", "3"), ("ObjectionWindow", "2"), ("LevelFloor", "1")]:
    s, n = re.subn(r"(\n\t" + name + r"\s+int64 = )[0-9_]+", r"\g<1>" + v, s)
    assert n == 1, name
open(p, "w").write(s)
PY
"$B/gnodev" local -no-watch -node-rpc-listener 127.0.0.1:36657 -web-listener 127.0.0.1:38888 \
  -extra-root "$ws" > "$D/gnodev.log" 2>&1 &
echo $! > "$D/pid"
for i in $(seq 1 90); do curl -sf -m 2 127.0.0.1:36657/status 2>/dev/null | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null && break; sleep 1; done
printf '%s\n\n\n' "source bonus chronic canvas draft south burst lottery vacant surface solve popular case indicate oppose farm nothing bullet exhibit title speed wink action roast" \
  | "$B/gnokey" add -home "$D/kb" -recover -insecure-password-stdin test1 >/dev/null
addr_of() { "$B/gnokey" list -home "$D/kb" | awk -v k="$1" '$2 == k {print $3}' | tr -d '(),' | sed 's/^addr://'; }
# Five checkers' keys, each funded from test1.
for k in c1 c2 c3 c4 c5; do
  m=$("$B/gnokey" generate)
  printf '%s\n\n\n' "$m" | "$B/gnokey" add -home "$D/kb" -recover -insecure-password-stdin "$k" >/dev/null
done
"$B/gnokey" list -home "$D/kb" > "$D/keys"
addr() { grep -E "^[0-9]+\. $1 " "$D/keys" | grep -oE 'g1[a-z0-9]{38}' | head -1; }
gaslog=$D/gas
call() { # key func [-send N] args...
  local key=$1 fn=$2; shift 2
  echo "" | "$B/gnokey" maketx call -home "$D/kb" -insecure-password-stdin -pkgpath gno.land/r/autopatch/guards \
    -func "$fn" -gas-fee 10000000ugnot -gas-wanted 900000000 -broadcast -chainid dev -remote 127.0.0.1:36657 "$@" "$key" > "$D/call.out" 2>&1 \
    || { echo "call $key $fn: $(tail -8 "$D/call.out")"; tail -20 "$D/gnodev.log"; exit 1; }
  printf '%-14s %s\n' "$fn" "$(grep -oE 'GAS USED: +[0-9]+' "$D/call.out" | grep -oE '[0-9]+')" >> "$gaslog"
}
send() { # key to amount
  echo "" | "$B/gnokey" maketx send -home "$D/kb" -insecure-password-stdin -to "$2" -send "$3" \
    -gas-fee 1000000ugnot -gas-wanted 2000000 -broadcast -chainid dev -remote 127.0.0.1:36657 "$1" > "$D/send.out" 2>&1 \
    || { echo "send: $(tail -5 "$D/send.out")"; exit 1; }
}
qeval() { "$B/gnokey" query vm/qeval -remote 127.0.0.1:36657 -data "gno.land/r/autopatch/guards.$1" 2>&1; }
worker=$(addr test1)
for k in c1 c2 c3 c4 c5; do send test1 "$(addr $k)" 100000000ugnot; done
for k in c1 c2 c3 c4 c5; do call "$k" StakeTicket -send 10000000ugnot; done
call test1 Fund -send 1000000ugnot # blocks pass; the tickets age
call test1 Fund -send 1000000ugnot
call test1 Fund -send 1000000ugnot
# test1 files guard one's drop for ubuntu 24.04, its transcript "aaaa... pass".
guard=$(cat "$repo/guard/testdata/cve-2026-98432-ipopt.json")
tr="$(printf 'a%.0s' $(seq 64)) pass"
C() { python3 -I -c 'import hashlib,sys; print(hashlib.sha256("\0".join(sys.argv[1:5]).encode()).hexdigest())' "$@"; }
gh=$(python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read().rstrip(b"\n")).hexdigest())' "$repo/guard/testdata/cve-2026-98432-ipopt.json")
tc=$(C "$worker" transcript "$tr" t)
commit=$(python3 -I -c 'import hashlib,sys; a,gh,sysn,tc=sys.argv[1:5]; print(hashlib.sha256((a+"\0guard\0"+gh+"\0"+sysn+"\0"+tc+"\0s").encode()).hexdigest())' "$worker" "$gh" "ubuntu 24.04" "$tc")
call test1 Commit -send 1000000ugnot -args "$commit"
call test1 Reveal -args 0 -args "$guard" -args "ubuntu 24.04" -args "$tc" -args s
round=$(qeval 'State(0)' | grep -oE '\([0-9]+ uint64\)' | grep -oE '[0-9]+' | head -1)
[ -n "$round" ] || { echo "no round in State(0): $(qeval 'State(0)')"; exit 1; }
echo "the reveal fixed drand round $round; waiting for it"
for i in $(seq 1 60); do
  sig=$(curl -sf -m 5 "$DRAND/public/$round" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["signature"])' 2>/dev/null || true)
  [ -n "$sig" ] && break
  sleep 2
done
[ -n "$sig" ] || { echo "drand round $round never came"; exit 1; }
call test1 SubmitBeacon -args "$round" -args "$sig"
call test1 Draw -args 0
drawn=$(qeval 'State(0)' | grep -oE 'g1[a-z0-9]{38}')
echo "drawn: $(echo $drawn)"
[ "$(echo "$drawn" | wc -l)" = 3 ] || { echo "not three checkers: $drawn"; exit 1; }
keyof() { for k in c1 c2 c3 c4 c5; do [ "$(addr $k)" = "$1" ] && echo "$k"; done; }
for a in $drawn; do call "$(keyof "$a")" CommitCheck -args 0 -args "$(C "$a" check "$tr" "c-$a")"; done
call test1 RevealCheck -args 0 -args "$tr" -args t
for a in $drawn; do call "$(keyof "$a")" RevealCheck -args 0 -args "$tr" -args "c-$a"; done
call test1 Settle -args 0
qeval 'State(0)' | grep -q '"agreed"' || { echo "not agreed: $(qeval 'State(0)')"; exit 1; }
call test1 Fund -send 1000000ugnot # the objection window passes
call test1 Fund -send 1000000ugnot
call test1 Fund -send 1000000ugnot
call test1 Finalize -args 0
lvl=$(qeval "Level(\"$gh\", \"ubuntu 24.04\")")
echo "$lvl" | grep -q '"tested"' || { echo "level: $lvl"; exit 1; }
# A ticket nobody drew leaves: unstaked, and withdrawn after unbonding.
for k in c1 c2 c3 c4 c5; do echo "$drawn" | grep -q "$(addr $k)" || { free=$k; break; }; done
tid=$(( ${free#c} - 1 ))
call "$free" Unstake -args "$tid"
for i in $(seq 1 61); do call test1 Fund -send 1ugnot; done
before=$("$B/gnokey" query bank/balances/"$(addr $free)" -remote 127.0.0.1:36657 | grep -oE '[0-9]+ugnot' | grep -oE '[0-9]+')
call "$free" Withdraw -args "$tid"
after=$("$B/gnokey" query bank/balances/"$(addr $free)" -remote 127.0.0.1:36657 | grep -oE '[0-9]+ugnot' | grep -oE '[0-9]+')
echo "withdrew $(( after - before + 10000000 )) ugnot with the fee added back"
grep -v '^Fund' "$gaslog" | sort | awk '{n[$1]++; s[$1]+=$2; if ($2>m[$1]) m[$1]=$2} END {for (f in n) printf "%-14s %3d calls, most %11d gas, mean %11d\n", f, n[f], m[f], s[f]/n[f]}' | sort
echo "realm-e2e: ok, level tested on chain at round $round"
