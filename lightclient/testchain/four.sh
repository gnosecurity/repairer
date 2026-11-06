#!/bin/bash
# four.sh BIN: the light client follows real validator changes on a local
# gnoland chain of five nodes (BIN holds gnoland and gnokey; GNOROOT is the
# gno checkout they were built from). Node 1 validates from genesis; nodes
# 2-5 follow. GovDAO (test1 alone, as chain "dev" allows) makes nodes 2, 3
# and 4 validators through their operators (the set trusted at the
# checkpoint signs over to them), then adds node 5 and removes 2 and 3 (too
# much change at once for the set trusted then, so the client steps through
# the heights between). A level is set after each change, and the Go test
# proves each from a client started at the checkpoint. Touches only a
# temporary directory and 127.0.0.1.
set -euo pipefail
B=${1:?the directory with gnoland and gnokey}
here=$(cd "$(dirname "$0")" && pwd)
D=$(mktemp -d)
cleanup() {
  for p in "$D"/n*.pid; do kill "$(cat "$p")" 2>/dev/null || true; done
  sleep 1
  if [ -n "${KEEP:-}" ]; then echo "kept $D"; else rm -rf "$D"; fi
}
trap cleanup EXIT
log() { echo "$(date -u +%H:%M:%S) $*"; }
rpcport() { echo $((21650 + $1)); } # below the ephemeral range (32768 on), so no outgoing connection holds one
R=127.0.0.1:$(rpcport 1)
: > "$D/empty.jsonl"

# Five nodes on 127.0.0.1: one-second blocks, everyone a persistent peer of
# everyone.
for i in 1 2 3 4 5; do
  "$B/gnoland" secrets init -data-dir "$D/n$i/secrets" >/dev/null 2>&1
  "$B/gnoland" config init -config-path "$D/n$i/config/config.toml" >/dev/null 2>&1
done
id() { "$B/gnoland" secrets get -data-dir "$D/n$1/secrets" node_id.id 2>/dev/null | tr -d '"[:space:]'; }
pub() { "$B/gnoland" secrets get -data-dir "$D/n$1/secrets" validator_key.pub_key 2>/dev/null | tr -d '"[:space:]'; }
for i in 1 2 3 4 5; do
  peers=""
  for j in 1 2 3 4 5; do
    [ "$i" = "$j" ] || peers="$peers${peers:+,}$(id "$j")@127.0.0.1:$((21660 + j))"
  done
  c=(-config-path "$D/n$i/config/config.toml")
  "$B/gnoland" config set "${c[@]}" rpc.laddr "tcp://127.0.0.1:$(rpcport "$i")" >/dev/null
  "$B/gnoland" config set "${c[@]}" p2p.laddr "tcp://127.0.0.1:$((21660 + i))" >/dev/null
  "$B/gnoland" config set "${c[@]}" p2p.persistent_peers "$peers" >/dev/null
  "$B/gnoland" config set "${c[@]}" p2p.allow_duplicate_ip true >/dev/null
  "$B/gnoland" config set "${c[@]}" p2p.pex false >/dev/null
  "$B/gnoland" config set "${c[@]}" consensus.timeout_commit 1s >/dev/null
done
start() {
  # The genesis' example packages are signed by keys this chain doesn't
  # have; a local chain skips that check.
  "$B/gnoland" start "$@" -skip-genesis-sig-verification -data-dir "$D/n$N" -genesis "$D/genesis.json" \
    -genesis-txs-file "$D/empty.jsonl" > "$D/n$N.log" 2>&1 &
  echo $! > "$D/n$N.pid"
}
height() { curl -sf -m 2 "$1/status" | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['sync_info']['latest_block_height'])"; }
# Node 1 writes the genesis (every example package, test1 funded, itself
# the one validator) and starts; the others start from that genesis.
N=1 start -lazy
for i in $(seq 1 180); do h=$(height "$R" 2>/dev/null || true); [ -n "$h" ] && [ "$h" -ge 1 ] && break; sleep 1; done
for N in 2 3 4 5; do start; done
for i in $(seq 1 120); do
  ok=yes
  for n in 2 3 4 5; do h=$(height "127.0.0.1:$(rpcport $n)" 2>/dev/null || true); [ -n "$h" ] && [ "$h" -ge 2 ] || ok=no; done
  [ $ok = yes ] && break; sleep 1
done
[ $ok = yes ] || { log "the other nodes didn't catch up"; tail -20 "$D/n2.log"; exit 1; }
CP=$(height "$R")
log "five nodes up; the checkpoint is height $CP (node 1 alone validates)"

# test1 (gnodev's public test key) is the chain's funded account; operators
# for nodes 2-5 come from the same seed at other indexes.
M="source bonus chronic canvas draft south burst lottery vacant surface solve popular case indicate oppose farm nothing bullet exhibit title speed wink action roast"
printf '%s\n\n\n' "$M" | "$B/gnokey" add -home "$D/kb" -recover -insecure-password-stdin test1 >/dev/null 2>&1
for i in 2 3 4 5; do
  printf '%s\n\n\n' "$M" | "$B/gnokey" add -home "$D/kb" -recover -index "$i" -insecure-password-stdin "op$i" >/dev/null 2>&1
done
addr() { "$B/gnokey" list -home "$D/kb" | sed -n "s/.*\. $1 (local) - addr: \(g1[a-z0-9]*\) .*/\1/p"; }
tx() { # tx KEY ARGS...: one transaction, waiting for its block; prints the height.
  local k=$1; shift
  local out
  out=$(echo "" | "$B/gnokey" maketx "$@" -gas-fee 10000000ugnot -gas-wanted 200000000 -broadcast -chainid dev \
    -remote "$R" -home "$D/kb" -insecure-password-stdin "$k" 2>&1) || { echo "$out" >&2; return 1; }
  echo "$out" | sed -n 's/^HEIGHT: *//p'
}
for i in 2 3 4 5; do
  tx test1 send -send 100000000000ugnot -to "$(addr "op$i")" >/dev/null
  tx "op$i" call -pkgpath gno.land/r/gnops/valopers -func Register -args "node$i" -args "a local test node" \
    -args on-prem -args "$(addr "op$i")" -args "$(pub "$i")" >/dev/null
done
log "operators 2-5 registered"
cat > "$D/dao.gno" <<EOF
package main

import daoinit "gno.land/r/gov/dao/init/v0"

func main(cur realm) {
	daoinit.InitWithUsers(cross(cur), address("$(addr test1)"))
}
EOF
# maketx run takes the key name before the file.
echo "" | "$B/gnokey" maketx run -gas-fee 10000000ugnot -gas-wanted 200000000 -broadcast -chainid dev -remote "$R" \
  -home "$D/kb" -insecure-password-stdin test1 "$D/dao.gno" >/dev/null
prop() { # prop TITLE CHANGES: propose, vote and execute one valset change
  cat > "$D/prop.gno" <<EOF
package main

import (
	"gno.land/r/gov/dao"
	vals "gno.land/r/sys/validators/v0"
)

func main(cur realm) {
	req := vals.NewValidatorProposalRequest(cross(cur), []vals.ValoperChange{$2}, "$1", "")
	id := dao.MustCreateProposal(cross(cur), req)
	dao.MustVoteOnProposal(cross(cur), dao.NewVoteRequest(dao.YesVote, id))
	if !dao.ExecuteProposal(cross(cur), id) {
		panic("the proposal didn't pass")
	}
}
EOF
  echo "" | "$B/gnokey" maketx run -gas-fee 10000000ugnot -gas-wanted 200000000 -broadcast -chainid dev -remote "$R" \
    -home "$D/kb" -insecure-password-stdin test1 "$D/prop.gno" | sed -n 's/^HEIGHT: *//p'
}
nvals() { curl -sf -m 2 "$R/validators" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['result']['validators']))"; }
waitvals() { # waitvals N: until the chain's set has N validators, then two more blocks
  for i in $(seq 1 60); do [ "$(nvals)" = "$1" ] && break; sleep 1; done
  [ "$(nvals)" = "$1" ] || { log "the set never reached $1"; exit 1; }
  local h; h=$(height "$R"); while [ "$(height "$R")" -lt $((h + 2)) ]; do sleep 1; done
}
ch() { echo "vals.NewValoperChange(address(\"$(addr "op$1")\"), $2)"; }
tx test1 addpkg -pkgdir "$here/lcspike" -pkgpath gno.land/r/repairer/lcspike -max-deposit 100000000ugnot >/dev/null
A=$(prop "nodes 2, 3 and 4 join" "$(ch 2 10), $(ch 3 10), $(ch 4 10)")
waitvals 4
H1=$(tx test1 call -pkgpath gno.land/r/repairer/lcspike -func SetLevel -args one -args tested)
log "change A at $A: four validators; level one set at $H1"
Bh=$(prop "node 5 joins, 2 and 3 leave" "$(ch 5 10), $(ch 2 0), $(ch 3 0)")
waitvals 3
H2=$(tx test1 call -pkgpath gno.land/r/repairer/lcspike -func SetLevel -args two -args tested)
log "change B at $Bh: nodes 1, 4 and 5 validate; level two set at $H2"
# Two more blocks, so header H2+1 exists.
while [ "$(height "$R")" -lt $((H2 + 2)) ]; do sleep 1; done
cd "$here/.." && LC_FOUR_RPC=http://$R LC_FOUR_CP=$CP LC_FOUR_H1=$H1 LC_FOUR_H2=$H2 \
  go test -count=1 -v -run TestFollowsARealChain ./...
