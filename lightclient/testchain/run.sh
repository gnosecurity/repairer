#!/bin/bash
# run.sh BIN: the light client's test against a local chain. Starts gnodev
# with the guards realm, sets one guard's level with gnodev's public test
# key, and runs the test at a height where the level is set. BIN holds
# gnodev and gnokey. Touches only a temporary directory and 127.0.0.1.
set -euo pipefail
B=${1:?the directory with gnodev and gnokey}
here=$(cd "$(dirname "$0")" && pwd)
D=$(mktemp -d)
trap 'kill $(cat "$D/pid" 2>/dev/null) 2>/dev/null || true; rm -rf "$D"' EXIT
export GNOHOME=$D/home
"$B/gnodev" local -no-watch -node-rpc-listener 127.0.0.1:36657 -web-listener 127.0.0.1:38888 -paths "" "$here/guards" > "$D/gnodev.log" 2>&1 &
echo $! > "$D/pid"
for i in $(seq 1 60); do curl -sf -m 2 127.0.0.1:36657/status 2>/dev/null | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null && break; sleep 1; done
# gnodev's default account is the public test1 key.
printf '%s\n\n\n' "source bonus chronic canvas draft south burst lottery vacant surface solve popular case indicate oppose farm nothing bullet exhibit title speed wink action roast" \
  | "$B/gnokey" add -home "$D/kb" -recover -insecure-password-stdin test1 >/dev/null
echo "" | "$B/gnokey" maketx call -home "$D/kb" -insecure-password-stdin -pkgpath gno.land/r/autopatch/guards -func SetLevel \
  -args 73804a3fcab787f11c404c13c46b06eb8452aa585fb7f92429fa7ab98635ed6c -args tested \
  -gas-fee 1000000ugnot -gas-wanted 20000000 -broadcast -chainid dev -remote 127.0.0.1:36657 test1 >/dev/null
sleep 3
H=$(curl -s -m 2 127.0.0.1:36657/status | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['sync_info']['latest_block_height'])")
cd "$here/.." && LC_RPC=http://127.0.0.1:36657 LC_HEIGHT=$((H-1)) go test -count=1 -v ./...
