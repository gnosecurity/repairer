#!/bin/bash
# site-e2e.sh BIN: H1's test against a local chain. Starts gnodev (BIN holds
# gnodev and gnokey built from gno 5d7d8f5f9) with the beacon package and the
# Guards realm, stakes a ticket, files and reveals guard one's drop with
# gnodev's public test key, builds the site from that node, and checks its
# pages. Touches only a temporary directory and 127.0.0.1.
set -euo pipefail
B=${1:?the directory with gnodev and gnokey}
repo=$(cd "$(dirname "$0")/.." && pwd)
D=$(mktemp -d)
trap 'kill $(cat "$D/pid" 2>/dev/null) 2>/dev/null || true; rm -rf "$D"' EXIT
export GNOHOME=$D/home
# One workspace with the beacon package, the realm and the example packages
# they import (gnodev loads a workspace in dependency order, but before the
# examples), without test files. GNOROOT is gno's source at 5d7d8f5f9.
GNOROOT=${GNOROOT:-/root/src/gno-f0}
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
"$B/gnodev" local -no-watch -node-rpc-listener 127.0.0.1:36657 -web-listener 127.0.0.1:38888 \
  -extra-root "$ws" > "$D/gnodev.log" 2>&1 &
echo $! > "$D/pid"
for i in $(seq 1 90); do curl -sf -m 2 127.0.0.1:36657/status 2>/dev/null | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null && break; sleep 1; done
# gnodev's default account is the public test1 key.
printf '%s\n\n\n' "source bonus chronic canvas draft south burst lottery vacant surface solve popular case indicate oppose farm nothing bullet exhibit title speed wink action roast" \
  | "$B/gnokey" add -home "$D/kb" -recover -insecure-password-stdin test1 >/dev/null
addr=g1jg8mtutu9khhfwc4nxmuhcpftf0pajdhfvsqf5
call() {
  echo "" | "$B/gnokey" maketx call -home "$D/kb" -insecure-password-stdin -pkgpath gno.land/r/autopatch/guards \
    -gas-fee 10000000ugnot -gas-wanted 300000000 -broadcast -chainid dev -remote 127.0.0.1:36657 "$@" test1 > "$D/call.out" 2>&1 \
    || { echo "call $*: $(tail -5 "$D/call.out")"; tail -20 "$D/gnodev.log"; exit 1; }
}
call -func StakeTicket -send 10000000ugnot
guard=$(cat "$repo/guard/testdata/cve-2026-98432-ipopt.json")
read -r tc commit < <(python3 -I - "$addr" "$repo/guard/testdata/cve-2026-98432-ipopt.json" <<'PY'
import hashlib, sys
addr, path = sys.argv[1], sys.argv[2]
c = lambda kind, payload, salt: hashlib.sha256((addr + "\0" + kind + "\0" + payload + "\0" + salt).encode()).hexdigest()
gh = hashlib.sha256(open(path, "rb").read().rstrip(b"\n")).hexdigest()
tc = c("transcript", "a" * 64 + " pass", "t")
print(tc, c("guard", gh + "\0" + tc, "s"))
PY
)
call -func Commit -args "$commit" -send 1000000ugnot
call -func Reveal -args 0 -args "$guard" -args "$tc" -args s
cd "$repo" && go run ./cmd/autopatch-site -rpc http://127.0.0.1:36657 -out "$D/site"
fail() { echo "FAIL: $1"; exit 1; }
grep -q '<a href="filing/0.html">filing 0</a>: revealed' "$D/site/index.html" || fail "the index: $(cat "$D/site/index.html")"
grep -q 'cve-2026-98432/linux-ipv4-ipopt' "$D/site/filing/0.html" || fail "the guard isn't on its filing's page"
grep -q "<a href=\"../address/$addr.html\">$addr</a>" "$D/site/filing/0.html" || fail "no link to the filer's record"
grep -q 'Filings tested: 0' "$D/site/address/$addr.html" || fail "the filer's record"
gh=$(python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read().rstrip(b"\n")).hexdigest())' "$repo/guard/testdata/cve-2026-98432-ipopt.json")
[ -f "$D/site/guard/$gh.html" ] || fail "no page for the guard's hash"
echo "site-e2e: ok, $(find "$D/site/" -name '*.html' | wc -l) pages from the chain"
