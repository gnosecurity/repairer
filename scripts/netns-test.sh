#!/bin/bash
# Runs the agent's integration test as root in a fresh network namespace, so
# the guard's firewall table and network settings never touch the machine's
# own. Files the agent writes go to a temporary directory.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "netns-test: run as root" >&2; exit 1; }
cd "$(dirname "$0")/.."
dir=$(mktemp -d)
ns=repairer-test-$$
cleanup() { ip netns del "$ns" 2>/dev/null || true; rm -rf "$dir"; }
trap cleanup EXIT
go test -c -tags integration -o "$dir/agent.test" ./agent
host_mptcp=$(sysctl -n net.mptcp.enabled)
ip netns add "$ns"
ip netns exec "$ns" ip link set lo up
(cd agent && ip netns exec "$ns" env REPAIRER_NETNS=1 "$dir/agent.test" -test.run Integration -test.v -test.count=1)
[ "$(sysctl -n net.mptcp.enabled)" = "$host_mptcp" ] || { echo "netns-test: the host's net.mptcp.enabled changed" >&2; exit 1; }
echo "netns-test: ok; the host's own settings are unchanged"
