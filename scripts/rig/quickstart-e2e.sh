#!/bin/bash
# quickstart-e2e.sh SYSTEM RUN: the README's "Try it in two minutes" exactly
# as a reader runs it, in a fresh VM (KVM, no internet): a normal user with
# sudo, and the agent and stopgap one from the latest GitHub release (fetched
# on this host and copied in). It checks that the README's way works end to
# end (plan; apply with its undo armed and its probe; status; undo; the
# machine back as it was), and that two ways that can't work are refused
# without changing the machine: the agent run from a directory its user owns
# (as the first release's notes had it), and, on an image without nft,
# apply itself, before the README's apt-get line puts nftables there.
#
# SYSTEM: "ubuntu 24.04", "debian 12" and so on (scripts/rig/images.tsv).
# Needs: RIG (images/, debs/, seed.iso, rig_ed25519). Touches nothing outside
# $RIG/runs, and the release's assets only by downloading them.
set -euo pipefail
sys=${1:?system, such as "ubuntu 24.04"}; run=${2:?run number}
here=$(cd "$(dirname "$0")" && pwd)
R=${RIG:-/root/repairer-rig}
file=$(awk -F'\t' -v s="$sys" '$1==s {print $2}' "$here/images.tsv")
[ -n "$file" ] || { echo "quickstart-e2e: no image for $sys" >&2; exit 1; }
w=$R/runs/quickstart-$run
port=$((2700 + run % 100))
rel=${REL:-https://github.com/gnosecurity/repairer/releases/latest/download}
rm -rf "$w"; mkdir -p "$w"
log() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$w/log.txt"; }
curl -fsSL -o "$w/repairer-agent-linux-amd64" "$rel/repairer-agent-linux-amd64"
curl -fsSL -o "$w/cve-2026-98432.json" "$rel/cve-2026-98432.json"
log "$sys; release agent sha256 $(sha256sum "$w/repairer-agent-linux-amd64" | cut -c1-16)…"
debs=()
while IFS=$'\t' read -r dsys dfile dsum _; do
  [ "$dsys" = "$sys" ] || continue
  [ "$(sha256sum "$R/debs/$dfile" | cut -d' ' -f1)" = "$dsum" ] || { echo "quickstart-e2e: $dfile isn't the pinned package" >&2; exit 1; }
  debs+=("$R/debs/$dfile")
done < <(grep -v '^#' "$here/debs.tsv")
qemu-img create -q -f qcow2 -F qcow2 -b "$R/images/$file" "$w/disk.qcow2" 8G
qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 \
  -drive file="$w/disk.qcow2",if=virtio -drive file="$R/seed.iso",if=virtio,format=raw,readonly=on \
  -nic user,model=virtio,restrict=on,hostfwd=tcp:127.0.0.1:$port-:22 \
  -display none -serial file:"$w/console.log" -daemonize -pidfile "$w/qemu.pid"
cleanup() { kill "$(cat "$w/qemu.pid" 2>/dev/null)" 2>/dev/null || true; rm -f "$w/disk.qcow2"; }
trap cleanup EXIT
O=(-q -i "$R/rig_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes)
S=(ssh "${O[@]}" -p "$port" rig@127.0.0.1)
for i in $(seq 1 120); do "${S[@]}" true 2>/dev/null && break; sleep 2; done
"${S[@]}" true
scp "${O[@]}" -P "$port" "$w/repairer-agent-linux-amd64" "$w/cve-2026-98432.json" rig@127.0.0.1:
# vm CMD: run CMD as the reader, in their home directory; log its output.
vm() { log "\$ $1"; "${S[@]}" "$1" 2>&1 | tee -a "$w/log.txt" || true; }
# machine: what the guard changes on the machine (the state file is the
# agent's own bookkeeping and is shown apart).
# (Read through /proc and sudo's own path: Debian keeps sysctl and nft in
# /usr/sbin, outside a normal user's PATH.)
machine() {
  "${S[@]}" 'echo "mptcp=$(cat /proc/sys/net/mptcp/enabled) tables=$(if sudo sh -c "command -v nft" >/dev/null; then sudo nft list tables | grep -c repairer; else echo no-nft; fi) timers=$(systemctl list-timers --all --no-legend | grep -c repairer-undo)"'
}
before=$(machine); log "fresh: $before; kernel $("${S[@]}" 'uname -r'); nft: $("${S[@]}" 'sudo sh -c "command -v nft || echo none"')"
fail=0
refused() { # refused WHAT OUTPUT: the run must fail and leave the machine as it was
  echo "$2" >> "$w/log.txt"
  log "$1: $(echo "$2" | grep -v '^exit=' | tail -1)"
  if grep -q '^exit=0$' <<<"$2"; then log "FAIL: $1 went on"; fail=1; fi
  now=$(machine)
  if [ "$now" != "$before" ]; then log "FAIL: $1 changed the machine: $now"; fail=1; fi
}
# 1. As the first release's notes had it: sudo on the binary where curl left it.
"${S[@]}" 'chmod +x repairer-agent-linux-amd64'
refused "sudo from the home directory" "$("${S[@]}" 'sudo ./repairer-agent-linux-amd64 apply cve-2026-98432.json 2>&1; echo "exit=$?"' || true)"
# 2. As the README has it: install where only root can change it.
vm 'sudo install -m 0755 repairer-agent-linux-amd64 /usr/local/sbin/repairer-agent'
if [ ${#debs[@]} -gt 0 ]; then
  refused "apply without nft" "$("${S[@]}" 'sudo repairer-agent apply cve-2026-98432.json 2>&1; echo "exit=$?"' || true)"
  # The README's "sudo apt-get install -y nftables" (no internet here: the pinned packages).
  "${S[@]}" 'mkdir -p debs'
  scp "${O[@]}" -P "$port" "${debs[@]}" rig@127.0.0.1:debs/
  "${S[@]}" 'sudo dpkg -i debs/*.deb >/dev/null && rm -rf debs'
  before=$(machine); log "nftables installed: $before"
fi
plan=$("${S[@]}" 'sudo repairer-agent plan cve-2026-98432.json 2>&1' || true)
echo "$plan" >> "$w/log.txt"
if grep -q "the fix is already running" <<<"$plan"; then
  # The stopgap isn't needed here, and the agent says so: apply must refuse.
  refused "apply where the fix already runs" "$("${S[@]}" 'sudo repairer-agent apply cve-2026-98432.json 2>&1; echo "exit=$?"' || true)"
  if [ $fail = 0 ]; then log "quickstart-e2e $sys: ok (the fixed kernel runs here, so the guard is refused, as it should be)"; else log "quickstart-e2e $sys: FAILED"; fi
  exit $fail
fi
vm 'sudo repairer-agent apply cve-2026-98432.json; echo "exit=$?"'
on=$(machine); log "on: $on"
case "$on" in "mptcp=0 tables=1 timers=1") ;; *) log "FAIL: not on as the README says"; fail=1 ;; esac
vm 'sudo repairer-agent status'
vm 'sudo repairer-agent undo cve-2026-98432/linux-ipv4-ipopt; echo "exit=$?"'
after=$(machine); log "after undo: $after"
if [ "$after" != "$before" ]; then log "FAIL: undo didn't put the machine back"; fail=1; fi
if [ $fail = 0 ]; then log "quickstart-e2e $sys: ok"; else log "quickstart-e2e $sys: FAILED"; fi
exit $fail
