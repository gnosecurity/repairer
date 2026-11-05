#!/bin/bash
# hit-e2e.sh RUN: W1's was-I-hit test in a fresh Ubuntu 24.04 VM on this
# machine (KVM, no internet). The agent goes in; the owner's signed Check of
# new setuid files finds none; then a setuid copy of bash is planted, a
# copied program is started and deleted, a file of base-files is changed,
# another made a FIFO, and one of its conffiles edited; the next Checks find
# each of them, by path, the conffile apart, without waiting on the FIFO.
# Then the other kinds, on the real machine: its loaded modules all come
# from packages, and the logins as rig show in the auth log and in ssh's
# journal, with history reaching back. Every report verifies against the
# agent's key. A result never carries a file's contents.
#
# Needs: RIG (images/, seed.iso, rig_ed25519), SRC (the autopatch source).
# Touches nothing outside $RIG/runs.
set -euo pipefail
run=${1:?run number}
R=${RIG:-/root/autopatch-rig}; SRC=${SRC:-/root/src/autopatch}
img=$R/images/ubuntu-24.04-server-cloudimg-amd64.img
w=$R/runs/hit-$run
port=$((2600 + run % 100))
rm -rf "$w"; mkdir -p "$w"
source /etc/profile.d/dev.sh
(cd "$SRC" && CGO_ENABLED=0 go build -trimpath -o "$w/autopatch-agent" ./cmd/autopatch-agent && go build -o "$w/e2e" ./scripts/e2e)
since=$(date -u +%s)
"$w/e2e" gencheck "$w/in" "$since" base-files
qemu-img create -q -f qcow2 -F qcow2 -b "$img" "$w/disk.qcow2" 8G
qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 \
  -drive file="$w/disk.qcow2",if=virtio -drive file="$R/seed.iso",if=virtio,format=raw,readonly=on \
  -nic user,model=virtio,restrict=on,hostfwd=tcp:127.0.0.1:$port-:22 \
  -display none -serial file:"$w/console.log" -daemonize -pidfile "$w/qemu.pid"
cleanup() { kill "$(cat "$w/qemu.pid" 2>/dev/null)" 2>/dev/null || true; rm -f "$w/disk.qcow2"; }
trap cleanup EXIT
S=(ssh -q -i "$R/rig_ed25519" -p "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o BatchMode=yes rig@127.0.0.1) # a reboot mid-call ends the call
waitssh() { for i in $(seq 1 120); do "${S[@]}" true 2>/dev/null && return 0; sleep 2; done; return 1; }
log() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$w/log.txt"; }
waitssh
scp -q -i "$R/rig_ed25519" -P "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "$w/autopatch-agent" "$w/in/policy.json" "$w"/in/check-*.json rig@127.0.0.1:
"${S[@]}" 'sudo install -o root -g root -m 0755 autopatch-agent /usr/local/sbin/autopatch-agent && sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin autopatch'
"${S[@]}" 'sudo /usr/local/sbin/autopatch-agent install' >> "$w/log.txt" 2>&1
key=$("${S[@]}" 'sudo /usr/local/sbin/autopatch-agent init -host vm1 -seq 0 -intake-user autopatch /home/rig/policy.json' | tail -1)
log "init: agent key $key"
n=0
# ask N NAME MIN PREV: deliver Check N through intake and wait for the
# report to carry a result of check NAME other than PREV, among at least
# MIN results; print it.
ask() {
  "${S[@]}" "sudo -u autopatch /usr/local/sbin/autopatch-agent intake < /home/rig/check-$1.json" >> "$w/log.txt" 2>&1
  for i in $(seq 1 12); do
    sleep 20; n=$((n+1))
    "${S[@]}" 'sudo -u autopatch /usr/local/sbin/autopatch-agent report' > "$w/report-$n.json" 2>/dev/null || continue
    "$w/e2e" verify "$w/report-$n.json" "$key" > "$w/summary-$n.txt" 2>&1 || { log "VERIFY FAILED: $(cat "$w/summary-$n.txt")"; return 1; }
    line=$(grep -m1 "^  hit: e2e/$2 v1 " "$w/summary-$n.txt" || true)
    if [ -n "$line" ] && [ "$line" != "${4:-}" ] && [ "$(grep -c '^  hit:' "$w/summary-$n.txt")" -ge "$3" ]; then
      echo "$line"
      return 0
    fi
  done
  log "Check $1 never came back"; return 1
}
clean=$(ask 1 new-since 1 ""); log "before planting: $clean"
pkgfile=$("${S[@]}" "grep -m1 -E '  usr/share/' /var/lib/dpkg/info/base-files.md5sums | cut -c35-")
fifo=$("${S[@]}" "grep -E '  usr/share/' /var/lib/dpkg/info/base-files.md5sums | sed -n 2p | cut -c35-")
"${S[@]}" "sudo bash -s" >> "$w/log.txt" 2>&1 <<SH
set -e
cp /bin/bash /var/tmp/.s && chmod u+s /var/tmp/.s
cp /bin/sleep /var/tmp/sl && (setsid /var/tmp/sl 900 >/dev/null 2>&1 < /dev/null &) && sleep 1 && rm /var/tmp/sl
echo "#" >> "/$pkgfile"
rm "/$fifo" && mkfifo "/$fifo"
echo "#" >> /etc/issue.net
SH
log "planted: /var/tmp/.s (setuid bash), /var/tmp/sl (running, deleted), /$pkgfile (changed), /$fifo (a FIFO), /etc/issue.net (a conffile, changed)"
setuid=$(ask 2 new-since 1 "$clean"); log "setuid: $setuid"
deleted=$(ask 3 deleted-exe 2 ""); log "deleted: $deleted"
files=$(ask 4 package-files 3 ""); log "package files: $files"
mods=$(ask 5 foreign-modules 4 ""); log "modules: $mods"
auth=$(ask 6 log-auth 5 ""); log "auth log: $auth"
unit=$(ask 7 log-unit 6 ""); log "ssh's journal: $unit"
ok=no
[[ $clean == *"flag=false count=0"* ]] && [[ $setuid == *"flag=true"*"/var/tmp/.s"* ]] && [[ $deleted == *"flag=true"*'error=""'*"/var/tmp/sl"* ]] &&
  [[ $files == *"flag=true count=2 "*"conf=1 "*"/$pkgfile"* ]] && [[ $files == *"/$fifo"* ]] && [[ $files == *"conf_paths=/etc/issue.net"* ]] &&
  [[ $mods == *'flag=false count=0 '*'capped="" error=""'* ]] &&
  [[ $auth == *'flag=true '*'capped="" error=""'* ]] && [[ $unit == *'flag=true '*'capped="" error=""'* ]] && ok=yes
log "hit e2e run $run took ${SECONDS}s; ok=$ok"
[ "$ok" = yes ]
