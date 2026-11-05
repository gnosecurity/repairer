#!/bin/bash
# rig.sh GUARD.json OUT.json: the rig's checks of one guard in a fresh Ubuntu
# 24.04 VM on this machine (KVM, no internet). Writes a transcript: canonical
# JSON with no times, ports, process ids or MACs, one entry per check with
# pass or fail and sorted evidence. Single-VM rig (D1a): the traffic checks
# that need a client VM and a router are listed as not run.
#
# Needs: RIG (the rig directory: images/, seed.iso, rig_ed25519) and AGENT
# (the autopatch-agent binary). Touches nothing outside $RIG/runs.
set -euo pipefail
guard=$(readlink -f "${1:?guard file}"); outfile=${2:?transcript file}
R=${RIG:?the rig directory}; AGENT=$(readlink -f "${AGENT:?the agent binary}")
here=$(dirname "$(readlink -f "$0")")
img=$R/images/ubuntu-24.04-server-cloudimg-amd64.img
w=$(mktemp -d "$R/runs/rig-XXXXXX")
port=$((2600 + RANDOM % 300))
qemu-img create -q -f qcow2 -F qcow2 -b "$img" "$w/disk.qcow2" 8G
boot() {
  qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 \
    -drive file="$w/disk.qcow2",if=virtio -drive file="$R/seed.iso",if=virtio,format=raw,readonly=on \
    -nic user,model=virtio,restrict=on,hostfwd=tcp:127.0.0.1:$port-:22 \
    -display none -serial file:"$w/console.log" -daemonize -pidfile "$w/qemu.pid"
}
cleanup() { kill "$(cat "$w/qemu.pid" 2>/dev/null)" 2>/dev/null || true; rm -rf "$w"; }
trap cleanup EXIT
S=(ssh -q -i "$R/rig_ed25519" -p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes rig@127.0.0.1)
waitssh() { for i in $(seq 1 90); do "${S[@]}" true 2>/dev/null && return 0; sleep 2; done; return 1; }
snap() { "${S[@]}" 'sudo python3 -I -' < "$here/snapshot.py"; }
boot; waitssh
CP=(scp -q -i "$R/rig_ed25519" -P $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
"${CP[@]}" "$AGENT" rig@127.0.0.1:autopatch-agent
"${CP[@]}" "$guard" rig@127.0.0.1:
"${S[@]}" 'sudo install -o root -g root -m 0755 autopatch-agent /usr/local/sbin/autopatch-agent && sudo /usr/local/sbin/autopatch-agent install >/dev/null && for i in $(ls /sys/class/net); do [ "$i" = lo ] || sudo ip link set dev "$i" mtu 1280; done'
A="sudo /usr/local/sbin/autopatch-agent"
G=/home/rig/$(basename "$guard")
declare -A pass ev
check() { pass[$1]=$2; ev[$1]=$3; }
snap > "$w/s0.json"
if out=$("${S[@]}" "$A apply -confirm-within 0 $G" 2>&1); then check applies true "applied"; else check applies false "$out"; fi
st=$("${S[@]}" "$A status" 2>&1 || true)
if echo "$st" | grep -q "stopped [1-9]"; then check probe_blocked true "the guard's rule stopped the probe"
elif ! grep -q '"drop"' "$guard"; then check probe_blocked true "no drop to probe"
else check probe_blocked false "$st"; fi
snap > "$w/s1.json"
"${S[@]}" "$A apply -confirm-within 0 $G" >/dev/null 2>&1 || true
snap > "$w/s2.json"
if cmp -s "$w/s1.json" "$w/s2.json"; then check twice_no_change true "the second apply changed nothing"; else check twice_no_change false "$(diff <(tr , '\n' < "$w/s1.json") <(tr , '\n' < "$w/s2.json") | head -5)"; fi
# Everyday traffic one VM can show: a fresh ssh login, a large transfer both ways over a 1280-byte MTU,
# names, time, IPv6 loopback. A client VM and a router (https, mail, DNS answers, p2p) come with D1.
head -c 8000000 /dev/urandom > "$w/big"
t=()
"${S[@]}" true && t+=("ssh login: ok") || t+=("ssh login: FAILED")
scp -q -i "$R/rig_ed25519" -P $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$w/big" rig@127.0.0.1:big \
  && scp -q -i "$R/rig_ed25519" -P $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null rig@127.0.0.1:big "$w/big.back" \
  && cmp -s "$w/big" "$w/big.back" && t+=("8 MB both ways at MTU 1280: ok") || t+=("8 MB both ways at MTU 1280: FAILED")
"${S[@]}" 'getent hosts localhost >/dev/null' && t+=("names: ok") || t+=("names: FAILED")
"${S[@]}" 'systemctl is-active --quiet systemd-timesyncd || systemctl is-active --quiet chrony' && t+=("time service: ok") || t+=("time service: FAILED")
"${S[@]}" 'ping -6 -c1 -W2 ::1 >/dev/null' && t+=("IPv6: ok") || t+=("IPv6: FAILED")
if printf '%s\n' "${t[@]}" | grep -q FAILED; then check traffic false "$(printf '%s; ' "${t[@]}")"; else check traffic true "$(printf '%s; ' "${t[@]}")"; fi
# Every running unit restarted (but the ones that would end the session), and one run of every timer.
"${S[@]}" 'for u in $(systemctl list-units --type=service --state=running --no-legend --plain | awk "{print \$1}" | grep -vE "^(dbus|systemd-|ssh|getty|serial-getty|user@)"); do sudo systemctl restart "$u" || true; done
  for t in $(systemctl list-timers --all --no-legend --plain | awk "{print \$NF}" | grep "\.timer$"); do s=$(systemctl show -p Unit --value "$t"); sudo systemctl start "$s" || true; done' >/dev/null 2>&1 || true
if out=$("${S[@]}" "$A check" 2>&1) && echo "$out" | grep -q "as set"; then r1="after restarts and timers: as set"; else r1="after restarts and timers: $out"; fi
"${S[@]}" 'sudo systemctl reboot' >/dev/null 2>&1 || true
sleep 5; waitssh
if out=$("${S[@]}" "$A check" 2>&1) && echo "$out" | grep -q "as set"; then r2="after a reboot: as set"; else r2="after a reboot: $out"; fi
if [[ $r1 == *"as set" && $r2 == *"as set" ]]; then check survives true "$r1; $r2"; else check survives false "$r1; $r2"; fi
# Nothing else changed: after the reboot, against before the guard, only what the guard declares.
snap > "$w/s3.json"
H=$("${S[@]}" "$A status" | awk 'NR==1{print $1}')
"${S[@]}" "$A undo $H" >/dev/null 2>&1 || true
snap > "$w/s4.json"
if cmp -s "$w/s0.json" "$w/s4.json"; then check undo_exact true "after undo the machine is as it was"; else check undo_exact false "$(python3 "$here/diffkeys.py" "$w/s0.json" "$w/s4.json" -)"; fi
extra=$(python3 "$here/diffkeys.py" "$w/s0.json" "$w/s3.json" "$guard")
if [ -z "$extra" ]; then check nothing_else true "only what the guard declares changed"; else check nothing_else false "also changed: $extra"; fi
for k in "${!pass[@]}"; do printf '%s\t%s\t%s\n' "$k" "${pass[$k]}" "${ev[$k]}"; done > "$w/results.tsv"
python3 "$here/transcript.py" "$w/results.tsv" "$guard" > "$outfile"
