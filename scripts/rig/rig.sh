#!/bin/bash
# rig.sh GUARD.json OUT.json: the rig's checks of one guard in a fresh VM of
# a pinned image (RIG_IMAGE, such as "debian 12"; scripts/rig/images.tsv) on
# this machine (KVM, no internet). Writes a transcript: canonical
# JSON with no times, ports, process ids or MACs, one entry per check with
# pass or fail and sorted evidence. Single-VM rig (D1a): the traffic checks
# that need a client VM and a router are listed as not run.
#
# Needs: RIG (the rig directory: images/, debs/, seed.iso, rig_ed25519) and AGENT
# (the autopatch-agent binary). Touches nothing outside $RIG/runs. QEMU's
# version is pinned (RIG_QEMU), so the rig hash names a rig anyone can rerun
# on other hardware; the CPU and QEMU go beside the transcript in OUT.env.json.
set -euo pipefail
guard=$(readlink -f "${1:?guard file}"); outfile=${2:?transcript file}
R=${RIG:?the rig directory}; AGENT=$(readlink -f "${AGENT:?the agent binary}")
here=$(dirname "$(readlink -f "$0")")
# The system to run (RIG_IMAGE, "ubuntu 24.04" by default): only an image
# pinned by sha256 in images.tsv boots.
export RIG_IMAGE=${RIG_IMAGE:-ubuntu 24.04}
read -r imgfile imgsum < <(awk -F'\t' -v s="$RIG_IMAGE" '$1 == s {print $2, $3}' "$here/images.tsv")
[ -n "${imgfile:-}" ] || { echo "rig.sh: no image pinned for $RIG_IMAGE" >&2; exit 1; }
img=$R/images/$imgfile
[ "$(sha256sum "$img" | cut -d' ' -f1)" = "$imgsum" ] || { echo "rig.sh: $imgfile isn't the pinned image" >&2; exit 1; }
# The packages this image needs added (debs.tsv: nftables where the image
# lacks it), each checked against its pin; installed before the agent.
debs=()
while IFS=$'\t' read -r dsys dfile dsum _; do
  [ "$dsys" = "$RIG_IMAGE" ] || continue
  [ "$(sha256sum "$R/debs/$dfile" | cut -d' ' -f1)" = "$dsum" ] || { echo "rig.sh: $dfile isn't the pinned package" >&2; exit 1; }
  debs+=("$R/debs/$dfile")
done < <(grep -v '^#' "$here/debs.tsv")
qv=$(qemu-system-x86_64 --version | head -1 | awk '{print $4}')
if [ "$qv" != "${RIG_QEMU:-8.2.2}" ]; then echo "rig.sh: QEMU $qv, but the rig pins ${RIG_QEMU:-8.2.2}" >&2; exit 1; fi
python3 -I -c 'import json,sys; print(json.dumps({"cpu": next((l.split(":",1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), ""), "qemu": sys.argv[1]}, sort_keys=True))' "$qv" > "$outfile.env.json"
w=$(mktemp -d "$R/runs/rig-XXXXXX")
port=$((2600 + RANDOM % 300))
# A drop narrowed by ports is probed from outside: a forwarded port on this
# machine leads to the first port it drops (round 8, minor 9).
read -r pproto pport < <(python3 -I -c 'import json,sys
for b in json.load(open(sys.argv[1]))["blocks"]:
    d = b.get("drop")
    if d and d.get("ports") and not d.get("ip_options"):
        print(d["protocol"], str(d["ports"][0]).split("-")[0]); break
else:
    print("- -")' "$guard")
fwd=""; pfwd=$((2900 + RANDOM % 300))
[ "$pproto" != "-" ] && fwd=",hostfwd=$pproto:127.0.0.1:$pfwd-:$pport"
qemu-img create -q -f qcow2 -F qcow2 -b "$img" "$w/disk.qcow2" 8G
# Two VMs (RIG_CLIENT=1, the default): the guarded machine and a client of
# the same image, joined by a private link (a QEMU socket, 10.99.0.0/24 and
# fd99::/64, MTU 1280), each running the everyday services (services.py),
# each checking the other's (traffic.py). RIG_CLIENT=0 is the single-VM rig.
two=${RIG_CLIENT:-1}
lan=$((3200 + RANDOM % 300)); cport=$((3500 + RANDOM % 300))
lannic() { echo "-netdev socket,id=lan,$1=127.0.0.1:$lan -device virtio-net-pci,netdev=lan,mac=52:54:00:99:00:0$2"; }
boot() {
  local extra=""
  [ "$two" = 1 ] && extra=$(lannic listen 1)
  qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 \
    -drive file="$w/disk.qcow2",if=virtio -drive file="$R/seed.iso",if=virtio,format=raw,readonly=on \
    -nic user,model=virtio,restrict=on,hostfwd=tcp:127.0.0.1:$port-:22$fwd $extra \
    -display none -serial file:"$w/console.log" -daemonize -pidfile "$w/qemu.pid"
}
bootclient() {
  qemu-img create -q -f qcow2 -F qcow2 -b "$img" "$w/client.qcow2" 8G
  qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 \
    -drive file="$w/client.qcow2",if=virtio -drive file="$R/seed.iso",if=virtio,format=raw,readonly=on \
    -nic user,model=virtio,restrict=on,hostfwd=tcp:127.0.0.1:$cport-:22 $(lannic connect 2) \
    -display none -serial file:"$w/client.log" -daemonize -pidfile "$w/qemu2.pid"
}
cleanup() { kill "$(cat "$w/qemu.pid" 2>/dev/null)" "$(cat "$w/qemu2.pid" 2>/dev/null)" 2>/dev/null || true; rm -rf "$w"; }
trap cleanup EXIT
S=(ssh -q -i "$R/rig_ed25519" -p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes rig@127.0.0.1)
C=(ssh -q -i "$R/rig_ed25519" -p $cport -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes rig@127.0.0.1)
waitssh() { for i in $(seq 1 90); do "${S[@]}" true 2>/dev/null && return 0; sleep 2; done; return 1; }
waitclient() { for i in $(seq 1 90); do "${C[@]}" true 2>/dev/null && return 0; sleep 2; done; return 1; }
snap() { "${S[@]}" 'sudo python3 -I -' < "$here/snapshot.py"; }
boot
[ "$two" = 1 ] && bootclient
waitssh
CP=(scp -q -i "$R/rig_ed25519" -P $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
"${CP[@]}" "$AGENT" rig@127.0.0.1:autopatch-agent
"${CP[@]}" "$guard" rig@127.0.0.1:
# The link's address and the services, on a machine (again after a reboot):
# ssh array name, MAC's last digit, IPv4, IPv6.
lanup() {
  local -n sh=$1
  "${sh[@]}" "n=\$(ip -o link | awk -F': ' '/52:54:00:99:00:0$2/ {print \$2}'); sudo ip link set \"\$n\" up mtu 1280 && sudo ip addr replace $3/24 dev \"\$n\" && sudo ip -6 addr replace $4/64 dev \"\$n\" nodad && (systemctl is-active --quiet rigsvc || sudo systemd-run --quiet --unit=rigsvc python3 -I /home/rig/services.py $3 $4)" < /dev/null
}
# traffic both ways: the client's checks of the guarded machine, and the
# guarded machine's of the client; one line each, prefixed by direction.
traffic() {
  { "${C[@]}" 'python3 -I /home/rig/traffic.py 10.99.0.1 fd99::1' < /dev/null | sed 's/^/to the guarded machine: /'
    "${S[@]}" 'python3 -I /home/rig/traffic.py 10.99.0.2 fd99::2' < /dev/null | sed 's/^/from the guarded machine: /'; } | sort
}
if [ "$two" = 1 ]; then
  waitclient
  CC=(scp -q -i "$R/rig_ed25519" -P $cport -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
  for f in services.py traffic.py; do "${CP[@]}" "$here/$f" rig@127.0.0.1: && "${CC[@]}" "$here/$f" rig@127.0.0.1:; done
  lanup S 1 10.99.0.1 fd99::1
  lanup C 2 10.99.0.2 fd99::2
  sleep 2
  base=$(traffic)
  if echo "$base" | grep -q FAILED; then
    echo "rig.sh: the rig's own traffic fails before any guard; this rig isn't sound here:" >&2
    echo "$base" >&2
    exit 3
  fi
fi
if [ ${#debs[@]} -gt 0 ]; then
  "${S[@]}" 'mkdir -p debs' < /dev/null
  "${CP[@]}" "${debs[@]}" rig@127.0.0.1:debs/
  "${S[@]}" 'sudo dpkg -i debs/*.deb >/dev/null && rm -rf debs' < /dev/null || { echo "rig.sh: the pinned packages didn't install" >&2; exit 1; }
fi
"${S[@]}" 'sudo install -o root -g root -m 0755 autopatch-agent /usr/local/sbin/autopatch-agent && sudo /usr/local/sbin/autopatch-agent install >/dev/null && for i in $(ls /sys/class/net); do [ "$i" = lo ] || sudo ip link set dev "$i" mtu 1280; done'
A="sudo /usr/local/sbin/autopatch-agent"
G=/home/rig/$(basename "$guard")
declare -A pass ev
check() { pass[$1]=$2; ev[$1]=$3; }
# A guard that mixes blocks that bite now with ones that bite later fails
# here, so no honest transcript passes it (AUTOPATCH.md rule 4).
timing=$("$AGENT" fmt "$guard" 2>&1 >/dev/null | sed 's/.*, //')
if [[ $timing == mixes* ]]; then check one_timing false "$timing; file them as two guards"; else check one_timing true "$timing"; fi
snap > "$w/s0.json"
if out=$("${S[@]}" "$A apply -confirm-within 0 $G" 2>&1); then check applies true "applied"; else check applies false "$out"; fi
case "$pproto" in
  tcp) timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$pfwd; head -c1 <&3" >/dev/null 2>&1 || true ;;
  udp) for i in 1 2 3; do echo probe > "/dev/udp/127.0.0.1/$pfwd" 2>/dev/null || true; sleep 1; done ;;
esac
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
if [ "$two" = 1 ]; then lan1=$(traffic); fi
"${S[@]}" 'sudo systemctl reboot' >/dev/null 2>&1 || true
sleep 5; waitssh
if [ "$two" = 1 ]; then
  lanup S 1 10.99.0.1 fd99::1
  sleep 2
  lan2=$(traffic)
  # Everyday traffic between the two machines, with the guard on and after
  # a reboot with it: any check that passed before the guard and fails now.
  failed=$(printf '%s\n%s\n' "$lan1" "$lan2" | grep FAILED | sort -u || true) # no match is the good case
  n=$(echo "$base" | wc -l)
  if [ -z "$failed" ]; then check traffic_lan true "all $n checks between the two machines pass with the guard on and after a reboot"
  else check traffic_lan false "$(echo "$failed" | tr '\n' ';' | sed 's/;$//; s/;/; /g')"; fi
fi
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
RIG_CLIENT=$two python3 "$here/transcript.py" "$w/results.tsv" "$guard" > "$outfile"
