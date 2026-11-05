#!/bin/bash
# reboot-e2e.sh RUN [MODE]: B3's reboot test in a fresh Ubuntu 24.04 VM on this
# machine (KVM, no internet). MODE window (the default): the tier reboots by
# itself, inside a window that covers the test. MODE signed: the tier waits
# for the owner's signed Reboot, which comes in through intake.
#
# GRUB is set as an admin sets it (GRUB_DEFAULT=saved, panic=10, the running
# kernel pinned as the saved default) and the VM rebooted once, so panic= is
# on the running command line. Then a newer kernel goes in offline (KDEBS: its
# linux-image and linux-modules .debs, from apt-get download), then the agent.
# The minute timer's ticks must reboot into the new kernel once, wait out the
# health window on it, and make it GRUB's default; every report must verify
# against the agent's key. In signed mode a second phase follows: the
# system asks for a reboot (/run/reboot-required) with no newer kernel; the
# tier waits; the owner's second Reboot, naming the running kernel, comes in;
# a plain reboot (a new boot id, the same kernel) and the health window.
#
# Needs: RIG (images/, seed.iso, rig_ed25519), KDEBS, KREL (the new kernel's
# release), SRC (the autopatch source). Touches nothing outside $RIG/runs.
set -euo pipefail
run=${1:?run number}; mode=${2:-window}
R=${RIG:-/root/autopatch-rig}; SRC=${SRC:-/root/src/autopatch}
KDEBS=${KDEBS:?a directory of the new kernel debs}; KREL=${KREL:?the new kernel release}
img=$R/images/ubuntu-24.04-server-cloudimg-amd64.img
w=$R/runs/reboot-$run
port=$((2500 + run % 100))
rm -rf "$w"; mkdir -p "$w"
source /etc/profile.d/dev.sh
(cd "$SRC" && CGO_ENABLED=0 go build -trimpath -o "$w/autopatch-agent" ./cmd/autopatch-agent && go build -o "$w/e2e" ./scripts/e2e)
# A window from five minutes ago to an hour on, in UTC; the Reboot's
# deadline two hours on, on a whole minute.
win=$(date -u -d '-5 min' +%H:%M)-$(date -u -d '+60 min' +%H:%M)
nota=$(( ($(date +%s) + 7200) / 60 * 60 ))
tier=$mode; [ "$mode" = signed ] && tier=yes
"$w/e2e" genreboot "$w/in" "$tier" "$win" "$KREL" "$nota"
qemu-img create -q -f qcow2 -F qcow2 -b "$img" "$w/disk.qcow2" 8G
boot() {
  qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 \
    -drive file="$w/disk.qcow2",if=virtio -drive file="$R/seed.iso",if=virtio,format=raw,readonly=on \
    -nic user,model=virtio,restrict=on,hostfwd=tcp:127.0.0.1:$port-:22 \
    -display none -serial file:"$w/console.log" -daemonize -pidfile "$w/qemu.pid"
}
cleanup() { kill "$(cat "$w/qemu.pid" 2>/dev/null)" 2>/dev/null || true; rm -f "$w/disk.qcow2"; }
trap cleanup EXIT
S=(ssh -q -i "$R/rig_ed25519" -p "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes rig@127.0.0.1)
waitssh() { for i in $(seq 1 120); do "${S[@]}" true 2>/dev/null && return 0; sleep 2; done; return 1; }
log() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$w/log.txt"; }
cp_in() { scp -q -i "$R/rig_ed25519" -P "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$@" rig@127.0.0.1:; }
boot; waitssh
old=$("${S[@]}" uname -r)
log "booted $old; mode $mode, window $win UTC, the new kernel $KREL"
# GRUB for one-shot boots, as an admin sets it, the running kernel pinned.
"${S[@]}" 'sudo bash -s' >> "$w/log.txt" 2>&1 <<'SH'
set -e
sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub
for f in /etc/default/grub.d/*.cfg; do sed -i '/^GRUB_DEFAULT=/d' "$f"; done
echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT panic=10"' > /etc/default/grub.d/99-panic.cfg
update-grub 2>/dev/null
rel=$(uname -r)
sub=$(grep -oP "^submenu .*\\\$menuentry_id_option '\K[^']+" /boot/grub/grub.cfg | head -1)
ent=$(grep -oP "menuentry '[^']*with Linux $rel'.*\\\$menuentry_id_option '\K[^']+" /boot/grub/grub.cfg | head -1)
grub-set-default "$sub>$ent"
echo "pinned: $(grub-editenv list)"
SH
"${S[@]}" 'sudo systemctl reboot' || true
sleep 5; waitssh
log "after the admin's reboot: $("${S[@]}" 'uname -r; grep -o "panic=[0-9]*" /proc/cmdline' | tr '\n' ' ')"
# The new kernel, offline.
cp_in "$KDEBS"/linux-image-"$KREL"_*.deb "$KDEBS"/linux-modules-"$KREL"_*.deb
"${S[@]}" "sudo dpkg -i linux-modules-${KREL}_*.deb linux-image-${KREL}_*.deb" >> "$w/log.txt" 2>&1
log "installed: $("${S[@]}" "ls /boot/vmlinuz-$KREL /boot/initrd.img-$KREL; sudo grub-editenv list" | tr '\n' ' ')"
# The agent, as in B1's test.
cp_in "$w/autopatch-agent" "$w/in/policy.json" "$w/in/reboot-1.json" "$w/in/reboot-2.json"
"${S[@]}" 'sudo install -o root -g root -m 0755 autopatch-agent /usr/local/sbin/autopatch-agent && sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin autopatch'
"${S[@]}" 'sudo /usr/local/sbin/autopatch-agent install' >> "$w/log.txt" 2>&1
key=$("${S[@]}" 'sudo /usr/local/sbin/autopatch-agent init -host vm1 -seq 0 -intake-user autopatch /home/rig/policy.json' | tail -1)
log "init: agent key $key"
report() { # report N: fetch the signed report as the unprivileged user and check it here
  "${S[@]}" 'sudo -u autopatch /usr/local/sbin/autopatch-agent report' > "$w/report-$1.json" 2>/dev/null || return 1
  "$w/e2e" verify "$w/report-$1.json" "$key" > "$w/summary-$1.txt" 2>&1 || { log "VERIFY FAILED: $(cat "$w/summary-$1.txt")"; return 1; }
}
said() { sed -n 's/^  reboot: //p' "$w/summary-$1.txt"; }
n=0; asked=no; settled=no; went=no
for i in $(seq 1 70); do
  sleep 30; n=$((n+1))
  if ! report $n; then log "$n: no report (rebooting?)"; continue; fi
  line=$(said $n); rel=$("${S[@]}" uname -r 2>/dev/null || echo "?")
  log "$n: running $rel; reboot: ${line:-(nothing owed)}"
  case $line in rebooting*|booted*) went=yes;; esac
  if [ "$mode" = signed ] && [ "$asked" = no ] && [[ $line == *"waits for your signed Reboot"* ]]; then
    log "the tier waits for the owner; the signed Reboot goes in through intake: $("${S[@]}" 'sudo -u autopatch /usr/local/sbin/autopatch-agent intake < /home/rig/reboot-1.json' 2>&1)"
    asked=yes
  fi
  if [[ $line == "rebooted into $KREL; it is the default now" ]]; then settled=yes; break; fi
done
phase2=skipped
if [ "$mode" = signed ] && [ "$settled" = yes ]; then
  "${S[@]}" 'sudo sh -c "echo \"*** System restart required ***\" > /run/reboot-required; printf \"libc6\nsystemd\n\" > /run/reboot-required.pkgs"'
  boot0=$("${S[@]}" cat /proc/sys/kernel/random/boot_id)
  log "the system asks for a reboot (libc6, systemd); boot id $boot0"
  asked2=no; held=no
  for i in $(seq 1 50); do
    sleep 30; n=$((n+1))
    if ! report $n; then log "$n: no report (rebooting?)"; continue; fi
    line=$(said $n)
    log "$n: running $("${S[@]}" uname -r 2>/dev/null || echo "?"); reboot: ${line:-(nothing owed)}"
    if [ "$asked2" = no ] && [[ $line == "a reboot is owed: the system asks for one (libc6, systemd); this tier waits for your signed Reboot"* ]]; then
      log "the second signed Reboot goes in through intake: $("${S[@]}" 'sudo -u autopatch /usr/local/sbin/autopatch-agent intake < /home/rig/reboot-2.json' 2>&1)"
      asked2=yes
    fi
    if [[ $line == "rebooted (the system asked); health held" ]]; then held=yes; break; fi
  done
  boot1=$("${S[@]}" cat /proc/sys/kernel/random/boot_id)
  phase2=no
  [ "$asked2" = yes ] && [ "$held" = yes ] && [ "$boot0" != "$boot1" ] && [ "$("${S[@]}" uname -r)" = "$KREL" ] && phase2=yes
  log "the system's reboot: asked=$asked2 held=$held, a new boot: $([ "$boot0" != "$boot1" ] && echo yes || echo no); phase 2 ok=$phase2"
fi
grubenv=$("${S[@]}" 'sudo grub-editenv list' 2>&1 | tr '\n' ' ')
state=$("${S[@]}" 'sudo cat /var/lib/autopatch/reboot.json' 2>&1)
final=$("${S[@]}" uname -r 2>&1)
log "grubenv: $grubenv"
log "reboot.json: $state"
log "booted kernels on the console: $(grep -oE 'Linux version [0-9][^ ]*' "$w/console.log" | awk '{print $3}' | tr '\n' ' ')"
ok=no
[ "$settled" = yes ] && [ "$final" = "$KREL" ] && [[ $grubenv == *"saved_entry="*"$KREL"* ]] && [[ $grubenv != *"next_entry=g"* ]] && ok=yes
[ "$mode" = signed ] && { [ "$asked" = no ] || [ "$phase2" != yes ]; } && ok=no
log "reboot e2e run $run ($mode) took ${SECONDS}s; from $old to $final; settled=$settled ok=$ok"
[ "$ok" = yes ]
