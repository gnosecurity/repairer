# autopatch

autopatch defends servers in the gap between a flaw going public and the
vendor's fix running. It is the home half of gno.security. A small agent on
each server puts on **guards**, which are stopgaps written as data, when the
owner's rules allow. It takes them off once the real fix runs.

This repository is at step 1: the agent's guard engine. The lookout, signed
policies, the test rig and the gno.land side come next.

## Guards only take away

A guard is a short JSON file. Its blocks come from a fixed list:

| Block | What it does |
|---|---|
| drop | drops inbound packets matching typed fields, in an nftables table of its own at prerouting priority -300 |
| setting | sets a kernel setting to the one value its allow-list entry permits |
| module | stops a kernel module from loading |
| service | stops and masks a systemd unit |
| strip | removes the setuid and setgid bits from a packaged program |

The agent writes every rule and change itself from typed fields, so no text
from a guard reaches a shell or the firewall. No block can accept, open, add,
download, run or hold anything.

A never-touch list built into the agent keeps these out of reach: the
firewall, ssh, sudo and doas, logging, time, the update path, and the agent
itself. Settings and modules are checked against allow-lists in the release.

Guard number one is
[guard/testdata/cve-2026-98432.json](guard/testdata/cve-2026-98432.json), the
stopgap for CVE-2026-98432. It drops inbound IPv4 TCP carrying IP options, and
turns MPTCP off for new sockets.

## Every change has its undo ready

- **`apply`** works in this order:
  1. It writes ahead to its state file.
  2. It arms an undo timer before the first change. The timer is a transient
     systemd timer, so it runs even if the agent dies.
  3. It applies each step.
  4. It probes each drop with a packet it builds itself, and checks that the
     guard's own rule counted it.

  Any failure takes everything back off.
- **A guard goes on pending.** Its undo runs unless `confirm` comes within
  `-confirm-within` (default 10 minutes). Nothing about a pending guard
  survives a reboot.
- **`confirm`** makes the guard last: the mask becomes lasting, and the setting
  goes into `/etc/sysctl.d/90-autopatch.conf`.
- **`boot`** runs early at every boot. It takes off whatever was never
  confirmed, including a guard left half on by a crash, and puts back what was
  confirmed.
- **`check`** compares live state with what was set, and catches things like a
  table flushed by a firewall reload. `check -repair` puts it back and probes
  again.
- **Shared changes come back last.** A setting, unit or file mode that two
  guards share returns to its original only when the last of them comes off.

## Use

```
autopatch-agent plan    guard.json   # what it would do here; changes nothing
autopatch-agent apply   guard.json   # on, pending, undo armed
autopatch-agent confirm <hash|id>
autopatch-agent undo    <hash|id>
autopatch-agent status
autopatch-agent check   [-repair]
autopatch-agent boot
```

## Build and test

The code uses only Go's standard library.

```
make qa            # gofmt, vet, unit tests, linux amd64 and arm64 builds
make integration   # as root on Linux: guard one for real, in a fresh network namespace
```

The integration test puts guard number one on with real nftables, the real
kernel setting and the real probe. It runs inside a network namespace of its
own, so the machine's own firewall and settings are never touched.
