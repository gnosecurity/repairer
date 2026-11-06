# Repairer

> "Your people will rebuild the ancient ruins; you will restore the age-old foundations; you will be called Repairer of the Breach, Restorer of the Streets of Dwelling." (Isaiah 58:12, Berean Standard Bible)

Repairer defends servers in the gap between a flaw going public and the
vendor's fix running. It is one of gno.security's two products, beside
Immune: a small agent on each server puts on **guards**, which are stopgaps
written as data, when the owner's signed rules allow, and takes them off once
the real fix runs. A lookout on the owner's own network reads the security
news, the owner signs approvals on a hardware wallet, and a swarm on gno.land
writes and checks the guards, with money at stake. More at
https://gno.security/repairer/.

Built and tested on test machines (Ubuntu 22.04, 24.04 and 26.04, Debian 12
and 13): the agent with its guards, reboots and was-I-hit checks; signed
policies and approvals; the lookout and its page; the test rig; gnosh at
home; a light client for gno.land; and the Guards realm on a local chain.
Not yet on gno.land, and not yet running on anyone's servers.

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

A guard file must be in canonical form (compact JSON, fields in a fixed
order), so that the hash a signature covers is the hash of the file's own
bytes. `fmt` writes that form from a readable one.

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
  goes into `/etc/sysctl.d/99-zz-repairer.conf`, which sorts after the
  system's own files.
- **`boot`** runs early at every boot. It takes off whatever was never
  confirmed, including a guard left half on by a crash. It puts back what was
  confirmed, unless this release no longer allows it or it is unsafe on the
  machine now; those it takes off too, and says so.
- **`check`** compares live state with what was set, and catches things like a
  table flushed by a firewall reload. `check -repair` puts it back and probes
  again.
- **Shared changes come back last.** A setting, unit or file mode that two
  guards share returns to its original only when the last of them comes off.
- **A failed undo is kept.** The guard stays in the state, marked, so status
  shows it and the next undo or boot tries again.

## Checked on the machine itself

A guard's fields can't show everything, so the agent also checks the machine
before putting a guard on, at every boot, and in `check`:

- **Modules:** the running kernel must have a module by exactly that name, not
  built in. Aliases such as `net-pf-16-proto-12` (which stands for the
  firewall's nfnetlink) are refused.
- **Drops by port:** they may not cover a port ssh or dropbear listens on, nor
  the ephemeral range the machine's own connections use. A drop covers at most
  1,024 ports.
- **Strips:** the file must be a root-owned regular file, reached without any
  symlink, through directories only root can change. It must not be sudo, su,
  doas or passwd by another name. Its mode goes back only onto that same file,
  never onto one an upgrade put in its place.
- **Network settings:** a setting such as MPTCP or SACK lives in each network
  namespace. When containers have their own, the agent says the guard covers
  only its own namespace and needs `-force`.
- **Services:** they are masked before they are stopped, so nothing can start
  them in between. `check` also asks whether a masked service is running.
- **Names:** tables, undo timers and module files are named by the guard's
  whole hash.
- **The undo timer:** it runs the agent only from a root-owned path that only
  root can change, never from a temporary directory or a `go run` build.

## Use

```
repairer-agent fmt     guard.json   # print it in canonical form, the only form apply takes
repairer-agent plan    guard.json   # what it would do here; changes nothing
repairer-agent apply   guard.json   # on, pending, undo armed
repairer-agent confirm <hash|id>
repairer-agent undo    <hash|id>
repairer-agent status
repairer-agent check   [-repair]
repairer-agent boot
```

## Build and test

The code uses only Go's standard library.

```
make qa            # gofmt, vet, unit tests, linux amd64 and arm64 builds
make integration   # as root on Linux: guard one for real, in a fresh network namespace
go test -tags hostread -run HostRead ./agent   # as root: the machine checks, read-only
```

The integration test puts guard number one on with real nftables, the real
kernel setting and the real probe. It runs inside a network namespace of its
own, so the machine's own firewall and settings are never touched.
