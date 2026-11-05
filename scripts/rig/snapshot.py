# snapshot.py: what a rig machine is, as facts that stay the same from run
# to run (no times, ports chosen by the kernel, process ids or MACs). Runs as
# root inside the rig VM with `python3 -I -`; prints canonical JSON.
import glob, hashlib, json, os, subprocess

def out(*cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else ""

def sha(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None

snap = {}
# Listening sockets by protocol and port: a guard must never open one.
ports = set()
for line in out("ss", "-lntuH").splitlines():
    f = line.split()
    if len(f) >= 5:
        ports.add(f[0] + " " + f[4].rsplit(":", 1)[-1])
snap["ports"] = sorted(ports)
snap["users"] = sorted(l.split(":")[0] for l in open("/etc/passwd") if l.strip())
snap["groups"] = sorted(l.split(":")[0] for l in open("/etc/group") if l.strip())
keys = {}
for p in ["/root/.ssh/authorized_keys"] + glob.glob("/home/*/.ssh/authorized_keys"):
    keys[p] = sha(p)
snap["ssh_keys"] = keys
snap["sshd_config"] = {p: sha(p) for p in sorted(["/etc/ssh/sshd_config"] + glob.glob("/etc/ssh/sshd_config.d/*"))}
setuid = []
for line in out("find", "/", "-xdev", "-type", "f", "-perm", "/6000", "-printf", "%p %m\n").splitlines():
    setuid.append(line)
snap["setuid"] = sorted(setuid)
units = []
for line in out("systemctl", "list-unit-files", "--no-legend", "--no-pager", "--type=service,socket,timer").splitlines():
    f = line.split()
    if len(f) >= 2:
        units.append(f[0] + " " + f[1])
snap["unit_files"] = sorted(units)
snap["nft_tables"] = sorted(l.strip() for l in out("nft", "list", "tables").splitlines() if l.strip())
settings = {}
for name in ["net.mptcp.enabled", "net.ipv4.tcp_sack", "kernel.unprivileged_userns_clone",
             "user.max_user_namespaces", "kernel.io_uring_disabled"]:
    try:
        settings[name] = open("/proc/sys/" + name.replace(".", "/")).read().strip()
    except OSError:
        settings[name] = None
snap["settings"] = settings
snap["sysctl_d"] = {p: sha(p) for p in sorted(glob.glob("/etc/sysctl.d/*"))}
snap["modprobe_d"] = {p: sha(p) for p in sorted(glob.glob("/etc/modprobe.d/*"))}
print(json.dumps(snap, sort_keys=True, separators=(",", ":")))
