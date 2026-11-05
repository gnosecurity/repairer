# diffkeys.py BEFORE.json AFTER.json GUARD.json|-: which facts changed between two
# snapshots that the guard doesn't explain (with "-", every change counts).
# Prints them comma-separated; nothing when all is explained.
import json, sys
a, b = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
blocks = json.load(open(sys.argv[3]))["blocks"] if sys.argv[3] != "-" else []
kinds = {k for blk in blocks for k in blk}
settings = {blk["setting"]["name"] for blk in blocks if "setting" in blk}
strips = {blk["strip"]["path"] for blk in blocks if "strip" in blk}
def ours(paths):
    return all(p.endswith("autopatch.conf") for p in paths)
bad = []
for k in sorted(set(a) | set(b)):
    x, y = a.get(k), b.get(k)
    if x == y:
        continue
    if k == "nft_tables" and "drop" in kinds and not set(x) - set(y) and all("autopatch_" in t for t in set(y) - set(x)):
        continue
    if k == "settings" and all(x.get(n) == y.get(n) or n in settings for n in set(x) | set(y)):
        continue
    if k in ("sysctl_d", "modprobe_d") and ours({p for p in set(x) | set(y) if x.get(p) != y.get(p)}):
        continue
    if k == "unit_files" and "service" in kinds:
        continue
    if k == "setuid" and strips and set(y) <= set(x) and all(l.split()[0] in strips for l in set(x) - set(y)):
        continue
    bad.append(k)
print(",".join(bad))
