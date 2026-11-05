# transcript.py RESULTS.tsv GUARD.json: the rig's transcript as canonical JSON:
# no times, ports, process ids, MACs, CPU or QEMU (those go beside it, in
# env.json); each check pass or fail with sorted evidence, and the system the
# image runs (RIG_IMAGE, "ubuntu 24.04"), the only one its Tested counts on.
# Single-VM rig: the checks that need a client VM are listed as not run.
import hashlib, json, os, sys
checks = {}
for line in open(sys.argv[1]):
    name, ok, evidence = line.rstrip("\n").split("\t", 2)
    checks[name] = {"pass": ok == "true", "evidence": sorted(e.strip() for e in evidence.split(";") if e.strip())}
two = os.environ.get("RIG_CLIENT", "1") == "1"
if not two:
    checks["traffic_needing_a_client_vm"] = {"pass": None, "evidence": ["https, mail, DNS answers, gno.land p2p: not run in the single-VM rig"]}
# A guard is named by the sha256 of its canonical form: the file without its newline.
guard = hashlib.sha256(open(sys.argv[2], "rb").read().rstrip(b"\n")).hexdigest()
image = os.environ.get("RIG_IMAGE", "ubuntu 24.04")
print(json.dumps({"rig": "two-vm/1" if two else "single-vm/1", "image": image, "guard": guard, "checks": checks}, sort_keys=True, separators=(",", ":")))
