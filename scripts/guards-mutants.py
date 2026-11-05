#!/usr/bin/env python3
# Mutation pass over the Guards realm: each mutant must make `gno test` fail.
# Usage: GNO_BIN=/path/to/gno GNOROOT=/path/to/gno-source python3 scripts/guards-mutants.py gno
import os, shutil, subprocess, sys, tempfile

SRC = sys.argv[1] if len(sys.argv) > 1 else "gno"
FILE = "r/guards/guards.gno"
GNO = os.environ.get("GNO_BIN", "gno")

M = [
    ("caller accepts code realms", "if !cur.Previous().IsUserCall() {", "if false {"),
    ("anyone reveals", 'case who != f.filer:\n\t\tpanic("guards: only the filer reveals")', 'case false:\n\t\tpanic("guards: only the filer reveals")'),
    ("reveal window never closes", 'case now() > f.committed+RevealWindow:\n\t\tpanic("guards: the reveal window has passed")', 'case false:\n\t\tpanic("guards: the reveal window has passed")'),
    ("guards of any size", "case len(guard) > MaxGuard:", "case false:"),
    ("reveal unchecked", 'case Commitment(who, "guard", h+"\\x00"+transcriptCommitment, salt) != f.commitment:', "case false:"),
    ("young tickets drawn", "t.height+MinTicketAge <= f.committed", "true"),
    ("filer and repeat owners drawn", "!on[t.owner]", "true"),
    ("silent owners drawn again", "!f.silent[t.owner]", "true"),
    ("an owner drawn twice", "if !e.out && e.t.owner == pick.owner {", "if !e.out && e.t == pick {"),
    ("leaving tickets drawn", "if t.leaving == 0 && t.stake > 0", "if t.stake > 0"),
    ("reveals before all commit", "case f.state != Drawn || f.allIn == 0:", "case f.state != Drawn:"),
    ("late check reveals", 'case now() > f.allIn+RevealWindow:\n\t\tpanic("guards: the reveal window has passed")', 'case false:\n\t\tpanic("guards: the reveal window has passed")'),
    ("mismatch ignored", "match = false", "match = true"),
    ("fines take nothing", "t.stake -= n", "t.stake -= 0"),
    ("drawn tickets leave", "case t.open > 0:", "case false:"),
    ("draw round ignores the delay", "return uint64(r + DrawDelay)", "return uint64(r + 1)"),
    ("abandon a drawable filing", "if len(distinct) >= Checkers-(len(f.checks)-1) {", "if false {"),
    ("anyone abandons", 'case who != f.filer:\n\t\tpanic("guards: only the filer abandons")', 'case false:\n\t\tpanic("guards: only the filer abandons")'),
    ("early forfeit", "if f.state != Committed || now() <= f.committed+RevealWindow {", "if f.state != Committed {"),
    ("underpaying", "if n < min {", "if false {"),
    ("late commits", "if f.state != Drawn || now() > f.drawnAt+CheckWindow {", "if f.state != Drawn {"),
    ("double commit", 'if ch.commitment != "" {\n\t\tpanic("guards: already committed")', 'if false {\n\t\tpanic("guards: already committed")'),
    ("replace inside the window", "if now() <= f.drawnAt+CheckWindow {", "if false {"),
    ("settle before reveals end", "if now() <= f.allIn+RevealWindow {", "if false {"),
    ("silent worker's checkers unpaid", "\t\t\t\t\tpay(cur, c.owner, CheckFee)\n\t\t\t\t\tbond -= CheckFee\n\t\t\t\t\trelease(c)\n\t\t\t\t} else {", "\t\t\t\t\tbond -= CheckFee\n\t\t\t\t\trelease(c)\n\t\t\t\t} else {"),
    ("no param written", '\tparams.SetString("lvl_"+f.guardHash, Tested)\n', ""),
    ("bad beacons accepted", "if !drandbn254.Verify(drandPub, round, sig) {", "if false {"),
    ("withdraw while unbonding", "case now() < t.leaving+UnbondBlocks:", "case false:"),
    ("anyone's ticket", "if caller(cur) != t.owner {", "if false {"),
    ("forfeits not locked", "\t\t\tburned += bond\n", ""),
    ("double draw", 'if f.state != Revealed {\n\t\tpanic("guards: not waiting for a draw")\n\t}\n\tv :=', 'if false {\n\t\tpanic("guards: not waiting for a draw")\n\t}\n\tv :='),
    ("double settle", 'if f.state != Drawn {\n\t\tpanic("guards: nothing to settle")', 'if false {\n\t\tpanic("guards: nothing to settle")'),
    ("checkers unpaid when tested", "\tfor _, c := range f.checks[1:] {\n\t\tpay(cur, c.owner, CheckFee)\n\t\tbond -= CheckFee\n\t\trelease(c)\n\t\trec(c.owner).Checked++", "\tfor _, c := range f.checks[1:] {\n\t\tbond -= CheckFee\n\t\trelease(c)\n\t\trec(c.owner).Checked++"),
    ("silent checkers redrawn after a lie", "\t\tif match {\n\t\t\treturn redraw(f, id)\n\t\t}", "\t\treturn redraw(f, id)"),
    ("failing guards tested", 'if verdict(f.checks[0].transcript) == "fail" {', "if false {"),
    ("any transcript accepted", 'case verdict(transcript) == "":', "case false:"),
    ("draw half-applied", "\tfor _, p := range picks {\n\t\tp.open++", "\tfor _, p := range picks[:0] {\n\t\tp.open++"),
]

base = open(os.path.join(SRC, FILE)).read()
survived = []
for name, old, new in M:
    n = base.count(old)
    if n != 1:
        print(f"BAD      {name}: found {n} times")
        survived.append(name)
        continue
    with tempfile.TemporaryDirectory(prefix="guards-mutant-") as tmp:
        work = os.path.join(tmp, "gno")
        shutil.copytree(SRC, work, ignore=shutil.ignore_patterns("reference"))
        open(os.path.join(work, FILE), "w").write(base.replace(old, new))
        r = subprocess.run([GNO, "test", "."], cwd=os.path.join(work, "r/guards"), capture_output=True, text=True, timeout=600)
    if r.returncode == 0:
        print(f"SURVIVED {name}")
        survived.append(name)
    else:
        print(f"killed   {name}")
print(f"{len(M) - len(survived)}/{len(M)} killed")
sys.exit(1 if survived else 0)
