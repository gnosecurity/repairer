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
    ("an owner drawn twice", "if !e.out && e.t.owner == p.owner {", "if !e.out && e.t == p {"),
    ("leaving tickets drawn", "if t.leaving == 0 && t.stake > 0", "if t.stake > 0"),
    ("reveals before all commit", "case !running(f) || f.allIn == 0:", "case !running(f):"),
    ("late check reveals", 'case now() > f.allIn+RevealWindow:\n\t\tpanic("guards: the reveal window has passed")', 'case false:\n\t\tpanic("guards: the reveal window has passed")'),
    ("mismatch ignored", "match = false", "match = true"),
    ("fines take nothing", "t.stake -= n", "t.stake -= 0"),
    ("drawn tickets leave", "case t.open > 0:", "case false:"),
    ("draw round ignores the delay", "return uint64(r + DrawDelay)", "return uint64(r + 1)"),
    ("abandon a drawable filing", "if len(distinct) >= Checkers-(len(f.checks)-1) {", "if false {"),
    ("anyone abandons", 'case who != f.filer:\n\t\tpanic("guards: only the filer abandons")', 'case false:\n\t\tpanic("guards: only the filer abandons")'),
    ("early forfeit", "if f.state != Committed || now() <= f.committed+RevealWindow {", "if f.state != Committed {"),
    ("underpaying", "if n < min {", "if false {"),
    ("late commits", "if !running(f) || now() > f.drawnAt+CheckWindow {", "if !running(f) {"),
    ("double commit", 'if ch.commitment != "" {\n\t\tpanic("guards: already committed")', 'if false {\n\t\tpanic("guards: already committed")'),
    ("replace inside the window", "if now() <= f.drawnAt+CheckWindow {", "if false {"),
    ("settle before reveals end", "if now() <= f.allIn+RevealWindow {", "if false {"),
    ("silent worker's checkers unpaid", "		if c.revealed || c.prev != \"\" {\n			pay(cur, c.owner, CheckFee)", "		if c.revealed || c.prev != \"\" {\n			pay(cur, c.owner, 0)"),
    ("no param written", '\tparams.SetString("lvl_"+f.guardHash, Tested)\n', ""),
    ("bad beacons accepted", "if !drandbn254.Verify(drandPub, round, sig) {", "if false {"),
    ("withdraw while unbonding", "case now() < t.leaving+UnbondBlocks:", "case false:"),
    ("anyone's ticket", "if caller(cur) != t.owner {", "if false {"),
    ("forfeits not locked", "	burned += bond\n	f.bond, f.state = 0, Forfeited", "	burned += 0\n	f.bond, f.state = 0, Forfeited"),
    ("double draw", 'if f.state != Revealed {\n\t\tpanic("guards: not waiting for a draw")\n\t}\n\tv :=', 'if false {\n\t\tpanic("guards: not waiting for a draw")\n\t}\n\tv :='),
    ("double settle", "	case Drawn:\n	default:\n		panic(\"guards: nothing to settle\")\n	}", "	default:\n	}"),
    ("checkers unpaid when tested", "\tfor _, c := range f.checks[1:] {\n\t\tpay(cur, c.owner, CheckFee)\n\t\tbond -= CheckFee\n\t\trelease(c)\n\t\trec(c.owner).Checked++", "\tfor _, c := range f.checks[1:] {\n\t\tbond -= CheckFee\n\t\trelease(c)\n\t\trec(c.owner).Checked++"),
    ("silent checkers redrawn after a lie", "\t\tif match {\n\t\t\treturn redraw(f, id)\n\t\t}", "\t\treturn redraw(f, id)"),
    ("failing guards tested", 'if verdict(f.checks[0].transcript) == "fail" {', "if false {"),
    ("any transcript accepted", 'case verdict(transcript) == "":', "case false:"),
    ("no reruns", "r/guards/dispute.gno", "	if f.reruns >= Reruns {", "	if f.reruns >= 0 {"),
    ("a panel without the fund", "r/guards/dispute.gno", "	if fund < fee {", "	if fund < 0 {"),
    ("panels may hold parties", "r/guards/guards.gno", "	for a := range f.served {\n		on[a] = true\n	}", "	for a := range f.served {\n		on[a] = on[a]\n	}"),
    ("a half panel decides", "r/guards/dispute.gno", "votes[c.transcript]*3 > size*2", "votes[c.transcript]*2 >= size"),
    ("a lying checker keeps its stake", "r/guards/dispute.gno", "			taken += slash(c, Slash)\n			rec(c.owner).Faults++\n		}\n		release(c)\n	}\n	var right", "			taken += 0\n			rec(c.owner).Faults++\n		}\n		release(c)\n	}\n	var right"),
    ("a lying worker keeps its bond", "r/guards/dispute.gno", "		taken += f.bond // the worker said otherwise: its whole bond", "		taken += 0"),
    ("a lying panelist keeps its stake", "r/guards/dispute.gno", "			taken += slash(c, Slash) // said otherwise, or never revealed", "			taken += 0"),
    ("a wrong panelist is paid", "r/guards/dispute.gno", "		if c.revealed && c.transcript == t {", "		if c.revealed {"),
    ("showers unpaid", "r/guards/dispute.gno", "			pay(cur, a, each)", "			pay(cur, a, 0)"),
    ("panels not refilled", "r/guards/dispute.gno", "	refill := least(taken, f.panelCost)", "	refill := least(taken, 0)"),
    ("a silent panelist goes free", "r/guards/dispute.gno", "			burned += slash(c, Slash)\n			release(c)\n			rec(c.owner).Silent++\n		} else {\n			keep = append(keep, c)\n		}\n	}\n	return keep", "			burned += 0\n			release(c)\n			rec(c.owner).Silent++\n		} else {\n			keep = append(keep, c)\n		}\n	}\n	return keep"),
    ("a split panel unpaid", "r/guards/dispute.gno", "	for _, c := range f.panel {\n		pay(cur, c.owner, PanelFee)", "	for _, c := range f.panel {\n		pay(cur, c.owner, 0)"),
    ("never the pool", "r/guards/dispute.gno", "	if f.panelLevel >= len(PanelSizes) {\n		f.state = Pool", "	if f.panelLevel >= 99 {\n		f.state = Pool"),
    ("a silent checker in a rerun goes free", "r/guards/dispute.gno", "			burned += slash(c, Slash)\n			release(c)\n			f.silent[c.owner] = true", "			burned += 0\n			release(c)\n			f.silent[c.owner] = true"),
    ("the fund gets nothing", "r/guards/guards.gno", "	bond := f.bond - FundFee\n	fund += FundFee", "	bond := f.bond - FundFee\n	fund += 0"),
    ("draw half-applied", "\tfor _, p := range picks {\n\t\tp.open++", "\tfor _, p := range picks[:0] {\n\t\tp.open++"),
]

survived = []
files = {}
for m in M:
    name, path, old, new = (m[0], FILE, m[1], m[2]) if len(m) == 3 else m
    if path not in files:
        files[path] = open(os.path.join(SRC, path)).read()
for m in M:
    name, path, old, new = (m[0], FILE, m[1], m[2]) if len(m) == 3 else m
    base = files[path]
    n = base.count(old)
    if n != 1:
        print(f"BAD      {name}: found {n} times")
        survived.append(name)
        continue
    with tempfile.TemporaryDirectory(prefix="guards-mutant-") as tmp:
        work = os.path.join(tmp, "gno")
        shutil.copytree(SRC, work, ignore=shutil.ignore_patterns("reference"))
        open(os.path.join(work, path), "w").write(base.replace(old, new))
        r = subprocess.run([GNO, "test", "."], cwd=os.path.join(work, "r/guards"), capture_output=True, text=True, timeout=600)
    if r.returncode == 0:
        print(f"SURVIVED {name}")
        survived.append(name)
    else:
        print(f"killed   {name}")
print(f"{len(M) - len(survived)}/{len(M)} killed")
sys.exit(1 if survived else 0)
