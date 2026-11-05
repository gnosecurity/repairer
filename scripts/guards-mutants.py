#!/usr/bin/env python3
# Mutation pass over the Guards realm: each mutant must make `gno test` fail.
# Usage: GNO_BIN=/path/to/gno GNOROOT=/path/to/gno-source JOBS=4 python3 scripts/guards-mutants.py gno
import os, shutil, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

SRC = sys.argv[1] if len(sys.argv) > 1 else "gno"
G, T, D, P, R = ("r/guards/" + f + ".gno" for f in ("guards", "tickets", "dispute", "pool", "render"))
GNO = os.environ.get("GNO_BIN", "gno")
JOBS = int(os.environ.get("JOBS", "1"))  # mutants run at once

M = [
    # guards.gno: filing, reveal, draw, checks, settle, final
    ("caller accepts code realms", G, "if !cur.Previous().IsUserCall() {", "if false {"),
    ("anyone reveals", G, 'case who != f.filer:\n\t\tpanic("guards: only the filer reveals")', 'case false:\n\t\tpanic("guards: only the filer reveals")'),
    ("reveal window never closes", G, "case now() > f.committed+RevealWindow:", "case false:"),
    ("guards of any size", G, "case len(guard) > MaxGuard:", "case false:"),
    ("reveal unchecked", G, 'case Commitment(who, "guard", h+"\\x00"+transcriptCommitment, salt) != f.commitment:', "case false:"),
    ("young tickets drawn", G, "f.oldBelow = oldBelow(f.committed - MinTicketAge)", "f.oldBelow = oldBelow(f.committed)"),
    ("reveals before all commit", G, "case !running(f) || f.allIn == 0:", "case !running(f):"),
    ("late check reveals", G, 'case now() > f.allIn+RevealWindow:\n\t\tpanic("guards: the reveal window has passed")', 'case false:\n\t\tpanic("guards: the reveal window has passed")'),
    ("mismatch ignored", G, "match = false", "match = true"),
    ("draw round ignores the delay", G, "f.round, f.fixedAt = uint64(r+DrawDelay), now()", "f.round, f.fixedAt = uint64(r+1), now()"),
    ("abandon a drawable filing", G, "if f.state != Revealed || now() <= f.fixedAt+DrawDeadline {", "if f.state != Revealed {"),
    ("early forfeit", G, "if f.state != Committed || now() <= f.committed+RevealWindow {", "if f.state != Committed {"),
    ("underpaying", G, "if n < min {", "if false {"),
    ("late commits", G, "if !running(f) || now() > f.drawnAt+CheckWindow {", "if !running(f) {"),
    ("double commit", G, 'if ch.commitment != "" {\n\t\tpanic("guards: already committed")', 'if false {\n\t\tpanic("guards: already committed")'),
    ("replace inside the window", G, "if now() <= f.drawnAt+CheckWindow {", "if false {"),
    ("settle before reveals end", G, "if now() <= f.allIn+RevealWindow {", "if false {"),
    ("silent worker's checkers unpaid", G, '\t\tif c.revealed || c.prev != "" {\n\t\t\tpay(cur, c.owner, CheckFee)', '\t\tif c.revealed || c.prev != "" {\n\t\t\tpay(cur, c.owner, 0)'),
    ("no level written", G, "setLevel(f.guardHash, Tested)", 'setLevel(f.guardHash, "")'),
    ("no param written", G, 'params.SetString("lvl_"+hash, level)', "_ = hash"),
    ("bad beacons accepted", G, "if !drandbn254.Verify(drandPub, round, sig) {", "if false {"),
    ("forfeits not locked", G, "\tburned += f.bond\n", "\tburned += 0\n"),
    ("a silent worker's bond not locked", G, "\tburned += bond\n\tf.bond, f.state = 0, Forfeited", "\tburned += 0\n\tf.bond, f.state = 0, Forfeited"),
    ("double draw", G, 'case f.state != Revealed:\n\t\tpanic("guards: not waiting for a draw")', 'case false:\n\t\tpanic("guards: not waiting for a draw")'),
    ("draw after its deadline", G, 'case now() > f.fixedAt+DrawDeadline:\n\t\tpanic("guards: the draw\'s deadline has passed; abandon it")', 'case false:\n\t\tpanic("guards: the draw\'s deadline has passed; abandon it")'),
    ("double settle", G, '\tcase Drawn:\n\tdefault:\n\t\tpanic("guards: nothing to settle")\n\t}', "\tdefault:\n\t}"),
    ("a stale round redrawn", G, "\t\tfixRound(f)\n\t\tf.state, f.allIn = Revealed, 0", "\t\tf.state, f.allIn = Revealed, 0"),
    ("the worker alone is checked", G, "if len(f.checks) == 1 {\n\t\t\treturn abandon(cur, f, id) // nobody checked it", "if false {\n\t\t\treturn abandon(cur, f, id) // nobody checked it"),
    ("fines unlocked", G, "burned += charge(t, NoShowFine)", "burned += 0 * charge(t, NoShowFine)"),
    ("a fined owner drawn again", G, "\tf.silent[c.owner] = true\n\trec(c.owner).Silent++", "\trec(c.owner).Silent++"),
    ("abandon pays nobody", G, "\tpay(cur, f.filer, bond)\n\tf.bond, f.state = 0, Abandoned", "\tpay(cur, f.filer, 0)\n\tf.bond, f.state = 0, Abandoned"),
    ("abandon: the fund gets nothing", G, "\tbond := f.bond - FundFee\n\tfund += FundFee", "\tbond := f.bond - FundFee\n\tfund += 0"),
    ("any transcript accepted", G, 'case verdict(transcript) == "":', "case false:"),
    ("a party objects", G, "case onFiling(f, who):", "case false:"),
    ("an objection with the same transcript", G, 'case verdict(transcript) == "" || transcript == f.verdict:', 'case verdict(transcript) == "":'),
    ("a late objection", G, "case f.state != Agreed || now() > f.until:", "case f.state != Agreed:"),
    ("finalize inside the window", G, "if f.state != Agreed || now() <= f.until {", "if f.state != Agreed {"),
    ("a stuck panel round", G, "if now() <= f.fixedAt+DrawDeadline {\n\t\t\tpanic(\"guards: the panel can still be drawn\")", "if true {\n\t\t\tpanic(\"guards: the panel can still be drawn\")"),
    ("the fund gets nothing", G, "\t\tbond := f.bond - FundFee\n\t\tfund += FundFee", "\t\tbond := f.bond - FundFee\n\t\tfund += 0"),
    ("checkers unpaid when right", G, "\t\t\tif said(c) == t {\n\t\t\t\tpay(cur, c.owner, CheckFee)", "\t\t\tif said(c) == t {\n\t\t\t\tpay(cur, c.owner, 0)"),
    ("a lying worker keeps its bond", G, "taken += f.bond // the worker said otherwise: its whole bond", "taken += 0"),
    ("a lying checker keeps its stake", G, "} else {\n\t\t\ttaken += slash(c, Slash)", "} else {\n\t\t\ttaken += 0"),
    ("the objector unpaid", G, "pay(cur, o.owner, f.objBond)", "pay(cur, o.owner, 0)"),
    ("a wrong objector keeps its bond", G, "taken += f.objBond", "taken += 0"),
    ("a wrong panelist is paid", G, "if c.revealed && c.transcript == t {", "if c.revealed {"),
    ("right panelists unpaid", G, "pay(cur, c.owner, PanelFee)", "pay(cur, c.owner, 0)"),
    ("a wrong panelist keeps its stake", G, "} else {\n\t\t\t\ttaken += slash(c, Slash)", "} else {\n\t\t\t\ttaken += 0"),
    ("a losing appeal is free", G, "taken += a.bond // the appeal didn't change the word", "taken += 0"),
    ("a winning appeal's bond kept", G, "\t\t\tpay(cur, a.who, a.bond)", "\t\t\tpay(cur, a.who, 0)"),
    ("the reserve kept", G, "\tfund += f.reserve\n\tf.reserve = 0\n\tif len(showers)", "\tfund += 0\n\tf.reserve = 0\n\tif len(showers)"),
    ("showers unpaid", G, "pay(cur, a, each)", "pay(cur, a, 0)"),
    ("panels not refilled", G, "refill := least(taken, f.panelCost)", "refill := least(taken, 0)"),
    ("failing guards tested", G, 'if verdict(t) == "pass" {', "if true {"),
    ("levels under the floor", G, "if LiveStake() >= LevelFloor {", "if true {"),
    ("a level never pulled", G, "setLevel(f.guardHash, Pulled)", "setLevel(f.guardHash, Tested)"),
    ("no record", G, "\t\t\trec(w.owner).Passed++", "\t\t\t_ = w"),
    # tickets.gno: stake, draw
    ("fines take nothing", T, "t.stake -= n", "t.stake -= 0"),
    ("drawn tickets leave", T, "case t.open > 0:", "case false:"),
    ("withdraw while unbonding", T, "case now() < t.leaving+UnbondBlocks:", "case false:"),
    ("anyone's ticket", T, "if caller(cur) != t.owner {", "if false {"),
    ("withdrawn stake still weighs", T, "\tsumAdd(t.id, -t.weight)\n", "\n"),
    ("leaving during a vote", T, "case inOpenVote(t):", "case false:"),
    ("the oldest tickets missed", T, "if ticketAt(m).height <= h {", "if ticketAt(m).height < h {"),
    ("silent owners drawn again", T, "!f.silent[t.owner] && ", ""),
    ("parties drawn", T, "!onFiling(f, t.owner)", "true"),
    ("leaving tickets drawn", T, "(t.leaving == 0 || t.leaving > fixed)", "true"),
    ("an owner drawn twice", T, "if chosen[t.owner] || !eligibleFor(f, t, fixed) {", "if !eligibleFor(f, t, fixed) {"),
    ("the draw runs out on a whale", T, "\t\tsetAside(aside, t.id, t.weight)\n\t\ttotal -= t.weight\n", ""),
    ("the worker drawn", T, "\tfor _, c := range f.checks {\n\t\tif c.owner == a {", "\tfor _, c := range f.checks[1:] {\n\t\tif c.owner == a {"),
    ("the objector drawn", T, "if f.objector != nil && f.objector.owner == a {", "if false {"),
    ("checkers on panels", T, "\tfor _, c := range f.checks {\n\t\tif c.owner == a {", "\tfor _, c := range f.checks[:0] {\n\t\tif c.owner == a {"),
    ("a panelist on the next panel", T, "\tfor _, p := range f.panels {\n\t\tfor _, c := range p {\n\t\t\tif c.owner == a {", "\tfor _, p := range f.panels[:0] {\n\t\tfor _, c := range p {\n\t\t\tif c.owner == a {"),
    # dispute.gno: reruns, panels, appeals
    ("no reruns", D, "if f.reruns >= Reruns {", "if f.reruns >= 0 {"),
    ("an objection reruns", G, "\tf.verdict, f.until = \"\", 0\n\tchain.Emit(\"GuardObjected\", \"filing\", strconv.Itoa(id), \"by\", string(who))\n\tpanelRequest(f, id)", "\tf.verdict, f.until = \"\", 0\n\tchain.Emit(\"GuardObjected\", \"filing\", strconv.Itoa(id), \"by\", string(who))\n\tdispute(f, id)"),
    ("a rerun's silent checker goes free", D, "burned += slash(c, Slash)\n\t\t\trelease(c)\n\t\t\tf.silent[c.owner] = true", "burned += 0\n\t\t\trelease(c)\n\t\t\tf.silent[c.owner] = true"),
    ("a rerun's agreement ignored", D, "if match && len(f.checks) > 1 {", "if false {"),
    ("the worker alone agrees", D, "if match && len(f.checks) > 1 {", "if match {"),
    ("a panel without the fund", D, "if fund < fee {", "if fund < 0 {"),
    ("a panel after its deadline", D, "case now() > f.fixedAt+DrawDeadline:", "case false:"),
    ("never the pool", D, "if f.panelLevel >= len(PanelSizes) {\n\t\tf.state = Pool", "if f.panelLevel >= 99 {\n\t\tf.state = Pool"),
    ("a panel decides early", D, "!all && now() <= f.allIn+RevealWindow {", "false {"),
    ("a half panel decides", D, "votes[c.transcript]*3 > size*2", "votes[c.transcript]*2 >= size"),
    ("a silent panelist goes free", D, "burned += slash(c, Slash)\n\t\t\trelease(c)\n\t\t\trec(c.owner).Silent++", "burned += 0\n\t\t\trelease(c)\n\t\t\trec(c.owner).Silent++"),
    ("anyone appeals", D, "if !against {", "if false {"),
    ("a late appeal", D, "if f.state != Appealable || now() > f.until {", "if f.state != Appealable {"),
    ("an appeal to the same panel size", D, "\tf.panelLevel++\n\tchain.Emit(\"GuardAppealed\"", "\tchain.Emit(\"GuardAppealed\""),
    # pool.gno: the pool's vote
    ("pool: under two thirds decides", P, "if v.revealed*3 <= v.total*2 {", "if v.revealed*3 <= v.total {"),
    ("pool: an early tally", P, "if !done {", "if false {"),
    ("pool: tally before every reveal", P, "v.reveals == v.committed", "v.reveals > 0"),
    ("pool: abstainers free", P, "burned += charge(t, t.stake*AbstainShare/100)", "burned += charge(t, 0)"),
    ("pool: wrong voters free", P, "burned += charge(t, n)", "burned += charge(t, 0)"),
    ("pool: wrong voters pay only WrongShare", P, "if s := Slash / int64(len(vt.tickets)); s > n {", "if s := int64(0); s > n {"),
    ("pool: winners unpaid", P, "pay(cur, who, n)", "pay(cur, who, 0)"),
    ("pool: claims overflow", P, "n := mulDiv(PoolFee, vt.weight, v.winners)", "n := PoolFee * vt.weight / v.winners"),
    ("pool: double claims", P, "vt.claimed = true", "vt.claimed = false"),
    ("pool: losers claim", P, "vt.transcript != v.decided || ", ""),
    ("pool: reveals before the commit window closes", P, "case h <= v.open+PoolCommitWindow:", "case false:"),
    ("pool: late commits", P, "case now() > v.open+PoolCommitWindow:", "case false:"),
    ("pool: late reveals", P, "case h > v.open+PoolCommitWindow+PoolRevealWindow:", "case false:"),
    ("pool: young tickets vote", P, "case t.gone || tid >= v.oldBelow:", "case t.gone:"),
    ("pool: others' tickets", P, "case t.owner != who:", "case false:"),
    ("pool: a ticket votes twice", P, "case v.voted.Has(key(uint64(tid))):", "case false:"),
    ("pool: undecided keeps the pot", P, "fund += v.pot\n\t\tv.pot = 0", "fund += 0\n\t\tv.pot = 0"),
    ("pool: undecided keeps the bond", P, "pay(cur, f.filer, f.bond)", "pay(cur, f.filer, 0)"),
    ("pool: undecided holds tickets", P, "\tfor _, c := range f.checks[1:] {\n\t\trelease(c)\n\t}", "\tfor _, c := range f.checks[1:] {\n\t\t_ = c\n\t}"),
    ("pool: no stake, a vote anyway", P, "if total <= 0 {\n\t\treturn undecided(cur, f, id)", "if false {\n\t\treturn undecided(cur, f, id)"),
    ("pool: a ticket's weight ignored", P, "vt.weight += t.weight", "vt.weight += 1"),
    ("pool: a vote without the fund", P, "if fund < PoolFee {", "if fund < 0 {"),
    ("pool: a wrong reveal accepted", P, 'if Commitment(who, "vote", transcript, salt) != vt.commitment {', "if false {"),
    # render.gno
    ("render: sealed transcripts shown", R, "\tcase c.revealed:\n", "\tcase c.revealed || c.commitment != \"\":\n"),
    ("render: a short fence", R, "max3(longest+1)", "max3(longest)"),
]

survived = []
files = {}
for name, path, old, new in M:
    if path not in files:
        files[path] = open(os.path.join(SRC, path)).read()


def run(m):
    name, path, old, new = m
    base = files[path]
    n = base.count(old)
    if n != 1:
        return name, f"BAD      {name}: found {n} times", False
    with tempfile.TemporaryDirectory(prefix="guards-mutant-") as tmp:
        work = os.path.join(tmp, "gno")
        shutil.copytree(SRC, work, ignore=shutil.ignore_patterns("reference"))
        open(os.path.join(work, path), "w").write(base.replace(old, new))
        r = subprocess.run([GNO, "test", "."], cwd=os.path.join(work, "r/guards"), capture_output=True, text=True, timeout=900)
    if r.returncode == 0:
        return name, f"SURVIVED {name}", False
    return name, f"killed   {name}", True


with ThreadPoolExecutor(JOBS) as ex:
    for name, line, killed in ex.map(run, M):
        print(line, flush=True)
        if not killed:
            survived.append(name)
print(f"{len(M) - len(survived)}/{len(M)} killed")
sys.exit(1 if survived else 0)
