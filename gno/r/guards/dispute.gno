package guards

import (
	"chain"
	"strconv"
)

// A dispute (AUTOPATCH.md, the swarm's rules 3 and 5): a filing's
// transcripts differ, or someone objected to their agreement.
//   - The same parties, the worker and its checkers, run it again, up to
//     Reruns times: honest runs that differed by chance now agree, and the
//     filing goes on as an agreement. (An objection skips the reruns.)
//   - Then a fresh panel, drawn by weight from a beacon round after the
//     dispute, from the pool as it was then, never anyone already on the
//     filing, runs it: PanelSizes[0] members, then the next size when no
//     side reaches more than two thirds of the panel, then the whole pool
//     (pool.gno). A panel is decided only once every member has revealed or
//     its reveal window has closed, so nobody revealing in time is charged
//     (round 9, new major 5). A panel is paid from the dispute fund, and a
//     dispute waits while the fund can't pay it.
//   - A panel's word can be appealed within AppealWindow by a party it went
//     against, with AppealBond: the next panel, or the pool, decides. Nothing
//     is paid or taken until the last word (round 9, new major 3), and then
//     everyone on every panel of the dispute is judged by it (final, in
//     guards.gno).
var (
	Reruns             = 2
	PanelSizes         = []int{7, 15, 31}
	PanelFee     int64 = 100_000   // ugnot, to each panelist who said the last word
	FundFee      int64 = 100_000   // ugnot of each filing's bond that settles, to the dispute fund
	Slash        int64 = 1_000_000 // ugnot taken from a ticket on the wrong side, or silent in a dispute
	ShowShare    int64 = 50        // percent of what is taken, to whoever showed it
	AppealWindow int64 = 2000      // blocks after a panel's word in which a party may appeal
	AppealBond   int64 = 1_000_000 // ugnot an appellant puts up
)

// dispute begins, or goes on with, a dispute: a rerun by the same parties
// while reruns are left, then a panel. (An objection goes to a panel
// directly: Object calls panelRequest.)
func dispute(f *filing, id int) string {
	if f.reruns >= Reruns {
		return panelRequest(f, id)
	}
	f.reruns++
	for _, c := range f.checks {
		if c.revealed {
			c.prev = c.transcript
		}
		c.commitment, c.transcript, c.revealed = "", "", false
	}
	f.state, f.drawnAt, f.allIn = Rerun, now(), 0
	chain.Emit("GuardRerun", "filing", strconv.Itoa(id), "run", strconv.Itoa(f.reruns))
	return f.state
}

// settleRerun ends a rerun. A worker silent in it forfeits; a checker
// silent in it loses Slash and leaves the filing. Then: those left agree,
// an agreement (round 9, minor 10); they still differ, another rerun or a
// panel.
func settleRerun(cur realm, f *filing, id int) string {
	if f.allIn == 0 {
		if now() <= f.drawnAt+CheckWindow {
			panic("guards: still waiting for commitments")
		}
		if f.checks[0].commitment == "" {
			return workerSilent(cur, f, id)
		}
		slashSilent(f, func(c *check) bool { return c.commitment == "" })
		f.allIn = now() // those who committed may reveal
		return f.state
	}
	all, match := agreement(f.checks)
	if !all {
		if now() <= f.allIn+RevealWindow {
			panic("guards: still waiting for reveals")
		}
		if !f.checks[0].revealed {
			return workerSilent(cur, f, id)
		}
		slashSilent(f, func(c *check) bool { return !c.revealed })
		_, match = agreement(f.checks)
	}
	if match && len(f.checks) > 1 {
		f.state, f.verdict, f.until = Agreed, f.checks[0].transcript, now()+ObjectionWindow
		chain.Emit("GuardAgreed", "filing", strconv.Itoa(id), "hash", f.guardHash, "until", strconv.FormatInt(f.until, 10))
		return f.state
	}
	return dispute(f, id)
}

// panelRequest asks for the next panel, drawn from a beacon round after now
// and the pool as it is now; after the largest, the whole pool decides.
func panelRequest(f *filing, id int) string {
	if f.panelLevel >= len(PanelSizes) {
		f.state = Pool
		chain.Emit("GuardToPool", "filing", strconv.Itoa(id))
		return f.state
	}
	fixRound(f)
	f.state = Panel
	chain.Emit("GuardPanel", "filing", strconv.Itoa(id), "size", strconv.Itoa(PanelSizes[f.panelLevel]), "round", strconv.FormatUint(f.round, 10))
	return f.state
}

// DrawPanel draws a disputed filing's panel from its beacon round, by weight
// as checkers are drawn, never anyone already on the filing. The fund must
// hold the panel's fees, which it sets aside; when too few owners are
// eligible, the whole pool decides instead. Anyone may call it, within
// DrawDeadline of the round being fixed; after that, Settle fixes a new one.
func DrawPanel(cur realm, id int) {
	caller(cur)
	f := get(id)
	switch {
	case f.state != Panel:
		panic("guards: not waiting for a panel")
	case now() > f.fixedAt+DrawDeadline:
		panic("guards: the panel's deadline has passed; settle it for a new round")
	}
	size := PanelSizes[f.panelLevel]
	fee := int64(size) * PanelFee
	if fund < fee {
		panic("guards: the dispute fund can't pay this panel yet; disputes wait for it")
	}
	picks := pick(roundSig(f), "panel", id, f.panelLevel, size, f, f.fixedAt)
	if picks == nil {
		f.state = Pool
		chain.Emit("GuardToPool", "filing", strconv.Itoa(id))
		return
	}
	fund -= fee
	f.reserve += fee
	f.panelCost += fee
	var panel []*check
	for _, p := range picks {
		p.open++
		panel = append(panel, &check{ticket: p.id, owner: p.owner})
	}
	f.panels = append(f.panels, panel)
	f.state, f.drawnAt, f.allIn = Panelled, now(), 0
	chain.Emit("GuardPanelDrawn", "filing", strconv.Itoa(id), "size", strconv.Itoa(size), "members", joinComma(owners(panel)))
}

// settlePanel ends a panel's run once every member has revealed, or its
// window has closed (members still silent lose Slash): a transcript more
// than two thirds of the panel's size revealed is the panel's word, open
// to appeal; with none, a larger panel runs it.
func settlePanel(cur realm, f *filing, id int) string {
	last := len(f.panels) - 1
	size := PanelSizes[f.panelLevel]
	if f.allIn == 0 {
		if now() <= f.drawnAt+CheckWindow {
			panic("guards: still waiting for commitments")
		}
		f.panels[last] = keepAnswering(f.panels[last], func(c *check) bool { return c.commitment == "" })
		f.allIn = now() // those who committed may reveal
		return f.state
	}
	if all, _ := agreement(f.panels[last]); !all && now() <= f.allIn+RevealWindow {
		panic("guards: still waiting for reveals")
	}
	f.panels[last] = keepAnswering(f.panels[last], func(c *check) bool { return !c.revealed })
	if t, ok := supermajority(f.panels[last], size); ok {
		f.state, f.verdict, f.until = Appealable, t, now()+AppealWindow
		chain.Emit("GuardPanelWord", "filing", strconv.Itoa(id), "until", strconv.FormatInt(f.until, 10))
		return f.state
	}
	f.panelLevel++
	return panelRequest(f, id)
}

// Appeal takes a panel's word to the next panel, or the pool: a party it
// went against (the worker, a checker, an objector) puts up AppealBond,
// which comes back if the last word differs from the word appealed.
func Appeal(cur realm, id int) string {
	who := caller(cur)
	f := get(id)
	if f.state != Appealable || now() > f.until {
		panic("guards: nothing to appeal")
	}
	against := false
	for _, c := range f.checks {
		if c.owner == who && said(c) != f.verdict {
			against = true
		}
	}
	if o := f.objector; o != nil && o.owner == who && o.transcript != f.verdict {
		against = true
	}
	if !against {
		panic("guards: only a party the panel went against appeals")
	}
	f.appeals = append(f.appeals, appeal{who: who, bond: received(AppealBond), against: f.verdict})
	f.verdict, f.until = "", 0
	f.panelLevel++
	chain.Emit("GuardAppealed", "filing", strconv.Itoa(id), "by", string(who))
	return panelRequest(f, id)
}

// said is what a party said last: its open transcript, or the one before.
func said(c *check) string {
	if c.revealed {
		return c.transcript
	}
	return c.prev
}

// supermajority finds a transcript that more than two thirds of a panel of
// size revealed.
func supermajority(panel []*check, size int) (string, bool) {
	votes := map[string]int{}
	for _, c := range panel {
		if c.revealed {
			votes[c.transcript]++
			if votes[c.transcript]*3 > size*2 {
				return c.transcript, true
			}
		}
	}
	return "", false
}

// slashSilent takes Slash from each checker silent in a rerun, locks it
// here for good, and drops it from the filing.
func slashSilent(f *filing, silent func(*check) bool) {
	keep := f.checks[:1]
	for _, c := range f.checks[1:] {
		if silent(c) {
			burned += slash(c, Slash)
			release(c)
			f.silent[c.owner] = true
			rec(c.owner).Silent++
		} else {
			keep = append(keep, c)
		}
	}
	f.checks = keep
}

// keepAnswering drops panel members who stayed silent, taking Slash from
// each, locked here for good.
func keepAnswering(panel []*check, silent func(*check) bool) []*check {
	var keep []*check
	for _, c := range panel {
		if silent(c) {
			burned += slash(c, Slash)
			release(c)
			rec(c.owner).Silent++
		} else {
			keep = append(keep, c)
		}
	}
	return keep
}

// Fund adds the coins sent to the dispute fund.
func Fund(cur realm) {
	caller(cur)
	fund += received(1)
}

// FundBalance is what the dispute fund holds.
func FundBalance() int64 { return fund }

// PanelOf says who is on a filing's current panel, and its size.
func PanelOf(id int) ([]address, int) {
	f := get(id)
	var out []address
	if len(f.panels) > 0 {
		for _, c := range f.panels[len(f.panels)-1] {
			out = append(out, c.owner)
		}
	}
	if f.panelLevel >= len(PanelSizes) {
		return out, 0
	}
	return out, PanelSizes[f.panelLevel]
}

// Word is a filing's pending word (the agreed transcript, or a panel's) and
// when its window closes.
func Word(id int) (string, int64) {
	f := get(id)
	return f.verdict, f.until
}

func joinComma(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}
