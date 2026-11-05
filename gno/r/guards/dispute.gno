package guards

import (
	"chain"
	"strconv"
)

// A dispute (AUTOPATCH.md, the swarm's rules 3 and 5): a filing's
// transcripts differ, or someone objected to their agreement.
//   - The same parties, the worker and its checkers, run it again, up to
//     Reruns times: honest runs that differed by chance now agree, and the
//     filing goes on as an agreement. At the last word, whoever differed
//     from it in an earlier run pays RerunFee for each such run, to the fund
//     (round 10, minor 4). An objection skips the reruns.
//   - Then a panel runs it: PanelSizes[0] seats, then the next size when no
//     side holds more than two thirds of the seats, then the whole pool
//     (pool.gno). Each seat is a ticket drawn by weight from a beacon round
//     after the dispute, from every eligible ticket, the parties' and
//     appellants' too, so each owner's seats follow its stake however many
//     addresses hold it (round 10, new major 2; round 11, new major 1); an
//     owner answers once for all its seats. A panel is decided only once
//     every member has revealed or its reveal window has closed, so nobody
//     revealing in time is charged (round 9, new major 5). The dispute fund
//     pays a panel's fees and its draw when its round is fixed: while the
//     fund can't, the dispute waits with no round, so whoever tops the fund
//     up can't pick a round already seen (round 11, minor 6).
//   - Anyone may appeal a panel's word within AppealWindow, putting up at
//     least what the next panel or the vote costs the fund: the next panel,
//     or the pool, decides. Nothing is paid or taken until the last word
//     (round 9, new major 3), and then everyone on every panel of the
//     dispute, every appellant too, is judged by it (final, in guards.gno).
var (
	Reruns             = 2
	PanelSizes         = []int{7, 15, 31}
	PanelFee     int64 = 100_000   // ugnot, to each seat that said the last word
	FundFee      int64 = 100_000   // ugnot of each filing's bond that settles, to the dispute fund
	Slash        int64 = 1_000_000 // ugnot taken from a ticket for each seat on the wrong side, or silent in a dispute
	ShowShare    int64 = 50        // percent of what is taken, once the fund is paid back, to whoever showed it
	AppealWindow int64 = 2000      // blocks after a panel's word in which anyone may appeal
	AppealBond   int64 = 1_000_000 // ugnot an appellant puts up at least: more when the next panel or the vote costs more
	RerunFee     int64 = 500_000   // ugnot, to the fund, from a party for each run it differed from the agreement
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
			c.past = append(c.past, c.transcript)
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

// rerunsOwed is what a party owes for the reruns it caused: RerunFee for
// each earlier run whose transcript differed from the last word t. Honest
// runs agree byte for byte, so only a party that differed pays (round 10,
// minor 4).
func rerunsOwed(c *check, t string) int64 {
	var n int64
	for _, p := range c.past {
		if p != t {
			n += RerunFee
		}
	}
	return n
}

// panelRequest asks for the next panel; after the largest, the whole pool
// decides. The fund sets aside the panel's fees and its draw, and the round
// that draws it is fixed then; while the fund can't pay, the dispute waits
// for RequestPanel, with no round.
func panelRequest(f *filing, id int) string {
	if f.panelLevel >= len(PanelSizes) {
		f.state = Pool
		chain.Emit("GuardToPool", "filing", strconv.Itoa(id))
		return f.state
	}
	cost := panelCost(f.panelLevel)
	if fund < cost {
		f.state = PanelWait
		chain.Emit("GuardPanelWait", "filing", strconv.Itoa(id), "fund", strconv.FormatInt(fund, 10), "cost", strconv.FormatInt(cost, 10))
		return f.state
	}
	fund -= cost
	f.reserve += cost
	f.panelCost += cost
	fixRound(f, id)
	f.state = Panel
	chain.Emit("GuardPanel", "filing", strconv.Itoa(id), "size", strconv.Itoa(PanelSizes[f.panelLevel]), "round", strconv.FormatUint(f.round, 10))
	return f.state
}

// panelCost is what a panel costs the fund: each seat's PanelFee, and its
// draw.
func panelCost(level int) int64 { return int64(PanelSizes[level])*PanelFee + DrawFee }

// RequestPanel asks again for a panel the fund couldn't pay. Anyone may
// call it.
func RequestPanel(cur realm, id int) string {
	caller(cur)
	f := get(id)
	if f.state != PanelWait {
		panic("guards: not waiting for the fund")
	}
	return panelRequest(f, id)
}

// DrawPanel draws a disputed filing's panel from its beacon round: each seat
// a ticket drawn by weight, so an owner may hold several. The caller is paid
// DrawFee from what the fund set aside; when the pool has too few eligible
// tickets, the seats' fees go back and the whole pool decides instead.
// Anyone may call it, within DrawDeadline of the round being fixed; after
// that, Settle fixes a new one.
func DrawPanel(cur realm, id int) {
	who := caller(cur)
	f := get(id)
	switch {
	case f.state != Panel:
		panic("guards: not waiting for a panel")
	case now() > f.fixedAt+DrawDeadline:
		panic("guards: the panel's deadline has passed; settle it for a new round")
	}
	size := PanelSizes[f.panelLevel]
	if moved(f) {
		fixRound(f, id) // its fees stay set aside
		chain.Emit("GuardPanel", "filing", strconv.Itoa(id), "size", strconv.Itoa(size), "round", strconv.FormatUint(f.round, 10), "why", "the pool moved")
		return
	}
	picks := pick(roundSig(f), "panel", id, f.panelLevel, size, f, true)
	unwait(f, id)
	compact(4)
	f.reserve -= DrawFee
	pay(cur, who, DrawFee)
	if picks == nil {
		fee := int64(size) * PanelFee
		f.reserve -= fee
		f.panelCost -= fee
		fund += fee
		f.state = Pool
		chain.Emit("GuardToPool", "filing", strconv.Itoa(id))
		return
	}
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
// window has closed (seats still silent lose Slash): a transcript revealed
// for more than two thirds of the panel's seats is the panel's word, open
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

// Appeal takes a panel's word to the next panel, or the pool. Anyone may
// appeal, not only the parties, so a decoy objection leaves nobody honest
// without a way on (round 10, new major 2); the appellant puts up what the
// next step costs the fund, at least AppealBond, which comes back if the
// last word differs from the word appealed, with a share of what is taken
// (round 11, minor 3).
func Appeal(cur realm, id int) string {
	who := caller(cur)
	f := get(id)
	if f.state != Appealable || now() > f.until {
		panic("guards: nothing to appeal")
	}
	f.appeals = append(f.appeals, appeal{who: who, bond: received(AppealCost(id)), against: f.verdict})
	f.verdict, f.until = "", 0
	f.panelLevel++
	chain.Emit("GuardAppealed", "filing", strconv.Itoa(id), "by", string(who))
	return panelRequest(f, id)
}

// AppealCost is what appealing a filing's panel's word costs now: what the
// next panel or the pool's vote costs the fund, and at least AppealBond.
func AppealCost(id int) int64 {
	f := get(id)
	cost := PoolFee
	if next := f.panelLevel + 1; next < len(PanelSizes) {
		cost = panelCost(next)
	}
	if cost < AppealBond {
		cost = AppealBond
	}
	return cost
}

// said is what a party said last: its open transcript, or the one before.
func said(c *check) string {
	if c.revealed {
		return c.transcript
	}
	return c.prev
}

// supermajority finds a transcript revealed for more than two thirds of a
// panel's size in seats.
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

// slashSilent takes Slash from each checker silent in a rerun, for the fund
// (round 11, minor 3), and drops it from the filing.
func slashSilent(f *filing, silent func(*check) bool) {
	keep := f.checks[:1]
	for _, c := range f.checks[1:] {
		if silent(c) {
			fund += slash(c, Slash)
			release(c)
			f.silent[c.owner] = true
			rec(c.owner).Silent++
		} else {
			keep = append(keep, c)
		}
	}
	f.checks = keep
}

// keepAnswering drops a panel's silent seats, taking Slash for each, for the
// fund (round 11, minor 3).
func keepAnswering(panel []*check, silent func(*check) bool) []*check {
	var keep []*check
	counted := map[address]bool{}
	for _, c := range panel {
		if silent(c) {
			fund += slash(c, Slash)
			release(c)
			if !counted[c.owner] {
				counted[c.owner] = true
				rec(c.owner).Silent++
			}
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

// PanelOf says who sits on a filing's current panel, each owner once, and
// the panel's size in seats.
func PanelOf(id int) ([]address, int) {
	f := get(id)
	var out []address
	seen := map[address]bool{}
	if len(f.panels) > 0 {
		for _, c := range f.panels[len(f.panels)-1] {
			if !seen[c.owner] {
				seen[c.owner] = true
				out = append(out, c.owner)
			}
		}
	}
	if f.panelLevel >= len(PanelSizes) {
		return out, 0
	}
	return out, PanelSizes[f.panelLevel]
}

// SeatsOf says how many seats an owner holds on a filing's current panel.
func SeatsOf(id int, a address) int {
	f := get(id)
	n := 0
	if len(f.panels) > 0 {
		for _, c := range f.panels[len(f.panels)-1] {
			if c.owner == a {
				n++
			}
		}
	}
	return n
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
