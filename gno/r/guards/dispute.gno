package guards

import (
	"chain"
	"chain/params"
	"strconv"
)

// A dispute (AUTOPATCH.md, the swarm's rules 3 and 5): the transcripts of a
// filing differ.
//   - The same parties, the worker and its checkers, run it again, up to
//     Reruns times: honest runs that differed by chance now agree, and the
//     filing settles as usual.
//   - Then a fresh panel, drawn by stake from a beacon round after the
//     dispute, runs it: PanelSizes[0] members, then the next size if no side
//     reached more than two thirds of the panel, then the whole pool (F3).
//     A panel is paid from the dispute fund, and a dispute waits while the
//     fund can't pay it.
//   - The side with more than two thirds decides which transcript is right.
//     Whoever said otherwise, the worker or any checker or panelist, loses
//     its bond or Slash of its stake. Of what is taken, ShowShare percent
//     goes to the parties who said what was decided (they showed it), as
//     much as the panels cost goes back to the fund (the losing side pays
//     every panel), and the rest is locked here for good, so showing your
//     own work wrong always loses money.
var (
	Reruns           = 2
	PanelSizes       = []int{7, 15, 31}
	PanelFee   int64 = 100_000   // ugnot, to each panelist who runs it
	FundFee    int64 = 100_000   // ugnot of each filing's bond that settles, to the dispute fund
	Slash      int64 = 1_000_000 // ugnot taken from a ticket on the wrong side, or silent in a dispute
	ShowShare  int64 = 50        // percent of what is taken, to whoever showed it
)

// dispute begins, or goes on with, a dispute: a rerun by the same parties
// while reruns are left, then a panel.
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

// settleRerun ends a rerun: all agree, the filing settles as usual; they
// still differ, another rerun or a panel. A worker silent in it forfeits; a
// checker silent in it loses Slash, and a panel decides.
func settleRerun(cur realm, f *filing, id int) string {
	if f.allIn == 0 {
		if now() <= f.drawnAt+CheckWindow {
			panic("guards: still waiting for commitments")
		}
		if f.checks[0].commitment == "" {
			return workerSilent(cur, f, id)
		}
		if slashSilent(f, func(c *check) bool { return c.commitment == "" }) > 0 {
			return panelRequest(f, id)
		}
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
		return panelRequest(f, id)
	}
	if match {
		return settleAgreed(cur, f, id)
	}
	return dispute(f, id)
}

// panelRequest asks for the next panel, drawn from a beacon round after
// now; after the largest, the whole pool decides (F3).
func panelRequest(f *filing, id int) string {
	if f.panelLevel >= len(PanelSizes) {
		f.state = Pool
		chain.Emit("GuardToPool", "filing", strconv.Itoa(id))
		return f.state
	}
	f.state, f.round = Panel, drawRound()
	chain.Emit("GuardPanel", "filing", strconv.Itoa(id), "size", strconv.Itoa(PanelSizes[f.panelLevel]), "round", strconv.FormatUint(f.round, 10))
	return f.state
}

// DrawPanel draws a disputed filing's panel from its beacon round, by stake
// as checkers are drawn, never anyone already on the filing or on an
// earlier panel of it. The fund must hold the panel's fees, which it sets
// aside; when fewer distinct owners are eligible than the panel's size, the
// whole pool decides instead. Anyone may call it.
func DrawPanel(cur realm, id int) {
	caller(cur)
	f := get(id)
	if f.state != Panel {
		panic("guards: not waiting for a panel")
	}
	v := beacon.Get(key(f.round))
	if v == nil {
		panic("guards: submit beacon round " + strconv.FormatUint(f.round, 10) + " first")
	}
	size := PanelSizes[f.panelLevel]
	fee := int64(size) * PanelFee
	if fund < fee {
		panic("guards: the dispute fund can't pay this panel yet; disputes wait for it")
	}
	picks := pick(v.([]byte), "panel", id, f.panelLevel, size, f)
	if picks == nil {
		f.state = Pool
		chain.Emit("GuardToPool", "filing", strconv.Itoa(id))
		return
	}
	fund -= fee
	f.reserve = fee
	f.panel = nil
	for _, p := range picks {
		p.open++
		f.served[p.owner] = true
		f.panel = append(f.panel, &check{ticket: p.id, owner: p.owner})
	}
	f.state, f.drawnAt, f.allIn = Panelled, now(), 0
	var names []string
	for _, c := range f.panel {
		names = append(names, string(c.owner))
	}
	chain.Emit("GuardPanelDrawn", "filing", strconv.Itoa(id), "size", strconv.Itoa(size), "members", joinComma(names))
}

// settlePanel ends a panel's run: a transcript that more than two thirds of
// the panel's size revealed decides; when none can any more, the members
// who ran it are paid and a larger panel is asked for. A member silent in
// it loses Slash.
func settlePanel(cur realm, f *filing, id int) string {
	size := PanelSizes[f.panelLevel]
	if f.allIn == 0 {
		if now() <= f.drawnAt+CheckWindow {
			panic("guards: still waiting for commitments")
		}
		f.panel = keepAnswering(f, f.panel, func(c *check) bool { return c.commitment == "" })
		f.allIn = now() // those who committed may reveal
		return f.state
	}
	if t, ok := supermajority(f.panel, size); ok {
		return decide(cur, f, id, t)
	}
	if all, _ := agreement(f.panel); !all && now() <= f.allIn+RevealWindow {
		panic("guards: still waiting for reveals")
	}
	f.panel = keepAnswering(f, f.panel, func(c *check) bool { return !c.revealed })
	// No side reached two thirds: those who ran it are paid, and a larger
	// panel runs it.
	for _, c := range f.panel {
		pay(cur, c.owner, PanelFee)
		f.reserve -= PanelFee
		f.panelCost += PanelFee
		release(c)
	}
	fund += f.reserve
	f.reserve, f.panel = 0, nil
	f.panelLevel++
	return panelRequest(f, id)
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

// decide ends a dispute with the transcript t: the guard's level follows
// its verdict, everyone who said t is paid, and everyone who said otherwise
// loses its bond or Slash of its stake (see the top of this file).
func decide(cur realm, f *filing, id int, t string) string {
	said := func(c *check) string {
		if c.revealed {
			return c.transcript
		}
		return c.prev
	}
	var taken int64
	var showers []address
	w := f.checks[0]
	if said(w) == t {
		showers = append(showers, w.owner)
		bond := f.bond - FundFee
		fund += FundFee
		for _, c := range f.checks[1:] {
			if said(c) == t {
				pay(cur, c.owner, CheckFee)
				bond -= CheckFee
			}
		}
		pay(cur, w.owner, bond)
	} else {
		taken += f.bond // the worker said otherwise: its whole bond
		rec(w.owner).Faults++
	}
	f.bond = 0
	for _, c := range f.checks[1:] {
		if said(c) == t {
			showers = append(showers, c.owner)
			rec(c.owner).Checked++
		} else {
			taken += slash(c, Slash)
			rec(c.owner).Faults++
		}
		release(c)
	}
	var right []address
	for _, c := range f.panel {
		if c.revealed && c.transcript == t {
			pay(cur, c.owner, PanelFee)
			f.reserve -= PanelFee
			f.panelCost += PanelFee
			right = append(right, c.owner)
		} else {
			taken += slash(c, Slash) // said otherwise, or never revealed
			rec(c.owner).Faults++
		}
		release(c)
	}
	fund += f.reserve
	f.reserve = 0
	if len(showers) == 0 {
		showers = right // only the panel said it
	}
	// Of what was taken: the showers' share, then the panels' cost back to
	// the fund, and the rest locked for good.
	share := taken * ShowShare / 100
	if len(showers) > 0 {
		each := share / int64(len(showers))
		for _, a := range showers {
			pay(cur, a, each)
		}
		taken -= each * int64(len(showers))
	}
	refill := least(taken, f.panelCost)
	fund += refill
	burned += taken - refill
	if verdict(t) == "pass" {
		f.state = Tested
		levels.Set(f.guardHash, Tested)
		params.SetString("lvl_"+f.guardHash, Tested)
		if said(w) == t {
			rec(w.owner).Passed++
		}
	} else {
		f.state = Failed
		if said(w) == t {
			rec(w.owner).Failed++
		}
	}
	chain.Emit("GuardDecided", "filing", strconv.Itoa(id), "hash", f.guardHash, "state", f.state)
	return f.state
}

// slash takes up to n from a check's ticket and returns what it took.
func slash(c *check, n int64) int64 {
	t := ticketAt(c.ticket)
	n = least(n, t.stake)
	t.stake -= n
	return n
}

// slashSilent takes Slash from each checker silent in a rerun, locks it
// here for good, and drops it from the filing; it returns how many.
func slashSilent(f *filing, silent func(*check) bool) int {
	keep := f.checks[:1]
	n := 0
	for _, c := range f.checks[1:] {
		if silent(c) {
			burned += slash(c, Slash)
			release(c)
			f.silent[c.owner] = true
			rec(c.owner).Silent++
			n++
		} else {
			keep = append(keep, c)
		}
	}
	f.checks = keep
	return n
}

// keepAnswering drops panel members who stayed silent, taking Slash from
// each, locked here for good.
func keepAnswering(f *filing, panel []*check, silent func(*check) bool) []*check {
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
	for _, c := range f.panel {
		out = append(out, c.owner)
	}
	if f.panelLevel >= len(PanelSizes) {
		return out, 0
	}
	return out, PanelSizes[f.panelLevel]
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

func least(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
