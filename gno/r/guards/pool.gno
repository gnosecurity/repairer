package guards

import (
	"chain"
	"strconv"
	"strings"

	"gno.land/p/nt/avl/v0"
)

// The pool's vote (REPAIRER.md, the swarm's rule 3): the last word on a
// dispute no panel decided or a panel's word appealed past the largest.
// Every ticket staked MinTicketAge before the filing and not leaving when
// the vote opens votes with its weight: its owner commits, naming its
// tickets (in more calls if they are many, each with the same commitment;
// round 13, minor 3), then reveals after the commit window. A transcript
// revealed with more than a third of the vote's weight, the stake not
// leaving when it opened (round 13, minor 1), when no other is, wins, and
// the dispute ends as a panel's would (final) (round 11, new major 1).
// Liars under a third of that weight can't make a transcript win alone,
// and honest runs agree byte for byte, so one that holds over a third has
// honest weight behind it and is right; only more than half the honest
// weight staying away stalls the vote.
//
// No call walks every ticket or every voter (round 9, new major 6): the
// total is the stake tree's sum, revealed weight is kept as it comes in,
// winners claim their share of PoolFee by weight, voters are kept in a
// tree, so finding one reads one path (round 13, new major 1), and each
// ticket's charge is settled when it is withdrawn, or by anyone once the
// vote has closed (round 12, minor 2): AbstainShare percent for a ticket
// that didn't vote (decided or not: a stall is the abstainers'), WrongShare
// percent, and at least the voter's share of Slash, for one that voted what
// wasn't decided (round 9, minor 11), each to the fund (round 11, minor 3).
// A vote holds the tickets in it: none can be withdrawn until it closes. A
// ticket leaving before a vote opens isn't in it, so a leaving ticket waits
// only for votes already open, which close within UnbondBlocks (round 12,
// new major 1). A vote that stalls decides nothing: no level, the bonds
// back but CheckFee from the filer's for each checker that answered, no
// seat paid, and no panel's word settles any money; the abstainers are
// charged, and fines for silence already taken stand (round 11, new major
// 1; round 12, minor 3; round 13, minor 5). What winners leave unclaimed
// for PoolClaimWindow goes to the fund.
var (
	PoolCommitWindow int64 = 10000      // blocks (about 10 hours)
	PoolRevealWindow int64 = 5000       // blocks
	PoolFee          int64 = 10_000_000 // ugnot, shared by weight among the winning voters
	AbstainShare     int64 = 1          // percent of a ticket's stake for not voting
	WrongShare       int64 = 2          // percent of a ticket's stake for voting what wasn't decided
	PoolClaimWindow  int64 = 49000      // blocks after a vote closes for winners to claim; then the rest goes to the fund
)

type voter struct {
	weight     int64
	tickets    []int
	commitment string
	transcript string
	revealed   bool
	claimed    bool
}

type poolVote struct {
	filing    int
	open      int64 // height
	oldBelow  int
	total     int64
	revealed  int64
	committed int
	reveals   int
	by        map[string]int64 // transcript → revealed weight
	order     []string         // transcripts in the order first revealed: ties go to the first
	voters    *avl.Tree        // owner → *voter: one path read per lookup (round 13, new major 1)
	voted     *avl.Tree        // key(ticket) → true
	closed    bool
	closedAt  int64
	leaveMark int    // leaves when it opened: a ticket that began leaving by then has no vote in it
	decided   string // the winning transcript, or "" when undecided
	winners   int64  // the winning weight
	pot       int64  // PoolFee, set aside from the fund
}

var (
	votes     = map[int]*poolVote{} // filing → its vote
	allVotes  []*poolVote           // every vote, in the order opened
	openVotes []int                 // the votes not yet closed, by their place in allVotes: a short list
)

// OpenPool opens the pool's vote on a filing that reached the pool. The
// fund must hold PoolFee, which it sets aside; with no stake to vote, the
// filing ends undecided. Anyone may call it.
func OpenPool(cur realm, id int) string {
	caller(cur)
	f := get(id)
	if f.state != Pool {
		panic("guards: not waiting for the pool")
	}
	sum, left, _, _ := below(f.oldBelow)
	total := sum - left // tickets leaving by now have no vote and aren't held by it (round 12, new major 1)
	if total <= 0 {
		return undecided(cur, f, id) // round 9, minor 10
	}
	if fund < PoolFee {
		panic("guards: the dispute fund can't pay the pool's vote yet; disputes wait for it")
	}
	fund -= PoolFee
	f.panelCost += PoolFee
	v := &poolVote{filing: id, open: now(), leaveMark: leaves, oldBelow: f.oldBelow, total: total, by: map[string]int64{},
		voters: avl.NewTree(), voted: avl.NewTree(), pot: PoolFee}
	votes[id] = v
	openVotes = append(openVotes, len(allVotes))
	allVotes = append(allVotes, v)
	f.state = Voting
	chain.Emit("GuardPoolOpen", "filing", strconv.Itoa(id), "stake", strconv.FormatInt(total, 10))
	return f.state
}

// CommitVote commits an owner's vote with the tickets it names
// ("3,17,42"), each its own, staked MinTicketAge before the filing and not
// leaving when the vote opened: Commitment(owner, "vote", transcript, salt).
// An owner with more tickets than one call can name commits again with the
// same commitment, naming more (round 13, minor 3).
func CommitVote(cur realm, id int, ticketList, commitment string) {
	who := caller(cur)
	v := openVote(id)
	vt := v.voterOf(who)
	switch {
	case now() > v.open+PoolCommitWindow:
		panic("guards: the vote's commit window has passed")
	case !isHex(commitment, 64):
		panic("guards: a commitment is 64 hex digits")
	case vt != nil && vt.commitment != commitment:
		panic("guards: more tickets join your commitment only with that same commitment")
	}
	first := vt == nil
	if first {
		vt = &voter{commitment: commitment}
	}
	for _, s := range strings.Split(ticketList, ",") {
		tid, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			panic("guards: tickets are numbers, separated by commas")
		}
		t := ticketAt(tid)
		switch {
		case t.owner != who:
			panic("guards: ticket " + s + " isn't yours")
		case t.gone || !inVote(t, v):
			panic("guards: ticket " + s + " has no vote on this filing")
		case v.voted.Has(key(uint64(tid))):
			panic("guards: ticket " + s + " already voted")
		}
		v.voted.Set(key(uint64(tid)), true)
		vt.weight += t.weight
		vt.tickets = append(vt.tickets, tid)
	}
	if first {
		v.voters.Set(string(who), vt)
		v.committed++
	}
}

// voterOf is an owner's vote in v, or nil.
func (v *poolVote) voterOf(a address) *voter {
	if x := v.voters.Get(string(a)); x != nil {
		return x.(*voter)
	}
	return nil
}

// RevealVote opens a vote, once the commit window has closed and before the
// reveal window does: "<64-hex hash> pass|fail", as a transcript.
func RevealVote(cur realm, id int, transcript, salt string) {
	who := caller(cur)
	v := openVote(id)
	h := now()
	switch {
	case h <= v.open+PoolCommitWindow:
		panic("guards: votes open when the commit window closes")
	case h > v.open+PoolCommitWindow+PoolRevealWindow:
		panic("guards: the vote's reveal window has passed")
	case verdict(transcript) == "":
		panic("guards: a transcript is its 64-hex hash and pass or fail")
	}
	vt := v.voterOf(who)
	if vt == nil {
		panic("guards: no vote of yours was committed")
	}
	if vt.revealed {
		panic("guards: already revealed")
	}
	if Commitment(who, "vote", transcript, salt) != vt.commitment {
		panic("guards: that isn't what was committed")
	}
	vt.transcript, vt.revealed = transcript, true
	if v.by[transcript] == 0 {
		v.order = append(v.order, transcript)
	}
	v.by[transcript] += vt.weight
	v.revealed += vt.weight
	v.reveals++
}

// Tally ends the vote once the reveal window has closed, or the commit
// window has and every committed vote is open (round 9, new major 5).
// Anyone may call it.
func Tally(cur realm, id int) string {
	caller(cur)
	f := get(id)
	v := openVote(id)
	h := now()
	done := h > v.open+PoolCommitWindow+PoolRevealWindow || (h > v.open+PoolCommitWindow && v.reveals == v.committed)
	if !done {
		panic("guards: the vote is still open")
	}
	v.closed, v.closedAt = true, h
	for i, n := range openVotes {
		if allVotes[n] == v {
			openVotes = append(openVotes[:i], openVotes[i+1:]...)
			break
		}
	}
	best, over := "", 0
	for _, t := range v.order {
		if v.by[t]*3 > v.total {
			best = t
			over++
		}
	}
	if over != 1 { // a stall: nothing decided; the bonds back but the checkers' fees
		fund += v.pot
		f.panelCost -= v.pot
		v.pot = 0
		return undecided(cur, f, id)
	}
	v.decided, v.winners = best, v.by[best]
	return final(cur, f, id, best)
}

// ClaimVote pays a winning voter its share of PoolFee, by weight.
func ClaimVote(cur realm, id int) int64 {
	who := caller(cur)
	v := votes[id]
	if v == nil || !v.closed || v.decided == "" {
		panic("guards: no decided vote on this filing")
	}
	vt := v.voterOf(who)
	if vt == nil || !vt.revealed || vt.transcript != v.decided || vt.claimed {
		panic("guards: nothing of yours to claim")
	}
	vt.claimed = true
	n := mulDiv(PoolFee, vt.weight, v.winners)
	n = least(n, v.pot)
	v.pot -= n
	pay(cur, who, n)
	return n
}

// SweepVote moves what a decided vote's winners left unclaimed, and the
// rounding, into the fund, once PoolClaimWindow has passed since it closed
// (round 10, minor 6). Anyone may call it.
func SweepVote(cur realm, id int) int64 {
	caller(cur)
	v := votes[id]
	if v == nil || !v.closed || now() <= v.closedAt+PoolClaimWindow {
		panic("guards: winners may still claim from this vote")
	}
	n := v.pot
	fund += n
	v.pot = 0
	return n
}

// undecided ends a dispute whose vote stalled: no level, the bonds back,
// every ticket let go. Each checker that answered is paid CheckFee from the
// filer's bond for running the rig, as an abandon pays it (round 12, minor
// 3); no panel seat is paid. Fines for silence already taken stand.
func undecided(cur realm, f *filing, id int) string {
	fund += f.reserve
	f.reserve = 0
	bond := f.bond
	for _, c := range f.checks[1:] {
		if c.revealed || c.prev != "" {
			pay(cur, c.owner, CheckFee)
			bond -= CheckFee
		}
		release(c)
	}
	pay(cur, f.filer, bond)
	f.bond = 0
	for _, p := range f.panels {
		for _, c := range p {
			release(c)
		}
	}
	for i, a := range f.appeals { // kept, settled, for the filing's page
		pay(cur, a.who, a.bond)
		f.appeals[i].bond = 0
	}
	if f.objector != nil {
		pay(cur, f.objector.owner, f.objBond)
		f.objBond = 0
	}
	f.state = Undecided
	chain.Emit("GuardUndecided", "filing", strconv.Itoa(id), "hash", f.guardHash)
	return f.state
}

func openVote(id int) *poolVote {
	f := get(id)
	v := votes[id]
	if f.state != Voting || v == nil || v.closed {
		panic("guards: no vote is open on this filing")
	}
	return v
}

// inVote says whether a ticket has a vote in v: in its prefix, and not
// leaving when it opened. A ticket leaving before a vote opened is neither
// held by it nor charged for not voting in it, so a leaving ticket waits
// only for votes already open, which close well within UnbondBlocks
// (round 12, new major 1).
func inVote(t *ticket, v *poolVote) bool {
	return t.id < v.oldBelow && (t.leftNo == 0 || t.leftNo > v.leaveMark)
}

// inOpenVote says whether a ticket may still vote in a vote not yet closed.
func inOpenVote(t *ticket) bool {
	for _, i := range openVotes {
		if i >= t.votes && inVote(t, allVotes[i]) {
			return true
		}
	}
	return false
}

// settleVotes charges a ticket, as it leaves, for up to max closed votes it
// had a vote in, in order: AbstainShare percent when it didn't vote,
// WrongShare percent (and at least its share of Slash) when it voted what
// wasn't decided. It stops at a vote still open that the ticket may vote
// in.
func settleVotes(t *ticket, max int) {
	for ; max > 0 && t.votes < len(allVotes); t.votes++ {
		max--
		v := allVotes[t.votes]
		if !inVote(t, v) {
			continue
		}
		if !v.closed {
			return
		}
		// The ticket's own entry first: an abstainer's charge reads no voter
		// (round 13, new major 1).
		voted := v.voted.Has(key(uint64(t.id)))
		var vt *voter
		if voted {
			vt = v.voterOf(t.owner)
			voted = vt != nil && vt.revealed
		}
		switch {
		case !voted:
			fund += charge(t, t.stake*AbstainShare/100)
		case v.decided != "" && vt.transcript != v.decided:
			n := t.stake * WrongShare / 100
			if s := Slash / int64(len(vt.tickets)); s > n {
				n = s
			}
			fund += charge(t, n)
		}
	}
}

// VoteOf says an owner's weight in a filing's vote and whether it revealed.
func VoteOf(id int, a address) (int64, bool) {
	v := votes[id]
	if v == nil {
		return 0, false
	}
	vt := v.voterOf(a)
	if vt == nil {
		return 0, false
	}
	return vt.weight, vt.revealed
}
