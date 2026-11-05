package guards

import (
	"chain"
	"strconv"
	"strings"

	"gno.land/p/nt/avl/v0"
)

// The pool's vote (AUTOPATCH.md, the swarm's rule 3): the last word on a
// dispute no panel decided or a panel's word appealed past the largest.
// Every ticket staked MinTicketAge before the filing and not withdrawn
// votes with its weight: its owner commits once, naming its tickets, then
// reveals after the commit window. It decides by Tendermint's rule: once
// more than two thirds of all that weight has revealed, the transcript with
// the most weight wins, and the dispute ends as a panel's would (final).
// With liars under a third of the stake, the honest side always wins.
//
// No call walks every ticket or every voter (round 9, new major 6): the
// total is the stake tree's sum, revealed weight is kept as it comes in,
// winners claim their share of PoolFee by weight, and each ticket's charge
// is settled when it is withdrawn: AbstainShare percent for a ticket that
// didn't vote (decided or not: a stall is the abstainers'), WrongShare
// percent, and at least the voter's share of Slash, for one that voted what
// wasn't decided (round 9, minor 11). A ticket can't leave while a vote it
// may vote in is open. A vote that never reaches two thirds decides
// nothing: no level, nobody paid, every bond back.
var (
	PoolCommitWindow int64 = 10000      // blocks (about 10 hours)
	PoolRevealWindow int64 = 5000       // blocks
	PoolFee          int64 = 10_000_000 // ugnot, shared by weight among the winning voters
	AbstainShare     int64 = 1          // percent of a ticket's stake for not voting
	WrongShare       int64 = 2          // percent of a ticket's stake for voting what wasn't decided
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
	voters    map[address]*voter
	voted     *avl.Tree // key(ticket) → true
	closed    bool
	decided   string // the winning transcript, or "" when undecided
	winners   int64  // the winning weight
	pot       int64  // PoolFee, set aside from the fund
}

var (
	votes    = map[int]*poolVote{} // filing → its vote
	allVotes []*poolVote           // every vote, in the order opened
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
	total := sumBelow(f.oldBelow)
	if total <= 0 {
		return undecided(cur, f, id) // round 9, minor 10
	}
	if fund < PoolFee {
		panic("guards: the dispute fund can't pay the pool's vote yet; disputes wait for it")
	}
	fund -= PoolFee
	f.panelCost += PoolFee
	v := &poolVote{filing: id, open: now(), oldBelow: f.oldBelow, total: total, by: map[string]int64{},
		voters: map[address]*voter{}, voted: avl.NewTree(), pot: PoolFee}
	votes[id] = v
	allVotes = append(allVotes, v)
	f.state = Voting
	chain.Emit("GuardPoolOpen", "filing", strconv.Itoa(id), "stake", strconv.FormatInt(total, 10))
	return f.state
}

// CommitVote commits an owner's vote with the tickets it names
// ("3,17,42"), each its own, staked MinTicketAge before the filing and not
// withdrawn: Commitment(owner, "vote", transcript, salt).
func CommitVote(cur realm, id int, ticketList, commitment string) {
	who := caller(cur)
	v := openVote(id)
	switch {
	case now() > v.open+PoolCommitWindow:
		panic("guards: the vote's commit window has passed")
	case !isHex(commitment, 64):
		panic("guards: a commitment is 64 hex digits")
	case v.voters[who] != nil:
		panic("guards: already committed")
	}
	vt := &voter{commitment: commitment}
	for _, s := range strings.Split(ticketList, ",") {
		tid, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			panic("guards: tickets are numbers, separated by commas")
		}
		t := ticketAt(tid)
		switch {
		case t.owner != who:
			panic("guards: ticket " + s + " isn't yours")
		case t.gone || tid >= v.oldBelow:
			panic("guards: ticket " + s + " has no vote on this filing")
		case v.voted.Has(key(uint64(tid))):
			panic("guards: ticket " + s + " already voted")
		}
		v.voted.Set(key(uint64(tid)), true)
		vt.weight += t.weight
		vt.tickets = append(vt.tickets, tid)
	}
	v.voters[who] = vt
	v.committed++
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
	vt := v.voters[who]
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
	v.closed = true
	if v.revealed*3 <= v.total*2 {
		fund += v.pot
		v.pot = 0
		return undecided(cur, f, id)
	}
	best := ""
	for _, t := range v.order {
		if v.by[t] > v.by[best] {
			best = t
		}
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
	vt := v.voters[who]
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

// undecided ends a dispute with no last word: no level, nobody paid or
// charged for the dispute, every bond back and every ticket let go.
func undecided(cur realm, f *filing, id int) string {
	fund += f.reserve
	f.reserve = 0
	pay(cur, f.filer, f.bond)
	f.bond = 0
	for _, c := range f.checks[1:] {
		release(c)
	}
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

// inOpenVote says whether a ticket may still vote in a vote not yet closed.
func inOpenVote(t *ticket) bool {
	for i := t.votes; i < len(allVotes); i++ {
		if v := allVotes[i]; !v.closed && t.id < v.oldBelow {
			return true
		}
	}
	return false
}

// settleVotes charges a ticket, as it leaves, for each closed vote it had a
// vote in: AbstainShare percent when it didn't vote, WrongShare percent (and
// at least its share of Slash) when it voted what wasn't decided.
func settleVotes(t *ticket) {
	for ; t.votes < len(allVotes); t.votes++ {
		v := allVotes[t.votes]
		if t.id >= v.oldBelow {
			continue
		}
		vt := v.voters[t.owner]
		voted := v.voted.Has(key(uint64(t.id))) && vt != nil && vt.revealed
		switch {
		case !voted:
			burned += charge(t, t.stake*AbstainShare/100)
		case v.decided != "" && vt.transcript != v.decided:
			n := t.stake * WrongShare / 100
			if s := Slash / int64(len(vt.tickets)); s > n {
				n = s
			}
			burned += charge(t, n)
		}
	}
}

// VoteOf says an owner's weight in a filing's vote and whether it revealed.
func VoteOf(id int, a address) (int64, bool) {
	v := votes[id]
	if v == nil || v.voters[a] == nil {
		return 0, false
	}
	return v.voters[a].weight, v.voters[a].revealed
}
