package guards

import (
	"chain"
	"strconv"
)

// The pool's vote (AUTOPATCH.md, the swarm's rule 3): the last word on a
// dispute no panel could decide. Every owner of a ticket staked
// MinTicketAge before the filing, and not leaving, votes with the stake of
// those tickets, by commit and reveal before deadlines: commitments for
// PoolCommitWindow blocks, then reveals for PoolRevealWindow. It decides by
// Tendermint's rule: once more than two thirds of all that stake has
// revealed, the transcript with the most stake wins, and the dispute ends
// as a panel's would (decide), with voters on the losing side losing Slash
// too. With liars under a third of the stake, the honest side always wins.
// The vote can stall: an owner who doesn't reveal loses AbstainShare
// percent of its stake, and a vote that never reaches two thirds decides
// nothing: the guard gets no level, nobody is paid, and the bonds and
// tickets are let go. The voters on the winning side share PoolFee, set
// aside from the dispute fund when the vote opens. Every voting ticket is
// held until the tally, so a voter can't leave before it.
var (
	PoolCommitWindow int64 = 10000      // blocks (about 10 hours)
	PoolRevealWindow int64 = 5000       // blocks
	PoolFee          int64 = 10_000_000 // ugnot, shared by stake among the winning voters
	AbstainShare     int64 = 1          // percent of an abstainer's stake
)

// Undecided: the pool's vote never reached two thirds of the stake.
const (
	Voting    = "voting"
	Undecided = "undecided"
)

type vote struct {
	stake      int64
	tickets    []int
	commitment string
	transcript string
	revealed   bool
}

type poolVote struct {
	open   int64 // height
	total  int64
	voters map[address]*vote
	order  []address // in the order of their first ticket, for a fixed iteration
}

var votes = map[int]*poolVote{} // filing → its vote

// OpenPool opens the pool's vote on a filing that reached the pool. The
// fund must hold PoolFee, which it sets aside. Anyone may call it.
func OpenPool(cur realm, id int) {
	caller(cur)
	f := get(id)
	if f.state != Pool {
		panic("guards: not waiting for the pool")
	}
	if fund < PoolFee {
		panic("guards: the dispute fund can't pay the pool's vote yet; disputes wait for it")
	}
	pv := &poolVote{open: now(), voters: map[address]*vote{}}
	tickets.Iterate("", "", func(_ string, v any) bool {
		t := v.(*ticket)
		if t.leaving == 0 && t.stake > 0 && t.height+MinTicketAge <= f.committed {
			vt := pv.voters[t.owner]
			if vt == nil {
				vt = &vote{}
				pv.voters[t.owner] = vt
				pv.order = append(pv.order, t.owner)
			}
			vt.stake += t.stake
			vt.tickets = append(vt.tickets, t.id)
			pv.total += t.stake
			t.open++
		}
		return false
	})
	if pv.total == 0 {
		panic("guards: no stake to vote")
	}
	fund -= PoolFee
	f.reserve = PoolFee
	votes[id] = pv
	f.state = Voting
	chain.Emit("GuardPoolOpen", "filing", strconv.Itoa(id), "stake", strconv.FormatInt(pv.total, 10), "voters", strconv.Itoa(len(pv.order)))
}

// CommitVote commits an owner's vote: Commitment(owner, "vote", transcript,
// salt), during the commit window.
func CommitVote(cur realm, id int, commitment string) {
	who := caller(cur)
	_, pv := voting(id)
	if now() > pv.open+PoolCommitWindow {
		panic("guards: the vote's commit window has passed")
	}
	if !isHex(commitment, 64) {
		panic("guards: a commitment is 64 hex digits")
	}
	vt := pv.voters[who]
	if vt == nil {
		panic("guards: no stake of yours votes on this filing")
	}
	if vt.commitment != "" {
		panic("guards: already committed")
	}
	vt.commitment = commitment
}

// RevealVote opens a vote, once the commit window has closed and before
// the reveal window does: "<64-hex hash> pass|fail", as a transcript.
func RevealVote(cur realm, id int, transcript, salt string) {
	who := caller(cur)
	_, pv := voting(id)
	h := now()
	switch {
	case h <= pv.open+PoolCommitWindow:
		panic("guards: votes open when the commit window closes")
	case h > pv.open+PoolCommitWindow+PoolRevealWindow:
		panic("guards: the vote's reveal window has passed")
	case verdict(transcript) == "":
		panic("guards: a transcript is its 64-hex hash and pass or fail")
	}
	vt := pv.voters[who]
	if vt == nil || vt.commitment == "" {
		panic("guards: no vote of yours was committed")
	}
	if vt.revealed {
		panic("guards: already revealed")
	}
	if Commitment(who, "vote", transcript, salt) != vt.commitment {
		panic("guards: that isn't what was committed")
	}
	vt.transcript, vt.revealed = transcript, true
}

// Tally ends the vote: as soon as one transcript has more than two thirds
// of all the stake, or once the reveal window has closed. Anyone may call
// it.
func Tally(cur realm, id int) string {
	caller(cur)
	f, pv := voting(id)
	byStake := map[string]int64{}
	var revealed int64
	for _, a := range pv.order {
		if vt := pv.voters[a]; vt.revealed {
			byStake[vt.transcript] += vt.stake
			revealed += vt.stake
		}
	}
	best, bestStake := "", int64(0)
	for _, a := range pv.order { // a fixed order: ties go to the first revealed
		if vt := pv.voters[a]; vt.revealed && byStake[vt.transcript] > bestStake {
			best, bestStake = vt.transcript, byStake[vt.transcript]
		}
	}
	closed := now() > pv.open+PoolCommitWindow+PoolRevealWindow
	if !closed && bestStake*3 <= pv.total*2 {
		panic("guards: the vote is still open")
	}
	// Abstainers lose a share of their stake, decided or not: a stall is
	// theirs.
	for _, a := range pv.order {
		if vt := pv.voters[a]; !vt.revealed {
			for _, tid := range vt.tickets {
				t := ticketAt(tid)
				n := t.stake * AbstainShare / 100
				t.stake -= n
				burned += n
			}
			rec(a).Silent++
		}
	}
	defer letGo(pv)
	if revealed*3 <= pv.total*2 {
		return undecided(cur, f, id)
	}
	// The winning voters share PoolFee by stake; the losing ones lose Slash
	// (their tickets' stake, first ticket first), locked for good.
	reserve := f.reserve
	f.reserve = 0
	for _, a := range pv.order {
		vt := pv.voters[a]
		if !vt.revealed {
			continue
		}
		if vt.transcript == best {
			n := PoolFee * vt.stake / bestStake
			pay(cur, a, n)
			reserve -= n
		} else {
			left := Slash
			for _, tid := range vt.tickets {
				t := ticketAt(tid)
				n := least(left, t.stake)
				t.stake -= n
				burned += n
				left -= n
			}
			rec(a).Faults++
		}
	}
	fund += reserve
	f.panelCost += PoolFee
	delete(votes, id)
	return decide(cur, f, id, best)
}

// undecided ends a vote that never reached two thirds: no level, nobody
// paid or charged for the dispute, the bond back to the worker and every
// ticket let go.
func undecided(cur realm, f *filing, id int) string {
	fund += f.reserve
	f.reserve = 0
	pay(cur, f.filer, f.bond)
	f.bond = 0
	for _, c := range f.checks[1:] {
		release(c)
	}
	delete(votes, id)
	f.state = Undecided
	chain.Emit("GuardUndecided", "filing", strconv.Itoa(id), "hash", f.guardHash)
	return f.state
}

// letGo releases every voting ticket.
func letGo(pv *poolVote) {
	for _, a := range pv.order {
		for _, tid := range pv.voters[a].tickets {
			ticketAt(tid).open--
		}
	}
}

func voting(id int) (*filing, *poolVote) {
	f := get(id)
	pv := votes[id]
	if f.state != Voting || pv == nil {
		panic("guards: no vote is open on this filing")
	}
	return f, pv
}

// VoteOf says an owner's stake in a filing's vote and whether it revealed.
func VoteOf(id int, a address) (int64, bool) {
	pv := votes[id]
	if pv == nil || pv.voters[a] == nil {
		return 0, false
	}
	return pv.voters[a].stake, pv.voters[a].revealed
}
