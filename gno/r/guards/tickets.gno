package guards

import (
	"crypto/sha256"
	"strconv"
)

// Tickets and the draw (round 9, new majors 1 and 6).
//
// A ticket's weight in every draw is the stake it was staked with, fixed;
// fines and slashes lower what is left to charge, never the weight. A tree
// of stake sums over ticket numbers draws a ticket in sumDepth reads, so
// no call walks every ticket. A filing's draws see the pool as it was when
// its beacon round was fixed: tickets staked MinTicketAge before the filing
// (a prefix of ticket numbers, found at Commit), not withdrawn, and not
// unstaked before the round was fixed. Unstaking after that changes no
// draw, and a draw must come within DrawDeadline, shorter than
// UnbondBlocks, so any ticket it may name is still there to charge.

type ticket struct {
	id      int
	owner   address
	weight  int64 // the stake staked: its weight in every draw, fixed
	stake   int64 // what is left to charge or give back
	height  int64 // staked at
	leaving int64 // Unstake's height, or when charges left it under the floor; 0 while staked
	open    int   // unsettled filings it is drawn into
	gone    bool  // withdrawn: out of the tree
	votes   int   // the pool votes whose charges it has settled, in order (pool.gno)
}

// sumDepth bounds the tickets at 2^sumDepth.
const sumDepth = 20

type sumNode struct {
	sum  int64
	l, r *sumNode
}

var sumRoot = &sumNode{}

// sumAdd adds w to ticket i's weight in the tree.
func sumAdd(i int, w int64) {
	n := sumRoot
	n.sum += w
	for d := sumDepth - 1; d >= 0; d-- {
		if i>>d&1 == 0 {
			if n.l == nil {
				n.l = &sumNode{}
			}
			n = n.l
		} else {
			if n.r == nil {
				n.r = &sumNode{}
			}
			n = n.r
		}
		n.sum += w
	}
}

// sumBelow is the weight of tickets numbered below k.
func sumBelow(k int) int64 {
	if k >= 1<<sumDepth {
		return sumRoot.sum
	}
	var s int64
	n := sumRoot
	for d := sumDepth - 1; d >= 0 && n != nil; d-- {
		if k>>d&1 == 1 {
			if n.l != nil {
				s += n.l.sum
			}
			n = n.r
		} else {
			n = n.l
		}
	}
	return s
}

// LiveStake is the weight of every ticket not withdrawn: what a level's
// stake floor is measured against.
func LiveStake() int64 { return sumRoot.sum }

// StakeTicket stakes the coins sent as one checker's ticket and returns its
// number.
func StakeTicket(cur realm) int {
	if nTickets >= 1<<sumDepth {
		panic("guards: no more tickets")
	}
	who := caller(cur)
	n := received(MinTicket)
	t := &ticket{id: nTickets, owner: who, weight: n, stake: n, height: now(), votes: len(allVotes)}
	nTickets++
	tickets.Set(key(uint64(t.id)), t)
	sumAdd(t.id, t.weight)
	emitTicket("TicketStaked", t)
	return t.id
}

// Unstake stops a ticket being drawn into filings whose round is fixed from
// now on. Withdraw returns its stake UnbondBlocks later, once every check it
// was drawn into has settled.
func Unstake(cur realm, id int) {
	t := ownTicket(cur, id)
	if t.leaving != 0 {
		panic("guards: already unstaking")
	}
	t.leaving = now()
}

// Withdraw settles an unstaked ticket's charges from the pool's votes and
// returns what is left of its stake.
func Withdraw(cur realm, id int) {
	t := ownTicket(cur, id)
	switch {
	case t.leaving == 0:
		panic("guards: unstake first")
	case now() < t.leaving+UnbondBlocks:
		panic("guards: still unbonding")
	case t.open > 0:
		panic("guards: drawn into a check that hasn't settled")
	case t.gone:
		panic("guards: already withdrawn")
	case inOpenVote(t):
		panic("guards: a pool vote it may vote in is still open")
	}
	settleVotes(t)
	n := t.stake
	t.stake, t.gone = 0, true
	sumAdd(t.id, -t.weight)
	pay(cur, t.owner, n)
}

// charge takes up to n from a ticket and returns what it took; a ticket
// left under half the minimum stops being drawn into later rounds.
func charge(t *ticket, n int64) int64 {
	n = least(n, t.stake)
	t.stake -= n
	if t.stake < MinTicket/2 && t.leaving == 0 {
		t.leaving = now()
	}
	return n
}

// oldBelow is how many tickets were staked at or before height h: ticket
// numbers rise with their heights.
func oldBelow(h int64) int {
	lo, hi := 0, nTickets
	for lo < hi {
		m := (lo + hi) / 2
		if ticketAt(m).height <= h {
			lo = m + 1
		} else {
			hi = m
		}
	}
	return lo
}

// eligibleFor says whether a ticket may be drawn into a filing whose round
// was fixed at height fixed.
func eligibleFor(f *filing, t *ticket, fixed int64) bool {
	return !t.gone && t.id < f.oldBelow && (t.leaving == 0 || t.leaving > fixed) &&
		!f.silent[t.owner] && !onFiling(f, t.owner)
}

// pick draws n tickets, one per owner, in proportion to weight, from the
// filing's pool as it was at height fixed, by a beacon signature and what
// the draw is for. Every ticket it lands on is set aside for the rest of the
// draw, taken or not, so an owner already chosen, a party to the filing or a
// ticket that can't be drawn is landed on once at most: one owner with most
// of the stake can't make the draw run out of tries. It returns nil if it
// can't (too few eligible owners, or too many tries); it changes nothing.
func pick(sig []byte, what string, id, nth, n int, f *filing, fixed int64) []*ticket {
	total := sumBelow(f.oldBelow)
	seed := sha256.Sum256([]byte(string(sig) + "\x00" + what + "\x00" + strconv.Itoa(id) + "\x00" + strconv.Itoa(nth)))
	var picks []*ticket
	chosen := map[address]bool{}
	aside := map[int]int64{} // weight set aside under each node of the tree, in memory only
	for i := 0; len(picks) < n; i++ {
		if total <= 0 || i >= 64+16*n {
			return nil
		}
		h := sha256.Sum256(append(seed[:], byte(i), byte(i>>8), byte(i>>16)))
		var x uint64
		for j := 0; j < 8; j++ {
			x = x<<8 | uint64(h[j])
		}
		t := ticketAt(sumFindAside(int64(x%uint64(total)), aside))
		setAside(aside, t.id, t.weight)
		total -= t.weight
		if chosen[t.owner] || !eligibleFor(f, t, fixed) {
			continue
		}
		chosen[t.owner] = true
		picks = append(picks, t)
	}
	return picks
}

// sumFindAside is the ticket whose share of the cumulative weight holds x,
// for x below the tree's total less the weight set aside, by node: the root
// is node 1, and node k's children are 2k and 2k+1.
func sumFindAside(x int64, aside map[int]int64) int {
	n, k, i := sumRoot, 1, 0
	for d := sumDepth - 1; d >= 0; d-- {
		var ls int64
		if n.l != nil {
			ls = n.l.sum
		}
		ls -= aside[2*k]
		if x < ls {
			n, k = n.l, 2*k
		} else {
			x -= ls
			n, k = n.r, 2*k+1
			i |= 1 << d
		}
	}
	return i
}

// setAside sets ticket i's weight w aside under every node above it.
func setAside(aside map[int]int64, i int, w int64) {
	for k := 1<<sumDepth + i; k >= 1; k >>= 1 {
		aside[k] += w
	}
}

// onFiling says whether an owner is already on a filing: its worker (the
// first check, from the reveal on, before which nothing is drawn or
// objected to), a checker, an objector, or a member of any of its panels.
func onFiling(f *filing, a address) bool {
	if f.objector != nil && f.objector.owner == a {
		return true
	}
	for _, c := range f.checks {
		if c.owner == a {
			return true
		}
	}
	for _, p := range f.panels {
		for _, c := range p {
			if c.owner == a {
				return true
			}
		}
	}
	return false
}

func ticketAt(id int) *ticket {
	v := tickets.Get(key(uint64(id)))
	if id < 0 || v == nil {
		panic("guards: no ticket " + strconv.Itoa(id))
	}
	return v.(*ticket)
}

func ownTicket(cur realm, id int) *ticket {
	t := ticketAt(id)
	if caller(cur) != t.owner {
		panic("guards: not your ticket")
	}
	return t
}

// TicketOf says a ticket's owner, what is left of its stake, the unsettled
// checks it is drawn into, and the height it began leaving (0 while staked).
func TicketOf(id int) (address, int64, int, int64) {
	t := ticketAt(id)
	return t.owner, t.stake, t.open, t.leaving
}
