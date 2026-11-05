package guards

import (
	"crypto/sha256"
	"strconv"
)

// Tickets and the draw (round 9, new majors 1 and 6; round 10, new majors 1
// and 2).
//
// A ticket's weight in every draw is the stake it was staked with, fixed;
// fines and slashes lower what is left to charge, never the weight. A tree
// of stake sums over ticket numbers draws a ticket in sumDepth reads, so
// no call walks every ticket. The tree is persistent: staking or
// withdrawing makes a new version by copying the nodes on one path, and
// leaves every older version whole. Fixing a filing's beacon round keeps
// the version current then, and every draw of that round reads only it, so
// nothing anyone stakes, unstakes or withdraws after the round is fixed
// moves its draw. The draw takes tickets staked MinTicketAge before the
// filing (a prefix of ticket numbers, found at Commit) and not unstaked
// before the round was fixed; it must come within DrawDeadline, shorter
// than UnbondBlocks, so any ticket it may name is still there to charge.

type ticket struct {
	id      int
	owner   address
	weight  int64 // the stake staked: its weight in every draw, fixed
	stake   int64 // what is left to charge or give back
	height  int64 // staked at
	leaving int64 // Unstake's height, or when charges left it under the floor; 0 while staked
	open    int   // unsettled seats it holds: checks and panel seats it was drawn into
	gone    bool  // withdrawn: out of the newest version of the tree
	votes   int   // the pool votes whose charges it has settled, in order (pool.gno)
}

// sumDepth bounds the tickets at 2^sumDepth (round 10, minor 6).
const sumDepth = 32

type sumNode struct {
	sum  int64
	l, r *sumNode
}

var (
	sumRoot *sumNode // the newest version of the tree
	active  int64    // the stake of every ticket not leaving: what a level's floor counts
)

// sumAdd returns a new version of the tree rooted at n, with w added to
// ticket i's weight: the nodes on i's path are new, every other node is
// shared, and n's version is unchanged (round 10, new major 1).
func sumAdd(n *sumNode, i int, w int64) *sumNode {
	root := copyNode(n)
	root.sum += w
	cur := root
	for d := sumDepth - 1; d >= 0; d-- {
		var next *sumNode
		if i>>d&1 == 0 {
			next = copyNode(cur.l)
			cur.l = next
		} else {
			next = copyNode(cur.r)
			cur.r = next
		}
		next.sum += w
		cur = next
	}
	return root
}

func copyNode(n *sumNode) *sumNode {
	c := &sumNode{}
	if n != nil {
		*c = *n
	}
	return c
}

// sumBelow is the weight, in the version rooted at n, of tickets numbered
// below k.
func sumBelow(n *sumNode, k int) int64 {
	if n == nil {
		return 0
	}
	if k >= 1<<sumDepth {
		return n.sum
	}
	var s int64
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

// LiveStake is the stake of every ticket not leaving, at what is left of
// it: what a level's stake floor is measured against (round 10, minor 5).
func LiveStake() int64 { return active }

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
	sumRoot = sumAdd(sumRoot, t.id, t.weight)
	active += n
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
	leave(t)
}

func leave(t *ticket) {
	t.leaving = now()
	active -= t.stake
}

// MaxSettle is how many pool votes one call settles for a ticket, so no
// call walks every vote ever opened (round 10, minor 6).
var MaxSettle = 64

// SettleVotes settles up to MaxSettle of a ticket's pool votes, in order,
// and says how many are left: a ticket with more to settle than Withdraw
// settles calls it first.
func SettleVotes(cur realm, id int) int {
	t := ownTicket(cur, id)
	settleVotes(t, MaxSettle)
	return len(allVotes) - t.votes
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
	case len(allVotes)-t.votes > MaxSettle:
		panic("guards: this ticket has more than " + strconv.Itoa(MaxSettle) + " votes to settle; call SettleVotes first")
	}
	settleVotes(t, MaxSettle)
	n := t.stake
	t.stake, t.gone = 0, true
	sumRoot = sumAdd(sumRoot, t.id, -t.weight)
	pay(cur, t.owner, n)
}

// charge takes up to n from a ticket and returns what it took; a ticket
// left under half the minimum stops being drawn into later rounds.
func charge(t *ticket, n int64) int64 {
	n = least(n, t.stake)
	t.stake -= n
	if t.leaving == 0 {
		active -= n
		if t.stake < MinTicket/2 {
			leave(t)
		}
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
// was fixed at height fixed: old enough, not leaving then, not fined for
// silence on it, and not a party to it.
func eligibleFor(f *filing, t *ticket, fixed int64) bool {
	return !t.gone && t.id < f.oldBelow && (t.leaving == 0 || t.leaving > fixed) &&
		!f.silent[t.owner] && !party(f, t.owner)
}

// pick draws from the version of the tree the filing's round was fixed on,
// in proportion to weight, by a beacon signature and what the draw is for:
// n tickets of n owners for checkers (once, false), or n seats for a panel
// (seats, true), where an eligible ticket may be drawn again, so an owner's
// seats follow its stake however many addresses hold it (round 10, new
// major 2). Every ticket the draw lands on that it doesn't take is set
// aside, in memory, for the rest of the draw, so a party, a ticket that
// can't be drawn, or an owner already chosen is landed on once at most. It
// returns nil if it can't (too few eligible, or too many tries); it changes
// nothing.
func pick(sig []byte, what string, id, nth, n int, f *filing, seats bool) []*ticket {
	total := sumBelow(f.pool, f.oldBelow)
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
		t := ticketAt(sumFindAside(f.pool, int64(x%uint64(total)), aside))
		if !eligibleFor(f, t, f.fixedAt) || (!seats && chosen[t.owner]) {
			setAside(aside, t.id, t.weight)
			total -= t.weight
			continue
		}
		if !seats {
			chosen[t.owner] = true
			setAside(aside, t.id, t.weight)
			total -= t.weight
		}
		picks = append(picks, t)
	}
	return picks
}

// sumFindAside is the ticket whose share of the cumulative weight holds x,
// in the version rooted at n, for x below its total less the weight set
// aside, by node: the root is node 1, and node k's children are 2k and
// 2k+1.
func sumFindAside(n *sumNode, x int64, aside map[int]int64) int {
	k, i := 1, 0
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

// party says whether an owner has a stake in how a filing ends: its worker
// (the first check, from the reveal on, before which nothing is drawn or
// objected to), a checker, its objector or an appellant. A party is never
// drawn into the filing; members of earlier panels may sit again.
func party(f *filing, a address) bool {
	if f.objector != nil && f.objector.owner == a {
		return true
	}
	for _, c := range f.checks {
		if c.owner == a {
			return true
		}
	}
	for _, ap := range f.appeals {
		if ap.who == a {
			return true
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
// seats it holds, and the height it began leaving (0 while staked).
func TicketOf(id int) (address, int64, int, int64) {
	t := ticketAt(id)
	return t.owner, t.stake, t.open, t.leaving
}
