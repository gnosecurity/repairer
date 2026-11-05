package guards

import (
	"crypto/sha256"
	"strconv"

	"gno.land/p/nt/avl/v0"
)

// Tickets and the draw (round 9, new majors 1 and 6; round 10, new majors 1
// and 2; round 11, new major 2).
//
// A ticket's weight in every draw is the stake it was staked with, fixed;
// fines and slashes lower what is left to charge, never the weight. A tree
// of weight sums over ticket numbers draws a ticket in sumDepth reads, so
// no call walks every ticket. The tree is changed in place. Each node keeps
// the weight below it that draws see (sum), how much of that is leaving and
// how much withdrawn but not yet taken out, and the weight parked: tickets
// leaving, moved out of what draws see but still bonded and still voting. A
// draw takes tickets staked MinTicketAge before the filing (a prefix of
// ticket numbers, found at Commit) and not leaving when its round was
// fixed, and reads the tree as it is; nothing changes what draws see below
// that prefix while the round waits for its draw:
//   - a stake appends a ticket above every prefix (ticket numbers only rise);
//   - charges never change a weight;
//   - a ticket that starts leaving while some round waits stays where it is,
//     marked leaving, and is parked once no round waits; one that starts
//     leaving when none waits is parked at once. So stake unstaked and never
//     withdrawn can't crowd the draws (found building round 11);
//   - a withdrawal of a parked ticket takes it out of the parked weight,
//     which draws don't see; of one not parked yet, while some round waits,
//     only marks it withdrawn: it was leaving UnbondBlocks before, longer
//     than DrawDeadline, so every waiting draw sets it aside anyway.
// Whatever waits for no round to wait is done by Compact, MaxSettle tickets
// at a time, by Withdraw, Draw and DrawPanel a few at a time, or at once
// when nothing waits. A draw must come within DrawDeadline of its round
// being fixed, so any ticket it names is still there to charge, and a round
// nobody draws stops holding the tree back.

type ticket struct {
	id      int
	owner   address
	weight  int64 // the stake staked: its weight in every draw, fixed
	stake   int64 // what is left to charge or give back
	height  int64 // staked at
	leaving int64 // Unstake's height, or when charges left it under the floor; 0 while staked
	leftNo  int   // which leave it was, counting every ticket's (leaves); 0 while staked
	open    int   // unsettled seats it holds: checks and panel seats it was drawn into
	gone    bool  // withdrawn: its stake paid back; its weight out of the tree, or marked withdrawn there until Compact
	parked  bool  // leaving, its weight moved out of what draws see
	out     bool  // its weight is out of the tree altogether
	votes   int   // the pool votes whose charges it has settled, in order (pool.gno)
}

// sumDepth bounds the tickets at 2^sumDepth (round 10, minor 6).
const sumDepth = 32

type sumNode struct {
	sum    int64 // the weight of the tickets below, as draws see it
	left   int64 // how much of it is leaving (withdrawn ones too)
	gone   int64 // how much of it is withdrawn, waiting for Compact
	parked int64 // the weight of tickets leaving, out of what draws see
	l, r   *sumNode
}

var (
	sumRoot = &sumNode{}
	active  int64           // the stake of every ticket not leaving, at what is left of it
	leaves  int             // how many tickets have begun leaving: orders leaves and votes within a block
	pending = avl.NewTree() // key(ticket) → ticket: tickets whose weight waits for no round to wait, to park or take out (round 12, minor 4)
	waits   = avl.NewTree() // key(fixedAt)+key(filing) → true: rounds waiting for their draw
)

// addPath adds to the sums on ticket i's path, in place, and drops the rest
// of the path where nothing is left below (round 11, new major 2).
func addPath(i int, sum, left, gone, parked int64) {
	n := sumRoot
	n.sum, n.left, n.gone, n.parked = n.sum+sum, n.left+left, n.gone+gone, n.parked+parked
	for d := sumDepth - 1; d >= 0; d-- {
		next := n.r
		if i>>d&1 == 0 {
			next = n.l
		}
		if next == nil {
			next = &sumNode{}
			if i>>d&1 == 0 {
				n.l = next
			} else {
				n.r = next
			}
		}
		next.sum, next.left, next.gone, next.parked = next.sum+sum, next.left+left, next.gone+gone, next.parked+parked
		if next.sum == 0 && next.parked == 0 { // nothing below: every node under it is on this path, and empty
			if i>>d&1 == 0 {
				n.l = nil
			} else {
				n.r = nil
			}
			return
		}
		n = next
	}
}

// below sums the tickets numbered below k: their weight as draws see it,
// how much of that is leaving, how much withdrawn, and the weight parked.
func below(k int) (sum, left, gone, parked int64) {
	n := sumRoot
	if k >= 1<<sumDepth {
		return n.sum, n.left, n.gone, n.parked
	}
	for d := sumDepth - 1; d >= 0 && n != nil; d-- {
		if k>>d&1 == 1 {
			if n.l != nil {
				sum, left, gone, parked = sum+n.l.sum, left+n.l.left, gone+n.l.gone, parked+n.l.parked
			}
			n = n.r
		} else {
			n = n.l
		}
	}
	return
}

// roundsWait says whether a round fixed for a draw may still be drawn: the
// newest fixed has the latest deadline.
func roundsWait() bool {
	wait := false
	waits.ReverseIterate("", "", func(k string, _ any) bool {
		fixed, _ := strconv.ParseInt(k[:20], 10, 64)
		wait = now() <= fixed+DrawDeadline
		return true
	})
	return wait
}

// Compact, once no round waits for its draw, parks tickets that started
// leaving while rounds waited and takes out those withdrawn meanwhile, up to
// MaxSettle of them; it says how many are left. Anyone may call it.
func Compact(cur realm) int {
	caller(cur)
	return compact(MaxSettle)
}

func compact(max int) int {
	if roundsWait() {
		return pending.Size()
	}
	var ids []int
	pending.Iterate("", "", func(_ string, v any) bool {
		ids = append(ids, v.(int))
		return len(ids) >= max
	})
	for _, id := range ids {
		pending.Remove(key(uint64(id)))
		t := ticketAt(id)
		switch {
		case t.out || t.parked: // done already
		case t.gone:
			addPath(t.id, -t.weight, -t.weight, -t.weight, 0)
			t.out = true
		default:
			addPath(t.id, -t.weight, -t.weight, 0, t.weight)
			t.parked = true
		}
	}
	return pending.Size()
}

// LiveStake is the stake of every ticket not leaving, at what is left of it.
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
	addPath(t.id, t.weight, 0, 0, 0)
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

// leave stops a ticket being drawn into rounds fixed from now on: parked at
// once when no round waits, or marked leaving until none does.
func leave(t *ticket) {
	t.leaving = now()
	leaves++
	t.leftNo = leaves
	active -= t.stake
	if roundsWait() {
		addPath(t.id, 0, t.weight, 0, 0)
		pending.Set(key(uint64(t.id)), t.id)
	} else {
		addPath(t.id, -t.weight, 0, 0, t.weight)
		t.parked = true
	}
}

// MaxSettle is how many pool votes one call settles for a ticket, so no
// call walks every vote ever opened (round 10, minor 6).
var MaxSettle = 64

// SettleVotes settles up to n of a ticket's pool votes (MaxSettle if n is
// 0 or more), in order, and says how many are left: a ticket with more to
// settle than Withdraw settles calls it first, in as many steps as it
// needs (round 13, new major 1). Anyone may call it for any ticket, so a
// ticket that voted wrong or not at all is charged without its owner, and
// one left under half its weight leaves (round 12, minor 2).
func SettleVotes(cur realm, id, n int) int {
	caller(cur)
	t := ticketAt(id)
	if n <= 0 || n > MaxSettle {
		n = MaxSettle
	}
	settleVotes(t, n)
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
	switch {
	case t.parked: // draws don't see it
		addPath(t.id, 0, 0, 0, -t.weight)
		t.parked, t.out = false, true
	case roundsWait(): // marked; out once no round waits (round 11, new major 2); it is pending since it left
		addPath(t.id, 0, 0, t.weight, 0)
	default:
		addPath(t.id, -t.weight, -t.weight, 0, 0)
		t.out = true
	}
	compact(4)
	pay(cur, t.owner, n)
}

// charge takes up to n from a ticket and returns what it took; a ticket
// left with under half its weight leaves, so whatever is drawn, seated or
// counted is backed by at least half of it (round 11, minor 5).
func charge(t *ticket, n int64) int64 {
	n = least(n, t.stake)
	t.stake -= n
	if t.leaving == 0 {
		active -= n
		if t.stake*2 < t.weight {
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

// eligibleFor says whether a ticket may be drawn into a filing's round:
// old enough, not leaving when the round was fixed (by the leave counter,
// so a leave later in the fix's own block is after it, as the floor and the
// draw's total count it; round 13, minor 2), and not fined for silence on
// it; a checker also not a party to it. Panel seats are drawn from every
// party's stake too, so the liars' share of the seats is their share of
// the stake (round 11, new major 1).
func eligibleFor(f *filing, t *ticket, seats bool) bool {
	return !t.gone && t.id < f.oldBelow && (t.leftNo == 0 || t.leftNo > f.leaveMark) &&
		!f.silent[t.owner] && (seats || !party(f, t.owner))
}

// pick draws from the tree, in proportion to weight, by a beacon signature
// and what the draw is for: n tickets of n owners for checkers (once,
// false), or n seats for a panel (seats, true), where an eligible ticket may
// be drawn again, so an owner's seats follow its stake however many
// addresses hold it (round 10, new major 2). Every ticket the draw lands on
// that it doesn't take is set aside, in memory, for the rest of the draw,
// so a ticket that can't be drawn, or an owner already chosen, is landed on
// once at most. It returns nil if it can't (too few eligible, or too many
// tries); it changes nothing. The weight below the filing's prefix is what
// it was when the round was fixed (see the top of this file).
func pick(sig []byte, what string, id, nth, n int, f *filing, seats bool) []*ticket {
	total, _, _, _ := below(f.oldBelow)
	if total != f.total {
		panic("guards: the tree changed under a waiting round")
	}
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
		t := ticketAt(sumFindAside(sumRoot, int64(x%uint64(total)), aside))
		if !eligibleFor(f, t, seats) || (!seats && chosen[t.owner]) {
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
// in the tree rooted at n, for x below its total less the weight set aside,
// by node: the root is node 1, and node k's children are 2k and 2k+1.
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

// party says whether an owner is the filing's worker (the first check,
// from the reveal on, before which nothing is drawn or objected to) or one
// of its checkers: it is never drawn as a checker, and can't object to the
// agreement it made. Anyone, a party too, may sit on a panel or appeal
// (round 11, new major 1); checkers are never drawn after an objection, so
// an objector or appellant needn't be a party.
func party(f *filing, a address) bool {
	for _, c := range f.checks {
		if c.owner == a {
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
