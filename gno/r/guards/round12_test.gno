package guards

import (
	"testing"

	"gno.land/p/nt/testutils/v0"
)

// Round 12's tests: a vote holds only tickets not leaving when it opens;
// anyone settles a ticket's vote charges; a stall pays the checkers who
// answered; a draw whose pool moved takes a new round; a leave at the last
// height a round can be drawn waits for the draw.

// A vote holds only tickets that weren't leaving when it opened (round 12,
// new major 1). X leaves before the vote opens: it can't vote, isn't in the
// vote's weight, withdraws while the vote is still open, and pays nothing
// for not voting. Y leaves after: the vote holds it until it closes, and it
// pays AbstainShare for not voting. Anyone may then settle another ticket's
// charges (round 12, minor 2).
func TestVoteHoldsOnlyWhoStayed(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, nil
	PoolCommitWindow, PoolRevealWindow = 100, 5 // longer than UnbondBlocks (60)
	owners := ownersN(5)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(anyone))
	send(PoolFee)
	Fund(cross(cur))
	send(0)
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", ok, salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, ok, salt(c))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	stranger := testutils.TestAddress("stranger")
	testing.SetRealm(u(stranger))
	send(ObjectionBond)
	Object(cross(cur), id, lie)
	send(0)
	party := map[address]bool{drawn[0]: true, drawn[1]: true, drawn[2]: true}
	var x, y address
	for _, o := range owners {
		if !party[o] {
			if x == "" {
				x = o
			} else {
				y = o
			}
		}
	}
	xi, yi := ticketIndex(x, owners), ticketIndex(y, owners)
	testing.SetRealm(u(x))
	Unstake(cross(cur), xi) // before the vote opens, in the same block
	testing.SetRealm(u(anyone))
	OpenPool(cross(cur), id)
	testing.SetRealm(u(y))
	Unstake(cross(cur), yi) // after it opens, in the same block
	if v := votes[id]; v.total != 4*MinTicket {
		t.Fatalf("the vote's weight is %d, want four tickets'", v.total)
	}
	testing.SetRealm(u(x))
	refuses(t, "has no vote on this filing", func() { CommitVote(cross(cur), id, itoa(xi), Commitment(x, "vote", ok, "v")) })
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitVote(cross(cur), id, itoa(ticketIndex(c, owners)), Commitment(c, "vote", ok, "v"))
	}
	testing.SkipHeights(UnbondBlocks)
	before := bal(x)
	testing.SetRealm(u(x))
	Withdraw(cross(cur), xi) // the vote is still open
	if got := bal(x) - before; got != MinTicket {
		t.Errorf("the ticket that left before the vote got back %d", got)
	}
	testing.SetRealm(u(y))
	refuses(t, "a pool vote it may vote in is still open", func() { Withdraw(cross(cur), yi) })
	testing.SkipHeights(PoolCommitWindow - UnbondBlocks + 1)
	for _, c := range drawn {
		testing.SetRealm(u(c))
		RevealVote(cross(cur), id, ok, "v")
	}
	testing.SkipHeights(PoolRevealWindow)
	testing.SetRealm(u(anyone))
	if s := Tally(cross(cur), id); s != Tested {
		t.Fatalf("the vote: %s", s)
	}
	f0 := FundBalance()
	SettleVotes(cross(cur), yi) // anyone may settle another's charges
	if stakeOf(yi) != MinTicket-MinTicket*AbstainShare/100 || FundBalance()-f0 != MinTicket*AbstainShare/100 {
		t.Errorf("y's stake %d, the fund +%d", stakeOf(yi), FundBalance()-f0)
	}
	before = bal(y)
	testing.SetRealm(u(y))
	Withdraw(cross(cur), yi)
	if got := bal(y) - before; got != MinTicket-MinTicket*AbstainShare/100 {
		t.Errorf("y got back %d", got)
	}
}

// A leave at the last height a round can be drawn waits for the draw: the
// round still waits there, so the ticket stays where the draw sees it, and
// the draw is the one the round was fixed for (round 12, minor 7).
func TestLeaveAtTheLastDrawableHeight(cur realm, t *testing.T) {
	var first []address
	for pass := 0; pass < 2; pass++ {
		reset()
		owners := []address{alice, bob, carol, dave, eve}
		for _, w := range owners {
			testing.SetRealm(u(w))
			stakeOne(t, cur)
		}
		testing.SkipHeights(MinTicketAge)
		testing.SetRealm(u(worker))
		id := file(t, cur, ok, 1001)
		testing.SkipHeights(DrawDeadline) // the last height Draw takes
		if pass == 1 {
			testing.SetRealm(u(eve))
			Unstake(cross(cur), 4)
			if pending.Size() != 1 {
				t.Fatalf("a leave at the last drawable height parked at once (%d pending)", pending.Size())
			}
		}
		testing.SetRealm(u(anyone))
		drawn := draw(t, cur, id, 1001, sig1001)
		if pass == 0 {
			first = drawn
			continue
		}
		for i := range drawn {
			if drawn[i] != first[i] {
				t.Fatalf("the leave moved the draw: %v, then %v", first, drawn)
			}
		}
	}
}

// If the weight under a waiting round ever differs from its record, Draw
// fixes a new round instead of failing until the filer's bond is lost
// (round 12, minor 7); the new round draws.
func TestDrawAfterThePoolMoved(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol, dave} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	addPath(0, 1, 0, 0, 0) // a slip, as no path should make one
	aim(1002)
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1001, sig1001)
	if s := Draw(cross(cur), id); s != Revealed {
		t.Fatalf("a draw over a moved pool: %s", s)
	}
	if _, r, _ := State(id); r != 1002 || get(id).bond != FilingBond {
		t.Fatalf("the new round is %d; the bond %d", r, get(id).bond)
	}
	draw(t, cur, id, 1002, sig1002)
}

// The same for a panel's draw: a new round, its fees still set aside.
func TestDrawPanelAfterThePoolMoved(cur realm, t *testing.T) {
	reset()
	Reruns = 0
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(anyone))
	send(panelCost(0))
	Fund(cross(cur))
	send(0)
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", lie, salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, or(map[address]string{worker: ok}[c], lie), salt(c))
	}
	aim(1003)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Panel {
		t.Fatalf("the panel: %s", s)
	}
	addPath(0, 1, 0, 0, 0)
	aim(1004)
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	if st, r, _ := State(id); st != Panel || r != 1004 || get(id).reserve != panelCost(0) {
		t.Fatalf("a panel's draw over a moved pool: %s, round %d, reserve %d", st, r, get(id).reserve)
	}
	SubmitBeacon(cross(cur), 1004, sig1004)
	DrawPanel(cross(cur), id)
	if st, _, _ := State(id); st != Panelled {
		t.Fatalf("the new round's draw: %s", st)
	}
}
