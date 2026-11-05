package guards

import (
	"testing"

	"gno.land/p/nt/testutils/v0"
)

// Round 13's tests: a leave later in a reveal's own block is drawn as the
// floor and the draw's total counted it; an owner commits its tickets in
// steps under one commitment; SettleVotes takes a count.

// A ticket that leaves later in the reveal's own block was counted in the
// draw's total and the level's floor when the round was fixed; the draw
// orders leaves by the counter, so it is drawn like any ticket not leaving
// at the fix (round 13, minor 2). The three checkers are all needed.
func TestLeaveInTheRevealsBlock(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(carol))
	Unstake(cross(cur), 2) // in the reveal's block, after it
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	got := map[address]bool{}
	for _, c := range drawn {
		got[c] = true
	}
	if !got[carol] {
		t.Fatalf("drawn %v, without the ticket that left after the fix", drawn)
	}
}

// An owner with more tickets than one call can name commits them in
// steps, each with the same commitment; another commitment is refused. It
// reveals once for all of them and counts as one voter, so the vote ends
// as soon as the commit window has closed and it has revealed (round 13,
// minor 3).
func TestCommitInSteps(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, nil
	PoolCommitWindow, PoolRevealWindow = 100, 50
	owners := ownersN(3)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	big := testutils.TestAddress("big")
	testing.SetRealm(u(big))
	stakeOne(t, cur)
	stakeOne(t, cur)
	stakeOne(t, cur)
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
	testing.SetRealm(u(anyone))
	OpenPool(cross(cur), id)
	c := Commitment(big, "vote", ok, "v")
	testing.SetRealm(u(big))
	CommitVote(cross(cur), id, "3,4", c)
	refuses(t, "only with that same commitment", func() { CommitVote(cross(cur), id, "5", Commitment(big, "vote", lie, "v")) })
	CommitVote(cross(cur), id, "5", c)
	refuses(t, "already voted", func() { CommitVote(cross(cur), id, "4", c) })
	if w, _ := VoteOf(id, big); w != 3*MinTicket {
		t.Fatalf("big's weight %d, want three tickets'", w)
	}
	testing.SkipHeights(PoolCommitWindow + 1)
	RevealVote(cross(cur), id, ok, "v")
	testing.SetRealm(u(anyone))
	if s := Tally(cross(cur), id); s != Tested { // every committed voter has revealed
		t.Fatalf("the vote: %s", s)
	}
}

// SettleVotes settles as many votes as it is asked, up to MaxSettle, so a
// backlog of costly votes clears in steps (round 13, new major 1).
func TestSettleVotesTakesACount(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, nil
	owners := []address{alice, bob, carol, dave}
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(anyone))
	send(2 * PoolFee)
	Fund(cross(cur))
	send(0)
	testing.SkipHeights(MinTicketAge)
	sigs := []string{sig1001, sig1002}
	for i := 0; i < 2; i++ { // two filings, each to the pool, where nobody votes
		testing.SetRealm(u(worker))
		id := file(t, cur, ok, uint64(1001+i))
		testing.SetRealm(u(anyone))
		drawn := draw(t, cur, id, uint64(1001+i), sigs[i])
		for _, c := range drawn {
			testing.SetRealm(u(c))
			CommitCheck(cross(cur), id, Commitment(c, "check", lie, salt(c)))
		}
		for _, c := range append([]address{worker}, drawn...) {
			testing.SetRealm(u(c))
			RevealCheck(cross(cur), id, or(map[address]string{worker: ok}[c], lie), salt(c))
		}
		testing.SetRealm(u(anyone))
		Settle(cross(cur), id)
		OpenPool(cross(cur), id)
		testing.SkipHeights(PoolCommitWindow + PoolRevealWindow + 1)
		if s := Tally(cross(cur), id); s != Undecided {
			t.Fatalf("filing %d: %s", i, s)
		}
	}
	testing.SetRealm(u(anyone))
	if left := SettleVotes(cross(cur), 0, 1); left != 1 {
		t.Fatalf("%d votes left to settle after one, want 1", left)
	}
	if stakeOf(0) != MinTicket-MinTicket*AbstainShare/100 {
		t.Fatalf("after one vote the stake is %d", stakeOf(0))
	}
	if left := SettleVotes(cross(cur), 0, 0); left != 0 {
		t.Fatalf("%d votes left to settle", left)
	}
}

// A ticket its owner left out of its vote is charged as an abstainer,
// though the owner voted with its other tickets and was right: settling
// reads the ticket's own entry in the voted tree, not the owner's vote
// (round 13, new major 1).
func TestUnvotedTicketOfAVoter(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, nil
	PoolCommitWindow, PoolRevealWindow = 100, 50
	owners := ownersN(2)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	big := testutils.TestAddress("big")
	testing.SetRealm(u(big))
	stakeOne(t, cur) // 2
	stakeOne(t, cur) // 3
	stakeOne(t, cur) // 4, left out of its vote
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
	testing.SetRealm(u(anyone))
	OpenPool(cross(cur), id)
	testing.SetRealm(u(big))
	CommitVote(cross(cur), id, "2,3", Commitment(big, "vote", ok, "v"))
	testing.SkipHeights(PoolCommitWindow + 1)
	RevealVote(cross(cur), id, ok, "v")
	testing.SetRealm(u(anyone))
	if s := Tally(cross(cur), id); s != Tested { // two of five tickets: over a third
		t.Fatalf("the vote: %s", s)
	}
	SettleVotes(cross(cur), 4, 0)
	SettleVotes(cross(cur), 2, 0)
	if got := stakeOf(4); got != MinTicket-MinTicket*AbstainShare/100 {
		t.Errorf("the ticket left out has %d, want an abstainer's charge taken", got)
	}
	if got := stakeOf(2); got != MinTicket {
		t.Errorf("the ticket that voted right has %d", got)
	}
}
