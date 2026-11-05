package guards

import (
	"testing"

	"gno.land/p/nt/testutils/v0"
)

// The pool decides by stake: six of eight owners reveal the worker's
// transcript, more than two thirds of the stake, so it wins at once. The
// two who voted otherwise lose Slash, the six share PoolFee, and the lying
// checkers lose Slash for their transcripts too; the guard is tested.
func TestPoolDecides(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, []int{4}
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(anyone))
	send(10_000_000)
	Fund(cross(cur))
	send(0)
	testing.SkipHeights(MinTicketAge)
	before := balances(append([]address{worker}, owners...)...)
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
		tr := lie
		if c == worker {
			tr = ok
		}
		RevealCheck(cross(cur), id, tr, salt(c))
	}
	aim(1003)
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	panel, _ := PanelOf(id)
	for i, p := range panel {
		testing.SetRealm(u(p))
		tr := ok
		if i%2 == 1 {
			tr = lie
		}
		CommitCheck(cross(cur), id, Commitment(p, "check", tr, salt(p)))
	}
	for i, p := range panel {
		testing.SetRealm(u(p))
		tr := ok
		if i%2 == 1 {
			tr = lie
		}
		RevealCheck(cross(cur), id, tr, salt(p))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Pool {
		t.Fatalf("after the panel split: %s", s)
	}
	young := testutils.TestAddress("young") // staked after the filing: no vote
	testing.SetRealm(u(young))
	stakeOne(t, cur)
	testing.SetRealm(u(anyone))
	OpenPool(cross(cur), id)
	testing.SetRealm(u(young))
	refuses(t, "no stake of yours votes on this filing", func() { CommitVote(cross(cur), id, Commitment(young, "vote", lie, "v")) })
	liars := map[address]bool{drawn[0]: true, drawn[1]: true}
	sayV := func(a address) string {
		if liars[a] {
			return lie
		}
		return ok
	}
	for _, a := range owners {
		testing.SetRealm(u(a))
		CommitVote(cross(cur), id, Commitment(a, "vote", sayV(a), "v"))
	}
	testing.SetRealm(u(owners[0]))
	refuses(t, "votes open when the commit window closes", func() { RevealVote(cross(cur), id, sayV(owners[0]), "v") })
	testing.SkipHeights(PoolCommitWindow + 1)
	for _, a := range owners {
		testing.SetRealm(u(a))
		RevealVote(cross(cur), id, sayV(a), "v")
	}
	testing.SetRealm(u(anyone))
	if s := Tally(cross(cur), id); s != Tested || Level(GuardHash(guardText)) != Tested {
		t.Fatalf("the pool decided %s", s)
	}
	for _, a := range owners {
		want := MinTicket
		if liars[a] {
			want -= Slash // the vote
		}
		for _, c := range drawn {
			if c == a {
				want -= Slash // the transcript
			}
		}
		if got := stakeOf2(a, owners); got != want {
			t.Errorf("%s: stake %d, want %d", a, got, want)
		}
		if _, _, open, _ := TicketOf(ticketIndex(a, owners)); open != 0 {
			t.Errorf("%s's ticket still held", a)
		}
		if !liars[a] && bal(a)-before[a] < PoolFee/6 {
			t.Errorf("%s, on the winning side, got %d", a, bal(a)-before[a])
		}
	}
}

// Only five of eight owners reveal: under two thirds of the stake. Nothing
// is decided: no level, the worker's bond goes back, every ticket is let
// go, and the three who didn't reveal lose AbstainShare of their stake.
func TestPoolUndecided(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, []int{4}
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(anyone))
	send(10_000_000)
	Fund(cross(cur))
	send(0)
	testing.SkipHeights(MinTicketAge)
	before := bal(worker)
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
		tr := lie
		if c == worker {
			tr = ok
		}
		RevealCheck(cross(cur), id, tr, salt(c))
	}
	aim(1003)
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	panel, _ := PanelOf(id)
	for i, p := range panel {
		testing.SetRealm(u(p))
		tr := ok
		if i%2 == 1 {
			tr = lie
		}
		CommitCheck(cross(cur), id, Commitment(p, "check", tr, salt(p)))
	}
	for i, p := range panel {
		testing.SetRealm(u(p))
		tr := ok
		if i%2 == 1 {
			tr = lie
		}
		RevealCheck(cross(cur), id, tr, salt(p))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	OpenPool(cross(cur), id)
	for _, a := range owners[:5] {
		testing.SetRealm(u(a))
		CommitVote(cross(cur), id, Commitment(a, "vote", ok, "v"))
	}
	testing.SkipHeights(PoolCommitWindow + 1)
	for _, a := range owners[:5] {
		testing.SetRealm(u(a))
		RevealVote(cross(cur), id, ok, "v")
	}
	testing.SetRealm(u(anyone))
	refuses(t, "the vote is still open", func() { Tally(cross(cur), id) })
	testing.SetRealm(u(owners[0]))
	Unstake(cross(cur), 0)
	testing.SkipHeights(UnbondBlocks)
	testing.SetRealm(u(owners[0]))
	refuses(t, "drawn into a check that hasn't settled", func() { Withdraw(cross(cur), 0) })
	testing.SetRealm(u(anyone))
	if s := Tally(cross(cur), id); s != Undecided || Level(GuardHash(guardText)) != "" {
		t.Fatalf("an undecided vote: %s", s)
	}
	if bal(worker)-before != FilingBond {
		t.Errorf("the worker got back %d", bal(worker)-before)
	}
	for _, a := range owners[5:] {
		if got := stakeOf2(a, owners); got != MinTicket-MinTicket*AbstainShare/100 && got != MinTicket-MinTicket*AbstainShare/100-Slash {
			t.Errorf("abstainer %s: stake %d", a, got)
		}
	}
	for _, a := range owners {
		if _, _, open, _ := TicketOf(ticketIndex(a, owners)); open != 0 {
			t.Errorf("%s's ticket still held", a)
		}
	}
}
