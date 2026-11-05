package guards

import (
	"strings"
	"testing"

	"gno.land/p/nt/testutils/v0"
)

// The pool decides by stake. A dispute no panel decided goes to the vote:
// six of eight owners, more than two thirds of the stake, vote the worker's
// transcript. That is the last word: the lying checkers and the panelists on
// the wrong side lose Slash, half of it to the worker who showed it. Each
// winner claims its share of PoolFee by weight, exactly, though PoolFee times
// a weight overflows 64 bits (round 9, minor 11); the two who voted otherwise
// are charged as their tickets leave (round 9, new major 6). A ticket staked
// after the filing has no vote.
func TestPoolDecides(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, []int{4}
	PoolFee = 1_000_000_000_000 // times a ticket's weight, past 2^63
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(anyone))
	send(PoolFee + 4*PanelFee)
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
		RevealCheck(cross(cur), id, or(map[address]string{worker: ok}[c], lie), salt(c))
	}
	aim(1003)
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	panel, _ := PanelOf(id)
	sayP := func(i int) string {
		if i%2 == 1 {
			return lie
		}
		return ok
	}
	for i, p := range panel {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", sayP(i), salt(p)))
	}
	for i, p := range panel {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, sayP(i), salt(p))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Pool {
		t.Fatalf("after the panel split: %s", s)
	}
	young := testutils.TestAddress("young")
	testing.SetRealm(u(young))
	stakeOne(t, cur) // ticket 8, staked after the filing
	testing.SetRealm(u(anyone))
	refuses(t, "no vote is open on this filing", func() { Tally(cross(cur), id) })
	if s := OpenPool(cross(cur), id); s != Voting || FundBalance() != 0 {
		t.Fatalf("opened %s, fund %d", s, FundBalance())
	}
	testing.SetRealm(u(young))
	refuses(t, "ticket 8 has no vote on this filing", func() { CommitVote(cross(cur), id, "8", Commitment(young, "vote", lie, "v")) })
	testing.SetRealm(u(owners[0]))
	refuses(t, "ticket 1 isn't yours", func() { CommitVote(cross(cur), id, "1", Commitment(owners[0], "vote", ok, "v")) })
	refuses(t, "tickets are numbers", func() { CommitVote(cross(cur), id, "one", Commitment(owners[0], "vote", ok, "v")) })
	liars := map[address]bool{drawn[0]: true, drawn[1]: true}
	sayV := func(a address) string {
		if liars[a] {
			return lie
		}
		return ok
	}
	for i, a := range owners {
		testing.SetRealm(u(a))
		CommitVote(cross(cur), id, itoa(i), Commitment(a, "vote", sayV(a), "v"))
	}
	testing.SetRealm(u(owners[0]))
	refuses(t, "already committed", func() { CommitVote(cross(cur), id, "0", Commitment(owners[0], "vote", ok, "w")) })
	refuses(t, "votes open when the commit window closes", func() { RevealVote(cross(cur), id, sayV(owners[0]), "v") })
	testing.SetRealm(u(anyone))
	refuses(t, "the vote is still open", func() { Tally(cross(cur), id) })
	testing.SkipHeights(PoolCommitWindow + 1)
	testing.SetRealm(u(owners[0]))
	refuses(t, "that isn't what was committed", func() { RevealVote(cross(cur), id, lie, "v") })
	for _, a := range owners {
		testing.SetRealm(u(a))
		RevealVote(cross(cur), id, sayV(a), "v")
	}
	if w, open := VoteOf(id, owners[0]); w != MinTicket || !open {
		t.Errorf("owners[0]'s vote: %d, %t", w, open)
	}
	testing.SetRealm(u(owners[0]))
	refuses(t, "no decided vote on this filing", func() { ClaimVote(cross(cur), id) })
	testing.SetRealm(u(anyone))
	if s := Tally(cross(cur), id); s != Tested || Level(GuardHash(guardText)) != Tested {
		t.Fatalf("the pool decided %s", s)
	}
	page := Render("filing/" + itoa(id))
	for _, want := range []string{"## Panel 1 (of 4)", "## The pool's vote", "8 voters committed, 80000000 of 80000000 ugnot", "- Decided: `" + ok + "`"} {
		if !strings.Contains(page, want) {
			t.Errorf("the filing's page lacks %q:\n%s", want, page)
		}
	}
	taken := 5 * Slash // three lying checkers, two panelists on the wrong side
	if got := bal(worker) - before[worker]; got != FilingBond-FundFee+taken*ShowShare/100 {
		t.Errorf("the worker got %d", got)
	}
	if FundBalance() != FundFee+2*PanelFee+taken-taken*ShowShare/100 {
		t.Errorf("fund %d", FundBalance())
	}
	for _, a := range owners {
		c0 := bal(a)
		testing.SetRealm(u(a))
		if liars[a] {
			refuses(t, "nothing of yours to claim", func() { ClaimVote(cross(cur), id) })
			continue
		}
		if got := ClaimVote(cross(cur), id); got != PoolFee/6 || bal(a)-c0 != got {
			t.Errorf("%s claimed %d, was paid %d", a, got, bal(a)-c0)
		}
		refuses(t, "nothing of yours to claim", func() { ClaimVote(cross(cur), id) })
	}
	for _, p := range []address{panel[0], panel[2]} {
		if got := bal(p) - before[p]; got != PanelFee+PoolFee/6 {
			t.Errorf("panelist %s, right, got %d", p, got)
		}
	}
	wrong := map[address]int64{}
	for _, c := range drawn {
		wrong[c] += Slash // their transcripts
	}
	for _, p := range []address{panel[1], panel[3]} {
		wrong[p] += Slash // their panel's word
	}
	for a := range liars {
		wrong[a] += Slash // their votes: WrongShare of 9M is less than Slash
	}
	for tid, a := range append(owners, young) {
		testing.SetRealm(u(a))
		Unstake(cross(cur), tid)
	}
	testing.SkipHeights(UnbondBlocks)
	for tid, a := range append(owners, young) {
		testing.SetRealm(u(a))
		w0 := bal(a)
		Withdraw(cross(cur), tid)
		if got := bal(a) - w0; got != MinTicket-wrong[a] {
			t.Errorf("%s withdrew %d, want %d", a, got, MinTicket-wrong[a])
		}
	}
	if Burned() != 2*Slash || LiveStake() != 0 {
		t.Errorf("burned %d, live stake %d", Burned(), LiveStake())
	}
}

// Five of eight owners commit and four open: under two thirds of the stake.
// The tally waits while a committed vote may still open. Nothing is
// decided: no level, nobody paid or charged for the dispute, the worker's
// whole bond back, every ticket let go, and the vote's fee back in the fund.
// The vote waits for a fund that can pay it; a ticket can't leave while the
// vote is open; each of the four that didn't vote is charged AbstainShare
// as it leaves (a stall is the abstainers').
func TestPoolUndecided(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, nil // a dispute goes straight to the pool
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(anyone))
	send(PoolFee - 1)
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
		RevealCheck(cross(cur), id, or(map[address]string{worker: ok}[c], lie), salt(c))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Pool {
		t.Fatalf("with no panels: %s", s)
	}
	refuses(t, "can't pay the pool's vote yet", func() { OpenPool(cross(cur), id) })
	send(1)
	Fund(cross(cur))
	send(0)
	OpenPool(cross(cur), id)
	onFiling := map[address]bool{drawn[0]: true, drawn[1]: true, drawn[2]: true}
	var abstain, voters []address
	for _, a := range owners {
		if !onFiling[a] && len(abstain) < 3 {
			abstain = append(abstain, a)
		} else {
			voters = append(voters, a)
		}
	}
	idle, k := abstain[0], itoa(ticketIndex(abstain[0], owners))
	testing.SetRealm(u(idle))
	refuses(t, "ticket "+k+" already voted", func() { CommitVote(cross(cur), id, k+","+k, Commitment(idle, "vote", ok, "v")) })
	Unstake(cross(cur), ticketIndex(idle, owners))
	for _, a := range voters {
		testing.SetRealm(u(a))
		CommitVote(cross(cur), id, itoa(ticketIndex(a, owners)), Commitment(a, "vote", ok, "v"))
	}
	testing.SetRealm(u(anyone))
	refuses(t, "the vote is still open", func() { Tally(cross(cur), id) })
	testing.SkipHeights(PoolCommitWindow + 1)
	testing.SetRealm(u(abstain[1]))
	refuses(t, "the vote's commit window has passed", func() {
		CommitVote(cross(cur), id, itoa(ticketIndex(abstain[1], owners)), Commitment(abstain[1], "vote", ok, "v"))
	})
	late := voters[len(voters)-1] // commits, never opens: charged as an abstainer
	for _, a := range voters[:len(voters)-1] {
		testing.SetRealm(u(a))
		RevealVote(cross(cur), id, ok, "v")
	}
	testing.SetRealm(u(anyone))
	refuses(t, "the vote is still open", func() { Tally(cross(cur), id) })
	testing.SkipHeights(PoolRevealWindow)
	testing.SetRealm(u(late))
	refuses(t, "the vote's reveal window has passed", func() { RevealVote(cross(cur), id, ok, "v") })
	testing.SkipHeights(UnbondBlocks)
	testing.SetRealm(u(idle))
	refuses(t, "a pool vote it may vote in is still open", func() { Withdraw(cross(cur), ticketIndex(idle, owners)) })
	testing.SetRealm(u(anyone))
	if s := Tally(cross(cur), id); s != Undecided || Level(GuardHash(guardText)) != "" {
		t.Fatalf("an undecided vote: %s", s)
	}
	if !strings.Contains(Render("filing/"+itoa(id)), "- Undecided: under two thirds revealed") {
		t.Errorf("the filing's page:\n%s", Render("filing/"+itoa(id)))
	}
	if bal(worker)-before != FilingBond || FundBalance() != PoolFee || Burned() != 0 {
		t.Errorf("the worker got back %d; fund %d, burned %d", bal(worker)-before, FundBalance(), Burned())
	}
	testing.SetRealm(u(voters[0]))
	refuses(t, "no decided vote on this filing", func() { ClaimVote(cross(cur), id) })
	for tid, a := range owners {
		if a != idle {
			testing.SetRealm(u(a))
			Unstake(cross(cur), tid)
		}
	}
	testing.SkipHeights(UnbondBlocks)
	charged := map[address]bool{late: true}
	for _, a := range abstain {
		charged[a] = true
	}
	for tid, a := range owners {
		testing.SetRealm(u(a))
		w0 := bal(a)
		Withdraw(cross(cur), tid)
		want := MinTicket
		if charged[a] {
			want -= MinTicket * AbstainShare / 100
		}
		if got := bal(a) - w0; got != want {
			t.Errorf("%s withdrew %d, want %d", a, got, want)
		}
	}
	if Burned() != 4*MinTicket*AbstainShare/100 {
		t.Errorf("burned %d", Burned())
	}
}

// With no stake left to vote, the vote ends undecided at once, taking
// nothing from the fund. Drawn tickets can't leave before the last word, so
// no real pool gets here; the test empties it by hand.
func TestPoolNoStake(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, nil
	owners := ownersN(4)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
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
		RevealCheck(cross(cur), id, or(map[address]string{worker: ok}[c], lie), salt(c))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	get(id).oldBelow = 0
	if s := OpenPool(cross(cur), id); s != Undecided || bal(worker)-before != FilingBond {
		t.Fatalf("with no stake: %s, the worker got back %d", s, bal(worker)-before)
	}
	for tid := range owners {
		if _, _, open, _ := TicketOf(tid); open != 0 {
			t.Errorf("ticket %d still held", tid)
		}
	}
}
