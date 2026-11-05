package guards

import (
	"strings"
	"testing"

	"gno.land/p/nt/testutils/v0"
)

// The pool decides by stake. A dispute no panel decided goes to the vote:
// six of eight owners, more than two thirds of the stake, vote the worker's
// transcript. That is the last word: the lying checkers and the seats on
// the wrong side lose Slash, which first pays the fund back for the panel
// and the vote. Each winner claims its share of PoolFee by weight, exactly,
// though PoolFee times a weight overflows 64 bits (round 9, minor 11); the
// two who voted otherwise are charged as their tickets leave (round 9, new
// major 6). A ticket staked after the filing has no vote.
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
	panel, size := PanelOf(id)
	seats := seatMap(id, panel)
	sayP, even := split(panel, seats, size, ok, lie)
	if !even {
		t.Fatalf("the panel's seats can't split: %v", seats)
	}
	for _, p := range panel {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", sayP[p], salt(p)))
	}
	for _, p := range panel {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, sayP[p], salt(p))
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
	refuses(t, "only with that same commitment", func() { CommitVote(cross(cur), id, "0", Commitment(owners[0], "vote", ok, "w")) })
	refuses(t, "already voted", func() { CommitVote(cross(cur), id, "0", Commitment(owners[0], "vote", sayV(owners[0]), "v")) })
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
	if s := Tally(cross(cur), id); s != Tested || lvl() != Tested {
		t.Fatalf("the pool decided %s", s)
	}
	page := Render("filing/" + itoa(id))
	for _, want := range []string{"## Panel 1 (of 4 seats)", "## The pool's vote", "8 voters committed, 80000000 of 80000000 ugnot", "- Decided: `" + ok + "`"} {
		if !strings.Contains(page, want) {
			t.Errorf("the filing's page lacks %q:\n%s", want, page)
		}
	}
	wrongSeats := 0
	for _, p := range panel {
		if sayP[p] == lie {
			wrongSeats += seats[p]
		}
	}
	taken := int64(3+wrongSeats) * Slash // three lying checkers, and the seats on the wrong side
	refill := least(taken, int64(size-wrongSeats)*PanelFee+PoolFee)
	rest := taken - refill
	if got := bal(worker) - before[worker]; got != FilingBond-FundFee+rest*ShowShare/100 {
		t.Errorf("the worker got %d", got)
	}
	if FundBalance() != FundFee+int64(wrongSeats)*PanelFee+refill {
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
	testing.SetRealm(u(anyone))
	refuses(t, "winners may still claim", func() { SweepVote(cross(cur), id) })
	testing.SkipHeights(PoolClaimWindow + 1)
	if n := SweepVote(cross(cur), id); n != PoolFee-6*(PoolFee/6) {
		t.Errorf("swept %d", n)
	}
	wrong := map[address]int64{}
	for _, c := range drawn {
		wrong[c] += Slash // their transcripts
	}
	for _, p := range panel {
		if sayP[p] == lie {
			wrong[p] += Slash * int64(seats[p]) // their seats
		}
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
	// The two wrong votes' charges go to the fund as their tickets leave
	// (round 11, minor 3), after the sweep.
	swept := PoolFee - 6*(PoolFee/6)
	if Burned() != rest-rest*ShowShare/100 || LiveStake() != 0 || FundBalance() != FundFee+int64(wrongSeats)*PanelFee+refill+swept+2*Slash {
		t.Errorf("burned %d, live stake %d, fund %d", Burned(), LiveStake(), FundBalance())
	}
}

// Five of eight owners commit and two open: no transcript holds over a
// third of the stake (round 11, new major 1). The tally waits while a
// committed vote may still open. Nothing is decided: no level, nobody paid
// or charged for the dispute, the worker's whole bond back, every ticket
// let go, and the vote's fee back in the fund. The vote waits for a fund
// that can pay it; a ticket can't leave while the vote is open; each of the
// six that didn't vote is charged AbstainShare as it leaves, for the fund
// (a stall is the abstainers').
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
	late := voters[2:] // commit, never open: charged as abstainers
	for _, a := range voters[:2] {
		testing.SetRealm(u(a))
		RevealVote(cross(cur), id, ok, "v")
	}
	testing.SetRealm(u(anyone))
	refuses(t, "the vote is still open", func() { Tally(cross(cur), id) })
	testing.SkipHeights(PoolRevealWindow)
	testing.SetRealm(u(late[0]))
	refuses(t, "the vote's reveal window has passed", func() { RevealVote(cross(cur), id, ok, "v") })
	testing.SkipHeights(UnbondBlocks)
	testing.SetRealm(u(idle))
	refuses(t, "a pool vote it may vote in is still open", func() { Withdraw(cross(cur), ticketIndex(idle, owners)) })
	testing.SetRealm(u(anyone))
	if s := Tally(cross(cur), id); s != Undecided || lvl() != "" {
		t.Fatalf("an undecided vote: %s", s)
	}
	if !strings.Contains(Render("filing/"+itoa(id)), "- Undecided: no transcript held over a third of the stake with no rival") {
		t.Errorf("the filing's page:\n%s", Render("filing/"+itoa(id)))
	}
	if bal(worker)-before != FilingBond-int64(Checkers)*CheckFee || FundBalance() != PoolFee || Burned() != 0 { // the checkers who answered are paid (round 12, minor 3)
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
	charged := map[address]bool{}
	for _, a := range append(abstain, late...) {
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
	if Burned() != 0 || FundBalance() != PoolFee+6*MinTicket*AbstainShare/100 {
		t.Errorf("burned %d, fund %d", Burned(), FundBalance())
	}
}

// A worker a panel found lying appeals to the pool, and the vote stalls:
// two owners of eight vote, no transcript holds over a third of the stake.
// No panel's word settles any money (round 11, new major 1): the worker's
// bond and appeal bond come back, nobody on the filing or the panel is paid
// or charged, the fund ends as it began, and no level is written or pulled.
func TestPoolStallGivesBondsBack(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, []int{4}
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
	id := file(t, cur, lie, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", fails, salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, or(map[address]string{worker: lie}[c], fails), salt(c))
	}
	aim(1003)
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	panel, size := PanelOf(id)
	seats := seatMap(id, panel)
	for _, p := range panel {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", fails, salt(p)))
	}
	for _, p := range panel {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, fails, salt(p))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Appealable {
		t.Fatalf("the panel's word: %s", s)
	}
	testing.SetRealm(u(worker))
	bond := AppealCost(id)
	if bond != PoolFee {
		t.Errorf("an appeal to the pool costs %d, not what the vote costs the fund", bond)
	}
	send(bond)
	if s := Appeal(cross(cur), id); s != Pool {
		t.Fatalf("after the appeal: %s", s)
	}
	send(0)
	testing.SetRealm(u(anyone))
	OpenPool(cross(cur), id)
	for _, a := range []address{drawn[0], drawn[1]} { // a quarter of the stake
		testing.SetRealm(u(a))
		CommitVote(cross(cur), id, itoa(ticketIndex(a, owners)), Commitment(a, "vote", fails, "v"))
	}
	testing.SkipHeights(PoolCommitWindow + 1)
	for _, a := range []address{drawn[0], drawn[1]} {
		testing.SetRealm(u(a))
		RevealVote(cross(cur), id, fails, "v")
	}
	testing.SetRealm(u(anyone))
	if s := Tally(cross(cur), id); s != Undecided || lvl() != "" {
		t.Fatalf("a stalled vote: %s, level %q", s, lvl())
	}
	if got := bal(worker) - before[worker]; got != FilingBond-int64(Checkers)*CheckFee+bond || RecordOf(worker).Faults != 0 {
		t.Errorf("the worker got %d back of %d and %d; record %+v", got, FilingBond, bond, RecordOf(worker))
	}
	checker := map[address]bool{drawn[0]: true, drawn[1]: true, drawn[2]: true}
	for _, a := range owners {
		want := int64(0)
		if checker[a] { // it answered: paid for the run, and no seat is (round 12, minor 3)
			want = CheckFee
		}
		if got := bal(a) - before[a]; got != want || stakeOf2(a, owners) != MinTicket {
			t.Errorf("%s (%d seats): paid %d, want %d, stake %d", a, seats[a], got, want, stakeOf2(a, owners))
		}
	}
	if FundBalance() != PoolFee+int64(size)*PanelFee || Burned() != 0 {
		t.Errorf("fund %d, burned %d", FundBalance(), Burned())
	}
	if !strings.Contains(Render("filing/"+itoa(id)), "the bonds went back, less each answering checker's fee") {
		t.Errorf("the filing's page:\n%s", Render("filing/"+itoa(id)))
	}
}

// A vote nobody votes in, after a panel's passing word that a lying checker
// appealed: no level, since only a word the pool itself reaches, or an
// agreement, makes a guard tested; and no money moves by the panel's word
// (round 11, new major 1): every bond back, the liar's stake untouched.
func TestPoolStallWritesNoLevel(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, []int{4}
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
	liar := drawn[0]
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", or(map[address]string{liar: lie}[c], ok), salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, or(map[address]string{liar: lie}[c], ok), salt(c))
	}
	aim(1003)
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	panel, size := PanelOf(id)
	for _, p := range panel {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", ok, salt(p)))
	}
	for _, p := range panel {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, ok, salt(p))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	testing.SetRealm(u(liar))
	bond := AppealCost(id)
	send(bond)
	Appeal(cross(cur), id)
	send(0)
	testing.SetRealm(u(anyone))
	OpenPool(cross(cur), id)
	testing.SkipHeights(PoolCommitWindow + PoolRevealWindow + 1) // nobody votes
	if s := Tally(cross(cur), id); s != Undecided || lvl() != "" {
		t.Fatalf("a stalled vote after a passing word: %s, level %q", s, lvl())
	}
	if got := bal(worker) - before[worker]; got != FilingBond-int64(Checkers)*CheckFee {
		t.Errorf("the worker got %d", got)
	}
	if stakeOf2(liar, owners) != MinTicket || bal(liar)-before[liar] != bond+CheckFee {
		t.Errorf("the liar: stake %d, paid %d", stakeOf2(liar, owners), bal(liar)-before[liar])
	}
	if FundBalance() != PoolFee+int64(size)*PanelFee || Burned() != 0 {
		t.Errorf("fund %d, burned %d", FundBalance(), Burned())
	}
}

// A frivolous objection taken all the way to the pool costs the objector
// what it cost the fund: the objection's bond and the appeal's pay back the
// panel and the vote first, so the fund ends whole (round 10, new major 3).
func TestFrivolousObjectionToPool(cur realm, t *testing.T) {
	reset()
	PanelSizes, PoolFee = []int{4}, 3_000_000 // the vote costs more than AppealBond
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(anyone))
	start := PoolFee + 4*PanelFee
	send(start)
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
	aim(1003)
	testing.SetRealm(u(eve))
	send(ObjectionBond)
	Object(cross(cur), id, fails)
	send(0)
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	panel, _ := PanelOf(id)
	for _, p := range panel {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", ok, salt(p)))
	}
	for _, p := range panel {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, ok, salt(p))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	testing.SetRealm(u(eve))
	send(AppealBond)
	refuses(t, "send at least 3000000", func() { Appeal(cross(cur), id) })
	send(AppealCost(id))
	Appeal(cross(cur), id)
	send(0)
	testing.SetRealm(u(anyone))
	OpenPool(cross(cur), id)
	for i, a := range owners {
		testing.SetRealm(u(a))
		CommitVote(cross(cur), id, itoa(i), Commitment(a, "vote", ok, "v"))
	}
	testing.SkipHeights(PoolCommitWindow + 1)
	for _, a := range owners {
		testing.SetRealm(u(a))
		RevealVote(cross(cur), id, ok, "v")
	}
	testing.SetRealm(u(anyone))
	if s := Tally(cross(cur), id); s != Tested || lvl() != Tested {
		t.Fatalf("the pool's word: %s", s)
	}
	if FundBalance() < start {
		t.Errorf("the fund paid %d for a frivolous objection", start-FundBalance())
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
	if s := OpenPool(cross(cur), id); s != Undecided || bal(worker)-before != FilingBond-int64(Checkers)*CheckFee {
		t.Fatalf("with no stake: %s, the worker got back %d", s, bal(worker)-before)
	}
	for tid := range owners {
		if _, _, open, _ := TicketOf(tid); open != 0 {
			t.Errorf("ticket %d still held", tid)
		}
	}
}
