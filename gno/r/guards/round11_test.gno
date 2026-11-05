package guards

import (
	"strings"
	"testing"

	"gno.land/p/nt/testutils/v0"
)

// Round 11's tests: the vote decides at a third, seats come from every
// ticket, drawers are paid, a drained ticket leaves, the floor is read when
// the round is fixed, and only those who said the last word in every run
// share what is taken.

func stakeAmount(t *testing.T, rlm realm, n int64) int {
	send(n)
	id := StakeTicket(cross(rlm))
	send(0)
	return id
}

// The vote's line is more than a third of all its weight, with no other
// transcript over it (round 11, new major 1): exactly a third stalls; a
// hair over decides; two transcripts both over a third stall; one over and
// two under decides. Each case stakes a ticket of each weight, files an
// honest guard the three owners check and agree on, and has a stranger
// object, so that with no panels the dispute goes to the pool.
func TestVoteThreshold(cur realm, t *testing.T) {
	cases := []struct {
		weights []int64
		says    []string // what each owner votes; "" stays away
		spare   bool     // a ticket withdrawn while the round waited: marked, not yet out of the tree
		want    string
	}{
		{[]int64{100_000_000, 100_000_000, 100_000_000}, []string{ok, "", ""}, false, Undecided},
		{[]int64{100_000_001, 100_000_000, 100_000_000}, []string{ok, "", ""}, false, Tested},
		{[]int64{110_000_000, 110_000_000, 80_000_000}, []string{ok, lie, ""}, false, Undecided},
		{[]int64{110_000_000, 100_000_000, 90_000_000}, []string{ok, lie, fails}, false, Tested},
		{[]int64{100_000_001, 100_000_000, 100_000_000}, []string{ok, "", ""}, true, Tested},
	}
	stranger, spare := testutils.TestAddress("stranger"), testutils.TestAddress("spare")
	for n, c := range cases {
		reset()
		Reruns, PanelSizes = 0, nil
		owners := ownersN(len(c.weights))
		for i, w := range owners {
			testing.SetRealm(u(w))
			stakeAmount(t, cur, c.weights[i])
		}
		if c.spare {
			testing.SetRealm(u(spare))
			stakeAmount(t, cur, 100_000_000)
			Unstake(cross(cur), len(owners))
		}
		testing.SetRealm(u(anyone))
		send(PoolFee)
		Fund(cross(cur))
		send(0)
		testing.SkipHeights(UnbondBlocks)
		testing.SetRealm(u(worker))
		id := file(t, cur, ok, 1001)
		if c.spare { // withdrawn while the checkers' round waits: the vote mustn't count its weight
			testing.SetRealm(u(spare))
			Withdraw(cross(cur), len(owners))
		}
		testing.SetRealm(u(anyone))
		drawn := draw(t, cur, id, 1001, sig1001)
		for _, d := range drawn {
			testing.SetRealm(u(d))
			CommitCheck(cross(cur), id, Commitment(d, "check", ok, salt(d)))
		}
		for _, d := range append([]address{worker}, drawn...) {
			testing.SetRealm(u(d))
			RevealCheck(cross(cur), id, ok, salt(d))
		}
		testing.SetRealm(u(anyone))
		Settle(cross(cur), id)
		testing.SetRealm(u(stranger))
		send(ObjectionBond)
		Object(cross(cur), id, lie)
		send(0)
		testing.SetRealm(u(anyone))
		OpenPool(cross(cur), id)
		for i, a := range owners {
			if c.says[i] != "" {
				testing.SetRealm(u(a))
				CommitVote(cross(cur), id, itoa(i), Commitment(a, "vote", c.says[i], "v"))
			}
		}
		testing.SkipHeights(PoolCommitWindow + 1)
		for i, a := range owners {
			if c.says[i] != "" {
				testing.SetRealm(u(a))
				RevealVote(cross(cur), id, c.says[i], "v")
			}
		}
		testing.SetRealm(u(anyone))
		if s := Tally(cross(cur), id); s != c.want {
			t.Errorf("case %d (%v voting %v): %s, want %s", n, c.weights, c.says, s, c.want)
		}
	}
}

// The reviewer's scenario (round 11, new major 1): honest stake is 70%, two
// owners of it holding 20% each; a liar holds 30% under six addresses and
// never votes in the pool, and a tenth of the honest stake stays silent.
// The liar objects to an honest agreement; every seat it holds says the
// liar's transcript on every panel, and whoever lost a panel's word
// appeals, up to the pool. The pool decides the honest transcript: the
// guard is tested, no honest bond or stake is taken, every seat the liar
// held loses Slash, and the liar's appeals are lost. Panel seats come from
// every ticket: the big owners, drawn as checkers, sit too.
func TestLiarCantStallThePool(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, []int{4, 7}
	big := []address{testutils.TestAddress("big1"), testutils.TestAddress("big2")}
	small := []address{testutils.TestAddress("h1"), testutils.TestAddress("h2"), testutils.TestAddress("h3")}
	var liars []address
	for i := 1; i <= 6; i++ {
		liars = append(liars, testutils.TestAddress("liar"+itoa(i)))
	}
	all := append(append(append([]address{}, big...), small...), liars...)
	weight := map[address]int64{}
	for _, a := range big {
		weight[a] = 200_000_000
	}
	for _, a := range small {
		weight[a] = 100_000_000
	}
	for _, a := range liars {
		weight[a] = 50_000_000
	}
	isLiar := map[address]bool{}
	for _, a := range liars {
		isLiar[a] = true
	}
	tid := map[address]int{}
	for _, a := range all {
		testing.SetRealm(u(a))
		tid[a] = stakeAmount(t, cur, weight[a])
	}
	testing.SetRealm(u(anyone))
	send(panelCost(0) + panelCost(1) + PoolFee)
	Fund(cross(cur))
	send(0)
	testing.SkipHeights(MinTicketAge)
	before := balances(append([]address{worker}, all...)...)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	for _, c := range drawn { // a liar drawn as a checker says it too, to be agreed
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", ok, salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, ok, salt(c))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Agreed {
		t.Fatalf("the honest agreement: %s", s)
	}
	party := map[address]bool{}
	for _, c := range drawn {
		party[c] = true
	}
	var objector address
	for _, a := range liars {
		if !party[a] {
			objector = a
			break
		}
	}
	aim(1003)
	testing.SetRealm(u(objector))
	send(ObjectionBond)
	Object(cross(cur), id, lie)
	send(0)
	sigs := map[uint64]string{1003: sig1003, 1004: sig1004}
	xSeats := map[address]int{}     // seats that said the liar's transcript
	ySeats := map[address]int{}     // seats that said the honest one
	appealed := map[address]int64{} // what each appellant put up
	partySeats := 0
	for step := 0; step < 6; step++ {
		st, r, _ := State(id)
		if st == Pool {
			break
		}
		testing.SetRealm(u(anyone))
		switch st {
		case Panel:
			SubmitBeacon(cross(cur), r, sigs[r])
			DrawPanel(cross(cur), id)
			members, _ := PanelOf(id)
			seats := seatMap(id, members)
			for _, p := range members {
				said := ok
				if isLiar[p] {
					said, xSeats[p] = lie, xSeats[p]+seats[p]
				} else {
					ySeats[p] += seats[p]
				}
				if party[p] || p == objector {
					partySeats += seats[p]
				}
				testing.SetRealm(u(p))
				CommitCheck(cross(cur), id, Commitment(p, "check", said, salt(p)))
			}
			for _, p := range members {
				said := ok
				if isLiar[p] {
					said = lie
				}
				testing.SetRealm(u(p))
				RevealCheck(cross(cur), id, said, salt(p))
			}
			aim(1004)
			testing.SetRealm(u(anyone))
			Settle(cross(cur), id)
		case Appealable:
			w, _ := Word(id)
			who := big[0] // the liar's word: an honest owner appeals
			if w == ok {
				who = objector // the honest word: the liar appeals, for its stall
			}
			aim(1004)
			testing.SetRealm(u(who))
			bond := AppealCost(id)
			send(bond)
			Appeal(cross(cur), id)
			send(0)
			appealed[who] += bond
		default:
			t.Fatalf("step %d: %s", step, st)
		}
	}
	if st, _, _ := State(id); st != Pool {
		t.Fatalf("the dispute never reached the pool: %s", st)
	}
	if partySeats == 0 {
		t.Error("no party sat on any panel: seats aren't drawn from every ticket")
	}
	testing.SetRealm(u(anyone))
	OpenPool(cross(cur), id)
	says := map[address]string{}
	for _, a := range all {
		if !isLiar[a] && a != small[2] { // the liar and a tenth of the honest stake stay away
			says[a] = ok
		}
	}
	for _, a := range all {
		if says[a] != "" {
			testing.SetRealm(u(a))
			CommitVote(cross(cur), id, itoa(tid[a]), Commitment(a, "vote", says[a], "v"))
		}
	}
	testing.SkipHeights(PoolCommitWindow + 1)
	for _, a := range all {
		if says[a] != "" {
			testing.SetRealm(u(a))
			RevealVote(cross(cur), id, says[a], "v")
		}
	}
	testing.SetRealm(u(anyone))
	if s := Tally(cross(cur), id); s != Tested || lvl() != Tested {
		t.Fatalf("the pool: %s, level %q", s, lvl())
	}
	for _, a := range all {
		want := weight[a]
		if isLiar[a] {
			want -= Slash * int64(xSeats[a])
		}
		if got := stakeOf(tid[a]); got != want {
			t.Errorf("%s (liar %v, %d wrong seats): stake %d, want %d", a, isLiar[a], xSeats[a], got, want)
		}
		if !isLiar[a] && bal(a) < before[a] {
			t.Errorf("honest %s lost %d", a, before[a]-bal(a))
		}
	}
	if got := bal(worker) - before[worker]; got < FilingBond-int64(Checkers)*CheckFee-FundFee {
		t.Errorf("the honest worker got back %d", got)
	}
	if bal(big[0])-before[big[0]] < appealed[big[0]] {
		t.Errorf("the honest appellant lost its bond: %d of %d", bal(big[0])-before[big[0]], appealed[big[0]])
	}
	if bal(objector)-before[objector] != 0 {
		t.Errorf("the liar's objector got %d back", bal(objector)-before[objector])
	}
}

// Whoever draws is paid DrawFee: a filing's draw from its bond, a panel's
// from what the fund set aside for it, which the last word refills from
// the losing side (round 11, minor 6).
func TestDrawPaysTheDrawer(cur realm, t *testing.T) {
	reset()
	DrawFee, AppealBond = 200_000, 0
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
	drawer := testutils.TestAddress("drawer")
	before := balances(append([]address{worker, drawer}, owners...)...)
	testing.SetRealm(u(worker))
	FilingBond = 3*CheckFee + FundFee + DrawFee - 1
	send(FilingBond)
	refuses(t, "the bond can't pay its checkers, its draw", func() { Commit(cross(cur), strings.Repeat("0", 64)) })
	send(0)
	FilingBond = 1_000_000
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(drawer))
	drawn := draw(t, cur, id, 1001, sig1001)
	if got := bal(drawer) - before[drawer]; got != DrawFee {
		t.Fatalf("the drawer got %d", got)
	}
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
	aim(1003)
	testing.SetRealm(u(stranger))
	send(ObjectionBond)
	Object(cross(cur), id, lie)
	send(0)
	if FundBalance() != 0 {
		t.Fatalf("the panel's fees and draw weren't set aside: fund %d", FundBalance())
	}
	testing.SetRealm(u(drawer))
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	if got := bal(drawer) - before[drawer]; got != 2*DrawFee {
		t.Fatalf("after the panel's draw the drawer has %d", got)
	}
	panel, size := PanelOf(id)
	seats := seatMap(id, panel)
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
	if c := AppealCost(id); c != panelCost(1) {
		t.Errorf("an appeal costs %d, not the next panel's seats and draw, %d", c, panelCost(1))
	}
	testing.SkipHeights(AppealWindow + 1)
	if s := Settle(cross(cur), id); s != Tested {
		t.Fatalf("the last word: %s", s)
	}
	spent := int64(size)*PanelFee + DrawFee
	refill := least(ObjectionBond, spent)
	each := (ObjectionBond - refill) * ShowShare / 100 / 4 // the worker and its three checkers
	if got := bal(worker) - before[worker]; got != FilingBond-3*CheckFee-FundFee-DrawFee+each {
		t.Errorf("the worker got %d", got)
	}
	for _, c := range drawn {
		if got := bal(c) - before[c]; got != CheckFee+each+PanelFee*int64(seats[c]) {
			t.Errorf("checker %s got %d", c, got)
		}
	}
	if FundBalance() != FundFee+refill {
		t.Errorf("fund %d, want %d", FundBalance(), FundFee+refill)
	}
}

// A ticket charged under half its weight leaves: its weight counts as
// leaving, its live stake is gone, and no later round draws it (round 11,
// minor 5). Above half, it stays.
func TestDrainedTicketLeaves(cur realm, t *testing.T) {
	reset()
	testing.SetRealm(u(alice))
	id := stakeAmount(t, cur, 30_000_000)
	tk := ticketAt(id)
	charge(tk, 15_000_000)
	if tk.leaving != 0 || LiveStake() != 15_000_000 {
		t.Fatalf("at half its weight: leaving %d, live %d", tk.leaving, LiveStake())
	}
	charge(tk, 1)
	if tk.leaving == 0 || LiveStake() != 0 {
		t.Fatalf("under half: leaving %d, live %d", tk.leaving, LiveStake())
	}
	if sum, left, _ := below(nTickets); sum != 30_000_000 || left != 30_000_000 {
		t.Fatalf("the tree: %d, %d leaving", sum, left)
	}
}

// The floor is the weight a filing's draw could take when its round was
// fixed: tickets old enough and not leaving then (round 11, minor 7). An
// unstake after the fix doesn't take the level away.
func TestFloorAtFix(cur realm, t *testing.T) {
	reset()
	LevelFloor = 25_000_000 // two and a half tickets
	for _, w := range []address{alice, bob, carol} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SkipHeights(1)
	testing.SetRealm(u(alice))
	Unstake(cross(cur), 0) // after the round is fixed: the live stake is under the floor now
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
	if s := finalize(t, cur, id); s != Tested || lvl() != Tested || LiveStake() >= LevelFloor {
		t.Errorf("an unstake after the fix: %s, level %q, live %d", s, lvl(), LiveStake())
	}
}

// Stake too young to be drawn into a filing doesn't make its level, though
// the live stake passes the floor (round 11, minor 7). A test of its own:
// a level written stays in the realm's params past reset.
func TestFloorYoungStake(cur realm, t *testing.T) {
	reset()
	LevelFloor = 35_000_000 // three and a half tickets
	for _, w := range []address{alice, bob, carol} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(eve))
	stakeOne(t, cur)
	Unstake(cross(cur), 3) // leaving before the filing: not in the floor either
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(dave))
	stakeOne(t, cur) // too young for the filing: the live stake passes the floor, the draw's weight doesn't
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
	if s := finalize(t, cur, id); s != Tested || lvl() != "" || LiveStake() < LevelFloor {
		t.Errorf("young stake: %s, level %q, live %d", s, lvl(), LiveStake())
	}
}

// Only a party that said the last word in every run shares what is taken
// (round 11, minor 3): a worker and a checker that differed in the first
// run and said it in the rerun are paid less RerunFee, and get no share;
// the steady checker gets it all.
func TestShowersSaidItEveryRun(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 1, []int{4}
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
	before := balances(append([]address{worker}, owners...)...)
	testing.SetRealm(u(worker))
	id := file(t, cur, fails, 1001) // the worker's first run says it fails
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	liar, flaky, steady := drawn[0], drawn[1], drawn[2]
	// The first run's commitments come in after the draw; the worker's is
	// already in from the reveal.
	first := map[address]string{liar: lie, flaky: fails, worker: fails}
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", or(first[c], ok), salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, or(first[c], ok), salt(c))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Rerun {
		t.Fatalf("after the first run: %s", s)
	}
	for _, c := range append([]address{worker}, drawn...) { // the flaky checker agrees now; the liar doesn't
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, kind(c), or(map[address]string{liar: lie}[c], ok), salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, or(map[address]string{liar: lie}[c], ok), salt(c))
	}
	aim(1003)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Panel {
		t.Fatalf("after the rerun: %s", s)
	}
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	panel, size := PanelOf(id)
	seats := seatMap(id, panel)
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
	testing.SkipHeights(AppealWindow + 1)
	if s := Settle(cross(cur), id); s != Tested {
		t.Fatalf("the last word: %s", s)
	}
	refill := least(Slash, int64(size)*PanelFee)
	share := (Slash - refill) * ShowShare / 100 // all to the steady checker
	want := map[address]int64{
		worker: FilingBond - 2*CheckFee - FundFee - RerunFee,
		steady: CheckFee + share,
		flaky:  CheckFee,
	}
	for _, p := range panel {
		want[p] += PanelFee * int64(seats[p])
	}
	for _, a := range append([]address{worker}, owners...) {
		if got := bal(a) - before[a]; got != want[a] {
			t.Errorf("%s (%d seats): got %d, want %d", a, seats[a], got, want[a])
		}
	}
	if stakeOf2(flaky, owners) != MinTicket-RerunFee || stakeOf2(liar, owners) != MinTicket-Slash {
		t.Errorf("the flaky checker's stake %d, the liar's %d", stakeOf2(flaky, owners), stakeOf2(liar, owners))
	}
}

// Withdrawals while a round waits are marked, and Compact takes them out
// MaxSettle at a time once no round waits; a withdrawal when none waits
// takes its own weight out at once (round 11, new major 2).
func TestCompactInSteps(cur realm, t *testing.T) {
	reset()
	MaxSettle = 2
	owners := []address{alice, bob, carol, dave}
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	var spares []address
	for i := 1; i <= 6; i++ {
		a := testutils.TestAddress("spare" + itoa(i))
		spares = append(spares, a)
		testing.SetRealm(u(a))
		stakeOne(t, cur)
		Unstake(cross(cur), len(owners)+i-1)
	}
	testing.SkipHeights(UnbondBlocks)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	for i, a := range spares[:5] {
		testing.SetRealm(u(a))
		Withdraw(cross(cur), len(owners)+i)
	}
	if len(dead) != 5 {
		t.Fatalf("%d marked", len(dead))
	}
	testing.SetRealm(u(anyone))
	draw(t, cur, id, 1001, sig1001)
	for _, want := range []int{3, 1, 0} {
		if n := Compact(cross(cur)); n != want {
			t.Fatalf("Compact left %d, want %d", n, want)
		}
	}
	if sum, left, gone := below(nTickets); sum != 5*MinTicket || left != MinTicket || gone != 0 {
		t.Fatalf("after Compact: %d, %d leaving, %d withdrawn", sum, left, gone)
	}
	testing.SetRealm(u(spares[5]))
	Withdraw(cross(cur), len(owners)+5) // no round waits now
	if sum, left, gone := below(nTickets); sum != 4*MinTicket || left != 0 || gone != 0 || len(dead) != 0 {
		t.Fatalf("a withdrawal with no round waiting: %d, %d leaving, %d withdrawn, %d marked", sum, left, gone, len(dead))
	}
}

// zeroNodes counts nodes of the tree with nothing below them: the paths
// addPath should have dropped.
func zeroNodes(n *sumNode) int {
	if n == nil {
		return 0
	}
	z := zeroNodes(n.l) + zeroNodes(n.r)
	if n.sum == 0 && n != sumRoot {
		z++
	}
	return z
}

// Taking a ticket's weight out drops the path nothing else holds, so the
// tree doesn't keep a node for every ticket ever staked (round 11, new
// major 2).
func TestTreeDropsEmptyPaths(cur realm, t *testing.T) {
	reset()
	for i, w := range []address{alice, bob, carol} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
		Unstake(cross(cur), i)
	}
	testing.SkipHeights(UnbondBlocks)
	for i, w := range []address{alice, bob} {
		testing.SetRealm(u(w))
		Withdraw(cross(cur), i)
	}
	if z := zeroNodes(sumRoot); z != 0 {
		t.Errorf("%d empty nodes left in the tree", z)
	}
	if sum, left, _ := below(nTickets); sum != MinTicket || left != MinTicket {
		t.Errorf("the tree holds %d, %d leaving", sum, left)
	}
}

// A redraw's bond has less to spare: the drawer is paid from the bond
// while it can be, then from the fund (round 11, minor 6). Every checker
// stays silent twice, and the third draw finds too few owners left.
func TestDrawFeeFromTheFund(cur realm, t *testing.T) {
	reset()
	DrawFee = 300_000 // two draws from the bond's 600,000 to spare
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	drawer := testutils.TestAddress("drawer")
	before := balances(worker, drawer)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	sigs := map[uint64]string{1001: sig1001, 1002: sig1002, 1003: sig1003}
	for r := uint64(1001); r <= 1003; r++ {
		testing.SetRealm(u(drawer))
		SubmitBeacon(cross(cur), r, sigs[r])
		s := Draw(cross(cur), id)
		if got := bal(drawer) - before[drawer]; got != int64(r-1000)*DrawFee {
			t.Fatalf("after draw %d the drawer has %d (fund %d)", r-1000, got, FundBalance())
		}
		if r == 1003 {
			if s != Abandoned {
				t.Fatalf("the third draw: %s", s)
			}
			break
		}
		testing.SkipHeights(CheckWindow + 1) // nobody drawn commits
		aim(r + 1)
		testing.SetRealm(u(anyone))
		if s := Settle(cross(cur), id); s != Revealed {
			t.Fatalf("after draw %d: %s", r-1000, s)
		}
	}
	// Six fined for silence, 6 × NoShowFine to the fund; it paid the third
	// draw; the bond went back less FundFee, after two draws from it.
	if FundBalance() != 6*NoShowFine-DrawFee+FundFee {
		t.Errorf("fund %d", FundBalance())
	}
	if got := bal(worker) - before[worker]; got != FilingBond-2*DrawFee-FundFee {
		t.Errorf("the worker got back %d", got)
	}
}

// A panel nobody eligible can sit on goes to the pool, and its seats' fees
// go back to the fund (round 11, minor 6): every owner unstaked before the
// panel's round was fixed.
func TestPanelNobodyEligible(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, []int{4}
	owners := ownersN(4)
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
	for i, w := range owners {
		testing.SetRealm(u(w))
		Unstake(cross(cur), i)
	}
	aim(1003)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Panel || FundBalance() != 0 {
		t.Fatalf("the panel: %s, fund %d", s, FundBalance())
	}
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	if st, _, _ := State(id); st != Pool || FundBalance() != int64(PanelSizes[0])*PanelFee || get(id).panelCost != 0 {
		t.Errorf("nobody to seat: %s, fund %d, the dispute's cost %d", st, FundBalance(), get(id).panelCost)
	}
}
