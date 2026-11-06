package guards

import (
	"chain"
	"chain/banker"
	"chain/runtime"
	"strings"
	"testing"
	"time"

	"gno.land/p/nt/avl/v0"
	"gno.land/p/nt/testutils/v0"
	"gno.land/p/nt/ufmt/v0"
)

// drand evmnet rounds 1001 and 1002, as api.drand.sh serves them.
const (
	sig1001 = "037ca0c482675da24ec2efed381ac9ac103ebfe834c798b0b8234828b309dc7704cafa24b93010156482236fed83576883f9fb15e7175216ed8d206e3e323d4c"
	sig1002 = "1ed7f88d4317f7fc378d6eece9dde7d6b3a4f6956c12450a9fdb843df146715d0ea34a65b09f1363b2b69fe532fd78979816ff876ee49d59514fdcbc09bd27fb"
)

// Revealed transcripts: the rig's transcript's hash and its verdict.
const (
	ok    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa pass"
	lie   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb pass"
	fails = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa fail"
)

const guardText = `{"flaw":"CVE-2026-98432","drop":{"ip_options":true}}` + "\n"

// sys is the system the tests' transcripts are for.
const sys = "ubuntu 24.04"

// lvl is the tests' guard's level on sys.
func lvl() string { return Level(GuardHash(guardText), sys) }

var (
	worker = testutils.TestAddress("worker")
	alice  = testutils.TestAddress("alice")
	bob    = testutils.TestAddress("bob")
	carol  = testutils.TestAddress("carol")
	dave   = testutils.TestAddress("dave")
	eve    = testutils.TestAddress("eve")
	anyone = testutils.TestAddress("anyone")
	self   = chain.PackageAddress("gno.land/r/repairer/guards")
)

// Note: testing.SetRealm rewrites the realm value of the function that
// calls it, so only the test functions themselves switch users; the helpers
// call the realm as whoever the test set.

func reset() {
	tickets, nTickets, filings, nFilings = avl.NewTree(), 0, avl.NewTree(), 0
	levels, records, beacon, burned, fund = avl.NewTree(), avl.NewTree(), avl.NewTree(), 0, 0
	sumRoot, active, pending, waits, leaves = &sumNode{}, 0, avl.NewTree(), avl.NewTree(), 0
	votes, allVotes, openVotes = map[int]*poolVote{}, nil, nil
	texts, byGuard = avl.NewTree(), avl.NewTree()
	MinTicketAge, RevealWindow, CheckWindow, DrawDeadline, UnbondBlocks, DrawDelay = 10, 5, 20, 30, 60, 3
	ObjectionWindow, AppealWindow, LevelFloor = 5, 5, 1
	Reruns, PanelSizes = 2, []int{4, 7}
	PoolCommitWindow, PoolRevealWindow, PoolFee, PoolClaimWindow = 5, 5, 1_000_000, 50
	AppealBond, RerunFee, MaxSettle = 1_000_000, 500_000, 64
	DrawFee, FilingBond = 0, 1_000_000 // TestDrawPaysTheDrawer and the tests after it set their own DrawFee
}

func u(a address) runtime.Realm { return testing.NewUserRealm(a) }

// send makes the next call send n ugnot here.
func send(n int64) {
	c := chain.Coins{}
	if n > 0 {
		c = chain.Coins{chain.NewCoin("ugnot", n)}
		testing.IssueCoins(self, c) // what the tx moves here
	}
	testing.SetOriginSend(c)
}

// aim makes the next reveal, redraw or panel draw from beacon round r.
func aim(r uint64) {
	drandGenesis = time.Now().Unix() - int64(r-1-uint64(DrawDelay))*drandPeriod
}

func bal(a address) int64 { return banker.NewReadonlyBanker().GetCoins(a).AmountOf("ugnot") }

func balances(as ...address) map[address]int64 {
	m := map[address]int64{}
	for _, a := range as {
		m[a] = bal(a)
	}
	return m
}

func stakeOf(id int) int64 {
	_, s, _, _ := TicketOf(id)
	return s
}

// refuses checks that f aborts with a message containing want.
func refuses(t *testing.T, want string, f func()) {
	t.Helper()
	r := revive(f)
	if r == nil {
		t.Errorf("%q: wasn't refused", want)
		return
	}
	if got := ufmt.Sprintf("%v", r); !strings.Contains(got, want) {
		t.Errorf("refused with %q, want %q", got, want)
	}
}

func stakeOne(t *testing.T, rlm realm) {
	send(MinTicket)
	StakeTicket(cross(rlm))
	send(0)
}

// filingCommit is the commitment of the worker's filing of guard on sys with the
// transcript commitment tc.
func filingCommit(guard, tc string) string {
	return Commitment(worker, "guard", GuardHash(guard)+"\x00"+sys+"\x00"+tc, "s")
}

// file commits and reveals the worker's filing of guardText with transcript
// tr, to be drawn from beacon round r. The test sets the worker first.
func file(t *testing.T, rlm realm, tr string, r uint64) int {
	tc := Commitment(worker, "transcript", tr, "t")
	send(FilingBond)
	id := Commit(cross(rlm), filingCommit(guardText, tc))
	send(0)
	testing.SkipHeights(1)
	aim(r)
	Reveal(cross(rlm), id, guardText, sys, tc, "s")
	return id
}

// draw submits the round and draws; the test sets anyone first.
func draw(t *testing.T, rlm realm, id int, round uint64, sig string) []address {
	t.Helper()
	SubmitBeacon(cross(rlm), round, sig)
	Draw(cross(rlm), id)
	st, r, drawn := State(id)
	if st != Drawn || r != round || len(drawn) != Checkers {
		t.Fatalf("draw: %s from %d, %d drawn", st, r, len(drawn))
	}
	return drawn
}

// finalize waits out the objection window and ends the agreement.
func finalize(t *testing.T, rlm realm, id int) string {
	testing.SkipHeights(ObjectionWindow + 1)
	return Finalize(cross(rlm), id)
}

func salt(who address) string {
	if who == worker {
		return "t"
	}
	return "c-" + string(who)
}

func kind(who address) string {
	if who == worker {
		return "transcript"
	}
	return "check"
}

func or(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// The honest path, and the draw's fixed round: a round other than the one
// the reveal fixed draws nothing, and a filing that can be drawn can't be
// abandoned. Once every transcript agrees, nothing is paid or written until
// the objection window passes; then every checker is paid, the rest of the
// bond goes back, and the level is written. A ticket comes back after
// unbonding.
func TestHonest(cur realm, t *testing.T) {
	reset()
	testing.SetRealm(testing.NewCodeRealm("gno.land/r/evil/proxy"))
	send(MinTicket)
	refuses(t, "call from your own account", func() { StakeTicket(cross(cur)) })
	for _, w := range []address{alice, bob, carol, dave} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	send(MinTicket - 1)
	refuses(t, "send at least", func() { StakeTicket(cross(cur)) })
	// The worker's own ticket and alice's next two are large: a draw that
	// let in the filer, or one owner twice, would take them.
	for _, w := range []address{worker, alice, alice} {
		testing.SetRealm(u(w))
		send(1000 * MinTicket)
		StakeTicket(cross(cur))
	}
	send(0)
	testing.SkipHeights(MinTicketAge)
	before := balances(worker, alice, bob, carol, dave)
	testing.SetRealm(u(worker))
	send(FilingBond - 1)
	refuses(t, "send at least", func() { Commit(cross(cur), Commitment(worker, "guard", "x", "s")) })
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	refuses(t, "submit beacon round 1001 first", func() { Draw(cross(cur), id) })
	SubmitBeacon(cross(cur), 1002, sig1002)
	refuses(t, "submit beacon round 1001 first", func() { Draw(cross(cur), id) })
	refuses(t, "that isn't drand evmnet's signature", func() { SubmitBeacon(cross(cur), 1003, sig1002) })
	refuses(t, "it can still be drawn", func() { Abandon(cross(cur), id) })
	drawn := draw(t, cur, id, 1001, sig1001)
	seen := map[address]bool{}
	for _, c := range drawn {
		if c == worker || seen[c] {
			t.Fatalf("drew %v", drawn)
		}
		seen[c] = true
	}
	refuses(t, "not waiting for a draw", func() { Draw(cross(cur), id) })
	testing.SetRealm(u(worker))
	refuses(t, "wait until every drawn checker has committed", func() { RevealCheck(cross(cur), id, ok, "t") })
	testing.SetRealm(u(eve))
	refuses(t, "you weren't drawn", func() { CommitCheck(cross(cur), id, Commitment(eve, "check", ok, "x")) })
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", ok, salt(c)))
	}
	refuses(t, "already committed", func() { CommitCheck(cross(cur), id, Commitment(drawn[2], "check", ok, "y")) })
	testing.SetRealm(u(anyone))
	refuses(t, "still waiting for reveals", func() { Settle(cross(cur), id) })
	testing.SetRealm(u(drawn[0]))
	refuses(t, "that isn't what was committed", func() { RevealCheck(cross(cur), id, ok, "wrong") })
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, ok, salt(c))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Agreed || lvl() != "" {
		t.Fatalf("agreed: %s, level %q", s, lvl())
	}
	refuses(t, "no agreement to finalize", func() { Finalize(cross(cur), id) })
	if bal(worker) != before[worker] {
		t.Fatal("paid before the objection window passed")
	}
	if s := finalize(t, cur, id); s != Tested || lvl() != Tested {
		t.Fatalf("finalized %s, level %q", s, lvl())
	}
	refuses(t, "nothing to settle", func() { Settle(cross(cur), id) })
	for _, c := range drawn {
		if got := bal(c) - before[c]; got != CheckFee {
			t.Errorf("checker paid %d", got)
		}
	}
	if got := bal(worker) - before[worker]; got != FilingBond-int64(Checkers)*CheckFee-FundFee {
		t.Errorf("worker got back %d", got)
	}
	if r := RecordOf(worker); r.Passed != 1 {
		t.Errorf("worker's record %+v", r)
	}
	// alice's ticket (0) comes back after unbonding.
	testing.SetRealm(u(alice))
	Unstake(cross(cur), 0)
	refuses(t, "still unbonding", func() { Withdraw(cross(cur), 0) })
	testing.SkipHeights(UnbondBlocks)
	testing.SetRealm(u(bob))
	refuses(t, "not your ticket", func() { Withdraw(cross(cur), 0) })
	a := bal(alice)
	testing.SetRealm(u(alice))
	Withdraw(cross(cur), 0)
	if bal(alice)-a != MinTicket {
		t.Errorf("alice got back %d", bal(alice)-a)
	}
	refuses(t, "already withdrawn", func() { Withdraw(cross(cur), 0) })
	if Burned() != 0 {
		t.Errorf("burned %d on the honest path", Burned())
	}
}

// A drawn checker who never commits is fined and replaced from a later
// round (no transcript is open yet); the honest checkers and the worker
// lose nothing.
func TestLazyChecker(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol, dave} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	ids := map[address]int{alice: 0, bob: 1, carol: 2, dave: 3}
	testing.SkipHeights(MinTicketAge)
	before := balances(worker, alice, bob, carol, dave)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	lazy := drawn[0]
	for _, c := range drawn[1:] {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", ok, salt(c)))
	}
	testing.SetRealm(u(anyone))
	refuses(t, "still waiting for commitments", func() { Settle(cross(cur), id) })
	testing.SkipHeights(CheckWindow + 1)
	testing.SetRealm(u(lazy))
	refuses(t, "not taking checks", func() { CommitCheck(cross(cur), id, Commitment(lazy, "check", ok, salt(lazy))) })
	aim(1002)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Revealed {
		t.Fatalf("after the window: %s", s)
	}
	if got := stakeOf(ids[lazy]); got != MinTicket-NoShowFine {
		t.Errorf("the lazy checker kept %d", got)
	}
	drawn2 := draw(t, cur, id, 1002, sig1002)
	if roundsWait() {
		t.Error("after the redraw's draw a round still holds the tree") // fixRound let go of the first
	}
	var fresh address
	for _, c := range drawn2 {
		if c == lazy {
			t.Fatal("the lazy checker was drawn again")
		}
		if c != drawn[1] && c != drawn[2] {
			fresh = c
		}
	}
	testing.SetRealm(u(fresh))
	CommitCheck(cross(cur), id, Commitment(fresh, "check", ok, salt(fresh)))
	for _, c := range append([]address{worker}, drawn2...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, ok, salt(c))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	if s := finalize(t, cur, id); s != Tested {
		t.Fatalf("finalized %s", s)
	}
	for _, c := range drawn2 {
		if got := bal(c) - before[c]; got != CheckFee || stakeOf(ids[c]) != MinTicket {
			t.Errorf("an honest checker: paid %d, stake %d", got, stakeOf(ids[c]))
		}
	}
	if bal(lazy) != before[lazy] || RecordOf(lazy).Silent != 1 {
		t.Errorf("the lazy checker: paid %d, record %+v", bal(lazy)-before[lazy], RecordOf(lazy))
	}
	if got := bal(worker) - before[worker]; got != FilingBond-int64(Checkers)*CheckFee-FundFee {
		t.Errorf("worker got back %d", got)
	}
	if Burned() != 0 || FundBalance() != FundFee+NoShowFine { // silence pays the fund (round 11, minor 3)
		t.Errorf("burned %d, fund %d", Burned(), FundBalance())
	}
}

// A checker silent once the transcripts are open is fined, and the filing
// settles with those who answered: no new checker is drawn who could copy
// the open transcripts (round 9, minor 9).
func TestSilentAfterReveals(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol, dave} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	before := balances(worker, alice, bob, carol, dave)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", ok, salt(c)))
	}
	for _, c := range []address{worker, drawn[0], drawn[1]} {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, ok, salt(c))
	}
	testing.SkipHeights(RevealWindow + 1)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Agreed {
		t.Fatalf("with one silent after the reveals: %s", s)
	}
	if _, _, d := State(id); len(d) != 2 {
		t.Fatalf("checkers now %v", d)
	}
	finalize(t, cur, id)
	if bal(drawn[2]) != before[drawn[2]] || bal(drawn[0])-before[drawn[0]] != CheckFee {
		t.Errorf("paid the silent one %d, an answering one %d", bal(drawn[2])-before[drawn[2]], bal(drawn[0])-before[drawn[0]])
	}
	if got := bal(worker) - before[worker]; got != FilingBond-2*CheckFee-FundFee {
		t.Errorf("worker got back %d", got)
	}
}

// A drawn checker who lies starts a dispute (a rerun first): nothing is
// tested, nobody is paid, and no honest bond or stake is taken. The bond
// and the drawn tickets stay held; an undrawn ticket can leave.
func TestLiar(cur realm, t *testing.T) {
	reset()
	owners := []address{alice, bob, carol, dave}
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	before := balances(worker, alice, bob, carol, dave)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	says := map[address]string{drawn[0]: lie}
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", or(says[c], ok), salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, or(says[c], ok), salt(c))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Rerun || lvl() != "" {
		t.Fatalf("with a liar: %s", s)
	}
	for _, a := range append([]address{worker}, owners...) {
		if bal(a) != before[a] {
			t.Errorf("%s was paid %d before the last word", a, bal(a)-before[a])
		}
	}
	for tid, c := range owners {
		if stakeOf(tid) != MinTicket {
			t.Errorf("%s's stake is %d", c, stakeOf(tid))
		}
		testing.SetRealm(u(c))
		Unstake(cross(cur), tid)
	}
	testing.SkipHeights(UnbondBlocks)
	left := 0
	for tid, c := range owners {
		testing.SetRealm(u(c))
		if c == drawn[0] || c == drawn[1] || c == drawn[2] {
			refuses(t, "drawn into a check that hasn't settled", func() { Withdraw(cross(cur), tid) })
			continue
		}
		Withdraw(cross(cur), tid)
		left++
	}
	if left != 1 || Burned() != 0 {
		t.Errorf("%d undrawn left, burned %d", left, Burned())
	}
}

// A liar and a silent checker together: the open transcripts already
// differ, so the dispute begins without anyone new, and the silent one is
// fined; no honest bond or stake is taken.
func TestLiarAndSilent(cur realm, t *testing.T) {
	reset()
	owners := []address{alice, bob, carol, dave}
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	before := balances(worker, alice, bob, carol, dave)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	says := map[address]string{drawn[0]: lie}
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", or(says[c], ok), salt(c)))
	}
	for _, c := range []address{worker, drawn[0], drawn[2]} { // drawn[1] stays silent
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, or(says[c], ok), salt(c))
	}
	testing.SkipHeights(RevealWindow + 1)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Rerun {
		t.Fatalf("settled %s", s)
	}
	for tid, c := range owners {
		want := MinTicket
		if c == drawn[1] {
			want -= NoShowFine
		}
		if stakeOf(tid) != want || bal(c) != before[c] {
			t.Errorf("%s: stake %d, paid %d", c, stakeOf(tid), bal(c)-before[c])
		}
	}
	if bal(worker) != before[worker] || Burned() != 0 || FundBalance() != NoShowFine {
		t.Errorf("worker paid %d, burned %d, fund %d", bal(worker)-before[worker], Burned(), FundBalance())
	}
}

// A worker who goes silent after the draw loses its bond: the checkers who
// answered are paid from it, and the rest is locked for good.
func TestSilentWorker(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol, dave} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	before := balances(worker, alice, bob, carol, dave)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", ok, salt(c)))
	}
	for _, c := range drawn {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, ok, salt(c))
	}
	testing.SetRealm(u(anyone))
	refuses(t, "still waiting for reveals", func() { Settle(cross(cur), id) })
	testing.SkipHeights(RevealWindow + 1)
	testing.SetRealm(u(worker))
	refuses(t, "the reveal window has passed", func() { RevealCheck(cross(cur), id, ok, "t") })
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Forfeited {
		t.Fatalf("settled %s", s)
	}
	for _, c := range drawn {
		if got := bal(c) - before[c]; got != CheckFee {
			t.Errorf("checker paid %d", got)
		}
	}
	if bal(worker) != before[worker] || Burned() != FilingBond-int64(Checkers)*CheckFee || RecordOf(worker).Forfeited != 1 {
		t.Errorf("worker got %d, burned %d", bal(worker)-before[worker], Burned())
	}
}

// A copier who submits another's commitment first can't reveal it, and
// loses its bond; so does a flood of filings never revealed, and a reveal
// after its window. The worker's filing goes on.
func TestCopierAndFlood(cur realm, t *testing.T) {
	reset()
	tr := Commitment(worker, "transcript", ok, "t")
	commit := filingCommit(guardText, tr)
	testing.SetRealm(u(eve))
	send(FilingBond)
	copied := Commit(cross(cur), commit) // eve saw it in the mempool
	testing.SetRealm(u(worker))
	send(FilingBond)
	id := Commit(cross(cur), commit)
	testing.SetRealm(u(eve))
	for i := 0; i < 5; i++ {
		send(FilingBond)
		Commit(cross(cur), Commitment(eve, "guard", "junk", "s"))
	}
	send(0)
	refuses(t, "nothing to forfeit", func() { Forfeit(cross(cur), copied) })
	refuses(t, "that isn't what was committed", func() { Reveal(cross(cur), copied, guardText, sys, tr, "s") })
	refuses(t, "only the filer reveals", func() { Reveal(cross(cur), id, guardText, sys, tr, "s") })
	testing.SetRealm(u(worker))
	big := strings.Repeat("x", MaxGuard+1)
	send(FilingBond)
	bigID := Commit(cross(cur), filingCommit(big, tr))
	send(0)
	refuses(t, "a guard is at most", func() { Reveal(cross(cur), bigID, big, sys, tr, "s") })
	refuses(t, "that isn't what was committed", func() { Reveal(cross(cur), id, guardText+" ", sys, tr, "s") })
	refuses(t, "that isn't what was committed", func() { Reveal(cross(cur), id, guardText, "debian 12", tr, "s") })
	refuses(t, "a system is its os-release ID and VERSION_ID", func() { Reveal(cross(cur), id, guardText, "Ubuntu", tr, "s") })
	Reveal(cross(cur), id, guardText, sys, tr, "s")
	testing.SkipHeights(RevealWindow + 1)
	testing.SetRealm(u(eve))
	refuses(t, "the reveal window has passed", func() { Reveal(cross(cur), copied, guardText, sys, tr, "s") })
	for f := 0; f < nFilings; f++ {
		if f == id {
			refuses(t, "nothing to forfeit", func() { Forfeit(cross(cur), f) })
			continue
		}
		Forfeit(cross(cur), f)
	}
	if Burned() != 7*FilingBond || RecordOf(eve).Forfeited != 6 || RecordOf(worker).Forfeited != 1 {
		t.Errorf("burned %d, eve's record %+v", Burned(), RecordOf(eve))
	}
	if st, _, _ := State(id); st != Revealed {
		t.Errorf("the worker's filing is %s", st)
	}
}

// A ticket staked less than MinTicketAge before a filing, even by one
// block, can't be drawn into it, nor one staked after it, nor one unstaked
// before its round was fixed. A draw that finds too few owners abandons the
// filing at once: the bond goes back, less FundFee (round 9, minor 10;
// round 11, minor 6).
func TestYoungTickets(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(1)
	testing.SetRealm(u(dave))
	stakeOne(t, cur) // one block too young for the filing below
	testing.SkipHeights(MinTicketAge - 1)
	testing.SetRealm(u(carol))
	Unstake(cross(cur), 2) // leaving before the round is fixed: never drawn
	before := bal(worker)
	tc := Commitment(worker, "transcript", ok, "t")
	testing.SetRealm(u(worker))
	send(FilingBond)
	id := Commit(cross(cur), filingCommit(guardText, tc))
	send(0)
	for _, w := range []address{eve, anyone} { // staked for the attack, after the filing
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	aim(1001)
	testing.SetRealm(u(worker))
	Reveal(cross(cur), id, guardText, sys, tc, "s")
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1001, sig1001)
	if s := Draw(cross(cur), id); s != Abandoned {
		t.Fatalf("a draw with too few owners left the filing %s", s)
	}
	if _, _, drawn := State(id); len(drawn) != 0 || roundsWait() {
		t.Errorf("the abandoned filing drew %v; a round still waits: %v", drawn, roundsWait())
	}
	if got := bal(worker) - before; got != FilingBond-FundFee || FundBalance() != FundFee {
		t.Errorf("worker got back %d, fund %d", got, FundBalance())
	}
	refuses(t, "not waiting for a draw", func() { Abandon(cross(cur), id) })
}

// A filing nobody draws by its deadline, though it could have been drawn,
// loses its bond to the fund when abandoned: letting a disliked draw lapse
// and filing again costs the bond (round 11, minor 6). Checkers kept from
// an earlier draw are paid first.
func TestLapsedDrawLosesBond(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol, dave} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	before := bal(worker)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	refuses(t, "it can still be drawn", func() { Abandon(cross(cur), id) })
	testing.SkipHeights(DrawDeadline + 1)
	refuses(t, "the draw's deadline has passed", func() { Draw(cross(cur), id) })
	if roundsWait() {
		t.Error("a round past its deadline still holds the tree")
	}
	Abandon(cross(cur), id)
	if st, _, _ := State(id); st != Abandoned || waits.Size() != 0 {
		t.Fatalf("abandoned: %s, %d rounds kept", st, waits.Size())
	}
	if got := bal(worker) - before; got != 0 || FundBalance() != FilingBond {
		t.Errorf("the filer got back %d of its bond; fund %d", got, FundBalance())
	}
}

// Every checker commits and none opens: once the window passes each is
// fined, and with nobody left who checked it the filing is abandoned, the
// bond back less FundFee. The worker's own transcript never tests a guard.
func TestNobodyAnswers(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol, dave} {
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
		CommitCheck(cross(cur), id, Commitment(c, "check", ok, salt(c)))
	}
	testing.SetRealm(u(worker))
	RevealCheck(cross(cur), id, ok, salt(worker))
	testing.SkipHeights(RevealWindow + 1)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Abandoned || lvl() != "" {
		t.Fatalf("checked by nobody: %s", s)
	}
	if got := bal(worker) - before; got != FilingBond-FundFee || Burned() != 0 || FundBalance() != FundFee+3*NoShowFine {
		t.Errorf("worker got back %d, burned %d, fund %d", got, Burned(), FundBalance())
	}
}

// Every transcript agrees the guard fails the rig: no level, the checkers
// are paid, the rest of the bond goes back; a transcript that isn't a hash
// and a verdict is refused.
func TestEveryoneSaysItFails(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol, dave} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	before := balances(worker, alice, bob, carol, dave)
	testing.SetRealm(u(worker))
	id := file(t, cur, fails, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", fails, salt(c)))
	}
	testing.SetRealm(u(drawn[0]))
	refuses(t, "a transcript is its 64-hex hash and pass or fail", func() { RevealCheck(cross(cur), id, "it passed", salt(drawn[0])) })
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, fails, salt(c))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	testing.SkipHeights(ObjectionWindow + 1)
	testing.SetRealm(u(eve))
	send(ObjectionBond)
	refuses(t, "no agreement to object to", func() { Object(cross(cur), id, ok) })
	send(0)
	testing.SetRealm(u(anyone))
	if s := Finalize(cross(cur), id); s != Failed || lvl() != "" {
		t.Fatalf("settled %s, level %q", s, lvl())
	}
	for _, c := range drawn {
		if got := bal(c) - before[c]; got != CheckFee {
			t.Errorf("checker paid %d", got)
		}
	}
	if got := bal(worker) - before[worker]; got != FilingBond-int64(Checkers)*CheckFee-FundFee || RecordOf(worker).Failed != 1 {
		t.Errorf("worker got back %d, record %+v", got, RecordOf(worker))
	}
}

// An owner fined for silence on a filing is never drawn into it again:
// with only the three owners there were, the redraw finds nobody.
func TestSilentOwnerNotRedrawn(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	for _, c := range drawn[1:] {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", ok, salt(c)))
	}
	testing.SkipHeights(CheckWindow + 1)
	aim(1002)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Revealed {
		t.Fatalf("after the window: %s", s)
	}
	SubmitBeacon(cross(cur), 1002, sig1002)
	if s := Draw(cross(cur), id); s != Abandoned { // only the silent owner is left to draw
		t.Fatalf("the redraw: %s", s)
	}
}

// The draw takes its pool as it was when the round was fixed: unstaking
// every ticket but the three first drawn, after the reveal, changes nothing
// (round 9, new major 1).
func TestDrawFixedPool(cur realm, t *testing.T) {
	owners := []address{alice, bob, carol, dave, eve, anyone}
	var first []address
	for pass := 0; pass < 2; pass++ {
		reset()
		for _, w := range owners {
			testing.SetRealm(u(w))
			stakeOne(t, cur)
		}
		testing.SkipHeights(MinTicketAge)
		testing.SetRealm(u(worker))
		id := file(t, cur, ok, 1001)
		if pass == 1 {
			for tid, w := range owners {
				if w != first[0] && w != first[1] && w != first[2] {
					testing.SetRealm(u(w))
					Unstake(cross(cur), tid)
				}
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
				t.Fatalf("leaving after the reveal changed the draw: %v, then %v", first, drawn)
			}
		}
	}
}

// Many tickets: the draw picks through the stake tree, never walking every
// ticket, and finds distinct owners among a thousand.
func TestManyTickets(cur realm, t *testing.T) {
	reset()
	for i := 0; i < 1000; i++ {
		testing.SetRealm(u(testutils.TestAddress("t" + ufmt.Sprintf("%d", i))))
		stakeOne(t, cur)
	}
	if LiveStake() != 1000*MinTicket {
		t.Fatalf("live stake %d", LiveStake())
	}
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	if drawn[0] == drawn[1] || drawn[1] == drawn[2] || drawn[0] == drawn[2] {
		t.Fatalf("drew %v", drawn)
	}
}

// A passing guard decided while the live stake is under the floor is
// tested, but no level is written for light clients (round 9, new major 7);
// stake that is leaving doesn't count.
func TestFloor(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol, dave, eve, anyone} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	LevelFloor = 5 * MinTicket
	// Two of the six leave: stake that is leaving, and can't be drawn,
	// doesn't count toward the floor (round 10, minor 5).
	testing.SetRealm(u(eve))
	Unstake(cross(cur), 4)
	testing.SetRealm(u(anyone))
	Unstake(cross(cur), 5)
	if LiveStake() != 4*MinTicket {
		t.Fatalf("live stake %d", LiveStake())
	}
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
	if s := finalize(t, cur, id); s != Tested || lvl() != "" {
		t.Fatalf("under the floor: %s, level %q", s, lvl())
	}
}

// Withdrawing tickets that started leaving while an earlier round waited,
// after a later round is fixed and before its draw, changes no pick: their
// weight stays where draws see it, marked withdrawn, until no round waits;
// then the draw's compaction takes it out (round 10, new major 1; round 11,
// new major 2).
func TestWithdrawMovesNoDraw(cur realm, t *testing.T) {
	owners := []address{alice, bob, carol, dave, eve, anyone}
	spares := []address{testutils.TestAddress("s1"), testutils.TestAddress("s2"), testutils.TestAddress("s3")}
	var first []address
	for pass := 0; pass < 2; pass++ {
		reset()
		for _, w := range owners {
			testing.SetRealm(u(w))
			stakeOne(t, cur)
		}
		for i, w := range spares {
			testing.SetRealm(u(w))
			send(MinTicket + int64(i+1))
			StakeTicket(cross(cur))
			send(0)
		}
		testing.SkipHeights(MinTicketAge)
		testing.SetRealm(u(worker))
		file(t, cur, ok, 1001) // an earlier filing, whose round waits while the spares leave
		for i, w := range spares {
			testing.SetRealm(u(w))
			Unstake(cross(cur), len(owners)+i)
		}
		if pending.Size() != 3 {
			t.Fatalf("%d leaving while a round waits are pending", pending.Size())
		}
		testing.SkipHeights(UnbondBlocks) // the earlier round lapses; nobody compacts
		testing.SetRealm(u(worker))
		id := file(t, cur, ok, 1001)
		if pass == 1 {
			for i, w := range spares { // after the round is fixed, before its draw
				testing.SetRealm(u(w))
				Withdraw(cross(cur), len(owners)+i)
			}
			sum, left, gone, parked := below(nTickets)
			if sum != 9*MinTicket+6 || left != 3*MinTicket+6 || gone != 3*MinTicket+6 || parked != 0 || pending.Size() != 3 {
				t.Fatalf("while the round waits the tree holds %d, %d leaving, %d withdrawn, %d parked; %d pending", sum, left, gone, parked, pending.Size())
			}
			testing.SetRealm(u(anyone))
			if n := Compact(cross(cur)); n != 3 {
				t.Fatalf("Compact took withdrawn weight out while a round waited: %d left", n)
			}
		}
		testing.SetRealm(u(anyone))
		drawn := draw(t, cur, id, 1001, sig1001)
		if pass == 0 {
			first = drawn
			continue
		}
		if sum, left, gone, parked := below(nTickets); sum != 6*MinTicket || left != 0 || gone != 0 || parked != 0 || pending.Size() != 0 {
			t.Fatalf("after the draw the tree holds %d, %d leaving, %d withdrawn, %d parked; %d pending", sum, left, gone, parked, pending.Size())
		}
		for i := range drawn {
			if drawn[i] != first[i] {
				t.Fatalf("withdrawing after the round was fixed moved the draw: %v, then %v", first, drawn)
			}
		}
	}
}

// A ticket's vote charges are settled a bounded number at a time, so no
// call walks every vote ever opened: with more than MaxSettle to settle,
// Withdraw asks for SettleVotes first (round 10, minor 6).
func TestSettleVotesInSteps(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes, MaxSettle = 0, nil, 1
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
	testing.SetRealm(u(alice))
	Unstake(cross(cur), 0)
	testing.SkipHeights(UnbondBlocks)
	refuses(t, "more than 1 votes to settle; call SettleVotes first", func() { Withdraw(cross(cur), 0) })
	if left := SettleVotes(cross(cur), 0, 0); left != 1 {
		t.Fatalf("%d votes left to settle", left)
	}
	a := bal(alice)
	Withdraw(cross(cur), 0)
	abstained := MinTicket * AbstainShare / 100
	if got := bal(alice) - a; got != MinTicket-abstained-(MinTicket-abstained)*AbstainShare/100 {
		t.Errorf("alice withdrew %d after abstaining twice", got)
	}
}
