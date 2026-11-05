package guards

import (
	"strings"
	"testing"

	"gno.land/p/nt/testutils/v0"
)

// drand evmnet rounds 1003 and 1004, as api.drand.sh serves them.
const (
	sig1003 = "2818c225b90518f3ab0ace0fe7b7402533974b08cd10bb4dbf3b385fa6bbf034121123cc310a4644ed3390de0e5b945a07aca893051ee168d19496a65863486c"
	sig1004 = "0067218f842f2177a4a1c19c1f8a1bc98a8aacd0f9f465e41b2ff955c43fcee10fbfc6303b23143c5956406ba4d2a337f052701a88562df444032542101d4566"
)

// junk is a transcript nobody's run gives: a decoy's objection.
const junk = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc pass"

// owners are n staking addresses, o1 to on.
func ownersN(n int) []address {
	var out []address
	for i := 1; i <= n; i++ {
		out = append(out, testutils.TestAddress("o"+itoa(i)))
	}
	return out
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

func stakeOf2(a address, owners []address) int64 {
	for tid, o := range owners {
		if o == a {
			return stakeOf(tid)
		}
	}
	return -1
}

func ticketIndex(a address, owners []address) int {
	for i, o := range owners {
		if o == a {
			return i
		}
	}
	return -1
}

// seatMap is how many seats each member of a filing's current panel holds.
func seatMap(id int, members []address) map[address]int {
	m := map[address]int{}
	for _, p := range members {
		m[p] = SeatsOf(id, p)
	}
	return m
}

// split gives each member of a panel one of two transcripts, so that the
// seats are as even as they can be; it says whether neither side then holds
// more than two thirds of size.
func split(members []address, seats map[address]int, size int, a, b string) (map[address]string, bool) {
	order := append([]address{}, members...)
	for i := range order { // most seats first
		for j := i + 1; j < len(order); j++ {
			if seats[order[j]] > seats[order[i]] {
				order[i], order[j] = order[j], order[i]
			}
		}
	}
	says, na, nb := map[address]string{}, 0, 0
	for _, p := range order {
		if na <= nb {
			says[p], na = a, na+seats[p]
		} else {
			says[p], nb = b, nb+seats[p]
		}
	}
	return says, na*3 <= size*2 && nb*3 <= size*2
}

func sumSeats(seats map[address]int) int {
	n := 0
	for _, s := range seats {
		n += s
	}
	return n
}

// The worker's run and a checker's differ once: the rerun agrees, and the
// filing goes on as an agreement. At the last word each pays RerunFee to the
// fund for the rerun it caused, the worker from its bond (round 10, minor
// 4); nobody else loses anything.
func TestFlakyRerun(cur realm, t *testing.T) {
	reset()
	owners := ownersN(4)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	before := balances(append([]address{worker}, owners...)...)
	testing.SetRealm(u(worker))
	id := file(t, cur, lie, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	says := map[address]string{worker: lie, drawn[0]: lie}
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", or(says[c], ok), salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, or(says[c], ok), salt(c))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Rerun {
		t.Fatalf("after a difference: %s", s)
	}
	parties := append([]address{worker}, drawn...)
	for _, c := range parties {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, kind(c), ok, salt(c)))
	}
	for _, c := range parties {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, ok, salt(c))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Agreed {
		t.Fatalf("after the rerun agreed: %s", s)
	}
	if s := finalize(t, cur, id); s != Tested || lvl() != Tested {
		t.Fatalf("finalized %s", s)
	}
	for _, c := range drawn {
		want := MinTicket
		if c == drawn[0] {
			want -= RerunFee
		}
		if bal(c)-before[c] != CheckFee || stakeOf2(c, owners) != want {
			t.Errorf("%s: paid %d, stake %d, want %d", c, bal(c)-before[c], stakeOf2(c, owners), want)
		}
	}
	if bal(worker)-before[worker] != FilingBond-int64(Checkers)*CheckFee-FundFee-RerunFee || FundBalance() != FundFee+2*RerunFee || Burned() != 0 {
		t.Errorf("worker got %d, fund %d, burned %d", bal(worker)-before[worker], FundBalance(), Burned())
	}
}

// A checker lies through both reruns. A panel drawn by stake from a later
// round, from every eligible ticket, parties' too (round 11, new major 1),
// gives its word once every member has revealed; nobody appeals, and at the
// last word the liar loses Slash: first the panel's fees go back to the
// fund, then half of the rest to the worker and the honest checkers. Every
// seat that said it is paid.
func TestPanelSlashesALiar(cur realm, t *testing.T) {
	reset()
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(anyone))
	send(1_000_000)
	Fund(cross(cur))
	send(0)
	testing.SkipHeights(MinTicketAge)
	before := balances(append([]address{worker}, owners...)...)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	liar := drawn[0]
	says := map[address]string{liar: lie}
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", or(says[c], ok), salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, or(says[c], ok), salt(c))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	parties := append([]address{worker}, drawn...)
	for run := 1; run <= Reruns; run++ {
		for _, c := range parties {
			testing.SetRealm(u(c))
			CommitCheck(cross(cur), id, Commitment(c, kind(c), or(says[c], ok), salt(c)))
		}
		for _, c := range parties {
			testing.SetRealm(u(c))
			RevealCheck(cross(cur), id, or(says[c], ok), salt(c))
		}
		aim(1003)
		testing.SetRealm(u(anyone))
		s := Settle(cross(cur), id)
		if (run < Reruns && s != Rerun) || (run == Reruns && s != Panel) {
			t.Fatalf("after rerun %d: %s", run, s)
		}
	}
	testing.SetRealm(u(anyone))
	refuses(t, "submit beacon round 1003 first", func() { DrawPanel(cross(cur), id) })
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	panel, size := PanelOf(id)
	seats := seatMap(id, panel)
	if size != PanelSizes[0] || sumSeats(seats) != size || len(panel) < 2 {
		t.Fatalf("panel %v, seats %v, of %d", panel, seats, size)
	}
	for _, p := range panel {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", ok, salt(p)))
	}
	last := panel[len(panel)-1]
	for _, p := range panel[:len(panel)-1] {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, ok, salt(p))
	}
	// Every member but one has revealed, perhaps more than two thirds of the
	// seats, but the last is still inside its window: no word yet (round 9,
	// new major 5).
	testing.SetRealm(u(anyone))
	refuses(t, "still waiting for reveals", func() { Settle(cross(cur), id) })
	testing.SetRealm(u(last))
	RevealCheck(cross(cur), id, ok, salt(last))
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Appealable {
		t.Fatalf("the panel's word: %s", s)
	}
	if w, _ := Word(id); w != ok || bal(worker) != before[worker] {
		t.Fatalf("word %q; paid before the last word: %d", w, bal(worker)-before[worker])
	}
	refuses(t, "the appeal window is open", func() { Settle(cross(cur), id) })
	testing.SkipHeights(AppealWindow + 1)
	testing.SetRealm(u(liar))
	send(AppealCost(id))
	refuses(t, "nothing to appeal", func() { Appeal(cross(cur), id) })
	send(0)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Tested || lvl() != Tested {
		t.Fatalf("the last word: %s", s)
	}
	taken := Slash
	refill := least(taken, int64(size)*PanelFee)
	rest := taken - refill
	each := rest * ShowShare / 100 / 3 // the worker and the two honest checkers showed it
	want := map[address]int64{worker: FilingBond - 2*CheckFee - FundFee + each}
	for _, c := range drawn[1:] {
		want[c] += CheckFee + each
	}
	for _, p := range panel { // every seat said it, a party's too
		want[p] += PanelFee * int64(seats[p])
	}
	for _, a := range append([]address{worker}, owners...) {
		if got := bal(a) - before[a]; got != want[a] {
			t.Errorf("%s (%d seats): paid %d, want %d", a, seats[a], got, want[a])
		}
		if a != worker && a != liar && stakeOf2(a, owners) != MinTicket {
			t.Errorf("%s lost stake: %d", a, stakeOf2(a, owners))
		}
	}
	if stakeOf2(liar, owners) != MinTicket-Slash || RecordOf(liar).Faults != 1 {
		t.Errorf("the liar: stake %d, record %+v", stakeOf2(liar, owners), RecordOf(liar))
	}
	if FundBalance() != 1_000_000-int64(size)*PanelFee+FundFee+refill || Burned() != rest-3*each {
		t.Errorf("fund %d, burned %d", FundBalance(), Burned())
	}
	for _, c := range append(drawn, panel...) { // every ticket is free again
		if _, _, open, _ := TicketOf(ticketIndex(c, owners)); open != 0 {
			t.Errorf("%s's ticket still held", c)
		}
	}
}

// All three checkers lie, and the whole first panel says what they said:
// its word goes against the honest worker. The worker appeals; the next
// panel, honest (a lying checker drawn to it says what it says), gives the
// last word. No honest bond or stake is taken;
// every lying checker loses Slash, and every lying seat too; the fund is
// paid back first, then half of the rest goes to the worker, who showed
// it, and its appeal bond comes back (round 9, new major 3).
func TestAppealOverturnsAPanel(cur realm, t *testing.T) {
	reset()
	Reruns = 0
	owners := ownersN(16)
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
		RevealCheck(cross(cur), id, or(map[address]string{worker: ok}[c], lie), salt(c))
	}
	aim(1003)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Panel {
		t.Fatalf("without reruns: %s", s)
	}
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	first, size1 := PanelOf(id)
	seats1 := seatMap(id, first)
	for _, p := range first {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", lie, salt(p)))
	}
	for _, p := range first {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, lie, salt(p))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Appealable {
		t.Fatalf("the first panel's word: %s", s)
	}
	aim(1004)
	testing.SetRealm(u(worker))
	bond := AppealCost(id)
	send(bond - 1)
	refuses(t, "send at least", func() { Appeal(cross(cur), id) })
	send(bond)
	if s := Appeal(cross(cur), id); s != Panel {
		t.Fatalf("after the appeal: %s", s)
	}
	send(0)
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1004, sig1004)
	DrawPanel(cross(cur), id)
	second, size2 := PanelOf(id)
	seats2 := seatMap(id, second)
	if size2 != PanelSizes[1] || sumSeats(seats2) != size2 {
		t.Fatalf("the second panel %v of %d", seats2, size2)
	}
	for _, p := range second {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", ok, salt(p)))
	}
	for _, p := range second {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, ok, salt(p))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	testing.SkipHeights(AppealWindow + 1)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Tested {
		t.Fatalf("the last word: %s", s)
	}
	taken := int64(3+size1) * Slash // three checkers and every seat of the first panel
	refill := least(taken, int64(size2)*PanelFee)
	share := (taken - refill) * ShowShare / 100 // all to the worker
	if got := bal(worker) - before[worker]; got != FilingBond-FundFee+share+bond {
		t.Errorf("the honest worker got %d, want %d", got, FilingBond-FundFee+share+bond)
	}
	for _, c := range owners {
		want, paid := MinTicket-Slash*int64(seats1[c]), PanelFee*int64(seats2[c])
		for _, d := range drawn {
			if c == d {
				want -= Slash
			}
		}
		if got := stakeOf2(c, owners); got != want || bal(c)-before[c] != paid {
			t.Errorf("%s: stake %d, want %d; paid %d, want %d", c, got, want, bal(c)-before[c], paid)
		}
	}
	if FundBalance() != 10_000_000-int64(size2)*PanelFee+FundFee+refill || Burned() != taken-refill-share {
		t.Errorf("fund %d, burned %d", FundBalance(), Burned())
	}
	page := Render("filing/" + itoa(id))
	for _, want := range []string{"- Appealed by " + link(worker) + " against `" + lie + "`", "## Panel 1 (of 4 seats)", "## Panel 2 (of 7 seats)", "- State: tested", "- System: " + sys} {
		if !strings.Contains(page, want) {
			t.Errorf("the filing's page lacks %q:\n%s", want, page)
		}
	}
}

// A worker files a guard that passes by its account and fails by every
// checker's: a panel says it fails, nobody appeals. The worker loses its
// whole bond: the panel's fees go back to the fund, and half the rest to
// the checkers who showed it; the guard gets no level.
func TestPanelSlashesALyingWorker(cur realm, t *testing.T) {
	reset()
	Reruns = 0
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(anyone))
	send(1_000_000)
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
		CommitCheck(cross(cur), id, Commitment(c, "check", fails, salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, or(map[address]string{worker: ok}[c], fails), salt(c))
	}
	aim(1003)
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	panel, size := PanelOf(id)
	for _, p := range panel {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", fails, salt(p)))
	}
	for _, p := range panel {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, fails, salt(p))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	testing.SkipHeights(AppealWindow + 1)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Failed || lvl() != "" {
		t.Fatalf("decided %s", s)
	}
	rest := FilingBond - least(FilingBond, int64(size)*PanelFee)
	each := rest * ShowShare / 100 / 3
	seats := seatMap(id, panel)
	for _, c := range drawn { // a checker drawn to the panel is paid for its seats too
		if bal(c)-before[c] != each+PanelFee*int64(seats[c]) || stakeOf2(c, owners) != MinTicket {
			t.Errorf("checker %s with %d seats: paid %d", c, seats[c], bal(c)-before[c])
		}
	}
	if bal(worker) != before[worker] || RecordOf(worker).Faults != 1 {
		t.Errorf("the worker: paid %d, record %+v", bal(worker)-before[worker], RecordOf(worker))
	}
}

// Disputes wait while the fund can't pay a panel, with no round fixed, so
// whoever tops the fund up can't pick a round already seen; anyone may fund
// it and ask again (round 11, minor 6). A round that goes stale is replaced
// by Settle, its fees still set aside, so a dispute is never stuck.
func TestFundWaits(cur realm, t *testing.T) {
	reset()
	Reruns = 0
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
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
	if s := Settle(cross(cur), id); s != PanelWait {
		t.Fatalf("without reruns and with an empty fund: %s", s)
	}
	if roundsWait() {
		t.Fatal("a round was fixed for a panel the fund can't pay")
	}
	refuses(t, "not waiting for a panel", func() { DrawPanel(cross(cur), id) })
	send(panelCost(0) - 1)
	Fund(cross(cur))
	send(0)
	if s := RequestPanel(cross(cur), id); s != PanelWait {
		t.Fatalf("one ugnot short: %s", s)
	}
	send(1)
	Fund(cross(cur))
	send(0)
	if s := RequestPanel(cross(cur), id); s != Panel || FundBalance() != 0 {
		t.Fatalf("funded: %s, fund %d", s, FundBalance())
	}
	if _, r, _ := State(id); r != 1003 {
		t.Fatalf("the panel's round is %d", r)
	}
	refuses(t, "not waiting for the fund", func() { RequestPanel(cross(cur), id) })
	refuses(t, "the panel can still be drawn", func() { Settle(cross(cur), id) })
	testing.SkipHeights(DrawDeadline + 1)
	refuses(t, "the panel's deadline has passed", func() { DrawPanel(cross(cur), id) })
	aim(1004)
	if s := Settle(cross(cur), id); s != Panel || FundBalance() != 0 {
		t.Fatalf("after the deadline: %s, fund %d", s, FundBalance())
	}
	if waits.Size() != 1 {
		t.Errorf("%d rounds kept waiting; the stale one should be let go", waits.Size())
	}
	if _, r, _ := State(id); r != 1004 {
		t.Fatalf("the new round is %d", r)
	}
	testing.SetRealm(u(owners[7]))
	Unstake(cross(cur), 7) // while the panel's round waits: pending until it is drawn
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1004, sig1004)
	DrawPanel(cross(cur), id)
	if st, _, _ := State(id); st != Panelled || FundBalance() != 0 || roundsWait() {
		t.Fatalf("after the draw: %s, fund %d, a round waits: %v", st, FundBalance(), roundsWait())
	}
	if _, _, _, parked := below(nTickets); len(pending) != 0 || parked != MinTicket {
		t.Errorf("the panel's draw left %d pending, %d parked", len(pending), parked)
	}
}

// A panel whose seats split gives no word: a larger panel runs it. A
// member silent there loses Slash for each seat. At the last word the
// first panel's seats are judged by it as well, and nobody is paid before
// it.
func TestSplitPanelEscalates(cur realm, t *testing.T) {
	reset()
	Reruns = 0
	owners := ownersN(16)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(anyone))
	send(10_000_000)
	Fund(cross(cur))
	send(0)
	testing.SkipHeights(MinTicketAge)
	before := balances(owners...)
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
	first, size1 := PanelOf(id)
	seats1 := seatMap(id, first)
	says1, even := split(first, seats1, size1, ok, lie)
	if !even {
		t.Fatalf("the first panel's seats can't split: %v", seats1)
	}
	for _, p := range first {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", says1[p], salt(p)))
	}
	for _, p := range first {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, says1[p], salt(p))
	}
	aim(1004)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Panel {
		t.Fatalf("after a split: %s", s)
	}
	for _, p := range first {
		if bal(p) != before[p] {
			t.Errorf("first panelist %s paid %d before the last word", p, bal(p)-before[p])
		}
	}
	SubmitBeacon(cross(cur), 1004, sig1004)
	DrawPanel(cross(cur), id)
	second, size2 := PanelOf(id)
	seats2 := seatMap(id, second)
	if size2 != PanelSizes[1] || sumSeats(seats2) != size2 || len(second) < 2 {
		t.Fatalf("second panel %v of %d", seats2, size2)
	}
	silent := second[0] // the member with the fewest seats
	for _, p := range second {
		if seats2[p] < seats2[silent] {
			silent = p
		}
	}
	if (size2-seats2[silent])*3 <= size2*2 {
		t.Fatalf("without the silent member's %d seats, no word could pass: %v", seats2[silent], seats2)
	}
	for _, p := range second {
		if p != silent {
			testing.SetRealm(u(p))
			CommitCheck(cross(cur), id, Commitment(p, "check", ok, salt(p)))
		}
	}
	testing.SetRealm(u(anyone))
	refuses(t, "still waiting for commitments", func() { Settle(cross(cur), id) })
	testing.SkipHeights(CheckWindow + 1)
	testing.SetRealm(u(anyone))
	f0, b0 := FundBalance(), Burned()
	Settle(cross(cur), id)                                                 // the silent member's seats are out; the rest may reveal
	if FundBalance()-f0 != Slash*int64(seats2[silent]) || Burned() != b0 { // silence pays the fund (round 11, minor 3)
		t.Errorf("the silent member's slash: fund +%d, burned +%d", FundBalance()-f0, Burned()-b0)
	}
	for _, p := range second {
		if p != silent {
			testing.SetRealm(u(p))
			RevealCheck(cross(cur), id, ok, salt(p))
		}
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Appealable {
		t.Fatalf("the larger panel: %s", s)
	}
	testing.SkipHeights(AppealWindow + 1)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Tested {
		t.Fatalf("the last word: %s", s)
	}
	for _, c := range owners {
		want, paid := MinTicket, int64(0)
		for _, d := range drawn {
			if c == d {
				want -= Slash // a lying checker
			}
		}
		if says1[c] == lie {
			want -= Slash * int64(seats1[c])
		} else {
			paid += PanelFee * int64(seats1[c])
		}
		if c == silent {
			want -= Slash * int64(seats2[c])
		} else {
			paid += PanelFee * int64(seats2[c])
		}
		if got := stakeOf2(c, owners); got != want || bal(c)-before[c] != paid {
			t.Errorf("%s: stake %d, want %d; paid %d, want %d", c, got, want, bal(c)-before[c], paid)
		}
	}
	if RecordOf(silent).Silent != 1 {
		t.Errorf("the silent member's record: %+v", RecordOf(silent))
	}
}

// A checker silent in a rerun loses Slash and leaves the filing; those left
// agree, so the filing goes on as an agreement (round 9, minor 10).
func TestSilentInARerun(cur realm, t *testing.T) {
	reset()
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
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
	Settle(cross(cur), id)
	for _, c := range []address{worker, drawn[1], drawn[2]} { // drawn[0] stays silent
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, kind(c), ok, salt(c)))
	}
	testing.SkipHeights(CheckWindow + 1)
	testing.SetRealm(u(anyone))
	f0 := FundBalance()
	if s := Settle(cross(cur), id); s != Rerun {
		t.Fatalf("after a silence in the rerun's commitments: %s", s)
	}
	if FundBalance()-f0 != Slash || Burned() != 0 { // silence pays the fund (round 11, minor 3)
		t.Errorf("the silent checker's slash: fund +%d, burned %d", FundBalance()-f0, Burned())
	}
	for _, c := range []address{worker, drawn[1], drawn[2]} {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, ok, salt(c))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Agreed {
		t.Fatalf("those left agree: %s", s)
	}
	if stakeOf2(drawn[0], owners) != MinTicket-Slash || RecordOf(drawn[0]).Silent != 1 {
		t.Errorf("the silent checker: stake %d", stakeOf2(drawn[0], owners))
	}
}

// An agreement is objected to: the worker and every checker said the guard
// passes, and an objector says a correct run fails it. A panel gives the
// objector's word; nobody appeals. The agreement's parties lose their bond
// and stakes; the fund is paid back first, and the objector gets its bond
// back and half the rest; no level is ever written. A party can't object
// to its own filing (round 9, new major 7).
func TestObjection(cur realm, t *testing.T) {
	reset()
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(anyone))
	send(1_000_000)
	Fund(cross(cur))
	send(0)
	testing.SkipHeights(MinTicketAge)
	before := balances(append([]address{worker, eve}, owners...)...)
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
	testing.SetRealm(u(drawn[0]))
	send(ObjectionBond)
	refuses(t, "a party can't object", func() { Object(cross(cur), id, fails) })
	testing.SetRealm(u(eve))
	refuses(t, "an objection is another transcript", func() { Object(cross(cur), id, ok) })
	aim(1003)
	Object(cross(cur), id, fails)
	send(0)
	if st, _, _ := State(id); st != Panel {
		t.Fatalf("after the objection: %s", st)
	}
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	panel, size := PanelOf(id)
	for _, p := range panel {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", fails, salt(p)))
	}
	for _, p := range panel {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, fails, salt(p))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	testing.SkipHeights(AppealWindow + 1)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Failed || lvl() != "" {
		t.Fatalf("after the objection's panel: %s, level %q", s, lvl())
	}
	taken := FilingBond + 3*Slash
	rest := taken - least(taken, int64(size)*PanelFee)
	if got := bal(eve) - before[eve]; got != ObjectionBond+rest*ShowShare/100 {
		t.Errorf("the objector got %d", got)
	}
	for _, c := range drawn {
		if stakeOf2(c, owners) != MinTicket-Slash {
			t.Errorf("checker %s kept %d", c, stakeOf2(c, owners))
		}
	}
	if bal(worker) != before[worker] {
		t.Errorf("the worker got %d", bal(worker)-before[worker])
	}
	if page := Render("filing/" + itoa(id)); !strings.Contains(page, "- Objected to by "+link(eve)+": `"+fails+"`") {
		t.Errorf("the filing's page:\n%s", page)
	}
}

// A level written and then decided against is pulled, and the pull sticks:
// a later filing of the same guard decided passing writes no "tested" over
// it; a fixed guard comes back as a new version (round 9, new major 7;
// round 10, minor 5).
func TestPull(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol, dave} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	sigs := []string{sig1001, sig1002, sig1003}
	for pass, tr := range []string{ok, fails, ok} {
		testing.SetRealm(u(worker))
		id := file(t, cur, tr, uint64(1001+pass))
		testing.SetRealm(u(anyone))
		drawn := draw(t, cur, id, uint64(1001+pass), sigs[pass])
		for _, c := range drawn {
			testing.SetRealm(u(c))
			CommitCheck(cross(cur), id, Commitment(c, "check", tr, salt(c)))
		}
		for _, c := range append([]address{worker}, drawn...) {
			testing.SetRealm(u(c))
			RevealCheck(cross(cur), id, tr, salt(c))
		}
		testing.SetRealm(u(anyone))
		Settle(cross(cur), id)
		finalize(t, cur, id)
		if want := []string{Tested, Pulled, Pulled}[pass]; lvl() != want {
			t.Fatalf("after filing %d: level %q", pass, lvl())
		}
		if Level(GuardHash(guardText), "debian 12") != "" {
			t.Fatalf("a level on another system")
		}
		if pass == 2 && !strings.Contains(Render("filing/"+itoa(id)), "the pull stands") {
			t.Errorf("the third filing's page:\n%s", Render("filing/"+itoa(id)))
		}
	}
}

// A checker the panel went against appeals, and the next panel says the
// same: the appellant loses its bond with its Slash. The fund is paid back
// first, and half the rest goes to those who showed the last word (round 9,
// new major 3; round 10, new major 3).
func TestLosingAppeal(cur realm, t *testing.T) {
	reset()
	Reruns = 0
	owners := ownersN(16)
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
	liar := drawn[0]
	says := map[address]string{liar: lie}
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", or(says[c], ok), salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, or(says[c], ok), salt(c))
	}
	aim(1003)
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	first, size1 := PanelOf(id)
	seats1 := seatMap(id, first)
	for _, p := range first {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", ok, salt(p)))
	}
	for _, p := range first {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, ok, salt(p))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Appealable {
		t.Fatalf("the first panel: %s", s)
	}
	aim(1004)
	testing.SetRealm(u(liar))
	bond := AppealCost(id)
	send(bond)
	Appeal(cross(cur), id)
	send(0)
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1004, sig1004)
	DrawPanel(cross(cur), id)
	second, size2 := PanelOf(id)
	seats2 := seatMap(id, second)
	for _, p := range second { // drawn from every ticket, the appellant's too (round 11, new major 1)
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", ok, salt(p)))
	}
	for _, p := range second {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, ok, salt(p))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	testing.SkipHeights(AppealWindow + 1)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Tested {
		t.Fatalf("the last word: %s", s)
	}
	taken := Slash + bond
	cost := int64(size1+size2) * PanelFee
	refill := least(taken, cost)
	rest := taken - refill
	each := rest * ShowShare / 100 / 3 // the worker and the two honest checkers
	want := map[address]int64{worker: FilingBond - 2*CheckFee - FundFee + each}
	for _, c := range drawn[1:] {
		want[c] += CheckFee + each
	}
	for _, o := range owners { // every seat of both panels said the last word
		want[o] += PanelFee * int64(seats1[o]+seats2[o])
	}
	for _, a := range append([]address{worker}, owners...) {
		if got := bal(a) - before[a]; got != want[a] {
			t.Errorf("%s (seats %d and %d): got %d, want %d", a, seats1[a], seats2[a], got, want[a])
		}
	}
	if stakeOf2(liar, owners) != MinTicket-Slash || RecordOf(liar).Faults != 1 {
		t.Errorf("the appellant: stake %d, record %+v", stakeOf2(liar, owners), RecordOf(liar))
	}
	if FundBalance() != 10_000_000-cost+FundFee+refill || Burned() != rest-3*each {
		t.Errorf("fund %d, burned %d", FundBalance(), Burned())
	}
}

// An owner objects to an agreement, and the panel says the agreement was
// right: the objector loses its bond, which first pays the fund back, then
// half the rest goes to those who showed it. The objector, a party now, is
// never drawn onto the panel that judges it.
func TestFrivolousObjection(cur realm, t *testing.T) {
	reset()
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SetRealm(u(anyone))
	send(1_000_000)
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
		CommitCheck(cross(cur), id, Commitment(c, "check", ok, salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, ok, salt(c))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	var objector address
	for _, a := range owners {
		if a != drawn[0] && a != drawn[1] && a != drawn[2] {
			objector = a
			break
		}
	}
	aim(1003)
	testing.SetRealm(u(objector))
	send(ObjectionBond)
	Object(cross(cur), id, fails)
	send(0)
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	panel, size := PanelOf(id)
	seats := seatMap(id, panel)
	for _, p := range panel { // every ticket may sit, the objector's too (round 11, new major 1)
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
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Tested || lvl() != Tested {
		t.Fatalf("the last word: %s", s)
	}
	rest := ObjectionBond - least(ObjectionBond, int64(size)*PanelFee)
	each := rest * ShowShare / 100 / 4 // the worker and the three checkers
	want := map[address]int64{worker: FilingBond - 3*CheckFee - FundFee + each}
	for _, c := range drawn {
		want[c] += CheckFee + each
	}
	for _, p := range panel {
		want[p] += PanelFee * int64(seats[p])
	}
	for _, a := range append([]address{worker}, owners...) {
		if got := bal(a) - before[a]; got != want[a] {
			t.Errorf("%s (%d seats): got %d, want %d", a, seats[a], got, want[a])
		}
	}
	if RecordOf(objector).Faults != 1 {
		t.Errorf("the objector's record: %+v", RecordOf(objector))
	}
}

// Every checker stays silent in a rerun: each loses Slash and leaves, and
// the worker's transcript alone is no agreement; the dispute goes on.
func TestRerunAllSilent(cur realm, t *testing.T) {
	reset()
	owners := ownersN(8)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
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
	Settle(cross(cur), id)
	testing.SetRealm(u(worker))
	CommitCheck(cross(cur), id, Commitment(worker, "transcript", ok, salt(worker)))
	testing.SkipHeights(CheckWindow + 1)
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id) // the silent checkers are out
	testing.SetRealm(u(worker))
	RevealCheck(cross(cur), id, ok, salt(worker))
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Rerun {
		t.Fatalf("with the worker alone: %s", s)
	}
	for _, c := range drawn {
		if stakeOf2(c, owners) != MinTicket-Slash || RecordOf(c).Silent != 1 {
			t.Errorf("silent checker %s: stake %d", c, stakeOf2(c, owners))
		}
	}
}

// A decoy objection leaves no honest party to appeal, so anyone may: the
// liar's worker and all three checkers agree on a broken guard, a fresh
// address objects with a junk transcript, and a panel the liar filled says
// the liar's word, which goes against nobody but the decoy. An honest owner
// who isn't on the filing appeals; the next panel says the guard fails; the
// guard is never tested, every lying bond, stake and seat pays, and the
// appellant's bond comes back (round 10, new major 2).
func TestAnyoneAppeals(cur realm, t *testing.T) {
	reset()
	Reruns = 0
	owners := ownersN(16)
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
	id := file(t, cur, lie, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", lie, salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, lie, salt(c))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Agreed {
		t.Fatalf("the liar's agreement: %s", s)
	}
	decoy := testutils.TestAddress("decoy")
	aim(1003)
	testing.SetRealm(u(decoy))
	send(ObjectionBond)
	Object(cross(cur), id, junk)
	send(0)
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	first, _ := PanelOf(id)
	seats1 := seatMap(id, first)
	for _, p := range first { // the liar's seats, by luck or by addresses
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", lie, salt(p)))
	}
	for _, p := range first {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, lie, salt(p))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Appealable {
		t.Fatalf("the filled panel: %s", s)
	}
	var honest address // an owner not on the filing
	for _, a := range owners {
		if !party(get(id), a) && seats1[a] == 0 {
			honest = a
			break
		}
	}
	aim(1004)
	testing.SetRealm(u(honest))
	bond := AppealCost(id)
	send(bond)
	Appeal(cross(cur), id)
	send(0)
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1004, sig1004)
	DrawPanel(cross(cur), id)
	second, size2 := PanelOf(id)
	seats2 := seatMap(id, second) // the appellant's tickets may sit too (round 11, new major 1)
	for _, p := range second {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", fails, salt(p)))
	}
	for _, p := range second {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, fails, salt(p))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	testing.SkipHeights(AppealWindow + 1)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Failed || lvl() != "" {
		t.Fatalf("the last word: %s, level %q", s, lvl())
	}
	// The appellant changed the word: its bond back, and ShowShare of what
	// is left once the fund is paid back, as the only one who showed it
	// (round 11, minor 3).
	taken := FilingBond + ObjectionBond + int64(3+sumSeats(seats1))*Slash
	refill := least(taken, int64(size2)*PanelFee) // what the fund paid out: the second panel's seats
	share := (taken - refill) * ShowShare / 100
	if got := bal(honest) - before[honest]; got != bond+share+PanelFee*int64(seats2[honest]) {
		t.Errorf("the honest appellant got %d: bond %d, share %d, %d seats", got, bond, share, seats2[honest])
	}
	if bal(worker) != before[worker] || RecordOf(worker).Faults != 1 {
		t.Errorf("the liar's worker: paid %d", bal(worker)-before[worker])
	}
	for _, c := range owners {
		want := MinTicket - Slash*int64(seats1[c])
		for _, d := range drawn {
			if c == d {
				want -= Slash
			}
		}
		if got := stakeOf2(c, owners); got != want {
			t.Errorf("%s: stake %d, want %d", c, got, want)
		}
	}
}

// Seats follow stake: an owner with as much stake as the other eligible
// owners together holds many seats of a panel (about half, by chance),
// where one seat per owner would give it one and the rest's addresses all
// the others; one owner may hold several seats (round 10, new major 2).
func TestSeatsFollowStake(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, []int{15}
	owners := ownersN(16)
	for _, w := range owners {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	big := testutils.TestAddress("big")
	testing.SetRealm(u(big))
	send(13 * MinTicket)
	StakeTicket(cross(cur))
	send(0)
	testing.SetRealm(u(anyone))
	send(10_000_000)
	Fund(cross(cur))
	send(0)
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	if drawn[0] == big || drawn[1] == big || drawn[2] == big {
		t.Fatalf("the big owner was drawn as a checker with this beacon: %v", drawn)
	}
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
	members, size := PanelOf(id)
	seats := seatMap(id, members)
	if sumSeats(seats) != size || seats[big] < 5 || len(members) >= size {
		t.Fatalf("seats %v of %d: the big owner holds %d", seats, size, seats[big])
	}
}
