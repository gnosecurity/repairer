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

// A checker's run differs once, by chance: the rerun agrees, and the
// filing goes on as an agreement; nobody loses anything.
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
	if s := finalize(t, cur, id); s != Tested || Level(GuardHash(guardText)) != Tested {
		t.Fatalf("finalized %s", s)
	}
	for _, c := range drawn {
		if bal(c)-before[c] != CheckFee || stakeOf2(c, owners) != MinTicket {
			t.Errorf("%s: paid %d, stake %d", c, bal(c)-before[c], stakeOf2(c, owners))
		}
	}
	if bal(worker)-before[worker] != FilingBond-int64(Checkers)*CheckFee-FundFee || FundBalance() != FundFee || Burned() != 0 {
		t.Errorf("worker got %d, fund %d, burned %d", bal(worker)-before[worker], FundBalance(), Burned())
	}
}

// A checker lies through both reruns. A panel drawn from a later round,
// never anyone already on the filing, gives its word once every member has
// revealed; nobody appeals, and the last word takes Slash from the liar,
// half of it to the worker and the honest checkers, the panel's cost back to
// the fund, and the rest locked. Everyone honest is paid.
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
	if len(panel) != size || size != PanelSizes[0] {
		t.Fatalf("panel %v of %d", panel, size)
	}
	for _, p := range panel {
		for _, c := range parties {
			if p == c {
				t.Fatalf("%s is on the filing and on its panel", p)
			}
		}
	}
	for _, p := range panel {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", ok, salt(p)))
	}
	for _, p := range panel[:3] {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, ok, salt(p))
	}
	// Three of four have revealed, more than two thirds, but the fourth is
	// still inside its window: no word yet (round 9, new major 5).
	testing.SetRealm(u(anyone))
	refuses(t, "still waiting for reveals", func() { Settle(cross(cur), id) })
	testing.SetRealm(u(panel[3]))
	RevealCheck(cross(cur), id, ok, salt(panel[3]))
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Appealable {
		t.Fatalf("the panel's word: %s", s)
	}
	if w, _ := Word(id); w != ok || bal(worker) != before[worker] {
		t.Fatalf("word %q; paid before the last word: %d", w, bal(worker)-before[worker])
	}
	refuses(t, "the appeal window is open", func() { Settle(cross(cur), id) })
	testing.SetRealm(u(drawn[1]))
	refuses(t, "only a party the panel went against appeals", func() { Appeal(cross(cur), id) })
	testing.SkipHeights(AppealWindow + 1)
	testing.SetRealm(u(liar))
	send(AppealBond)
	refuses(t, "nothing to appeal", func() { Appeal(cross(cur), id) })
	send(0)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Tested || Level(GuardHash(guardText)) != Tested {
		t.Fatalf("the last word: %s", s)
	}
	each := Slash * ShowShare / 100 / 3 // the worker and the two honest checkers showed it
	left := Slash - 3*each
	refill := least(left, int64(size)*PanelFee)
	if stakeOf2(liar, owners) != MinTicket-Slash || bal(liar) != before[liar] || RecordOf(liar).Faults != 1 {
		t.Errorf("the liar: stake %d, paid %d, record %+v", stakeOf2(liar, owners), bal(liar)-before[liar], RecordOf(liar))
	}
	for _, c := range drawn[1:] {
		if bal(c)-before[c] != CheckFee+each || stakeOf2(c, owners) != MinTicket {
			t.Errorf("honest checker %s: paid %d, stake %d", c, bal(c)-before[c], stakeOf2(c, owners))
		}
	}
	if got := bal(worker) - before[worker]; got != FilingBond-2*CheckFee-FundFee+each {
		t.Errorf("the worker got %d", got)
	}
	for _, p := range panel {
		if bal(p)-before[p] != PanelFee || stakeOf2(p, owners) != MinTicket {
			t.Errorf("panelist %s: paid %d", p, bal(p)-before[p])
		}
	}
	if FundBalance() != 1_000_000-int64(size)*PanelFee+FundFee+refill || Burned() != left-refill {
		t.Errorf("fund %d, burned %d", FundBalance(), Burned())
	}
	for _, c := range append(drawn, panel...) { // every ticket is free again
		if _, _, open, _ := TicketOf(ticketIndex(c, owners)); open != 0 {
			t.Errorf("%s's ticket still held", c)
		}
	}
}

// All three checkers lie, and three of the first panel's four lie too: the
// panel's word goes against the honest worker. The worker appeals; the next
// panel, honest, gives the last word. No honest bond or stake is taken;
// every liar on the filing and on the first panel loses Slash, half of it to
// the worker, who showed it; the appeal bond comes back (round 9, new major
// 3).
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
	first, _ := PanelOf(id)
	say1 := func(p address) string {
		if p == first[0] {
			return ok
		}
		return lie
	}
	for _, p := range first {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", say1(p), salt(p)))
	}
	for _, p := range first {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, say1(p), salt(p))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Appealable {
		t.Fatalf("the first panel's word: %s", s)
	}
	if w, _ := Word(id); w != lie {
		t.Fatalf("the first panel said %q", w)
	}
	aim(1004)
	testing.SetRealm(u(worker))
	send(AppealBond)
	if s := Appeal(cross(cur), id); s != Panel {
		t.Fatalf("after the appeal: %s", s)
	}
	send(0)
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1004, sig1004)
	DrawPanel(cross(cur), id)
	second, size := PanelOf(id)
	if size != PanelSizes[1] || len(second) != size {
		t.Fatalf("the second panel %v of %d", second, size)
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
	share := 6 * Slash * ShowShare / 100 // three checkers and three first panelists, all to the worker
	if got := bal(worker) - before[worker]; got != FilingBond-FundFee+share+AppealBond {
		t.Errorf("the honest worker got %d, want %d", got, FilingBond-FundFee+share+AppealBond)
	}
	honest := map[address]bool{first[0]: true}
	for _, p := range second {
		honest[p] = true
	}
	for _, c := range append(append(append([]address{}, drawn...), first...), second...) {
		want := MinTicket
		if !honest[c] {
			want -= Slash
		}
		if got := stakeOf2(c, owners); got != want {
			t.Errorf("%s: stake %d, want %d", c, got, want)
		}
	}
	if bal(first[0])-before[first[0]] != PanelFee {
		t.Errorf("the honest member of the first panel was paid %d", bal(first[0])-before[first[0]])
	}
	page := Render("filing/" + itoa(id))
	for _, want := range []string{"- Appealed by " + link(worker) + " against `" + lie + "`", "## Panel 1 (of 4)", "## Panel 2 (of 7)", "- State: tested"} {
		if !strings.Contains(page, want) {
			t.Errorf("the filing's page lacks %q:\n%s", want, page)
		}
	}
}

// A worker files a guard that passes by its account and fails by every
// checker's: a panel says it fails, nobody appeals. The worker loses its
// whole bond, half of which goes to the checkers who showed it; the guard
// gets no level.
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
	panel, _ := PanelOf(id)
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
	if s := Settle(cross(cur), id); s != Failed || Level(GuardHash(guardText)) != "" {
		t.Fatalf("decided %s", s)
	}
	each := FilingBond * ShowShare / 100 / 3
	for _, c := range drawn {
		if bal(c)-before[c] != each || stakeOf2(c, owners) != MinTicket {
			t.Errorf("checker %s: paid %d", c, bal(c)-before[c])
		}
	}
	if bal(worker) != before[worker] || RecordOf(worker).Faults != 1 {
		t.Errorf("the worker: paid %d, record %+v", bal(worker)-before[worker], RecordOf(worker))
	}
}

// Disputes wait while the fund can't pay a panel; anyone may fund it.
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
	if s := Settle(cross(cur), id); s != Panel {
		t.Fatalf("without reruns: %s", s)
	}
	SubmitBeacon(cross(cur), 1003, sig1003)
	refuses(t, "disputes wait for it", func() { DrawPanel(cross(cur), id) })
	refuses(t, "the panel can still be drawn", func() { Settle(cross(cur), id) })
	// The fund stays short past the draw's deadline: the round goes stale,
	// and Settle fixes a new one, so the dispute is never stuck.
	testing.SkipHeights(DrawDeadline + 1)
	send(int64(PanelSizes[0]) * PanelFee)
	Fund(cross(cur))
	send(0)
	refuses(t, "the panel's deadline has passed", func() { DrawPanel(cross(cur), id) })
	aim(1004)
	if s := Settle(cross(cur), id); s != Panel {
		t.Fatalf("after the deadline: %s", s)
	}
	if _, r, _ := State(id); r != 1004 {
		t.Fatalf("the new round is %d", r)
	}
	SubmitBeacon(cross(cur), 1004, sig1004)
	DrawPanel(cross(cur), id)
	if st, _, _ := State(id); st != Panelled || FundBalance() != 0 {
		t.Fatalf("after funding: %s, fund %d", st, FundBalance())
	}
}

// A panel that splits evenly gives no word: a larger panel, none of them on
// it, runs it. A member silent there loses Slash, one on the wrong side too;
// at the last word the first panel's members are judged by it as well, and
// nobody is paid before it.
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
	first, _ := PanelOf(id)
	say1 := func(i int) string {
		if i%2 == 1 {
			return lie
		}
		return ok
	}
	for i, p := range first {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", say1(i), salt(p)))
	}
	for i, p := range first {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, say1(i), salt(p))
	}
	aim(1004)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Panel {
		t.Fatalf("after an even split: %s", s)
	}
	for _, p := range first {
		if bal(p) != before[p] {
			t.Errorf("first panelist %s paid %d before the last word", p, bal(p)-before[p])
		}
	}
	SubmitBeacon(cross(cur), 1004, sig1004)
	DrawPanel(cross(cur), id)
	second, size := PanelOf(id)
	if size != PanelSizes[1] || len(second) != size {
		t.Fatalf("second panel %v of %d", second, size)
	}
	for _, p := range second {
		for _, q := range first {
			if p == q {
				t.Fatalf("%s sat on both panels", p)
			}
		}
	}
	silent, wrong := second[0], second[1]
	sayP := func(p address) string {
		if p == wrong {
			return lie
		}
		return ok
	}
	for _, p := range second[1:] {
		testing.SetRealm(u(p))
		CommitCheck(cross(cur), id, Commitment(p, "check", sayP(p), salt(p)))
	}
	testing.SetRealm(u(anyone))
	refuses(t, "still waiting for commitments", func() { Settle(cross(cur), id) })
	testing.SkipHeights(CheckWindow + 1)
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id) // the silent member is out; the rest may reveal
	for _, p := range second[1:] {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, sayP(p), salt(p))
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
	if stakeOf2(silent, owners) != MinTicket-Slash || RecordOf(silent).Silent != 1 {
		t.Errorf("the silent member: stake %d", stakeOf2(silent, owners))
	}
	if stakeOf2(wrong, owners) != MinTicket-Slash || bal(wrong) != before[wrong] {
		t.Errorf("the panelist on the wrong side: stake %d, paid %d", stakeOf2(wrong, owners), bal(wrong)-before[wrong])
	}
	for i, p := range first {
		if say1(i) == ok && bal(p)-before[p] != PanelFee {
			t.Errorf("first panelist %s, right, paid %d", p, bal(p)-before[p])
		}
		if say1(i) == lie && (bal(p) != before[p] || stakeOf2(p, owners) != MinTicket-Slash) {
			t.Errorf("first panelist %s, wrong: paid %d, stake %d", p, bal(p)-before[p], stakeOf2(p, owners))
		}
	}
	for _, c := range drawn {
		if stakeOf2(c, owners) != MinTicket-Slash {
			t.Errorf("a lying checker kept %d", stakeOf2(c, owners))
		}
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
	if s := Settle(cross(cur), id); s != Rerun {
		t.Fatalf("after a silence in the rerun's commitments: %s", s)
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
// and stakes, the objector gets its bond back and a share, and no level is
// ever written. A party can't object to its own filing (round 9, new major
// 7).
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
	panel, _ := PanelOf(id)
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
	if s := Settle(cross(cur), id); s != Failed || Level(GuardHash(guardText)) != "" {
		t.Fatalf("after the objection's panel: %s, level %q", s, Level(GuardHash(guardText)))
	}
	taken := FilingBond + 3*Slash
	if got := bal(eve) - before[eve]; got != ObjectionBond+taken*ShowShare/100 {
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

// A level written and then decided against is pulled: a later filing of the
// same guard that every account fails takes it back (round 9, new major 7).
func TestPull(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol, dave} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	for pass, tr := range []string{ok, fails} {
		testing.SetRealm(u(worker))
		id := file(t, cur, tr, uint64(1001+pass))
		testing.SetRealm(u(anyone))
		sig := sig1001
		if pass == 1 {
			sig = sig1002
		}
		drawn := draw(t, cur, id, uint64(1001+pass), sig)
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
		want := []string{Tested, Pulled}[pass]
		if Level(GuardHash(guardText)) != want {
			t.Fatalf("after filing %d: level %q", pass, Level(GuardHash(guardText)))
		}
	}
}

// A checker the panel went against appeals, and the next panel says the
// same: the appellant loses its bond with its Slash, half of both to those
// who showed the last word, and the panels' cost comes back to the fund
// (round 9, new major 3).
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
	first, _ := PanelOf(id)
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
	send(AppealBond)
	Appeal(cross(cur), id)
	send(0)
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1004, sig1004)
	DrawPanel(cross(cur), id)
	second, _ := PanelOf(id)
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
	taken := Slash + AppealBond
	each := taken * ShowShare / 100 / 3 // the worker and the two honest checkers
	left := taken - 3*each
	cost := int64(PanelSizes[0]+PanelSizes[1]) * PanelFee
	if bal(liar) != before[liar] || stakeOf2(liar, owners) != MinTicket-Slash || RecordOf(liar).Faults != 1 {
		t.Errorf("the appellant: paid %d, stake %d", bal(liar)-before[liar], stakeOf2(liar, owners))
	}
	if got := bal(worker) - before[worker]; got != FilingBond-2*CheckFee-FundFee+each {
		t.Errorf("the worker got %d", got)
	}
	for _, c := range drawn[1:] {
		if got := bal(c) - before[c]; got != CheckFee+each {
			t.Errorf("honest checker %s got %d", c, got)
		}
	}
	if FundBalance() != 10_000_000-cost+FundFee+least(left, cost) || Burned() != left-least(left, cost) {
		t.Errorf("fund %d, burned %d", FundBalance(), Burned())
	}
}

// An owner objects to an agreement, and the panel says the agreement was
// right: the objector loses its bond, half of it to those who showed it.
// The objector, a party now, is never drawn onto the panel that judges it.
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
	if !onFiling(get(id), objector) {
		t.Fatal("the objector isn't a party, so its ticket could sit on its own panel")
	}
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	panel, _ := PanelOf(id)
	for _, p := range panel {
		if p == objector {
			t.Fatalf("the objector sits on the panel judging it: %v", panel)
		}
	}
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
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Tested || Level(GuardHash(guardText)) != Tested {
		t.Fatalf("the last word: %s", s)
	}
	each := ObjectionBond * ShowShare / 100 / 4 // the worker and the three checkers
	if bal(objector) != before[objector] || RecordOf(objector).Faults != 1 {
		t.Errorf("the objector: paid %d, record %+v", bal(objector)-before[objector], RecordOf(objector))
	}
	for _, c := range drawn {
		if got := bal(c) - before[c]; got != CheckFee+each {
			t.Errorf("checker %s got %d", c, got)
		}
	}
	if got := bal(worker) - before[worker]; got != FilingBond-3*CheckFee-FundFee+each {
		t.Errorf("the worker got %d", got)
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
