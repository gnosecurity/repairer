package guards

import (
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

// A checker's run differs once, by chance: the rerun agrees, the filing
// settles as usual, and nobody loses anything.
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
	if s := Settle(cross(cur), id); s != Tested || Level(GuardHash(guardText)) != Tested {
		t.Fatalf("after the rerun agreed: %s", s)
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
// never anyone already on the filing, decides; the liar loses Slash, half
// of it goes to the worker and the honest checkers, the panels' cost goes
// back to the fund, and the rest is locked. Everyone honest is paid.
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
	for _, p := range panel {
		testing.SetRealm(u(p))
		RevealCheck(cross(cur), id, ok, salt(p))
	}
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Tested || Level(GuardHash(guardText)) != Tested {
		t.Fatalf("decided %s", s)
	}
	taken := Slash
	each := taken * ShowShare / 100 / 3 // the worker and the two honest checkers showed it
	left := taken - 3*each
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

func ticketIndex(a address, owners []address) int {
	for i, o := range owners {
		if o == a {
			return i
		}
	}
	return -1
}

// A worker files a guard that passes by its account and fails by every
// checker's: a panel says it fails. The worker loses its whole bond, half of
// which goes to the checkers who showed it; the guard gets no level.
func TestPanelSlashesALyingWorker(cur realm, t *testing.T) {
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
	says := func(c address) string {
		if c == worker {
			return ok
		}
		return fails
	}
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", says(c), salt(c)))
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, says(c), salt(c))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	parties := append([]address{worker}, drawn...)
	for run := 1; run <= Reruns; run++ {
		for _, c := range parties {
			testing.SetRealm(u(c))
			CommitCheck(cross(cur), id, Commitment(c, kind(c), says(c), salt(c)))
		}
		for _, c := range parties {
			testing.SetRealm(u(c))
			RevealCheck(cross(cur), id, says(c), salt(c))
		}
		aim(1003)
		testing.SetRealm(u(anyone))
		Settle(cross(cur), id)
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
		tr := lie
		if c == worker {
			tr = ok
		}
		RevealCheck(cross(cur), id, tr, salt(c))
	}
	aim(1003)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Panel {
		t.Fatalf("without reruns: %s", s)
	}
	SubmitBeacon(cross(cur), 1003, sig1003)
	refuses(t, "disputes wait for it", func() { DrawPanel(cross(cur), id) })
	send(int64(PanelSizes[0]) * PanelFee)
	Fund(cross(cur))
	send(0)
	DrawPanel(cross(cur), id)
	if st, _, _ := State(id); st != Panelled || FundBalance() != 0 {
		t.Fatalf("after funding: %s, fund %d", st, FundBalance())
	}
}

// A panel that splits evenly decides nothing: its members are paid for the
// run, and a larger panel, none of them on it, decides. A silent member
// loses Slash and the rest still decide.
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
	first, _ := PanelOf(id)
	for i, p := range first {
		testing.SetRealm(u(p))
		tr := ok
		if i%2 == 1 {
			tr = lie
		}
		CommitCheck(cross(cur), id, Commitment(p, "check", tr, salt(p)))
	}
	for i, p := range first {
		testing.SetRealm(u(p))
		tr := ok
		if i%2 == 1 {
			tr = lie
		}
		RevealCheck(cross(cur), id, tr, salt(p))
	}
	aim(1004)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Panel {
		t.Fatalf("after an even split: %s", s)
	}
	for _, p := range first {
		if bal(p)-before[p] != PanelFee {
			t.Errorf("first panelist %s paid %d", p, bal(p)-before[p])
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
	if s := Settle(cross(cur), id); s != Tested {
		t.Fatalf("the larger panel: %s", s)
	}
	if stakeOf2(wrong, owners) != MinTicket-Slash || bal(wrong) != before[wrong] {
		t.Errorf("the panelist on the wrong side: stake %d, paid %d", stakeOf2(wrong, owners), bal(wrong)-before[wrong])
	}
	if stakeOf2(silent, owners) != MinTicket-Slash || RecordOf(silent).Silent != 1 {
		t.Errorf("the silent member: stake %d", stakeOf2(silent, owners))
	}
	for _, c := range drawn {
		if stakeOf2(c, owners) != MinTicket-Slash {
			t.Errorf("a lying checker kept %d", stakeOf2(c, owners))
		}
	}
}

// When no panel reaches two thirds, the whole pool decides (F3): the
// filing waits there, with every bond and drawn ticket held.
func TestToThePool(cur realm, t *testing.T) {
	reset()
	Reruns, PanelSizes = 0, []int{4}
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
	if s := Settle(cross(cur), id); s != Pool || Level(GuardHash(guardText)) != "" {
		t.Fatalf("after the last panel split: %s", s)
	}
	for _, c := range drawn {
		if _, _, open, _ := TicketOf(ticketIndex(c, owners)); open != 1 {
			t.Errorf("%s's ticket isn't held for the pool", c)
		}
	}
}

// A checker silent in a rerun loses Slash and is out of the filing, and a
// panel decides at once.
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
	aim(1003)
	testing.SetRealm(u(anyone))
	if s := Settle(cross(cur), id); s != Panel {
		t.Fatalf("after a silence in the rerun: %s", s)
	}
	if stakeOf2(drawn[0], owners) != MinTicket-Slash || RecordOf(drawn[0]).Silent != 1 {
		t.Errorf("the silent checker: stake %d", stakeOf2(drawn[0], owners))
	}
	if _, _, d := State(id); len(d) != 2 {
		t.Errorf("still on the filing: %v", d)
	}
}
