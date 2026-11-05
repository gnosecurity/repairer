package guards

import (
	"chain"
	"testing"

	"gno.land/p/nt/testutils/v0"
)

// Gas, measured by twins (round 12, minor 5): each TestGasX does what
// TestGasXBase does, then the one call measured; the difference of their
// "--- GAS:" lines is that call's VM gas with the objects already in
// memory. A chain loads them from its store first, so on-chain numbers come
// from realm-e2e (POOL=n). The pool is built with bulk below, as
// StakeTicket builds it but without the bank and events, so a thousand
// owners fit in one test.

// bulk stakes n tickets of MinTicket, one owner each, as StakeTicket does.
func bulk(n int) []address {
	var owners []address
	for i := 0; i < n; i++ {
		a := testutils.TestAddress("bulk" + itoa(i))
		owners = append(owners, a)
		tk := &ticket{id: nTickets, owner: a, weight: MinTicket, stake: MinTicket, height: now(), votes: len(allVotes)}
		nTickets++
		tickets.Set(key(uint64(tk.id)), tk)
		addPath(tk.id, tk.weight, 0, 0, 0)
		active += MinTicket
	}
	testing.IssueCoins(self, chain.Coins{chain.NewCoin("ugnot", int64(n)*MinTicket)}) // what the stakes moved here
	return owners
}

func TestGasDraw1000Base(cur realm, t *testing.T) {
	reset()
	bulk(1000)
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1001, sig1001)
	_ = id
}

func TestGasDraw1000(cur realm, t *testing.T) {
	reset()
	bulk(1000)
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	testing.SetRealm(u(anyone))
	SubmitBeacon(cross(cur), 1001, sig1001)
	if s := Draw(cross(cur), id); s != Drawn {
		t.Fatalf("the draw: %s", s)
	}
}

// A 31-seat panel over 1,000 owners: the filing's three checkers differ
// from the worker, and with no reruns the dispute asks for the panel.
func TestGasDrawPanel31Base(cur realm, t *testing.T) {
	reset()
	bulk(1000)
	testing.SkipHeights(MinTicketAge)
	Reruns, PanelSizes = 0, []int{31}
	testing.SetRealm(u(anyone))
	send(panelCost(0))
	Fund(cross(cur))
	send(0)
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
	SubmitBeacon(cross(cur), 1003, sig1003)
}

func TestGasDrawPanel31(cur realm, t *testing.T) {
	reset()
	bulk(1000)
	testing.SkipHeights(MinTicketAge)
	Reruns, PanelSizes = 0, []int{31}
	testing.SetRealm(u(anyone))
	send(panelCost(0))
	Fund(cross(cur))
	send(0)
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
	SubmitBeacon(cross(cur), 1003, sig1003)
	DrawPanel(cross(cur), id)
	if st, _, _ := State(id); st != Panelled {
		t.Fatalf("the panel's draw: %s", st)
	}
}

// A withdrawal while a round waits, over 1,000 owners: the ticket began
// leaving while an earlier round waited, so it is pending, and now is
// marked withdrawn. (The setup is spelled out in each twin: only a test's
// own body may switch users.)
func TestGasWithdrawWaitingBase(cur realm, t *testing.T) {
	reset()
	owners := bulk(1000)
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	file(t, cur, ok, 1001)
	testing.SetRealm(u(owners[999]))
	Unstake(cross(cur), 999)
	testing.SkipHeights(UnbondBlocks)
	testing.SetRealm(u(worker))
	file(t, cur, ok, 1001)
}

func TestGasWithdrawWaiting(cur realm, t *testing.T) {
	reset()
	owners := bulk(1000)
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	file(t, cur, ok, 1001)
	testing.SetRealm(u(owners[999]))
	Unstake(cross(cur), 999)
	testing.SkipHeights(UnbondBlocks)
	testing.SetRealm(u(worker))
	file(t, cur, ok, 1001)
	testing.SetRealm(u(owners[999]))
	Withdraw(cross(cur), 999)
	if _, _, gone, _ := below(nTickets); gone != MinTicket {
		t.Fatalf("not marked: %d", gone)
	}
}

// Compact(64) over 1,000 owners: 64 tickets began leaving while a round
// waited; that round has lapsed.
func TestGasCompact64Base(cur realm, t *testing.T) {
	reset()
	owners := bulk(1000)
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	file(t, cur, ok, 1001)
	for i := 0; i < 64; i++ {
		testing.SetRealm(u(owners[i*15]))
		Unstake(cross(cur), i*15)
	}
	testing.SkipHeights(DrawDeadline + 1)
	if pending.Size() != 64 {
		t.Fatalf("%d pending", pending.Size())
	}
}

func TestGasCompact64(cur realm, t *testing.T) {
	reset()
	owners := bulk(1000)
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	file(t, cur, ok, 1001)
	for i := 0; i < 64; i++ {
		testing.SetRealm(u(owners[i*15]))
		Unstake(cross(cur), i*15)
	}
	testing.SkipHeights(DrawDeadline + 1)
	testing.SetRealm(u(anyone))
	if n := Compact(cross(cur)); n != 0 {
		t.Fatalf("%d left", n)
	}
}
