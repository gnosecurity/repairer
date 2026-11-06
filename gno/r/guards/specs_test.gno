package guards

import (
	"chain"
	"chain/runtime"
	"strings"
	"testing"
)

// Tests from reading gno-interrealm-v2.md and gno-security-guide.md rule by
// rule (2026-11-06). A level read from another realm is in
// level_from_another_realm_filetest.gno.

// Every call that takes a payment refuses a caller that isn't an account
// calling directly, a code realm's or a MsgRun script's, though the send it
// names is there: neither one's send landed here (guide §5.5).
func TestPaymentsOnlyFromAccounts(cur realm, t *testing.T) {
	reset()
	// A code realm, and a MsgRun script's realm: IsUser lets the script in.
	callers := []runtime.Realm{
		testing.NewCodeRealm("gno.land/r/evil/proxy"),
		runtime.NewRealm(alice, "gno.land/e/"+string(alice)+"/run"),
	}
	if !callers[1].IsUserRun() {
		t.Fatal("not a MsgRun script's realm")
	}
	for _, r := range callers {
		send(1000 * MinTicket)
		testing.SetRealm(r)
		refuses(t, "call from your own account", func() { Commit(cross(cur), strings.Repeat("a", 64)) })
		testing.SetRealm(r)
		refuses(t, "call from your own account", func() { StakeTicket(cross(cur)) })
		testing.SetRealm(r)
		refuses(t, "call from your own account", func() { Object(cross(cur), 0, ok) })
		testing.SetRealm(r)
		refuses(t, "call from your own account", func() { Appeal(cross(cur), 0) })
		testing.SetRealm(r)
		refuses(t, "call from your own account", func() { Fund(cross(cur)) })
	}
	send(0)
	if FundBalance() != 0 || nTickets != 0 || nFilings != 0 {
		t.Fatalf("a refused payment counted: fund %d, %d tickets, %d filings", FundBalance(), nTickets, nFilings)
	}
}

// A send with any denom but ugnot is refused whole: nothing here could use
// the other coins or send them back.
func TestPaymentsOnlyUgnot(cur realm, t *testing.T) {
	reset()
	c := chain.Coins{chain.NewCoin("ugnot", MinTicket), chain.NewCoin("gno.land/r/other:tok", 1)}
	testing.IssueCoins(self, c)
	testing.SetOriginSend(c)
	testing.SetRealm(u(alice))
	refuses(t, "send only ugnot", func() { StakeTicket(cross(cur)) })
	testing.SetRealm(u(alice))
	refuses(t, "send only ugnot", func() { Fund(cross(cur)) })
	send(MinTicket)
	testing.SetRealm(u(alice))
	if id := StakeTicket(cross(cur)); id != 0 {
		t.Fatalf("ticket %d", id)
	}
	send(0)
}
