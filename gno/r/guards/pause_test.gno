package guards

import (
	"strings"
	"testing"
)

// The admin's emergency pause stops new filings and stakes, lets everything
// already in flight exit, and is open to no one but the admin — not another
// user, and not a realm calling in.
func TestPause(cur realm, t *testing.T) {
	reset()

	// A ticket staked while open, so we can exit it later while paused.
	testing.SetRealm(u(worker))
	send(MinTicket)
	id := StakeTicket(cross(cur))

	// No one but the admin may pause.
	testing.SetRealm(u(worker))
	refuses(t, "only the admin may pause", func() { Pause(cross(cur)) })
	testing.SetRealm(testing.NewCodeRealm("gno.land/r/evil/proxy"))
	refuses(t, "call from your own account", func() { Pause(cross(cur)) })
	if Paused() {
		t.Fatal("paused before the admin paused it")
	}

	// The admin pauses.
	testing.SetRealm(u(adminAddr))
	Pause(cross(cur))
	if !Paused() {
		t.Fatal("not paused after the admin paused it")
	}

	// Nor may anyone but the admin lift it.
	testing.SetRealm(u(worker))
	refuses(t, "only the admin may pause", func() { Unpause(cross(cur)) })
	if !Paused() {
		t.Fatal("someone other than the admin lifted the pause")
	}

	// While paused: no new filing, no new stake.
	testing.SetRealm(u(worker))
	refuses(t, "paused", func() { Commit(cross(cur), strings.Repeat("a", 64)) })
	refuses(t, "paused", func() { StakeTicket(cross(cur)) })

	// But work in flight still exits: the earlier ticket can still unstake.
	Unstake(cross(cur), id)

	// The admin lifts it; new work resumes.
	testing.SetRealm(u(adminAddr))
	Unpause(cross(cur))
	if Paused() {
		t.Fatal("still paused after unpause")
	}
	testing.SetRealm(u(worker))
	send(MinTicket)
	StakeTicket(cross(cur))
}
