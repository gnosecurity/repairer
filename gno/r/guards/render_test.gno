package guards

import (
	"strings"
	"testing"
)

// The pages the site is built from: the index lists the filing, the
// filing's page shows its guard in a block a guard's text can't close,
// its transcripts once opened, and links to each address's record.
func TestRender(cur realm, t *testing.T) {
	reset()
	for _, w := range []address{alice, bob, carol, dave} {
		testing.SetRealm(u(w))
		stakeOne(t, cur)
	}
	testing.SkipHeights(MinTicketAge)
	testing.SetRealm(u(worker))
	id := file(t, cur, ok, 1001)
	h := GuardHash(guardText)
	idx := Render("")
	if !strings.Contains(idx, "- [filing 0](filing/0): revealed, guard `"+h[:16]+"`") {
		t.Fatalf("the index:\n%s", idx)
	}
	page := Render("filing/0")
	for _, want := range []string{"# Filing 0", "- State: revealed", "- Guard: `" + h + "`", "## The guard\n\n```\n" + strings.TrimSuffix(guardText, "\n") + "\n```\n",
		"- worker [" + string(worker) + "](address/" + string(worker) + "): committed, not yet opened"} {
		if !strings.Contains(page, want) {
			t.Errorf("the filing's page lacks %q:\n%s", want, page)
		}
	}
	if Render("guard/"+h) != page {
		t.Error("the guard's page isn't its newest filing's")
	}
	testing.SetRealm(u(anyone))
	drawn := draw(t, cur, id, 1001, sig1001)
	for _, c := range drawn {
		testing.SetRealm(u(c))
		CommitCheck(cross(cur), id, Commitment(c, "check", ok, salt(c)))
	}
	if page := Render("filing/0"); !strings.Contains(page, "committed, not yet opened") || strings.Contains(page, ok) {
		t.Errorf("a sealed transcript shown:\n%s", page)
	}
	for _, c := range append([]address{worker}, drawn...) {
		testing.SetRealm(u(c))
		RevealCheck(cross(cur), id, ok, salt(c))
	}
	testing.SetRealm(u(anyone))
	Settle(cross(cur), id)
	page = Render("filing/0")
	for _, want := range []string{"- State: agreed", "proves: none", "- Agreed: `" + ok + "`, final after height"} {
		if !strings.Contains(page, want) {
			t.Errorf("the agreement's page lacks %q:\n%s", want, page)
		}
	}
	finalize(t, cur, id)
	page = Render("filing/0")
	if !strings.Contains(page, "- State: tested") || !strings.Contains(page, "proves: tested") || !strings.Contains(page, "`"+ok+"`") || strings.Contains(page, "- Agreed:") {
		t.Errorf("after the last word:\n%s", page)
	}
	if rp := Render("address/" + string(worker)); !strings.Contains(rp, "- Filings tested: 1") {
		t.Errorf("the worker's record:\n%s", rp)
	}
	for _, bad := range []string{"filing/9", "filing/x", "guard/zz", "address/nope", "elsewhere"} {
		if !strings.HasPrefix(Render(bad), "# Not found") {
			t.Errorf("%q: %s", bad, Render(bad))
		}
	}
}

// A guard's text with backticks gets a longer fence, so it can't end the
// block early.
func TestFenced(t *testing.T) {
	got := fenced("a ``` b ```` c")
	if !strings.HasPrefix(got, "`````\n") || !strings.HasSuffix(got, "\n`````\n") {
		t.Fatalf("%q", got)
	}
	if fenced("plain") != "```\nplain\n```\n" {
		t.Fatalf("%q", fenced("plain"))
	}
}
