# AGENTS.md: rules for changing this repo, for people and agents alike

## The gno code (gno/, lightclient/testchain/)

Before you write or review any `.gno` file, read gno's two rule books and
check the change against each rule:

- [gno-interrealm-v2.md](https://github.com/gnolang/gno/blob/master/docs/resources/gno-interrealm-v2.md)
- [gno-security-guide.md](https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md)

The realm is built and tested at gno 5d7d8f5f9. Read the books at that
commit, then check master for anything newer.

Fifteen review rounds checked the Guards realm's game theory, money and gas,
but none checked these books rule by rule. The audit that did (2026-11-06)
found `Level` answering for whichever realm called it. These rules are the
ones this realm has broken or depends on:

- **A call that doesn't cross leaves the caller acting** (interrealm v2
  §2). An exported function without `cur realm` runs on this realm's
  storage while the caller's realm is still the one acting. It must not
  read `chain/params` or `unsafe.CurrentRealm`/`PreviousRealm`, directly or
  through a helper, because those answer for the realm acting. Read the
  realm's own storage instead.
- **Payments are read in one place.** Only `paid()` reads
  `unsafe.OriginSend`, and only after `caller()` has checked
  `IsUserCall()` (guide §5.5). Never use `IsUser()`, which lets a MsgRun
  script spend the send before it calls.
- **No `cur.IsCurrent()` on your own `cur`.** It is always true.
  `IsCurrent` is for a realm value a caller hands you, and this realm takes
  none.
- **Return values, not pointers into state.** Take no callbacks or
  interfaces from callers, and keep `/p/` types such as `avl.Tree` in
  unexported places (guide §3, §5).
- **A realm that anyone may write lives at a path of its own**, never
  `gno.land/r/repairer/guards`. The light client's spike is at
  `gno.land/r/repairer/lcspike`.

`make qa` runs `scripts/check-realm-context.py`, which enforces the first
two rules by scanning the text. `make gnotest` runs the realm's tests, its
filetests and every mutant, with gno at the pinned commit. The filetests
call the realm as another realm would.

When a review finds a new rule, add a test that calls the realm from
another realm or from a MsgRun script, and add a check to the scan if the
scan can catch it.
