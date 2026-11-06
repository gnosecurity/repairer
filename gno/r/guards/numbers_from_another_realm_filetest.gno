// The realm's numbers are exported vars so anyone can read them; no other
// realm can change them. The VM refuses the write (and an element's, a
// copy's, an append's, and one through a /p/ function, method or pointer,
// as probes showed on 2026-11-06); this test fails if a VM ever lets one
// through.

// PKGPATH: gno.land/r/probe/consumer
package consumer

import "gno.land/r/repairer/guards"

func main(cur realm) {
	guards.FilingBond = 0
	println("wrote", guards.FilingBond)
}

// Error:
// gno.land/r/probe/consumer/numbers_from_another_realm.gno:13:2-19: cannot directly mutate gno.land/r/repairer/guards.FilingBond from gno.land/r/probe/consumer
