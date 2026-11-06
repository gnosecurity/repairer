// PanelSizes is a slice, so a reader holds the realm's own array; the VM
// refuses another realm's write into it (see
// numbers_from_another_realm_filetest.gno).

// PKGPATH: gno.land/r/probe/consumer
package consumer

import "gno.land/r/repairer/guards"

func main(cur realm) {
	guards.PanelSizes[0] = 1
	println("wrote", guards.PanelSizes[0])
}

// Error:
// cannot directly modify readonly tainted object (use a method or crossing function): (const (ref(gno.land/r/repairer/guards) package{})).PanelSizes[(const (0 int))]
