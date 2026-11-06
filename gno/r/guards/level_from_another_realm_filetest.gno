// A level read from another realm is the Guards realm's, not the caller's
// own param of the same name (gno-interrealm-v2.md §2: a call that doesn't
// cross leaves the caller acting, and chain/params keys by the realm
// acting). Before 2026-11-06 Level read the param, and this printed
// "after: [tested]" for a guard the realm never decided.

// PKGPATH: gno.land/r/probe/consumer
package consumer

import (
	"chain/params"

	"gno.land/r/repairer/guards"
)

const h = "0000000000000000000000000000000000000000000000000000000000000000"

func main(cur realm) {
	println("before: [" + guards.Level(h, "ubuntu 24.04") + "]")
	params.SetString("lvl_"+h+"_ubuntu-24.04", "tested")
	println("after: [" + guards.Level(h, "ubuntu 24.04") + "]")
}

// Output:
// before: []
// after: []
