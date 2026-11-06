// Package lcspike is the light client spike's realm: one param per guard,
// lvl_<hash>, holding its level. Only this realm can write its params, but
// anyone may call SetLevel: the spike has no bonds or draws. So it lives at
// a path of its own, never the Guards realm's, where a mistaken deploy
// would let anyone write the levels light clients trust (2026-11-06).
package lcspike

import "chain/params"

// SetLevel records a guard's level, for anyone (the spike's tests only).
func SetLevel(cur realm, hash, level string) {
	params.SetString("lvl_"+hash, level)
}
