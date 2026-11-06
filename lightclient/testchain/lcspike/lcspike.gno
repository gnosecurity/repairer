// Package guards is the light client spike's realm: one param per guard,
// lvl_<hash>, holding its level. Only this realm can write its params.
package guards

import "chain/params"

// SetLevel records a guard's level (the spike has no bonds or draws).
func SetLevel(cur realm, hash, level string) {
	params.SetString("lvl_"+hash, level)
}
