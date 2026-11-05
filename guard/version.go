package guard

import "strings"

// CompareVersions compares two Debian-style versions ([epoch:]upstream[-revision])
// the way dpkg does: below zero if a is older than b, zero if they are the
// same version, above zero if a is newer. Ubuntu and Debian kernel builds
// compare this way.
func CompareVersions(a, b string) int {
	ae, au, ar := splitVersion(a)
	be, bu, br := splitVersion(b)
	if c := compareEpoch(ae, be); c != 0 {
		return c
	}
	if c := verrevcmp(au, bu); c != 0 {
		return c
	}
	return verrevcmp(ar, br)
}

// splitVersion splits [epoch:]upstream[-revision]. The revision follows the
// last '-'.
func splitVersion(v string) (epoch, upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func compareEpoch(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	return strings.Compare(a, b)
}

// order ranks a character as dpkg does: '~' sorts before everything, even
// the end of the string; letters before other characters.
func order(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return int(c)
	case c == '~':
		return -1
	case c != 0:
		return int(c) + 256
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// verrevcmp is dpkg's comparison of an upstream version or a revision:
// alternating runs of non-digits (compared by order) and digits (compared
// as numbers).
func verrevcmp(a, b string) int {
	at := func(s string, i int) byte {
		if i < len(s) {
			return s[i]
		}
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := order(at(a, i)), order(at(b, j))
			if ac != bc {
				return ac - bc
			}
			i++
			j++
		}
		for at(a, i) == '0' {
			i++
		}
		for at(b, j) == '0' {
			j++
		}
		for isDigit(at(a, i)) && isDigit(at(b, j)) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if isDigit(at(a, i)) {
			return 1
		}
		if isDigit(at(b, j)) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}

// System is the running system, as far as guards care.
type System struct {
	OS      string // os-release ID, such as "ubuntu"
	Release string // os-release VERSION_ID, such as "24.04"
	// Kernel is the running build's version, such as "6.8.0-142.142", or ""
	// when it can't be read.
	Kernel string
	// Flavour is the build's flavour, such as "generic", or "" when unknown.
	Flavour string
}

// Fits reports whether the guard is written for this system.
func (g *Guard) Fits(s System) bool {
	for _, t := range g.For {
		if t.OS != s.OS {
			continue
		}
		for _, r := range t.Releases {
			if r == s.Release {
				return true
			}
		}
	}
	return false
}

// FixRunning reports whether a vendor's fixed build, or a later one, is
// running, and whether that could be decided at all. It decides only for
// the generic flavour, whose versions the fixed builds name; any other
// flavour, or an unreadable kernel, is undecided.
func (g *Guard) FixRunning(s System) (fixed, decided bool) {
	if s.Kernel == "" || (s.Flavour != "" && s.Flavour != "generic") {
		return false, false
	}
	for _, u := range g.Until {
		if u.OS == s.OS && u.Release == s.Release {
			return CompareVersions(s.Kernel, u.Kernel) >= 0, true
		}
	}
	return false, false
}
