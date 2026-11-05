package guard

import "testing"

// Cases from dpkg's own comparison rules, and the kernel builds this
// project compares.
var versionCases = []struct {
	a, b string
	want int // the sign of CompareVersions(a, b)
}{
	{"1.0", "1.0", 0},
	{"1.02", "1.2", 0},
	{"0:1.0", "1.0", 0},
	{"1.0", "1.0-1", -1},
	{"1.0-1", "1.0-2", -1},
	{"1.0~rc1", "1.0", -1},
	{"1.0~rc1", "1.0~rc2", -1},
	{"1.0~", "1.0", -1},
	{"1.0~~", "1.0~", -1},
	{"1.0a", "1.0", 1},
	{"1.0+b1", "1.0", 1},
	{"1.0.1", "1.0a", 1}, // "." sorts after letters
	{"1:0.1", "2.0", 1},
	{"2:1.0", "10:0.1", -1},
	{"1.10", "1.9", 1},
	{"6.8.0-149.149", "6.8.0-142.142", 1},
	{"6.8.0-142.142", "6.8.0-149.149", -1},
	{"7.0.0-43.43", "7.0.0-42.42", 1},
	{"5.15.0-203.213", "5.15.0-140.150", 1},
	{"6.1.153-1", "6.1.153-1", 0},
	{"6.12.48-1", "6.12.9-1", 1},
	{"6.1.0-37", "6.1.0-37+deb12u1", -1},
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func TestCompareVersions(t *testing.T) {
	for _, c := range versionCases {
		if got := sign(CompareVersions(c.a, c.b)); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := sign(CompareVersions(c.b, c.a)); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}
