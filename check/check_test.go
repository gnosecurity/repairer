package check

import (
	"strings"
	"testing"
)

const head = `{"id":"cve-2026-98432/hit","version":1,"flaws":["CVE-2026-98432"],"for":[{"os":"ubuntu","releases":["24.04"]}],`

// Each kind of version 1, in canonical form, parses and says in words what
// it reads.
func TestKinds(t *testing.T) {
	for file, says := range map[string]string{
		head + `"kind":"package-files","args":{"package":"openssh-server"},"flag":"a file of sshd differs from its package"}`:     "the files of package openssh-server against its md5sums",
		head + `"kind":"deleted-exe","args":{},"flag":"a process runs a program that was deleted or replaced"}`:                   "processes running a deleted or replaced program",
		head + `"kind":"new-since","args":{"what":"setuid","since":"1793923200"},"flag":"a setuid file is new"}`:                  "setuid changed since 1793923200",
		head + `"kind":"foreign-modules","args":{},"flag":"a kernel module no package owns is loaded"}`:                           "loaded kernel modules no package owns",
		head + `"kind":"log-match","args":{"since":"1793923200","source":"auth","pattern":"Accepted publickey"},"flag":"logins"}`: `lines of auth since 1793923200 holding "Accepted publickey"`,
	} {
		c, err := Parse([]byte(file + "\n"))
		if err != nil {
			t.Errorf("%s: %v", file, err)
			continue
		}
		if c.Says() != says || len(c.Hash()) != 64 || !c.ForSystem("ubuntu", "24.04") || c.ForSystem("debian", "12") {
			t.Errorf("%s: says %q", c.Name(), c.Says())
		}
	}
}

// Every field is the kind's own: a field another kind takes, a missing one,
// an unknown kind or field, a bad value, a file not in canonical form, or
// one too big is refused.
func TestRefused(t *testing.T) {
	for name, file := range map[string]string{
		"unknown kind":       head + `"kind":"shell","args":{},"flag":"x"}`,
		"a field of another": head + `"kind":"deleted-exe","args":{"package":"bash"},"flag":"x"}`,
		"a field missing":    head + `"kind":"new-since","args":{"what":"keys"},"flag":"x"}`,
		"what":               head + `"kind":"new-since","args":{"what":"everything","since":"1793923200"},"flag":"x"}`,
		"since not digits":   head + `"kind":"new-since","args":{"what":"keys","since":"yesterday"},"flag":"x"}`,
		"since a number":     head + `"kind":"new-since","args":{"what":"keys","since":1793923200},"flag":"x"}`,
		"a package path":     head + `"kind":"package-files","args":{"package":"../etc"},"flag":"x"}`,
		"a log file by path": head + `"kind":"log-match","args":{"since":"1793923200","source":"/etc/shadow","pattern":"root"},"flag":"x"}`,
		"a unit not a unit":  head + `"kind":"log-match","args":{"since":"1793923200","source":"unit:../x","pattern":"x"},"flag":"x"}`,
		"a long pattern":     head + `"kind":"log-match","args":{"since":"1793923200","source":"auth","pattern":"` + strings.Repeat("a", 65) + `"},"flag":"x"}`,
		"no flag words":      head + `"kind":"deleted-exe","args":{},"flag":""}`,
		"an unknown field":   head + `"kind":"deleted-exe","args":{},"flag":"x","run":"rm -rf /"}`,
		"not canonical":      `{"version":1,"id":"cve-2026-98432/hit","flaws":["CVE-2026-98432"],"for":[{"os":"ubuntu","releases":["24.04"]}],"kind":"deleted-exe","args":{},"flag":"x"}`,
		"something after it": head + `"kind":"deleted-exe","args":{},"flag":"x"}{}`,
		"too big":            head + `"kind":"deleted-exe","args":{},"flag":"` + strings.Repeat("x", MaxSize) + `"}`,
		"no system":          `{"id":"x","version":1,"flaws":["CVE-2026-98432"],"for":[],"kind":"deleted-exe","args":{},"flag":"x"}`,
	} {
		if _, err := Parse([]byte(file)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}
