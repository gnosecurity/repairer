package guard

import (
	"os"
	"strings"
	"testing"
)

func readOne(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/cve-2026-98432.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseGuardOne(t *testing.T) {
	g, err := Parse(readOne(t))
	if err != nil {
		t.Fatal(err)
	}
	if g.Name() != "cve-2026-98432/linux-ipv4-ipopt v1" {
		t.Errorf("name %q", g.Name())
	}
	if len(g.Blocks) != 2 || g.Blocks[0].Kind() != "drop" || g.Blocks[1].Kind() != "setting" {
		t.Fatalf("blocks %+v", g.Blocks)
	}
	if got := g.Blocks[0].Describe(); got != "drop inbound ipv4 tcp carrying IP options" {
		t.Errorf("describe %q", got)
	}
	if e := g.Blocks[1].Effect(); e != NewSockets {
		t.Errorf("mptcp effect %q", e)
	}
}

// The hash is over the canonical form, so the same guard written another
// way (spacing, key order) has the same hash, and any change of meaning
// changes it.
func TestHashCanonical(t *testing.T) {
	a, err := Parse(readOne(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(`{"version":1,"id":"cve-2026-98432/linux-ipv4-ipopt","flaws":["CVE-2026-98432"],` +
		`"for":[{"releases":["22.04","24.04","26.04"],"os":"ubuntu"},{"os":"debian","releases":["12","13"]}],` +
		`"blocks":[{"drop":{"protocol":"tcp","family":"ipv4","ip_options":true}},{"setting":{"value":"0","name":"net.mptcp.enabled"}}],` +
		`"breaks":"IP Record Route and Timestamp on TCP; nothing common uses them",` +
		`"until":[{"os":"ubuntu","release":"22.04","kernel":"5.15.0-203.213"},{"os":"ubuntu","release":"24.04","kernel":"6.8.0-149.149"},{"os":"ubuntu","release":"26.04","kernel":"7.0.0-43.43"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash() != b.Hash() {
		t.Fatalf("same guard, different hashes: %s %s", a.Hash(), b.Hash())
	}
	b.Version = 2
	if a.Hash() == b.Hash() {
		t.Fatal("a new version has the same hash")
	}
	if len(a.Hash()) != 64 {
		t.Fatalf("hash %q", a.Hash())
	}
}

// edit returns guard number one's JSON with one substring replaced.
func edit(t *testing.T, from, to string) []byte {
	t.Helper()
	s := string(readOne(t))
	if !strings.Contains(s, from) {
		t.Fatalf("test fixture lacks %q", from)
	}
	return []byte(strings.Replace(s, from, to, 1))
}

func TestRefusals(t *testing.T) {
	drop := `{"drop": {"family": "ipv4", "protocol": "tcp", "ip_options": true}}`
	cases := []struct {
		name, from, to, want string
	}{
		{"unknown field", `"version": 1,`, `"version": 1, "run": "sh",`, "unknown field"},
		{"unknown field in a list", `"blocks": [`, `"blocks": [], "x": [`, "unknown field"},
		{"two kinds in a block", drop, `{"drop": {"family": "ipv4", "protocol": "tcp", "ip_options": true}, "module": {"name": "ksmbd"}}`, "exactly one"},
		{"empty block", drop, `{}`, "exactly one"},
		{"too broad", drop, `{"drop": {"family": "ipv4", "protocol": "tcp"}}`, "too broad"},
		{"syn alone is too broad", drop, `{"drop": {"family": "ipv4", "protocol": "tcp", "syn": true}}`, "too broad"},
		{"ssh by port", drop, `{"drop": {"family": "ipv4", "protocol": "tcp", "ports": ["20-30"]}}`, "port 22"},
		{"bad port", drop, `{"drop": {"family": "ipv4", "protocol": "tcp", "ports": ["0443"]}}`, "port"},
		{"reversed range", drop, `{"drop": {"family": "ipv4", "protocol": "tcp", "ports": ["139-137"]}}`, "port"},
		{"ports without protocol", drop, `{"drop": {"family": "ipv4", "ports": ["445"]}}`, "ports need"},
		{"options on ipv6", drop, `{"drop": {"family": "ipv6", "protocol": "tcp", "ip_options": true}}`, "ipv4 only"},
		{"icmp on ipv6", drop, `{"drop": {"family": "ipv6", "protocol": "icmp", "ports": ["1"]}}`, "icmp is ipv4"},
		{"unknown family", drop, `{"drop": {"family": "inet", "protocol": "tcp", "ip_options": true}}`, "family"},
		{"setting not listed", `"net.mptcp.enabled"`, `"kernel.panic_on_oops"`, "not on the agent's list"},
		{"setting wrong value", `"value": "0"`, `"value": "1"`, "may only be set"},
		{"module never blocked", drop, `{"module": {"name": "nf_tables"}}`, "never blocked"},
		{"module bad name", drop, `{"module": {"name": "ksmbd; rm"}}`, "not a module name"},
		{"service never stopped", drop, `{"service": {"unit": "ssh.service"}}`, "never-touch"},
		{"updater never stopped", drop, `{"service": {"unit": "unattended-upgrades.service"}}`, "never-touch"},
		{"certbot never stopped", drop, `{"service": {"unit": "certbot.timer"}}`, "never-touch"},
		{"service bad name", drop, `{"service": {"unit": "../x.service"}}`, "not a unit name"},
		{"strip sudo", drop, `{"strip": {"path": "/usr/bin/sudo"}}`, "never-touch"},
		{"strip relative", drop, `{"strip": {"path": "usr/bin/pkexec"}}`, "plain absolute path"},
		{"strip dot-dot", drop, `{"strip": {"path": "/usr/bin/../../etc/shadow"}}`, "plain absolute path"},
		{"strip outside", drop, `{"strip": {"path": "/etc/shadow"}}`, "outside"},
		{"bad id", `"cve-2026-98432/linux-ipv4-ipopt"`, `"CVE 2026"`, "guard id"},
		{"bad flaw", `["CVE-2026-98432"]`, `["remote root"]`, "flaw"},
		{"no flaw", `["CVE-2026-98432"]`, `[]`, "flaws"},
		{"version zero", `"version": 1`, `"version": 0`, "version"},
		{"bad until", `"kernel": "6.8.0-149.149"`, `"kernel": "$(id)"`, "until"},
		{"bad release", `"releases": ["12", "13"]`, `"releases": ["bookworm"]`, "release"},
		{"no breaks", `"breaks": "IP Record Route and Timestamp on TCP; nothing common uses them"`, `"breaks": ""`, "breaks"},
		{"control character", `nothing common uses them"`, `nothing\u0007 common uses them"`, "breaks"},
		{"same block twice", `{"setting": {"name": "net.mptcp.enabled", "value": "0"}}`, `{"setting": {"name": "net.mptcp.enabled", "value": "0"}}, {"setting": {"name": "net.mptcp.enabled", "value": "0"}}`, "twice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(edit(t, c.from, c.to))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q lacks %q", err, c.want)
			}
		})
	}
}

func TestNoBlocks(t *testing.T) {
	g, err := Parse(readOne(t))
	if err != nil {
		t.Fatal(err)
	}
	g.Blocks = nil
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "blocks") {
		t.Fatalf("err %v", err)
	}
}

func TestTrailingData(t *testing.T) {
	if _, err := Parse(append(readOne(t), []byte(`{"id":"x"}`)...)); err == nil {
		t.Fatal("accepted a second guard after the first")
	}
}

func TestTooBig(t *testing.T) {
	b := append(readOne(t), make([]byte, MaxSize)...)
	if _, err := Parse(b); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err %v", err)
	}
}

func TestAutoLists(t *testing.T) {
	cases := []struct {
		b    Block
		auto bool
	}{
		{Block{Module: &Module{Name: "ksmbd"}}, true},
		{Block{Module: &Module{Name: "can-raw"}}, true}, // '-' and '_' alike
		{Block{Module: &Module{Name: "usb_storage"}}, false},
		{Block{Service: &Service{Unit: "cups-browsed.service"}}, true},
		{Block{Service: &Service{Unit: "exim4.service"}}, false},
		{Block{Setting: &Setting{Name: "net.mptcp.enabled", Value: "0"}}, true},
	}
	for _, c := range cases {
		if got := c.b.Auto(); got != c.auto {
			t.Errorf("%s: auto %v", c.b.Describe(), got)
		}
	}
}

func TestFitsAndFixRunning(t *testing.T) {
	g, err := Parse(readOne(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		s              System
		fits           bool
		fixed, decided bool
	}{
		{System{OS: "ubuntu", Release: "24.04", Kernel: "6.8.0-142.142", Flavour: "generic"}, true, false, true},
		{System{OS: "ubuntu", Release: "24.04", Kernel: "6.8.0-149.149", Flavour: "generic"}, true, true, true},
		{System{OS: "ubuntu", Release: "24.04", Kernel: "6.8.0-150.150", Flavour: "generic"}, true, true, true},
		{System{OS: "ubuntu", Release: "26.04", Kernel: "7.0.0-42.42", Flavour: "generic"}, true, false, true},
		// Other flavours number their builds differently: undecided.
		{System{OS: "ubuntu", Release: "24.04", Kernel: "6.8.0-1021.23", Flavour: "aws"}, true, false, false},
		// No fixed build named for Debian: undecided.
		{System{OS: "debian", Release: "13", Kernel: "6.12.48-1"}, true, false, false},
		{System{OS: "ubuntu", Release: "20.04", Kernel: "5.4.0-200.220", Flavour: "generic"}, false, false, false},
		{System{OS: "fedora", Release: "43"}, false, false, false},
		{System{OS: "ubuntu", Release: "24.04"}, true, false, false},
	}
	for _, c := range cases {
		if got := g.Fits(c.s); got != c.fits {
			t.Errorf("%+v: fits %v", c.s, got)
		}
		fixed, decided := g.FixRunning(c.s)
		if fixed != c.fixed || decided != c.decided {
			t.Errorf("%+v: fixed %v decided %v", c.s, fixed, decided)
		}
	}
}
