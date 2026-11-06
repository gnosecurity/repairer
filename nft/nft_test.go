package nft

import (
	"os"
	"strings"
	"testing"

	"github.com/gnosecurity/repairer/guard"
)

func guardOne(t *testing.T) *guard.Guard {
	t.Helper()
	b, err := os.ReadFile("../guard/testdata/cve-2026-98432.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := guard.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// Guard number one's table holds the rule first written by hand for
// CVE-2026-98432, in a table of its own.
func TestScriptGuardOne(t *testing.T) {
	g := guardOne(t)
	tables := Tables(g)
	if len(tables) != 1 || len(tables["ip"]) != 1 {
		t.Fatalf("tables %v", tables)
	}
	name := TableName(g.Hash())
	got, err := Script("ip", name, g.Name(), tables["ip"])
	if err != nil {
		t.Fatal(err)
	}
	want := "table ip " + name + "\n" +
		"delete table ip " + name + "\n" +
		"table ip " + name + " {\n" +
		"\tchain in {\n" +
		"\t\ttype filter hook prerouting priority -300; policy accept;\n" +
		"\t\tip protocol tcp ip hdrlength gt 5 counter drop comment \"cve-2026-98432/linux-ipv4-ipopt v1\"\n" +
		"\t}\n}\n"
	if got != want {
		t.Fatalf("script:\n%s\nwant:\n%s", got, want)
	}
}

func TestRules(t *testing.T) {
	cases := []struct {
		d    guard.Drop
		want string
	}{
		{guard.Drop{Family: "ipv4", Protocol: "tcp", Ports: []string{"445"}}, "ip protocol tcp tcp dport 445 counter drop"},
		{guard.Drop{Family: "ipv4", Protocol: "udp", Ports: []string{"137-139", "5353"}}, "ip protocol udp udp dport { 137-139, 5353 } counter drop"},
		{guard.Drop{Family: "ipv4", Protocol: "tcp", Ports: []string{"8080"}, SYN: true}, "ip protocol tcp tcp dport 8080 tcp flags & (syn | ack) == syn counter drop"},
		{guard.Drop{Family: "ipv6", Protocol: "udp", Ports: []string{"5353"}}, "meta l4proto 17 udp dport 5353 counter drop"},
		{guard.Drop{Family: "ipv4", IPOptions: true}, "ip hdrlength gt 5 counter drop"},
	}
	for _, c := range cases {
		got, err := Rule(&c.d)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("rule %q, want %q", got, c.want)
		}
	}
}

func TestScriptRefusesOddComment(t *testing.T) {
	d := []*guard.Drop{{Family: "ipv4", IPOptions: true}}
	for _, c := range []string{`x" ; flush ruleset ; "`, "", strings.Repeat("a", 101), "UPPER"} {
		if _, err := Script("ip", TableName(strings.Repeat("0", 64)), c, d); err == nil {
			t.Errorf("comment %q accepted", c)
		}
	}
}

// A trimmed copy of `nft -j list table ip repairer_…` from nftables 1.0.9.
const listJSON = `{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
{"table": {"family": "ip", "name": "repairer_0123456789ab", "handle": 7}},
{"chain": {"family": "ip", "table": "repairer_0123456789ab", "name": "in", "handle": 1, "type": "filter", "hook": "prerouting", "prio": -300, "policy": "accept"}},
{"rule": {"family": "ip", "table": "repairer_0123456789ab", "chain": "in", "handle": 2, "comment": "cve-2026-98432/linux-ipv4-ipopt v1",
 "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "protocol"}}, "right": "tcp"}},
          {"match": {"op": ">", "left": {"payload": {"protocol": "ip", "field": "hdrlength"}}, "right": 5}},
          {"counter": {"packets": 3, "bytes": 180}}, {"drop": null}]}}]}`

func TestParseList(t *testing.T) {
	lt, err := ParseList([]byte(listJSON), "repairer_0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	if lt.Hook != "prerouting" || lt.Priority != -300 || len(lt.Rules) != 1 {
		t.Fatalf("%+v", lt)
	}
	if lt.Rules[0].Packets != 3 || lt.Rules[0].Comment != "cve-2026-98432/linux-ipv4-ipopt v1" {
		t.Fatalf("%+v", lt.Rules[0])
	}
	if _, err := ParseList([]byte(listJSON), "repairer_other"); err == nil {
		t.Fatal("found a chain in the wrong table")
	}
}
