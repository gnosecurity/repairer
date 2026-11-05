// Package nft writes the nftables tables that hold a guard's drops, and
// reads their counters back.
//
// Every word of a rule comes from a guard's typed fields, already checked
// by package guard: families and protocols from fixed lists, ports as
// numbers, the comment from the guard's checked ID. Each guard gets a table
// of its own per family, hooked at prerouting priority -300 (before
// connection tracking), whose base chain only ever drops; its "accept"
// policy lets other packets go on to every other table as before.
package nft

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jaekwon/autopatch/guard"
)

// Priority is where a guard's chain hooks in: the "raw" priority, before
// connection tracking and every ordinary filter table.
const Priority = -300

// Chain is the name of the base chain in each guard table.
const Chain = "in"

// Family returns nft's family for a drop's family: "ip" or "ip6".
func Family(f string) string {
	if f == "ipv6" {
		return "ip6"
	}
	return "ip"
}

// TableName returns the name of a guard's table: "autopatch_" and the
// guard's whole hash. A shorter name would let a guard ground to share a
// prefix with another replace that guard's table.
func TableName(guardHash string) string {
	if len(guardHash) != 64 {
		panic("nft: a guard hash is 64 hex digits")
	}
	return "autopatch_" + guardHash
}

// Rule returns the rule for one drop, without its comment.
func Rule(d *guard.Drop) (string, error) {
	var w []string
	switch d.Family {
	case "ipv4":
		if d.Protocol != "" {
			w = append(w, "ip protocol "+d.Protocol)
		}
		if d.IPOptions {
			w = append(w, "ip hdrlength gt 5")
		}
	case "ipv6":
		if d.Protocol != "" {
			n, ok := map[string]int{"tcp": 6, "udp": 17, "icmpv6": 58}[d.Protocol]
			if !ok {
				return "", fmt.Errorf("nft: protocol %q in ipv6", d.Protocol)
			}
			// meta l4proto sees past IPv6 extension headers.
			w = append(w, "meta l4proto "+strconv.Itoa(n))
		}
	default:
		return "", fmt.Errorf("nft: family %q", d.Family)
	}
	ranges, err := d.PortRanges()
	if err != nil {
		return "", err
	}
	if len(ranges) > 0 {
		var ps []string
		for _, r := range ranges {
			if r[0] == r[1] {
				ps = append(ps, strconv.Itoa(r[0]))
			} else {
				ps = append(ps, strconv.Itoa(r[0])+"-"+strconv.Itoa(r[1]))
			}
		}
		set := ps[0]
		if len(ps) > 1 {
			set = "{ " + strings.Join(ps, ", ") + " }"
		}
		w = append(w, d.Protocol+" dport "+set)
	}
	if d.SYN {
		w = append(w, "tcp flags & (syn | ack) == syn")
	}
	w = append(w, "counter", "drop")
	return strings.Join(w, " "), nil
}

// Tables returns, per nft family, the drops of a guard in that family.
func Tables(g *guard.Guard) map[string][]*guard.Drop {
	out := map[string][]*guard.Drop{}
	for _, b := range g.Blocks {
		if b.Drop != nil {
			f := Family(b.Drop.Family)
			out[f] = append(out[f], b.Drop)
		}
	}
	return out
}

// Script returns an nft script that replaces the guard's table in one
// family with one holding the given drops, in one transaction: the first
// line makes the table if it is missing, so that deleting it can't fail.
func Script(family, table, comment string, drops []*guard.Drop) (string, error) {
	if !safeComment(comment) {
		return "", fmt.Errorf("nft: comment %q", comment)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table %s %s\n", family, table)
	fmt.Fprintf(&b, "delete table %s %s\n", family, table)
	fmt.Fprintf(&b, "table %s %s {\n", family, table)
	fmt.Fprintf(&b, "\tchain %s {\n", Chain)
	fmt.Fprintf(&b, "\t\ttype filter hook prerouting priority %d; policy accept;\n", Priority)
	for _, d := range drops {
		r, err := Rule(d)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "\t\t%s comment %q\n", r, comment)
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}

// DeleteScript returns an nft script that removes a guard's table in one
// family if it is there.
func DeleteScript(family, table string) string {
	return fmt.Sprintf("table %s %s\ndelete table %s %s\n", family, table, family, table)
}

// safeComment admits what a guard ID and version can produce.
func safeComment(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("._-/ v", c)) {
			return false
		}
	}
	return true
}

// LiveRule is one rule of a guard table as nft lists it.
type LiveRule struct {
	Comment string
	Packets uint64
}

// LiveTable is what nft says a guard table holds now.
type LiveTable struct {
	Hook     string
	Priority int
	Rules    []LiveRule
}

// ParseList reads `nft -j list table <family> <table>` and returns the
// table's base chain and its rules' counters.
func ParseList(out []byte, table string) (*LiveTable, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("nft: reading its json: %w", err)
	}
	lt := &LiveTable{}
	found := false
	for _, item := range doc.Nftables {
		if raw, ok := item["chain"]; ok {
			var c struct {
				Table string `json:"table"`
				Name  string `json:"name"`
				Hook  string `json:"hook"`
				Prio  int    `json:"prio"`
			}
			if err := json.Unmarshal(raw, &c); err != nil {
				return nil, fmt.Errorf("nft: reading a chain: %w", err)
			}
			if c.Table == table && c.Name == Chain {
				lt.Hook, lt.Priority, found = c.Hook, c.Prio, true
			}
		}
		if raw, ok := item["rule"]; ok {
			var r struct {
				Table   string                       `json:"table"`
				Chain   string                       `json:"chain"`
				Comment string                       `json:"comment"`
				Expr    []map[string]json.RawMessage `json:"expr"`
			}
			if err := json.Unmarshal(raw, &r); err != nil {
				return nil, fmt.Errorf("nft: reading a rule: %w", err)
			}
			if r.Table != table || r.Chain != Chain {
				continue
			}
			lr := LiveRule{Comment: r.Comment}
			for _, e := range r.Expr {
				if raw, ok := e["counter"]; ok {
					var cnt struct {
						Packets uint64 `json:"packets"`
					}
					if err := json.Unmarshal(raw, &cnt); err != nil {
						return nil, fmt.Errorf("nft: reading a counter: %w", err)
					}
					lr.Packets = cnt.Packets
				}
			}
			lt.Rules = append(lt.Rules, lr)
		}
	}
	if !found {
		return nil, errors.New("nft: the table has no base chain " + Chain)
	}
	return lt, nil
}
