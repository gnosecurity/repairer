// Package signer is the owner's side of a statement: it writes the memo
// from the files themselves, exactly as the agent will, has gnokey sign it
// without ever broadcasting, and checks the signed result as an agent
// would before handing it on. It also does the checks the owner can't do
// by eye: the pending policy on every machine, from fresh signed reports,
// and every key's name against the owner's own address book.
package signer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
)

// Statement is one owner statement, ready to sign: its call's function and
// arguments, its memo, its chain id and sequence, and how an agent checks
// the signed result.
type Statement struct {
	Func   string
	Args   []string
	Memo   string
	Chain  string
	Seq    uint64
	verify func(tx []byte, owner []byte) error
}

func chainOf(p *policy.Policy) (string, []byte, error) {
	owner, err := hex.DecodeString(p.Signers.Me.Hex)
	if err != nil {
		return "", nil, err
	}
	return approve.ChainID(owner, p.Fleet), owner, nil
}

// PrepareYes readies the owner's Yes to a guard on some tiers of a policy.
func PrepareYes(p *policy.Policy, g *guard.Guard, y approve.Yes, seq uint64) (*Statement, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	for _, t := range y.Tiers {
		if !hasTier(p, t) {
			return nil, fmt.Errorf("signer: the policy has no tier %q", t)
		}
	}
	y.Hash = g.Hash()
	if _, err := approve.ParseYes(approve.Call{Func: "Yes", Args: y.Args()}); err != nil {
		return nil, err
	}
	memo, err := approve.MemoYes(g, y)
	if err != nil {
		return nil, err
	}
	chain, _, err := chainOf(p)
	if err != nil {
		return nil, err
	}
	return &Statement{Func: "Yes", Args: y.Args(), Memo: memo, Chain: chain, Seq: seq,
		verify: func(tx, owner []byte) error {
			got, err := approve.VerifyYes(tx, chain, seq, owner, g)
			if err == nil && strings.Join(got.Args(), "\x00") != strings.Join(y.Args(), "\x00") {
				err = errors.New("signer: the signed Yes says something else")
			}
			return err
		}}, nil
}

// PrepareOff readies the owner's Off for a guard on some hosts of a policy.
func PrepareOff(p *policy.Policy, g *guard.Guard, hosts []string, seq uint64) (*Statement, error) {
	for _, h := range hosts {
		if _, ok := p.TierOf(h); !ok {
			return nil, fmt.Errorf("signer: the policy has no host %q", h)
		}
	}
	o := approve.Off{Hash: g.Hash(), Hosts: hosts}
	if _, err := approve.ParseOff(approve.Call{Func: "Off", Args: o.Args()}); err != nil {
		return nil, err
	}
	memo, err := approve.MemoOff(g, o)
	if err != nil {
		return nil, err
	}
	chain, _, err := chainOf(p)
	if err != nil {
		return nil, err
	}
	return &Statement{Func: "Off", Args: o.Args(), Memo: memo, Chain: chain, Seq: seq,
		verify: func(tx, owner []byte) error {
			got, err := approve.VerifyOff(tx, chain, seq, owner, g)
			if err == nil && strings.Join(got.Hosts, ",") != strings.Join(hosts, ",") {
				err = errors.New("signer: the signed Off names other hosts")
			}
			return err
		}}, nil
}

// PrepareOn readies the owner's On: it lifts an Off for a guard on some
// hosts of a policy.
func PrepareOn(p *policy.Policy, g *guard.Guard, hosts []string, seq uint64) (*Statement, error) {
	for _, h := range hosts {
		if _, ok := p.TierOf(h); !ok {
			return nil, fmt.Errorf("signer: the policy has no host %q", h)
		}
	}
	o := approve.Off{Hash: g.Hash(), Hosts: hosts}
	if _, err := approve.ParseOn(approve.Call{Func: "On", Args: o.Args()}); err != nil {
		return nil, err
	}
	memo, err := approve.MemoOn(g, o)
	if err != nil {
		return nil, err
	}
	chain, _, err := chainOf(p)
	if err != nil {
		return nil, err
	}
	return &Statement{Func: "On", Args: o.Args(), Memo: memo, Chain: chain, Seq: seq,
		verify: func(tx, owner []byte) error {
			got, err := approve.VerifyOn(tx, chain, seq, owner, g)
			if err == nil && strings.Join(got.Hosts, ",") != strings.Join(hosts, ",") {
				err = errors.New("signer: the signed On names other hosts")
			}
			return err
		}}, nil
}

// PreparePolicy readies a policy change: the memo is the full diff against
// the policy it replaces.
func PreparePolicy(old, new *policy.Policy, seq uint64) (*Statement, error) {
	memo, err := approve.MemoPolicy(old, new)
	if err != nil {
		return nil, err
	}
	chain, _, err := chainOf(old)
	if err != nil {
		return nil, err
	}
	return &Statement{Func: "Policy", Args: []string{new.Hash(), old.Hash()}, Memo: memo, Chain: chain, Seq: seq,
		verify: func(tx, owner []byte) error { return approve.VerifyPolicy(tx, chain, seq, owner, old, new) }}, nil
}

func hasTier(p *policy.Policy, name string) bool {
	for _, t := range p.Tiers {
		if t.Name == name {
			return true
		}
	}
	return false
}

// DefaultMode is the mode the tool offers for a Yes: keep when a flaw is on
// CISA's list of exploited flaws, but never on a critical tier, where the
// trial is what catches a guard that cuts what the machine is for.
func DefaultMode(p *policy.Policy, tiers []string, flaws []string, exploited map[string]bool) string {
	for _, t := range p.Tiers {
		for _, name := range tiers {
			if t.Name == name && t.Critical {
				return "undo"
			}
		}
	}
	for _, f := range flaws {
		if exploited[f] {
			return "keep"
		}
	}
	return "undo"
}

// Gnokey has gnokey make and sign a statement. It never broadcasts: maketx
// gets -broadcast=false, and both steps get a remote that can't be reached.
type Gnokey struct {
	Bin  string // the gnokey program
	Home string // gnokey's home; "" for its default
	Key  string // the key's name in gnokey's keybase (a Ledger entry, in use)
	// Password, if set, is written to gnokey's stdin (test keybases only;
	// a Ledger asks on the device).
	Password string
}

// noRemote is where gnokey would send anything, if it ever tried: a closed
// local port, so a mistake fails instead of reaching a node.
const noRemote = "127.0.0.1:1"

// Sign makes the transaction, signs it, checks it as an agent would against
// the owner's key, and returns the signed file.
func (gk Gnokey) Sign(ctx context.Context, st *Statement, owner []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "autopatch-sign")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	args := append([]string{"maketx", "call"}, gk.homeFlag()...)
	args = append(args, "-broadcast=false", "-remote", noRemote,
		// gnokey refuses a zero gas here; the fee is set to zero below,
		// before signing, as the agent rebuilds it.
		"-pkgpath", approve.Realm, "-func", st.Func, "-gas-fee", "1ugnot", "-gas-wanted", "1", "-memo", st.Memo)
	for _, a := range st.Args {
		args = append(args, "-args", a)
	}
	unsigned, err := gk.run(ctx, append(args, gk.Key), false)
	if err != nil {
		return nil, fmt.Errorf("gnokey maketx: %w", err)
	}
	unsigned, err = zeroFee(unsigned)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "tx.json")
	if err := os.WriteFile(path, unsigned, 0o600); err != nil {
		return nil, err
	}
	sargs := append([]string{"sign"}, gk.homeFlag()...)
	sargs = append(sargs, "-remote", noRemote, "-tx-path", path, "-chainid", st.Chain,
		"-account-number", "0", "-account-sequence", strconv.FormatUint(st.Seq, 10))
	if gk.Password != "" {
		sargs = append(sargs, "-insecure-password-stdin")
	}
	if _, err := gk.run(ctx, append(sargs, gk.Key), true); err != nil {
		return nil, fmt.Errorf("gnokey sign: %w", err)
	}
	signed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := st.verify(signed, owner); err != nil {
		return nil, fmt.Errorf("signer: the signed file wouldn't pass an agent: %w", err)
	}
	return signed, nil
}

// zeroFee sets an unsigned transaction's fee to zero: nothing is ever
// broadcast, and the agent rebuilds the sign bytes with a zero fee.
func zeroFee(tx []byte) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(tx, &m); err != nil {
		return nil, fmt.Errorf("gnokey's unsigned transaction: %w", err)
	}
	if _, ok := m["fee"]; !ok {
		return nil, errors.New("gnokey's unsigned transaction has no fee")
	}
	m["fee"] = json.RawMessage(`{"gas_wanted":"0","gas_fee":"0ugnot"}`) // gnokey writes it back as ""
	return json.Marshal(m)
}

func (gk Gnokey) homeFlag() []string {
	if gk.Home == "" {
		return nil
	}
	return []string{"-home", gk.Home}
}

func (gk Gnokey) run(ctx context.Context, args []string, password bool) ([]byte, error) {
	cmd := exec.CommandContext(ctx, gk.Bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if password && gk.Password != "" {
		cmd.Stdin = strings.NewReader(gk.Password + "\n")
	} else {
		cmd.Stdin = os.Stdin // a Ledger confirms on the device; gnokey may print to the terminal
	}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// Message is what the lookout carries to the agents: the sequence and the
// signed transaction file.
type Message struct {
	Seq uint64          `json:"seq"`
	Tx  json.RawMessage `json:"tx"`
}

// MessageFile writes the message for a signed statement.
func MessageFile(seq uint64, tx []byte) ([]byte, error) {
	var compact bytes.Buffer
	if err := json.Compact(&compact, tx); err != nil {
		return nil, err
	}
	return json.Marshal(Message{Seq: seq, Tx: compact.Bytes()})
}

// readAll reads at most n bytes of a file the lookout handed over.
func readAll(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, n+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > n {
		return nil, fmt.Errorf("%s is more than %d bytes", path, n)
	}
	return b, nil
}

// ReportFresh is how old a report may be for the pending-policy check.
const ReportFresh = 15 * time.Minute

// reportBody is the part of an agent's signed report this tool reads.
type reportBody struct {
	Kind    string    `json:"kind"`
	Chain   string    `json:"chain"`
	Host    string    `json:"host"`
	Time    time.Time `json:"time"`
	Policy  string    `json:"policy"`
	Pending *struct {
		Hash      string    `json:"hash"`
		FirstSeen time.Time `json:"first_seen"`
	} `json:"pending"`
	OwnerSeq uint64   `json:"owner_seq"`
	Off      []string `json:"off"`
}

// Checked is what the reports say, for the owner to read before signing.
type Checked struct {
	Lines    []string // one per machine
	Pending  bool     // some machine has a policy change pending
	OwnerSeq uint64   // the highest owner sequence any agent has accepted
	// Off holds, for each machine, the guards the owner took off there.
	Off map[string][]string
}

// CheckReports reads each machine's signed report from dir (<host>.json),
// checked only against the agent keys in keysFrom: the newest policy the
// owner signed with this tool. A machine without a fresh, valid report must
// be one the owner named in unchecked; otherwise the check fails, so a
// lookout can't hide a pending policy by withholding a report.
func CheckReports(dir string, keysFrom *policy.Policy, unchecked []string, now time.Time) (*Checked, error) {
	chain, _, err := chainOf(keysFrom)
	if err != nil {
		return nil, err
	}
	named := map[string]bool{}
	for _, h := range unchecked {
		if _, ok := keysFrom.TierOf(h); !ok {
			return nil, fmt.Errorf("signer: -unchecked names %q, which isn't a host of the policy", h)
		}
		named[h] = true
	}
	c := &Checked{}
	var missing []string
	for _, k := range keysFrom.Signers.Agents {
		line, r, err := checkOne(dir, k, chain, now)
		if err != nil {
			if named[k.Host] {
				c.Lines = append(c.Lines, k.Host+": not checked ("+err.Error()+"); you named it")
				continue
			}
			missing = append(missing, k.Host+" ("+err.Error()+")")
			continue
		}
		if named[k.Host] {
			return nil, fmt.Errorf("signer: %s has a fresh report; don't name it in -unchecked", k.Host)
		}
		c.Lines = append(c.Lines, line)
		if r.Pending != nil {
			c.Pending = true
		}
		if len(r.Off) > 0 {
			if c.Off == nil {
				c.Off = map[string][]string{}
			}
			c.Off[k.Host] = r.Off
		}
		c.OwnerSeq = max(c.OwnerSeq, r.OwnerSeq)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("signer: no fresh signed report from %s; fetch them, or name each machine in -unchecked", strings.Join(missing, ", "))
	}
	return c, nil
}

func checkOne(dir string, k policy.Key, chain string, now time.Time) (string, *reportBody, error) {
	b, err := readAll(filepath.Join(dir, k.Host+".json"), 16<<20)
	if err != nil {
		return "", nil, err
	}
	body, err := approve.VerifyReport(b, k.Hex)
	if err != nil {
		return "", nil, err
	}
	var r reportBody
	if err := json.Unmarshal(body, &r); err != nil {
		return "", nil, err
	}
	switch {
	case r.Kind != "report" || r.Chain != chain || r.Host != k.Host:
		return "", nil, errors.New("the report is for another machine or fleet")
	case now.Sub(r.Time) > ReportFresh:
		return "", nil, fmt.Errorf("the report is %s old", now.Sub(r.Time).Round(time.Minute))
	case r.Time.After(now.Add(time.Minute)):
		return "", nil, errors.New("the report is from the future")
	}
	line := fmt.Sprintf("%s: policy %.16s in force", k.Host, r.Policy)
	if r.Pending != nil {
		line += fmt.Sprintf("; policy %.16s PENDING since %s", r.Pending.Hash, r.Pending.FirstSeen.UTC().Format(time.RFC3339))
	}
	return line, &r, nil
}

// Book is the owner's own address book: the names they use for keys, and
// each key's hex. It lives on the owner's machine, never with the lookout.
type Book map[string]string

// CheckBook compares every key a policy names with the address book. A name
// the book has with another key, a key the book has under another name, or
// a name the book lacks is refused unless the owner confirms it; confirmed
// entries are returned, to be added to the book.
func CheckBook(book Book, p *policy.Policy, confirm bool) (Book, []string, error) {
	add := Book{}
	var notes []string
	byHex := map[string]string{}
	for name, h := range book {
		byHex[h] = name
	}
	keys := []policy.Key{p.Signers.Me}
	for _, role := range [][]policy.Key{p.Signers.Rig, p.Signers.Vetters, p.Signers.Model, p.Signers.Builders, p.Signers.Agents} {
		keys = append(keys, role...)
	}
	var bad []string
	for _, k := range keys {
		switch have, ok := book[k.Name]; {
		case ok && have != k.Hex:
			bad = append(bad, fmt.Sprintf("%s is %s in your book but %s in the policy", k.Name, short(have), short(k.Hex)))
		case !ok && byHex[k.Hex] != "":
			bad = append(bad, fmt.Sprintf("key %s is %s in your book but %s in the policy", short(k.Hex), byHex[k.Hex], k.Name))
		case !ok:
			if !confirm {
				bad = append(bad, fmt.Sprintf("%s (%s) isn't in your book", k.Name, k.Hex))
			} else {
				add[k.Name] = k.Hex
				notes = append(notes, fmt.Sprintf("adding %s = %s to your book", k.Name, k.Hex))
			}
		}
	}
	if len(bad) > 0 && !confirm {
		return nil, nil, fmt.Errorf("signer: the policy's keys don't match your address book: %s; check each one, then pass -confirm-keys", strings.Join(bad, "; "))
	}
	if confirm {
		for _, b := range bad {
			notes = append(notes, "CONFIRMED BY YOU: "+b)
		}
	}
	return add, notes, nil
}

func short(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:8] + "…" + h[len(h)-8:]
}
