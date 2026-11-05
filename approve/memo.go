package approve

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
)

// MaxMemo caps a memo, so that every statement stays small enough for a
// Ledger to sign.
const MaxMemo = 600

var (
	tierRe = regexp.MustCompile(`^[A-Za-z0-9]{1,8}$`)
	hostRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`) // as policy names hosts
)

// Yes is an owner's yes to a guard: on these tiers, until a time, with its
// undo kept or not.
type Yes struct {
	Hash  string    // the guard's full hash
	Tiers []string  // tier names, such as A and B
	Until time.Time // when the yes ends, to the second, in UTC
	Mode  string    // "undo" or "keep"
	// NoCanary lets this guard go on every machine of the tiers at once,
	// without waiting for a canary's Healthy.
	NoCanary bool
}

// mode is the Yes's mode as signed: "undo" or "keep", with "+nocanary".
func (y Yes) mode() string {
	if y.NoCanary {
		return y.Mode + "+nocanary"
	}
	return y.Mode
}

// Args are the Yes's arguments as signed: hash, tiers joined by commas, the
// end as Unix seconds, and the mode.
func (y Yes) Args() []string {
	return []string{y.Hash, strings.Join(y.Tiers, ","), strconv.FormatInt(y.Until.Unix(), 10), y.mode()}
}

// ParseYes reads a Yes from a statement's call, strictly.
func ParseYes(c Call) (Yes, error) {
	if c.Func != "Yes" || len(c.Args) != 4 {
		return Yes{}, errors.New("approve: not a Yes with four arguments")
	}
	mode, nocanary := strings.CutSuffix(c.Args[3], "+nocanary")
	y := Yes{Hash: c.Args[0], Mode: mode, NoCanary: nocanary}
	if !isHash(y.Hash) {
		return Yes{}, fmt.Errorf("approve: %q is not a guard hash", y.Hash)
	}
	y.Tiers = strings.Split(c.Args[1], ",")
	seen := map[string]bool{}
	for _, t := range y.Tiers {
		if !tierRe.MatchString(t) || seen[t] {
			return Yes{}, fmt.Errorf("approve: tiers %q", c.Args[1])
		}
		seen[t] = true
	}
	secs, err := strconv.ParseInt(c.Args[2], 10, 64)
	if err != nil || secs <= 0 || strconv.FormatInt(secs, 10) != c.Args[2] {
		return Yes{}, fmt.Errorf("approve: end %q is not Unix seconds", c.Args[2])
	}
	y.Until = time.Unix(secs, 0).UTC()
	if y.Mode != "undo" && y.Mode != "keep" {
		return Yes{}, fmt.Errorf("approve: mode %q is not undo or keep", y.Mode)
	}
	return y, nil
}

func isHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// MemoYes writes the memo for a Yes, in words, from the guard itself: its ID
// and version, the first 16 digits of its hash, each block as the agent
// describes it, the tiers, the end and the mode. The signing tool shows it
// and the Ledger shows it again; the agent writes it the same way and
// refuses a statement whose memo differs by a byte. One line, printable
// ASCII, at most MaxMemo bytes.
func MemoYes(g *guard.Guard, y Yes) (string, error) {
	if g.Hash() != y.Hash {
		return "", errors.New("approve: the Yes names another guard")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s Yes %s %s:", MemoVersion, g.Name(), y.Hash[:16])
	for _, bl := range g.Blocks {
		b.WriteString(" " + bl.Describe() + ";")
	}
	fmt.Fprintf(&b, " tiers %s; until %s; mode %s", strings.Join(y.Tiers, ","), y.Until.UTC().Format(time.RFC3339), y.mode())
	return checkMemo(b.String())
}

// Off takes a guard off the hosts it names and keeps it off there; On lifts
// that on the hosts it names. A Yes never lifts an Off. Both statements
// have this shape: a guard's hash and some hosts.
type Off struct {
	Hash  string
	Hosts []string
}

// Args are the Off's arguments as signed: the hash and the hosts joined by
// commas.
func (o Off) Args() []string { return []string{o.Hash, strings.Join(o.Hosts, ",")} }

// Names reports whether the Off names a host.
func (o Off) Names(host string) bool {
	for _, h := range o.Hosts {
		if h == host {
			return true
		}
	}
	return false
}

// ParseOff reads an Off from a statement's call, strictly.
func ParseOff(c Call) (Off, error) { return parseHosts("Off", c) }

// ParseOn reads an On from a statement's call, strictly.
func ParseOn(c Call) (Off, error) { return parseHosts("On", c) }

func parseHosts(fn string, c Call) (Off, error) {
	if c.Func != fn || len(c.Args) != 2 {
		return Off{}, fmt.Errorf("approve: not an %s with two arguments", fn)
	}
	o := Off{Hash: c.Args[0], Hosts: strings.Split(c.Args[1], ",")}
	if !isHash(o.Hash) {
		return Off{}, fmt.Errorf("approve: %q is not a guard hash", o.Hash)
	}
	seen := map[string]bool{}
	for _, h := range o.Hosts {
		if !hostRe.MatchString(h) || seen[h] {
			return Off{}, fmt.Errorf("approve: hosts %q", c.Args[1])
		}
		seen[h] = true
	}
	return o, nil
}

// MemoOff writes the memo for taking a guard off some hosts.
func MemoOff(g *guard.Guard, o Off) (string, error) { return memoHosts("Off", g, o) }

// MemoOn writes the memo for lifting an Off on some hosts.
func MemoOn(g *guard.Guard, o Off) (string, error) { return memoHosts("On", g, o) }

func memoHosts(fn string, g *guard.Guard, o Off) (string, error) {
	if g.Hash() != o.Hash {
		return "", fmt.Errorf("approve: the %s names another guard", fn)
	}
	return checkMemo(fmt.Sprintf("%s %s %s %s: hosts %s", MemoVersion, fn, g.Name(), o.Hash[:16], strings.Join(o.Hosts, ",")))
}

// VerifyOff checks an owner's Off for guard g in gnokey's signed transaction
// file, as VerifyYes does for a Yes.
func VerifyOff(txJSON []byte, chainID string, seq uint64, ownerPub []byte, g *guard.Guard) (Off, error) {
	return verifyHosts("Off", txJSON, chainID, seq, ownerPub, g)
}

// VerifyOn checks an owner's On for guard g, as VerifyOff does.
func VerifyOn(txJSON []byte, chainID string, seq uint64, ownerPub []byte, g *guard.Guard) (Off, error) {
	return verifyHosts("On", txJSON, chainID, seq, ownerPub, g)
}

func verifyHosts(fn string, txJSON []byte, chainID string, seq uint64, ownerPub []byte, g *guard.Guard) (Off, error) {
	var tx GnokeyTx
	if err := json.Unmarshal(txJSON, &tx); err != nil || len(tx.Msg) != 1 {
		return Off{}, errors.New("approve: not one message")
	}
	m := tx.Msg[0]
	o, err := parseHosts(fn, Call{Caller: m.Caller, Func: m.Func, Args: m.Args})
	if err != nil {
		return Off{}, err
	}
	memo, err := memoHosts(fn, g, o)
	if err != nil {
		return Off{}, err
	}
	if _, err := VerifyGnokey(txJSON, chainID, seq, ownerPub, memo); err != nil {
		return Off{}, err
	}
	return o, nil
}

func checkMemo(m string) (string, error) {
	if len(m) > MaxMemo {
		return "", fmt.Errorf("approve: the memo is %d bytes, more than a Ledger statement allows (%d); split it into smaller steps", len(m), MaxMemo)
	}
	for i := 0; i < len(m); i++ {
		if m[i] < 0x20 || m[i] > 0x7e {
			return "", fmt.Errorf("approve: the memo has a character a Ledger may not show (byte %d)", i)
		}
	}
	return m, nil
}

// VerifyYes checks an owner's Yes to guard g in gnokey's signed transaction
// file: the arguments are read from the file, the memo is rewritten from the
// guard and those arguments, and the signature must cover both.
func VerifyYes(txJSON []byte, chainID string, seq uint64, ownerPub []byte, g *guard.Guard) (Yes, error) {
	var tx GnokeyTx
	if err := json.Unmarshal(txJSON, &tx); err != nil || len(tx.Msg) != 1 {
		return Yes{}, errors.New("approve: not one message")
	}
	m := tx.Msg[0]
	y, err := ParseYes(Call{Caller: m.Caller, Func: m.Func, Args: m.Args})
	if err != nil {
		return Yes{}, err
	}
	memo, err := MemoYes(g, y)
	if err != nil {
		return Yes{}, err
	}
	if _, err := VerifyGnokey(txJSON, chainID, seq, ownerPub, memo); err != nil {
		return Yes{}, err
	}
	return y, nil
}

// MemoCancel writes the memo for cancelling a pending policy change.
func MemoCancel(fleet, pending string) (string, error) {
	if !isHash(pending) {
		return "", errors.New("approve: Cancel names a policy by its hash")
	}
	return checkMemo(fmt.Sprintf("%s Cancel %s %s", MemoVersion, fleet, pending[:16]))
}

// MemoVersion starts every memo, so that a release can change the memo
// format without the agents and signing tools of one fleet disagreeing.
const MemoVersion = "autopatch/1"

// MemoPolicy writes a policy change's memo: the full diff, field by field,
// against the policy it replaces. A key the change adds shows its owner's
// name for it and all of its hex; the signing tool also checks every key
// against its own address book and refuses a name or key that doesn't
// match it unless the owner confirms the change.
// A diff too big for a Ledger is refused, so a big change goes in steps.
func MemoPolicy(old, new *policy.Policy) (string, error) {
	if new.Replaces != old.Hash() {
		return "", errors.New("approve: the new policy doesn't replace this one")
	}
	if new.Fleet != old.Fleet {
		return "", errors.New("approve: a policy can't move to another fleet")
	}
	var d []string
	if old.DelaySeconds != new.DelaySeconds {
		d = append(d, fmt.Sprintf("delay %ds->%ds", old.DelaySeconds, new.DelaySeconds))
	}
	d = append(d, keysDiff("me", []policy.Key{old.Signers.Me}, []policy.Key{new.Signers.Me})...)
	d = append(d, keysDiff("rig", old.Signers.Rig, new.Signers.Rig)...)
	d = append(d, keysDiff("vetters", old.Signers.Vetters, new.Signers.Vetters)...)
	if old.Signers.VettersNeeded != new.Signers.VettersNeeded {
		d = append(d, fmt.Sprintf("vetters needed %d->%d", old.Signers.VettersNeeded, new.Signers.VettersNeeded))
	}
	d = append(d, keysDiff("model", old.Signers.Model, new.Signers.Model)...)
	d = append(d, keysDiff("builders", old.Signers.Builders, new.Signers.Builders)...)
	d = append(d, keysDiff("agents", old.Signers.Agents, new.Signers.Agents)...)
	d = append(d, listDiff("rig build", old.Rigs, new.Rigs)...)
	d = append(d, listDiff("tier", tierLines(old), tierLines(new))...)
	d = append(d, listDiff("protected", flowLines(old), flowLines(new))...)
	d = append(d, listDiff("health", healthLines(old), healthLines(new))...)
	if len(d) == 0 {
		return "", errors.New("approve: the new policy changes nothing")
	}
	return checkMemo(fmt.Sprintf("%s Policy %s %s replaces %s: %s", MemoVersion, new.Fleet, new.Hash()[:16], old.Hash()[:16], strings.Join(d, "; ")))
}

func keyLine(k policy.Key) string {
	s := k.Name + " " + k.Hex
	if k.Host != "" {
		s += " host " + k.Host
	}
	return s
}

// keysDiff names keys removed (by name and the first 8 hex digits) and
// added (by name and all of its hex).
func keysDiff(role string, old, new []policy.Key) []string {
	in := func(ks []policy.Key, k policy.Key) bool {
		for _, x := range ks {
			if x == k {
				return true
			}
		}
		return false
	}
	var d []string
	for _, k := range old {
		if !in(new, k) {
			d = append(d, fmt.Sprintf("%s -%s %s", role, k.Name, k.Hex[:8]))
		}
	}
	for _, k := range new {
		if !in(old, k) {
			d = append(d, fmt.Sprintf("%s +%s", role, keyLine(k)))
		}
	}
	return d
}

func listDiff(what string, old, new []string) []string {
	has := func(xs []string, x string) bool {
		for _, y := range xs {
			if y == x {
				return true
			}
		}
		return false
	}
	var d []string
	for _, x := range old {
		if !has(new, x) {
			d = append(d, what+" -"+x)
		}
	}
	for _, x := range new {
		if !has(old, x) {
			d = append(d, what+" +"+x)
		}
	}
	return d
}

func tierLines(p *policy.Policy) []string {
	var out []string
	for _, t := range p.Tiers {
		line := fmt.Sprintf("%s hosts %s admit %s", t.Name, strings.Join(t.Hosts, ","), strings.Join(t.Admit, ","))
		if len(t.Canaries) > 0 {
			line += " canaries " + strings.Join(t.Canaries, ",")
		}
		if t.Critical {
			line += " critical"
		}
		if t.SpacingSeconds > 0 {
			line += fmt.Sprintf(" spacing %ds", t.SpacingSeconds)
		}
		out = append(out, line)
	}
	return out
}

func flowLines(p *policy.Policy) []string {
	var out []string
	for _, f := range p.Protected {
		out = append(out, fmt.Sprintf("%s %s/%d", strings.Join(f.Hosts, ","), f.Proto, f.Port))
	}
	return out
}

func healthLines(p *policy.Policy) []string {
	var out []string
	for _, h := range p.Health {
		line := fmt.Sprintf("%s %s %s", strings.Join(h.Hosts, ","), h.Kind, h.Target)
		if h.Want != "" {
			line += " " + h.Want
		}
		if h.GraceSeconds > 0 {
			line += fmt.Sprintf(" grace %ds", h.GraceSeconds)
		}
		out = append(out, line)
	}
	return out
}

// VerifyPolicy checks the owner's signature on a policy change: its two
// arguments are the new policy's hash and the hash it replaces, and its memo
// must be the diff MemoPolicy writes from the two policies.
func VerifyPolicy(txJSON []byte, chainID string, seq uint64, ownerPub []byte, old, new *policy.Policy) error {
	memo, err := MemoPolicy(old, new)
	if err != nil {
		return err
	}
	st, err := VerifyGnokey(txJSON, chainID, seq, ownerPub, memo)
	if err != nil {
		return err
	}
	if st.Call.Func != "Policy" || len(st.Call.Args) != 2 || st.Call.Args[0] != new.Hash() || st.Call.Args[1] != old.Hash() {
		return errors.New("approve: not a Policy statement for these two policies")
	}
	return nil
}
