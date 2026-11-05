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
)

// MaxMemo caps a memo, so that every statement stays small enough for a
// Ledger to sign.
const MaxMemo = 600

var tierRe = regexp.MustCompile(`^[A-Za-z0-9]{1,8}$`)

// Yes is an owner's yes to a guard: on these tiers, until a time, with its
// undo kept or not.
type Yes struct {
	Hash  string    // the guard's full hash
	Tiers []string  // tier names, such as A and B
	Until time.Time // when the yes ends, to the second, in UTC
	Mode  string    // "undo" or "keep"
}

// Args are the Yes's arguments as signed: hash, tiers joined by commas, the
// end as Unix seconds, and the mode.
func (y Yes) Args() []string {
	return []string{y.Hash, strings.Join(y.Tiers, ","), strconv.FormatInt(y.Until.Unix(), 10), y.Mode}
}

// ParseYes reads a Yes from a statement's call, strictly.
func ParseYes(c Call) (Yes, error) {
	if c.Func != "Yes" || len(c.Args) != 4 {
		return Yes{}, errors.New("approve: not a Yes with four arguments")
	}
	y := Yes{Hash: c.Args[0], Mode: c.Args[3]}
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
	fmt.Fprintf(&b, "autopatch Yes %s %s:", g.Name(), y.Hash[:16])
	for _, bl := range g.Blocks {
		b.WriteString(" " + bl.Describe() + ";")
	}
	fmt.Fprintf(&b, " tiers %s; until %s; mode %s", strings.Join(y.Tiers, ","), y.Until.UTC().Format(time.RFC3339), y.Mode)
	return checkMemo(b.String())
}

// MemoOff writes the memo for taking a guard off.
func MemoOff(g *guard.Guard) (string, error) {
	return checkMemo(fmt.Sprintf("autopatch Off %s %s", g.Name(), g.Hash()[:16]))
}

func checkMemo(m string) (string, error) {
	if len(m) > MaxMemo {
		return "", fmt.Errorf("approve: the memo is %d bytes, more than a Ledger statement allows (%d); split the guard", len(m), MaxMemo)
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
