// Command autopatch-sign is the owner's signing tool. It runs on the
// owner's own machine, next to gnokey and the Ledger: it reads the file a
// statement is about, writes the memo itself, checks every machine's
// pending policy from fresh signed reports, shows the owner what will be
// signed, has gnokey sign it (never broadcast), and checks the result as an
// agent would before writing the message for the lookout to carry.
//
//	autopatch-sign yes    -policy P.json -tiers A,B -until 2026-11-12T00:00:00Z GUARD.json
//	autopatch-sign off    -policy P.json -hosts mail,web GUARD.json
//	autopatch-sign on     -policy P.json -hosts mail GUARD.json
//	autopatch-sign policy -policy OLD.json NEW.json
//	autopatch-sign standing -policy P.json
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/guard"
	"github.com/jaekwon/autopatch/policy"
	"github.com/jaekwon/autopatch/signer"
)

const usage = `usage: autopatch-sign <yes|off|on|policy|cancel|standing> [flags] FILE|HASH

  yes    GUARD.json   the owner's yes to a guard: -tiers A,B -until RFC3339 [-mode undo|keep] [-nocanary] [-kev KEV.json]
  off    GUARD.json   take a guard off some hosts and keep it off there: -hosts mail,web
  on     GUARD.json   lift an Off on some hosts: -hosts mail (a Yes never does)
  cancel HASH         cancel a pending policy change (allowed even after you signed a change of key)
  policy NEW.json     a policy change, against the policy in force (-policy); its keys are checked
                      against your address book (-confirm-keys to accept the differences shown)
  standing            list your Yeses still in force, from the statements this tool kept, with
                      the command to sign each again: a machine added or rebuilt starts at the
                      current sequence and has none of them (only -policy is needed)

Every command needs:
  -policy FILE     the policy in force (for policy: the one NEW replaces)
  -reports DIR     each machine's signed report, as <host>.json, fetched from the lookout; a machine
                   without a fresh one must be named in -unchecked
  -key NAME        your key in gnokey's keybase (your Ledger entry)
and takes -seq N (default: one above the highest sequence any agent or this tool has seen),
-gnokey PATH, -home DIR (gnokey's), -config DIR (default ~/.config/autopatch), -out FILE.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(context.Background(), os.Args[1], os.Args[2:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "autopatch-sign:", err)
		os.Exit(1)
	}
}

// testPassword is set only by tests, for a test keybase; a Ledger asks on
// the device.
var testPassword string

// state is what the tool remembers per fleet, on the owner's machine: the
// last sequence it signed and the newest policy it signed, whose agent keys
// are the only ones it checks reports against.
type state struct {
	LastSeq      uint64 `json:"last_seq"`
	NewestPolicy []byte `json:"newest_policy,omitempty"` // canonical; base64 in the file
}

func run(ctx context.Context, cmd string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	policyFile := fs.String("policy", "", "the policy in force (for policy: the one the new one replaces)")
	reports := fs.String("reports", "", "a folder of each machine's signed report, <host>.json")
	unchecked := fs.String("unchecked", "", "machines whose fresh report you couldn't get, by name, comma-separated")
	key := fs.String("key", "", "your key's name in gnokey's keybase")
	seq := fs.Uint64("seq", 0, "the statement's sequence (default: one above the highest seen)")
	gnokeyBin := fs.String("gnokey", "gnokey", "the gnokey program")
	home := fs.String("home", "", "gnokey's home directory")
	configDir := fs.String("config", "", "where this tool keeps your address book and its own record (default ~/.config/autopatch)")
	out := fs.String("out", "", "where to write the message for the lookout (default: <statement>-<seq>.json)")
	assumeYes := fs.Bool("yes", false, "don't ask before signing (tests only)")
	tiers := fs.String("tiers", "", "yes: the tiers, comma-separated")
	until := fs.String("until", "", "yes: when the yes ends, RFC 3339 in UTC")
	mode := fs.String("mode", "", "yes: undo or keep (default: keep for a flaw on CISA's list outside critical tiers, else undo)")
	nocanary := fs.Bool("nocanary", false, "yes: every machine of the tiers at once, without waiting for a canary")
	kevFile := fs.String("kev", "", "yes: CISA's known exploited list (JSON), for the default mode")
	hosts := fs.String("hosts", "", "off: the hosts, comma-separated")
	confirmKeys := fs.Bool("confirm-keys", false, "policy: accept the key differences shown, and add new names to your book")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if cmd == "standing" {
		if *policyFile == "" {
			return errors.New("standing needs -policy")
		}
		if *configDir == "" {
			h, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			*configDir = filepath.Join(h, ".config", "autopatch")
		}
		cur, err := readPolicy(*policyFile)
		if err != nil {
			return err
		}
		return standing(*configDir, cur, time.Now(), stdout)
	}
	if fs.NArg() != 1 || *policyFile == "" || *reports == "" || *key == "" {
		fs.Usage()
		return errors.New("needs one file, -policy, -reports and -key")
	}
	if *configDir == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		*configDir = filepath.Join(h, ".config", "autopatch")
	}
	cur, err := readPolicy(*policyFile)
	if err != nil {
		return err
	}
	st, statePath, err := loadState(*configDir, cur.Fleet)
	if err != nil {
		return err
	}
	// After you sign a change of key, statements signed with the old key
	// would hold every machine once the change is in force there.
	if st.NewestPolicy != nil && cmd != "cancel" { // a Cancel is how a change of key is stopped
		if np, err := policy.Parse(st.NewestPolicy); err == nil && np.Signers.Me.Hex != cur.Signers.Me.Hex {
			return fmt.Errorf("you signed a change of your key (policy %.16s); once the reports show it in force on every machine, sign with the new key and -policy that policy", np.Hash())
		}
	}
	// Reports are checked only against agent keys in the newest policy this
	// tool signed; before it has signed one, the policy given.
	keysFrom := cur
	if st.NewestPolicy != nil {
		if keysFrom, err = policy.Parse(st.NewestPolicy); err != nil {
			return fmt.Errorf("the newest policy this tool signed (%s): %w", statePath, err)
		}
	}
	checked, err := signer.CheckReports(*reports, keysFrom, split(*unchecked), time.Now(), cur)
	if err != nil {
		return err
	}
	if *seq == 0 {
		*seq = max(st.LastSeq, checked.OwnerSeq) + 1
	}
	if *seq <= st.LastSeq {
		return fmt.Errorf("sequence %d: this tool already signed %d for fleet %s", *seq, st.LastSeq, cur.Fleet)
	}

	var stmt *signer.Statement
	var notes []string
	var newPolicy *policy.Policy
	var bookAdd signer.Book
	switch cmd {
	case "yes", "off", "on":
		b, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return err
		}
		g, err := guard.Parse(b)
		if err != nil {
			return fmt.Errorf("%s: %w (autopatch-agent fmt writes the canonical form)", fs.Arg(0), err)
		}
		switch cmd {
		case "off":
			if stmt, err = signer.PrepareOff(cur, g, split(*hosts), *seq); err != nil {
				return err
			}
		case "on":
			if stmt, err = signer.PrepareOn(cur, g, split(*hosts), *seq); err != nil {
				return err
			}
		}
		if cmd != "yes" {
			break
		}
		end, err := time.Parse(time.RFC3339, *until)
		if err != nil {
			return fmt.Errorf("-until: %w", err)
		}
		ts := split(*tiers)
		if *mode == "" {
			kev, err := readKEV(*kevFile)
			if err != nil {
				return err
			}
			*mode = signer.DefaultMode(cur, ts, g.Flaws, kev)
			notes = append(notes, "mode "+*mode+" (the default; -mode to choose)")
		}
		// keep on a guard that bites later: no window can show it booted on a
		// canary, so the rest of the tier would wait; nocanary is offered.
		nocanarySet := false
		fs.Visit(func(f *flag.Flag) { nocanarySet = nocanarySet || f.Name == "nocanary" })
		if *mode == "keep" && g.Later() && !nocanarySet {
			*nocanary = true
			notes = append(notes, "nocanary too, since the guard bites later and is kept: no machine will boot with it first (-nocanary=false waits for a canary's boot)")
		}
		for host, offs := range checked.Off {
			for _, h := range offs {
				if h == g.Hash() {
					notes = append(notes, "this Yes doesn't put the guard back on "+host+", where you took it off; sign `on` for that")
				}
			}
		}
		for host, held := range checked.HeldByHand {
			for _, h := range held {
				if h == g.Hash() {
					notes = append(notes, "this Yes doesn't put the guard back on "+host+", where root took it off by hand; sign `on` for that")
				}
			}
		}
		if stmt, err = signer.PrepareYes(cur, g, approve.Yes{Tiers: ts, Until: end.UTC(), Mode: *mode, NoCanary: *nocanary}, *seq); err != nil {
			return err
		}
	case "cancel":
		if stmt, err = signer.PrepareCancel(cur, fs.Arg(0), *seq); err != nil {
			return err
		}
		if !checked.Pending {
			notes = append(notes, "no machine reports a pending policy change")
		}
		// A Cancel that reaches a machine after the change took effect there
		// can't stop it (round 8, minor 7).
		for host, pd := range checked.PendingOn {
			if pd.Hash != fs.Arg(0) {
				continue
			}
			if left := time.Until(pd.FirstSeen.Add(time.Duration(cur.DelaySeconds) * time.Second)); left < 2*time.Hour {
				notes = append(notes, fmt.Sprintf("on %s the change takes effect in %s; if this Cancel reaches it later, that machine stays on the new policy and holds your statements until root installs the policy in force again", host, max(left, 0).Round(time.Minute)))
			}
		}
	case "policy":
		if newPolicy, err = readPolicy(fs.Arg(0)); err != nil {
			return err
		}
		book, err := loadBook(*configDir)
		if err != nil {
			return err
		}
		if bookAdd, notes, err = signer.CheckBook(book, newPolicy, *confirmKeys); err != nil {
			return err
		}
		if stmt, err = signer.PreparePolicy(cur, newPolicy, *seq); err != nil {
			return err
		}
	default:
		fs.Usage()
		return fmt.Errorf("unknown command %q", cmd)
	}

	fmt.Fprintf(stdout, "Machines (signed reports):\n")
	for _, l := range checked.Lines {
		fmt.Fprintf(stdout, "  %s\n", l)
	}
	if checked.Pending {
		fmt.Fprintf(stdout, "  ** A policy change is PENDING on some machine. If you didn't sign it, stop and cancel it. **\n")
	}
	for _, n := range notes {
		fmt.Fprintf(stdout, "Note: %s\n", n)
	}
	fmt.Fprintf(stdout, "\nYou are about to sign, as sequence %d for %s:\n\n  %s\n\nYour Ledger will show the same memo.\n", stmt.Seq, stmt.Chain, stmt.Memo)
	if !*assumeYes && !confirm(stdout) {
		return errors.New("not signed")
	}
	owner, err := hex.DecodeString(cur.Signers.Me.Hex)
	if err != nil {
		return err
	}
	signed, err := signer.Gnokey{Bin: *gnokeyBin, Home: *home, Key: *key, Password: testPassword}.Sign(ctx, stmt, owner)
	if err != nil {
		return err
	}
	msg, err := signer.MessageFile(stmt.Seq, signed)
	if err != nil {
		return err
	}
	if *out == "" {
		*out = fmt.Sprintf("%s-%d.json", strings.ToLower(stmt.Func), stmt.Seq)
	}
	if err := os.WriteFile(*out, append(msg, '\n'), 0o644); err != nil {
		return err
	}
	// A copy of every statement signed, by fleet and number: a machine held
	// at a number can be given it again.
	kept := filepath.Join(*configDir, "statements", cur.Fleet, fmt.Sprintf("%d.json", stmt.Seq))
	if err := os.MkdirAll(filepath.Dir(kept), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(kept, append(msg, '\n'), 0o600); err != nil {
		return err
	}
	st.LastSeq = stmt.Seq
	// Cancelling the newest policy this tool signed puts the one in force
	// back as the newest: the old key signs again, and reports are checked
	// against its agents (round 8, minor 7).
	if cmd == "cancel" && st.NewestPolicy != nil {
		if np, err := policy.Parse(st.NewestPolicy); err == nil && np.Hash() == fs.Arg(0) {
			st.NewestPolicy = cur.Canonical()
		}
	}
	if newPolicy != nil {
		st.NewestPolicy = newPolicy.Canonical()
		if err := addToBook(*configDir, bookAdd); err != nil {
			return err
		}
	}
	if err := saveState(statePath, st); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Signed. Upload %s to the lookout's page.\n", *out)
	return nil
}

// standing lists the owner's Yeses still in force, from the statements this
// tool kept: for each guard and tier, the newest Yes, if it hasn't ended.
// A machine added or rebuilt starts at the current sequence, so it has none
// of them until they are signed again (round 8, new major 3).
func standing(configDir string, p *policy.Policy, now time.Time, stdout io.Writer) error {
	files, err := filepath.Glob(filepath.Join(configDir, "statements", p.Fleet, "*.json"))
	if err != nil {
		return err
	}
	type kept struct {
		seq uint64
		y   approve.Yes
	}
	newest := map[string]kept{} // hash/tier
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var m signer.Message
		var tx approve.GnokeyTx
		if json.Unmarshal(b, &m) != nil || json.Unmarshal(m.Tx, &tx) != nil || len(tx.Msg) != 1 || tx.Msg[0].Func != "Yes" {
			continue
		}
		y, err := approve.ParseYes(approve.Call{Func: "Yes", Args: tx.Msg[0].Args})
		if err != nil {
			continue
		}
		for _, t := range y.Tiers {
			if k, ok := newest[y.Hash+"/"+t]; !ok || m.Seq > k.seq {
				newest[y.Hash+"/"+t] = kept{m.Seq, y}
			}
		}
	}
	// One line per statement, with only the tiers it is still the newest for.
	tiers := map[uint64][]string{}
	yeses := map[uint64]approve.Yes{}
	for k, v := range newest {
		if v.y.Until.After(now) {
			tiers[v.seq] = append(tiers[v.seq], k[strings.Index(k, "/")+1:])
			yeses[v.seq] = v.y
		}
	}
	seqs := make([]uint64, 0, len(tiers))
	for s := range tiers {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	if len(seqs) == 0 {
		fmt.Fprintln(stdout, "No Yes of yours is in force.")
		return nil
	}
	fmt.Fprintln(stdout, "Your Yeses in force; sign each again for a machine added or rebuilt.")
	fmt.Fprintln(stdout, "A Yes signed again for a tier clears the guard's tries, asks and suspects on every")
	fmt.Fprintln(stdout, "machine of that tier, so a guard that reached your ask elsewhere is tried again there:")
	for _, s := range seqs {
		y := yeses[s]
		ts := tiers[s]
		sort.Strings(ts)
		nc := ""
		if y.NoCanary {
			nc = " -nocanary"
		}
		fmt.Fprintf(stdout, "  statement %d, guard %.16s, tiers %s, until %s, mode %s%s\n    autopatch-sign yes -policy P.json -tiers %s -until %s -mode %s%s GUARD.json\n",
			s, y.Hash, strings.Join(ts, ","), y.Until.UTC().Format(time.RFC3339), y.Mode, nc,
			strings.Join(ts, ","), y.Until.UTC().Format(time.RFC3339), y.Mode, nc)
	}
	return nil
}

func readPolicy(path string) (*policy.Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := policy.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// confirm asks on the terminal itself, so a script piped into the tool
// can't answer for the owner.
func confirm(stdout io.Writer) bool {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		fmt.Fprintln(stdout, "no terminal to ask on; not signing")
		return false
	}
	defer tty.Close()
	fmt.Fprint(stdout, "Sign it? Type yes: ")
	line, _ := bufio.NewReader(tty).ReadString('\n')
	return strings.TrimSpace(line) == "yes"
}

// readKEV reads CISA's known exploited vulnerabilities list into a set.
func readKEV(path string) (map[string]bool, error) {
	out := map[string]bool{}
	if path == "" {
		return out, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kev struct {
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &kev); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, v := range kev.Vulnerabilities {
		out[v.CVE] = true
	}
	return out, nil
}

func loadState(dir, fleet string) (*state, string, error) {
	path := filepath.Join(dir, "fleet-"+fleet+".json")
	st := &state{}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, path, nil
	}
	if err != nil {
		return nil, "", err
	}
	return st, path, json.Unmarshal(b, st)
}

func saveState(path string, st *state) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func loadBook(dir string) (signer.Book, error) {
	book := signer.Book{}
	b, err := os.ReadFile(filepath.Join(dir, "addressbook.json"))
	if errors.Is(err, os.ErrNotExist) {
		return book, nil
	}
	if err != nil {
		return nil, err
	}
	return book, json.Unmarshal(b, &book)
}

func addToBook(dir string, add signer.Book) error {
	if len(add) == 0 {
		return nil
	}
	book, err := loadBook(dir)
	if err != nil {
		return err
	}
	for k, v := range add {
		book[k] = v
	}
	b, err := json.MarshalIndent(book, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "addressbook.json"), append(b, '\n'), 0o600)
}
