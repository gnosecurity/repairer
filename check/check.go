// Package check defines repairer's was-I-hit check: a read-only question
// about a machine, written as data.
//
// A check names one kind from a fixed list and fills its typed fields. The
// agent's own code answers it, read-only and capped, with a flag, a count
// and paths from the kind's fixed places; never a file's contents. A new
// kind comes only in an agent release.
package check

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/gnosecurity/repairer/guard"
)

// MaxSize is the largest check file the agent reads.
const MaxSize = 4 << 10

// Check is one question: what it is about, where it applies, its kind and
// what a flag means.
type Check struct {
	// ID names the check, such as "cve-2026-98432/hit-sshd".
	ID string `json:"id"`
	// Version counts the check's revisions; a new version is a new check.
	Version int `json:"version"`
	// Flaws lists what it looks for signs of, such as "CVE-2026-98432".
	Flaws []string `json:"flaws"`
	// For lists the systems it is written for.
	For []guard.Target `json:"for"`
	// Kind is what it does: one of the Kinds, its fields in Args.
	Kind string `json:"kind"`
	Args Args   `json:"args"`
	// Flag says, in plain words, what a raised flag means.
	Flag string `json:"flag"`
}

// Args are a kind's fields; each kind sets only its own.
type Args struct {
	Package string `json:"package,omitempty"` // package-files: the package
	What    string `json:"what,omitempty"`    // new-since: units, keys, cron or setuid
	Since   string `json:"since,omitempty"`   // new-since, log-match: Unix seconds, as digits
	Source  string `json:"source,omitempty"`  // log-match: "auth" or "unit:<name>"
	Pattern string `json:"pattern,omitempty"` // log-match: a fixed substring
}

// The kinds of version 1.
const (
	PackageFiles   = "package-files"
	DeletedExe     = "deleted-exe"
	NewSince       = "new-since"
	ForeignModules = "foreign-modules"
	LogMatch       = "log-match"
)

// Kinds are the kinds this release runs.
var Kinds = []string{PackageFiles, DeletedExe, NewSince, ForeignModules, LogMatch}

// What new-since may look at.
var Whats = []string{"units", "keys", "cron", "setuid"}

const (
	maxFlaws   = 16
	maxTargets = 16
	maxFlag    = 300
	maxPattern = 64
)

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$`)
	flawRe    = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[0-9A-Za-z][0-9A-Za-z.:_-]*$`)
	osRe      = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
	releaseRe = regexp.MustCompile(`^[0-9][0-9.]*$`)
	packageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,63}(:[a-z0-9]+)?$`)
	unitRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]{0,63}\.(service|socket|timer)$`)
	digitsRe  = regexp.MustCompile(`^[1-9][0-9]{0,11}$`)
)

// Parse reads a check file as the agent acts on it: the file must be the
// check's canonical form and valid.
func Parse(data []byte) (*Check, error) {
	c, err := Decode(data)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(bytes.TrimSuffix(data, []byte("\n")), c.Canonical()) {
		return nil, errors.New("reading check: the file isn't in canonical form")
	}
	return c, nil
}

// Decode reads a check strictly by field (no unknown fields, nothing after
// it) and validates it.
func Decode(data []byte) (*Check, error) {
	if len(data) > MaxSize {
		return nil, fmt.Errorf("check is %d bytes; the limit is %d", len(data), MaxSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Check
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("reading check: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("reading check: something follows the check")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Canonical is the check's canonical form: compact JSON, fields in order.
func (c *Check) Canonical() []byte {
	b, err := json.Marshal(c)
	if err != nil {
		panic("check: encoding a check: " + err.Error()) // only plain fields
	}
	return b
}

// Hash is the check's identity for signatures: the hex sha256 of its
// canonical form, which for a file Parse accepted is the file's own bytes.
func (c *Check) Hash() string {
	sum := sha256.Sum256(c.Canonical())
	return hex.EncodeToString(sum[:])
}

// Name is the check's ID and version, as people read them.
func (c *Check) Name() string { return fmt.Sprintf("%s v%d", c.ID, c.Version) }

// ForSystem reports whether the check is written for a system.
func (c *Check) ForSystem(os, release string) bool {
	for _, t := range c.For {
		if t.OS != os {
			continue
		}
		for _, r := range t.Releases {
			if r == release {
				return true
			}
		}
	}
	return false
}

// SinceUnix is Since as Unix seconds (0 when the kind takes none).
func (c *Check) SinceUnix() int64 {
	n, _ := strconv.ParseInt(c.Args.Since, 10, 64)
	return n
}

// Validate checks every field against the kind's own.
func (c *Check) Validate() error {
	if len(c.ID) > 64 || !idRe.MatchString(c.ID) {
		return fmt.Errorf("check id %q: use lowercase letters, digits, '.', '_', '-' and '/', at most 64", c.ID)
	}
	if c.Version < 1 || c.Version > 1_000_000 {
		return fmt.Errorf("check %s: version must be from 1 to 1000000", c.ID)
	}
	if len(c.Flaws) == 0 || len(c.Flaws) > maxFlaws {
		return fmt.Errorf("check %s: name 1 to %d flaws", c.ID, maxFlaws)
	}
	for _, f := range c.Flaws {
		if len(f) > 64 || !flawRe.MatchString(f) {
			return fmt.Errorf("check %s: flaw %q is not an identifier like CVE-2026-98432", c.ID, f)
		}
	}
	if len(c.For) == 0 || len(c.For) > maxTargets {
		return fmt.Errorf("check %s: name 1 to %d systems in \"for\"", c.ID, maxTargets)
	}
	for _, t := range c.For {
		if !osRe.MatchString(t.OS) || len(t.OS) > 32 || len(t.Releases) == 0 || len(t.Releases) > maxTargets {
			return fmt.Errorf("check %s: system %+v is not an os-release ID with 1 to %d releases", c.ID, t, maxTargets)
		}
		for _, r := range t.Releases {
			if !releaseRe.MatchString(r) || len(r) > 16 {
				return fmt.Errorf("check %s: release %q of %s is not a VERSION_ID", c.ID, r, t.OS)
			}
		}
	}
	if c.Flag == "" || len(c.Flag) > maxFlag || !printable(c.Flag) {
		return fmt.Errorf("check %s: \"flag\" must say in 1 to %d printable characters what a flag means", c.ID, maxFlag)
	}
	a := c.Args
	set := map[string]bool{"package": a.Package != "", "what": a.What != "", "since": a.Since != "", "source": a.Source != "", "pattern": a.Pattern != ""}
	var want []string
	switch c.Kind {
	case PackageFiles:
		want = []string{"package"}
		if !packageRe.MatchString(a.Package) {
			return fmt.Errorf("check %s: package %q is not a package name", c.ID, a.Package)
		}
	case DeletedExe, ForeignModules:
	case NewSince:
		want = []string{"what", "since"}
		if !contains(Whats, a.What) {
			return fmt.Errorf("check %s: what must be one of %s", c.ID, strings.Join(Whats, ", "))
		}
	case LogMatch:
		want = []string{"source", "pattern", "since"}
		if u, ok := strings.CutPrefix(a.Source, "unit:"); !(a.Source == "auth" || (ok && unitRe.MatchString(u))) {
			return fmt.Errorf("check %s: source %q is not auth or unit:<a unit>", c.ID, a.Source)
		}
		if a.Pattern == "" || len(a.Pattern) > maxPattern || !printable(a.Pattern) {
			return fmt.Errorf("check %s: the pattern is 1 to %d printable characters", c.ID, maxPattern)
		}
	default:
		return fmt.Errorf("check %s: kind %q is not one of %s", c.ID, c.Kind, strings.Join(Kinds, ", "))
	}
	for name, on := range set {
		if on != contains(want, name) {
			if on {
				return fmt.Errorf("check %s: %s takes no %s", c.ID, c.Kind, name)
			}
			return fmt.Errorf("check %s: %s needs %s", c.ID, c.Kind, name)
		}
	}
	if contains(want, "since") && !digitsRe.MatchString(a.Since) {
		return fmt.Errorf("check %s: since %q is not Unix seconds", c.ID, a.Since)
	}
	return nil
}

// Says is the check's kind and arguments in words, for the memo.
func (c *Check) Says() string {
	a := c.Args
	switch c.Kind {
	case PackageFiles:
		return "the files of package " + a.Package + " against its md5sums"
	case DeletedExe:
		return "processes running a deleted or replaced program"
	case NewSince:
		return a.What + " changed since " + a.Since
	case ForeignModules:
		return "loaded kernel modules no package owns"
	case LogMatch:
		return fmt.Sprintf("lines of %s since %s holding %q", a.Source, a.Since, a.Pattern)
	}
	return c.Kind
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
