// Package policy is the owner's rules for a fleet: which signers count for
// what, which machines are in which tier, which flows are protected and what
// health means on each machine. Every agent keeps the policy and checks it
// itself; a change takes effect only after the owner signs it and its delay
// has passed.
package policy

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
	"time"
)

// MaxSize is the largest policy file the agent reads.
const MaxSize = 64 << 10

// Policy is one version of a fleet's rules.
type Policy struct {
	// Fleet names the fleet; with the owner's key it makes the chain id of
	// every statement.
	Fleet string `json:"fleet"`
	// Replaces is the hash of the policy this one replaces, or "" for the
	// first, which root installs by hand.
	Replaces string `json:"replaces"`
	// DelaySeconds is how long a signed change to this policy waits, counted
	// from when an agent first sees it.
	DelaySeconds int     `json:"delay_seconds"`
	Signers      Signers `json:"signers"`
	// Rigs are the rig builds whose Tested count, by the hash each Tested
	// carries: the pinned scripts, images and QEMU. A Tested from any other
	// build, an old or a private one, counts for nothing (round 9, minor
	// 12). A policy whose tiers admit the rig or vetters names at least one.
	Rigs      []string `json:"rigs,omitempty"`
	Tiers     []Tier   `json:"tiers"`
	Protected []Flow   `json:"protected,omitempty"`
	Health    []Health `json:"health,omitempty"`
}

// Signers are every key the agents count, by role. A key may appear once.
type Signers struct {
	Me            Key   `json:"me"` // the owner's Ledger key, secp256k1
	Rig           []Key `json:"rig,omitempty"`
	Vetters       []Key `json:"vetters,omitempty"`
	VettersNeeded int   `json:"vetters_needed,omitempty"`
	Model         []Key `json:"model,omitempty"`
	Builders      []Key `json:"builders,omitempty"`
	Agents        []Key `json:"agents,omitempty"` // each with its Host
}

// Key is a public key in hex: 33 bytes (secp256k1, compressed) for Me, 32
// (Ed25519) for every other role. Name is the owner's own name for it, which
// the memo shows beside the hex.
type Key struct {
	Name string `json:"name"`
	Hex  string `json:"key"`
	Host string `json:"host,omitempty"`
}

// Tier is a set of machines that take guards the same way.
type Tier struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
	// Admit lists the roles any one of which admits a guard here: "me",
	// "rig", "vetters" (VettersNeeded of them) or "model".
	Admit []string `json:"admit"`
	// Canaries are up to two hosts of this tier that take a guard first;
	// either one's Healthy lets the rest follow.
	Canaries []string `json:"canaries,omitempty"`
	// Critical tiers (the sentry and validator) never count the model.
	Critical       bool `json:"critical,omitempty"`
	SpacingSeconds int  `json:"spacing_seconds,omitempty"`
	// Reboot says who reboots this tier's hosts into a newer kernel (B3):
	// "window", the agent itself inside RebootWindow, once the gates pass;
	// "yes", only on the owner's signed Reboot (the default); or "never".
	Reboot string `json:"reboot,omitempty"`
	// RebootWindow is when a "window" tier may reboot: "HH:MM-HH:MM", UTC.
	// It may wrap midnight ("23:30-00:30").
	RebootWindow string `json:"reboot_window,omitempty"`
	// RebootAfter names a host, in another tier, whose agent must have
	// signed Healthy since its own last reboot before this tier's hosts
	// reboot: the validator waits for the sentry.
	RebootAfter string `json:"reboot_after,omitempty"`
}

// RebootMode is the tier's reboot mode, "yes" when it names none.
func (t *Tier) RebootMode() string {
	if t.Reboot == "" {
		return "yes"
	}
	return t.Reboot
}

// ParseWindow reads "HH:MM-HH:MM" as minutes after midnight, UTC.
func ParseWindow(s string) (start, end int, err error) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, fmt.Errorf("policy: a reboot window is HH:MM-HH:MM, not %q", s)
	}
	clock := func(x string) (int, error) {
		if len(x) != 5 || x[2] != ':' {
			return 0, fmt.Errorf("policy: %q isn't HH:MM", x)
		}
		h, err1 := strconv.Atoi(x[:2])
		m, err2 := strconv.Atoi(x[3:])
		if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
			return 0, fmt.Errorf("policy: %q isn't HH:MM", x)
		}
		return h*60 + m, nil
	}
	if start, err = clock(a); err != nil {
		return
	}
	if end, err = clock(b); err != nil {
		return
	}
	if start == end {
		return 0, 0, fmt.Errorf("policy: the reboot window %q is empty", s)
	}
	return start, end, nil
}

// InWindow says whether t falls in the tier's reboot window: from its
// start, up to but not at its end, wrapping midnight when the end comes
// first.
func (t *Tier) InWindow(now time.Time) bool {
	start, end, err := ParseWindow(t.RebootWindow)
	if err != nil {
		return false
	}
	u := now.UTC()
	m := u.Hour()*60 + u.Minute()
	if start < end {
		return m >= start && m < end
	}
	return m >= start || m < end
}

// Flow is a protected flow: traffic no guard may block on these hosts.
type Flow struct {
	Hosts []string `json:"hosts"`
	Proto string   `json:"proto"` // tcp or udp
	Port  int      `json:"port"`
}

// DefaultGrace is a check's grace after a boot when the policy sets none,
// and MaxGraceSeconds the most it may set.
const (
	DefaultGrace    = 600
	MaxGraceSeconds = 3600
)

// Grace is how long the check may fail after a boot before it counts.
func (h Health) Grace() int {
	if h.GraceSeconds > 0 {
		return h.GraceSeconds
	}
	return DefaultGrace
}

// Health is a check that must hold through a guard's trial on these hosts.
type Health struct {
	// GraceSeconds is how long the check may fail after a boot before it
	// counts against a guard, unless it has passed since the boot; 0 means
	// DefaultGrace. A model server or signed_last20 needs some.
	GraceSeconds int      `json:"grace_seconds,omitempty"`
	Hosts        []string `json:"hosts"`
	// Kind is "tcp" (Target is host:port and must connect), "http" (Target
	// is a URL and Want its status), "unit" (Target is a systemd unit that
	// must be active) or "json" (Target is a URL, Want is "field=value").
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Want   string `json:"want,omitempty"`
}

var (
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
	fleetRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	tierRe  = regexp.MustCompile(`^[A-Za-z0-9]{1,8}$`)
)

// Parse reads a policy file as agents act on it: strict fields, every rule
// valid, and the file exactly in canonical form (with at most one trailing
// newline), so a signature over its hash covers the file's bytes.
func Parse(data []byte) (*Policy, error) {
	p, err := Decode(data)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(bytes.TrimSuffix(data, []byte("\n")), p.Canonical()) {
		return nil, errors.New("policy: the file isn't in canonical form")
	}
	return p, nil
}

// Decode reads a policy in any JSON spelling, strictly by field.
func Decode(data []byte) (*Policy, error) {
	if len(data) > MaxSize {
		return nil, fmt.Errorf("policy: %d bytes; the limit is %d", len(data), MaxSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("policy: something follows it")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Canonical is the policy's canonical form: compact JSON, fields in declared
// order, empty optional fields left out.
func (p *Policy) Canonical() []byte {
	b, err := json.Marshal(p)
	if err != nil {
		panic("policy: encoding: " + err.Error())
	}
	return b
}

// Hash is the hex sha256 of the canonical form.
func (p *Policy) Hash() string {
	sum := sha256.Sum256(p.Canonical())
	return hex.EncodeToString(sum[:])
}

// RigsPinned refuses a policy whose tiers admit the rig or vetters while it
// pins no rig build: no Tested would count there, so such a tier would
// admit nothing but the owner's Yes. Validate allows it, since an agent
// then fails closed (and older signed policies stay readable); the signing
// tool refuses to sign it, and the agent's init warns.
func (p *Policy) RigsPinned() error {
	if len(p.Rigs) > 0 {
		return nil
	}
	for _, t := range p.Tiers {
		for _, a := range t.Admit {
			if a == "rig" || a == "vetters" {
				return fmt.Errorf("policy: tier %s admits %s, but no rig build is pinned (rigs), so no Tested would count", t.Name, a)
			}
		}
	}
	return nil
}

// Validate checks every rule: names, keys of the right length, no key twice
// or in two roles, each host in one tier, canaries in their tier, roles a
// tier can admit, and flows and checks on known hosts.
func (p *Policy) Validate() error {
	if !fleetRe.MatchString(p.Fleet) {
		return fmt.Errorf("policy: fleet %q", p.Fleet)
	}
	if p.Replaces != "" && !isHex(p.Replaces, 32) {
		return fmt.Errorf("policy: replaces %q is not a policy hash", p.Replaces)
	}
	if p.DelaySeconds < 3600 || p.DelaySeconds > 30*86400 {
		return errors.New("policy: the delay must be between an hour and 30 days")
	}
	seenKey := map[string]string{}
	keys := func(role string, ks []Key, size int, needHost bool) error {
		for _, k := range ks {
			if !nameRe.MatchString(k.Name) || !isHex(k.Hex, size) {
				return fmt.Errorf("policy: %s key %q (%s) must be a name and %d bytes of hex", role, k.Name, k.Hex, size)
			}
			if role == "me" && k.Hex[:2] != "02" && k.Hex[:2] != "03" {
				return errors.New("policy: the owner's key must be a compressed secp256k1 key")
			}
			if (k.Host != "") != needHost {
				return fmt.Errorf("policy: %s key %s: a host is for agents' keys only, and each agent's key names its host", role, k.Name)
			}
			if prev, ok := seenKey[k.Hex]; ok {
				return fmt.Errorf("policy: key %s is listed twice (%s and %s); each key is one signer in one role", k.Name, prev, role)
			}
			seenKey[k.Hex] = role
		}
		return nil
	}
	s := p.Signers
	for _, r := range []struct {
		role     string
		ks       []Key
		size     int
		needHost bool
	}{{"me", []Key{s.Me}, 33, false}, {"rig", s.Rig, 32, false}, {"vetters", s.Vetters, 32, false}, {"model", s.Model, 32, false}, {"builders", s.Builders, 32, false}, {"agents", s.Agents, 32, true}} {
		if err := keys(r.role, r.ks, r.size, r.needHost); err != nil {
			return err
		}
	}
	if len(s.Vetters) > 0 && (s.VettersNeeded < 1 || s.VettersNeeded > len(s.Vetters)) {
		return errors.New("policy: vetters_needed must be from 1 to the number of vetters")
	}
	if len(s.Builders) == 1 {
		return errors.New("policy: a release needs two builders' rebuilds, so name none or at least two")
	}
	seenRig := map[string]bool{}
	for _, r := range p.Rigs {
		if !isHex(r, 32) {
			return fmt.Errorf("policy: rig %q is not a rig build's hash (64 lowercase hex digits)", r)
		}
		if seenRig[r] {
			return fmt.Errorf("policy: rig %s is listed twice", r[:16])
		}
		seenRig[r] = true
	}
	hostTier := map[string]string{}
	if len(p.Tiers) == 0 {
		return errors.New("policy: no tiers")
	}
	for _, t := range p.Tiers {
		if !tierRe.MatchString(t.Name) {
			return fmt.Errorf("policy: tier name %q", t.Name)
		}
		if len(t.Hosts) == 0 || len(t.Admit) == 0 {
			return fmt.Errorf("policy: tier %s needs hosts and a rule", t.Name)
		}
		for _, h := range t.Hosts {
			if !nameRe.MatchString(h) {
				return fmt.Errorf("policy: host %q", h)
			}
			if prev, ok := hostTier[h]; ok {
				return fmt.Errorf("policy: host %s is in tiers %s and %s", h, prev, t.Name)
			}
			hostTier[h] = t.Name
		}
		for _, a := range t.Admit {
			switch a {
			case "me":
			case "rig", "vetters", "model":
				if (a == "rig" && len(s.Rig) == 0) || (a == "vetters" && len(s.Vetters) == 0) || (a == "model" && len(s.Model) == 0) {
					return fmt.Errorf("policy: tier %s admits %s, but no %s key is listed", t.Name, a, a)
				}
				if a == "model" && t.Critical {
					return fmt.Errorf("policy: tier %s is critical, and the model never counts there", t.Name)
				}
			default:
				return fmt.Errorf("policy: tier %s: %q is not a role (me, rig, vetters, model)", t.Name, a)
			}
		}
		if len(t.Canaries) > 2 {
			return fmt.Errorf("policy: tier %s names more than two canaries", t.Name)
		}
		switch t.Reboot {
		case "window":
			if _, _, err := ParseWindow(t.RebootWindow); err != nil {
				return fmt.Errorf("policy: tier %s: %w", t.Name, err)
			}
		case "", "yes", "never":
			if t.RebootWindow != "" {
				return fmt.Errorf("policy: tier %s has a reboot window but reboots %s", t.Name, t.RebootMode())
			}
		default:
			return fmt.Errorf("policy: tier %s: reboot is window, yes or never, not %q", t.Name, t.Reboot)
		}
		for _, c := range t.Canaries {
			if hostTier[c] != t.Name {
				return fmt.Errorf("policy: canary %s isn't in tier %s", c, t.Name)
			}
		}
	}
	known := func(hosts []string) error {
		for _, h := range hosts {
			if _, ok := hostTier[h]; !ok {
				return fmt.Errorf("policy: host %s is in no tier", h)
			}
		}
		if len(hosts) == 0 {
			return errors.New("policy: a flow or check names no hosts")
		}
		return nil
	}
	for _, t := range p.Tiers {
		if t.RebootAfter == "" {
			continue
		}
		switch tier, ok := hostTier[t.RebootAfter]; {
		case !ok:
			return fmt.Errorf("policy: tier %s reboots after %s, which is in no tier", t.Name, t.RebootAfter)
		case tier == t.Name:
			return fmt.Errorf("policy: tier %s reboots after %s, one of its own hosts", t.Name, t.RebootAfter)
		}
	}
	for _, f := range p.Protected {
		if err := known(f.Hosts); err != nil {
			return err
		}
		if (f.Proto != "tcp" && f.Proto != "udp") || f.Port < 1 || f.Port > 65535 {
			return fmt.Errorf("policy: protected flow %s/%d", f.Proto, f.Port)
		}
	}
	for _, h := range p.Health {
		if err := known(h.Hosts); err != nil {
			return err
		}
		switch h.Kind {
		case "tcp", "unit":
		case "http", "json":
			if h.Want == "" {
				return fmt.Errorf("policy: a %s check needs what it wants", h.Kind)
			}
		default:
			return fmt.Errorf("policy: check kind %q", h.Kind)
		}
		if h.Target == "" || len(h.Target) > 256 {
			return errors.New("policy: a check needs a target")
		}
		if h.GraceSeconds < 0 || h.GraceSeconds > MaxGraceSeconds {
			return fmt.Errorf("policy: a check's grace after a boot is 0 to %d seconds", MaxGraceSeconds)
		}
	}
	for _, k := range s.Agents {
		if _, ok := hostTier[k.Host]; !ok {
			return fmt.Errorf("policy: agent key %s is for host %s, which is in no tier", k.Name, k.Host)
		}
	}
	return nil
}

// TierOf returns the tier a host is in.
func (p *Policy) TierOf(host string) (*Tier, bool) {
	for i := range p.Tiers {
		for _, h := range p.Tiers[i].Hosts {
			if h == host {
				return &p.Tiers[i], true
			}
		}
	}
	return nil, false
}

func isHex(s string, n int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == n && s == hex.EncodeToString(b)
}
