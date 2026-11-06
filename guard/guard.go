// Package guard defines repairer's guard: a stopgap for a security flaw,
// written as data.
//
// A guard can only take exposure away. Its blocks come from a short, fixed
// list, and each block has typed fields that the agent turns into firewall
// rules, settings and file changes itself. No text from a guard reaches a
// shell or the firewall: names are checked against allow-lists, and numbers
// are numbers.
package guard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// MaxSize is the largest guard file the agent reads.
const MaxSize = 64 << 10

// Guard is one stopgap: what it protects against, where it applies, its
// blocks, what it breaks, and when it comes off.
type Guard struct {
	// ID names the guard, such as "cve-2026-98432/linux-ipv4-ipopt".
	ID string `json:"id"`
	// Version counts the guard's revisions; a new version is a new guard.
	Version int `json:"version"`
	// Flaws lists what it protects against, such as "CVE-2026-98432".
	Flaws []string `json:"flaws"`
	// For lists the systems it is written for.
	For []Target `json:"for"`
	// Blocks are what it does, applied in order and undone in reverse.
	Blocks []Block `json:"blocks"`
	// Breaks says, in plain words, what stops working while it is on.
	Breaks string `json:"breaks"`
	// Until lists the vendors' first fixed builds; once one of them is
	// running, the guard is no longer needed.
	Until []Fixed `json:"until,omitempty"`
}

// Target is a system a guard is written for.
type Target struct {
	OS       string   `json:"os"`       // os-release ID, such as "ubuntu"
	Releases []string `json:"releases"` // os-release VERSION_ID values
}

// Fixed is a vendor's first build of the kernel with the fix.
type Fixed struct {
	OS      string `json:"os"`
	Release string `json:"release"`
	// Kernel is the fixed build's version, such as "6.8.0-149.149", compared
	// with the running build the way dpkg compares versions.
	Kernel string `json:"kernel"`
}

// Block is one action of a guard. Exactly one field is set.
type Block struct {
	Drop    *Drop    `json:"drop,omitempty"`
	Setting *Setting `json:"setting,omitempty"`
	Module  *Module  `json:"module,omitempty"`
	Service *Service `json:"service,omitempty"`
	Strip   *Strip   `json:"strip,omitempty"`
}

// Drop drops inbound packets that match all of its fields, before every
// other firewall rule.
type Drop struct {
	// Family is "ipv4" or "ipv6".
	Family string `json:"family"`
	// Protocol is "tcp", "udp", "icmp" (ipv4) or "icmpv6" (ipv6); empty
	// means any protocol.
	Protocol string `json:"protocol,omitempty"`
	// Ports are destination ports, "445" or "137-139"; tcp and udp only.
	Ports []string `json:"ports,omitempty"`
	// SYN matches only connection requests (SYN without ACK); tcp only.
	SYN bool `json:"syn,omitempty"`
	// IPOptions matches only IPv4 packets that carry IP options, whose
	// header is longer than 20 bytes; ipv4 only.
	IPOptions bool `json:"ip_options,omitempty"`
}

// Setting sets a kernel setting to the one value its allow-list entry permits.
type Setting struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Module stops a kernel module from loading.
type Module struct {
	Name string `json:"name"`
}

// Service stops and masks a systemd unit.
type Service struct {
	Unit string `json:"unit"`
}

// Strip removes the setuid and setgid bits from a packaged program.
type Strip struct {
	Path string `json:"path"`
}

// Limits on a guard's size, so that every guard stays small enough to read.
const (
	maxFlaws   = 16
	maxTargets = 16
	maxBlocks  = 16
	maxPorts   = 32
	// maxPortsCovered caps how many ports one drop may cover in all.
	maxPortsCovered = 1024
	maxUntil        = 32
	maxBreaks       = 300
)

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$`)
	flawRe    = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[0-9A-Za-z][0-9A-Za-z.:_-]*$`)
	osRe      = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
	releaseRe = regexp.MustCompile(`^[0-9][0-9.]*$`)
	versionRe = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~:-]*$`)
	moduleRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	unitRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]*\.(service|socket|timer|path)$`)
	pathRe    = regexp.MustCompile(`^(/[A-Za-z0-9._+-]+)+$`)
)

// Parse reads a guard file as the agent acts on it: the file must be the
// guard's canonical form exactly (Canonical), with at most one trailing
// newline, so that the hash a signature covers is the hash of the file's
// bytes. Unknown fields, repeated keys, data after the guard, and any other
// spelling of the same guard are refused. Use Decode, then Canonical, to
// write a guard file from a looser one.
func Parse(data []byte) (*Guard, error) {
	g, err := Decode(data)
	if err != nil {
		return nil, err
	}
	body := bytes.TrimSuffix(data, []byte("\n"))
	if !bytes.Equal(body, g.Canonical()) {
		return nil, errors.New("reading guard: the file isn't in canonical form; write it with `repairer-agent fmt`")
	}
	return g, nil
}

// Decode reads a guard strictly by field (no unknown fields, nothing after
// it, every field valid) but in any spelling of JSON. Parse is what the agent
// uses for files it acts on.
func Decode(data []byte) (*Guard, error) {
	if len(data) > MaxSize {
		return nil, fmt.Errorf("guard is %d bytes; the limit is %d", len(data), MaxSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var g Guard
	if err := dec.Decode(&g); err != nil {
		return nil, fmt.Errorf("reading guard: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("reading guard: something follows the guard")
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return &g, nil
}

// Canonical is the guard's canonical form: compact JSON, its fields in the
// order this package declares them, empty optional fields left out. It is a
// frozen format: TestCanonicalIsFrozen pins guard one's bytes and hash, so
// that no release can change a guard's hash and void the signatures on it.
func (g *Guard) Canonical() []byte {
	b, err := json.Marshal(g)
	if err != nil {
		panic("guard: encoding a guard: " + err.Error()) // only plain fields
	}
	return b
}

// Hash is the guard's identity for signatures: the hex sha256 of its
// canonical form, which for a file Parse accepted is the file's own bytes.
func (g *Guard) Hash() string {
	sum := sha256.Sum256(g.Canonical())
	return hex.EncodeToString(sum[:])
}

// Name is the guard's ID and version, as people read them.
func (g *Guard) Name() string { return fmt.Sprintf("%s v%d", g.ID, g.Version) }

// Validate checks every field of the guard and every block against the
// agent's lists.
func (g *Guard) Validate() error {
	if len(g.ID) > 64 || !idRe.MatchString(g.ID) {
		return fmt.Errorf("guard id %q: use lowercase letters, digits, '.', '_', '-' and '/', at most 64", g.ID)
	}
	if g.Version < 1 || g.Version > 1_000_000 {
		return fmt.Errorf("guard %s: version must be from 1 to 1000000", g.ID)
	}
	if len(g.Flaws) == 0 || len(g.Flaws) > maxFlaws {
		return fmt.Errorf("guard %s: name 1 to %d flaws", g.ID, maxFlaws)
	}
	for _, f := range g.Flaws {
		if len(f) > 64 || !flawRe.MatchString(f) {
			return fmt.Errorf("guard %s: flaw %q is not an identifier like CVE-2026-98432", g.ID, f)
		}
	}
	if len(g.For) == 0 || len(g.For) > maxTargets {
		return fmt.Errorf("guard %s: name 1 to %d systems in \"for\"", g.ID, maxTargets)
	}
	for _, t := range g.For {
		if !osRe.MatchString(t.OS) || len(t.OS) > 32 {
			return fmt.Errorf("guard %s: os %q is not an os-release ID", g.ID, t.OS)
		}
		if len(t.Releases) == 0 || len(t.Releases) > maxTargets {
			return fmt.Errorf("guard %s: name 1 to %d releases of %s", g.ID, maxTargets, t.OS)
		}
		for _, r := range t.Releases {
			if !releaseRe.MatchString(r) || len(r) > 16 {
				return fmt.Errorf("guard %s: release %q of %s is not a VERSION_ID", g.ID, r, t.OS)
			}
		}
	}
	if len(g.Blocks) == 0 || len(g.Blocks) > maxBlocks {
		return fmt.Errorf("guard %s: give 1 to %d blocks", g.ID, maxBlocks)
	}
	seen := map[string]bool{}
	for i, b := range g.Blocks {
		if err := b.validate(); err != nil {
			return fmt.Errorf("guard %s, block %d: %w", g.ID, i+1, err)
		}
		k := b.key()
		if seen[k] {
			return fmt.Errorf("guard %s, block %d: the same %s twice", g.ID, i+1, b.Kind())
		}
		seen[k] = true
	}
	if g.Breaks == "" || len(g.Breaks) > maxBreaks || !printable(g.Breaks) {
		return fmt.Errorf("guard %s: \"breaks\" must say in 1 to %d printable characters what stops working", g.ID, maxBreaks)
	}
	if len(g.Until) > maxUntil {
		return fmt.Errorf("guard %s: at most %d fixed builds in \"until\"", g.ID, maxUntil)
	}
	for _, u := range g.Until {
		if !osRe.MatchString(u.OS) || !releaseRe.MatchString(u.Release) ||
			len(u.Kernel) > 64 || !versionRe.MatchString(u.Kernel) {
			return fmt.Errorf("guard %s: until %+v is not an os, release and kernel version", g.ID, u)
		}
	}
	return nil
}

// Kind names the block's kind: "drop", "setting", "module", "service" or
// "strip".
func (b Block) Kind() string {
	switch {
	case b.Drop != nil:
		return "drop"
	case b.Setting != nil:
		return "setting"
	case b.Module != nil:
		return "module"
	case b.Service != nil:
		return "service"
	case b.Strip != nil:
		return "strip"
	}
	return ""
}

func (b Block) count() int {
	n := 0
	for _, set := range []bool{b.Drop != nil, b.Setting != nil, b.Module != nil, b.Service != nil, b.Strip != nil} {
		if set {
			n++
		}
	}
	return n
}

// key identifies what a block touches, to refuse the same thing twice in one
// guard.
func (b Block) key() string {
	switch {
	case b.Drop != nil:
		j, _ := json.Marshal(b.Drop)
		return "drop " + string(j)
	case b.Setting != nil:
		return "setting " + b.Setting.Name
	case b.Module != nil:
		return "module " + b.Module.Name
	case b.Service != nil:
		return "service " + b.Service.Unit
	case b.Strip != nil:
		return "strip " + b.Strip.Path
	}
	return ""
}

func (b Block) validate() error {
	if b.count() != 1 {
		return errors.New("a block must have exactly one of drop, setting, module, service, strip")
	}
	switch {
	case b.Drop != nil:
		return b.Drop.validate()
	case b.Setting != nil:
		return b.Setting.validate()
	case b.Module != nil:
		return b.Module.validate()
	case b.Service != nil:
		return b.Service.validate()
	default:
		return b.Strip.validate()
	}
}

func (d *Drop) validate() error {
	switch d.Family {
	case "ipv4", "ipv6":
	default:
		return fmt.Errorf("drop: family %q must be ipv4 or ipv6", d.Family)
	}
	switch d.Protocol {
	case "", "tcp", "udp":
	case "icmp":
		if d.Family != "ipv4" {
			return errors.New("drop: icmp is ipv4; use icmpv6 for ipv6")
		}
	case "icmpv6":
		if d.Family != "ipv6" {
			return errors.New("drop: icmpv6 is ipv6; use icmp for ipv4")
		}
	default:
		return fmt.Errorf("drop: protocol %q must be tcp, udp, icmp or icmpv6", d.Protocol)
	}
	if len(d.Ports) > 0 && d.Protocol != "tcp" && d.Protocol != "udp" {
		return errors.New("drop: ports need protocol tcp or udp")
	}
	if len(d.Ports) > maxPorts {
		return fmt.Errorf("drop: at most %d ports", maxPorts)
	}
	ranges, err := d.PortRanges()
	if err != nil {
		return err
	}
	covered := 0
	for _, r := range ranges {
		covered += r[1] - r[0] + 1
	}
	if covered > maxPortsCovered {
		return fmt.Errorf("drop: covers %d ports; at most %d", covered, maxPortsCovered)
	}
	if d.SYN && d.Protocol != "tcp" {
		return errors.New("drop: syn needs protocol tcp")
	}
	if d.IPOptions && d.Family != "ipv4" {
		return errors.New("drop: ip_options is ipv4 only")
	}
	// A drop must be narrower than "all of a protocol": by port or by a
	// packet feature. SYN alone isn't narrowing; it would refuse every new
	// connection.
	if len(ranges) == 0 && !d.IPOptions {
		return errors.New("drop: too broad; narrow it by ports or by a packet feature such as ip_options")
	}
	// Dropping ssh by port alone would lock owners out; ssh is on the
	// never-touch list.
	if !d.IPOptions && d.Protocol == "tcp" {
		for _, r := range ranges {
			if r[0] <= 22 && 22 <= r[1] {
				return errors.New("drop: port 22 (ssh) is never dropped by port alone")
			}
		}
	}
	return nil
}

// PortRanges parses Ports into inclusive [from, to] ranges.
func (d *Drop) PortRanges() ([][2]int, error) {
	var out [][2]int
	for _, p := range d.Ports {
		from, to, ok := strings.Cut(p, "-")
		lo, err1 := port(from)
		hi := lo
		var err2 error
		if ok {
			hi, err2 = port(to)
		}
		if err1 != nil || err2 != nil || hi < lo {
			return nil, fmt.Errorf("drop: port %q must be a port from 1 to 65535 or a range like 137-139", p)
		}
		out = append(out, [2]int{lo, hi})
	}
	return out, nil
}

func port(s string) (int, error) {
	if s == "" || len(s) > 5 || (len(s) > 1 && s[0] == '0') {
		return 0, errors.New("bad port")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("bad port")
		}
		n = n*10 + int(c-'0')
	}
	if n < 1 || n > 65535 {
		return 0, errors.New("bad port")
	}
	return n, nil
}

func (s *Setting) validate() error {
	r, ok := settings[s.Name]
	if !ok {
		return fmt.Errorf("setting: %q is not on the agent's list of settings a guard may change", s.Name)
	}
	if s.Value != r.Value {
		return fmt.Errorf("setting: %s may only be set to %s", s.Name, r.Value)
	}
	return nil
}

func (m *Module) validate() error {
	if len(m.Name) > 64 || !moduleRe.MatchString(m.Name) {
		return fmt.Errorf("module: %q is not a module name", m.Name)
	}
	if neverBlock(m.Name) {
		return fmt.Errorf("module: %s is never blocked (firewall, storage, network, virtualization or graphics)", m.Name)
	}
	if looksLikeAlias(m.Name) {
		return fmt.Errorf("module: %q looks like a module alias; name the module itself", m.Name)
	}
	return nil
}

func (s *Service) validate() error {
	if len(s.Unit) > 128 || !unitRe.MatchString(s.Unit) {
		return fmt.Errorf("service: %q is not a unit name like cups-browsed.service", s.Unit)
	}
	if neverStop(s.Unit) {
		return fmt.Errorf("service: %s is on the never-touch list", s.Unit)
	}
	return nil
}

func (s *Strip) validate() error {
	p := s.Path
	if len(p) > 256 || !pathRe.MatchString(p) || strings.Contains(p, "/../") ||
		strings.HasSuffix(p, "/..") || strings.Contains(p, "/./") || strings.HasSuffix(p, "/.") {
		return fmt.Errorf("strip: %q is not a plain absolute path", p)
	}
	if !strings.HasPrefix(p, "/usr/") && !strings.HasPrefix(p, "/bin/") &&
		!strings.HasPrefix(p, "/sbin/") && !strings.HasPrefix(p, "/opt/") {
		return fmt.Errorf("strip: %s is outside /usr, /bin, /sbin and /opt", p)
	}
	if neverStrip(p) {
		return fmt.Errorf("strip: %s is on the never-touch list", p)
	}
	return nil
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '�' {
			return false
		}
	}
	return true
}
