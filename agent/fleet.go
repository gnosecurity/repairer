package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/jaekwon/autopatch/policy"
)

// The agent's fleet files, beside its state file. The policy and the
// sequence floor are installed by root by hand (init); after that only
// statements the owner signed change them.
const (
	fleetFile = "fleet.json"
	keyFile   = "agent.key" // the agent's Ed25519 private key, 0600
	spoolDir  = "spool"     // bundles from the lookout, waiting for tick

	// SpoolDir is where intake leaves bundles, under the state directory.
	SpoolDir = spoolDir

	// MaxBundle caps one bundle from the lookout.
	MaxBundle = 1 << 20
)

// errNoFleet is loadFleet's error before init has installed a policy.
var errNoFleet = errors.New("agent: no policy installed; run init as root")

// Fleet is what the agent knows of its fleet: this host's name in the
// policy, the policy in force, a signed change waiting out its delay, the
// last sequence accepted from the owner, and guards refused for good.
type Fleet struct {
	Host string `json:"host"`
	// Policy is the canonical bytes of the policy in force, kept exactly
	// (base64 in the file: a json.RawMessage would be re-indented).
	Policy  []byte         `json:"policy"`
	Pending *PendingPolicy `json:"pending,omitempty"`
	LastSeq uint64         `json:"last_seq"`
	Off     []string       `json:"off,omitempty"` // guard hashes the owner took off this host
	// ReportSeq numbers this agent's signed reports.
	ReportSeq uint64 `json:"report_seq"`
	// Held says why the owner's statements stop where they do, until it
	// clears; Skipped lists the newest statements taken but not acted on.
	Held    string    `json:"held,omitempty"`
	Skipped []Skipped `json:"skipped,omitempty"`
}

// Skipped is an owner statement this agent took but couldn't act on.
type Skipped struct {
	Seq  uint64 `json:"seq"`
	What string `json:"what"`
	Why  string `json:"why"`
}

// maxSkipped is how many skipped statements the fleet file keeps.
const maxSkipped = 20

// PendingPolicy is a signed policy change counting down its delay from when
// this agent first saw it.
type PendingPolicy struct {
	Policy    []byte    `json:"policy"`
	FirstSeen time.Time `json:"first_seen"`
}

// InstalledPolicy reads the policy in force.
func (f *Fleet) InstalledPolicy() (*policy.Policy, error) {
	return policy.Parse(f.Policy)
}

// Init installs the first policy by hand, as root on the machine itself:
// the host's name in it, the policy file, and the owner's sequence floor (a
// restored or rebuilt machine is set up again the same way). It makes the
// agent's Ed25519 key if there isn't one and returns its public half, which
// the owner puts in the next policy as this host's agent key.
func (a *Agent) Init(host string, policyFile []byte, seqFloor uint64) (ed25519.PublicKey, error) {
	p, err := policy.Parse(policyFile)
	if err != nil {
		return nil, err
	}
	if _, ok := p.TierOf(host); !ok {
		return nil, fmt.Errorf("init: host %s is in no tier of this policy", host)
	}
	pub, err := a.agentKey()
	if err != nil {
		return nil, err
	}
	lock, err := lockFile(filepath.Join(a.StateDir, "tick.lock")) // no tick in between
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	f := &Fleet{Host: host, Policy: p.Canonical(), LastSeq: seqFloor}
	if err := a.saveFleet(f); err != nil {
		return nil, err
	}
	return pub, nil
}

// agentKey returns the agent's public key, making the key pair once.
func (a *Agent) agentKey() (ed25519.PublicKey, error) {
	path := filepath.Join(a.StateDir, keyFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(a.StateDir, 0o700); err != nil {
			return nil, err
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := writeAtomic(path, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
			return nil, err
		}
		return priv.Public().(ed25519.PublicKey), nil
	}
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("agent: the key file is damaged")
	}
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
}

// privateKey reads the agent's Ed25519 private key.
func (a *Agent) privateKey() (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(a.StateDir, keyFile))
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("agent: the key file is damaged")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (a *Agent) loadFleet() (*Fleet, error) {
	b, err := os.ReadFile(filepath.Join(a.StateDir, fleetFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoFleet
	}
	if err != nil {
		return nil, err
	}
	var f Fleet
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("agent: reading %s: %w", fleetFile, err)
	}
	if _, err := f.InstalledPolicy(); err != nil {
		return nil, fmt.Errorf("agent: the installed policy: %w", err)
	}
	return &f, nil
}

func (a *Agent) saveFleet(f *Fleet) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(a.StateDir, fleetFile), append(b, '\n'), 0o600)
}

// Intake takes one bundle from the lookout and leaves it in the spool for
// the next tick. It acts on nothing: the lookout's ssh key runs only this,
// as the unprivileged user that owns the spool, and tick (as root) checks
// every signature before anything happens.
func Intake(spool string, r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBundle+1))
	if err != nil {
		return "", err
	}
	if len(b) > MaxBundle {
		return "", fmt.Errorf("intake: a bundle is at most %d bytes", MaxBundle)
	}
	if !json.Valid(b) {
		return "", errors.New("intake: a bundle is JSON")
	}
	if err := os.MkdirAll(spool, 0o700); err != nil {
		return "", err
	}
	var name [8]byte
	if _, err := rand.Read(name[:]); err != nil {
		return "", err
	}
	path := filepath.Join(spool, time.Now().UTC().Format("20060102T150405Z")+"-"+hex.EncodeToString(name[:])+".json")
	return path, writeAtomic(path, b, 0o600)
}
