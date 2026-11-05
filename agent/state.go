package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jaekwon/autopatch/guard"
)

// Status of a guard on this machine.
const (
	// Applying: the agent is putting the guard on, or died doing so. Steps
	// below Entry.Applied are on; the step at Applied may be partly on.
	Applying = "applying"
	// Pending: the guard is on live, with its undo armed until confirmed.
	// Nothing about it survives a reboot except what the boot undoes.
	Pending = "pending"
	// Confirmed: the guard is on and stays on across reboots.
	Confirmed = "confirmed"
)

// Entry is one guard on this machine.
type Entry struct {
	Hash      string       `json:"hash"`
	Guard     *guard.Guard `json:"guard"`
	Status    string       `json:"status"`
	Applied   int          `json:"applied"` // steps fully on, in order
	AppliedAt time.Time    `json:"applied_at"`
	ConfirmBy time.Time    `json:"confirm_by,omitzero"`
	Unprobed  bool         `json:"unprobed,omitempty"` // a drop the agent has no probe for
}

// UnitState is a unit's state before the first guard masked it.
type UnitState struct {
	Enabled string `json:"enabled"` // what `systemctl is-enabled` said
	Active  bool   `json:"active"`
}

// Originals holds what a resource was before the first guard changed it,
// so the last guard to let go of it can put it back.
type Originals struct {
	Settings map[string]string    `json:"settings,omitempty"`
	Modes    map[string]uint32    `json:"modes,omitempty"`
	Units    map[string]UnitState `json:"units,omitempty"`
}

// State is the agent's record of the guards on this machine. It is written
// ahead of every change, so that after a crash the agent knows what may be
// on.
type State struct {
	Guards    []*Entry  `json:"guards"`
	Originals Originals `json:"originals"`
}

func (s *State) find(hash string) *Entry {
	for _, e := range s.Guards {
		if e.Hash == hash {
			return e
		}
	}
	return nil
}

func (s *State) remove(hash string) {
	out := s.Guards[:0]
	for _, e := range s.Guards {
		if e.Hash != hash {
			out = append(out, e)
		}
	}
	s.Guards = out
}

// store reads and writes the state file under a lock held for a whole
// command, so the undo timer and a command never interleave.
type store struct {
	dir  string
	lock *os.File
}

const stateFile = "state.json"

func openStore(dir string) (*store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("locking %s: %w", dir, err)
	}
	return &store{dir: dir, lock: f}, nil
}

func (s *store) close() { s.lock.Close() } // closing drops the lock

func (s *store) load() (*State, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("reading %s: %w", stateFile, err)
	}
	// Only the hash is checked here, not the agent's lists: a guard that
	// went on under an older release must still be readable, so that it can
	// be checked and taken off after an upgrade that tightened a list.
	for _, e := range st.Guards {
		if e.Guard == nil || e.Guard.Hash() != e.Hash {
			return nil, fmt.Errorf("%s: entry %s doesn't hold a guard with that hash", stateFile, e.Hash)
		}
	}
	return &st, nil
}

func (s *store) save(st *State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.dir, stateFile), append(b, '\n'), 0o600)
}
