package approve

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

// Kinds of Ed25519 statement, and the role that may sign each.
const (
	KindTested  = "Tested"   // a rig or vetter: the guard passed the pinned rig
	KindHealthy = "Healthy"  // an agent: the guard is on here, or refused here
	KindModel   = "ModelYes" // the local model, within rule 6's limits
)

// What a canary's Healthy says.
const (
	StateOn      = "on"      // on and confirmed here, keep included
	StateBooted  = "booted"  // on, and confirmed again after a boot
	StateRefused = "refused" // refused here, for one of RefusalCodes
)

// RefusalCodes are the only reasons a canary may give for refusing a guard:
// conditions of its own, never a missing signature or a passing error.
var RefusalCodes = []string{"in-use", "netns", "never-touch", "protected-flow"}

// IsRefusalCode reports whether s is one of RefusalCodes.
func IsRefusalCode(s string) bool {
	for _, c := range RefusalCodes {
		if s == c {
			return true
		}
	}
	return false
}

// Statement is what an agent, the rig, a vetter or the local model signs
// with Ed25519. The signed bytes are the statement's canonical JSON, which
// the checker rebuilds itself from the fields; it never checks a signature
// over bytes it was handed.
type Statement struct {
	Version string `json:"v"`     // MemoVersion
	Kind    string `json:"kind"`  // KindTested, KindHealthy or KindModel
	Chain   string `json:"chain"` // autopatch:vet for Tested, the fleet's chain id otherwise
	Guard   string `json:"guard"` // the guard's hash
	// Rig is the pinned rig's hash, for Tested, and Image the system it ran,
	// such as "ubuntu 24.04": a Tested counts only on machines of that
	// system (round 8, minor 9).
	Rig   string `json:"rig,omitempty"`
	Image string `json:"image,omitempty"`
	// Host, State (StateOn, StateBooted or StateRefused) and Why (a refusal
	// code), for Healthy; Nonce is the fresh number the waiting agent chose,
	// so an old Healthy can't be replayed.
	Host  string `json:"host,omitempty"`
	State string `json:"state,omitempty"`
	Why   string `json:"why,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// Signed is a statement with its signer's key and signature, in hex.
type Signed struct {
	Statement Statement `json:"statement"`
	Key       string    `json:"key"`
	Sig       string    `json:"sig"`
}

// SignStatement signs a statement with an Ed25519 key.
func SignStatement(priv ed25519.PrivateKey, st Statement) (Signed, error) {
	b, err := st.bytes()
	if err != nil {
		return Signed{}, err
	}
	return Signed{Statement: st, Key: hex.EncodeToString(priv.Public().(ed25519.PublicKey)), Sig: hex.EncodeToString(ed25519.Sign(priv, b))}, nil
}

// imageRe is a system as a Tested names it: an os-release ID and VERSION_ID.
var imageRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31} [0-9][0-9.]{0,15}$`)

func (st Statement) bytes() ([]byte, error) {
	if st.Version != MemoVersion {
		return nil, fmt.Errorf("approve: statement version %q", st.Version)
	}
	if !isHash(st.Guard) {
		return nil, errors.New("approve: a statement names a guard by its hash")
	}
	switch st.Kind {
	case KindTested:
		if st.Chain != "autopatch:vet" || !isHash(st.Rig) || !imageRe.MatchString(st.Image) || st.Host != "" || st.State != "" {
			return nil, errors.New("approve: a Tested statement names the rig, the system it ran (\"ubuntu 24.04\") and no fleet")
		}
	case KindHealthy:
		okState := st.State == StateOn || st.State == StateBooted || (st.State == StateRefused && IsRefusalCode(st.Why))
		if st.Host == "" || !okState || (st.State != StateRefused && st.Why != "") || len(st.Nonce) != 32 || st.Image != "" {
			return nil, errors.New("approve: a Healthy statement names a host; on, booted, or refused with a listed reason; and a nonce")
		}
	case KindModel:
		if st.Rig != "" || st.Image != "" || st.Host != "" || st.State != "" {
			return nil, errors.New("approve: a model's yes names only the guard")
		}
	default:
		return nil, fmt.Errorf("approve: kind %q", st.Kind)
	}
	if len(st.Why) > 200 || !printable(st.Why) {
		return nil, errors.New("approve: why must be short and printable")
	}
	return json.Marshal(st)
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// ParseSigned reads a signed statement strictly and checks its signature
// against the bytes rebuilt from its fields. It returns the signer's key.
func ParseSigned(data []byte) (*Signed, []byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Signed
	if err := dec.Decode(&s); err != nil {
		return nil, nil, fmt.Errorf("approve: reading a signed statement: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, errors.New("approve: something follows the statement")
	}
	key, err1 := hex.DecodeString(s.Key)
	sig, err2 := hex.DecodeString(s.Sig)
	if err1 != nil || err2 != nil {
		return nil, nil, errors.New("approve: key and signature are hex")
	}
	b, err := s.Statement.bytes()
	if err != nil {
		return nil, nil, err
	}
	if !VerifyEd25519(key, b, sig) {
		return nil, nil, errors.New("approve: the signature doesn't verify")
	}
	return &s, key, nil
}
