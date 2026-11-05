package approve

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Kinds of Ed25519 statement, and the role that may sign each.
const (
	KindTested  = "Tested"   // a rig or vetter: the guard passed the pinned rig
	KindHealthy = "Healthy"  // an agent: the guard is on here, or refused here
	KindModel   = "ModelYes" // the local model, within rule 6's limits
)

// Statement is what an agent, the rig, a vetter or the local model signs
// with Ed25519. The signed bytes are the statement's canonical JSON, which
// the checker rebuilds itself from the fields; it never checks a signature
// over bytes it was handed.
type Statement struct {
	Version string `json:"v"`     // MemoVersion
	Kind    string `json:"kind"`  // KindTested, KindHealthy or KindModel
	Chain   string `json:"chain"` // autopatch:vet for Tested, the fleet's chain id otherwise
	Guard   string `json:"guard"` // the guard's hash
	// Rig is the pinned rig's hash, for Tested.
	Rig string `json:"rig,omitempty"`
	// Host, State ("on" or "refused") and Why, for Healthy; Nonce is the
	// fresh number the waiting agent chose, so an old Healthy can't be
	// replayed.
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

func (st Statement) bytes() ([]byte, error) {
	if st.Version != MemoVersion {
		return nil, fmt.Errorf("approve: statement version %q", st.Version)
	}
	if !isHash(st.Guard) {
		return nil, errors.New("approve: a statement names a guard by its hash")
	}
	switch st.Kind {
	case KindTested:
		if st.Chain != "autopatch:vet" || !isHash(st.Rig) || st.Host != "" || st.State != "" {
			return nil, errors.New("approve: a Tested statement names the rig and no fleet")
		}
	case KindHealthy:
		if st.Host == "" || (st.State != "on" && st.State != "refused") || len(st.Nonce) != 32 || (st.State == "refused") != (st.Why != "") {
			return nil, errors.New("approve: a Healthy statement names a host, on or refused (with why), and a nonce")
		}
	case KindModel:
		if st.Rig != "" || st.Host != "" || st.State != "" {
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
