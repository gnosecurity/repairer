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

// reportDomain starts the bytes an agent signs for a report, so a report's
// signature can never pass as a statement's, or the other way round.
const reportDomain = MemoVersion + " report\n"

// SignedReport is an agent's report as it signed it: the exact body bytes,
// its key and its signature, in hex. The reader checks the signature over
// the bytes it was given, then parses them; nothing is re-encoded.
type SignedReport struct {
	Body []byte `json:"body"` // JSON; base64 in the file
	Key  string `json:"key"`
	Sig  string `json:"sig"`
}

// SignReport signs a report's body with an agent's Ed25519 key.
func SignReport(priv ed25519.PrivateKey, body []byte) SignedReport {
	msg := append([]byte(reportDomain), body...)
	return SignedReport{Body: body, Key: hex.EncodeToString(priv.Public().(ed25519.PublicKey)), Sig: hex.EncodeToString(ed25519.Sign(priv, msg))}
}

// VerifyReport reads a signed report strictly and checks its signature
// against want, the agent's key in hex as the policy lists it. It returns
// the body.
func VerifyReport(data []byte, want string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var sr SignedReport
	if err := dec.Decode(&sr); err != nil {
		return nil, fmt.Errorf("approve: reading a signed report: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("approve: something follows the report")
	}
	if sr.Key != want {
		return nil, errors.New("approve: the report is signed by another key")
	}
	key, err1 := hex.DecodeString(sr.Key)
	sig, err2 := hex.DecodeString(sr.Sig)
	if err1 != nil || err2 != nil {
		return nil, errors.New("approve: key and signature are hex")
	}
	if !VerifyEd25519(key, append([]byte(reportDomain), sr.Body...), sig) {
		return nil, errors.New("approve: the report's signature doesn't verify")
	}
	return sr.Body, nil
}
