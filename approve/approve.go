// Package approve checks the signed statements an agent acts on: approvals,
// policies and attestations.
//
// The owner signs with a Ledger through gnokey. The statement is a gno sign doc
// on a chain id no real chain uses, whose one message is a MsgCall to
// gno.land/r/autopatch/approve that never runs. The agent rebuilds the signed
// bytes itself from typed fields and checks the signature against them. It
// never checks a signature over JSON it parsed. Every other key (agents, the
// rig, vetters, the local model) is Ed25519.
package approve

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Realm is the path every statement's MsgCall names. Nothing runs there.
const Realm = "gno.land/r/autopatch/approve"

// MaxSeqJump is the most a signer's sequence may rise in one step. A larger
// jump is refused, so a hijacked lookout can't spend a signer's sequence
// numbers to the top and lock out everything the signer signs after.
const MaxSeqJump = 1000

// ChainID returns the chain id of an owner's statements for one fleet:
// "autopatch:" and the first 16 hex digits of the owner key's sha256, a "/",
// and the fleet's name. Two owners who both call a fleet "home" don't accept
// each other's statements.
func ChainID(ownerKey []byte, fleet string) string {
	sum := sha256.Sum256(ownerKey)
	return "autopatch:" + hex.EncodeToString(sum[:8]) + "/" + fleet
}

// Call is a statement's one message: the function and arguments of a MsgCall
// to Realm.
type Call struct {
	// Caller is the MsgCall's caller as gnokey wrote it. It is part of the
	// signed bytes and nothing else: who signed is told by the key.
	Caller string
	Func   string
	Args   []string
}

var (
	funcRe   = regexp.MustCompile(`^[A-Z][A-Za-z]{1,31}$`)
	callerRe = regexp.MustCompile(`^g1[02-9ac-hj-np-z]{38}$`)
)

// SignBytes rebuilds the bytes gno signs for a statement: the sign doc as
// amino JSON with sorted keys. The current rendering carries the fee in the
// Ledger Cosmos app's form, {"amount": [], "gas": "0"} for a zero fee; the
// legacy rendering, which gno also accepts, carries {"gas_fee": "",
// "gas_wanted": "0"}. encoding/json sorts map keys and escapes <, >, & and
// U+2028/U+2029 exactly as gno's sortJSON does, and every number here is a
// string, as amino writes 64-bit numbers.
func SignBytes(chainID string, seq uint64, c Call, memo string, legacy bool) ([]byte, error) {
	if !funcRe.MatchString(c.Func) {
		return nil, fmt.Errorf("approve: function %q", c.Func)
	}
	if !callerRe.MatchString(c.Caller) {
		return nil, fmt.Errorf("approve: caller %q is not a g1 address", c.Caller)
	}
	msg := map[string]any{
		"@type":       "/vm.m_call",
		"caller":      c.Caller,
		"send":        "",
		"max_deposit": "",
		"pkg_path":    Realm,
		"func":        c.Func,
	}
	if len(c.Args) > 0 { // amino omits an empty args list
		msg["args"] = c.Args
	}
	var fee map[string]any
	if legacy {
		fee = map[string]any{"gas_fee": "", "gas_wanted": "0"}
	} else {
		fee = map[string]any{"amount": []any{}, "gas": "0"}
	}
	return json.Marshal(map[string]any{
		"account_number": "0",
		"chain_id":       chainID,
		"fee":            fee,
		"memo":           memo,
		"msgs":           []any{msg},
		"sequence":       strconv.FormatUint(seq, 10),
	})
}

// VerifySecp256k1 reports whether sig, 64 bytes of r and s, is pub's
// signature over the sha256 of msg, checked as gno checks it: pub is a
// 33-byte compressed key on the curve, r and s are below the group order and
// not zero, and s is at most half the order.
func VerifySecp256k1(pub, msg, sig []byte) bool {
	if len(pub) != 33 || (pub[0] != 2 && pub[0] != 3) || len(sig) != 64 {
		return false
	}
	key, err := secp256k1.ParsePubKey(pub)
	if err != nil {
		return false
	}
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(sig[:32]) || s.SetByteSlice(sig[32:]) {
		return false // r or s overflowed the order
	}
	if r.IsZero() || s.IsZero() || s.IsOverHalfOrder() {
		return false
	}
	h := sha256.Sum256(msg)
	return ecdsa.NewSignature(&r, &s).Verify(h[:], key)
}

// VerifyEd25519 reports whether sig is pub's Ed25519 signature over msg.
func VerifyEd25519(pub, msg, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize &&
		ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// GnokeyTx is the part of gnokey's signed transaction file a statement
// needs: its one message, its memo, and its one signature.
type GnokeyTx struct {
	Msg []struct {
		Type       string   `json:"@type"`
		Caller     string   `json:"caller"`
		Send       string   `json:"send"`
		MaxDeposit string   `json:"max_deposit"`
		PkgPath    string   `json:"pkg_path"`
		Func       string   `json:"func"`
		Args       []string `json:"args"`
	} `json:"msg"`
	Memo       string `json:"memo"`
	Signatures []struct {
		PubKey struct {
			Type  string `json:"@type"`
			Value []byte `json:"value"` // base64
		} `json:"pub_key"`
		Signature []byte `json:"signature"` // base64
	} `json:"signatures"`
}

// Statement is a checked statement: who signed it, with which sequence, and
// what it says.
type Statement struct {
	Seq  uint64
	Call Call
}

// VerifyGnokey checks a statement in gnokey's signed transaction file. The
// signer must be pub (pinned in the policy), the sequence seq, the chain id
// chainID, and the memo exactly wantMemo, which the agent wrote itself from
// the file the statement is about. The signature is checked against bytes
// the agent rebuilds, in both of gno's fee renderings.
func VerifyGnokey(txJSON []byte, chainID string, seq uint64, pub []byte, wantMemo string) (*Statement, error) {
	var tx GnokeyTx
	if err := json.Unmarshal(txJSON, &tx); err != nil {
		return nil, fmt.Errorf("approve: reading the signed transaction: %w", err)
	}
	if len(tx.Msg) != 1 || len(tx.Signatures) != 1 {
		return nil, errors.New("approve: a statement has exactly one message and one signature")
	}
	m := tx.Msg[0]
	if m.Type != "/vm.m_call" || m.PkgPath != Realm || m.Send != "" || m.MaxDeposit != "" {
		return nil, fmt.Errorf("approve: the message is not a call to %s", Realm)
	}
	if tx.Memo != wantMemo {
		return nil, errors.New("approve: the memo differs from the one the agent writes for this statement")
	}
	sg := tx.Signatures[0]
	if sg.PubKey.Type != "/tm.PubKeySecp256k1" || string(sg.PubKey.Value) != string(pub) {
		return nil, errors.New("approve: signed by a key other than the pinned one")
	}
	c := Call{Caller: m.Caller, Func: m.Func, Args: m.Args}
	for _, legacy := range []bool{false, true} {
		b, err := SignBytes(chainID, seq, c, wantMemo, legacy)
		if err != nil {
			return nil, err
		}
		if VerifySecp256k1(pub, b, sg.Signature) {
			return &Statement{Seq: seq, Call: c}, nil
		}
	}
	return nil, errors.New("approve: the signature doesn't verify for this chain id, sequence and memo")
}

// CheckSeq applies the sequence rule: a statement's sequence must be above
// the last one accepted from its signer, by at most MaxSeqJump.
func CheckSeq(last, seq uint64) error {
	if seq <= last {
		return fmt.Errorf("approve: sequence %d is not above the last accepted, %d", seq, last)
	}
	if seq-last > MaxSeqJump {
		return fmt.Errorf("approve: sequence %d jumps more than %d past the last accepted, %d", seq, MaxSeqJump, last)
	}
	return nil
}
