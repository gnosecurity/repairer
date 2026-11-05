// Package lightclient proves what a gno.land realm holds without trusting
// the node it asks: a realm param (chain/params, stored at
// /pv/vm:<realm>:<key> in the proven main store) with its ics23 proofs,
// checked against the app hash of a header that more than two thirds of a
// trusted validator set signed. Trust starts at an owner-signed checkpoint
// and follows the validator set forward (G2): a header signed by a new set
// is accepted only when more than two thirds of the trusted set signed it
// too, stepping through heights in between when too much changed at once,
// and never more than MaxGap past the checkpoint. It is a separate module,
// so the agent never carries tm2.
package lightclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gnolang/gno/tm2/pkg/bft/rpc/client"
	ctypes "github.com/gnolang/gno/tm2/pkg/bft/rpc/core/types"
	"github.com/gnolang/gno/tm2/pkg/bft/types"
	"github.com/gnolang/gno/tm2/pkg/crypto/merkle"
	"github.com/gnolang/gno/tm2/pkg/store/rootmulti"
)

// Node is what the client asks: a gno.land node's RPC client (one you run),
// or a stand-in in tests.
type Node interface {
	ABCIQueryWithOptions(ctx context.Context, path string, data []byte, opts client.ABCIQueryOptions) (*ctypes.ResultABCIQuery, error)
	Commit(ctx context.Context, height *int64) (*ctypes.ResultCommit, error)
	Validators(ctx context.Context, height *int64) (*ctypes.ResultValidators, error)
}

// Checkpoint is where trust starts: a height, the hash of the validator set
// that signs it, and its time, as the owner signs them in a Checkpoint
// statement (the caller checks that signature).
type Checkpoint struct {
	Height         int64
	ValidatorsHash []byte
	Time           time.Time
}

// MaxGap is the most a header's time may be past the checkpoint's: the
// owner signs a new checkpoint at least this often, so validators retired
// longer ago than that can't sign a history the client would follow
// (gno.land's validators aren't slashed).
const MaxGap = 30 * 24 * time.Hour

// Client proves realm params at heights.
type Client struct {
	RPC     Node
	ChainID string
	// Validators is the set the client trusts, at TrustedHeight: from the
	// checkpoint (Start), followed forward.
	Validators    *types.ValidatorSet
	TrustedHeight int64
	Checkpoint    *Checkpoint
	trustedNext   []byte // the set the trusted header names for the height after it
	// MaxAge refuses a proof whose header is older than this (the plan's
	// five minutes); it and Now are required.
	MaxAge time.Duration
	Now    func() time.Time

	// The newest header accepted: a later answer may not be older, so a
	// node can't walk the client back to an earlier state (round 8, minor
	// 11).
	mu   sync.Mutex
	last *types.Header
}

// MaxSkew is how far in the future a header's time may be: the validators'
// clocks and this machine's differ a little, never by more.
const MaxSkew = time.Minute

// Param asks the node for one key, which tells that node which guards
// matter here: ask only nodes you run (rule 5).

// ParamKey is where a realm param lives in the main store.
func ParamKey(realm, key string) []byte { return []byte("/pv/vm:" + realm + ":" + key) }

// Param proves a realm param at height h: its value, or that nothing is
// stored there. The proof is checked against the app hash of header h+1,
// which the trusted validators must have signed.
func (c *Client) Param(ctx context.Context, realm, key string, h int64) ([]byte, bool, error) {
	k := ParamKey(realm, key)
	res, err := c.RPC.ABCIQueryWithOptions(ctx, ".store/main/key", k, client.ABCIQueryOptions{Height: h, Prove: true})
	if err != nil {
		return nil, false, err
	}
	r := res.Response
	if r.Error != nil {
		return nil, false, fmt.Errorf("lightclient: the node: %v", r.Error)
	}
	if r.Height != h || !bytes.Equal(r.Key, k) || r.Proof == nil {
		return nil, false, errors.New("lightclient: the answer is for another height or key, or has no proof")
	}
	hdr, err := c.Header(ctx, h+1)
	if err != nil {
		return nil, false, err
	}
	return r.Value, len(r.Value) > 0, Verify(r.Proof, hdr.AppHash, k, r.Value)
}

// Verify checks a main-store proof of key's value (or of its absence, for
// an empty value) against an app hash.
func Verify(proof *merkle.Proof, appHash, key, value []byte) error {
	kp := merkle.KeyPath{}.AppendKey([]byte("main"), merkle.KeyEncodingURL).AppendKey(key, merkle.KeyEncodingURL)
	prt := rootmulti.DefaultProofRuntime()
	if len(value) == 0 {
		return prt.VerifyAbsence(proof, appHash, kp.String())
	}
	return prt.VerifyValue(proof, appHash, kp.String(), value)
}

// Start trusts the validator set a node gives for the checkpoint's height,
// once its hash is the checkpoint's: the only way trust begins.
func (c *Client) Start(ctx context.Context, cp Checkpoint) error {
	set, err := c.validators(ctx, cp.Height)
	if err != nil {
		return err
	}
	if !bytes.Equal(set.Hash(), cp.ValidatorsHash) {
		return errors.New("lightclient: the node's validators at the checkpoint aren't the ones the owner signed")
	}
	c.Validators, c.TrustedHeight, c.Checkpoint = set, cp.Height, &cp
	sh, _, err := c.signed(ctx, cp.Height) // the checkpoint's header names the next set
	if err != nil {
		return err
	}
	if err := set.VerifyCommit(c.ChainID, sh.Commit.BlockID, cp.Height, sh.Commit); err != nil {
		return fmt.Errorf("lightclient: the checkpoint's header: %w", err)
	}
	c.trustedNext = sh.Header.NextValidatorsHash
	return nil
}

// Header fetches header h with its commit, checks that the trusted
// validators signed it, following a change of validators from the trusted
// height (verify), and that it is fresh.
func (c *Client) Header(ctx context.Context, h int64) (*types.Header, error) {
	hdr, err := c.verify(ctx, h, 0)
	if err != nil {
		return nil, err
	}
	if err := c.fresh(hdr); err != nil {
		return nil, err
	}
	return hdr, nil
}

// maxSteps bounds how many heights between the trusted one and a target
// the client verifies on its way, when too much of the set changed at once.
const maxSteps = 64

// verify checks header h:
//   - signed by the trusted set: more than two thirds of its power signed it;
//   - the height right after the trusted one, signed by the set the trusted
//     header named as the next one: more than two thirds of that set signed
//     it (a change of any size, one height at a time);
//   - any later height, signed by another set: that set signed it with more
//     than two thirds of its power, and more than two thirds of the trusted
//     set's power signed it too. When too much changed at once for that, it
//     verifies a height halfway there first, and tries again.
//
// A header verified after the trusted height becomes the trusted one, with
// its set and the next set it names. Trust never moves back.
func (c *Client) verify(ctx context.Context, h int64, steps int) (*types.Header, error) {
	if c.Validators == nil || c.Checkpoint == nil {
		return nil, errors.New("lightclient: start from a checkpoint first")
	}
	sh, set, err := c.signed(ctx, h)
	if err != nil {
		return nil, err
	}
	if sh.Header.Time.Sub(c.Checkpoint.Time) > MaxGap {
		return nil, fmt.Errorf("lightclient: header %d is more than %s past the checkpoint; the owner signs a new one", h, MaxGap)
	}
	switch {
	case bytes.Equal(set.Hash(), c.Validators.Hash()):
		if err := c.Validators.VerifyCommit(c.ChainID, sh.Commit.BlockID, h, sh.Commit); err != nil {
			return nil, fmt.Errorf("lightclient: the signatures: %w", err)
		}
	case h <= c.TrustedHeight:
		return nil, fmt.Errorf("lightclient: header %d is signed by another set than the one trusted from %d on", h, c.TrustedHeight)
	case h == c.TrustedHeight+1 && bytes.Equal(set.Hash(), c.trustedNext):
		if err := set.VerifyCommit(c.ChainID, sh.Commit.BlockID, h, sh.Commit); err != nil {
			return nil, fmt.Errorf("lightclient: the signatures of the next set: %w", err)
		}
	default:
		err := c.Validators.VerifyFutureCommit(set, c.ChainID, sh.Commit.BlockID, h, sh.Commit)
		if types.IsErrTooMuchChange(err) && h > c.TrustedHeight+1 && steps < maxSteps {
			if _, err := c.verify(ctx, c.TrustedHeight+(h-c.TrustedHeight)/2, steps+1); err != nil {
				return nil, err
			}
			return c.verify(ctx, h, steps+1)
		}
		if err != nil {
			return nil, fmt.Errorf("lightclient: header %d is signed by a new set the trusted one didn't sign over to: %w", h, err)
		}
	}
	if h > c.TrustedHeight {
		c.Validators, c.TrustedHeight, c.trustedNext = set, h, sh.Header.NextValidatorsHash
	}
	return sh.Header, nil
}

// signed fetches header h with its commit and the validators that sign it,
// and checks they belong together: the header is h of this chain, the
// commit is for it, and the set is the one the header names.
func (c *Client) signed(ctx context.Context, h int64) (*types.SignedHeader, *types.ValidatorSet, error) {
	rc, err := c.RPC.Commit(ctx, &h)
	if err != nil {
		return nil, nil, err
	}
	sh := rc.SignedHeader
	if sh.Header == nil || sh.Commit == nil {
		return nil, nil, errors.New("lightclient: no signed header")
	}
	if sh.Header.Height != h || sh.Header.ChainID != c.ChainID {
		return nil, nil, fmt.Errorf("lightclient: header %d of %q, wanted %d of %q", sh.Header.Height, sh.Header.ChainID, h, c.ChainID)
	}
	if !bytes.Equal(sh.Commit.BlockID.Hash, sh.Header.Hash()) {
		return nil, nil, errors.New("lightclient: the commit is for another header")
	}
	set := c.Validators
	if !bytes.Equal(sh.Header.ValidatorsHash, set.Hash()) {
		if set, err = c.validators(ctx, h); err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(sh.Header.ValidatorsHash, set.Hash()) {
			return nil, nil, errors.New("lightclient: the node's validators aren't the ones the header names")
		}
	}
	return &sh, set, nil
}

func (c *Client) validators(ctx context.Context, h int64) (*types.ValidatorSet, error) {
	rv, err := c.RPC.Validators(ctx, &h)
	if err != nil {
		return nil, err
	}
	if len(rv.Validators) == 0 {
		return nil, fmt.Errorf("lightclient: no validators at %d", h)
	}
	return types.NewValidatorSet(rv.Validators), nil
}

// fresh refuses a header older than MaxAge, dated more than MaxSkew in the
// future, or older than the newest one this client has accepted; otherwise
// it becomes the newest.
func (c *Client) fresh(hdr *types.Header) error {
	if c.MaxAge <= 0 || c.Now == nil {
		return errors.New("lightclient: set MaxAge and Now")
	}
	now := c.Now()
	switch {
	case now.Sub(hdr.Time) > c.MaxAge:
		return fmt.Errorf("lightclient: header %d is from %s, older than %s", hdr.Height, hdr.Time, c.MaxAge)
	case hdr.Time.Sub(now) > MaxSkew:
		return fmt.Errorf("lightclient: header %d is dated %s, in the future", hdr.Height, hdr.Time)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last != nil && (hdr.Height < c.last.Height || hdr.Time.Before(c.last.Time)) {
		return fmt.Errorf("lightclient: header %d is older than header %d, already seen", hdr.Height, c.last.Height)
	}
	c.last = hdr
	return nil
}
