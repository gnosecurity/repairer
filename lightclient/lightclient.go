// Package lightclient proves what a gno.land realm holds without trusting
// the node it asks: a realm param (chain/params, stored at
// /pv/vm:<realm>:<key> in the proven main store) with its ics23 proofs,
// checked against the app hash of a header that more than two thirds of a
// trusted validator set signed. It is a separate module, so the agent never
// carries tm2.
package lightclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gnolang/gno/tm2/pkg/bft/rpc/client"
	"github.com/gnolang/gno/tm2/pkg/bft/types"
	"github.com/gnolang/gno/tm2/pkg/crypto/merkle"
	"github.com/gnolang/gno/tm2/pkg/store/rootmulti"
)

// Client proves realm params at heights.
type Client struct {
	RPC     *client.RPCClient
	ChainID string
	// Validators is the set the client trusts: from its pinned start (an
	// owner-signed checkpoint), followed forward.
	Validators *types.ValidatorSet
	// MaxAge refuses a proof whose header is older than this, unless zero.
	MaxAge time.Duration
	Now    func() time.Time
}

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

// Header fetches header h with its commit and checks that the trusted
// validators signed it: the set named in the header is the trusted set,
// and more than two thirds of its power signed this block.
func (c *Client) Header(ctx context.Context, h int64) (*types.Header, error) {
	rc, err := c.RPC.Commit(ctx, &h)
	if err != nil {
		return nil, err
	}
	sh := rc.SignedHeader
	if sh.Header == nil || sh.Commit == nil {
		return nil, errors.New("lightclient: no signed header")
	}
	if sh.Header.Height != h || sh.Header.ChainID != c.ChainID {
		return nil, fmt.Errorf("lightclient: header %d of %q, wanted %d of %q", sh.Header.Height, sh.Header.ChainID, h, c.ChainID)
	}
	if !bytes.Equal(sh.Header.ValidatorsHash, c.Validators.Hash()) {
		return nil, errors.New("lightclient: the header names another validator set (following a change isn't built yet)")
	}
	if !bytes.Equal(sh.Commit.BlockID.Hash, sh.Header.Hash()) {
		return nil, errors.New("lightclient: the commit is for another header")
	}
	if err := c.Validators.VerifyCommit(c.ChainID, sh.Commit.BlockID, h, sh.Commit); err != nil {
		return nil, fmt.Errorf("lightclient: the signatures: %w", err)
	}
	if c.MaxAge > 0 && c.Now != nil && c.Now().Sub(sh.Header.Time) > c.MaxAge {
		return nil, fmt.Errorf("lightclient: header %d is from %s, older than %s", h, sh.Header.Time, c.MaxAge)
	}
	return sh.Header, nil
}
