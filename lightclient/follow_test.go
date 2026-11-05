package lightclient

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gnolang/gno/tm2/pkg/bft/rpc/client"
	ctypes "github.com/gnolang/gno/tm2/pkg/bft/rpc/core/types"
	"github.com/gnolang/gno/tm2/pkg/bft/types"
)

const chainID = "testchain"

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// chain is a stand-in node: signed headers and the validators of each
// height, built here with keys the test holds.
type chain struct {
	headers map[int64]types.SignedHeader
	vals    map[int64]*types.ValidatorSet
}

func (c *chain) Commit(_ context.Context, h *int64) (*ctypes.ResultCommit, error) {
	sh, ok := c.headers[*h]
	if !ok {
		return nil, errors.New("no such height")
	}
	return &ctypes.ResultCommit{SignedHeader: sh}, nil
}

func (c *chain) Validators(_ context.Context, h *int64) (*ctypes.ResultValidators, error) {
	v, ok := c.vals[*h]
	if !ok {
		return nil, errors.New("no such height")
	}
	return &ctypes.ResultValidators{BlockHeight: *h, Validators: v.Copy().Validators}, nil
}

func (c *chain) ABCIQueryWithOptions(context.Context, string, []byte, client.ABCIQueryOptions) (*ctypes.ResultABCIQuery, error) {
	return nil, errors.New("not served")
}

// keys are validators' signing keys, each with power 10.
func keys(n int) []types.PrivValidator {
	var out []types.PrivValidator
	for i := 0; i < n; i++ {
		out = append(out, types.NewMockPV())
	}
	return out
}

func setOf(pvs ...types.PrivValidator) *types.ValidatorSet {
	var vals []*types.Validator
	for _, pv := range pvs {
		vals = append(vals, types.NewValidator(pv.PubKey(), 10))
	}
	return types.NewValidatorSet(vals)
}

// block adds header h of a chain whose validators at h are set (next: at
// h+1), signed by signers, which must hold more than two thirds of set.
func (c *chain) block(t *testing.T, h int64, set, next *types.ValidatorSet, signers []types.PrivValidator, at time.Time) {
	t.Helper()
	hdr := &types.Header{ChainID: chainID, Height: h, Time: at, ValidatorsHash: set.Hash(), NextValidatorsHash: next.Hash(),
		AppHash: []byte{byte(h), 1, 2, 3}, ProposerAddress: set.Validators[0].Address}
	c.sign(t, hdr, set, signers)
	c.vals[h] = set
}

// sign makes header hdr's commit, signed by signers as members of set.
func (c *chain) sign(t *testing.T, hdr *types.Header, set *types.ValidatorSet, signers []types.PrivValidator) {
	t.Helper()
	id := types.BlockID{Hash: hdr.Hash()}
	vs := types.NewVoteSet(chainID, hdr.Height, 0, types.PrecommitType, set)
	for _, pv := range signers {
		idx, _ := set.GetByAddress(pv.PubKey().Address())
		v := &types.Vote{ValidatorAddress: pv.PubKey().Address(), ValidatorIndex: idx, Height: hdr.Height, Type: types.PrecommitType,
			BlockID: id, Timestamp: hdr.Time}
		if err := pv.SignVote(chainID, v); err != nil {
			t.Fatal(err)
		}
		if _, err := vs.AddVote(v); err != nil {
			t.Fatal(err)
		}
	}
	c.headers[hdr.Height] = types.SignedHeader{Header: hdr, Commit: vs.MakeCommit()}
}

func newChain() *chain {
	return &chain{headers: map[int64]types.SignedHeader{}, vals: map[int64]*types.ValidatorSet{}}
}

// client starts from a checkpoint at height 1, with the clock at now.
func clientOf(t *testing.T, c *chain, now time.Time) *Client {
	t.Helper()
	lc := &Client{RPC: c, ChainID: chainID, MaxAge: time.Hour, Now: func() time.Time { return now }}
	if err := lc.Start(context.Background(), Checkpoint{Height: 1, ValidatorsHash: c.vals[1].Hash(), Time: c.headers[1].Header.Time}); err != nil {
		t.Fatal(err)
	}
	return lc
}

// One validator of four is replaced at height 6. The trusted set signed
// over to the new one, so the client follows it, and trusts the new set
// from then on (G2: "a validator-set change").
func TestFollowsASetChange(t *testing.T) {
	k := keys(5)
	a, b := setOf(k[0], k[1], k[2], k[3]), setOf(k[1], k[2], k[3], k[4])
	c := newChain()
	for h := int64(1); h <= 10; h++ {
		set, next, signers := a, a, k[0:4]
		if h == 5 {
			next = b
		}
		if h >= 6 {
			set, next, signers = b, b, k[1:5]
		}
		c.block(t, h, set, next, signers, t0.Add(time.Duration(h)*time.Minute))
	}
	lc := clientOf(t, c, t0.Add(10*time.Minute))
	if _, err := lc.Header(context.Background(), 9); err != nil {
		t.Fatal(err)
	}
	if lc.TrustedHeight != 9 || string(lc.Validators.Hash()) != string(b.Hash()) {
		t.Fatalf("trusts height %d, set b: %v", lc.TrustedHeight, string(lc.Validators.Hash()) == string(b.Hash()))
	}
	if _, err := lc.Header(context.Background(), 10); err != nil {
		t.Fatalf("the next header, by the set now trusted: %v", err)
	}
}

// Two of four change at once between heights 1 and 10, one at a time on
// the chain: the trusted set signed too little of header 10 for one step,
// so the client verifies a height between first, then 10.
func TestStepsThroughABigChange(t *testing.T) {
	k := keys(6)
	a, b, cc := setOf(k[0], k[1], k[2], k[3]), setOf(k[1], k[2], k[3], k[4]), setOf(k[2], k[3], k[4], k[5])
	ch := newChain()
	for h := int64(1); h <= 10; h++ {
		set, next, signers := a, a, k[0:4]
		switch {
		case h == 3:
			next = b
		case h >= 4 && h <= 6:
			set, next, signers = b, b, k[1:5]
			if h == 6 {
				next = cc
			}
		case h >= 7:
			set, next, signers = cc, cc, k[2:6]
		}
		ch.block(t, h, set, next, signers, t0.Add(time.Duration(h)*time.Minute))
	}
	lc := clientOf(t, ch, t0.Add(10*time.Minute))
	if _, err := lc.Header(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	if lc.TrustedHeight != 10 || string(lc.Validators.Hash()) != string(cc.Hash()) {
		t.Fatalf("trusts height %d", lc.TrustedHeight)
	}
}

// A node that lies: a header signed by keys the set doesn't hold, the
// validators the header doesn't name, a header changed after it was signed
// (G2: "a lying node").
func TestRefusesALyingNode(t *testing.T) {
	k := keys(4)
	a := setOf(k...)
	strangers := keys(4)
	ch := newChain()
	for h := int64(1); h <= 4; h++ {
		ch.block(t, h, a, a, k, t0.Add(time.Duration(h)*time.Minute))
	}
	// Height 5 signed by strangers claiming to be the set.
	hdr := &types.Header{ChainID: chainID, Height: 5, Time: t0.Add(5 * time.Minute), ValidatorsHash: a.Hash(), NextValidatorsHash: a.Hash(), AppHash: []byte{9}, ProposerAddress: a.Validators[0].Address}
	ch.sign(t, hdr, setOf(strangers...), strangers)
	ch.vals[5] = a
	// Height 6: the validators answer names another set than the header.
	ch.block(t, 6, a, a, k, t0.Add(6*time.Minute))
	ch.vals[6] = setOf(strangers...)
	ch.headers[6].Header.ValidatorsHash = setOf(strangers...).Hash()
	// Height 7: the app hash changed after the validators signed.
	ch.block(t, 7, a, a, k, t0.Add(7*time.Minute))
	ch.headers[7].Header.AppHash = []byte("a state they never signed")
	lc := clientOf(t, ch, t0.Add(8*time.Minute))
	for h, want := range map[int64]string{5: "", 6: "", 7: "the commit is for another header"} {
		_, err := lc.Header(context.Background(), h)
		if err == nil || (want != "" && !strings.Contains(err.Error(), want)) {
			t.Errorf("height %d: %v", h, err)
		}
	}
	if lc.TrustedHeight != 1 {
		t.Fatalf("a lie moved trust to %d", lc.TrustedHeight)
	}
	if _, err := lc.Header(context.Background(), 4); err != nil {
		t.Fatalf("an honest header after the lies: %v", err)
	}
}

// After the set turned over completely, the retired validators sign a
// history of their own: a client that followed the change refuses it, and
// a client whose checkpoint is older than MaxGap refuses to follow at all
// (G2: "a fork signed by retired validators", "a stale header").
func TestRefusesRetiredValidatorsFork(t *testing.T) {
	k := keys(8)
	a, m, b := setOf(k[0:4]...), setOf(k[2], k[3], k[4], k[5]), setOf(k[4:8]...)
	ch := newChain()
	for h := int64(1); h <= 9; h++ {
		set, next, signers := a, a, k[0:4]
		switch {
		case h == 3:
			next = m
		case h >= 4 && h <= 6:
			set, next, signers = m, m, []types.PrivValidator{k[2], k[3], k[4], k[5]}
			if h == 6 {
				next = b
			}
		case h >= 7:
			set, next, signers = b, b, k[4:8]
		}
		ch.block(t, h, set, next, signers, t0.Add(time.Duration(h)*time.Minute))
	}
	lc := clientOf(t, ch, t0.Add(20*time.Minute))
	if _, err := lc.Header(context.Background(), 9); err != nil {
		t.Fatal(err)
	}
	// The retired set a signs a height 10 of its own, right after the
	// trusted one, and a height 12 further on.
	ch.block(t, 10, a, a, k[0:4], t0.Add(10*time.Minute))
	ch.block(t, 12, a, a, k[0:4], t0.Add(12*time.Minute))
	for _, h := range []int64{10, 12} {
		if _, err := lc.Header(context.Background(), h); err == nil || !strings.Contains(err.Error(), "didn't sign over to") {
			t.Fatalf("a fork by retired validators at %d: %v", h, err)
		}
	}
	// A client whose checkpoint is more than MaxGap before the header won't
	// follow anything, so retired keys can't walk it into their history.
	old := newChain()
	old.block(t, 1, a, a, k[0:4], t0)
	old.block(t, 2, a, a, k[0:4], t0.Add(MaxGap+time.Hour))
	lc2 := clientOf(t, old, t0.Add(MaxGap+time.Hour))
	if _, err := lc2.Header(context.Background(), 2); err == nil || !strings.Contains(err.Error(), "past the checkpoint") {
		t.Fatalf("a header past the checkpoint's gap: %v", err)
	}
	// And a header older than MaxAge is stale, whoever signed it.
	lc3 := clientOf(t, ch, t0.Add(3*time.Hour))
	if _, err := lc3.Header(context.Background(), 2); err == nil || !strings.Contains(err.Error(), "older than") {
		t.Fatalf("a stale header: %v", err)
	}
}

// Trust begins only at a checkpoint whose validators the node gives back:
// a node with another set at that height is refused, and so is a client
// that never started.
func TestStartChecksTheCheckpoint(t *testing.T) {
	k := keys(4)
	a := setOf(k...)
	ch := newChain()
	ch.block(t, 1, a, a, k, t0)
	lc := &Client{RPC: ch, ChainID: chainID, MaxAge: time.Hour, Now: func() time.Time { return t0 }}
	if _, err := lc.Header(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "checkpoint first") {
		t.Fatalf("no checkpoint: %v", err)
	}
	if err := lc.Start(context.Background(), Checkpoint{Height: 1, ValidatorsHash: setOf(keys(4)...).Hash(), Time: t0}); err == nil {
		t.Fatal("a checkpoint whose set the node doesn't have")
	}
	if err := lc.Start(context.Background(), Checkpoint{Height: 1, ValidatorsHash: a.Hash(), Time: t0}); err != nil {
		t.Fatal(err)
	}
	if _, err := lc.Header(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	// A node that answers the right validators for the checkpoint, but a
	// header there that strangers signed, naming a next set of theirs.
	strangers := keys(4)
	forged := newChain()
	hdr := &types.Header{ChainID: chainID, Height: 1, Time: t0, ValidatorsHash: a.Hash(), NextValidatorsHash: setOf(strangers...).Hash(),
		AppHash: []byte{1}, ProposerAddress: a.Validators[0].Address}
	forged.sign(t, hdr, setOf(strangers...), strangers)
	forged.vals[1] = a
	lf := &Client{RPC: forged, ChainID: chainID, MaxAge: time.Hour, Now: func() time.Time { return t0 }}
	if err := lf.Start(context.Background(), Checkpoint{Height: 1, ValidatorsHash: a.Hash(), Time: t0}); err == nil {
		t.Fatal("a checkpoint header the set never signed")
	}
}
