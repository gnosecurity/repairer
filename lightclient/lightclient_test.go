package lightclient

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gnolang/gno/tm2/pkg/bft/rpc/client"
	"github.com/gnolang/gno/tm2/pkg/bft/types"
)

// Against a local chain (LC_RPC, LC_HEIGHT, a height where the spike
// realm's lvl_<hash> param was "tested"): the param is proven; the same
// proof refuses another value; a key never set is proven absent; and a
// header signed by validators the client doesn't trust is refused.
func TestParamOnALocalChain(t *testing.T) {
	rpc, hs := os.Getenv("LC_RPC"), os.Getenv("LC_HEIGHT")
	if rpc == "" || hs == "" {
		t.Skip("set LC_RPC and LC_HEIGHT to a local chain with the spike realm")
	}
	h, _ := strconv.ParseInt(hs, 10, 64)
	ctx := context.Background()
	c, err := client.NewHTTPClient(rpc)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.Status(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	one := int64(1)
	vals, err := c.Validators(ctx, &one)
	if err != nil {
		t.Fatal(err)
	}
	lc := &Client{RPC: c, ChainID: st.NodeInfo.Network, MaxAge: time.Hour, Now: time.Now}
	if err := lc.Start(ctx, Checkpoint{Height: 1, ValidatorsHash: types.NewValidatorSet(vals.Validators).Hash(), Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	const realm = "gno.land/r/repairer/lcspike" // the spike realm, at a path of its own
	const key = "lvl_73804a3fcab787f11c404c13c46b06eb8452aa585fb7f92429fa7ab98635ed6c"
	v, found, err := lc.Param(ctx, realm, key, h)
	if err != nil || !found || string(v) != `"tested"` {
		t.Fatalf("the level: %q %v %v", v, found, err)
	}
	// The same proof can't say anything else.
	res, err := c.ABCIQueryWithOptions(ctx, ".store/main/key", ParamKey(realm, key), client.ABCIQueryOptions{Height: h, Prove: true})
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := lc.Header(ctx, h+1)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(res.Response.Proof, hdr.AppHash, ParamKey(realm, key), []byte(`"settled"`)) == nil {
		t.Fatal("the proof accepted another value")
	}
	if Verify(res.Response.Proof, append([]byte{1}, hdr.AppHash[1:]...), ParamKey(realm, key), res.Response.Value) == nil {
		t.Fatal("the proof accepted another app hash")
	}
	// A guard that isn't there: proven absent.
	v, found, err = lc.Param(ctx, realm, "lvl_"+"00000000000000000000000000000000000000000000000000000000000000ff", h)
	if err != nil || found {
		t.Fatalf("an absent level: %q %v %v", v, found, err)
	}
	// Validators the client doesn't trust: a checkpoint naming another set.
	stranger, _ := types.RandValidatorSet(1, 10)
	other := &Client{RPC: c, ChainID: lc.ChainID, MaxAge: time.Hour, Now: time.Now}
	if err := other.Start(ctx, Checkpoint{Height: 1, ValidatorsHash: stranger.Hash(), Time: time.Now()}); err == nil {
		t.Fatal("a checkpoint naming validators the chain never had")
	}
}

// A header must be recent, not dated in the future, and never older than
// one already accepted; and the client won't run without an age limit
// (round 8, minor 11).
func TestFresh(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	hdr := func(h int64, at time.Time) *types.Header { return &types.Header{Height: h, Time: at} }
	if err := (&Client{Now: func() time.Time { return now }}).fresh(hdr(1, now)); err == nil {
		t.Fatal("no MaxAge: accepted")
	}
	c := &Client{MaxAge: 5 * time.Minute, Now: func() time.Time { return now }}
	for name, h := range map[string]*types.Header{
		"an old header":   hdr(10, now.Add(-6*time.Minute)),
		"a future header": hdr(10, now.Add(2*time.Minute)),
	} {
		if err := c.fresh(h); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := c.fresh(hdr(10, now.Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}
	if err := c.fresh(hdr(9, now.Add(-30*time.Second))); err == nil {
		t.Error("a lower height after a higher one: accepted")
	}
	if err := c.fresh(hdr(11, now.Add(-2*time.Minute))); err == nil {
		t.Error("an earlier time after a later one: accepted")
	}
	if err := c.fresh(hdr(11, now.Add(30*time.Second))); err != nil {
		t.Fatal(err)
	}
}
