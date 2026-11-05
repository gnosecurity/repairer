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

// Against a local chain (LC_RPC, LC_HEIGHT, a height where the guards
// realm's lvl_<hash> param was "tested"): the param is proven; the same
// proof refuses another value; a key never set is proven absent; and a
// header signed by validators the client doesn't trust is refused.
func TestParamOnALocalChain(t *testing.T) {
	rpc, hs := os.Getenv("LC_RPC"), os.Getenv("LC_HEIGHT")
	if rpc == "" || hs == "" {
		t.Skip("set LC_RPC and LC_HEIGHT to a local chain with the guards realm")
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
	lc := &Client{RPC: c, ChainID: st.NodeInfo.Network, Validators: types.NewValidatorSet(vals.Validators), MaxAge: time.Hour, Now: time.Now}
	const realm = "gno.land/r/autopatch/guards"
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
	// Validators the client doesn't trust.
	other := &Client{RPC: c, ChainID: lc.ChainID, Validators: types.NewValidatorSet(nil)}
	if _, err := other.Header(ctx, h+1); err == nil {
		t.Fatal("a header from validators the client doesn't trust")
	}
}
