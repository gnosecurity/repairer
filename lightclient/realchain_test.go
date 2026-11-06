package lightclient

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gnolang/gno/tm2/pkg/bft/rpc/client"
	ctypes "github.com/gnolang/gno/tm2/pkg/bft/rpc/core/types"
	"github.com/gnolang/gno/tm2/pkg/bft/types"
)

// counting passes a node's answers through, noting the heights whose
// commits were asked for, and hides the commits of the heights in hide.
type counting struct {
	Node
	asked []int64
	hide  func(h int64) bool
}

func (c *counting) Commit(ctx context.Context, h *int64) (*ctypes.ResultCommit, error) {
	c.asked = append(c.asked, *h)
	if c.hide != nil && c.hide(*h) {
		return nil, errors.New("not served")
	}
	return c.Node.Commit(ctx, h)
}

// Against four.sh's chain of real gnoland nodes (LC_FOUR_*): node 1 alone
// validates at the checkpoint; change A makes nodes 1-4 the set (level
// "one" set at H1); change B makes it nodes 1, 4 and 5 (level "two" set at
// H2). A client started at the checkpoint proves both levels, ending with
// the three-validator set; going from four to three took the heights in
// between, since half the trusted power can't sign over by itself; and a
// node that hides those heights gets the second proof refused.
func TestFollowsARealChain(t *testing.T) {
	rpc := os.Getenv("LC_FOUR_RPC")
	if rpc == "" {
		t.Skip("run testchain/four.sh")
	}
	num := func(k string) int64 {
		n, err := strconv.ParseInt(os.Getenv(k), 10, 64)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		return n
	}
	cp, h1, h2 := num("LC_FOUR_CP"), num("LC_FOUR_H1"), num("LC_FOUR_H2")
	ctx := context.Background()
	node, err := client.NewHTTPClient(rpc)
	if err != nil {
		t.Fatal(err)
	}
	st, err := node.Status(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The owner's checkpoint: here read from the node at cp, standing in
	// for what the owner signs.
	vals, err := node.Validators(ctx, &cp)
	if err != nil {
		t.Fatal(err)
	}
	if len(vals.Validators) != 1 {
		t.Fatalf("the checkpoint's set has %d validators, wanted node 1 alone", len(vals.Validators))
	}
	rc, err := node.Commit(ctx, &cp)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := Checkpoint{Height: cp, ValidatorsHash: types.NewValidatorSet(vals.Validators).Hash(), Time: rc.SignedHeader.Header.Time}
	const realm = "gno.land/r/repairer/guards"
	fresh := func(n Node) *Client {
		c := &Client{RPC: n, ChainID: st.NodeInfo.Network, MaxAge: time.Hour, Now: time.Now}
		if err := c.Start(ctx, checkpoint); err != nil {
			t.Fatal(err)
		}
		return c
	}

	seen := &counting{Node: node}
	lc := fresh(seen)
	v, found, err := lc.Param(ctx, realm, "lvl_one", h1)
	if err != nil || !found || string(v) != `"tested"` {
		t.Fatalf("level one at %d: %q %v %v", h1, v, found, err)
	}
	if n := len(lc.Validators.Validators); n != 4 {
		t.Fatalf("after change A the client trusts %d validators, wanted 4", n)
	}
	// Level two wasn't set yet at H1: proven absent.
	if _, found, err := lc.Param(ctx, realm, "lvl_two", h1); err != nil || found {
		t.Fatalf("level two at %d: %v %v", h1, found, err)
	}
	seen.asked = nil
	v, found, err = lc.Param(ctx, realm, "lvl_two", h2)
	if err != nil || !found || string(v) != `"tested"` {
		t.Fatalf("level two at %d: %q %v %v", h2, v, found, err)
	}
	if n := len(lc.Validators.Validators); n != 3 {
		t.Fatalf("after change B the client trusts %d validators, wanted 3", n)
	}
	between := 0
	for _, h := range seen.asked {
		if h > h1+1 && h < h2+1 {
			between++
		}
	}
	if between == 0 {
		t.Fatalf("change B was taken in one step (asked %v); half the trusted power can't sign over to a new set", seen.asked)
	}
	t.Logf("checkpoint %d; change A proven at %d; change B at %d, through %d heights between (%v)", cp, h1, h2, between, seen.asked)

	// A node that hides the heights between: the client can't step, and
	// must refuse rather than take the new set's word.
	hiding := &counting{Node: node, hide: func(h int64) bool { return h > h1+1 && h < h2+1 }}
	lc2 := fresh(hiding)
	if _, _, err := lc2.Param(ctx, realm, "lvl_one", h1); err != nil {
		t.Fatalf("level one through the hiding node: %v", err)
	}
	_, _, err = lc2.Param(ctx, realm, "lvl_two", h2)
	if err == nil {
		t.Fatal("a node hiding the heights between got the four-to-three change accepted")
	}
	if !strings.Contains(err.Error(), "not served") && !strings.Contains(err.Error(), "didn't sign over") {
		t.Fatalf("refused for another reason: %v", err)
	}
	if lc2.TrustedHeight > h1+1 {
		t.Fatalf("the refused client moved its trust to %d", lc2.TrustedHeight)
	}
}
