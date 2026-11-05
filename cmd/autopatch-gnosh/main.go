// Command autopatch-gnosh is gnosh at home: the local model's reading of a
// guard, and its yes within rule 6.
//
//	autopatch-gnosh launch -socket MODEL.sock -model NAME -weights HASH -key MODEL.key -chain CHAIN < ASK.json
//	autopatch-gnosh judge  -socket MODEL.sock -model NAME -weights HASH < ASK.json   (what launch runs, sandboxed)
//
// launch holds the model's key and never lets it into the sandbox: it runs
// judge in new user, network and mount namespaces (unshare), in a jail whose
// whole filesystem is an empty in-memory root holding the model's UNIX
// socket and nothing else, with no network interfaces; then it checks the
// answer against rule 6 itself and signs the model's yes only for a drop
// narrowed by IP options that isn't one of the model's own drafts (-drafts
// is required: the list of what the model drafted, empty if nothing). In:
// advisories and a guard, never the inventory. Out: the reading, the
// verdict, the prompt's and the model's hashes, and the signed yes if any,
// within ten minutes. On Ubuntu 24.04 an unprivileged launcher needs an
// AppArmor profile that allows user namespaces.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/gnosh"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: autopatch-gnosh <launch|judge> [flags] < ASK.json")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := run(ctx, os.Args[1], os.Args[2:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "autopatch-gnosh:", err)
		os.Exit(1)
	}
}

// Out is what launch prints.
type Out struct {
	Answer *gnosh.Answer   `json:"answer"`
	Yes    *approve.Signed `json:"yes,omitempty"`
	NoYes  string          `json:"no_yes,omitempty"` // why the yes wasn't signed
}

func run(ctx context.Context, cmd string, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	socket := fs.String("socket", "", "the model server's UNIX socket")
	model := fs.String("model", "", "the model to ask for")
	weights := fs.String("weights", "", "the model weights' hash")
	keyFile := fs.String("key", "", "launch: the model's Ed25519 key (hex seed)")
	chain := fs.String("chain", "", "launch: the fleet's chain id")
	drafts := fs.String("drafts", "", "launch: a file of guard hashes the model drafted, one a line")
	sandbox := fs.String("sandbox", "unshare", "launch: how judge is cut off (unshare; none only for tests)")
	root := fs.String("root", "", "jail: the empty directory that becomes judge's whole filesystem")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *socket == "" || *model == "" || *weights == "" {
		return errors.New("needs -socket, -model and -weights")
	}
	in, err := io.ReadAll(io.LimitReader(stdin, 4<<20))
	if err != nil {
		return err
	}
	var ask gnosh.Ask
	if err := json.Unmarshal(in, &ask); err != nil {
		return fmt.Errorf("the ask: %w", err)
	}
	switch cmd {
	case "jail", "judge":
		if cmd == "jail" {
			if *socket, err = enterJail(*root, *socket); err != nil {
				return fmt.Errorf("the jail: %w", err)
			}
		}
		ans, err := gnosh.Judge(ctx, gnosh.SocketModel{Socket: *socket, Name: *model, Weight: *weights}, ask)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(ans)
	case "launch":
		if *drafts == "" {
			return errors.New("launch needs -drafts: a file of the guard hashes the model drafted, empty if none, so its yes never counts for its own draft")
		}
		k, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		seed, err := hex.DecodeString(strings.TrimSpace(string(k)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return errors.New("the model's key is a 32-byte seed in hex")
		}
		self, err := os.Executable()
		if err != nil {
			return err
		}
		sock, err := filepath.Abs(*socket)
		if err != nil {
			return err
		}
		var c *exec.Cmd
		switch *sandbox {
		case "unshare":
			// User, network and mount namespaces: no interfaces, not even up
			// loopback, and a filesystem that holds only the model's socket.
			jail, err := os.MkdirTemp("", "gnosh-jail-")
			if err != nil {
				return err
			}
			defer os.Remove(jail)
			c = exec.CommandContext(ctx, "unshare", "--user", "--map-root-user", "--net", "--mount", "--",
				self, "jail", "-root", jail, "-socket", sock, "-model", *model, "-weights", *weights)
		case "none":
			c = exec.CommandContext(ctx, self, "judge", "-socket", sock, "-model", *model, "-weights", *weights)
		default:
			return fmt.Errorf("sandbox %q", *sandbox)
		}
		c.Env = []string{"PATH=/usr/bin:/bin"} // nothing of the launcher's environment, its key least of all
		var outb, errb bytes.Buffer
		c.Stdin, c.Stdout, c.Stderr = bytes.NewReader(in), &outb, &errb
		if err := c.Run(); err != nil {
			return fmt.Errorf("judge: %v: %s", err, strings.TrimSpace(errb.String()))
		}
		var ans gnosh.Answer
		if err := json.Unmarshal(outb.Bytes(), &ans); err != nil {
			return fmt.Errorf("judge's answer: %w", err)
		}
		out := Out{Answer: &ans}
		ds := map[string]bool{}
		b, err := os.ReadFile(*drafts)
		if err != nil {
			return err
		}
		for _, l := range strings.Fields(string(b)) {
			ds[l] = true
		}
		sg, err := gnosh.SignYes(ed25519.NewKeyFromSeed(seed), *chain, ask, &ans, ds)
		if err != nil {
			out.NoYes = err.Error()
		} else {
			out.Yes = sg
		}
		return json.NewEncoder(stdout).Encode(out)
	}
	return fmt.Errorf("unknown command %q", cmd)
}
