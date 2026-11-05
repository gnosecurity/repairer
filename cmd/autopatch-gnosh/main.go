// Command autopatch-gnosh is gnosh at home: the local model's reading of a
// guard, and its yes within rule 6.
//
//	autopatch-gnosh launch -socket MODEL.sock -model NAME -weights HASH -key MODEL.key -chain CHAIN < ASK.json
//	autopatch-gnosh judge  -socket MODEL.sock -model NAME -weights HASH < ASK.json   (what launch runs, sandboxed)
//
// launch holds the model's key and never lets it into the sandbox: it runs
// judge in a new network namespace with no interfaces (unshare), where the
// only way out is the model's UNIX socket, then checks the answer against
// rule 6 itself and signs the model's yes only for a drop-only guard that
// isn't one of the model's own drafts. In: advisories and a guard, never the
// inventory. Out: the reading, the verdict, the prompt's and the model's
// hashes, and the signed yes if any, within ten minutes.
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
	case "judge":
		ans, err := gnosh.Judge(ctx, gnosh.SocketModel{Socket: *socket, Name: *model, Weight: *weights}, ask)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(ans)
	case "launch":
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
		judgeArgs := []string{self, "judge", "-socket", *socket, "-model", *model, "-weights", *weights}
		var c *exec.Cmd
		switch *sandbox {
		case "unshare":
			// A user and a network namespace: no interfaces, not even up
			// loopback. A UNIX socket on the filesystem still reaches the model.
			c = exec.CommandContext(ctx, "unshare", append([]string{"--user", "--map-root-user", "--net", "--"}, judgeArgs...)...)
		case "none":
			c = exec.CommandContext(ctx, judgeArgs[0], judgeArgs[1:]...)
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
		if *drafts != "" {
			b, err := os.ReadFile(*drafts)
			if err != nil {
				return err
			}
			for _, l := range strings.Fields(string(b)) {
				ds[l] = true
			}
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
