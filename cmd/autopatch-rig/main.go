// Command autopatch-rig signs what the rig found. scripts/rig/rig.sh runs a
// guard's checks in a fresh VM and writes a transcript; this command names
// the rig that ran (a hash of its scripts, the image, the agent binary,
// QEMU's version and the CPU model) and, when every check that ran passed,
// signs Tested(guard, rig) with the rig's Ed25519 key. The rig's real key
// stays off the devbox; development uses a test key.
//
//	autopatch-rig hash -image IMG -agent BIN
//	autopatch-rig sign -key RIG.key -rig HASH -guard GUARD.json TRANSCRIPT.json
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/guard"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: autopatch-rig <hash|sign> [flags]")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "autopatch-rig:", err)
		os.Exit(1)
	}
}

func run(cmd string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	image := fs.String("image", "", "hash: the rig's disk image")
	agentBin := fs.String("agent", "", "hash: the agent binary the rig installs")
	scripts := fs.String("scripts", "scripts/rig", "hash: the rig's scripts")
	keyFile := fs.String("key", "", "sign: the rig's Ed25519 key (hex seed)")
	rig := fs.String("rig", "", "sign: the rig hash, from autopatch-rig hash")
	guardFile := fs.String("guard", "", "sign: the guard the transcript is about")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch cmd {
	case "hash":
		h, err := rigHash(*scripts, *image, *agentBin)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, h)
		return nil
	case "sign":
		if fs.NArg() != 1 || *keyFile == "" || *rig == "" || *guardFile == "" {
			return errors.New("sign needs -key, -rig, -guard and the transcript")
		}
		t, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return err
		}
		g, err := os.ReadFile(*guardFile)
		if err != nil {
			return err
		}
		k, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		sg, err := Sign(bytes.TrimSpace(k), *rig, g, t)
		if err != nil {
			return err
		}
		b, err := json.Marshal(sg)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s\n", b)
		return nil
	}
	return fmt.Errorf("unknown command %q", cmd)
}

// Transcript is what scripts/rig/transcript.py writes.
type Transcript struct {
	Rig    string `json:"rig"`
	Image  string `json:"image"`
	Guard  string `json:"guard"`
	Checks map[string]struct {
		Pass     *bool    `json:"pass"` // nil: not run on this rig
		Evidence []string `json:"evidence"`
	} `json:"checks"`
}

// required are the checks every rig runs; a transcript missing one, or
// failing one, is never signed.
var required = []string{"applies", "probe_blocked", "twice_no_change", "traffic", "survives", "undo_exact", "nothing_else"}

// Sign checks a transcript and, when every check that ran passed, signs
// Tested for the guard with the rig's key.
func Sign(seedHex []byte, rig string, guardFile, transcript []byte) (approve.Signed, error) {
	var t Transcript
	if err := json.Unmarshal(transcript, &t); err != nil {
		return approve.Signed{}, fmt.Errorf("the transcript: %w", err)
	}
	g, err := guard.Parse(guardFile)
	if err != nil {
		return approve.Signed{}, err
	}
	if t.Guard != g.Hash() { // a guard is named by its canonical form's hash
		return approve.Signed{}, errors.New("the transcript is about another guard")
	}
	var failed []string
	for _, name := range required {
		c, ok := t.Checks[name]
		switch {
		case !ok || c.Pass == nil:
			failed = append(failed, name+" (not run)")
		case !*c.Pass:
			failed = append(failed, name+": "+strings.Join(c.Evidence, "; "))
		}
	}
	for name, c := range t.Checks {
		if c.Pass != nil && !*c.Pass && !contains(required, name) {
			failed = append(failed, name)
		}
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		return approve.Signed{}, fmt.Errorf("not signed; failed: %s", strings.Join(failed, " | "))
	}
	seed, err := hex.DecodeString(string(seedHex))
	if err != nil || len(seed) != ed25519.SeedSize {
		return approve.Signed{}, errors.New("the rig key is a 32-byte seed in hex")
	}
	return approve.SignStatement(ed25519.NewKeyFromSeed(seed), approve.Statement{Version: approve.MemoVersion,
		Kind: approve.KindTested, Chain: "autopatch:vet", Guard: g.Hash(), Rig: rig})
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// rigHash names the rig that ran: its scripts, the image, the agent
// binary, QEMU's version and the CPU model, so a Tested says exactly which
// rig passed the guard.
func rigHash(scripts, image, agentBin string) (string, error) {
	if image == "" || agentBin == "" {
		return "", errors.New("hash needs -image and -agent")
	}
	h := sha256.New()
	files, err := filepath.Glob(filepath.Join(scripts, "*"))
	if err != nil || len(files) == 0 {
		return "", fmt.Errorf("no rig scripts in %s", scripts)
	}
	sort.Strings(files)
	for _, f := range append(files, image, agentBin) {
		fh, err := os.Open(f)
		if err != nil {
			return "", err
		}
		fsum := sha256.New()
		_, err = io.Copy(fsum, fh)
		fh.Close()
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s %x\n", filepath.Base(f), fsum.Sum(nil))
	}
	q, err := exec.Command("qemu-system-x86_64", "--version").Output()
	if err != nil {
		return "", fmt.Errorf("QEMU's version: %w", err)
	}
	fmt.Fprintf(h, "qemu %s\n", strings.SplitN(string(q), "\n", 2)[0])
	cpu, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(cpu), "\n") {
		if strings.HasPrefix(line, "model name") {
			fmt.Fprintf(h, "cpu %s\n", strings.TrimSpace(strings.SplitN(line, ":", 2)[1]))
			break
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
