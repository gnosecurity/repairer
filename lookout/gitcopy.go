package lookout

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// gitCopy is a whole copy of a public git repository: bare, one commit
// deep, its HEAD the branch "copy" whatever the publisher calls its own.
// Reading a file from it says nothing to anyone about what the fleet runs.
// It is fetched over https, whose server is checked: what such a copy
// says decides findings.
type gitCopy struct {
	dir, remote, git string
}

func (g gitCopy) cmd(ctx context.Context, args ...string) *exec.Cmd {
	prog := g.git
	if prog == "" {
		prog = "git"
	}
	return exec.CommandContext(ctx, prog, args...)
}

func (g gitCopy) run(ctx context.Context, args ...string) error {
	out, err := g.cmd(ctx, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %s: %v: %s", args[0], err, lastLine(out))
	}
	return nil
}

// synced is where the time of the last good sync is kept, beside the copy.
func (g gitCopy) synced() string { return g.dir + ".synced" }

func (g gitCopy) exists() bool {
	_, err := os.Stat(filepath.Join(g.dir, "HEAD"))
	return err == nil
}

// sync clones the repository the first time and fetches its newest commit
// after, within ctx's deadline, then notes the time.
func (g gitCopy) sync(ctx context.Context) error {
	if !g.exists() {
		tmp := g.dir + ".new"
		os.RemoveAll(tmp)
		if err := g.run(ctx, "clone", "--quiet", "--bare", "--depth", "1", "--", g.remote, tmp); err != nil {
			os.RemoveAll(tmp)
			return fmt.Errorf("cloning: %w", err)
		}
		for _, a := range [][]string{{"update-ref", "refs/heads/copy", "HEAD"}, {"symbolic-ref", "HEAD", "refs/heads/copy"}} {
			if err := g.run(ctx, append([]string{"--git-dir", tmp}, a...)...); err != nil {
				os.RemoveAll(tmp)
				return err
			}
		}
		if err := os.Rename(tmp, g.dir); err != nil {
			return err
		}
	} else {
		if err := g.run(ctx, "--git-dir", g.dir, "fetch", "--quiet", "--depth", "1", "--", g.remote, "+HEAD:refs/heads/copy"); err != nil {
			return fmt.Errorf("fetching: %w", err)
		}
		// Older commits' objects go as git sees fit, so the copy stays
		// about one commit's size.
		_ = g.run(ctx, "--git-dir", g.dir, "gc", "--auto", "--quiet")
	}
	return os.WriteFile(g.synced(), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
}

// blob reads one file from the copy's newest commit, at most max bytes:
// found is false when the commit has no such file. Any other trouble, a
// broken copy included, is an error.
func (g gitCopy) blob(ctx context.Context, path string, max int) (b []byte, found bool, err error) {
	if !g.exists() {
		return nil, false, errors.New("no copy yet")
	}
	cmd := g.cmd(ctx, "--git-dir", g.dir, "cat-file", "blob", "HEAD:"+path)
	var out, errOut bytes.Buffer
	lim := &limited{w: &out, n: max}
	cmd.Stdout, cmd.Stderr = lim, &errOut
	err = cmd.Run()
	switch {
	case lim.over:
		return nil, false, fmt.Errorf("%s is over %d bytes", path, max)
	case err != nil && notThere(errOut.String()):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("reading %s: %v: %s", path, err, lastLine(errOut.Bytes()))
	}
	return out.Bytes(), true, nil
}

// names lists the files under dir in the copy's newest commit, by path
// from dir.
func (g gitCopy) names(ctx context.Context, dir string) ([]string, error) {
	if !g.exists() {
		return nil, errors.New("no copy yet")
	}
	out, err := g.cmd(ctx, "--git-dir", g.dir, "ls-tree", "-r", "--name-only", "HEAD:"+dir).Output()
	if err != nil {
		return nil, fmt.Errorf("listing %s: %v", dir, err)
	}
	return strings.Fields(string(out)), nil
}

// notThere says whether git's complaint is only that the path isn't in the
// commit.
func notThere(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "does not exist") || strings.Contains(s, "not a valid object name") || strings.Contains(s, "invalid object name")
}

// limited keeps at most n bytes and notes when more came.
type limited struct {
	w    interface{ Write([]byte) (int, error) }
	n    int
	over bool
}

func (l *limited) Write(p []byte) (int, error) {
	if len(p) > l.n {
		l.over = true
		return 0, errors.New("past the size limit")
	}
	l.n -= len(p)
	return l.w.Write(p)
}

func lastLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
