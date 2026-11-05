//go:build linux

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// OpenFile opens a regular file and refuses anything else without waiting
// on it: a FIFO no one writes, a link, a directory (round 15, new major 4).
func TestLinuxOpenFile(t *testing.T) {
	root := t.TempDir()
	l := Linux{Root: root}
	if err := os.WriteFile(filepath.Join(root, "plain"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("plain", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	f, err := l.OpenFile("/plain")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	done := make(chan error, 3)
	go func() {
		for _, name := range []string{"/fifo", "/link", "/"} {
			_, err := l.OpenFile(name)
			if !errors.Is(err, ErrNotRegular) {
				done <- errors.New(name + ": " + errString(err))
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OpenFile waited on a FIFO")
	}
	if _, err := l.OpenFile("/nosuch"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing file: %v", err)
	}
}

func errString(err error) string {
	if err == nil {
		return "opened"
	}
	return err.Error()
}

// RunCapped kills a program once it printed its limit, and keeps its
// stderr whole to maxStderr (round 15, new major 4, minor 4).
func TestLinuxRunCapped(t *testing.T) {
	l := Linux{}
	start := time.Now()
	o, err := l.RunCapped(context.Background(), 1000, "yes")
	if !o.OutCapped || len(o.Out) != 1000 || err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("yes: capped %v, %d bytes, %v, after %v", o.OutCapped, len(o.Out), err, time.Since(start))
	}
	o, err = l.RunCapped(context.Background(), 1000, "ls", "/nosuch-1", "/nosuch-2")
	if err == nil || o.OutCapped || strings.Count(string(o.Err), "No such file or directory") != 2 {
		t.Fatalf("ls: %q %v", o.Err, err)
	}
	o, err = l.RunCapped(context.Background(), 1000, "echo", "hi")
	if err != nil || string(o.Out) != "hi\n" || o.OutCapped {
		t.Fatalf("echo: %q %v", o.Out, err)
	}
}
