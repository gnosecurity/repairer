//go:build unix

package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// lockFile takes an exclusive lock held until the file is closed.
func lockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	return f, nil
}

// readSpoolFile reads one entry of the spool, which the unprivileged half
// writes: never through a symlink, never a fifo or a device (opened
// without blocking, then checked), and at most MaxBundle bytes.
func readSpoolFile(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBundle+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBundle {
		return nil, fmt.Errorf("more than %d bytes", MaxBundle)
	}
	return b, nil
}
