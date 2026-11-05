//go:build unix

package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"syscall"
)

// FileID opens the file without following a symlink at its last element,
// after checking that no element of the path is a symlink, and describes
// it through that handle.
func (l Linux) FileID(path string) (FileID, error) {
	full := l.path(path)
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return FileID{}, err
	}
	if real != full {
		return FileID{}, fmt.Errorf("%s goes through a symlink (it is %s)", path, real)
	}
	// Every directory above the file must be root's and writable by no one
	// else, or someone else could swap the file, or a directory, between
	// this check and a change.
	for d := filepath.Dir(full); ; d = filepath.Dir(d) {
		var st syscall.Stat_t
		if err := syscall.Lstat(d, &st); err != nil {
			return FileID{}, fmt.Errorf("%s: %w", d, err)
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
			return FileID{}, fmt.Errorf("%s: the directory %s can be changed by someone other than root", path, d)
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	fd, err := syscall.Open(full, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return FileID{}, fmt.Errorf("opening %s: %w", path, err)
	}
	defer syscall.Close(fd)
	return fstatID(fd)
}

func (l Linux) ChmodIf(path string, want FileID, mode fs.FileMode) (bool, error) {
	fd, err := syscall.Open(l.path(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ELOOP) {
		return false, nil // gone, or a symlink now: not the file it was
	}
	if err != nil {
		return false, fmt.Errorf("opening %s: %w", path, err)
	}
	defer syscall.Close(fd)
	got, err := fstatID(fd)
	if err != nil {
		return false, err
	}
	if !got.Regular || got.UID != 0 || got.Dev != want.Dev || got.Ino != want.Ino {
		return false, nil
	}
	if err := syscall.Fchmod(fd, unixMode(mode)); err != nil {
		return false, fmt.Errorf("chmod %s: %w", path, err)
	}
	return true, nil
}

func fstatID(fd int) (FileID, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return FileID{}, err
	}
	m := fs.FileMode(st.Mode & 0o777)
	if st.Mode&syscall.S_ISUID != 0 {
		m |= fs.ModeSetuid
	}
	if st.Mode&syscall.S_ISGID != 0 {
		m |= fs.ModeSetgid
	}
	if st.Mode&syscall.S_ISVTX != 0 {
		m |= fs.ModeSticky
	}
	return FileID{
		Mode:    m,
		Regular: st.Mode&syscall.S_IFMT == syscall.S_IFREG,
		UID:     st.Uid,
		Dev:     uint64(st.Dev),
		Ino:     uint64(st.Ino),
	}, nil
}

func unixMode(m fs.FileMode) uint32 {
	u := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		u |= syscall.S_ISUID
	}
	if m&fs.ModeSetgid != 0 {
		u |= syscall.S_ISGID
	}
	if m&fs.ModeSticky != 0 {
		u |= syscall.S_ISVTX
	}
	return u
}
