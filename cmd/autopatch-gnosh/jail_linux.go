//go:build linux

package main

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

// enterJail makes judge's filesystem, inside the user and mount namespaces
// launch makes, and moves this process into it: an in-memory root holding
// the model's socket, at /model.sock, and a copy of this program, at
// /judge, and nothing else. The old root is unmounted after pivot_root, so
// no path leads back to the disk, the model's key file least of all (round
// 9, minor 12: from a chroot alone, root in its namespace can climb out),
// and the root is then read-only: judge can change nothing, its own program
// least of all. execJudge runs judge there with no capabilities.
func enterJail(root, socket, self string) error {
	if root == "" || !filepath.IsAbs(root) {
		return errors.New("jail: the root must be an absolute path")
	}
	prog, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	if err := staticProgram(prog); err != nil {
		return err
	}
	// Nothing done here may reach the namespace launch came from.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return err
	}
	size := strconv.Itoa(len(prog) + 64<<10)
	if err := syscall.Mount("tmpfs", root, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "size="+size+",mode=0755"); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "judge"), prog, 0o555); err != nil {
		return err
	}
	in := filepath.Join(root, "model.sock")
	f, err := os.OpenFile(in, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	if err := syscall.Mount(socket, in, "", syscall.MS_BIND, ""); err != nil {
		return err
	}
	old := filepath.Join(root, ".old")
	if err := os.Mkdir(old, 0o700); err != nil {
		return err
	}
	if err := syscall.PivotRoot(root, old); err != nil {
		return err
	}
	if err := os.Chdir("/"); err != nil {
		return err
	}
	if err := syscall.Unmount("/.old", syscall.MNT_DETACH); err != nil {
		return err
	}
	if err := os.Remove("/.old"); err != nil {
		return err
	}
	return syscall.Mount("", "/", "", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV, "")
}

// staticProgram refuses a program that needs a dynamic loader: the jail
// holds no loader and no libraries, so judge couldn't start there. The
// release builds are static (CGO_ENABLED=0, the Makefile).
func staticProgram(prog []byte) error {
	f, err := elf.NewFile(bytes.NewReader(prog))
	if err != nil {
		return fmt.Errorf("jail: this program isn't an ELF file: %w", err)
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("jail: this program is linked dynamically, and the jail holds no loader; build it with CGO_ENABLED=0")
		}
	}
	return nil
}

// Capability calls (linux/capability.h, linux/prctl.h).
const (
	prCapbsetDrop        = 24
	prSetNoNewPrivs      = 38
	prCapAmbient         = 47
	prCapAmbientClearAll = 4
	capabilityVersion3   = 0x20080522
)

// execJudge drops every capability and runs /judge with args, from one
// thread: Go keeps capabilities per thread, so the drop counts only through
// the exec, which starts the program afresh with that thread's empty sets.
// No new privileges can come back by any later exec, and judge, root in its
// namespace, can't mount, pivot or chroot. It returns only on failure.
func execJudge(args, env []string) error {
	runtime.LockOSThread()
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); e != 0 {
		return e
	}
	for c := uintptr(0); c < 64; c++ {
		if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, prCapbsetDrop, c, 0, 0, 0, 0); e != 0 && e != syscall.EINVAL {
			return e
		}
	}
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClearAll, 0, 0, 0, 0); e != 0 && e != syscall.EINVAL {
		return e
	}
	hdr := struct {
		version uint32
		pid     int32
	}{capabilityVersion3, 0}
	var data [2]struct{ effective, permitted, inheritable uint32 }
	if _, _, e := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return e
	}
	return syscall.Exec("/judge", args, env)
}
