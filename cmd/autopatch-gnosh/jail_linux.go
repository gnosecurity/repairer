//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// enterJail is judge's filesystem, entered inside the user and mount
// namespaces launch makes: an empty in-memory root that holds only the
// model's socket, at /model.sock. After it, nothing on the disk is in view,
// the model's key file least of all, and no other local socket is reachable
// by path (round 8, minor 10). It returns the socket's path in the jail.
func enterJail(root, socket string) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", errors.New("jail: the root must be an absolute path")
	}
	// Nothing done here may reach the namespace launch came from.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return "", err
	}
	if err := syscall.Mount("tmpfs", root, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=64k,mode=0755"); err != nil {
		return "", err
	}
	in := filepath.Join(root, "model.sock")
	f, err := os.OpenFile(in, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	f.Close()
	if err := syscall.Mount(socket, in, "", syscall.MS_BIND, ""); err != nil {
		return "", err
	}
	if err := syscall.Chroot(root); err != nil {
		return "", err
	}
	if err := os.Chdir("/"); err != nil {
		return "", err
	}
	return "/model.sock", nil
}
