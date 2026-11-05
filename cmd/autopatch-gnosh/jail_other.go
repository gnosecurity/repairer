//go:build !linux

package main

import "errors"

func enterJail(root, socket string) (string, error) {
	return "", errors.New("the jail needs Linux namespaces; use -sandbox none only for tests")
}
