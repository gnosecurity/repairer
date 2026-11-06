//go:build !linux

package main

import "errors"

var errNoJail = errors.New("the jail needs Linux namespaces; use -sandbox none only for tests")

func enterJail(root, socket, self string) error { return errNoJail }

func execJudge(args, env []string) error { return errNoJail }
