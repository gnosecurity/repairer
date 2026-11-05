//go:build !linux

package agent

import (
	"context"
	"errors"
)

// ProbeIPOptions is Linux only.
func (Linux) ProbeIPOptions(context.Context) error {
	return errors.New("probe: IPv4 options probe runs on Linux only")
}
