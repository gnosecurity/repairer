//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// ProbeIPOptions checks, on loopback, that plain TCP connects and that a
// TCP connection request carrying IPv4 options does not. The agent builds
// this packet itself; a guard has no say in its shape.
func (Linux) ProbeIPOptions(ctx context.Context) error {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("probe: listening on loopback: %w", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	addr := ln.Addr().String()

	// Plain TCP must connect, or the probe proves nothing.
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return fmt.Errorf("probe: plain TCP on loopback doesn't connect, so the probe can't tell anything: %w", err)
	}
	c.Close()

	// One connection request carrying IPv4 options (four no-ops) must not
	// get through. TCP_SYNCNT 1 and a timeout shorter than the first
	// retransmission (1 s) keep it to a single packet.
	od := net.Dialer{
		Timeout: 600 * time.Millisecond,
		Control: func(_, _ string, rc syscall.RawConn) error {
			var serr error
			if err := rc.Control(func(fd uintptr) {
				serr = syscall.SetsockoptString(int(fd), syscall.IPPROTO_IP, syscall.IP_OPTIONS, "\x01\x01\x01\x01")
				if serr == nil {
					serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_SYNCNT, 1)
				}
			}); err != nil {
				return err
			}
			return serr
		},
	}
	oc, err := od.DialContext(ctx, "tcp4", addr)
	if err == nil {
		oc.Close()
		return errors.New("probe: a TCP connection request carrying IPv4 options got through")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil
	}
	return fmt.Errorf("probe: the request with IPv4 options failed, but not by being dropped: %w", err)
}
