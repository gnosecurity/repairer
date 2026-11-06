//go:build linux

package agent

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const devHead = "Inter-|   Receive                                                |  Transmit\n" +
	" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"

func TestOnlyLoopback(t *testing.T) {
	for _, c := range []struct {
		name string
		dev  string
		want bool
	}{
		{"lo alone (PrivateNetwork=)", devHead + "    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n", true},
		{"lo and a veth", devHead + "    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n  eth0: 9 1 0 0 0 0 0 0 9 1 0 0 0 0 0 0\n", false},
		{"lo and a tunnel's fallback device", devHead + "    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n  sit0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", false},
		{"no interface at all", devHead, false},
		{"not net/dev", "garbage", false},
		{"empty", "", false},
	} {
		if got := onlyLoopback(c.dev); got != c.want {
			t.Errorf("%s: onlyLoopback = %v, want %v", c.name, got, c.want)
		}
	}
}

// On a real machine, as root: a process in a namespace with only lo is
// left out of the netns check, and one in a namespace with another
// interface is named. (Ubuntu 26.04's polkitd runs with PrivateNetwork=yes,
// and the old check refused guard one there for it.)
func TestOtherNetNamespaceSkipsLoopbackOnly(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to make network namespaces")
	}
	for _, prog := range []string{"unshare", "ip"} {
		if _, err := exec.LookPath(prog); err != nil {
			t.Skip(prog + " isn't installed")
		}
	}
	start := func(script string) int {
		t.Helper()
		cmd := exec.Command("unshare", "--net", "sh", "-c", script)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
		return cmd.Process.Pid
	}
	lo := start("exec sleep 60")
	other := start("ip link add v0 type veth peer name v1 && exec sleep 60")
	// Wait until both are in their own namespace, and the veth is there.
	self, _ := os.Readlink("/proc/self/ns/net")
	deadline := time.Now().Add(10 * time.Second)
	for {
		a, _ := os.Readlink("/proc/" + strconv.Itoa(lo) + "/ns/net")
		b, _ := os.Readlink("/proc/" + strconv.Itoa(other) + "/ns/net")
		dev, _ := os.ReadFile("/proc/" + strconv.Itoa(other) + "/net/dev")
		if a != "" && a != self && b != "" && b != self && strings.Contains(string(dev), "v0:") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the namespaces never came up")
		}
		time.Sleep(50 * time.Millisecond)
	}
	dev, err := os.ReadFile("/proc/" + strconv.Itoa(lo) + "/net/dev")
	if err != nil || !onlyLoopback(string(dev)) {
		t.Fatalf("the unshared sleep's namespace should have only lo: %q %v", dev, err)
	}
	got, err := otherNetNamespace()
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(got, "process "+strconv.Itoa(lo)+" ") {
		t.Fatalf("a loopback-only namespace counted: %s", got)
	}
	if got == "" {
		t.Fatal("a namespace with a veth didn't count")
	}
}
