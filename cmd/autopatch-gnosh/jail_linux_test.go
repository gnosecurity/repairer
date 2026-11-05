//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The jail's helper, run by TestJail in new user, network and mount
// namespaces: it enters the jail, says what it can see, and runs the probe
// in it, as /judge with no capabilities, the way launch runs judge.
func TestJailHelper(t *testing.T) {
	if os.Getenv("GNOSH_JAIL_HELPER") == "" {
		t.Skip("run by TestJail")
	}
	if err := enterJail(os.Getenv("ROOT"), os.Getenv("SOCK"), os.Args[0]); err != nil {
		fmt.Println("jail:", err)
		os.Exit(3)
	}
	_, keyErr := os.ReadFile(os.Getenv("KEY"))
	var names []string
	if es, err := os.ReadDir("/"); err == nil {
		for _, e := range es {
			names = append(names, e.Name())
		}
	}
	b, _ := json.Marshal(map[string]any{"key_readable": keyErr == nil, "root": names})
	fmt.Println(string(b))
	err := execJudge([]string{"judge", "-test.run=^TestJailProbe$"}, []string{"GNOSH_JAIL_PROBE=1"})
	fmt.Println("exec:", err)
	os.Exit(4)
}

// The probe, run by the helper as /judge inside the jail: with no
// capabilities it can't chroot or mount its way out, the root is
// read-only, the old root is gone, and the model's socket still answers.
func TestJailProbe(t *testing.T) {
	if os.Getenv("GNOSH_JAIL_PROBE") == "" {
		t.Skip("run in the jail by TestJailHelper")
	}
	msg := func(err error) string {
		if err == nil {
			return ""
		}
		return err.Error()
	}
	_, oldErr := os.Stat("/.old")
	c, dialErr := net.Dial("unix", "/model.sock")
	if dialErr == nil {
		c.Close()
	}
	nnp, _, _ := syscall.RawSyscall6(syscall.SYS_PRCTL, 39, 0, 0, 0, 0, 0)    // PR_GET_NO_NEW_PRIVS
	admin, _, _ := syscall.RawSyscall6(syscall.SYS_PRCTL, 23, 21, 0, 0, 0, 0) // PR_CAPBSET_READ, CAP_SYS_ADMIN
	b, _ := json.Marshal(map[string]any{
		"no_new_privs":   nnp == 1,
		"bounding_admin": admin != 0,
		"chroot":         msg(syscall.Chroot("/")),
		"mount":          msg(syscall.Mount("tmpfs", "/", "tmpfs", 0, "")),
		"write":          msg(os.WriteFile("/judge", nil, 0o555)),
		"old":            oldErr == nil, "model_reachable": dialErr == nil,
	})
	fmt.Println(string(b))
	os.Exit(0)
}

// In the jail, judge sees only the model's socket and its own program: not
// the model's key file, nothing else on the disk, and no way back to it;
// it holds no capabilities, can write nothing, and the socket still
// reaches the model (round 8, minor 10; round 9, minor 12). The jail holds
// no loader, so the helper is this package's tests built static.
func TestJail(t *testing.T) {
	if err := exec.Command("unshare", "--user", "--map-root-user", "--net", "--mount", "true").Run(); err != nil {
		t.Skip("user, network and mount namespaces aren't available here: ", err)
	}
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go to build the static helper")
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "gnosh.test")
	build := exec.Command(gobin, "test", "-c", "-o", helper, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	key := filepath.Join(dir, "model.key")
	os.WriteFile(key, []byte("secret"), 0o600)
	sock := filepath.Join(dir, "m.sock")
	fakeModelSocket(t, sock, "{}")
	root := filepath.Join(dir, "root")
	os.Mkdir(root, 0o700)
	cmd := exec.Command("unshare", "--user", "--map-root-user", "--net", "--mount", "--", helper, "-test.run=^TestJailHelper$")
	cmd.Env = append(os.Environ(), "GNOSH_JAIL_HELPER=1", "ROOT="+root, "SOCK="+sock, "KEY="+key)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var seen struct {
		KeyReadable bool     `json:"key_readable"`
		Root        []string `json:"root"`
	}
	var probe struct {
		Chroot, Mount, Write string
		Old                  bool
		ModelReachable       bool `json:"model_reachable"`
		NoNewPrivs           bool `json:"no_new_privs"`
		BoundingAdmin        bool `json:"bounding_admin"`
	}
	if len(lines) < 2 || json.Unmarshal([]byte(lines[0]), &seen) != nil || json.Unmarshal([]byte(lines[1]), &probe) != nil {
		t.Fatalf("the jail said: %s", out)
	}
	if seen.KeyReadable || strings.Join(seen.Root, ",") != "judge,model.sock" {
		t.Fatalf("inside the jail: %+v", seen)
	}
	denied := "operation not permitted"
	if !strings.Contains(probe.Chroot, denied) || !strings.Contains(probe.Mount, denied) ||
		!strings.Contains(probe.Write, "read-only file system") || probe.Old || !probe.ModelReachable || !probe.NoNewPrivs || probe.BoundingAdmin {
		t.Fatalf("judge in the jail: %+v", probe)
	}
}

// A program linked dynamically can't start in the jail, which holds no
// loader: the jail refuses it and says how to build it.
func TestStaticProgram(t *testing.T) {
	prog, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skip("no /bin/true")
	}
	if err := staticProgram(prog); err == nil || !strings.Contains(err.Error(), "CGO_ENABLED=0") {
		t.Fatalf("a dynamic program: %v", err)
	}
	if err := staticProgram([]byte("#!/bin/sh\n")); err == nil {
		t.Fatal("a script taken for a program")
	}
}
