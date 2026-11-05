package main

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// In the sandbox launch uses (a new network namespace with no interfaces),
// a UNIX socket on the filesystem still reaches the model, and nothing on
// the network does. Runs where unshare works (Linux, user namespaces).
func TestSandboxHasNoNetwork(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("no unshare")
	}
	if err := exec.Command("unshare", "--user", "--map-root-user", "--net", "true").Run(); err != nil {
		t.Skip("user and network namespaces aren't available here: ", err)
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "m.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("hello"))
			c.Close()
		}
	}()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	script := `exec 3<>/dev/null
		python3 -c "
import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); print('unix', s.recv(5).decode())
t=socket.socket()
try:
    t.settimeout(2); t.connect(('127.0.0.1', int(sys.argv[2]))); print('tcp reached')
except OSError as e:
    print('tcp refused')
" ` + sock + ` ` + strings.Split(tcp.Addr().String(), ":")[1]
	out, err := exec.Command("unshare", "--user", "--map-root-user", "--net", "sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got := string(out); !strings.Contains(got, "unix hello") || !strings.Contains(got, "tcp refused") {
		t.Fatalf("inside the sandbox: %s", got)
	}
}

func TestOutShape(t *testing.T) {
	b, _ := json.Marshal(Out{NoYes: "outside rule 6"})
	if !strings.Contains(string(b), `"no_yes":"outside rule 6"`) || strings.Contains(string(b), `"yes"`) {
		t.Fatal(string(b))
	}
	_ = os.Getenv
}
