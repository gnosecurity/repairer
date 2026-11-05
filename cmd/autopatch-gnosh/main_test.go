package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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

// fakeModelSocket serves the chat API on a UNIX socket, answering with
// reply.
func fakeModelSocket(t *testing.T, sock, reply string) {
	t.Helper()
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"content": reply}}}})
	}))
}

// The jail's helper: run in new user, network and mount namespaces, it
// enters the jail and says what it can see.
func TestJailHelper(t *testing.T) {
	if os.Getenv("GNOSH_JAIL_HELPER") == "" {
		t.Skip("run by TestJail")
	}
	sock, err := enterJail(os.Getenv("ROOT"), os.Getenv("SOCK"))
	if err != nil {
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
	c, dialErr := net.Dial("unix", sock)
	if dialErr == nil {
		c.Close()
	}
	b, _ := json.Marshal(map[string]any{"key_readable": keyErr == nil, "root": names, "model_reachable": dialErr == nil})
	fmt.Println(string(b))
	os.Exit(0)
}

// In the jail, judge sees an empty filesystem with only the model's
// socket: not the model's key file, nothing else on the disk; and the
// socket still reaches the model (round 8, minor 10).
func TestJail(t *testing.T) {
	if err := exec.Command("unshare", "--user", "--map-root-user", "--net", "--mount", "true").Run(); err != nil {
		t.Skip("user, network and mount namespaces aren't available here: ", err)
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "model.key")
	os.WriteFile(key, []byte("secret"), 0o600)
	sock := filepath.Join(dir, "m.sock")
	fakeModelSocket(t, sock, "{}")
	root := filepath.Join(dir, "root")
	os.Mkdir(root, 0o700)
	cmd := exec.Command("unshare", "--user", "--map-root-user", "--net", "--mount", "--", os.Args[0], "-test.run=^TestJailHelper$")
	cmd.Env = append(os.Environ(), "GNOSH_JAIL_HELPER=1", "ROOT="+root, "SOCK="+sock, "KEY="+key)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	var got struct {
		KeyReadable    bool     `json:"key_readable"`
		Root           []string `json:"root"`
		ModelReachable bool     `json:"model_reachable"`
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got.KeyReadable || len(got.Root) != 1 || got.Root[0] != "model.sock" || !got.ModelReachable {
		t.Fatalf("inside the jail: %+v", got)
	}
}

// launch end to end with the built program: the jail answers through the
// model's socket, and launch refuses to run without a drafts list.
func TestLaunchJailed(t *testing.T) {
	if err := exec.Command("unshare", "--user", "--map-root-user", "--net", "--mount", "true").Run(); err != nil {
		t.Skip("namespaces aren't available here: ", err)
	}
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go to build the program")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "autopatch-gnosh")
	if out, err := exec.Command(gobin, "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	sock := filepath.Join(dir, "m.sock")
	fakeModelSocket(t, sock, `{"reading": "drops TCP packets with IP options", "verdict": "yes"}`)
	_, priv, _ := ed25519.GenerateKey(nil)
	keyFile := filepath.Join(dir, "model.key")
	os.WriteFile(keyFile, []byte(hex.EncodeToString(priv.Seed())), 0o600)
	drafts := filepath.Join(dir, "drafts")
	os.WriteFile(drafts, nil, 0o600)
	g, err := os.ReadFile("../../guard/testdata/cve-2026-98432-ipopt.json")
	if err != nil {
		t.Fatal(err)
	}
	ask, _ := json.Marshal(map[string]any{"advisories": []string{"CVE-2026-98432: IP options."}, "guard": json.RawMessage(guardJSON(g))})
	args := []string{"launch", "-socket", sock, "-model", "m", "-weights", "w1", "-key", keyFile, "-chain", "autopatch:x/home"}
	c := exec.Command(bin, append(args, "-drafts", drafts)...)
	c.Stdin = bytes.NewReader(ask)
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	var o Out
	if err := json.Unmarshal(out, &o); err != nil || o.Answer == nil || o.Answer.Verdict != "yes" || o.Yes == nil {
		t.Fatalf("%v: %s", err, out)
	}
	c = exec.Command(bin, args...)
	c.Stdin = bytes.NewReader(ask)
	if out, err := c.CombinedOutput(); err == nil || !strings.Contains(string(out), "needs -drafts") {
		t.Fatalf("launched without a drafts list: %s", out)
	}
}

// guardJSON is the guard file as JSON bytes (base64), as Ask holds it.
func guardJSON(b []byte) []byte {
	q, _ := json.Marshal(b)
	return q
}
