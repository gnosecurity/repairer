package page

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/jaekwon/autopatch/agent"
	"github.com/jaekwon/autopatch/approve"
	"github.com/jaekwon/autopatch/lookout"
	"github.com/jaekwon/autopatch/policy"
)

// The address rule, against a pair taken off the live chain (gnoshop's test).
func TestAddressAgainstTheChain(t *testing.T) {
	pub, _ := base64.StdEncoding.DecodeString("AgBSSj+NLAA6icQ/Rf6vbrjtRbbjo197vms7Sf+eLYPI")
	if got := gnoAddress(pub); got != "g1manfred47kzduec920z88wfr64ylksmdcedlf5" {
		t.Fatalf("gnoAddress = %s", got)
	}
	if !validAddr(DefaultAdmin) || validAddr("g1ecsuj0q572jr0dhu29q9njtnmw03hyu7tyyvv7") {
		t.Fatal("validAddr")
	}
}

// testWallet signs what Adena signs, built the way Adena builds it.
type testWallet struct {
	priv *secp256k1.PrivateKey
	pub  string
	addr string
}

func newTestWallet(t *testing.T) testWallet {
	p, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := p.PubKey().SerializeCompressed()
	return testWallet{p, base64.StdEncoding.EncodeToString(pub), gnoAddress(pub)}
}

func (w testWallet) doc(words, signer string) string {
	b, _ := json.Marshal(map[string]any{
		"account_number": "0", "chain_id": "gnoland1", "fee": map[string]any{"amount": []any{}, "gas": "0"},
		"memo": "", "sequence": "0",
		"msgs": []any{map[string]any{"type": "sign/MsgSignData", "value": map[string]any{"data": base64.StdEncoding.EncodeToString([]byte(words)), "signer": signer}}},
	})
	return string(b)
}

func (w testWallet) sign(doc string) string {
	h := sha256.Sum256([]byte(doc))
	sig := ecdsa.Sign(w.priv, h[:])
	r, s := sig.R(), sig.S()
	rb, sb := r.Bytes(), s.Bytes()
	return base64.StdEncoding.EncodeToString(append(rb[:], sb[:]...))
}

// testPage is a lookout page with one admin, w, and one machine whose
// signed report the lookout keeps.
func testPage(t *testing.T, w testWallet) (*Server, *httptest.Server, ed25519.PrivateKey) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(nil)
	p, err := policy.Decode([]byte(`{"fleet":"home","replaces":"","delay_seconds":86400,
		"signers":{"me":{"name":"owner","key":"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"},
		"agents":[{"name":"mail","key":"` + hex.EncodeToString(key.Public().(ed25519.PublicKey)) + `","host":"mail"}]},
		"tiers":[{"name":"A","hosts":["mail","web"],"admit":["me"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	owner, _ := hex.DecodeString(p.Signers.Me.Hex)
	rep := agent.FleetReport{Version: approve.MemoVersion, Kind: "report", Chain: approve.ChainID(owner, "home"), Host: "mail", Seq: 3,
		Time: now.Add(-2 * time.Minute), Policy: p.Hash(),
		Pending:  &agent.PendingReport{Hash: strings.Repeat("ab", 32), FirstSeen: now.Add(-time.Hour)},
		OnTheWay: []agent.OnTheWay{{Hash: strings.Repeat("cd", 32), Name: "cve-2099-1/test v1", Ask: true, Last: "health failed 3 times in a row"}}}
	body, _ := json.Marshal(rep)
	signed, _ := json.Marshal(approve.SignReport(key, body))
	col := &lookout.Collector{Policy: p, Dir: t.TempDir(), Now: clock,
		Fetch: func(context.Context, string) ([]byte, error) { return signed, nil }}
	col.Collect(context.Background())
	s, err := New(t.TempDir(), []string{w.addr}, p, col, &lookout.Store{Dir: t.TempDir()}, clock)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts, key
}

func post(t *testing.T, c *http.Client, url, origin, ctype string, body []byte) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Origin", origin)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

// signIn runs the page's sign-in as Adena would, and returns the cookie.
func signIn(t *testing.T, ts *httptest.Server, w testWallet) *http.Cookie {
	t.Helper()
	c := ts.Client()
	_, ch := post(t, c, ts.URL+"/admin/challenge", ts.URL, "", nil)
	words, _ := ch["words"].(string)
	doc := w.doc(words, w.addr)
	in, _ := json.Marshal(map[string]string{"id": ch["id"].(string), "addr": w.addr, "pub": w.pub, "sig": w.sign(doc), "doc": doc})
	res, out := post(t, c, ts.URL+"/admin/login", ts.URL, "application/json", in)
	if res.StatusCode != 200 || out["ok"] != true {
		t.Fatalf("sign-in: %d %v", res.StatusCode, out)
	}
	for _, ck := range res.Cookies() {
		if ck.Name == adminCookie {
			return ck
		}
	}
	t.Fatal("no cookie")
	return nil
}

func get(t *testing.T, ts *httptest.Server, path string, ck *http.Cookie) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	if ck != nil {
		req.AddCookie(ck)
	}
	c := ts.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

// Nothing shows before the admin signs in with Adena; then the dashboard
// shows the machine, its pending policy and the guard waiting for the
// owner, and every answer is private.
func TestSignInAndDashboard(t *testing.T) {
	w := newTestWallet(t)
	_, ts, _ := testPage(t, w)
	res, body := get(t, ts, "/admin", nil)
	if !strings.Contains(body, "Sign in with Adena") || strings.Contains(body, "mail") {
		t.Fatalf("before sign-in: %s", body)
	}
	// same-origin, so a browser sends the page's own origin with its forms'
	// POSTs (under no-referrer it sends "Origin: null", and the sign-out and
	// upload forms were refused).
	if res.Header.Get("Cache-Control") != "no-store" || !strings.Contains(res.Header.Get("X-Robots-Tag"), "noindex") ||
		res.Header.Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("headers %v", res.Header)
	}
	for _, path := range []string{"/admin/reports.tar", "/admin/policy.json", "/admin/guard/" + strings.Repeat("cd", 32)} {
		if res, _ := get(t, ts, path, nil); res.StatusCode != http.StatusSeeOther {
			t.Errorf("%s without signing in: %d", path, res.StatusCode)
		}
	}
	ck := signIn(t, ts, w)
	if !ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie %+v", ck)
	}
	_, body = get(t, ts, "/admin", ck)
	for _, want := range []string{"mail", "2 min ago", "PENDING", "waiting for you: health failed 3 times in a row", "cve-2099-1/test v1",
		"<td>web</td>", "no agent key in the policy yet"} { // a machine that can't report yet is listed
		if !strings.Contains(body, want) {
			t.Errorf("the dashboard lacks %q", want)
		}
	}
}

// The sign-in refuses another wallet, a reused code, a forged signature,
// and a request from another site.
func TestSignInRefuses(t *testing.T) {
	w, other := newTestWallet(t), newTestWallet(t)
	_, ts, _ := testPage(t, w)
	c := ts.Client()
	try := func(origin string, signer testWallet, mutate func(map[string]string)) (int, map[string]any) {
		_, ch := post(t, c, ts.URL+"/admin/challenge", ts.URL, "", nil)
		doc := signer.doc(ch["words"].(string), signer.addr)
		in := map[string]string{"id": ch["id"].(string), "addr": signer.addr, "pub": signer.pub, "sig": signer.sign(doc), "doc": doc}
		if mutate != nil {
			mutate(in)
		}
		b, _ := json.Marshal(in)
		res, out := post(t, c, ts.URL+"/admin/login", origin, "application/json", b)
		return res.StatusCode, out
	}
	if code, _ := try(ts.URL, other, nil); code != http.StatusForbidden {
		t.Errorf("another wallet: %d", code)
	}
	if code, _ := try(ts.URL, w, func(in map[string]string) { in["sig"] = other.sign(in["doc"]) }); code != http.StatusForbidden {
		t.Errorf("a forged signature: %d", code)
	}
	if code, _ := try("https://evil.example", w, nil); code != http.StatusForbidden {
		t.Errorf("another site: %d", code)
	}
	_, ch := post(t, c, ts.URL+"/admin/challenge", ts.URL, "", nil)
	doc := w.doc(ch["words"].(string), w.addr)
	in, _ := json.Marshal(map[string]string{"id": ch["id"].(string), "addr": w.addr, "pub": w.pub, "sig": w.sign(doc), "doc": doc})
	post(t, c, ts.URL+"/admin/login", ts.URL, "application/json", in)
	if res, _ := post(t, c, ts.URL+"/admin/login", ts.URL, "application/json", in); res.StatusCode != http.StatusBadRequest {
		t.Errorf("a reused code: %d", res.StatusCode)
	}
}

// An uploaded message from autopatch-sign is kept for the next delivery;
// only a signed-in admin, from the page itself, can upload. The downloads
// are the machines' signed reports (a tar for autopatch-sign), the policy
// and a kept guard.
func TestUploadAndDownloads(t *testing.T) {
	w := newTestWallet(t)
	s, ts, key := testPage(t, w)
	ck := signIn(t, ts, w)
	msg, err := os.ReadFile("../../approve/testdata/tiers/1.json")
	if err != nil {
		t.Fatal(err)
	}
	message, _ := json.Marshal(map[string]any{"seq": 1, "tx": json.RawMessage(msg)})
	upload := func(origin string, ck *http.Cookie) *http.Response {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("file", "yes-1.json")
		fw.Write(message)
		mw.Close()
		req, _ := http.NewRequest("POST", ts.URL+"/admin/upload", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Origin", origin)
		if ck != nil {
			req.AddCookie(ck)
		}
		c := ts.Client()
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	if res := upload(ts.URL, nil); res.StatusCode != http.StatusSeeOther || strings.Contains(res.Header.Get("Location"), "kept") {
		t.Fatalf("an upload without signing in: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if res := upload("https://evil.example", ck); res.StatusCode != http.StatusForbidden {
		t.Fatalf("an upload from another site: %d", res.StatusCode)
	}
	if res := upload(ts.URL, ck); !strings.Contains(res.Header.Get("Location"), "kept=Kept+the+owner") {
		t.Fatalf("the upload: %s", res.Header.Get("Location"))
	}
	if _, err := os.Stat(filepath.Join(s.Store.Dir, "messages", "1.json")); err != nil {
		t.Fatal("the message wasn't kept")
	}

	res, body := get(t, ts, "/admin/reports.tar", ck)
	if res.StatusCode != 200 {
		t.Fatalf("reports.tar: %d", res.StatusCode)
	}
	tr := tar.NewReader(strings.NewReader(body))
	hdr, err := tr.Next()
	if err != nil || hdr.Name != "reports/mail.json" {
		t.Fatalf("tar: %v %v", hdr, err)
	}
	b, _ := io.ReadAll(tr)
	if _, err := approve.VerifyReport(b, hex.EncodeToString(key.Public().(ed25519.PublicKey))); err != nil {
		t.Fatalf("the report in the tar doesn't verify: %v", err)
	}
	if _, body := get(t, ts, "/admin/policy.json", ck); body != string(s.PolicyFile) {
		t.Fatal("the policy download")
	}
	if res, _ := get(t, ts, "/admin/guard/..%2fetc%2fpasswd", ck); res.StatusCode != http.StatusNotFound {
		t.Fatalf("a path for a guard: %d", res.StatusCode)
	}
}

// Signing out ends every session.
func TestSignOut(t *testing.T) {
	w := newTestWallet(t)
	_, ts, _ := testPage(t, w)
	ck := signIn(t, ts, w)
	req, _ := http.NewRequest("POST", ts.URL+"/admin/logout", nil)
	req.Header.Set("Origin", ts.URL)
	req.AddCookie(ck)
	c := ts.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if res, err := c.Do(req); err != nil || res.StatusCode != http.StatusSeeOther {
		t.Fatal(err)
	}
	if _, body := get(t, ts, "/admin", ck); !strings.Contains(body, "Sign in with Adena") {
		t.Fatal("the old cookie still opens the page")
	}
}

// The dashboard lists the kernel's new flaws a network can reach, as the
// feeds command kept them: name, what, the files, and the releases that fix
// them in order, mainline last.
func TestDashboardShowsNewKernelFlaws(t *testing.T) {
	w := newTestWallet(t)
	s, ts, _ := testPage(t, w)
	b, err := os.ReadFile("../testdata/vulns-CVE-2026-98432.json")
	if err != nil {
		t.Fatal(err)
	}
	k, err := lookout.ParseKernelCVE(b)
	if err != nil {
		t.Fatal(err)
	}
	k.FirstSeen = time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	kept, _ := json.Marshal([]*lookout.KernelCVE{k})
	if err := os.WriteFile(filepath.Join(dir, "kernel-new.json"), kept, 0o600); err != nil {
		t.Fatal(err)
	}
	s.Feeds = &lookout.Feeds{Dir: dir, Fetcher: &lookout.Fetcher{Dir: filepath.Join(dir, "copies")}}
	ck := signIn(t, ts, w)
	_, body := get(t, ts, "/admin", ck)
	for _, want := range []string{"New kernel flaws a network can reach", "CVE-2026-98432", "ipv4: free inet_opt and ireq_opt",
		"net/ipv4/af_inet.c net/ipv4/tcp_ipv4.c", "5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56, 7.2.10, mainline 7.3", "3 h ago"} {
		if !strings.Contains(body, want) {
			t.Errorf("the dashboard lacks %q", want)
		}
	}
}
