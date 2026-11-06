package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	w1   = "g1wahhy6m9wf047h6lta047h6lta047h6ltyyhl8"
	hash = "53a97f22c8a05955b5ad8fb73625cca829768ccb253095164644ba895518ab04"
)

// fakeNode answers vm/qrender for the guards realm from pages.
func fakeNode(t *testing.T, pages map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := hex.DecodeString(strings.TrimPrefix(r.URL.Query().Get("data"), "0x"))
		realm, path, _ := strings.Cut(string(data), ":")
		if r.URL.Query().Get("path") != `"vm/qrender"` || realm != "gno.land/r/repairer/guards" {
			http.Error(w, "bad query", 400)
			return
		}
		md, ok := pages[path]
		if !ok {
			md = "# Not found\n"
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": "", "result": map[string]any{"response": map[string]any{
			"ResponseBase": map[string]any{"Error": nil, "Data": base64.StdEncoding.EncodeToString([]byte(md)), "Log": ""}}}})
	}))
}

// The site follows the realm's links, writes a page for each, escapes a
// guard's text that tries to become page, links only the realm's own
// pages, and swaps the whole site in at once.
func TestBuild(t *testing.T) {
	pages := map[string]string{
		"": "# Guards\n\n1 filings.\n\n## Filings, newest first\n\n- [filing 0](filing/0): tested, guard `53a97f22c8a05955`\n",
		"filing/0": "# Filing 0\n\n- State: tested\n- Filed by [" + w1 + "](address/" + w1 + ") at height 3\n- Guard: `" + hash + "`\n\n## The guard\n\n````\n" +
			"{\"breaks\":\"x</code></pre><script>alert(1)</script> ```\"}\n````\n\n## Transcripts\n\n- worker [" + w1 + "](address/" + w1 + "): `aa pass`\n- [click](javascript:alert(1))\n",
		"guard/" + hash: "# Filing 0\n\n- State: tested\n",
		"address/" + w1: "# " + w1 + "\n\n- Filings tested: 1\n",
	}
	node := fakeNode(t, pages)
	defer node.Close()
	out := filepath.Join(t.TempDir(), "guards")
	n, err := Build(&Node{RPC: node.URL, Client: node.Client()}, "gno.land/r/repairer/guards", out)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("%d pages", n)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if idx := read("index.html"); !strings.Contains(idx, `<a href="filing/0.html">filing 0</a>`) {
		t.Errorf("the index:\n%s", idx)
	}
	f := read("filing/0.html")
	for _, want := range []string{
		`<a href="../address/` + w1 + `.html">` + w1 + `</a>`,
		"<pre><code>{&#34;breaks&#34;:&#34;x&lt;/code&gt;&lt;/pre&gt;&lt;script&gt;alert(1)&lt;/script&gt; ```&#34;}</code></pre>",
		"<code>aa pass</code>",
		"[click](javascript:alert(1))",
		`<a href="../index.html">Guards</a>`,
	} {
		if !strings.Contains(f, want) {
			t.Errorf("the filing's page lacks %q:\n%s", want, f)
		}
	}
	if strings.Contains(f, "<script>") || strings.Contains(f, `href="javascript`) {
		t.Errorf("page text became page:\n%s", f)
	}
	for _, name := range []string{"guard/" + hash + ".html", "address/" + w1 + ".html", "verify.html"} {
		read(name)
	}
	// A second build replaces the first whole, and the first is gone.
	first, _ := os.Readlink(out)
	if _, err := Build(&Node{RPC: node.URL, Client: node.Client()}, "gno.land/r/repairer/guards", out); err != nil {
		t.Fatal(err)
	}
	if second, _ := os.Readlink(out); second == first {
		t.Fatal("the site wasn't swapped")
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatal("the old build is still there")
	}
}

// A node that answers with an error builds nothing and keeps the old site.
func TestBuildKeepsTheOldSiteOnError(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","id":"","result":{"response":{"ResponseBase":{"Error":{"@type":"/vm.InvalidPkgPathError"},"Data":null,"Log":"no realm"}}}}`))
	}))
	defer bad.Close()
	out := filepath.Join(t.TempDir(), "guards")
	if _, err := Build(&Node{RPC: bad.URL, Client: bad.Client()}, "gno.land/r/repairer/guards", out); err == nil {
		t.Fatal("built from an error")
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatal("a site appeared")
	}
}
