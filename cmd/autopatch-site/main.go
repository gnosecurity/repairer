// Command autopatch-site builds gno.security's guard pages (H1) from the
// Guards realm. It asks a gno.land node for the realm's pages (vm/qrender),
// turns their small Markdown into HTML, and writes a static site: the
// index, a page per filing, per guard and per address the filings name,
// and how to verify a level yourself. It builds into a new folder and
// swaps a symlink, so a server never shows half a site. Run it every
// minute; ask only a node you run, since every page it reads is a question
// to that node.
//
//	autopatch-site -rpc http://127.0.0.1:26657 -realm gno.land/r/autopatch/guards -out /var/www/guards
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func main() {
	rpc := flag.String("rpc", "http://127.0.0.1:26657", "a gno.land node you run")
	realm := flag.String("realm", "gno.land/r/autopatch/guards", "the Guards realm")
	out := flag.String("out", "", "the site: a symlink this swaps to each new build")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: autopatch-site -rpc URL -realm PATH -out DIR")
		os.Exit(2)
	}
	n, err := Build(&Node{RPC: *rpc, Client: &http.Client{Timeout: 30 * time.Second}}, *realm, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "autopatch-site:", err)
		os.Exit(1)
	}
	fmt.Printf("built %d pages\n", n)
}

// Node asks a gno.land node for a realm's pages.
type Node struct {
	RPC    string
	Client *http.Client
}

// Render is the realm's Render(path), through vm/qrender.
func (n *Node) Render(realm, path string) (string, error) {
	q := n.RPC + `/abci_query?path="vm/qrender"&data=0x` + hex.EncodeToString([]byte(realm+":"+path))
	res, err := n.Client.Get(q)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return "", err
	}
	var r struct {
		Result struct {
			Response struct {
				ResponseBase struct {
					Error json.RawMessage `json:"Error"`
					Data  string          `json:"Data"`
					Log   string          `json:"Log"`
				} `json:"ResponseBase"`
			} `json:"response"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return "", fmt.Errorf("the node's answer: %w", err)
	}
	if len(r.Error) > 0 && string(r.Error) != "null" {
		return "", fmt.Errorf("the node: %s", r.Error)
	}
	rb := r.Result.Response.ResponseBase
	if len(rb.Error) > 0 && string(rb.Error) != "null" {
		return "", fmt.Errorf("the realm: %s %s", rb.Error, rb.Log)
	}
	page, err := base64.StdEncoding.DecodeString(rb.Data)
	return string(page), err
}

// maxPages bounds one build.
const maxPages = 5000

var (
	pathRe = regexp.MustCompile(`^(filing/[0-9]{1,9}|guard/[0-9a-f]{64}|address/g1[0-9a-z]{38})$`)
	linkRe = regexp.MustCompile(`\]\(((?:filing|guard|address)/[0-9A-Za-z]+)\)`)
	hashRe = regexp.MustCompile("- Guard: `([0-9a-f]{64})`")
)

// Build reads every page of the realm the index leads to and writes the
// site. It returns how many pages it wrote.
func Build(n *Node, realm, out string) (int, error) {
	pages := map[string]string{} // realm path → its Markdown
	todo := []string{""}
	for len(todo) > 0 {
		p := todo[0]
		todo = todo[1:]
		if _, done := pages[p]; done {
			continue
		}
		if len(pages) >= maxPages {
			return 0, fmt.Errorf("more than %d pages", maxPages)
		}
		md, err := n.Render(realm, p)
		if err != nil {
			return 0, fmt.Errorf("page %q: %w", p, err)
		}
		pages[p] = md
		for _, m := range linkRe.FindAllStringSubmatch(md, -1) {
			if pathRe.MatchString(m[1]) {
				todo = append(todo, m[1])
			}
		}
		if strings.HasPrefix(p, "filing/") {
			for _, m := range hashRe.FindAllStringSubmatch(md, -1) {
				todo = append(todo, "guard/"+m[1])
			}
		}
	}
	dir := out + ".d"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	build, err := os.MkdirTemp(dir, "build-")
	if err != nil {
		return 0, err
	}
	if err := os.Chmod(build, 0o755); err != nil {
		return 0, err
	}
	for p, md := range pages {
		name := "index"
		if p != "" {
			name = p
		}
		depth := strings.Count(name, "/")
		if err := write(filepath.Join(build, name+".html"), page(md, depth)); err != nil {
			return 0, err
		}
	}
	if err := write(filepath.Join(build, "verify.html"), page(verifyMD, 0)); err != nil {
		return 0, err
	}
	// Swap: a new symlink renamed over the old one, then the old build goes.
	old, _ := os.Readlink(out)
	link := out + ".new"
	os.Remove(link)
	if err := os.Symlink(build, link); err != nil {
		return 0, err
	}
	if err := os.Rename(link, out); err != nil {
		return 0, err
	}
	if old != "" && old != build && strings.HasPrefix(old, dir+string(os.PathSeparator)) {
		os.RemoveAll(old)
	}
	return len(pages) + 1, nil
}

func write(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

const verifyMD = "# Verify a guard's level yourself\n\n" +
	"A level here is a copy. What counts is what the chain proves, and you can check it without trusting this site or the node that answers.\n\n" +
	"- The Guards realm keeps one param per guard: `lvl_<hash>`, stored at `/pv/vm:gno.land/r/autopatch/guards:lvl_<hash>` in the chain's main store.\n" +
	"- Ask a node you run for that key at height H, with `abci_query` on `.store/main/key` and prove=true.\n" +
	"- Check the proof against the app hash of header H+1, and that more than two thirds of the validators you trust signed that header.\n" +
	"- The header must be recent, never dated ahead of your clock, and never older than one you already accepted.\n" +
	"- autopatch's light client does exactly this (github.com/jaekwon/autopatch, lightclient/).\n"

// page wraps a realm page's HTML in the site's page.
func page(md string, depth int) []byte {
	var b bytes.Buffer
	up := strings.Repeat("../", depth)
	title := "Guards"
	if strings.HasPrefix(md, "# ") {
		title = strings.TrimSpace(strings.SplitN(md[2:], "\n", 2)[0])
	}
	fmt.Fprintf(&b, `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s · gno.security</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:52rem;margin:1rem auto;padding:0 1rem;color:#111;background:#fff}
pre{background:#f4f4f4;padding:.75rem;overflow-x:auto}code{font:14px ui-monospace,monospace}a{color:#0645ad}
nav{margin-bottom:1rem}@media(prefers-color-scheme:dark){body{color:#eee;background:#111}pre{background:#222}a{color:#8ab4f8}}</style>
</head><body><nav><a href="%sindex.html">Guards</a> · <a href="%sverify.html">Verify a level</a></nav>
`, html.EscapeString(title), up, up)
	b.WriteString(ToHTML(md, up))
	b.WriteString("</body></html>\n")
	return b.Bytes()
}

// ToHTML turns the realm's small Markdown into HTML: headings, bullet
// lines, fenced blocks, paragraphs, `code` and links to the realm's own
// pages; everything else is text, escaped.
func ToHTML(md, up string) string {
	var b strings.Builder
	var para []string
	inList := false
	closeAll := func() {
		if len(para) > 0 {
			b.WriteString("<p>" + inline(strings.Join(para, " "), up) + "</p>\n")
			para = nil
		}
		if inList {
			b.WriteString("</ul>\n")
			inList = false
		}
	}
	lines := strings.Split(md, "\n")
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		switch {
		case strings.HasPrefix(l, "```"):
			closeAll()
			fence := l[:len(l)-len(strings.TrimLeft(l, "`"))]
			var code []string
			for i++; i < len(lines) && lines[i] != fence; i++ {
				code = append(code, lines[i])
			}
			b.WriteString("<pre><code>" + html.EscapeString(strings.Join(code, "\n")) + "</code></pre>\n")
		case strings.HasPrefix(l, "# "):
			closeAll()
			b.WriteString("<h1>" + inline(l[2:], up) + "</h1>\n")
		case strings.HasPrefix(l, "## "):
			closeAll()
			b.WriteString("<h2>" + inline(l[3:], up) + "</h2>\n")
		case strings.HasPrefix(l, "- "):
			if len(para) > 0 {
				b.WriteString("<p>" + inline(strings.Join(para, " "), up) + "</p>\n")
				para = nil
			}
			if !inList {
				b.WriteString("<ul>\n")
				inList = true
			}
			b.WriteString("<li>" + inline(l[2:], up) + "</li>\n")
		case strings.TrimSpace(l) == "":
			closeAll()
		default:
			if inList {
				b.WriteString("</ul>\n")
				inList = false
			}
			para = append(para, l)
		}
	}
	closeAll()
	return b.String()
}

// inline escapes a line, keeping `code` spans and links to the realm's own
// pages.
func inline(s, up string) string {
	var b strings.Builder
	for len(s) > 0 {
		switch {
		case s[0] == '`':
			if end := strings.IndexByte(s[1:], '`'); end >= 0 {
				b.WriteString("<code>" + html.EscapeString(s[1:1+end]) + "</code>")
				s = s[2+end:]
				continue
			}
		case s[0] == '[':
			if close := strings.Index(s, "]("); close > 0 {
				if end := strings.IndexByte(s[close:], ')'); end > 0 {
					target := s[close+2 : close+end]
					if pathRe.MatchString(target) {
						b.WriteString(`<a href="` + up + target + `.html">` + html.EscapeString(s[1:close]) + "</a>")
						s = s[close+end+1:]
						continue
					}
				}
			}
		}
		b.WriteString(html.EscapeString(s[:1]))
		s = s[1:]
	}
	return b.String()
}
