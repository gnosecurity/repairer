// Package page is the lookout's web page. Everything on it is behind the
// Adena sign-in (admin.go). It shows what the lookout knows, offers files
// to download (the guards and policy to sign, the machines' signed reports
// for autopatch-sign), and takes files back (what autopatch-sign signed).
// It never offers a command, and it can't sign anything.
package page

import (
	"archive/tar"
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/agent"
	"github.com/jaekwon/autopatch/lookout"
	"github.com/jaekwon/autopatch/policy"
)

//go:embed web
var web embed.FS

// MaxUpload is the most one uploaded file may be: a message from
// autopatch-sign is a few KB.
const MaxUpload = 256 << 10

// Server is the lookout's page.
type Server struct {
	Policy     *policy.Policy
	PolicyFile []byte
	Collector  *lookout.Collector
	Store      *lookout.Store
	Feeds      *lookout.Feeds // findings, when the feeds run
	Now        func() time.Time

	admins     map[string]bool
	sessions   *sessionKey
	challenges *challenges
	limit      *limiter
	tmpl       *template.Template
	script     []byte
}

// New makes the page. dir keeps the session key; admins are the g1
// addresses whose Adena signature opens it.
func New(dir string, admins []string, p *policy.Policy, col *lookout.Collector, store *lookout.Store, now func() time.Time) (*Server, error) {
	s := &Server{Policy: p, PolicyFile: p.Canonical(), Collector: col, Store: store, Now: now,
		admins: map[string]bool{}, challenges: newChallenges(), limit: newLimiter(10, 6*time.Second)}
	for _, a := range admins {
		a = strings.TrimSpace(a)
		if !validAddr(a) {
			return nil, fmt.Errorf("page: admin %q is not a gno address", a)
		}
		s.admins[a] = true
	}
	if len(s.admins) == 0 {
		return nil, fmt.Errorf("page: no admin")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var err error
	if s.sessions, err = loadSessionKey(filepath.Join(dir, adminKeyFile)); err != nil {
		return nil, err
	}
	if s.tmpl, err = template.New("").Funcs(template.FuncMap{"short": shortHash, "ago": s.ago}).ParseFS(web, "web/*.html"); err != nil {
		return nil, err
	}
	if s.script, err = web.ReadFile("web/admin.js"); err != nil {
		return nil, err
	}
	return s, nil
}

// Handler serves the page.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin", http.StatusSeeOther) })
	// No icon, said plainly: a browser asks for one on every page, and a 404 is an error in its console.
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /admin", s.dashboard)
	mux.HandleFunc("GET /admin/admin.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(s.script)
	})
	mux.HandleFunc("POST /admin/challenge", s.challenge)
	mux.HandleFunc("POST /admin/login", s.login)
	mux.HandleFunc("POST /admin/logout", s.logout)
	mux.HandleFunc("POST /admin/upload", s.signedIn(s.upload))
	mux.HandleFunc("GET /admin/reports.tar", s.signedIn(s.reports))
	mux.HandleFunc("GET /admin/guard/{hash}", s.signedIn(s.guardFile))
	mux.HandleFunc("GET /admin/policy.json", s.signedIn(s.policyFile))
	return headers(mux)
}

// headers marks every answer private: never stored, never indexed, never
// framed.
func headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'")
		// same-origin, not no-referrer: under no-referrer a browser sends
		// "Origin: null" with a form's POST, and the same-origin check then
		// refuses this page's own sign-out and upload forms.
		w.Header().Set("Referrer-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}

// signedIn runs h for a signed-in admin, and sends anyone else to sign in.
// A request that changes something must also come from this page.
func (s *Server) signedIn(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.adminFrom(r); !ok {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && !sameOrigin(r.Header.Get("Origin"), r) {
			http.Error(w, "Send it from the page itself.", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// view is what the dashboard shows.
type view struct {
	Host     string
	Admin    string
	Fleet    string
	Policy   string
	Machines []machineRow
	Waiting  []waitRow
	Findings []lookout.Finding
	// FeedProblems: a feed a day old, or a record skipped (round 8, minor 8).
	FeedProblems []string
	// KernelNew: the kernel's flaws a network can reach, named in the last
	// two weeks, before any distro rates them: what a guard could be
	// thought about for.
	KernelNew []kernelRow
	Notice    string
	Problem   string
}

type kernelRow struct {
	ID, Title, Files, Fixed string
	Seen                    time.Time
}

type machineRow struct {
	Host    string
	Seen    time.Time
	Silent  bool
	Error   string
	Policy  string // "" when the same as the lookout's
	Pending string
	Held    string
	Skipped []string
	Guards  []string
	Failing []string
	Wants   int
	Hits    []hitRow // the newest result of each was-I-hit check run there
	// Reboot is the agent's reboot step, in its words: a reboot owed and why
	// it waits, or one under way (B3); RebootBad marks one that needs you.
	Reboot    string
	RebootBad bool
	// Facts are the problems behind November's failures that the machine's
	// facts show, in words (AUTOPATCH-BRIEF.md, section 1).
	Facts []string
}

// hitRow is one was-I-hit result, in words.
type hitRow struct {
	Flag bool
	Text string
}

type waitRow struct {
	Host string
	Hash string
	Name string
	Why  string
	Ask  bool
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	addr, ok := s.adminFrom(r)
	if !ok {
		s.render(w, "signin.html", view{Host: requestHost(r)})
		return
	}
	v := view{Host: requestHost(r), Admin: short(addr), Fleet: s.Policy.Fleet, Policy: s.Policy.Hash(),
		Notice: r.URL.Query().Get("kept"), Problem: r.URL.Query().Get("problem")}
	for _, st := range s.Collector.Kept() {
		row := machineRow{Host: st.Host, Seen: st.Time, Silent: st.Silent, Error: st.Error}
		if rep := st.Report; rep != nil {
			if rep.Policy != s.Policy.Hash() {
				row.Policy = rep.Policy
			}
			if rep.Pending != nil {
				row.Pending = rep.Pending.Hash
			}
			row.Held = rep.Held
			for _, sk := range rep.Skipped {
				row.Skipped = append(row.Skipped, fmt.Sprintf("%d %s: %s", sk.Seq, sk.What, sk.Why))
			}
			if rep.Tick != nil {
				for k, why := range rep.Tick.Health {
					row.Failing = append(row.Failing, k+": "+why)
				}
				sort.Strings(row.Failing)
				row.Reboot = rep.Tick.Reboot
				row.RebootBad = rebootNeedsYou(rep.Tick.Reboot)
			}
			row.Facts = factLines(rep.Facts, s.Now())
			for _, g := range rep.Guards {
				row.Guards = append(row.Guards, guardLine(g))
			}
			row.Wants = len(rep.Wants)
			for _, h := range rep.Hits {
				row.Hits = append(row.Hits, hitRow{Flag: h.Flag || h.Error != "" || h.Capped != "", Text: hitLine(h)})
			}
			for _, o := range rep.OnTheWay {
				v.Waiting = append(v.Waiting, waitRow{Host: st.Host, Hash: o.Hash, Name: o.Name, Why: wayLine(o), Ask: o.Ask})
			}
		}
		v.Machines = append(v.Machines, row)
	}
	// A machine in a tier whose agent key isn't in the policy can't report:
	// listed so it isn't forgotten.
	keyed := map[string]bool{}
	for _, k := range s.Policy.Signers.Agents {
		keyed[k.Host] = true
	}
	for _, t := range s.Policy.Tiers {
		for _, h := range t.Hosts {
			if !keyed[h] {
				keyed[h] = true
				v.Machines = append(v.Machines, machineRow{Host: h, Silent: true,
					Error: "no agent key in the policy yet (autopatch-agent init prints it)"})
			}
		}
	}
	sort.SliceStable(v.Machines, func(i, j int) bool { return v.Machines[i].Host < v.Machines[j].Host })
	sort.SliceStable(v.Waiting, func(i, j int) bool { return v.Waiting[i].Ask && !v.Waiting[j].Ask })
	if s.Feeds != nil {
		if fs, err := s.Feeds.Findings(); err == nil {
			v.Findings = fs[:min(len(fs), 200)] // exploited first
		}
		v.FeedProblems = s.Feeds.Problems(s.Now())
		if ks, err := s.Feeds.KernelNewKept(); err == nil {
			for _, k := range ks[:min(len(ks), 100)] {
				v.KernelNew = append(v.KernelNew, kernelRow{ID: k.ID, Title: k.Title, Files: strings.Join(k.Files, " "), Fixed: kernelFixes(k), Seen: k.FirstSeen})
			}
		}
	}
	s.render(w, "dashboard.html", v)
}

// kernelFixes lists the releases that fix a kernel flaw, by series, then
// mainline's.
func kernelFixes(k *lookout.KernelCVE) string {
	var out []string
	for _, v := range k.Fixed {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return lookout.KernelReleaseLess(out[i], out[j]) })
	if k.Mainline != "" {
		out = append(out, "mainline "+k.Mainline)
	}
	if len(out) == 0 {
		return "no fix yet"
	}
	return strings.Join(out, ", ")
}

func guardLine(g agent.GuardState) string {
	line := g.Name + ": " + g.Status
	if g.By != "" {
		line += ", by " + g.By
	}
	if g.Keep {
		line += ", kept"
	}
	if g.Later && !g.Booted {
		line += ", waits for a boot"
	}
	if g.BootWindow {
		line += ", in its window after a boot"
	}
	if g.Stopped > 0 {
		line += fmt.Sprintf(", stopped %d packets", g.Stopped)
	}
	if g.Failed != "" {
		line += "; failed to come off: " + g.Failed
	}
	return line
}

// rebootNeedsYou says whether the agent's reboot line is one to act on: a
// reboot owed and waiting, or one that failed.
func rebootNeedsYou(line string) bool {
	for _, w := range []string{"owed", "fail", "didn't", "gone", "replaced in place"} {
		if strings.Contains(line, w) {
			return true
		}
	}
	return false
}

// factLines says, in words, what a machine's facts show that needs you:
// the failures of November (AUTOPATCH-BRIEF.md, section 1). A fix installed
// but not running is the reboot line's; the rest are here: a release past
// its end of support, updates that stopped (dpkg left half done, packages
// kept back, unattended-upgrades not run for two days), a newer kernel's
// missing driver builds, and a disk too full to update.
func factLines(f *agent.Report, now time.Time) []string {
	if f == nil {
		return nil
	}
	var out []string
	if end, err := time.Parse("2006-01-02", f.OS.EOL); err == nil && !now.Before(end) {
		out = append(out, fmt.Sprintf("%s %s has had no fixes since its support ended on %s", f.OS.ID, f.OS.Version, f.OS.EOL))
	}
	if len(f.Updates.DpkgAudit) > 0 {
		out = append(out, "updates are stuck: dpkg --audit says "+clipLine(strings.Join(f.Updates.DpkgAudit, " / "), 300))
	}
	if n := len(f.Updates.KeptBack); n > 0 {
		out = append(out, fmt.Sprintf("unattended-upgrades keeps back %d package(s): %s", n, clipLine(strings.Join(f.Updates.KeptBack, ", "), 300)))
	}
	if t := f.Updates.LastUnattended; !t.IsZero() && now.Sub(t) > 48*time.Hour {
		out = append(out, "unattended-upgrades last ran "+t.UTC().Format("2006-01-02 15:04 UTC"))
	}
	if len(f.Kernel.DKMSMissing) > 0 {
		out = append(out, fmt.Sprintf("the newest kernel, %s, lacks its driver builds: %s", f.Kernel.Newest, clipLine(strings.Join(f.Kernel.DKMSMissing, ", "), 300)))
	}
	for _, d := range f.Disk {
		min := uint64(1 << 30)
		if d.Path == "/boot" {
			min = 100 << 20 // a kernel and its initrd
		}
		if d.Free < min {
			out = append(out, fmt.Sprintf("only %d MB free on %s", d.Free>>20, d.Path))
		}
	}
	return out
}

// clipLine cuts a line to n bytes.
func clipLine(s string, n int) string {
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}

// hitLine says what a was-I-hit check found, and when it ran.
func hitLine(h agent.HitResult) string {
	when := h.Ran.UTC().Format("2006-01-02 15:04 UTC")
	switch {
	case h.Error != "" && h.Count == 0:
		return fmt.Sprintf("%s (%s): couldn't run: %s", h.Name, when, h.Error)
	case h.Error != "": // what it found, and that part went unread
		s := fmt.Sprintf("%s (%s): FLAGGED, %d found, and part couldn't be read (%s)", h.Name, when, h.Count, h.Error)
		if len(h.Paths) > 0 {
			s += ": " + strings.Join(h.Paths, ", ")
			if h.Count > len(h.Paths) {
				s += fmt.Sprintf(" and %d more", h.Count-len(h.Paths))
			}
		}
		return s + confLine(h)
	case h.Count == 0 && h.Capped == "":
		s := fmt.Sprintf("%s (%s): nothing found", h.Name, when)
		if h.Gone > 0 {
			s += fmt.Sprintf(" (%d listed files gone)", h.Gone)
		}
		return s + confLine(h)
	}
	s := fmt.Sprintf("%s (%s): FLAGGED, %d found", h.Name, when, h.Count)
	switch h.Capped {
	case "":
	case "history":
		s = fmt.Sprintf("%s (%s): %d found, but the logs here don't reach back to its start, so not a clean answer", h.Name, when, h.Count)
	default:
		s = fmt.Sprintf("%s (%s): stopped at its %s cap with %d found, so not a clean answer", h.Name, when, h.Capped, h.Count)
	}
	if h.Untimed > 0 {
		s += fmt.Sprintf(" (%d of them at a time it couldn't read, counted)", h.Untimed)
	}
	if len(h.Paths) > 0 {
		s += ": " + strings.Join(h.Paths, ", ")
		if h.Count > len(h.Paths) {
			s += fmt.Sprintf(" and %d more", h.Count-len(h.Paths))
		}
	}
	return s + confLine(h)
}

// confLine says which of a package's config files changed since it put
// them: apart, as the owner's own edits look the same.
func confLine(h agent.HitResult) string {
	if h.Conf == 0 {
		return ""
	}
	s := fmt.Sprintf("; %d of its config files changed since the package put them (yours look the same)", h.Conf)
	if len(h.ConfPaths) > 0 {
		s += ": " + strings.Join(h.ConfPaths, ", ")
		if h.Conf > len(h.ConfPaths) {
			s += fmt.Sprintf(" and %d more", h.Conf-len(h.ConfPaths))
		}
	}
	return s
}

func wayLine(o agent.OnTheWay) string {
	switch {
	case o.Ask:
		return "waiting for you: " + o.Last
	case o.Refused != "":
		return "refused here: " + o.Refused
	case o.Baseline > 0:
		return fmt.Sprintf("health baseline, %d of 3 samples", o.Baseline)
	case !o.RetryAt.IsZero():
		return fmt.Sprintf("try %d failed (%s); next try %s", o.Tries, o.Last, o.RetryAt.UTC().Format("15:04 UTC"))
	}
	return "waiting: not admitted here yet, or a canary's Healthy, or another change in flight"
}

func (s *Server) render(w http.ResponseWriter, name string, v view) {
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, v); err != nil {
		log.Printf("page: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

// upload keeps what autopatch-sign signed (or a guard, a policy, a signed
// Tested). The agents check every signature; the lookout only carries.
func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxUpload+16<<10)
	f, _, err := r.FormFile("file")
	if err != nil {
		http.Redirect(w, r, "/admin?problem="+queryEscape("Choose a file to upload."), http.StatusSeeOther)
		return
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxUpload+1))
	if err != nil || len(b) > MaxUpload {
		http.Redirect(w, r, "/admin?problem="+queryEscape("That file is too big."), http.StatusSeeOther)
		return
	}
	what, err := s.Store.AddFile(b)
	if err != nil {
		http.Redirect(w, r, "/admin?problem="+queryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	log.Printf("page: kept %s", what)
	http.Redirect(w, r, "/admin?kept="+queryEscape("Kept "+what+". It goes out with the next delivery."), http.StatusSeeOther)
}

// reports is every machine's newest signed report, as signed, in one tar:
// what autopatch-sign checks before you sign (its -reports folder).
func (s *Server) reports(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, k := range s.Policy.Signers.Agents {
		b, err := os.ReadFile(filepath.Join(s.Collector.Dir, k.Host+".json"))
		if err != nil {
			continue // no report kept: autopatch-sign will say so, and ask you to name it
		}
		hdr := &tar.Header{Name: "reports/" + k.Host + ".json", Mode: 0o644, Size: int64(len(b)), ModTime: s.Now()}
		if err := tw.WriteHeader(hdr); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tw.Write(b)
	}
	if err := tw.Close(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", `attachment; filename="reports-`+s.Policy.Fleet+`.tar"`)
	w.Write(buf.Bytes())
}

func (s *Server) guardFile(w http.ResponseWriter, r *http.Request) {
	h := r.PathValue("hash")
	b, err := s.Store.Guard(h)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="guard-`+h[:16]+`.json"`)
	w.Write(b)
}

func (s *Server) policyFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="policy-`+s.Policy.Fleet+`.json"`)
	w.Write(s.PolicyFile)
}

func (s *Server) ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := s.Now().Sub(t).Round(time.Minute)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

func queryEscape(s string) string { return template.URLQueryEscaper(s) }
