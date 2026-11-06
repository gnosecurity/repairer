package page

// Signing in to the lookout's page: whoever proves with the Adena wallet
// that they hold one of the admin addresses (Jae's g1ecsu... by default)
// gets a cookie for 30 days. There is no password: the proof is a
// SignArbitrary signature over a one-time phrase (wallet.go). This is
// gnoshop's admin.go (github.com/jaekwon/gnoshop), the pattern every one of
// Jae's sites follows.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultAdmin is Jae's Adena address, his Ledger key: the one wallet that
// opens the page unless the flag says otherwise.
const DefaultAdmin = "g1ecsuj0q572jr0dhu29q9njtnmw03hyu7tyyvv6"

const (
	adminCookie  = "__Host-repairer-admin"
	adminLife    = 30 * 24 * time.Hour
	adminKeyFile = "admin.key"
	adminBody    = 16 << 10
)

// sessionKey signs the admin cookie. It is kept in a file, so a restart
// keeps everyone signed in.
type sessionKey struct {
	mu   sync.Mutex
	path string
	key  []byte
}

func loadSessionKey(path string) (*sessionKey, error) {
	k := &sessionKey{path: path}
	b, err := os.ReadFile(path)
	switch {
	case err == nil && len(b) == 32:
		k.key = b
		return k, nil
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	return k, k.rotate()
}

// rotate replaces the key, which ends every session signed with the old one.
func (k *sessionKey) rotate() error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	tmp := k.path + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, k.path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	k.mu.Lock()
	k.key = b
	k.mu.Unlock()
	return nil
}

func (k *sessionKey) sum(addr string, exp int64) []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	m := hmac.New(sha256.New, k.key)
	fmt.Fprintf(m, "repairer lookout admin\n%s\n%d", addr, exp)
	return m.Sum(nil)
}

// issue is a cookie value naming addr until exp: ADDR.EXP.MAC.
func (k *sessionKey) issue(addr string, exp time.Time) string {
	e := exp.Unix()
	return addr + "." + strconv.FormatInt(e, 10) + "." + base64.RawURLEncoding.EncodeToString(k.sum(addr, e))
}

// check returns the address a cookie value names, when this key signed it
// and it has not run out.
func (k *sessionKey) check(v string, now time.Time) (string, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || now.Unix() >= exp {
		return "", false
	}
	mac, err := base64.RawURLEncoding.Strict().DecodeString(parts[2]) // Strict: one spelling per MAC
	if err != nil || !hmac.Equal(mac, k.sum(parts[0], exp)) {
		return "", false
	}
	return parts[0], true
}

// adminFrom is the admin whose cookie came with the request, if one did.
func (s *Server) adminFrom(r *http.Request) (string, bool) {
	c, err := r.Cookie(adminCookie)
	if err != nil {
		return "", false
	}
	addr, ok := s.sessions.check(c.Value, s.Now())
	return addr, ok && s.admins[addr]
}

// ask lets a sign-in step through when it comes from this site's own page
// and not too often; otherwise it answers the request itself.
func (s *Server) ask(w http.ResponseWriter, r *http.Request) bool {
	if !sameOrigin(r.Header.Get("Origin"), r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "message": "Sign in from " + requestHost(r) + "/admin itself."})
		return false
	}
	if ok, wait := s.limit.take(clientKey(r), s.Now()); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "message": "Too many sign-in tries. Wait a minute and try again."})
		return false
	}
	return true
}

// challenge hands the page a phrase for the wallet to sign.
func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	if !s.ask(w, r) {
		return
	}
	id, words, err := s.challenges.issue(requestHost(r), s.Now())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "words": words})
}

// login takes the signed phrase and, when it proves an admin's wallet,
// hands back the session cookie.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.ask(w, r) {
		return
	}
	no := func(status int, msg string) { writeJSON(w, status, map[string]any{"ok": false, "message": msg}) }
	if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct != "application/json" {
		no(http.StatusUnsupportedMediaType, "Send the sign-in as JSON.")
		return
	}
	var in struct {
		ID   string `json:"id"`
		Addr string `json:"addr"`
		Pub  string `json:"pub"`
		Sig  string `json:"sig"`
		Doc  string `json:"doc"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, adminBody)).Decode(&in); err != nil {
		no(http.StatusBadRequest, "That sign-in could not be read. Try again.")
		return
	}
	now := s.Now()
	words, fresh := s.challenges.take(in.ID, now) // spent, whatever happens next
	switch {
	case !validAddr(in.Addr):
		no(http.StatusBadRequest, "That is not a gno.land address.")
		return
	case !s.admins[in.Addr]:
		log.Printf("admin: refused %s, which is not an admin", short(in.Addr))
		no(http.StatusForbidden, "That wallet ("+short(in.Addr)+") is not an admin here. Switch accounts in Adena and try again.")
		return
	case words == "":
		no(http.StatusBadRequest, "That sign-in code was already used. Try again.")
		return
	case !fresh:
		no(http.StatusBadRequest, "That sign-in took too long. Try again.")
		return
	}
	if err := verifyArbitrary(in.Doc, in.Sig, in.Pub, in.Addr, words); err != nil {
		log.Printf("admin: refused %s: %v", short(in.Addr), err)
		no(http.StatusForbidden, "That signature did not check out. Try again.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: s.sessions.issue(in.Addr, now.Add(adminLife)), Path: "/",
		MaxAge: int(adminLife / time.Second), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	log.Printf("admin: %s signed in", short(in.Addr))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// logout replaces the key, which ends every admin session in every
// browser, and clears this browser's cookie.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r.Header.Get("Origin"), r) {
		http.Error(w, "Sign out from the admin page itself.", http.StatusForbidden)
		return
	}
	if addr, ok := s.adminFrom(r); ok {
		if err := s.sessions.rotate(); err != nil {
			log.Printf("admin: signing out: %v", err)
			http.Error(w, "could not sign out; the journal says why", http.StatusInternalServerError)
			return
		}
		log.Printf("admin: %s signed out, which ends every admin session", short(addr))
	}
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func sameOrigin(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	return err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host)
}

func requestHost(r *http.Request) string {
	h := r.Host
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// clientKey is who is asking, for the rate limit: the address, or behind a
// proxy on this machine, the one it names; an IPv6 address by its /64.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		if real := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); real != nil {
			ip = real
		}
	}
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
