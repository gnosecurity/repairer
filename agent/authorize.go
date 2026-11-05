package agent

import (
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var pubKeyRe = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]{68}(?: [A-Za-z0-9._@-]{1,64})?$`)

// AuthorizedKeys writes the intake user's two ssh lines for the lookout:
// one key may only print the last signed report, the other may only hand
// in a bundle. Each line is restricted (no shell, no forwarding, no pty)
// and, given addresses, accepted only from the lookouts.
func AuthorizedKeys(self, stateDir, reportKey, intakeKey, from string) (string, error) {
	for _, k := range []string{reportKey, intakeKey} {
		if !pubKeyRe.MatchString(strings.TrimSpace(k)) {
			return "", fmt.Errorf("authorize: %q isn't one ssh-ed25519 public key", k)
		}
	}
	if strings.TrimSpace(reportKey) == strings.TrimSpace(intakeKey) {
		return "", fmt.Errorf("authorize: report and intake need two different keys")
	}
	if strings.ContainsAny(self+stateDir, "\" ,\n") {
		return "", fmt.Errorf("authorize: paths with quotes, spaces or commas")
	}
	opts := "restrict"
	if from != "" {
		for _, a := range strings.Split(from, ",") {
			if _, err := netip.ParsePrefix(a); err != nil {
				if _, err := netip.ParseAddr(a); err != nil {
					return "", fmt.Errorf("authorize: from %q isn't an address", a)
				}
			}
		}
		opts += `,from="` + from + `"`
	}
	line := func(cmd, key string) string {
		return fmt.Sprintf("%s,command=\"%s %s -state-dir %s\" %s\n", opts, self, cmd, stateDir, strings.TrimSpace(key))
	}
	return line("report", reportKey) + line("intake", intakeKey), nil
}

// WriteAuthorizedKeys puts the lines in the intake user's
// ~/.ssh/authorized_keys, replacing what was there: the user exists only
// for the lookout. Root runs it once, by hand, at install.
func WriteAuthorizedKeys(name, lines string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if uid == 0 || u.HomeDir == "" || u.HomeDir == "/" || u.HomeDir == "/nonexistent" {
		return fmt.Errorf("authorize: %s needs a home of its own, and must not be root", name)
	}
	dir := filepath.Join(u.HomeDir, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Lchown(dir, uid, gid); err != nil {
		return err
	}
	path := filepath.Join(dir, "authorized_keys")
	if err := writeAtomic(path, []byte(lines), 0o600); err != nil {
		return err
	}
	return os.Lchown(path, uid, gid)
}
