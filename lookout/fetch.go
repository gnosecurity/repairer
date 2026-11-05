package lookout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// UserAgent is what the lookout calls itself to the feeds: Go's own
// default, which countless programs send, so a feed can't tell a lookout
// (and with few users, whose) from anything else.
const UserAgent = "Go-http-client/1.1"

// Fetcher downloads public feeds whole, asking each time only for what
// changed (ETag, Last-Modified), so the lookout's hourly reads are cheap
// and nothing about the fleet is in any request.
type Fetcher struct {
	Dir    string // <Dir>/<name> holds the newest copy, <Dir>/<name>.meta how it was fetched
	Client *http.Client
}

type fetchMeta struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Fetched      time.Time `json:"fetched"`
}

var feedNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`) // no slash, no leading dot

// Get brings <Dir>/<name> up to date from url, reading at most max bytes.
// It reports whether the copy changed.
func (f *Fetcher) Get(ctx context.Context, name, url string, max int64) (bool, error) {
	if !feedNameRe.MatchString(name) {
		return false, fmt.Errorf("lookout: feed name %q", name)
	}
	path := filepath.Join(f.Dir, name)
	var meta fetchMeta
	if b, err := os.ReadFile(path + ".meta"); err == nil && json.Unmarshal(b, &meta) == nil && meta.URL == url {
		if _, err := os.Stat(path); err != nil {
			meta = fetchMeta{} // the copy is gone: ask for it whole
		}
	} else {
		meta = fetchMeta{}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", UserAgent)
	if meta.ETag != "" {
		req.Header.Set("If-None-Match", meta.ETag)
	}
	if meta.LastModified != "" {
		req.Header.Set("If-Modified-Since", meta.LastModified)
	}
	c := f.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Minute}
	}
	res, err := c.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusNotModified:
		// Checked now and current: the copy's time says when it was last
		// known good, which the stale-feed alert reads.
		now := time.Now()
		os.Chtimes(filepath.Join(f.Dir, name), now, now)
		return false, nil
	case http.StatusNotFound:
		return false, fmt.Errorf("%w: %s", ErrNotFound, url)
	case http.StatusOK:
	default:
		return false, fmt.Errorf("lookout: %s answered %s", url, res.Status)
	}
	if res.ContentLength > max {
		return false, fmt.Errorf("lookout: %s is %d bytes, more than %d", url, res.ContentLength, max)
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(f.Dir, "."+name+".*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(res.Body, max+1))
	if err == nil && n > max {
		err = fmt.Errorf("lookout: %s is more than %d bytes", url, max)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, err
	}
	meta = fetchMeta{URL: url, ETag: res.Header.Get("ETag"), LastModified: res.Header.Get("Last-Modified"), Fetched: time.Now().UTC()}
	mb, _ := json.Marshal(meta)
	if err := os.WriteFile(path+".meta", mb, 0o600); err != nil {
		return true, err
	}
	return true, nil
}

// Path is where a feed's newest copy is.
func (f *Fetcher) Path(name string) string { return filepath.Join(f.Dir, name) }

// ErrNotFound is Get's error when the feed has no such file.
var ErrNotFound = errors.New("lookout: not found")

// errNoCopy is Open's error for a feed never fetched.
var errNoCopy = errors.New("lookout: no copy of that feed yet")

// Open opens a feed's newest copy.
func (f *Fetcher) Open(name string) (*os.File, error) {
	fh, err := os.Open(f.Path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNoCopy
	}
	return fh, err
}
