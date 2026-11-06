// Command repairer-lookout is the watcher: it collects each machine's
// signed report, carries signed messages to the machines, and says which
// machines a flaw reaches. It holds no key an agent trusts; it can't sign
// anything, log in as root, or change a machine.
//
//	repairer-lookout collect -config lookout.json
//	repairer-lookout deliver -config lookout.json
//	repairer-lookout run     -config lookout.json         collect and deliver every minute
//	repairer-lookout serve   -config lookout.json         run, and serve the page (Adena sign-in) on -listen
//	repairer-lookout add     -config lookout.json FILE... a signed message, a guard, a policy, or a Tested
//	repairer-lookout match   -config lookout.json -ubuntu CVE.json... [-debian TRACKER.json -cve ID...] [-kev KEV.json]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gnosecurity/repairer/lookout"
	"github.com/gnosecurity/repairer/lookout/page"
	"github.com/gnosecurity/repairer/policy"
)

const usage = `usage: repairer-lookout <collect|deliver|run|serve|feeds|add|match> -config lookout.json [args]

  collect          fetch every machine's signed report (ssh, the report key), keep the newest that verifies
  deliver          carry each machine its bundle (ssh, the intake key)
  run              collect and deliver every minute until stopped
  serve            run, and serve the page on -listen (127.0.0.1:8794; put TLS in front): sign in with
                   Adena as one of -admin (Jae's g1ecsu... by default)
  feeds            fetch the flaw feeds once, with a deadline, and match them against the reports kept:
                   run it hourly from its own timer, as its own user (write access to <state>/feeds
                   only), so a slow or hostile feed holds up no delivery and is parsed apart
  add FILE...      keep a message from repairer-sign, a guard, a policy, or a signed Tested or model yes
  match            which machines flaws reach: -ubuntu CVE.json (repeat), -debian TRACKER.json with -cve ID
                   (repeat), -kev KEV.json
`

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1], os.Args[2:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "repairer-lookout:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	configFile := fs.String("config", "", "the lookout's config")
	var ubuntu, cves multi
	fs.Var(&ubuntu, "ubuntu", "match: an Ubuntu per-CVE record (ubuntu.com/security/cves/ID.json); repeat")
	fs.Var(&cves, "cve", "match: a flaw to look up in Debian's tracker; repeat")
	debian := fs.String("debian", "", "match: Debian's tracker JSON")
	kevFile := fs.String("kev", "", "match: CISA's known exploited list")
	listen := fs.String("listen", "127.0.0.1:8794", "serve: where the page listens; TLS goes in front")
	admins := fs.String("admin", page.DefaultAdmin, "serve: comma-separated g1 addresses whose Adena signature opens the page")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configFile == "" {
		fs.Usage()
		return errors.New("needs -config")
	}
	c, err := lookout.ReadConfig(*configFile)
	if err != nil {
		return err
	}
	pb, err := os.ReadFile(c.Policy)
	if err != nil {
		return err
	}
	p, err := policy.Parse(pb)
	if err != nil {
		return fmt.Errorf("%s: %w", c.Policy, err)
	}
	report := lookout.SSH{Key: c.ReportKey, KnownHosts: c.KnownHosts}
	intake := lookout.SSH{Key: c.IntakeKey, KnownHosts: c.KnownHosts}
	col := &lookout.Collector{Policy: p, Dir: filepath.Join(c.State, "reports"), Now: time.Now,
		Fetch: func(ctx context.Context, host string) ([]byte, error) {
			target, ok := c.Hosts[host]
			if !ok {
				return nil, errors.New("no address in the config")
			}
			return report.Run(ctx, target, nil)
		}}
	store := &lookout.Store{Dir: filepath.Join(c.State, "store")}
	feeds := &lookout.Feeds{Dir: filepath.Join(c.State, "feeds"), Fetcher: &lookout.Fetcher{Dir: filepath.Join(c.State, "feeds", "copies")},
		Tracker: &lookout.UbuntuTracker{Dir: filepath.Join(c.State, "feeds", "ubuntu-cve-tracker.git")},
		Kernel:  &lookout.KernelVulns{Dir: filepath.Join(c.State, "feeds", "kernel-vulns.git")}}
	var lastFeeds time.Time
	// feedProblems says, once an hour, what is wrong with the feeds: the
	// feeds command fetches them, apart from the delivery loop (round 8,
	// minor 8), and a feed a day old is an alert.
	feedProblems := func() {
		if time.Since(lastFeeds) < time.Hour {
			return
		}
		lastFeeds = time.Now()
		for _, pr := range feeds.Problems(time.Now()) {
			fmt.Fprintf(stdout, "ALERT feeds: %s\n", pr)
		}
	}

	collect := func() []lookout.HostStatus {
		sts := col.Collect(ctx)
		for _, st := range sts {
			line := fmt.Sprintf("%-16s report %d at %s", st.Host, st.Seq, st.Time.Format(time.RFC3339))
			if st.Silent {
				line += "  SILENT"
			}
			if st.Error != "" {
				line += "  (" + st.Error + ")"
			}
			fmt.Fprintln(stdout, line)
		}
		return sts
	}
	deliver := func(sts []lookout.HostStatus) {
		for _, st := range sts {
			target, ok := c.Hosts[st.Host]
			if !ok || st.Report == nil {
				continue
			}
			b, err := store.Bundle(st.Host, sts, p)
			if err == nil {
				_, err = intake.Run(ctx, target, b)
			}
			if err != nil {
				fmt.Fprintf(stdout, "%-16s not delivered: %v\n", st.Host, err)
				continue
			}
			fmt.Fprintf(stdout, "%-16s delivered %d bytes\n", st.Host, len(b))
		}
	}

	switch cmd {
	case "collect":
		collect()
		return nil
	case "deliver":
		deliver(col.Collect(ctx))
		return nil
	case "run", "serve":
		if cmd == "serve" {
			pg, err := page.New(filepath.Join(c.State, "page"), strings.Split(*admins, ","), p, col, store, time.Now)
			if err != nil {
				return err
			}
			pg.Feeds = feeds
			srv := &http.Server{Addr: *listen, Handler: pg.Handler(), ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout: time.Minute, WriteTimeout: time.Minute, MaxHeaderBytes: 64 << 10}
			go func() {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Printf("page: %v", err)
				}
			}()
			defer srv.Close()
		}
		for {
			sts := collect()
			deliver(sts)
			feedProblems()
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Minute):
			}
		}
	case "feeds":
		// Every request is the same whatever the fleet runs: whole feeds,
		// and every changed OSV record.
		fctx, cancel := context.WithTimeout(ctx, lookout.FeedDeadline)
		defer cancel()
		for _, err := range feeds.Refresh(fctx) {
			fmt.Fprintf(stdout, "feeds: %v\n", err)
		}
		ms := lookout.Machines(col.Kept())
		fs, err := feeds.Find(ms, feeds.Watch(store, ms), time.Now())
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "feeds: %d findings leave a machine exposed\n", len(fs))
		news, err := feeds.KernelNew(fctx, time.Now())
		if err != nil {
			fmt.Fprintf(stdout, "feeds: the kernel's new flaws: %v\n", err)
		}
		for _, k := range news {
			fmt.Fprintf(stdout, "kernel: %s %s (network; %s; fixed in %s)\n", k.ID, k.Title, strings.Join(k.Files, " "), fixes(k))
		}
		for _, pr := range feeds.Problems(time.Now()) {
			fmt.Fprintf(stdout, "ALERT feeds: %s\n", pr)
		}
		return nil
	case "add":
		for _, f := range fs.Args() {
			b, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			what, err := store.AddFile(b)
			if err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			fmt.Fprintf(stdout, "%s: %s\n", f, what)
		}
		return nil
	case "match":
		return match(stdout, col.Collect(ctx), ubuntu, *debian, cves, *kevFile)
	}
	fs.Usage()
	return fmt.Errorf("unknown command %q", cmd)
}

func match(stdout io.Writer, sts []lookout.HostStatus, ubuntu []string, debian string, cves []string, kevFile string) error {
	ms := lookout.Machines(sts)
	now := time.Now()
	var all []lookout.Finding
	for _, f := range ubuntu {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		c, err := lookout.ParseUbuntuCVE(b)
		if err != nil {
			return err
		}
		all = append(all, c.Match(ms, now)...)
	}
	if debian != "" {
		f, err := os.Open(debian)
		if err != nil {
			return err
		}
		want := map[string]bool{}
		for _, c := range cves {
			want[c] = true
		}
		d, err := lookout.ReadDebianTracker(f, want)
		f.Close()
		if err != nil {
			return err
		}
		all = append(all, d.Match(ms, now)...)
	}
	if kevFile != "" {
		b, err := os.ReadFile(kevFile)
		if err != nil {
			return err
		}
		k, err := lookout.ParseKEV(b)
		if err != nil {
			return err
		}
		k.Mark(all)
	}
	lookout.SortFindings(all)
	fmt.Fprint(stdout, lookout.Summary(all))
	return nil
}

// fixes lists the releases that fix a kernel flaw, by series, then
// mainline's.
func fixes(k *lookout.KernelCVE) string {
	var out []string
	for s, v := range k.Fixed {
		out = append(out, s+":"+v)
	}
	sort.Strings(out)
	if k.Mainline != "" {
		out = append(out, "mainline:"+k.Mainline)
	}
	if len(out) == 0 {
		return "nothing yet"
	}
	return strings.Join(out, " ")
}
