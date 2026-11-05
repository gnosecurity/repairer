// Command autopatch-lookout is the watcher: it collects each machine's
// signed report, carries signed messages to the machines, and says which
// machines a flaw reaches. It holds no key an agent trusts; it can't sign
// anything, log in as root, or change a machine.
//
//	autopatch-lookout collect -config lookout.json
//	autopatch-lookout deliver -config lookout.json
//	autopatch-lookout run     -config lookout.json         collect and deliver every minute
//	autopatch-lookout add     -config lookout.json FILE... a signed message, a guard, a policy, or a Tested
//	autopatch-lookout match   -config lookout.json -ubuntu CVE.json... [-debian TRACKER.json -cve ID...] [-kev KEV.json]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/jaekwon/autopatch/lookout"
	"github.com/jaekwon/autopatch/policy"
)

const usage = `usage: autopatch-lookout <collect|deliver|run|add|match> -config lookout.json [args]

  collect          fetch every machine's signed report (ssh, the report key), keep the newest that verifies
  deliver          carry each machine its bundle (ssh, the intake key)
  run              collect and deliver every minute until stopped
  add FILE...      keep a message from autopatch-sign, a guard, a policy, or a signed Tested or model yes
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
		fmt.Fprintln(os.Stderr, "autopatch-lookout:", err)
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
	case "run":
		for {
			deliver(collect())
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Minute):
			}
		}
	case "add":
		for _, f := range fs.Args() {
			b, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			what, err := add(store, b)
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

// add keeps a file by what it is.
func add(store *lookout.Store, b []byte) (string, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return "", err
	}
	switch {
	case probe["seq"] != nil && probe["tx"] != nil:
		seq, err := store.AddMessage(b)
		return fmt.Sprintf("the owner's statement %d", seq), err
	case probe["statement"] != nil:
		return "a signed statement", store.AddSigned(b)
	case probe["blocks"] != nil:
		h, err := store.AddGuard(b)
		return "guard " + h, err
	case probe["tiers"] != nil:
		h, err := store.AddPolicy(b)
		return "policy " + h, err
	}
	return "", errors.New("not a message, a signed statement, a guard or a policy")
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
