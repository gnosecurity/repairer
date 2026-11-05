package guards

import (
	"strconv"
	"strings"

	"gno.land/p/nt/avl/v0"
)

// The realm's pages, on gno.land and as gno.security's source (H1). The
// site's generator turns them into static pages, so they use only a small
// part of Markdown: headings, bullet lines, fenced blocks, `code` and links
// to other pages of the realm. Paths:
//
//	""                the filings, newest first
//	"filing/<id>"     one filing: its guard, transcripts, panel and vote
//	"guard/<hash>"    the newest filing of a guard
//	"address/<g1…>"   an address's public record (rule 7)
var (
	texts   = avl.NewTree() // guard hash → the guard, as revealed (without its final newline)
	byGuard = avl.NewTree() // guard hash → its newest filing
)

// maxListed is how many filings the index lists.
const maxListed = 100

func keepGuard(id int, hash, text string) {
	texts.Set(hash, text)
	byGuard.Set(hash, id)
}

// Render is the realm's page at path.
func Render(path string) string {
	switch {
	case path == "":
		return renderIndex()
	case strings.HasPrefix(path, "filing/"):
		id, err := strconv.Atoi(strings.TrimPrefix(path, "filing/"))
		if err != nil || id < 0 || id >= nFilings {
			return "# Not found\n\nNo such filing.\n"
		}
		return renderFiling(id)
	case strings.HasPrefix(path, "guard/"):
		h := strings.TrimPrefix(path, "guard/")
		v := byGuard.Get(h)
		if !isHex(h, 64) || v == nil {
			return "# Not found\n\nNo filing of that guard.\n"
		}
		return renderFiling(v.(int))
	case strings.HasPrefix(path, "address/"):
		return renderAddress(address(strings.TrimPrefix(path, "address/")))
	}
	return "# Not found\n"
}

func renderIndex() string {
	var b strings.Builder
	b.WriteString("# Guards\n\n")
	b.WriteString(strconv.Itoa(nFilings) + " filings, " + strconv.Itoa(nTickets) + " tickets. The dispute fund holds " +
		strconv.FormatInt(fund, 10) + " ugnot.\n\n## Filings, newest first\n\n")
	for id := nFilings - 1; id >= 0 && id >= nFilings-maxListed; id-- {
		f := get(id)
		line := "- [filing " + strconv.Itoa(id) + "](filing/" + strconv.Itoa(id) + "): " + f.state
		if f.guardHash != "" {
			line += ", guard `" + f.guardHash[:16] + "`"
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func renderFiling(id int) string {
	f := get(id)
	var b strings.Builder
	b.WriteString("# Filing " + strconv.Itoa(id) + "\n\n")
	b.WriteString("- State: " + f.state + "\n")
	b.WriteString("- Filed by " + link(f.filer) + " at height " + strconv.FormatInt(f.committed, 10) + "\n")
	if f.guardHash != "" {
		b.WriteString("- Guard: `" + f.guardHash + "`\n")
		lvl := Level(f.guardHash)
		if lvl == "" {
			lvl = "none"
		}
		b.WriteString("- Level, as the param lvl_" + f.guardHash[:16] + "… proves: " + lvl + "\n")
	}
	if f.round != 0 {
		b.WriteString("- Beacon round: " + strconv.FormatUint(f.round, 10) + " (drand evmnet)\n")
	}
	if f.reruns > 0 {
		b.WriteString("- Reruns: " + strconv.Itoa(f.reruns) + "\n")
	}
	if v := texts.Get(f.guardHash); v != nil && f.guardHash != "" {
		b.WriteString("\n## The guard\n\n" + fenced(v.(string)))
	}
	if len(f.checks) > 0 {
		b.WriteString("\n## Transcripts\n\n")
		for i, c := range f.checks {
			who := "checker"
			if i == 0 {
				who = "worker"
			}
			b.WriteString("- " + who + " " + link(c.owner) + ": " + shown(c) + "\n")
		}
	}
	if len(f.panel) > 0 {
		size := 0
		if f.panelLevel < len(PanelSizes) {
			size = PanelSizes[f.panelLevel]
		}
		b.WriteString("\n## Panel of " + strconv.Itoa(size) + "\n\n")
		for _, c := range f.panel {
			b.WriteString("- " + link(c.owner) + ": " + shown(c) + "\n")
		}
	}
	if pv := votes[id]; pv != nil {
		var revealed int64
		for _, a := range pv.order {
			if pv.voters[a].revealed {
				revealed += pv.voters[a].stake
			}
		}
		b.WriteString("\n## The pool's vote\n\n- Opened at height " + strconv.FormatInt(pv.open, 10) + "; " +
			strconv.Itoa(len(pv.order)) + " voters, " + strconv.FormatInt(revealed, 10) + " of " + strconv.FormatInt(pv.total, 10) + " ugnot of stake revealed\n")
	}
	return b.String()
}

// shown is a transcript as the page shows it: opened, sealed, or not in.
func shown(c *check) string {
	switch {
	case c.revealed:
		return "`" + c.transcript + "`"
	case c.commitment != "":
		return "committed, not yet opened"
	case c.prev != "":
		return "`" + c.prev + "` (the run before)"
	}
	return "not yet committed"
}

func renderAddress(a address) string {
	if !a.IsValid() {
		return "# Not found\n\nNot an address.\n"
	}
	r := RecordOf(a)
	return "# " + string(a) + "\n\n" +
		"- Filings tested: " + strconv.Itoa(r.Passed) + "\n" +
		"- Filings every account failed: " + strconv.Itoa(r.Failed) + "\n" +
		"- Filings lost for silence: " + strconv.Itoa(r.Forfeited) + "\n" +
		"- Checks answered: " + strconv.Itoa(r.Checked) + "\n" +
		"- Draws or votes left unanswered: " + strconv.Itoa(r.Silent) + "\n" +
		"- Disputes decided against it: " + strconv.Itoa(r.Faults) + "\n"
}

func link(a address) string { return "[" + string(a) + "](address/" + string(a) + ")" }

// fenced puts text in a fenced block whose fence is longer than any run of
// backticks in it, so a guard's text can't close the block and become page.
func fenced(text string) string {
	run, longest := 0, 0
	for i := 0; i < len(text); i++ {
		if text[i] == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", max3(longest+1))
	return fence + "\n" + text + "\n" + fence + "\n"
}

func max3(n int) int {
	if n < 3 {
		return 3
	}
	return n
}
