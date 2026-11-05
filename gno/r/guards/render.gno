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
		b.WriteString("- System: " + f.system + "\n")
		lvl := Level(f.guardHash, f.system)
		if lvl == "" {
			lvl = "none"
		}
		b.WriteString("- Level on " + f.system + ", as the param " + levelKey(f.guardHash[:16]+"…", f.system) + " proves: " + lvl + "\n")
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
	if f.verdict != "" && (f.state == Agreed || f.state == Appealable) {
		what := "Agreed"
		if f.state == Appealable {
			what = "A panel's word"
		}
		b.WriteString("- " + what + ": `" + f.verdict + "`, final after height " + strconv.FormatInt(f.until, 10) + " unless someone objects or appeals\n")
	}
	if f.floor {
		b.WriteString("- Decided passing while the live stake was under the floor: no level written\n")
	}
	if f.pulled {
		b.WriteString("- Decided passing after its level was pulled: the pull stands; a fixed guard is filed as a new version\n")
	}
	if f.state == Undecided && f.lastWord != "" {
		b.WriteString("- The pool's vote didn't reach two thirds: the last panel's word, `" + f.lastWord + "`, settled the money, and no level was written or pulled\n")
	}
	if o := f.objector; o != nil {
		b.WriteString("- Objected to by " + link(o.owner) + ": `" + o.transcript + "`\n")
	}
	for _, a := range f.appeals {
		b.WriteString("- Appealed by " + link(a.who) + " against `" + a.against + "`\n")
	}
	for i, p := range f.panels {
		size := PanelSizes[least2(i, len(PanelSizes)-1)]
		b.WriteString("\n## Panel " + strconv.Itoa(i+1) + " (of " + strconv.Itoa(size) + " seats)\n\n")
		seats, order := map[address]int{}, []*check{}
		for _, c := range p {
			if seats[c.owner] == 0 {
				order = append(order, c)
			}
			seats[c.owner]++
		}
		for _, c := range order {
			n := ""
			if seats[c.owner] > 1 {
				n = " (" + strconv.Itoa(seats[c.owner]) + " seats)"
			}
			b.WriteString("- " + link(c.owner) + n + ": " + shown(c) + "\n")
		}
	}
	if v := votes[id]; v != nil {
		b.WriteString("\n## The pool's vote\n\n- Opened at height " + strconv.FormatInt(v.open, 10) + "; " +
			strconv.Itoa(v.committed) + " voters committed, " + strconv.FormatInt(v.revealed, 10) + " of " + strconv.FormatInt(v.total, 10) + " ugnot of stake revealed\n")
		if v.closed {
			if v.decided == "" {
				b.WriteString("- Undecided: under two thirds revealed\n")
			} else {
				b.WriteString("- Decided: `" + v.decided + "`\n")
			}
		}
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

func least2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
