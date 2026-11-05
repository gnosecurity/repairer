// Package guards is the Guards realm (AUTOPATCH.md, "A swarm that holds when
// agents lie"), version 1 with the public draw:
//
//   - Checkers stake tickets. A ticket can be drawn only into filings
//     committed MinTicketAge blocks or more after it was staked, so names made
//     for one attack can't check it.
//   - A worker commits a filing with a bond: sha256 of its address, the
//     guard's hash, its rig transcript's own commitment and a salt, so nobody
//     can copy the filing from the mempool and claim it.
//   - The reveal puts the guard on chain (at most 4,000 bytes, in an event)
//     and fixes the drand evmnet round that will draw its checkers: DrawDelay
//     rounds after the reveal's time. Nobody can see the draw before
//     revealing, or pick a round that suits them.
//   - Three checkers are drawn in proportion to stake, distinct owners, never
//     the filer. They commit their transcripts, and once all are in, every
//     transcript is opened, the worker's too.
//   - A transcript is opened as its hash and its verdict, "<hash> pass" or
//     "<hash> fail". Every transcript matches, passing: the guard is
//     "tested", written to the param lvl_<hash> that light clients prove.
//     Matching but failing: "failed", with no level. Either way each checker
//     is paid CheckFee from the bond, FundFee goes to the dispute fund, and
//     the rest goes back. One differs: a dispute (dispute.gno), with the
//     bond and the drawn tickets held until it is decided.
//   - A drawn checker who stays silent is fined NoShowFine and replaced from a
//     later round. A worker who stays silent loses its bond: the checkers who
//     answered are paid from it and the rest is locked here for good (a realm
//     can't destroy GNOT).
package guards

import (
	"chain"
	"chain/banker"
	"chain/params"
	"chain/runtime"
	"chain/runtime/unsafe"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"gno.land/p/autopatch/drandbn254"
	"gno.land/p/nt/avl/v0"
)

// The numbers to start with (AUTOPATCH.md, "Numbers to start with"). They
// are vars so tests can scale the windows down.
var (
	MinTicketAge int64 = 49000      // blocks between staking a ticket and a filing it may check (~2 days)
	RevealWindow int64 = 100        // blocks to open a commitment
	CheckWindow  int64 = 1000       // blocks for drawn checkers to commit
	UnbondBlocks int64 = 49000      // blocks between Unstake and Withdraw
	Checkers           = 3          // drawn per filing
	MinTicket    int64 = 10_000_000 // ugnot; a checker's stake is at least 10 times what checking pays
	CheckFee     int64 = 100_000    // ugnot, paid to each checker from the filing's bond
	FilingBond   int64 = 1_000_000  // ugnot, at least Checkers × CheckFee
	NoShowFine   int64 = 1_000_000  // ugnot, taken from a drawn ticket that stays silent
	DrawDelay    int64 = 20         // beacon rounds between a reveal's time and its draw (60 seconds)
	MaxGuard           = 4000       // bytes of a guard on chain (events cap at 4,096)
)

// drand evmnet (api.drand.sh/04f1e9062b8a81f848fded9c12306733282b2727ecced50032187751166ec8c3/info).
var (
	drandGenesis int64 = 1727521075
	drandPeriod  int64 = 3
	drandPub           = mustHex("07e1d1d335df83fa98462005690372c643340060d205306a9aa8106b6bd0b3820557ec32c2ad488e4d4f6008f89a346f18492092ccc0d594610de2732c8b808f0095685ae3a85ba243747b1b2f426049010f6b73a0cf1d389351d5aaaa1047f6297d3a4f9749b33eb2d904c9d9ebf17224150ddd7abd7567a9bec6c74480ee0b")
)

// States of a filing.
const (
	Committed = "committed" // waiting for the worker's reveal
	Revealed  = "revealed"  // waiting for its beacon round and the draw
	Drawn     = "drawn"     // the checkers' commitments and reveals
	Rerun     = "rerun"     // transcripts differed: the same parties run it again
	Panel     = "panel"     // waiting for a panel's beacon round and the dispute fund
	Panelled  = "panelled"  // a panel's commitments and reveals
	Pool      = "pool"      // no panel reached two thirds: the whole pool votes (F3)
	Tested    = "tested"
	Failed    = "failed"    // every transcript, or the deciding side, says the guard fails the rig
	Forfeited = "forfeited" // the worker went silent
	Abandoned = "abandoned" // too few staked checkers to draw; the bond went back
)

type ticket struct {
	id      int
	owner   address
	stake   int64
	height  int64 // staked at
	leaving int64 // Unstake's height; 0 while staked
	open    int   // unsettled filings it is drawn into
}

type check struct {
	ticket     int // -1 for the worker's own transcript
	owner      address
	commitment string
	transcript string
	revealed   bool
	prev       string // the transcript revealed in the run before this one
}

type filing struct {
	filer      address
	commitment string
	committed  int64 // height
	bond       int64
	state      string
	guardHash  string
	round      uint64 // the beacon round that draws it
	draws      int
	drawnAt    int64
	allIn      int64            // height the last drawn checker committed; 0 before
	checks     []*check         // [0] is the worker's transcript
	silent     map[address]bool // owners fined for silence on it, never drawn into it again
	// A dispute (dispute.gno): reruns by the same parties, then panels.
	reruns     int
	panelLevel int              // which of PanelSizes the next or current panel is
	panel      []*check         // the current panel
	served     map[address]bool // every panel's members, never drawn into it again
	reserve    int64            // the current panel's fees, taken from the dispute fund
	panelCost  int64            // what every panel of this dispute was paid
}

// Record is an address's public record (rule 7).
type Record struct {
	Passed    int // its filings tested
	Failed    int // its filings every transcript failed
	Forfeited int // its filings lost for silence
	Checked   int // checks it answered that settled
	Silent    int // draws it never answered
	Faults    int // times a dispute decided against what it said
}

var (
	tickets  = avl.NewTree() // key(id) → *ticket
	nTickets int
	filings  = avl.NewTree() // key(id) → *filing
	nFilings int
	levels   = avl.NewTree() // guard hash → level
	records  = avl.NewTree() // address → *Record
	beacon   = avl.NewTree() // key(round) → signature
	burned   int64           // forfeits, fines and slashes, locked here for good
	fund     int64           // the dispute fund: pays panels; disputes wait when it is short
)

// Commitment is what a filing or a check commits: sha256 of who, what kind,
// the payload and a salt, so nobody can copy it and claim the work.
func Commitment(who address, kind, payload, salt string) string {
	sum := sha256.Sum256([]byte(string(who) + "\x00" + kind + "\x00" + payload + "\x00" + salt))
	return hex.EncodeToString(sum[:])
}

// GuardHash is the hash a guard is known by: sha256 of its bytes without the
// final newline, as the agent names files.
func GuardHash(guard string) string {
	sum := sha256.Sum256([]byte(strings.TrimSuffix(guard, "\n")))
	return hex.EncodeToString(sum[:])
}

// StakeTicket stakes the coins sent as one checker's ticket and returns its
// number.
func StakeTicket(cur realm) int {
	t := &ticket{id: nTickets, owner: caller(cur), stake: received(MinTicket), height: now()}
	nTickets++
	tickets.Set(key(uint64(t.id)), t)
	chain.Emit("TicketStaked", "ticket", strconv.Itoa(t.id), "owner", string(t.owner), "stake", strconv.FormatInt(t.stake, 10))
	return t.id
}

// Unstake stops a ticket being drawn. Withdraw returns its stake UnbondBlocks
// later, once every check it was drawn into has settled.
func Unstake(cur realm, id int) {
	t := ownTicket(cur, id)
	if t.leaving != 0 {
		panic("guards: already unstaking")
	}
	t.leaving = now()
}

// Withdraw returns an unstaked ticket's stake.
func Withdraw(cur realm, id int) {
	t := ownTicket(cur, id)
	switch {
	case t.leaving == 0:
		panic("guards: unstake first")
	case now() < t.leaving+UnbondBlocks:
		panic("guards: still unbonding")
	case t.open > 0:
		panic("guards: drawn into a check that hasn't settled")
	case t.stake == 0:
		panic("guards: nothing left to withdraw")
	}
	n := t.stake
	t.stake = 0
	pay(cur, t.owner, n)
}

// Commit files a guard's commitment, with the coins sent as its bond:
// Commitment(filer, "guard", GuardHash(guard)+"\x00"+transcriptCommitment,
// salt), where transcriptCommitment is Commitment(filer, "transcript",
// transcript, salt2).
func Commit(cur realm, commitment string) int {
	if !isHex(commitment, 64) {
		panic("guards: a commitment is 64 hex digits")
	}
	if int64(Checkers)*CheckFee+FundFee > FilingBond {
		panic("guards: the bond can't pay its checkers and the dispute fund")
	}
	f := &filing{filer: caller(cur), commitment: commitment, committed: now(), bond: received(FilingBond), state: Committed,
		silent: map[address]bool{}, served: map[address]bool{}}
	id := nFilings
	nFilings++
	filings.Set(key(uint64(id)), f)
	chain.Emit("GuardCommitted", "filing", strconv.Itoa(id), "filer", string(f.filer))
	return id
}

// Reveal opens a filing within RevealWindow: the guard itself, and its
// transcript's commitment (the transcript is opened with the checkers').
// It fixes the beacon round that will draw the checkers.
func Reveal(cur realm, id int, guard, transcriptCommitment, salt string) {
	f := get(id)
	who := caller(cur)
	h := GuardHash(guard)
	switch {
	case f.state != Committed:
		panic("guards: not waiting for a reveal")
	case who != f.filer:
		panic("guards: only the filer reveals")
	case now() > f.committed+RevealWindow:
		panic("guards: the reveal window has passed")
	case len(guard) > MaxGuard:
		panic("guards: a guard is at most " + strconv.Itoa(MaxGuard) + " bytes")
	case !isHex(transcriptCommitment, 64):
		panic("guards: a commitment is 64 hex digits")
	case Commitment(who, "guard", h+"\x00"+transcriptCommitment, salt) != f.commitment:
		panic("guards: that isn't what was committed")
	}
	f.guardHash = h
	f.checks = []*check{{ticket: -1, owner: who, commitment: transcriptCommitment}}
	f.state, f.round = Revealed, drawRound()
	chain.Emit("GuardRevealed", "filing", strconv.Itoa(id), "hash", h, "round", strconv.FormatUint(f.round, 10), "guard", strings.TrimSuffix(guard, "\n"))
}

// Forfeit locks the bond of a filing not revealed in time.
func Forfeit(cur realm, id int) {
	caller(cur)
	f := get(id)
	if f.state != Committed || now() <= f.committed+RevealWindow {
		panic("guards: nothing to forfeit")
	}
	burned += f.bond
	f.bond, f.state = 0, Forfeited
	rec(f.filer).Forfeited++
	chain.Emit("GuardForfeited", "filing", strconv.Itoa(id))
}

// SubmitBeacon records a drand evmnet round, checked against the network's
// key in gno (about 85M gas). Anyone may submit one.
func SubmitBeacon(cur realm, round uint64, sigHex string) {
	caller(cur)
	sig := mustHex(sigHex)
	if !drandbn254.Verify(drandPub, round, sig) {
		panic("guards: that isn't drand evmnet's signature for round " + strconv.FormatUint(round, 10))
	}
	beacon.Set(key(round), sig)
}

// Draw draws a revealed filing's checkers from its beacon round, in
// proportion to stake: tickets staked MinTicketAge blocks before the filing,
// not leaving, one per owner, never the filer's or one already on it, and
// none whose owner went silent on it. Anyone may call it once the round is
// submitted.
func Draw(cur realm, id int) {
	caller(cur)
	f := get(id)
	if f.state != Revealed {
		panic("guards: not waiting for a draw")
	}
	v := beacon.Get(key(f.round))
	if v == nil {
		panic("guards: submit beacon round " + strconv.FormatUint(f.round, 10) + " first")
	}
	picks := pick(v.([]byte), "draw", id, f.draws, Checkers-(len(f.checks)-1), f)
	if picks == nil {
		panic("guards: too few staked checkers for this filing")
	}
	for _, p := range picks {
		p.open++
		f.checks = append(f.checks, &check{ticket: p.id, owner: p.owner})
	}
	f.draws++
	f.drawnAt, f.allIn, f.state = now(), 0, Drawn
	chain.Emit("GuardDrawn", "filing", strconv.Itoa(id), "round", strconv.FormatUint(f.round, 10), "checkers", strings.Join(owners(f), ","))
}

// CommitCheck commits a transcript in the run under way:
// Commitment(who, "check", transcript, salt), or "transcript" for the
// worker. The drawn checkers commit after the draw; in a rerun the worker
// and the checkers commit again; in a panel, its members.
func CommitCheck(cur realm, id int, commitment string) {
	who := caller(cur)
	f := get(id)
	if !running(f) || now() > f.drawnAt+CheckWindow {
		panic("guards: not taking checks")
	}
	if !isHex(commitment, 64) {
		panic("guards: a commitment is 64 hex digits")
	}
	ch := findIn(committers(f), who)
	if ch.commitment != "" {
		panic("guards: already committed")
	}
	ch.commitment = commitment
	for _, c := range committers(f) {
		if c.commitment == "" {
			return
		}
	}
	f.allIn = now()
}

// RevealCheck opens a transcript once every commitment of the run is in,
// so nobody can wait to see which way the others went: "<64-hex hash of the
// rig's transcript> pass|fail".
func RevealCheck(cur realm, id int, transcript, salt string) {
	who := caller(cur)
	f := get(id)
	switch {
	case !running(f) || f.allIn == 0:
		panic("guards: wait until every drawn checker has committed")
	case now() > f.allIn+RevealWindow:
		panic("guards: the reveal window has passed")
	case verdict(transcript) == "":
		panic("guards: a transcript is its 64-hex hash and pass or fail")
	}
	ch := findIn(revealers(f), who)
	if ch.revealed {
		panic("guards: already revealed")
	}
	if Commitment(who, kindOf(ch), transcript, salt) != ch.commitment {
		panic("guards: that isn't what was committed")
	}
	ch.transcript, ch.revealed = transcript, true
}

// running says whether a run of commitments and reveals is under way.
func running(f *filing) bool { return f.state == Drawn || f.state == Rerun || f.state == Panelled }

// committers are who commits in the run under way; revealers, who reveals.
func committers(f *filing) []*check {
	switch f.state {
	case Drawn:
		return f.checks[1:] // the worker's commitment came with its reveal
	case Panelled:
		return f.panel
	}
	return f.checks
}

func revealers(f *filing) []*check {
	if f.state == Panelled {
		return f.panel
	}
	return f.checks
}

func findIn(cs []*check, who address) *check {
	for _, c := range cs {
		if c.owner == who {
			return c
		}
	}
	panic("guards: you weren't drawn for this filing")
}

func kindOf(c *check) string {
	if c.ticket < 0 {
		return "transcript"
	}
	return "check"
}

// Settle moves a filing's run on once it can (a rerun's and a panel's in
// dispute.gno). After the draw:
//   - drawn checkers who never committed, once CheckWindow passed, are
//     fined and replaced from a later round;
//   - once every transcript is open: all match, the guard is tested (or
//     failed) and everyone is paid; one differs, a dispute begins;
//   - once RevealWindow passed with transcripts still shut: a silent worker
//     forfeits its bond; silent checkers are fined, and replaced unless the
//     open transcripts already differ.
func Settle(cur realm, id int) string {
	caller(cur)
	f := get(id)
	switch f.state {
	case Rerun:
		return settleRerun(cur, f, id)
	case Panelled:
		return settlePanel(cur, f, id)
	case Drawn:
	default:
		panic("guards: nothing to settle")
	}
	if f.allIn == 0 {
		if now() <= f.drawnAt+CheckWindow {
			panic("guards: still waiting for commitments")
		}
		dropSilent(f, func(c *check) bool { return c.commitment == "" })
		return redraw(f, id)
	}
	all, match := agreement(f.checks)
	if !all {
		if now() <= f.allIn+RevealWindow {
			panic("guards: still waiting for reveals")
		}
		if !f.checks[0].revealed {
			return workerSilent(cur, f, id)
		}
		dropSilent(f, func(c *check) bool { return !c.revealed })
		if match {
			return redraw(f, id)
		}
	}
	if !match {
		return dispute(f, id) // the bond and the drawn tickets stay held
	}
	return settleAgreed(cur, f, id)
}

// agreement says whether every transcript is open, and whether the open
// ones are all the same.
func agreement(cs []*check) (all, match bool) {
	all, match = true, true
	first := ""
	for _, c := range cs {
		switch {
		case !c.revealed:
			all = false
		case first == "":
			first = c.transcript
		case c.transcript != first:
			match = false
		}
	}
	return all, match
}

// workerSilent: the worker didn't open its transcript. The checkers who
// answered are paid from its bond, and the rest is locked here for good.
func workerSilent(cur realm, f *filing, id int) string {
	bond := f.bond
	for _, c := range f.checks[1:] {
		if c.revealed || c.prev != "" {
			pay(cur, c.owner, CheckFee)
			bond -= CheckFee
			release(c)
		} else {
			fine(f, c)
		}
	}
	burned += bond
	f.bond, f.state = 0, Forfeited
	rec(f.filer).Forfeited++
	chain.Emit("GuardForfeited", "filing", strconv.Itoa(id))
	return f.state
}

// settleAgreed: every party's transcript is the same. Passing, the guard is
// tested; failing, failed with no level. Each checker is paid, the fund
// takes FundFee, and the rest of the bond goes back.
func settleAgreed(cur realm, f *filing, id int) string {
	f.state = Tested
	if verdict(f.checks[0].transcript) == "fail" {
		f.state = Failed // the rig fails it, by every account: no level
	} else {
		levels.Set(f.guardHash, Tested)
		params.SetString("lvl_"+f.guardHash, Tested)
	}
	bond := f.bond - FundFee
	fund += FundFee
	for _, c := range f.checks[1:] {
		pay(cur, c.owner, CheckFee)
		bond -= CheckFee
		release(c)
		rec(c.owner).Checked++
	}
	pay(cur, f.filer, bond)
	f.bond = 0
	if f.state == Failed {
		rec(f.filer).Failed++
		chain.Emit("GuardFailed", "filing", strconv.Itoa(id), "hash", f.guardHash)
		return f.state
	}
	rec(f.filer).Passed++
	chain.Emit("GuardTested", "filing", strconv.Itoa(id), "hash", f.guardHash)
	return f.state
}

// Abandon returns the bond of a revealed filing that can never be drawn:
// fewer distinct owners are eligible than it still needs, and eligibility
// only shrinks. Checkers kept from an earlier draw are paid.
func Abandon(cur realm, id int) {
	who := caller(cur)
	f := get(id)
	switch {
	case who != f.filer:
		panic("guards: only the filer abandons")
	case f.state != Revealed:
		panic("guards: not waiting for a draw")
	}
	pool, _ := eligible(f)
	distinct := map[address]bool{}
	for _, e := range pool {
		distinct[e.t.owner] = true
	}
	if len(distinct) >= Checkers-(len(f.checks)-1) {
		panic("guards: it can still be drawn")
	}
	bond := f.bond
	for _, c := range f.checks[1:] {
		pay(cur, c.owner, CheckFee)
		bond -= CheckFee
		release(c)
	}
	pay(cur, f.filer, bond)
	f.bond, f.state = 0, Abandoned
	chain.Emit("GuardAbandoned", "filing", strconv.Itoa(id))
}

// Level is a guard's level, as the param lvl_<hash> that light clients
// prove holds it: "tested", or "".
func Level(guardHash string) string {
	v, _ := params.GetString("lvl_" + guardHash)
	return v
}

// State says where a filing stands, the beacon round that draws it, and who
// was drawn.
func State(id int) (string, uint64, []address) {
	f := get(id)
	var drawn []address
	for _, c := range f.checks {
		if c.ticket >= 0 {
			drawn = append(drawn, c.owner)
		}
	}
	return f.state, f.round, drawn
}

// TicketOf says a ticket's owner, stake, the unsettled checks it is drawn
// into, and the height it began unstaking (0 while staked).
func TicketOf(id int) (address, int64, int, int64) {
	t := ticketAt(id)
	return t.owner, t.stake, t.open, t.leaving
}

// RecordOf is an address's public record.
func RecordOf(a address) Record {
	if v := records.Get(string(a)); v != nil {
		return *v.(*Record)
	}
	return Record{}
}

// Burned is what forfeits and fines have locked here for good.
func Burned() int64 { return burned }

// Render lists the tested guards.
func Render(path string) string {
	var b strings.Builder
	b.WriteString("# Guards\n\n" + strconv.Itoa(nFilings) + " filings, " + strconv.Itoa(nTickets) + " tickets.\n\n## Tested\n\n")
	levels.Iterate("", "", func(h string, v any) bool {
		b.WriteString("- `" + h + "`\n")
		return false
	})
	return b.String()
}

func caller(cur realm) address {
	if !cur.Previous().IsUserCall() {
		panic("guards: call from your own account")
	}
	return cur.Previous().Address()
}

// received is what the call sent; a user call's send lands here.
func received(min int64) int64 {
	n := unsafe.OriginSend().AmountOf("ugnot")
	if n < min {
		panic("guards: send at least " + strconv.FormatInt(min, 10) + "ugnot")
	}
	return n
}

func pay(cur realm, to address, n int64) {
	if n <= 0 {
		return
	}
	banker.NewBanker(banker.BankerTypeRealmSend, cur).SendCoins(cur.Address(), to, chain.Coins{chain.NewCoin("ugnot", n)})
}

func now() int64 { return runtime.ChainHeight() }

// drawRound is the round DrawDelay rounds after the one in progress now.
func drawRound() uint64 {
	r := int64(1)
	if t := time.Now().Unix(); t > drandGenesis {
		r = (t-drandGenesis)/drandPeriod + 1
	}
	return uint64(r + DrawDelay)
}

func redraw(f *filing, id int) string {
	f.state, f.round, f.allIn = Revealed, drawRound(), 0
	chain.Emit("GuardRedraw", "filing", strconv.Itoa(id), "round", strconv.FormatUint(f.round, 10))
	return f.state
}

func dropSilent(f *filing, silent func(*check) bool) {
	keep := f.checks[:1]
	for _, c := range f.checks[1:] {
		if silent(c) {
			fine(f, c)
		} else {
			keep = append(keep, c)
		}
	}
	f.checks = keep
}

func fine(f *filing, c *check) {
	t := ticketAt(c.ticket)
	n := NoShowFine
	if n > t.stake {
		n = t.stake
	}
	t.stake -= n
	burned += n
	t.open--
	f.silent[c.owner] = true
	rec(c.owner).Silent++
}

func release(c *check) { ticketAt(c.ticket).open-- }

type entry struct {
	t   *ticket
	out bool
}

func eligible(f *filing) ([]*entry, int64) {
	on := map[address]bool{}
	for _, c := range f.checks {
		on[c.owner] = true
	}
	for a := range f.served {
		on[a] = true
	}
	var pool []*entry
	var total int64
	tickets.Iterate("", "", func(_ string, v any) bool {
		t := v.(*ticket)
		if t.leaving == 0 && t.stake > 0 && !on[t.owner] && !f.silent[t.owner] && t.height+MinTicketAge <= f.committed {
			pool = append(pool, &entry{t: t})
			total += t.stake
		}
		return false
	})
	return pool, total
}

// pick draws n tickets from the filing's eligible ones, in proportion to
// stake, one per owner, from a beacon signature and what the draw is for;
// nil when fewer than n distinct owners are eligible. It changes nothing.
func pick(sig []byte, what string, id, nth, n int, f *filing) []*ticket {
	pool, total := eligible(f)
	seed := sha256.Sum256([]byte(string(sig) + "\x00" + what + "\x00" + strconv.Itoa(id) + "\x00" + strconv.Itoa(nth)))
	var picks []*ticket
	for i := 0; len(picks) < n; i++ {
		if total <= 0 {
			return nil
		}
		h := sha256.Sum256(append(seed[:], byte(i), byte(i>>8)))
		var x uint64
		for j := 0; j < 8; j++ {
			x = x<<8 | uint64(h[j])
		}
		x %= uint64(total)
		var p *ticket
		for _, e := range pool {
			if e.out {
				continue
			}
			if x < uint64(e.t.stake) {
				p = e.t
				break
			}
			x -= uint64(e.t.stake)
		}
		for _, e := range pool { // one ticket per owner
			if !e.out && e.t.owner == p.owner {
				e.out = true
				total -= e.t.stake
			}
		}
		picks = append(picks, p)
	}
	return picks
}

func owners(f *filing) []string {
	var out []string
	for _, c := range f.checks[1:] {
		out = append(out, string(c.owner))
	}
	return out
}

func get(id int) *filing {
	v := filings.Get(key(uint64(id)))
	if id < 0 || v == nil {
		panic("guards: no filing " + strconv.Itoa(id))
	}
	return v.(*filing)
}

func ticketAt(id int) *ticket {
	v := tickets.Get(key(uint64(id)))
	if id < 0 || v == nil {
		panic("guards: no ticket " + strconv.Itoa(id))
	}
	return v.(*ticket)
}

func ownTicket(cur realm, id int) *ticket {
	t := ticketAt(id)
	if caller(cur) != t.owner {
		panic("guards: not your ticket")
	}
	return t
}

func rec(a address) *Record {
	if v := records.Get(string(a)); v != nil {
		return v.(*Record)
	}
	r := &Record{}
	records.Set(string(a), r)
	return r
}

// key orders numbers as text.
func key(n uint64) string {
	s := strconv.FormatUint(n, 10)
	return strings.Repeat("0", 20-len(s)) + s
}

// verdict reads a revealed transcript: "pass" or "fail", or "" if it isn't
// "<64-hex hash> pass|fail".
func verdict(transcript string) string {
	h, v, ok := strings.Cut(transcript, " ")
	if !ok || !isHex(h, 64) || (v != "pass" && v != "fail") {
		return ""
	}
	return v
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("guards: not hex")
	}
	return b
}
