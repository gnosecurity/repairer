// Package guards is the Guards realm (AUTOPATCH.md, "A swarm that holds when
// agents lie"), version 1 with the public draw:
//
//   - Checkers stake tickets (tickets.gno). A ticket can be drawn only into
//     filings committed MinTicketAge blocks or more after it was staked, so
//     names made for one attack can't check it.
//   - A worker commits a filing with a bond: sha256 of its address, the
//     guard's hash, the system its rig ran ("ubuntu 24.04"), its transcript's
//     own commitment and a salt, so nobody can copy the filing from the
//     mempool and claim it.
//   - The reveal puts the guard on chain (at most 4,000 bytes) and fixes the
//     drand evmnet round that will draw its checkers, DrawDelay rounds after
//     the reveal's time, and the weight that round draws from: nobody can
//     see the draw before revealing, pick a round, or change the pool after
//     (tickets.gno).
//   - Three checkers are drawn by weight, one per owner, never the filer,
//     by whoever calls Draw, who is paid DrawFee from the bond. A filing
//     whose draw nobody makes by DrawDeadline loses its bond to the fund, so
//     letting a draw lapse re-rolls nothing for free (round 11, minor 6).
//     They commit their transcripts, and once all are in, every transcript
//     is opened, the worker's too, as "<hash> pass" or "<hash> fail".
//   - Every transcript matches: agreed. For ObjectionWindow anyone may
//     object with a bond and another transcript, which opens a dispute;
//     otherwise Finalize ends it: passing, the guard is "tested" on that
//     system (the param lvl_<hash>_<system> light clients prove, written
//     only if the stake of its pool not leaving when the round was fixed,
//     the worker's own included, passed LevelFloor, and never over
//     "pulled");
//     failing, failed, and a level written before is pulled. Each checker is
//     paid CheckFee from the bond, FundFee goes to the dispute fund, and the
//     rest goes back.
//   - One differs: a dispute (dispute.gno), then the pool's vote (pool.gno),
//     with every bond and drawn ticket held until the last word.
//   - A drawn checker who stays silent is fined NoShowFine: before the
//     transcripts open it is replaced from a later round; after, the filing
//     settles with those who answered. A worker who stays silent loses its
//     bond: the checkers who answered are paid from it and the rest is
//     locked here for good (a realm can't destroy GNOT).
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
	u256 "gno.land/p/onbloc/uint256/v0"
)

// The numbers to start with (AUTOPATCH.md, "Numbers to start with"). They
// are vars so tests can scale them down.
var (
	MinTicketAge    int64 = 49000          // blocks between staking a ticket and a filing it may check (~2 days)
	RevealWindow    int64 = 2000           // blocks to open a commitment (~2 hours)
	CheckWindow     int64 = 2000           // blocks for drawn checkers to commit
	DrawDeadline    int64 = 2000           // blocks after a round is fixed for its draw; under UnbondBlocks
	UnbondBlocks    int64 = 49000          // blocks between Unstake and Withdraw
	Checkers              = 3              // drawn per filing
	MinTicket       int64 = 10_000_000     // ugnot; a checker's stake is at least 10 times what checking pays
	CheckFee        int64 = 100_000        // ugnot, paid to each checker from the filing's bond
	FilingBond      int64 = 1_000_000      // ugnot, at least Checkers × CheckFee + FundFee + DrawFee
	DrawFee         int64 = 200_000        // ugnot to whoever draws: a beacon round (~85M gas) and the draw
	NoShowFine      int64 = 1_000_000      // ugnot, taken from a drawn ticket that stays silent, to the fund
	DrawDelay       int64 = 20             // beacon rounds between a reveal's time and its draw (60 seconds)
	MaxGuard              = 4000           // bytes of a guard on chain (events cap at 4,096)
	ObjectionWindow int64 = 2000           // blocks after agreement in which anyone may object
	ObjectionBond   int64 = 1_000_000      // ugnot an objector puts up
	LevelFloor      int64 = 10_000_000_000 // ugnot of a filing's pool's stake not leaving at its fix, below which no level is written
)

// drand evmnet (api.drand.sh/04f1e9062b8a81f848fded9c12306733282b2727ecced50032187751166ec8c3/info).
var (
	drandGenesis int64 = 1727521075
	drandPeriod  int64 = 3
	drandPub           = mustHex("07e1d1d335df83fa98462005690372c643340060d205306a9aa8106b6bd0b3820557ec32c2ad488e4d4f6008f89a346f18492092ccc0d594610de2732c8b808f0095685ae3a85ba243747b1b2f426049010f6b73a0cf1d389351d5aaaa1047f6297d3a4f9749b33eb2d904c9d9ebf17224150ddd7abd7567a9bec6c74480ee0b")
)

// States of a filing.
const (
	Committed  = "committed"  // waiting for the worker's reveal
	Revealed   = "revealed"   // waiting for its beacon round and the draw
	Drawn      = "drawn"      // the checkers' commitments and reveals
	Agreed     = "agreed"     // every transcript matched: the objection window
	Rerun      = "rerun"      // transcripts differed: the same parties run it again
	PanelWait  = "panelwait"  // waiting for the dispute fund to pay the next panel
	Panel      = "panel"      // waiting for a panel's beacon round
	Panelled   = "panelled"   // a panel's commitments and reveals
	Appealable = "appealable" // a panel decided: the appeal window
	Pool       = "pool"       // to the pool's vote (pool.gno)
	Voting     = "voting"     // the pool's vote
	Tested     = "tested"
	Failed     = "failed"    // the guard fails the rig, by agreement or the last word
	Undecided  = "undecided" // the pool's vote found no transcript over a third of its weight with no rival
	Forfeited  = "forfeited" // the worker went silent
	Abandoned  = "abandoned" // never drawn, or never answered; the bond went back
	Pulled     = "pulled"    // a level written and then decided against
)

type check struct {
	ticket     int // -1 for the worker's own transcript, -2 for an objector; a panel's seat otherwise
	owner      address
	commitment string
	transcript string
	revealed   bool
	prev       string   // the transcript revealed in the run before this one
	past       []string // every transcript revealed in earlier runs (round 10, minor 4)
}

type appeal struct {
	who     address
	bond    int64
	against string // the verdict appealed
}

type filing struct {
	filer      address
	commitment string
	committed  int64 // height
	bond       int64
	state      string
	guardHash  string
	system     string // the system its transcripts are for: os-release ID and VERSION_ID
	oldBelow   int    // tickets staked by committed - MinTicketAge: its draws' pool
	round      uint64 // the beacon round that draws it now
	fixedAt    int64  // the height that round was fixed
	leaveMark  int    // leaves when it was fixed: a ticket that began leaving by then isn't drawn
	total      int64  // the weight below oldBelow then, which its draw reads (tickets.gno)
	waiting    bool   // its round waits for a draw: the tree holds still below oldBelow
	floorAt    int64  // its pool's weight not leaving when its first round was fixed, the worker's own included: the level's floor (round 11, minor 7)
	draws      int
	drawnAt    int64
	allIn      int64            // height the last commitment of the run came in; 0 before
	checks     []*check         // [0] is the worker's transcript
	silent     map[address]bool // owners fined for silence on it, never drawn into it again
	verdict    string           // the agreed transcript, or a panel's word, awaiting its window
	until      int64            // when the objection or appeal window closes
	objector   *check           // whoever objected to an agreement, with its transcript
	objBond    int64
	// A dispute (dispute.gno): reruns by the same parties, then panels.
	reruns     int
	panelLevel int        // which of PanelSizes the next or current panel is
	panels     [][]*check // every panel of the dispute, the current last; a check per seat
	reserve    int64      // every panel's fees, set aside from the dispute fund
	panelCost  int64      // what the fund set aside for this dispute (panels and the vote)
	appeals    []appeal
	floor      bool // decided passing with floorAt under LevelFloor: no level written
	pulled     bool // decided passing after its level was pulled: the pull stands
}

// Record is an address's public record (rule 7).
type Record struct {
	Passed    int // its filings tested
	Failed    int // its filings every account failed
	Forfeited int // its filings lost for silence
	Checked   int // checks it answered that settled
	Silent    int // draws or votes it never answered
	Faults    int // times a decision went against what it said
}

var (
	tickets  = avl.NewTree() // key(id) → *ticket
	nTickets int
	filings  = avl.NewTree() // key(id) → *filing
	nFilings int
	levels   = avl.NewTree() // guard hash → level
	records  = avl.NewTree() // address → *Record
	beacon   = avl.NewTree() // key(round) → signature
	burned   int64           // forfeits and what settling a dispute leaves, locked here for good
	fund     int64           // the dispute fund: pays panels and votes, and takes what silence is charged
)

// Commitment is what a filing, a check or a vote commits: sha256 of who,
// what kind, the payload and a salt, so nobody can copy it and claim it.
// A filing's payload is GuardHash(guard), its system and its transcript's
// commitment, each followed by a zero byte but the last.
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

// Commit files a guard's commitment, with the coins sent as its bond:
// Commitment(filer, "guard", GuardHash(guard)+"\x00"+system+"\x00"+
// transcriptCommitment, salt), where transcriptCommitment is
// Commitment(filer, "transcript", transcript, salt2), and system is what the
// rig ran, as its transcript names it ("ubuntu 24.04").
func Commit(cur realm, commitment string) int {
	if !isHex(commitment, 64) {
		panic("guards: a commitment is 64 hex digits")
	}
	if int64(Checkers)*CheckFee+FundFee+DrawFee > FilingBond {
		panic("guards: the bond can't pay its checkers, its draw and the dispute fund")
	}
	f := &filing{filer: caller(cur), commitment: commitment, committed: now(), bond: received(FilingBond), state: Committed,
		silent: map[address]bool{}}
	f.oldBelow = oldBelow(f.committed - MinTicketAge)
	id := nFilings
	nFilings++
	filings.Set(key(uint64(id)), f)
	chain.Emit("GuardCommitted", "filing", strconv.Itoa(id), "filer", string(f.filer))
	return id
}

// Reveal opens a filing within RevealWindow: the guard itself, the system
// its transcripts are for, and its transcript's commitment (the transcript
// is opened with the checkers'). It fixes the beacon round that will draw
// the checkers, and the pool.
func Reveal(cur realm, id int, guard, system, transcriptCommitment, salt string) {
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
	case !isSystem(system):
		panic("guards: a system is its os-release ID and VERSION_ID, such as \"ubuntu 24.04\"")
	case Commitment(who, "guard", h+"\x00"+system+"\x00"+transcriptCommitment, salt) != f.commitment:
		panic("guards: that isn't what was committed")
	}
	f.guardHash, f.system = h, system
	keepGuard(id, h, strings.TrimSuffix(guard, "\n"))
	f.checks = []*check{{ticket: -1, owner: who, commitment: transcriptCommitment}}
	fixRound(f, id)
	sum, left, _, _ := below(f.oldBelow)
	f.floorAt = sum - left
	f.state = Revealed
	chain.Emit("GuardRevealed", "filing", strconv.Itoa(id), "hash", h, "system", system, "round", strconv.FormatUint(f.round, 10), "guard", strings.TrimSuffix(guard, "\n"))
}

// fixRound fixes the beacon round of a filing's next draw, DrawDelay rounds
// after the round in progress, and the weight it draws from, which nothing
// changes while the round waits for its draw (tickets.gno).
func fixRound(f *filing, id int) {
	unwait(f, id)
	r := int64(1)
	if t := time.Now().Unix(); t > drandGenesis {
		r = (t-drandGenesis)/drandPeriod + 1
	}
	f.round, f.fixedAt, f.leaveMark = uint64(r+DrawDelay), now(), leaves
	f.total, _, _, _ = below(f.oldBelow)
	f.waiting = true
	waits.Set(waitKey(f, id), true)
}

// moved says whether the weight under a waiting round's prefix differs from
// what it was when the round was fixed. Nothing should move it; if
// something ever does, the draw takes a new round instead of failing until
// its deadline costs the filer its bond (round 12, minor 7).
func moved(f *filing) bool {
	total, _, _, _ := below(f.oldBelow)
	return total != f.total
}

// unwait: the filing's round no longer waits for a draw.
func unwait(f *filing, id int) {
	if f.waiting {
		waits.Remove(waitKey(f, id))
		f.waiting = false
	}
}

func waitKey(f *filing, id int) string { return key(uint64(f.fixedAt)) + key(uint64(id)) }

// payDrawer pays whoever draws DrawFee: from the bond's spare, for a
// filing's checkers, then from the fund for what that can't (round 11,
// minor 6).
func payDrawer(cur realm, who address, f *filing) {
	n := least(DrawFee, f.bond-int64(Checkers)*CheckFee-FundFee)
	if n < 0 {
		n = 0
	}
	f.bond -= n
	if rest := DrawFee - n; rest > 0 && fund >= rest {
		fund -= rest
		n += rest
	}
	pay(cur, who, n)
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

// roundSig is the signature of a filing's round, once submitted.
func roundSig(f *filing) []byte {
	v := beacon.Get(key(f.round))
	if v == nil {
		panic("guards: submit beacon round " + strconv.FormatUint(f.round, 10) + " first")
	}
	return v.([]byte)
}

// Draw draws a revealed filing's checkers from its beacon round, by weight,
// from the pool as it was when the round was fixed (tickets.gno), within
// DrawDeadline of then, and pays the caller DrawFee. Too few eligible
// owners: the filing is abandoned at once, its bond back less FundFee and
// the DrawFee paid.
// Anyone may call it.
func Draw(cur realm, id int) string {
	who := caller(cur)
	f := get(id)
	switch {
	case f.state != Revealed:
		panic("guards: not waiting for a draw")
	case now() > f.fixedAt+DrawDeadline:
		panic("guards: the draw's deadline has passed; abandon it")
	}
	if moved(f) {
		fixRound(f, id)
		chain.Emit("GuardRedraw", "filing", strconv.Itoa(id), "round", strconv.FormatUint(f.round, 10), "why", "the pool moved")
		return f.state
	}
	picks := pick(roundSig(f), "draw", id, f.draws, Checkers-(len(f.checks)-1), f, false)
	unwait(f, id)
	compact(4)
	payDrawer(cur, who, f)
	if picks == nil {
		return abandon(cur, f, id, true) // too few staked owners: nobody's fault
	}
	for _, p := range picks {
		p.open++
		f.checks = append(f.checks, &check{ticket: p.id, owner: p.owner})
	}
	f.draws++
	f.drawnAt, f.allIn, f.state = now(), 0, Drawn
	chain.Emit("GuardDrawn", "filing", strconv.Itoa(id), "round", strconv.FormatUint(f.round, 10), "checkers", strings.Join(owners(f.checks[1:]), ","))
	return f.state
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
	mine := findIn(committers(f), who)
	if mine[0].commitment != "" {
		panic("guards: already committed")
	}
	for _, ch := range mine {
		ch.commitment = commitment
	}
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
	mine := findIn(revealers(f), who)
	if mine[0].revealed {
		panic("guards: already revealed")
	}
	if Commitment(who, kindOf(mine[0]), transcript, salt) != mine[0].commitment {
		panic("guards: that isn't what was committed")
	}
	for _, ch := range mine {
		ch.transcript, ch.revealed = transcript, true
	}
}

// running says whether a run of commitments and reveals is under way.
func running(f *filing) bool { return f.state == Drawn || f.state == Rerun || f.state == Panelled }

// committers are who commits in the run under way; revealers, who reveals.
func committers(f *filing) []*check {
	switch f.state {
	case Drawn:
		return f.checks[1:] // the worker's commitment came with its reveal
	case Panelled:
		return f.panels[len(f.panels)-1]
	}
	return f.checks
}

func revealers(f *filing) []*check {
	if f.state == Panelled {
		return f.panels[len(f.panels)-1]
	}
	return f.checks
}

// findIn is who's checks in a run: one, or a panel member's seats.
func findIn(cs []*check, who address) []*check {
	var mine []*check
	for _, c := range cs {
		if c.owner == who {
			mine = append(mine, c)
		}
	}
	if len(mine) == 0 {
		panic("guards: you weren't drawn for this filing")
	}
	return mine
}

func kindOf(c *check) string {
	if c.ticket == -1 {
		return "transcript"
	}
	return "check"
}

// Settle moves a filing on once it can (a rerun's, a panel's and an
// appeal's in dispute.gno); a panel not drawn by its deadline gets a new
// beacon round. After the draw:
//   - drawn checkers who never committed, once CheckWindow passed, are
//     fined and replaced from a later round (no transcript is open yet);
//   - once every transcript is open: all match, agreed (the objection
//     window); one differs, a dispute begins;
//   - once RevealWindow passed with transcripts still shut: a silent worker
//     forfeits its bond; silent checkers are fined, and the filing goes on
//     with those who answered, never with a new checker who could copy the
//     open transcripts (round 9, minor 9).
func Settle(cur realm, id int) string {
	caller(cur)
	f := get(id)
	switch f.state {
	case Rerun:
		return settleRerun(cur, f, id)
	case Panelled:
		return settlePanel(cur, f, id)
	case Appealable:
		if now() <= f.until {
			panic("guards: the appeal window is open")
		}
		return final(cur, f, id, f.verdict)
	case Panel:
		if now() <= f.fixedAt+DrawDeadline {
			panic("guards: the panel can still be drawn")
		}
		fixRound(f, id) // a new round, the pool as it is now; its fees stay set aside
		chain.Emit("GuardPanel", "filing", strconv.Itoa(id), "size", strconv.Itoa(PanelSizes[f.panelLevel]), "round", strconv.FormatUint(f.round, 10))
		return f.state
	case Drawn:
	default:
		panic("guards: nothing to settle")
	}
	if f.allIn == 0 {
		if now() <= f.drawnAt+CheckWindow {
			panic("guards: still waiting for commitments")
		}
		dropSilent(f, func(c *check) bool { return c.commitment == "" })
		fixRound(f, id)
		f.state, f.allIn = Revealed, 0
		chain.Emit("GuardRedraw", "filing", strconv.Itoa(id), "round", strconv.FormatUint(f.round, 10))
		return f.state
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
		if len(f.checks) == 1 {
			return abandon(cur, f, id, true) // nobody checked it
		}
		_, match = agreement(f.checks)
	}
	if !match {
		return dispute(f, id) // the bond and the drawn tickets stay held
	}
	f.state, f.verdict, f.until = Agreed, f.checks[0].transcript, now()+ObjectionWindow
	chain.Emit("GuardAgreed", "filing", strconv.Itoa(id), "hash", f.guardHash, "until", strconv.FormatInt(f.until, 10))
	return f.state
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

// Object disputes an agreement within its window: the objector puts up
// ObjectionBond and says which transcript a correct run gives. The filing
// goes to a panel; the objector is a party to its decision (round 9, new
// major 7).
func Object(cur realm, id int, transcript string) {
	who := caller(cur)
	f := get(id)
	switch {
	case f.state != Agreed || now() > f.until:
		panic("guards: no agreement to object to")
	case verdict(transcript) == "" || transcript == f.verdict:
		panic("guards: an objection is another transcript, its 64-hex hash and pass or fail")
	case party(f, who):
		panic("guards: a party can't object to its own filing")
	}
	f.objBond = received(ObjectionBond)
	f.objector = &check{ticket: -2, owner: who, transcript: transcript, revealed: true}
	f.verdict, f.until = "", 0
	chain.Emit("GuardObjected", "filing", strconv.Itoa(id), "by", string(who))
	panelRequest(f, id)
}

// Finalize ends an agreement nobody objected to.
func Finalize(cur realm, id int) string {
	caller(cur)
	f := get(id)
	if f.state != Agreed || now() <= f.until {
		panic("guards: no agreement to finalize")
	}
	return final(cur, f, id, f.verdict)
}

// Abandon ends a filing whose draw nobody made by its deadline, though anyone
// could have (a Draw that finds too few owners abandons at once): checkers
// kept from an earlier draw are paid, and the rest of the bond goes to the
// fund, so a filer gains nothing by letting a draw it dislikes lapse and
// filing again (round 11, minor 6). Anyone may call it.
func Abandon(cur realm, id int) {
	caller(cur)
	f := get(id)
	switch {
	case f.state != Revealed:
		panic("guards: not waiting for a draw")
	case now() <= f.fixedAt+DrawDeadline:
		panic("guards: it can still be drawn")
	}
	abandon(cur, f, id, false)
}

// abandon lets a filing go: checkers kept from an earlier draw are paid;
// the rest of the bond goes back less FundFee (refund), or to the fund.
func abandon(cur realm, f *filing, id int, refund bool) string {
	unwait(f, id)
	bond := f.bond
	for _, c := range f.checks[1:] {
		pay(cur, c.owner, CheckFee)
		bond -= CheckFee
		release(c)
	}
	if refund {
		bond -= FundFee
		fund += FundFee
		pay(cur, f.filer, bond)
	} else {
		fund += bond
	}
	f.bond, f.state = 0, Abandoned
	chain.Emit("GuardAbandoned", "filing", strconv.Itoa(id), "refund", strconv.FormatBool(refund))
	return f.state
}

// final is a filing's last word, t: settle pays and charges everyone by
// it, and the guard is tested or failed on the filing's system. Passing,
// its level is written if its pool's weight not leaving when its first
// round was fixed (the worker's own included) passed LevelFloor (round 11,
// minor 7; round 13, minor 5), but never over "pulled": a guard decided
// against comes back as a new version (round 10, minor 5). Failing, a
// level written before is pulled.
func final(cur realm, f *filing, id int, t string) string {
	w := f.checks[0]
	settle(cur, f, t)
	if verdict(t) == "pass" {
		f.state = Tested
		switch {
		case Level(f.guardHash, f.system) == Pulled:
			f.pulled = true
		case f.floorAt < LevelFloor:
			f.floor = true
		default:
			setLevel(f.guardHash, f.system, Tested)
		}
		if said(w) == t {
			rec(w.owner).Passed++
		}
	} else {
		f.state = Failed
		if Level(f.guardHash, f.system) == Tested {
			setLevel(f.guardHash, f.system, Pulled) // decided against: light clients see it pulled
		}
		if said(w) == t {
			rec(w.owner).Failed++
		}
	}
	chain.Emit("GuardDecided", "filing", strconv.Itoa(id), "hash", f.guardHash, "system", f.system, "state", f.state)
	return f.state
}

// settle pays and charges everyone on a filing by the word t: whoever said
// t is paid, and whoever said otherwise loses its bond or Slash of its
// stake: the worker, the checkers, an objector, every seat of every panel,
// an appellant who appealed t. A party that said t but differed from it in
// an earlier run pays the fund RerunFee for each such run. What is taken
// first pays the fund back what this dispute cost it (the panels' fees it
// paid and the vote), so the losing side pays them (round 10, new major 3);
// ShowShare percent of the rest goes to those who showed t: the parties who
// said it in every run, and the appellants whose appeal changed the word to
// it (round 11, minor 3); or else to the panel seats that said it. The rest
// is locked here for good.
func settle(cur realm, f *filing, t string) {
	var taken int64
	var showers []address
	faulted := map[address]bool{}
	fault := func(a address) { // once per filing, however many seats
		if !faulted[a] {
			faulted[a] = true
			rec(a).Faults++
		}
	}
	w := f.checks[0]
	if said(w) == t {
		if rerunsOwed(w, t) == 0 {
			showers = append(showers, w.owner)
		}
		bond := f.bond - FundFee
		fund += FundFee
		for _, c := range f.checks[1:] {
			if said(c) == t {
				pay(cur, c.owner, CheckFee)
				bond -= CheckFee
			}
		}
		owed := least(rerunsOwed(w, t), bond) // the reruns its own earlier runs caused
		fund += owed
		pay(cur, w.owner, bond-owed)
	} else {
		taken += f.bond // the worker said otherwise: its whole bond
		fault(w.owner)
	}
	f.bond = 0
	for _, c := range f.checks[1:] {
		if said(c) == t {
			if rerunsOwed(c, t) == 0 {
				showers = append(showers, c.owner)
			}
			rec(c.owner).Checked++
			fund += slash(c, rerunsOwed(c, t))
		} else {
			taken += slash(c, Slash)
			fault(c.owner)
		}
		release(c)
	}
	if o := f.objector; o != nil {
		if o.transcript == t {
			showers = append(showers, o.owner)
			pay(cur, o.owner, f.objBond)
		} else {
			taken += f.objBond
			fault(o.owner)
		}
		f.objBond = 0
	}
	var right []address
	for _, p := range f.panels {
		for _, c := range p {
			if c.revealed && c.transcript == t {
				pay(cur, c.owner, PanelFee)
				f.reserve -= PanelFee
				right = append(right, c.owner)
			} else {
				taken += slash(c, Slash)
				fault(c.owner)
			}
			release(c)
		}
	}
	for i, a := range f.appeals { // kept, settled, for the filing's page
		if a.against == t {
			taken += a.bond // the appeal didn't change the word
			fault(a.who)
		} else {
			pay(cur, a.who, a.bond)
			showers = append(showers, a.who) // it changed the word to t
		}
		f.appeals[i].bond = 0
	}
	spent := f.panelCost - f.reserve // the fees it paid out, and the vote
	fund += f.reserve
	f.reserve = 0
	refill := least(taken, spent)
	fund += refill
	taken -= refill
	if len(showers) == 0 {
		showers = right // only a panel said it
	}
	showers = distinct(showers) // a share each, however many ways one showed it
	if share := taken * ShowShare / 100; len(showers) > 0 && share > 0 {
		each := share / int64(len(showers))
		for _, a := range showers {
			pay(cur, a, each)
		}
		taken -= each * int64(len(showers))
	}
	burned += taken
}

func setLevel(hash, system, level string) {
	levels.Set(levelKey(hash, system), level)
	params.SetString(levelKey(hash, system), level)
}

// levelKey is the param that holds a guard's level on one system:
// lvl_<hash>_<id>-<version>, such as lvl_<hash>_ubuntu-24.04.
func levelKey(hash, system string) string {
	return "lvl_" + hash + "_" + strings.Replace(system, " ", "-", 1)
}

// Level is a guard's level on a system, as the param lvl_<hash>_<system>
// that light clients prove holds it: "tested", "pulled", or "".
func Level(guardHash, system string) string {
	v, _ := params.GetString(levelKey(guardHash, system))
	return v
}

// isSystem says whether s names a system as an os-release ID and
// VERSION_ID: "ubuntu 24.04", "debian 12".
func isSystem(s string) bool {
	id, ver, ok := strings.Cut(s, " ")
	if !ok || len(id) == 0 || len(id) > 32 || len(ver) == 0 || len(ver) > 16 || !(id[0] >= 'a' && id[0] <= 'z') || !(ver[0] >= '0' && ver[0] <= '9') {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	for _, c := range ver {
		if !(c >= '0' && c <= '9' || c == '.') {
			return false
		}
	}
	return true
}

// State says where a filing stands, the beacon round that draws it now,
// and who its checkers are.
func State(id int) (string, uint64, []address) {
	f := get(id)
	var drawn []address
	if len(f.checks) > 1 {
		for _, c := range f.checks[1:] {
			drawn = append(drawn, c.owner)
		}
	}
	return f.state, f.round, drawn
}

// RecordOf is an address's public record.
func RecordOf(a address) Record {
	if v := records.Get(string(a)); v != nil {
		return *v.(*Record)
	}
	return Record{}
}

// Burned is what forfeits and settled disputes have locked here for good.
func Burned() int64 { return burned }

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
	fund += charge(t, NoShowFine) // silence pays the fund (round 11, minor 3)
	t.open--
	f.silent[c.owner] = true
	rec(c.owner).Silent++
}

func release(c *check) {
	if c.ticket >= 0 {
		ticketAt(c.ticket).open--
	}
}

// slash takes up to n from a check's ticket and returns what it took.
func slash(c *check, n int64) int64 {
	if c.ticket < 0 {
		return 0
	}
	return charge(ticketAt(c.ticket), n)
}

func distinct(as []address) []address {
	seen := map[address]bool{}
	var out []address
	for _, a := range as {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

func owners(cs []*check) []string {
	var out []string
	for _, c := range cs {
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

func rec(a address) *Record {
	if v := records.Get(string(a)); v != nil {
		return v.(*Record)
	}
	r := &Record{}
	records.Set(string(a), r)
	return r
}

func emitTicket(what string, t *ticket) {
	chain.Emit(what, "ticket", strconv.Itoa(t.id), "owner", string(t.owner), "stake", strconv.FormatInt(t.weight, 10))
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

func least(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// mulDiv is a*b/c without overflow (round 9, minor 11).
func mulDiv(a, b, c int64) int64 {
	if a <= 0 || b <= 0 || c <= 0 {
		return 0
	}
	x := new(u256.Uint).Mul(u256.NewUint(uint64(a)), u256.NewUint(uint64(b)))
	return int64(new(u256.Uint).Div(x, u256.NewUint(uint64(c))).Uint64())
}
