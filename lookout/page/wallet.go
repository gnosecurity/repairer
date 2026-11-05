package page

// Signing in with a gno wallet: the box hands the page a one-time phrase, Adena signs it (SignArbitrary, ADR-036,
// message type sign/MsgSignData, Adena 1.22.2 and later, Ledger accounts included), and the box checks that the
// signature is that key's over exactly that document, that the key is the claimed g1... address's, and that the
// document says what was asked. This is gnomail's internal/wallet (kourier), which is gno.world's
// presence/namesig.go, where the verifier is held against the live chain and Adena's own fixture; the test vectors
// came along with it.
//
// The box verifies the EXACT bytes the page says were signed and never re-serializes them: Adena builds its
// document with sortedJsonStringify + encodeCharacterSet, and reproducing that byte for byte is the one part of
// this that would fail closed and silently. Verifying the given bytes and then reading the fields out of them is
// equally safe and has nothing to get wrong.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // tm2 derives secp256k1 addresses with it; the hash is their choice
)

// addrRE is the shape of a gno address.
var addrRE = regexp.MustCompile(`^g1[02-9ac-hj-np-z]{38}$`)

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(v []int) int {
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, x := range v {
		b := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ x
		for i := 0; i < 5; i++ {
			if (b>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32Expand(hrp string) []int {
	out := make([]int, 0, len(hrp)*2+1)
	for _, c := range hrp {
		out = append(out, int(c)>>5)
	}
	out = append(out, 0)
	for _, c := range hrp {
		out = append(out, int(c)&31)
	}
	return out
}

// bech32 is the BIP-173 encoding, a checksum rather than a cipher: written here instead of pulled in, and held to
// the live-chain vector in the tests.
func bech32(hrp string, data []byte) string {
	var five []int
	acc, bits := 0, 0
	for _, b := range data {
		acc = acc<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			five = append(five, (acc>>bits)&31)
		}
	}
	if bits > 0 {
		five = append(five, (acc<<(5-bits))&31)
	}
	chk := append(append(bech32Expand(hrp), five...), 0, 0, 0, 0, 0, 0)
	pm := bech32Polymod(chk) ^ 1
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, x := range five {
		b.WriteByte(bech32Charset[x])
	}
	for i := 0; i < 6; i++ {
		b.WriteByte(bech32Charset[(pm>>(5*(5-i)))&31])
	}
	return b.String()
}

// validAddr reports whether s is a g1... address whose checksum holds, so a typo in -admin stops the service at
// start-up instead of quietly locking everyone out.
func validAddr(s string) bool {
	if !addrRE.MatchString(s) {
		return false
	}
	v := bech32Expand("g")
	for _, c := range s[2:] {
		v = append(v, strings.IndexRune(bech32Charset, c))
	}
	return bech32Polymod(v) == 1
}

// gnoAddress is the g1... address of a compressed secp256k1 key: RIPEMD160(SHA256(the raw 33 bytes)), bech32
// under "g". NOT tmhash.SumTruncated: tm2's crypto.AddressFromPreimage uses the first 20 bytes of SHA256, which is
// a DIFFERENT address for the same key, and taking it would let the wrong wallet in.
func gnoAddress(pub []byte) string {
	sum := sha256.Sum256(pub)
	r := ripemd160.New()
	r.Write(sum[:])
	return bech32("g", r.Sum(nil))
}

// short is an address as a line shows it: g1ecsu...yvv6.
func short(addr string) string {
	if len(addr) > 12 {
		return addr[:6] + "..." + addr[len(addr)-4:]
	}
	return addr
}

// signedDoc is the part of an ADR-036 document this box insists on reading.
type signedDoc struct {
	Msgs []struct {
		Type  string `json:"type"`
		Value struct {
			Data   string `json:"data"`
			Signer string `json:"signer"`
		} `json:"value"`
	} `json:"msgs"`
}

// errProof is every way a wallet proof can fail; the wrapped text says which.
var errProof = errors.New("that signature does not prove this wallet")

// verifyArbitrary checks a SignArbitrary proof. doc is the exact string the wallet signed; sigB64 and pubB64 are
// as Adena returns them. It answers nil only when the signature is that key's over that string, the key is
// wantAddr's, and the document is one sign/MsgSignData by wantAddr carrying wantWords. Any network's proof will
// do: the words are what this box asked for, once.
func verifyArbitrary(doc, sigB64, pubB64, wantAddr, wantWords string) error {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != 33 {
		return fmt.Errorf("%w: the public key is not 33 compressed bytes", errProof)
	}
	if got := gnoAddress(pub); got != wantAddr {
		return fmt.Errorf("%w: that key belongs to %s", errProof, short(got))
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return fmt.Errorf("%w: the signature is not 64 bytes", errProof)
	}
	key, err := secp256k1.ParsePubKey(pub)
	if err != nil {
		return fmt.Errorf("%w: the public key does not parse", errProof)
	}
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(sig[:32]) || s.SetByteSlice(sig[32:]) { // true means it overflowed the curve order
		return fmt.Errorf("%w: the signature is out of range", errProof)
	}
	h := sha256.Sum256([]byte(doc))
	if !ecdsa.NewSignature(&r, &s).Verify(h[:], key) {
		return fmt.Errorf("%w: the signature is not that key's", errProof)
	}
	var d signedDoc // only now, on bytes the wallet is known to have signed, is it worth reading what they say
	if json.Unmarshal([]byte(doc), &d) != nil || len(d.Msgs) != 1 {
		return fmt.Errorf("%w: the signed document is not one message", errProof)
	}
	m := d.Msgs[0]
	switch {
	case m.Type != "sign/MsgSignData":
		return fmt.Errorf("%w: it signs %q, not a plain message", errProof, m.Type)
	case m.Value.Signer != wantAddr:
		return fmt.Errorf("%w: it names another signer", errProof)
	// base64, not the words themselves: Adena's makeArbitraryMessageDoc does toBase64(toUtf8(data))
	case m.Value.Data != base64.StdEncoding.EncodeToString([]byte(wantWords)):
		return fmt.Errorf("%w: it signs something other than this browser's phrase", errProof)
	}
	return nil
}

// --- the challenge: a phrase this box gave a browser, signed once

const (
	challengeLife = 10 * time.Minute // long enough to find the wallet's window and the Ledger, short enough that a stolen phrase is stale
	maxChallenges = 4096             // outstanding phrases kept; beyond that new ones wait
)

type challenges struct {
	mu sync.Mutex
	at map[string]challenge
}

type challenge struct {
	words string
	at    time.Time
}

func newChallenges() *challenges { return &challenges{at: map[string]challenge{}} }

// issue hands out a phrase under a fresh id. The phrase is read in the wallet's approval window, so it says which
// site asks and what for.
func (c *challenges) issue(host string, now time.Time) (id, words string, err error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	id = hex.EncodeToString(b[:8])
	words = "Sign in to " + host + " admin. One-time code: " + base64.RawURLEncoding.EncodeToString(b[8:])
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.at) >= maxChallenges {
		for k, v := range c.at {
			if now.Sub(v.at) > challengeLife {
				delete(c.at, k)
			}
		}
		if len(c.at) >= maxChallenges {
			return "", "", errors.New("too many sign-ins are waiting; try again in a few minutes")
		}
	}
	c.at[id] = challenge{words: words, at: now}
	return id, words, nil
}

// take returns the phrase under an id and FORGETS it: one phrase answers once. fresh says it is still in its life.
func (c *challenges) take(id string, now time.Time) (words string, fresh bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.at[id]
	if !ok {
		return "", false
	}
	delete(c.at, id)
	return ch.words, now.Sub(ch.at) <= challengeLife
}
