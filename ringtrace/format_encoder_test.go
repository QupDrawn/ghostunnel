package ringtrace

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// ---- the oracle: EncodeLine through encoding/json ----

// lineHeader is declared first in every wire struct so that encoding/json
// writes kind as the first key.
type lineHeader struct {
	Kind     Kind   `json:"kind"`
	Version  int    `json:"version"`
	Sequence int64  `json:"sequence"`
	At       string `json:"at"`
}

// oldEncodeLine builds a wire value from the tagged structs and calls
// json.Marshal: the oracle the hand-written encoder is held byte-identical
// to.
func oldEncodeLine(r Record) ([]byte, error) {
	if r.Body == nil {
		return nil, errors.New("ringtrace: nil body")
	}
	if err := positive(r.Sequence, "sequence"); err != nil {
		return nil, fmt.Errorf("ringtrace: %v", err)
	}
	if r.At.IsZero() {
		return nil, errors.New("ringtrace: zero time")
	}
	if err := r.Body.validate(); err != nil {
		return nil, fmt.Errorf("ringtrace: %s: %v", r.Body.Kind(), err)
	}
	h := lineHeader{Kind: r.Body.Kind(), Version: Version, Sequence: r.Sequence, At: formatTimestamp(r.At)}
	var wire interface{}
	switch b := r.Body.(type) {
	case *Start:
		wire = struct {
			lineHeader
			*Start
		}{h, b}
	case *Accept:
		wire = struct {
			lineHeader
			*Accept
		}{h, b}
	case *Handshake:
		wire = struct {
			lineHeader
			*Handshake
		}{h, b}
	case *ACL:
		wire = struct {
			lineHeader
			*ACL
		}{h, b}
	case *Close:
		wire = struct {
			lineHeader
			*Close
		}{h, b}
	case *Reload:
		wire = struct {
			lineHeader
			*Reload
		}{h, b}
	case *Shutdown:
		wire = struct {
			lineHeader
			*Shutdown
		}{h, b}
	case *Tick:
		wire = h
	case *AcceptError:
		wire = struct {
			lineHeader
			*AcceptError
		}{h, b}
	case *Refusal:
		wire = struct {
			lineHeader
			*Refusal
		}{h, b}
	default:
		return nil, fmt.Errorf("ringtrace: unknown body type %T", r.Body)
	}
	out, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	out = append(out, '\n')
	if len(out) > MaxLineBytes {
		return nil, ErrLineTooLong
	}
	return out, nil
}

// ---- the differential ----

// adversarialStrings is what the generator builds strings from: quotes,
// backslashes, every escaping class of control character, DEL, the three
// HTML-escaped bytes, multi-byte runes of every width, the two line
// separators, an encoded U+FFFD, a byte order mark, and invalid UTF-8 of
// every shape (a lone continuation byte, 0xFF, an overlong encoding, a
// truncated sequence, a surrogate, a code point past U+10FFFF). The runes
// are spelled as their UTF-8 bytes so that no tool between the author and
// the file rewrites a \u escape.
var adversarialStrings = []string{
	"", "plain", " ", `"`, `\`, `\"`, "\x00", "\x01", "\b", "\f", "\n", "\r", "\t", "\x0b", "\x1f", "\x7f",
	"<", ">", "&", "<script>&amp;</script>", "a<b>c&d", "'", "/", "=",
	"é", "ß", "日本語", "😀", "\xc2\xa0", "\xe2\x80\xa8", "\xe2\x80\xa9", "\xe2\x80\xa7", "\xe2\x80\xaa", "\xef\xbf\xbd", "\xef\xbb\xbf",
	"\x80", "\xbf", "\xff", "\xc0\xaf", "\xc1\xbf", "\xe2\x80", "\xe2", "\xf0\x9f\x98", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xf8\x88\x80\x80\x80",
	"a\x00b", "x\xffy", "\xe2\x80\xa8", "\\u2028", "\\n", "\"quoted\"", "tab\there", "crlf\r\n",
	strings.Repeat("x", 300), strings.Repeat("\"\\", 40), strings.Repeat("\xff", 20),
}

// gen builds random records across every kind, mostly valid so that the
// encoders are exercised, sometimes invalid so that they are seen to refuse
// identically.
type gen struct {
	r *rand.Rand
	// poisoned: a PEM marker was already put in one string of the record
	// being built. At most one per record, because validate checks some
	// fields by ranging over a map, whose order is random: two refusable
	// fields in one map would be named in either order, and the two
	// encoders, sharing that code, would disagree only by that accident.
	poisoned bool
}

func (g *gen) pick(ss []string) string { return ss[g.r.IntN(len(ss))] }

// str is a random concatenation of adversarial pieces and raw random bytes.
func (g *gen) str() string {
	var sb strings.Builder
	for n := g.r.IntN(5); n > 0; n-- {
		if g.r.IntN(4) == 0 {
			raw := make([]byte, g.r.IntN(12))
			for i := range raw {
				raw[i] = byte(g.r.IntN(256))
			}
			sb.Write(raw)
		} else {
			sb.WriteString(g.pick(adversarialStrings))
		}
	}
	if !g.poisoned && g.r.IntN(50) == 0 {
		sb.WriteString("-----BEGIN") // refused by validation, identically
		g.poisoned = true
	}
	return sb.String()
}

func (g *gen) nonEmpty() string {
	if s := g.str(); s != "" {
		return s
	}
	return "x"
}

func (g *gen) ptr() *string {
	if g.r.IntN(3) == 0 {
		return nil
	}
	s := g.str()
	return &s
}

func (g *gen) hash() string {
	const hex = "0123456789abcdef"
	b := make([]byte, 64)
	for i := range b {
		b[i] = hex[g.r.IntN(16)]
	}
	if g.r.IntN(40) == 0 {
		b[0] = 'G' // not a hash: refused
	}
	return string(b)
}

func (g *gen) hashPtr() *string {
	if g.r.IntN(2) == 0 {
		return nil
	}
	h := g.hash()
	return &h
}

func (g *gen) strings() []string {
	switch g.r.IntN(4) {
	case 0:
		return nil
	case 1:
		return []string{}
	}
	out := make([]string, 1+g.r.IntN(4))
	for i := range out {
		out[i] = g.str()
	}
	return out
}

func (g *gen) i64() int64 {
	switch g.r.IntN(8) {
	case 0:
		return 0
	case 1:
		return -1
	case 2:
		return math.MaxInt64
	case 3:
		return math.MinInt64
	case 4:
		return -g.r.Int64N(1 << 40)
	default:
		return g.r.Int64N(1 << 40)
	}
}

func (g *gen) positive() int64 {
	switch g.r.IntN(10) {
	case 0:
		return 1
	case 1:
		return math.MaxInt64
	case 2:
		return g.i64() // sometimes invalid
	default:
		return 1 + g.r.Int64N(1<<40)
	}
}

func (g *gen) nonNegative() int64 {
	switch g.r.IntN(10) {
	case 0:
		return 0
	case 1:
		return math.MaxInt64
	case 2:
		return g.i64() // sometimes invalid
	default:
		return g.r.Int64N(1 << 40)
	}
}

func (g *gen) bool() bool { return g.r.IntN(2) == 0 }

func (g *gen) materials() []Material {
	switch g.r.IntN(5) {
	case 0:
		return nil // refused
	case 1:
		return []Material{}
	}
	out := make([]Material, 1+g.r.IntN(4))
	for i := range out {
		m := Material{Material: g.pick(Materials), Path: g.str(), SHA256: g.hashPtr()}
		if m.Material == "key" && g.r.IntN(8) != 0 {
			m.SHA256 = nil
		}
		out[i] = m
	}
	return out
}

func (g *gen) acl() []string {
	switch g.r.IntN(12) {
	case 0:
		return nil // refused
	case 1:
		return []string{} // refused
	case 2:
		return []string{g.str()} // almost always refused
	}
	set := map[string]bool{}
	for n := 1 + g.r.IntN(4); n > 0; n-- {
		if g.r.IntN(3) == 0 {
			set[g.pick(ACLTokens)] = true
			continue
		}
		prefix := g.pick(ACLPrefixes)
		if prefix == "policy:" {
			set[prefix+g.hash()] = true
		} else {
			set[prefix+g.nonEmpty()] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	if g.r.IntN(30) == 0 && len(out) > 1 {
		out[0], out[1] = out[1], out[0] // unsorted: refused
	}
	return out
}

func (g *gen) at() time.Time {
	switch g.r.IntN(8) {
	case 0:
		return time.Date(1, 1, 1, 0, 0, 0, 1, time.UTC) // one nanosecond past the zero time
	case 1:
		return time.Date(9999, 12, 31, 23, 59, 59, 999_999_999, time.UTC)
	case 2:
		return time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	case 3:
		return time.Date(-1, 6, 15, 12, 0, 0, 0, time.UTC)
	case 4:
		return time.Time{} // refused
	case 5:
		return time.Unix(g.r.Int64N(1<<35)-(1<<34), g.r.Int64N(1e9)).In(time.FixedZone("x", int(g.r.IntN(48)-24)*1800))
	default:
		return time.Unix(g.r.Int64N(1<<32), 0).UTC()
	}
}

func (g *gen) body() Body {
	g.poisoned = false
	switch g.r.IntN(10) {
	case 0:
		return &Start{Boot: g.positive(), PID: g.positive(), Config: Config{
			Mode: g.pick(Modes), Listen: g.nonEmpty(), Target: g.nonEmpty(), ProxyProtocol: g.pick(ProxyProtocols), StatusListen: g.ptr(),
			StatusClientCert: g.bool(), PprofCmdlineRedacted: g.bool(), ShutdownRequiresClientCert: g.bool(),
			SessionTickets: g.bool(), VerifyOnResume: g.bool(), ACL: g.acl(), LifetimeCapSeconds: g.nonNegative(),
			SandboxState: g.pick(SandboxStates), SandboxAccepted: g.ptr(), Material: g.materials(),
		}}
	case 1:
		return &Accept{Conn: g.positive(), Listener: g.nonEmpty(), Remote: g.nonEmpty()}
	case 2:
		h := &Handshake{Conn: g.positive(), Outcome: g.pick(HandshakeOutcome), Resumed: g.bool(), Verified: g.bool(), Protocol: g.str(), Error: g.ptr()}
		if g.r.IntN(3) != 0 {
			h.Peer = &Peer{Subject: g.str(), Issuer: g.str(), Serial: g.str(), SANs: g.strings(), Fingerprint: g.hash()}
		}
		switch g.r.IntN(4) {
		case 0:
			h.Chain = g.hash()
		case 1:
			h.Chain = "" // absent
		}
		return h
	case 3:
		return &ACL{Conn: g.positive(), Decision: g.pick(Decisions), Rule: g.nonEmpty(), Reason: g.str()}
	case 4:
		return &Close{Conn: g.positive(), Reason: g.pick(CloseReasons), DurationMS: g.nonNegative()}
	case 5:
		return &Reload{Outcome: g.pick(ReloadOutcomes), Error: g.ptr(), Serving: g.bool(), Material: g.materials()}
	case 6:
		return &Shutdown{Source: g.pick(ShutdownSources), Authorized: g.bool(), Peer: g.ptr(), Detail: g.str()}
	case 7:
		return &Tick{}
	case 8:
		return &AcceptError{Error: g.nonEmpty(), BackoffMS: g.nonNegative()}
	default:
		return &Refusal{Source: g.pick(RefusalSources), Error: g.nonEmpty()}
	}
}

// compareEncoders holds EncodeLine to oldEncodeLine on one record: the same
// bytes, or the same refusal.
func compareEncoders(t *testing.T, rec Record, what string) (encoded bool) {
	t.Helper()
	got, gerr := EncodeLine(rec)
	want, werr := oldEncodeLine(rec)
	if (gerr == nil) != (werr == nil) || (gerr != nil && gerr.Error() != werr.Error()) {
		t.Fatalf("%s: EncodeLine err %v, json.Marshal path err %v\nrecord %#v", what, gerr, werr, rec.Body)
	}
	if gerr != nil {
		if got != nil {
			t.Fatalf("%s: a refused record returned bytes", what)
		}
		return false
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: encodings differ\n got %q\nwant %q\nrecord %#v", what, got, want, rec.Body)
	}
	return true
}

// TestEncodeLineMatchesJSON is the differential: for every sample body at
// several timestamps, and for a seeded stream of random bodies of every
// kind built from adversarial strings, nil and empty slices, nil pointers,
// zero, negative and extreme integers and timestamps at the edges, the
// hand-written encoder produces exactly the bytes json.Marshal produced
// from the tagged wire structs, or refuses with exactly the same error.
func TestEncodeLineMatchesJSON(t *testing.T) {
	ats := []time.Time{
		time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC),
		time.Date(1, 1, 1, 0, 0, 0, 1, time.UTC),
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(2026, 9, 24, 10, 7, 0, 999_000_000, time.FixedZone("x", 3600)),
	}
	for i, body := range sampleBodies() {
		for _, at := range ats {
			for _, seq := range []int64{1, 7, math.MaxInt64, 0, -1} {
				compareEncoders(t, Record{Sequence: seq, At: at, Body: body}, fmt.Sprintf("sample %d %s", i, body.Kind()))
			}
		}
	}
	compareEncoders(t, Record{Sequence: 1, At: ats[0], Body: nil}, "nil body")
	compareEncoders(t, Record{Sequence: 1, At: time.Time{}, Body: &Tick{}}, "zero time")
	compareEncoders(t, Record{Sequence: 1, At: ats[0], Body: &ACL{Conn: 1, Decision: "deny", Rule: "r", Reason: strings.Repeat("x", MaxLineBytes)}}, "over-long")
	compareEncoders(t, Record{Sequence: 1, At: ats[0], Body: &ACL{Conn: 1, Decision: "deny", Rule: "r", Reason: strings.Repeat("<", MaxLineBytes/4)}}, "over-long after escaping")

	const n = 20000
	const seed = 20260925
	g := &gen{r: rand.New(rand.NewPCG(seed, 1))}
	encoded := map[Kind]int{}
	total := 0
	for i := 0; i < n; i++ {
		rec := Record{Sequence: g.positive(), At: g.at(), Body: g.body()}
		if compareEncoders(t, rec, fmt.Sprintf("random %d (seed %d)", i, seed)) {
			encoded[rec.Body.Kind()]++
			total++
		}
	}
	if total < n/2 {
		t.Fatalf("only %d of %d random records were valid; the generator exercises the refusal path more than the encoder", total, n)
	}
	for _, k := range kinds {
		if encoded[k] < 200 {
			t.Fatalf("only %d valid random %s records; the generator does not exercise that kind", encoded[k], k)
		}
	}
	t.Logf("%d of %d random records encoded identically (%v); the rest refused identically", total, n, encoded)
}

// TestAppendStringMatchesJSON holds the string escaper to json.Marshal
// exhaustively over every single byte, every pair of bytes and every rune,
// plus the adversarial pieces and random byte strings.
func TestAppendStringMatchesJSON(t *testing.T) {
	check := func(s string) {
		got := appendString(nil, s)
		want, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("json.Marshal(%q): %v", s, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("appendString(%q) = %q, json.Marshal = %q", s, got, want)
		}
	}
	for b := 0; b < 256; b++ {
		check(string([]byte{byte(b)}))
	}
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			check(string([]byte{byte(a), byte(b)}))
		}
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		check(string(r))
	}
	// Every rune between two others, so that the copied-through run
	// around an escape is cut at the right byte.
	for r := rune(0); r <= 0x3000; r++ {
		check("a" + string(r) + "z")
	}
	for _, s := range adversarialStrings {
		check(s)
		check("<" + s + ">")
		check(s + s)
	}
	g := &gen{r: rand.New(rand.NewPCG(7, 7))}
	for i := 0; i < 10000; i++ {
		raw := make([]byte, g.r.IntN(24))
		for j := range raw {
			raw[j] = byte(g.r.IntN(256))
		}
		check(string(raw))
		check(g.str())
	}
	if got := appendString(nil, "\xff"); !utf8.ValidString(string(got)) || bytes.IndexByte(got, 0xff) >= 0 {
		t.Fatalf("an invalid byte must be replaced, not copied: %q", got)
	}
}

// TestEncodedKeysAreDocumented pins the encoder's own output to the
// documented key lists: the keys of every line, in the order written, are
// Keys(kind) (chain absent when the handshake has none), and the nested
// config, peer and material objects carry ConfigKeys, PeerKeys and
// MaterialKeys in order.
func TestEncodedKeysAreDocumented(t *testing.T) {
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	for i, body := range sampleBodies() {
		line, err := EncodeLine(Record{Sequence: int64(i + 1), At: at, Body: body})
		if err != nil {
			t.Fatal(err)
		}
		objects := map[string][]string{}
		dec := json.NewDecoder(bytes.NewReader(line))
		if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
			t.Fatalf("%s: not an object: %v %v", body.Kind(), tok, err)
		}
		collectKeys(t, dec, "", objects)
		want := Keys(body.Kind())
		if h, ok := body.(*Handshake); ok && h.Chain == "" {
			want = want[:len(want)-1]
		}
		if got := objects[""]; strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: keys %v, documented %v", body.Kind(), got, want)
		}
		for path, keys := range objects {
			var want []string
			switch {
			case path == "":
				continue
			case path == "config":
				want = ConfigKeys
			case path == "peer":
				want = PeerKeys
			case strings.HasSuffix(path, "material[]"):
				want = MaterialKeys
			default:
				t.Errorf("%s: unexpected nested object at %q", body.Kind(), path)
				continue
			}
			if strings.Join(keys, ",") != strings.Join(want, ",") {
				t.Errorf("%s: %s keys %v, documented %v", body.Kind(), path, keys, want)
			}
		}
	}
}

// collectKeys reads the members of the object whose '{' was just consumed,
// records its keys in order under path, and descends into nested objects
// (an array's objects under path[]).
func collectKeys(t *testing.T, dec *json.Decoder, path string, objects map[string][]string) {
	t.Helper()
	keys := []string{}
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		if d, ok := tok.(json.Delim); ok && d == '}' {
			objects[path] = keys
			return
		}
		key := tok.(string)
		keys = append(keys, key)
		collectValue(t, dec, joinPath(path, key), objects)
	}
}

func collectValue(t *testing.T, dec *json.Decoder, path string, objects map[string][]string) {
	t.Helper()
	tok, err := dec.Token()
	if err != nil {
		t.Fatal(err)
	}
	switch tok {
	case json.Delim('{'):
		collectKeys(t, dec, path, objects)
	case json.Delim('['):
		for dec.More() {
			collectValue(t, dec, path+"[]", objects)
		}
		if tok, err := dec.Token(); err != nil || tok != json.Delim(']') {
			t.Fatalf("array at %s not closed: %v %v", path, tok, err)
		}
	}
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// AppendLine writes exactly EncodeLine's bytes after whatever dst holds,
// for every sample body, and appends nothing when the record is refused.
func TestAppendLineAppendsEncodeLine(t *testing.T) {
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	prefix := []byte("prefix\n")
	for i, body := range sampleBodies() {
		rec := Record{Sequence: int64(i + 1), At: at, Body: body}
		want, err := EncodeLine(rec)
		if err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
		dst := append([]byte{}, prefix...)
		got, err := AppendLine(dst, rec)
		if err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
		if string(got) != string(prefix)+string(want) {
			t.Fatalf("sample %d %s: AppendLine gave %q, want the prefix then %q", i, body.Kind(), got, want)
		}
	}
	dst := append([]byte{}, prefix...)
	for _, bad := range []Record{{Sequence: 0, At: at, Body: &Tick{}}, {Sequence: 1, Body: &Tick{}}, {Sequence: 1, At: at}, {Sequence: 1, At: at, Body: &Accept{}}} {
		got, err := AppendLine(dst, bad)
		if err == nil {
			t.Fatalf("%+v: no error", bad)
		}
		if string(got) != string(prefix) {
			t.Fatalf("%+v: a refused record appended %q", bad, got[len(prefix):])
		}
	}
}
