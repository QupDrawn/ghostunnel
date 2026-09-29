package main

// gtreader.go is this member's own reader of the trace ghostunnel leaves
// under gt/ (ringtrace/README.md, section 1). It is written from that
// document and shares no code with ringtrace: the two agree only by agreeing
// with the description, and where they disagree the ring halts rather than
// tolerates. Every rule of section 1.4 is applied here, in the same order,
// and the first violation ends the read with nothing returned: a trace that
// cannot be read has not been read.
//
// The segment rule (ringtrace/README.md; SPEC 14 and 14.3), applied by
// gtReadSegment before any rule of 1.4 looks at the bytes: a segment's
// content is its bytes before the first NUL byte (0x00), or all of its
// bytes when it has none; bytes from the first NUL onward are unwritten
// space of a pre-extended segment and are not part of the trace; a reader
// reads a segment in bounded chunks from its start and stops at the first
// chunk holding a NUL or at end of file, never reading a whole
// pre-extended segment; the complete-line prefix and the torn tail are
// then taken of the content. The emitter pre-extends the
// segment it is writing to its maximum size and truncates it to its
// written length when it closes it, so an at-rest segment is exact and
// the live one, or the last of a boot that crashed, carries a tail of NUL
// bytes. Lines are JSON objects, which never carry a raw NUL, so the rule
// is exact. Nothing below the read sees a file size: every length in this
// file, in the decode memory and in trace-consistent is a length of
// content.
//
// Every member of the ring carries a byte-identical copy of this file. None
// imports it from another; the observers are a trust domain of their own.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// gtMaxLineBytes bounds one line including its line feed (README 1.1).
const gtMaxLineBytes = 65536

// gtMaxSegmentBytes bounds a segment's content, the emitter's own segment
// size (ringtrace.DefaultMaxSegmentBytes): the emitter rotates at it, so
// content past it is not a segment the emitter wrote, and a reader that
// kept reading would hold an unbounded file in memory every cycle.
const gtMaxSegmentBytes = 64 << 20

// gtReadChunkBytes bounds one read of a segment (the segment rule): a
// pre-extended segment is read a chunk at a time from its start, and the
// read stops in the chunk that holds the first NUL, so a segment holding a
// few lines in front of 64 MiB of unwritten space costs one chunk.
const gtReadChunkBytes = 1 << 20

// gtTimestampLayout is the one timestamp form: YYYY-MM-DDTHH:MM:SSZ.
const gtTimestampLayout = "2006-01-02T15:04:05Z"

var (
	gtReBootName    = regexp.MustCompile(`^[0-9]{10}$`)
	gtReSegmentName = regexp.MustCompile(`^[0-9]{10}\.trace$`)
	gtReHash        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gtReInteger     = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`) // the spelling gtIsInteger matches
)

// The ten kinds, in the order the README lists them (the emitter's
// ClassifyLine order), and the exact key set of each after the four header
// keys. A tick is the header and nothing else. The marker a line is
// classified by includes the closing quote and comma (gtClassify), so
// accept never prefix-matches accept-error.
var (
	gtKinds      = []string{"start", "accept", "handshake", "acl", "close", "reload", "shutdown", "tick", "accept-error", "refusal"}
	gtHeaderKeys = []string{"kind", "version", "sequence", "at"}
	gtBodyKeys   = map[string][]string{
		"start":        {"boot", "pid", "config"},
		"accept":       {"conn", "listener", "remote"},
		"handshake":    {"conn", "outcome", "resumed", "verified", "protocol", "peer", "error"},
		"acl":          {"conn", "decision", "rule", "reason"},
		"close":        {"conn", "reason", "duration_ms"},
		"reload":       {"outcome", "error", "serving", "material"},
		"shutdown":     {"source", "authorized", "peer", "detail"},
		"tick":         {},
		"accept-error": {"error", "backoff_ms"},
		"refusal":      {"source", "error"},
	}
	gtConfigKeys   = []string{"mode", "listen", "target", "proxy_protocol", "status_listen", "status_client_cert", "pprof_cmdline_redacted", "shutdown_requires_client_cert", "session_tickets", "verify_on_resume", "acl", "lifetime_cap_seconds", "sandbox_state", "sandbox_accepted", "material", "binary"}
	gtMaterialKeys = []string{"material", "path", "sha256"}
	gtBinaryKeys   = []string{"path", "sha256"}
	gtPeerKeys     = []string{"subject", "issuer", "serial", "sans", "fingerprint"}
)

// Built once from the lists above and only ever read: each kind's marker
// in gtKinds order, each kind's full key set (the header keys, then the
// body's), and a handshake's with its one optional key, chain, after them.
var (
	gtKindMarkers        = gtMarkersOf(gtKinds)
	gtKindKeys           = gtKeysOf(gtKinds)
	gtHandshakeChainKeys = append(append([]string{}, gtKindKeys["handshake"]...), "chain")
)

func gtMarkersOf(kinds []string) [][]byte {
	out := make([][]byte, len(kinds))
	for i, k := range kinds {
		out[i] = []byte(`{"kind":"` + k + `",`)
	}
	return out
}

func gtKeysOf(kinds []string) map[string][]string {
	out := make(map[string][]string, len(kinds))
	for _, k := range kinds {
		keys := append(append([]string{}, gtHeaderKeys...), gtBodyKeys[k]...)
		out[k] = keys[:len(keys):len(keys)]
	}
	return out
}

// The closed enumerations (README 1.1, 1.2).
var (
	gtModes            = []string{"server", "client"}
	gtMaterials        = []string{"cert", "key", "ca", "policy"}
	gtHandshakeOutcome = []string{"ok", "refused"}
	gtDecisions        = []string{"allow", "deny"}
	gtCloseReasons     = []string{"eof", "error", "lifetime", "shutdown", "halt", "refused"}
	gtReloadOutcomes   = []string{"ok", "failed"}
	gtShutdownSources  = []string{"signal", "status-endpoint", "service-control", "ring-halt", "internal"}
	// gtRefusalSources is what a refusal line may name as having failed
	// (README 1.2): the proxy refuses to serve until restart from that
	// line on, for a reason no other line records.
	gtRefusalSources = []string{"status-listener"}
	gtSANPrefixes    = []string{"dns:", "uri:", "ip:", "email:"}
	// The config.acl vocabulary (README 1.2). gtACLTokens stand alone; a
	// gtACLPrefixes entry is followed by the rule's value, which is never
	// empty, and for policy is the SHA-256 of the policy file.
	gtACLTokens   = []string{"allow-all", "verify-hostname", "disable-authentication"}
	gtACLPrefixes = []string{"allow-cn:", "allow-ou:", "allow-dns:", "allow-ip:", "allow-uri:", "allow-spki-pin:", "verify-cn:", "verify-ou:", "verify-dns:", "verify-ip:", "verify-uri:", "verify-spki-pin:", "policy:"}
	// gtSandboxStates is what became of the process sandbox attempt at
	// startup (README 1.2); "unsupported" is the one state beside which
	// ghostunnel records an acceptance.
	gtSandboxStates = []string{"applied", "unsupported", "disabled", "failed", "skipped"}
	// gtProxyProtocols is what the backend is handed ahead of each
	// connection's bytes (README 1.2): no header, or a PROXY protocol v2
	// header with the addresses, with the TLS metadata too, or with the
	// client's certificate as well. Closed: a line without the key, or
	// with a value outside it, is malformed, never a mode of off.
	gtProxyProtocols = []string{"off", "conn", "tls", "tls-full"}
)

// gtError locates the first violation. Rel is the path relative to the
// trace root ("" for the root itself); Line is 1-based and 0 when the
// finding is about a file or directory rather than a line.
type gtError struct {
	Rel    string
	Line   int
	Reason string
}

func (e *gtError) Error() string {
	switch {
	case e.Line > 0:
		return fmt.Sprintf("gt/%s:%d: %s", e.Rel, e.Line, e.Reason)
	case e.Rel != "":
		return fmt.Sprintf("gt/%s: %s", e.Rel, e.Reason)
	}
	return "gt: " + e.Reason
}

// Subject is the compact finding subject for this error: the relative path
// with the line appended when there is one, or "gt" for the root itself.
func (e *gtError) Subject() string {
	switch {
	case e.Line > 0:
		return e.Rel + ":" + strconv.Itoa(e.Line)
	case e.Rel != "":
		return e.Rel
	}
	return "gt"
}

// gtSubject is the finding subject for any error a read returned.
func gtSubject(err error) string {
	var e *gtError
	if errors.As(err, &e) {
		return e.Subject()
	}
	return "gt"
}

// gtBoot is one process's trace as read.
type gtBoot struct {
	Number int64
	Root   string // the trace root it was read from, where gt/chains/ is

	// Records are every complete line, in sequence order. They are only
	// ever read: the slice, or the leading part of it, may be the decode
	// memory's own (gtDecodedSegment.Records), handed to the next read.
	Records []gtRecord
	// Carried is how many of the leading Records this read took from the
	// decode memory unchanged: Records[:Carried] were decoded by an earlier
	// read from bytes that hash the same now, from the same reader state,
	// and Records[Carried:] were decoded by this one. 0 for a read with no
	// memory, or one whose first segment did not match it.
	Carried int
	// Memory and Read say which read of which memory this is: the memory
	// the read resumed from (nil for none) and its count of reads when
	// this one began (gtDecodeMemory.Reads). The earlier read Carried
	// speaks of is that memory's read numbered Read-1, the one before.
	Memory   *gtDecodeMemory
	Read     uint64
	Segments []gtSegment // each segment read, in order, with its complete-line prefix
	Torn     bool        // the last segment ends in a line without a line feed
}

// gtSegment is one segment as read: its name and the prefix of it made of
// complete lines, which is what the records came from. A torn tail is not
// in the prefix. Sums holds the SHA-256 (lower-case hex) of the first n
// bytes of the prefix for every n the read summed at, always len(Prefix)
// and, when a memory was consulted, the length it remembered: one pass
// over the bytes serves both the memory's key and trace-consistent
// (tracememory.go).
type gtSegment struct {
	Name   string
	Prefix []byte
	Sums   map[int64]string
}

// gtDecodeMemory is what a member keeps, across cycles, of the last
// successful read of the current boot: for each segment, the records
// decoded from its prefix of complete lines, the SHA-256 of exactly those
// bytes, and the reader's state at both ends of them. It exists so that a
// cycle decodes only the lines that were not there last cycle; the bytes
// are still read in full and hashed in full every cycle, and nothing
// decoded from bytes that are not on the disk now is ever reused. A read
// that fails under any rule empties the memory: a boot that could not be
// read has not been read.
//
// The key of a reuse is content: the boot number, the segment name, the
// remembered length L, the SHA-256 of the first L bytes as read this
// cycle, and the reader's state (next sequence and last timestamp) at the
// segment's start. Identical bytes from an identical start state decode,
// under rules 7 to 10, to identical records and an identical end state,
// so a resumed decode and a full decode are the same function of the
// bytes on the disk. No part of the key is a size or a modification time.
type gtDecodeMemory struct {
	Boot     int64
	Segments map[string]*gtDecodedSegment
	// Reads counts the reads made with the memory, failed ones included,
	// so that a judgement kept of one read (judgememory.go) can tell the
	// read after it from any later one.
	Reads uint64
}

// gtDecodedSegment is one segment of the memory.
type gtDecodedSegment struct {
	// StartNext and StartAt are the reader's state when the segment began:
	// the sequence its first line must carry and the timestamp its first
	// line may not precede.
	StartNext int64
	StartAt   time.Time
	// Length is how many bytes of the prefix the Records were decoded
	// from, and Hash the SHA-256 of exactly those bytes.
	Length int64
	Hash   string
	// Records are the lines of those bytes, decoded. The slice is stored
	// capped (cap == len), so that an append to it, by the boot it is
	// handed to or by anyone, copies rather than writes into the memory;
	// and it is never written to in place.
	Records []gtRecord
	// Next and LastAt are the reader's state after the last record.
	Next   int64
	LastAt time.Time
}

// gtRecord is one line: the header and exactly one body, by Kind.
type gtRecord struct {
	Sequence  int64
	At        time.Time
	Kind      string
	Start     *gtStart
	Accept    *gtAccept
	Handshake *gtHandshake
	ACL       *gtACL
	Close     *gtClose
	Reload    *gtReload
	Shutdown  *gtShutdown
	// A tick has no body: Kind "tick" and the header are all of it.
	AcceptError *gtAcceptError
	Refusal     *gtRefusal
}

type gtStart struct {
	Boot   int64
	PID    int64
	Config gtConfig
}

type gtConfig struct {
	Mode                       string
	Listen                     string
	Target                     string
	ProxyProtocol              string // one of gtProxyProtocols: what the backend is handed ahead of each connection
	StatusListen               *string
	StatusClientCert           bool
	PprofCmdlineRedacted       bool
	ShutdownRequiresClientCert bool
	SessionTickets             bool
	VerifyOnResume             bool
	ACL                        []string // the rule in force, sorted, never empty (README 1.2)
	LifetimeCapSeconds         int64
	SandboxState               string  // one of gtSandboxStates
	SandboxAccepted            *string // the OS an operator accepted no sandbox on; nil otherwise
	Material                   []gtMaterial
	Binary                     gtBinary // the executable the process started from, always present
}

// gtBinary is the start line's config.binary (README 1.2): the path the
// process was executed from with every symbolic link resolved, and the
// SHA-256 of that file's bytes when the process started.
type gtBinary struct {
	Path   string
	SHA256 string
}

type gtMaterial struct {
	Material string
	Path     string
	SHA256   *string
}

type gtAccept struct {
	Conn     int64
	Listener string
	Remote   string
}

type gtHandshake struct {
	Conn     int64
	Outcome  string
	Resumed  bool
	Verified bool
	Protocol string
	Peer     *gtPeer
	Error    *string
	// Chain is the name of the presented chain under gt/chains/ (its
	// content's SHA-256), "" when the line carries none: the key is
	// optional, omitted when the client presented no certificate.
	Chain string
}

type gtPeer struct {
	Subject     string
	Issuer      string
	Serial      string
	SANs        []string
	Fingerprint string
}

type gtACL struct {
	Conn     int64
	Decision string
	Rule     string
	Reason   string
}

type gtClose struct {
	Conn       int64
	Reason     string
	DurationMS int64
}

type gtReload struct {
	Outcome  string
	Error    *string
	Serving  bool
	Material []gtMaterial
}

type gtShutdown struct {
	Source     string
	Authorized bool
	Peer       *string
	Detail     string
}

type gtAcceptError struct {
	Error     string
	BackoffMS int64
}

// gtRefusal is the process refusing to serve until restart, for a reason
// no other line records: what failed (one of gtRefusalSources) and the
// error as it was reported.
type gtRefusal struct {
	Source string
	Error  string
}

// gtACLRuleValid is the rule one config.acl entry is held to (README 1.2):
// a bare token, or a prefix followed by a non-empty value, a hash after
// policy. The flag parser refuses an expectation with it, so that a rule
// the trace could never carry is refused at start rather than compared
// every cycle.
func gtACLRuleValid(rule string) error {
	for _, token := range gtACLTokens {
		if rule == token {
			return nil
		}
	}
	for _, prefix := range gtACLPrefixes {
		if !strings.HasPrefix(rule, prefix) {
			continue
		}
		value := rule[len(prefix):]
		if value == "" {
			return fmt.Errorf("%q has no value", rule)
		}
		if prefix == "policy:" && !gtReHash.MatchString(value) {
			return fmt.Errorf("%q: policy is not followed by a lower-case SHA-256 hex string", rule)
		}
		return nil
	}
	return fmt.Errorf("%q is not in the vocabulary %v %v", rule, gtACLTokens, gtACLPrefixes)
}

// gtBootName is the directory name of a boot number.
func gtBootName(n int64) string { return fmt.Sprintf("%010d", n) }

// gtNumber is the number a ten-digit name carries, or -1.
func gtNumber(name string) int64 {
	if len(name) < 10 {
		return -1
	}
	n, err := strconv.ParseInt(name[:10], 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// gtRoot is the trace root as listed: its entries, or the error listing it
// returned. A cycle lists the root once and hands the listing to every
// check that needs it (gtReadLatestFrom, bootAmbiguousFindings), so that
// the two judge one listing rather than two.
type gtRoot struct {
	Entries []os.DirEntry
	Err     error
}

// gtListRoot lists the trace root now.
func gtListRoot(root string) *gtRoot {
	des, err := os.ReadDir(root)
	return &gtRoot{Entries: des, Err: err}
}

// gtReadLatest reads the highest-numbered boot under root (README 1.3) and
// applies every rule of 1.4 to the root and to that boot, decoding every
// line afresh: it lists the root now and consults no memory. A root that
// cannot be listed, holds anything but ten-digit directories and the
// emitter's lock file, or holds no boot at all is an error; so is any
// malformation of the boot.
func gtReadLatest(root string) (*gtBoot, error) {
	if root == "" {
		return nil, &gtError{Reason: "no trace root configured"}
	}
	return gtReadLatestFrom(root, gtListRoot(root), nil)
}

// gtReadLatestFrom is gtReadLatest over a root already listed, with a
// memory of the last read to resume the decode from (nil decodes every
// line). Rules 1 to 6 run on what the disk holds now, every time; rules 7
// to 10 run on every line the memory does not hold. The records returned
// are, line for line, what a read with no memory returns.
func gtReadLatestFrom(root string, listing *gtRoot, mem *gtDecodeMemory) (*gtBoot, error) {
	if root == "" {
		return nil, &gtError{Reason: "no trace root configured"}
	}
	if listing.Err != nil {
		return nil, &gtError{Reason: listing.Err.Error()}
	}
	highest := int64(-1)
	for _, de := range listing.Entries {
		// Rule 1. de.IsDir is the entry's own type: a symbolic link is not
		// a directory here, and is not tolerated. The emitter's lock
		// (README 1.3) is the one permitted non-boot entry, and only as
		// a regular file: a directory or a link at that name is a stray.
		if de.Name() == "lock" {
			if !de.Type().IsRegular() {
				return nil, &gtError{Rel: "lock", Reason: "the lock is not a regular file"}
			}
			continue
		}
		// The chain store and the material store (SPEC 14.3): the two
		// permitted non-boot directories, and only as directories. Their
		// content is read by the substance rules by name, never listed
		// here.
		if de.Name() == substanceChainsDir || de.Name() == substanceMaterialDir {
			if !de.IsDir() {
				return nil, &gtError{Rel: de.Name(), Reason: "the " + de.Name() + " store is not a directory"}
			}
			continue
		}
		if !de.IsDir() || !gtReBootName.MatchString(de.Name()) {
			return nil, &gtError{Rel: de.Name(), Reason: "unexpected entry under the trace root"}
		}
		if n := gtNumber(de.Name()); n > highest {
			highest = n
		}
	}
	if highest < 0 {
		return nil, &gtError{Reason: "no boot under the trace root"}
	}
	return gtReadBoot(root, highest, mem)
}

// gtDecode decodes one line. It is a variable only so that a test can count
// the lines a read decodes, which is the whole point of the memory.
var gtDecode = gtDecodeLine

// gtReadBoot reads one boot directory said to hold boot number n, resuming
// from mem where its key matches (nil decodes everything). On success mem
// holds this read; on any error it holds nothing.
func gtReadBoot(root string, n int64, mem *gtDecodeMemory) (*gtBoot, error) {
	if mem != nil {
		mem.Reads++
		if mem.Boot != n || mem.Segments == nil {
			mem.Boot = n
			mem.Segments = map[string]*gtDecodedSegment{}
		}
	}
	b, err := gtReadBootWith(root, n, mem)
	if mem != nil {
		if err != nil {
			mem.Segments = map[string]*gtDecodedSegment{}
		} else {
			b.Memory, b.Read = mem, mem.Reads
			// Forget segments that are not on the disk now; the
			// present ones were replaced by this read.
			for name := range mem.Segments {
				if !b.hasSegment(name) {
					delete(mem.Segments, name)
				}
			}
		}
	}
	return b, err
}

func (b *gtBoot) hasSegment(name string) bool {
	for _, seg := range b.Segments {
		if seg.Name == name {
			return true
		}
	}
	return false
}

func gtReadBootWith(root string, n int64, mem *gtDecodeMemory) (*gtBoot, error) {
	rel := gtBootName(n)
	dir := filepath.Join(root, rel)
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, &gtError{Rel: rel, Reason: err.Error()}
	}
	var segments []string
	for _, de := range des {
		// Rule 2.
		if !de.Type().IsRegular() || !gtReSegmentName.MatchString(de.Name()) {
			return nil, &gtError{Rel: rel + "/" + de.Name(), Reason: "unexpected entry in a boot directory"}
		}
		segments = append(segments, de.Name())
	}
	sort.Strings(segments)
	b := &gtBoot{Number: n, Root: root}
	if len(segments) == 0 {
		// Rule 3: a process that died before its first line. Benign to the
		// reader; the checks decide what a boot with no start line means.
		return b, nil
	}
	next := int64(1)
	var lastAt time.Time
	for i, name := range segments {
		segRel := rel + "/" + name
		last := i == len(segments)-1
		// Rule 4.
		if got := gtNumber(name); got != next {
			return nil, &gtError{Rel: segRel, Reason: fmt.Sprintf("segment is named %d but the next sequence is %d", got, next)}
		}
		// The segment rule: data is the segment's content, never the
		// whole of a pre-extended file. The memory's length for the
		// segment sizes the read's buffer and nothing else.
		var hint int64
		if mem != nil {
			if c := mem.Segments[name]; c != nil {
				hint = c.Length
			}
		}
		data, err := gtReadSegment(filepath.Join(dir, name), hint)
		if err != nil {
			return nil, &gtError{Rel: segRel, Reason: err.Error()}
		}
		prefix := data[:len(data)-gtTornLen(data)]
		torn := len(prefix) < len(data)

		// The memory's entry for this segment is a candidate while the
		// prefix is at least as long as it remembers and the reader is in
		// the state it started from; it is used only when the first
		// Length bytes on the disk now hash to what it remembers. The
		// hash pass is one pass whatever the outcome, with a sum taken at
		// the remembered length and at the end.
		var cand *gtDecodedSegment
		if mem != nil {
			if c := mem.Segments[name]; c != nil && int64(len(prefix)) >= c.Length && c.StartNext == next && c.StartAt.Equal(lastAt) {
				cand = c
			}
		}
		var sums map[int64]string
		if cand != nil {
			sums = gtSums(prefix, cand.Length)
			if sums[cand.Length] != cand.Hash {
				cand = nil
			}
		} else {
			sums = gtSums(prefix)
		}
		b.Segments = append(b.Segments, gtSegment{Name: name, Prefix: prefix, Sums: sums})

		// The lines to decode this time: all of them, or those after the
		// remembered length. The line count of rules 5 and 6 counts both.
		var reused int
		var rest []byte
		if cand != nil {
			reused = len(cand.Records)
			rest = prefix[cand.Length:]
		} else {
			rest = prefix
		}
		lines, _ := gtSplitLines(rest)
		count := reused + len(lines)
		// Rule 5.
		if torn && !last {
			return nil, &gtError{Rel: segRel, Line: count + 1, Reason: "torn line in a segment that is not the last"}
		}
		// Rule 6.
		if count == 0 && !last {
			return nil, &gtError{Rel: segRel, Reason: "empty segment that is not the last"}
		}
		startNext, startAt := next, lastAt
		first := len(b.Records)
		if cand != nil && first == 0 && len(lines) == 0 {
			// The boot so far is this segment, and all of it is the
			// memory's: its records are the memory's own slice, which is
			// capped, so that any append to it copies.
			b.Records = cand.Records
		} else {
			b.Records = slices.Grow(b.Records, reused+len(lines))
			if cand != nil {
				b.Records = append(b.Records, cand.Records...)
			}
		}
		if cand != nil {
			if b.Carried == first {
				b.Carried += reused
			}
			next, lastAt = cand.Next, cand.LastAt
		}
		for j, line := range lines {
			lineNo := reused + j + 1
			// Rule 7.
			rec, err := gtDecode(line)
			if err != nil {
				return nil, &gtError{Rel: segRel, Line: lineNo, Reason: err.Error()}
			}
			// Rule 8.
			if rec.Sequence != next {
				return nil, &gtError{Rel: segRel, Line: lineNo, Reason: fmt.Sprintf("sequence %d where %d is expected", rec.Sequence, next)}
			}
			// Rule 9.
			if next == 1 {
				if rec.Kind != "start" {
					return nil, &gtError{Rel: segRel, Line: lineNo, Reason: "the first line of a boot is not a start line"}
				}
				if rec.Start.Boot != n {
					return nil, &gtError{Rel: segRel, Line: lineNo, Reason: fmt.Sprintf("start line names boot %d in the directory of boot %d", rec.Start.Boot, n)}
				}
			} else if rec.Kind == "start" {
				return nil, &gtError{Rel: segRel, Line: lineNo, Reason: "a start line after the first line"}
			}
			// Rule 10.
			if rec.At.Before(lastAt) {
				return nil, &gtError{Rel: segRel, Line: lineNo, Reason: "timestamp goes back"}
			}
			lastAt = rec.At
			b.Records = append(b.Records, rec)
			next++
		}
		if last {
			b.Torn = torn
		}
		if mem != nil {
			// Remember this segment as decoded this time. The records are
			// the boot's own slice, capped so that an append to either
			// copies rather than writes into the other: the next read hands
			// this very slice to its boot when nothing in the segment is
			// new. Every reader of a boot's records, &boot.Records[i]
			// included, only reads them (gtBoot.Records).
			end := len(b.Records)
			mem.Segments[name] = &gtDecodedSegment{
				StartNext: startNext, StartAt: startAt,
				Length: int64(len(prefix)), Hash: sums[int64(len(prefix))],
				Records: b.Records[first:end:end],
				Next:    next, LastAt: lastAt,
			}
		}
	}
	return b, nil
}

// gtReadSegment returns the content of the segment at p by the segment
// rule: its bytes before the first NUL, or all of them when it has none.
// The file is read from its start straight into the buffer the content is
// returned in, at most gtReadChunkBytes per read; the read ends in the
// chunk that holds the first NUL, with the content cut there, or at end of
// file. A segment pre-extended to its maximum size is therefore never read
// whole. hint is a content length this reader read of the segment before
// (the decode memory's Length), never a file size: the buffer is sized to
// it, clamped to gtMaxSegmentBytes, and one chunk more, so that a segment
// read again after a few more lines landed is read with no growth. A wrong
// hint changes only the allocation. The open (openRegular: a named pipe is
// refused, never waited on) and every read go through readRetrying as one
// operation: on Windows a sharing violation on the open or on any chunk
// repeats the whole read from a fresh open, at length 0, within the
// budget, so that the content comes from one open and never from two
// spliced together; after the budget the error is the segment's.
func gtReadSegment(p string, hint int64) ([]byte, error) {
	if hint < 0 {
		hint = 0
	}
	if hint > gtMaxSegmentBytes {
		hint = gtMaxSegmentBytes
	}
	var content []byte
	err := readRetrying(func() error {
		f, _, err := openRegular(p, nil)
		if err != nil {
			return err
		}
		defer f.Close()
		content = make([]byte, 0, hint+gtReadChunkBytes)
		for {
			if len(content) == cap(content) {
				content = gtGrowSegment(content)
			}
			room := content[len(content):cap(content)]
			if len(room) > gtReadChunkBytes {
				room = room[:gtReadChunkBytes]
			}
			n, err := f.Read(room)
			if n > 0 {
				if i := bytes.IndexByte(room[:n], 0); i >= 0 {
					content = content[:len(content)+i]
					return nil
				}
				if len(content)+n > gtMaxSegmentBytes {
					return fmt.Errorf("segment content exceeds %d bytes", gtMaxSegmentBytes)
				}
				content = content[:len(content)+n]
			}
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
		}
	})
	if err != nil {
		return nil, err
	}
	return content, nil
}

// gtGrowSegment returns content with room for at least one more chunk: the
// capacity doubled, and never past gtMaxSegmentBytes and one chunk, which
// is all the read can use before it refuses the segment.
func gtGrowSegment(content []byte) []byte {
	want := 2 * cap(content)
	if want < len(content)+gtReadChunkBytes {
		want = len(content) + gtReadChunkBytes
	}
	if limit := gtMaxSegmentBytes + gtReadChunkBytes; want > limit {
		want = limit
	}
	grown := make([]byte, len(content), want)
	copy(grown, content)
	return grown
}

// gtSums is one SHA-256 pass over b with a sum taken at each length in at
// (each within [0, len(b)]) and at len(b), keyed by length. Sum does not
// change the hash state, so every value is the SHA-256 of exactly that
// prefix, as a separate hash of it would give.
func gtSums(b []byte, at ...int64) map[int64]string {
	lengths := append([]int64{}, at...)
	lengths = append(lengths, int64(len(b)))
	sort.Slice(lengths, func(i, j int) bool { return lengths[i] < lengths[j] })
	out := make(map[int64]string, len(lengths))
	h := sha256.New()
	pos := int64(0)
	for _, n := range lengths {
		if n < pos || n > int64(len(b)) {
			continue
		}
		h.Write(b[pos:n])
		pos = n
		out[n] = hex.EncodeToString(h.Sum(nil))
	}
	return out
}

// gtTornLen is the length of the torn tail of data: the bytes after its last
// line feed, or all of it when it has none.
func gtTornLen(data []byte) int {
	i := bytes.LastIndexByte(data, '\n')
	return len(data) - (i + 1)
}

// gtSplitLines returns the complete lines of data, without their line
// feeds, and whether a torn final line follows them.
func gtSplitLines(data []byte) ([][]byte, bool) {
	var lines [][]byte
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return lines, len(data) > 0
		}
		lines = append(lines, data[:i])
		data = data[i+1:]
	}
}

// gtClassify returns the kind a line's first bytes declare, or "" when they
// do not begin with a marker. The marker is exactly {"kind":"<kind>", with
// no whitespace; classification reads no further (README 1.1).
func gtClassify(line []byte) string {
	for i, k := range gtKinds {
		if bytes.HasPrefix(line, gtKindMarkers[i]) {
			return k
		}
	}
	return ""
}

// gtDecodeLine parses one complete line (without its line feed) strictly
// under README 1.1 and 1.2.
func gtDecodeLine(line []byte) (gtRecord, error) {
	if len(line)+1 > gtMaxLineBytes {
		return gtRecord{}, errors.New("line exceeds 65536 bytes")
	}
	kind := gtClassify(line)
	if kind == "" {
		return gtRecord{}, errors.New("line does not begin with a trace marker")
	}
	if !utf8.Valid(line) {
		return gtRecord{}, errors.New("line is not valid UTF-8")
	}
	obj, err := gtParseTop(line)
	if err != nil {
		return gtRecord{}, err
	}
	keys := gtKindKeys[kind]
	if kind == "handshake" && obj.has("chain") {
		// The one optional key: a handshake names the presented chain
		// under gt/chains/ when the client presented a certificate.
		keys = gtHandshakeChainKeys
	}
	if err := obj.exactly(keys); err != nil {
		return gtRecord{}, err
	}
	rec := gtRecord{Kind: kind}
	k, err := obj.str("kind")
	if err != nil {
		return gtRecord{}, err
	}
	if k != kind {
		return gtRecord{}, errors.New("kind does not match the marker")
	}
	v, err := obj.int("version")
	if err != nil {
		return gtRecord{}, err
	}
	if v != 1 {
		return gtRecord{}, fmt.Errorf("version %d is not 1", v)
	}
	if rec.Sequence, err = obj.int("sequence"); err != nil {
		return gtRecord{}, err
	}
	if rec.Sequence < 1 {
		return gtRecord{}, errors.New("sequence is below 1")
	}
	if rec.At, err = obj.timestamp("at"); err != nil {
		return gtRecord{}, err
	}
	switch kind {
	case "start":
		rec.Start, err = gtDecodeStart(obj)
	case "accept":
		rec.Accept, err = gtDecodeAccept(obj)
	case "handshake":
		rec.Handshake, err = gtDecodeHandshake(obj)
	case "acl":
		rec.ACL, err = gtDecodeACL(obj)
	case "close":
		rec.Close, err = gtDecodeClose(obj)
	case "reload":
		rec.Reload, err = gtDecodeReload(obj)
	case "shutdown":
		rec.Shutdown, err = gtDecodeShutdown(obj)
	case "tick":
		// The header is all of it; exactly() above refused any other key.
	case "accept-error":
		rec.AcceptError, err = gtDecodeAcceptError(obj)
	case "refusal":
		rec.Refusal, err = gtDecodeRefusal(obj)
	}
	if err != nil {
		return gtRecord{}, err
	}
	return rec, nil
}

func gtDecodeStart(obj *gtObject) (*gtStart, error) {
	s := &gtStart{}
	var err error
	if s.Boot, err = obj.int("boot"); err != nil {
		return nil, err
	}
	if s.Boot < 1 {
		return nil, errors.New("boot is below 1")
	}
	if s.PID, err = obj.int("pid"); err != nil {
		return nil, err
	}
	if s.PID < 1 {
		return nil, errors.New("pid is below 1")
	}
	c, err := obj.sub("config", gtConfigKeys)
	if err != nil {
		return nil, err
	}
	cfg := &s.Config
	if cfg.Mode, err = c.enum("mode", gtModes); err != nil {
		return nil, err
	}
	if cfg.Listen, err = c.nonEmpty("listen"); err != nil {
		return nil, err
	}
	if cfg.Target, err = c.nonEmpty("target"); err != nil {
		return nil, err
	}
	if cfg.ProxyProtocol, err = c.enum("proxy_protocol", gtProxyProtocols); err != nil {
		return nil, err
	}
	if cfg.StatusListen, err = c.nullableStr("status_listen"); err != nil {
		return nil, err
	}
	if cfg.StatusClientCert, err = c.boolean("status_client_cert"); err != nil {
		return nil, err
	}
	if cfg.PprofCmdlineRedacted, err = c.boolean("pprof_cmdline_redacted"); err != nil {
		return nil, err
	}
	if cfg.ShutdownRequiresClientCert, err = c.boolean("shutdown_requires_client_cert"); err != nil {
		return nil, err
	}
	if cfg.SessionTickets, err = c.boolean("session_tickets"); err != nil {
		return nil, err
	}
	if cfg.VerifyOnResume, err = c.boolean("verify_on_resume"); err != nil {
		return nil, err
	}
	if cfg.ACL, err = c.acl("acl"); err != nil {
		return nil, err
	}
	if cfg.LifetimeCapSeconds, err = c.int("lifetime_cap_seconds"); err != nil {
		return nil, err
	}
	if cfg.LifetimeCapSeconds < 0 {
		return nil, errors.New("config.lifetime_cap_seconds is negative")
	}
	if cfg.SandboxState, err = c.enum("sandbox_state", gtSandboxStates); err != nil {
		return nil, err
	}
	if cfg.SandboxAccepted, err = c.nullableStr("sandbox_accepted"); err != nil {
		return nil, err
	}
	if cfg.SandboxAccepted != nil {
		// The README constrains only the shapes; the cross-field rule is
		// ghostunnel's, and this reader holds a trace to it: an acceptance
		// is recorded beside "unsupported" and beside nothing else.
		if *cfg.SandboxAccepted == "" {
			return nil, errors.New("config.sandbox_accepted: empty")
		}
		if cfg.SandboxState != "unsupported" {
			return nil, fmt.Errorf("config.sandbox_accepted is set beside sandbox_state %q; ghostunnel writes it only beside \"unsupported\"", cfg.SandboxState)
		}
	}
	if cfg.Material, err = c.materials("material"); err != nil {
		return nil, err
	}
	b, err := c.sub("binary", gtBinaryKeys)
	if err != nil {
		return nil, err
	}
	if cfg.Binary.Path, err = b.nonEmpty("path"); err != nil {
		return nil, fmt.Errorf("config.binary.%v", err)
	}
	if cfg.Binary.SHA256, err = b.hash("sha256"); err != nil {
		return nil, fmt.Errorf("config.binary.%v", err)
	}
	return s, nil
}

func gtDecodeAccept(obj *gtObject) (*gtAccept, error) {
	a := &gtAccept{}
	var err error
	if a.Conn, err = obj.conn(); err != nil {
		return nil, err
	}
	if a.Listener, err = obj.nonEmpty("listener"); err != nil {
		return nil, err
	}
	if a.Remote, err = obj.nonEmpty("remote"); err != nil {
		return nil, err
	}
	return a, nil
}

func gtDecodeHandshake(obj *gtObject) (*gtHandshake, error) {
	h := &gtHandshake{}
	var err error
	if h.Conn, err = obj.conn(); err != nil {
		return nil, err
	}
	if h.Outcome, err = obj.enum("outcome", gtHandshakeOutcome); err != nil {
		return nil, err
	}
	if h.Resumed, err = obj.boolean("resumed"); err != nil {
		return nil, err
	}
	if h.Verified, err = obj.boolean("verified"); err != nil {
		return nil, err
	}
	if h.Protocol, err = obj.str("protocol"); err != nil {
		return nil, err
	}
	if !obj.isNull("peer") {
		p, err := obj.sub("peer", gtPeerKeys)
		if err != nil {
			return nil, err
		}
		peer := &gtPeer{}
		if peer.Subject, err = p.str("subject"); err != nil {
			return nil, err
		}
		if peer.Issuer, err = p.str("issuer"); err != nil {
			return nil, err
		}
		if peer.Serial, err = p.str("serial"); err != nil {
			return nil, err
		}
		if peer.SANs, err = p.strings("sans"); err != nil {
			return nil, err
		}
		for i, san := range peer.SANs {
			ok := false
			for _, pre := range gtSANPrefixes {
				if strings.HasPrefix(san, pre) {
					ok = true
				}
			}
			if !ok {
				return nil, fmt.Errorf("peer.sans[%d]: no dns:, uri:, ip: or email: prefix", i)
			}
		}
		if peer.Fingerprint, err = p.hash("fingerprint"); err != nil {
			return nil, err
		}
		h.Peer = peer
	}
	if h.Error, err = obj.nullableStr("error"); err != nil {
		return nil, err
	}
	if obj.has("chain") {
		if h.Chain, err = obj.hash("chain"); err != nil {
			return nil, err
		}
	}
	return h, nil
}

func gtDecodeACL(obj *gtObject) (*gtACL, error) {
	a := &gtACL{}
	var err error
	if a.Conn, err = obj.conn(); err != nil {
		return nil, err
	}
	if a.Decision, err = obj.enum("decision", gtDecisions); err != nil {
		return nil, err
	}
	if a.Rule, err = obj.nonEmpty("rule"); err != nil {
		return nil, err
	}
	if a.Reason, err = obj.str("reason"); err != nil {
		return nil, err
	}
	return a, nil
}

func gtDecodeClose(obj *gtObject) (*gtClose, error) {
	c := &gtClose{}
	var err error
	if c.Conn, err = obj.conn(); err != nil {
		return nil, err
	}
	if c.Reason, err = obj.enum("reason", gtCloseReasons); err != nil {
		return nil, err
	}
	if c.DurationMS, err = obj.int("duration_ms"); err != nil {
		return nil, err
	}
	if c.DurationMS < 0 {
		return nil, errors.New("duration_ms is negative")
	}
	return c, nil
}

func gtDecodeReload(obj *gtObject) (*gtReload, error) {
	r := &gtReload{}
	var err error
	if r.Outcome, err = obj.enum("outcome", gtReloadOutcomes); err != nil {
		return nil, err
	}
	if r.Error, err = obj.nullableStr("error"); err != nil {
		return nil, err
	}
	if r.Serving, err = obj.boolean("serving"); err != nil {
		return nil, err
	}
	if r.Material, err = obj.materials("material"); err != nil {
		return nil, err
	}
	return r, nil
}

func gtDecodeAcceptError(obj *gtObject) (*gtAcceptError, error) {
	a := &gtAcceptError{}
	var err error
	if a.Error, err = obj.nonEmpty("error"); err != nil {
		return nil, err
	}
	if a.BackoffMS, err = obj.int("backoff_ms"); err != nil {
		return nil, err
	}
	if a.BackoffMS < 0 {
		return nil, errors.New("backoff_ms is negative")
	}
	return a, nil
}

func gtDecodeRefusal(obj *gtObject) (*gtRefusal, error) {
	r := &gtRefusal{}
	var err error
	if r.Source, err = obj.enum("source", gtRefusalSources); err != nil {
		return nil, err
	}
	if r.Error, err = obj.nonEmpty("error"); err != nil {
		return nil, err
	}
	return r, nil
}

func gtDecodeShutdown(obj *gtObject) (*gtShutdown, error) {
	s := &gtShutdown{}
	var err error
	if s.Source, err = obj.enum("source", gtShutdownSources); err != nil {
		return nil, err
	}
	if s.Authorized, err = obj.boolean("authorized"); err != nil {
		return nil, err
	}
	if s.Peer, err = obj.nullableStr("peer"); err != nil {
		return nil, err
	}
	if s.Detail, err = obj.str("detail"); err != nil {
		return nil, err
	}
	return s, nil
}

// ---- the strict object ----

// gtObject is one JSON object as raw values by key, with the key order.
type gtObject struct {
	order []string
	vals  map[string]json.RawMessage
}

// gtParseTop parses b as exactly one object with nothing after it.
func gtParseTop(b []byte) (*gtObject, error) {
	if bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, errors.New("byte-order mark")
	}
	obj, off, err := gtParseObjectAt(b)
	if err != nil {
		return nil, err
	}
	if off != int64(len(b)) {
		return nil, errors.New("bytes after the object")
	}
	return obj, nil
}

// gtParseObjectAt parses one object from the start of b: a string key, a
// value, no duplicate key. It returns the offset just past the object.
func gtParseObjectAt(b []byte) (*gtObject, int64, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, 0, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, 0, errors.New("not a JSON object")
	}
	obj := &gtObject{vals: map[string]json.RawMessage{}}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, 0, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, 0, errors.New("object key is not a string")
		}
		if _, dup := obj.vals[key]; dup {
			return nil, 0, fmt.Errorf("duplicate key %q", key)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, 0, err
		}
		obj.vals[key] = raw
		obj.order = append(obj.order, key)
	}
	if _, err := dec.Token(); err != nil {
		return nil, 0, err
	}
	return obj, dec.InputOffset(), nil
}

// exactly checks the object holds exactly keys.
func (o *gtObject) exactly(keys []string) error {
	for _, k := range keys {
		if _, ok := o.vals[k]; !ok {
			return fmt.Errorf("missing key %q", k)
		}
	}
	if len(o.vals) != len(keys) {
		want := map[string]bool{}
		for _, k := range keys {
			want[k] = true
		}
		for _, k := range o.order {
			if !want[k] {
				return fmt.Errorf("unknown key %q", k)
			}
		}
	}
	return nil
}

func (o *gtObject) raw(k string) []byte { return bytes.TrimSpace(o.vals[k]) }

func (o *gtObject) has(k string) bool { _, ok := o.vals[k]; return ok }

func (o *gtObject) isNull(k string) bool { return bytes.Equal(o.raw(k), []byte("null")) }

// int is a JSON integer: digits only, never a float, a string or null.
func (o *gtObject) int(k string) (int64, error) {
	raw := o.raw(k)
	if !gtIsInteger(raw) {
		return 0, fmt.Errorf("%s: not an integer", k)
	}
	// Eighteen bytes, a sign included, cannot overflow an int64; a longer
	// integer is left to strconv, which refuses one that does.
	if len(raw) <= 18 {
		neg := raw[0] == '-'
		digits := raw
		if neg {
			digits = raw[1:]
		}
		var n int64
		for _, c := range digits {
			n = n*10 + int64(c-'0')
		}
		if neg {
			n = -n
		}
		return n, nil
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %v", k, err)
	}
	return n, nil
}

// gtIsInteger reports whether raw is a JSON integer as gtReInteger spells
// it, ^-?(0|[1-9][0-9]*)$: an optional minus, then 0 alone or a digit
// other than 0 followed by digits, and nothing else.
func gtIsInteger(raw []byte) bool {
	i := 0
	if i < len(raw) && raw[i] == '-' {
		i++
	}
	if i == len(raw) {
		return false
	}
	if raw[i] == '0' {
		return i+1 == len(raw)
	}
	for ; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return false
		}
	}
	return true
}

// conn is the connection id every connection line carries, at least 1.
func (o *gtObject) conn() (int64, error) {
	n, err := o.int("conn")
	if err != nil {
		return 0, err
	}
	if n < 1 {
		return 0, errors.New("conn is below 1")
	}
	return n, nil
}

// str is a JSON string that carries no PEM header (README 1.1).
func (o *gtObject) str(k string) (string, error) {
	return gtStr(o.raw(k), k)
}

// gtStr is str over one raw value. A value that is a quote, bytes with no
// backslash, no quote and no control byte that are valid UTF-8, and a
// quote, decodes to exactly those bytes, which is what json.Unmarshal
// gives for it; they are taken directly. Every other value is decoded by
// json.Unmarshal.
func gtStr(raw []byte, k string) (string, error) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", fmt.Errorf("%s: not a string", k)
	}
	s, ok := gtPlainString(raw)
	if !ok {
		var err error
		if s, err = gtUnmarshalString(raw); err != nil {
			return "", fmt.Errorf("%s: not a string", k)
		}
	}
	if strings.Contains(s, "-----BEGIN") {
		return "", fmt.Errorf("%s: carries a PEM block", k)
	}
	return s, nil
}

// gtUnmarshalString is json.Unmarshal of raw into a string. It is a
// function of its own so that the string json.Unmarshal is handed the
// address of is not gtStr's, which then stays off the heap.
func gtUnmarshalString(raw []byte) (string, error) {
	var s string
	err := json.Unmarshal(raw, &s)
	return s, err
}

// gtPlainString returns the bytes between the quotes of raw, as a string,
// when raw is a JSON string that needs no decoding: nothing but those
// bytes between two quotes, none of them a backslash, a quote or a control
// byte (below 0x20), and all of them valid UTF-8.
func gtPlainString(raw []byte) (string, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return "", false
	}
	inner := raw[1 : len(raw)-1]
	for _, c := range inner {
		if c == '\\' || c == '"' || c < 0x20 {
			return "", false
		}
	}
	if !utf8.Valid(inner) {
		return "", false
	}
	return string(inner), true
}

func (o *gtObject) nonEmpty(k string) (string, error) {
	s, err := o.str(k)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", fmt.Errorf("%s: empty", k)
	}
	return s, nil
}

func (o *gtObject) enum(k string, set []string) (string, error) {
	s, err := o.str(k)
	if err != nil {
		return "", err
	}
	for _, v := range set {
		if s == v {
			return s, nil
		}
	}
	return "", fmt.Errorf("%s: %q is not one of %v", k, s, set)
}

func (o *gtObject) nullableStr(k string) (*string, error) {
	if o.isNull(k) {
		return nil, nil
	}
	s, err := o.str(k)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (o *gtObject) boolean(k string) (bool, error) {
	switch string(o.raw(k)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("%s: not a boolean", k)
}

func (o *gtObject) hash(k string) (string, error) {
	s, err := o.str(k)
	if err != nil {
		return "", err
	}
	if !gtReHash.MatchString(s) {
		return "", fmt.Errorf("%s: not a lower-case SHA-256 hex string", k)
	}
	return s, nil
}

func (o *gtObject) timestamp(k string) (time.Time, error) {
	s, err := o.str(k)
	if err != nil {
		return time.Time{}, err
	}
	if len(s) != len(gtTimestampLayout) {
		return time.Time{}, fmt.Errorf("%s: not of the form YYYY-MM-DDTHH:MM:SSZ", k)
	}
	t, err := time.Parse(gtTimestampLayout, s)
	if err != nil || t.UTC().Format(gtTimestampLayout) != s {
		return time.Time{}, fmt.Errorf("%s: not a canonical UTC timestamp", k)
	}
	return t.UTC(), nil
}

// array returns the raw items of a JSON array, never null.
func (o *gtObject) array(k string) ([]json.RawMessage, error) {
	raw := o.raw(k)
	if len(raw) == 0 || raw[0] != '[' {
		return nil, fmt.Errorf("%s: not an array", k)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("%s: not an array", k)
	}
	return items, nil
}

func (o *gtObject) strings(k string) ([]string, error) {
	items, err := o.array(k)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(items))
	for i, it := range items {
		s, err := gtStr(bytes.TrimSpace(it), "x")
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: not a string", k, i)
		}
		out = append(out, s)
	}
	return out, nil
}

// acl decodes config.acl (README 1.2): a non-empty array of strings, each
// in the closed vocabulary (gtACLRuleValid), strictly ascending in byte
// order so that the list is sorted and holds no duplicate. Anything else
// is malformed.
func (o *gtObject) acl(k string) ([]string, error) {
	rules, err := o.strings(k)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("%s: empty", k)
	}
	for i, rule := range rules {
		if err := gtACLRuleValid(rule); err != nil {
			return nil, fmt.Errorf("%s[%d]: %v", k, i, err)
		}
		if i > 0 && rule <= rules[i-1] {
			return nil, fmt.Errorf("%s[%d]: %q is not sorted after %q, or repeats it", k, i, rule, rules[i-1])
		}
	}
	return rules, nil
}

// sub decodes a nested value as a strict object with exactly keys.
func (o *gtObject) sub(k string, keys []string) (*gtObject, error) {
	return gtSubobject(o.raw(k), k, keys)
}

func gtSubobject(raw []byte, name string, keys []string) (*gtObject, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, fmt.Errorf("%s: not an object", name)
	}
	obj, off, err := gtParseObjectAt(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	if len(bytes.TrimSpace(raw[off:])) != 0 {
		return nil, fmt.Errorf("%s: bytes after the object", name)
	}
	if err := obj.exactly(keys); err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	return obj, nil
}

// materials decodes an array of material objects (README 1.2): a closed
// kind, a path, and a hash that is null for a key and may be null otherwise.
func (o *gtObject) materials(k string) ([]gtMaterial, error) {
	items, err := o.array(k)
	if err != nil {
		return nil, err
	}
	out := make([]gtMaterial, 0, len(items))
	for i, it := range items {
		name := fmt.Sprintf("%s[%d]", k, i)
		m, err := gtSubobject(bytes.TrimSpace(it), name, gtMaterialKeys)
		if err != nil {
			return nil, err
		}
		var mat gtMaterial
		if mat.Material, err = m.enum("material", gtMaterials); err != nil {
			return nil, fmt.Errorf("%s.%v", name, err)
		}
		if mat.Path, err = m.str("path"); err != nil {
			return nil, fmt.Errorf("%s.%v", name, err)
		}
		if !m.isNull("sha256") {
			h, err := m.hash("sha256")
			if err != nil {
				return nil, fmt.Errorf("%s.%v", name, err)
			}
			if mat.Material == "key" {
				return nil, fmt.Errorf("%s: a key never carries a hash", name)
			}
			mat.SHA256 = &h
		}
		out = append(out, mat)
	}
	return out, nil
}
