package main

// encoding.go implements SPEC 3: the three file kinds, classification by
// prefix before parsing (3.1), strict key sets (3.1), timestamps and hashes
// (3.1, 3.5), sizes checked before content is read (3.1), and the marker rule
// that lets a truncated or misplaced file be classified without a parser.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"
)

// Kind is a file kind of SPEC 3.
type Kind string

const (
	KindHeartbeat Kind = "heartbeat"
	KindFault     Kind = "fault"
	KindHalt      Kind = "halt"
)

// markers are the exact first bytes of each kind (SPEC 3.1).
var markers = map[Kind][]byte{
	KindHeartbeat: []byte(`{"kind":"heartbeat",`),
	KindFault:     []byte(`{"kind":"fault",`),
	KindHalt:      []byte(`{"kind":"halt",`),
}

// markerMax is the longest marker, the number of bytes classification needs.
const markerMax = 20

// Name patterns (SPEC 3.2, 6.1 C1, 14.1).
var (
	reHeartbeatName = regexp.MustCompile(`^[0-9]{10}\.hb$`)
	reStagingName   = regexp.MustCompile(`^[0-9]{10}\.hb\.tmp$`)
	reTraceName     = regexp.MustCompile(`^[0-9]{10}\.trace$`)
	reHash          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reInteger       = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
)

// maxSequence is the largest sequence a name can carry (SPEC 3.2).
const maxSequence int64 = 9999999999

// timestampLayout is SPEC 3.1: YYYY-MM-DDTHH:MM:SSZ, UTC, whole seconds.
const timestampLayout = "2006-01-02T15:04:05Z"

// classify returns the kind whose marker the bytes begin with, or "" when
// they begin with none (SPEC 3.1). It reads no further than the marker.
func classify(b []byte) Kind {
	for kind, marker := range markers {
		if bytes.HasPrefix(b, marker) {
			return kind
		}
	}
	return ""
}

// sha256Hex is SPEC 3.5: SHA-256 over the whole file as bytes on disk,
// written as 64 lower-case hexadecimal characters.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// formatTimestamp writes t in the form of SPEC 3.1.
func formatTimestamp(t time.Time) string {
	return t.UTC().Format(timestampLayout)
}

// parseTimestamp accepts exactly the form of SPEC 3.1.
func parseTimestamp(s string) (time.Time, error) {
	if len(s) != len(timestampLayout) {
		return time.Time{}, fmt.Errorf("timestamp %q is not of the form YYYY-MM-DDTHH:MM:SSZ", s)
	}
	t, err := time.Parse(timestampLayout, s)
	if err != nil {
		return time.Time{}, err
	}
	// time.Parse tolerates nothing here, but the round trip is the proof.
	if t.Format(timestampLayout) != s {
		return time.Time{}, fmt.Errorf("timestamp %q is not canonical", s)
	}
	return t, nil
}

// sequenceOfName returns the integer a heartbeat or staging name carries.
func sequenceOfName(name string) int64 {
	n, err := strconv.ParseInt(name[:10], 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// heartbeatName is the file name for a sequence (SPEC 3.2).
func heartbeatName(seq int64) string {
	return fmt.Sprintf("%010d.hb", seq)
}

// readBounded stats a file, refuses one larger than max without reading it,
// and otherwise returns its bytes (SPEC 3.1: sizes are checked before
// content). oversized is true when the bound was exceeded; err reports a
// file that could not be read at all. The open and the read go through
// readRetrying: on Windows a handle held elsewhere for an instant is waited
// out within a bounded budget, and a file still unreadable after it fails.
func readBounded(path string, max int64) (data []byte, oversized bool, err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > max {
		return nil, true, nil
	}
	err = readRetrying(func() error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		// The file may have grown between the stat and the read; the
		// bound holds over what is actually read.
		data, err = io.ReadAll(io.LimitReader(f, max+1))
		return err
	})
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > max {
		return nil, true, nil
	}
	return data, false, nil
}

// readPrefix returns the first markerMax bytes of a file, for classification
// of a file at a place where no kind is expected (SPEC 6.1 C1, 9 K2, 10.2 H2,
// 11.2). A file that cannot be read classifies as nothing; the open goes
// through readRetrying as readBounded's does.
func readPrefix(path string) []byte {
	var prefix []byte
	err := readRetrying(func() error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		buf := make([]byte, markerMax)
		n, _ := io.ReadFull(f, buf)
		prefix = buf[:n]
		return nil
	})
	if err != nil {
		return nil
	}
	return prefix
}

// ---- strict JSON ----

// rawObject is a decoded top-level object with its keys' raw values.
type rawObject map[string]json.RawMessage

// decodeStrictObject decodes exactly one JSON object from b: UTF-8 without a
// byte-order mark, no duplicate keys, nothing after the object but at most
// one line feed (SPEC 3.1), and exactly the given key set.
func decodeStrictObject(b []byte, keys []string) (rawObject, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("not valid UTF-8")
	}
	if bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, errors.New("byte-order mark")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	obj := rawObject{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		if _, dup := obj[key]; dup {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		obj[key] = raw
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, err
	}
	rest := b[dec.InputOffset():]
	if len(rest) != 0 && !bytes.Equal(rest, []byte("\n")) {
		return nil, errors.New("bytes after the object")
	}
	if err := exactKeys(obj, keys); err != nil {
		return nil, err
	}
	return obj, nil
}

// decodeStrictSubobject applies the same key discipline to a nested value.
func decodeStrictSubobject(raw json.RawMessage, keys []string) (rawObject, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	obj := rawObject{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		if _, dup := obj[key]; dup {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		obj[key] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if err := exactKeys(obj, keys); err != nil {
		return nil, err
	}
	return obj, nil
}

func exactKeys(obj rawObject, keys []string) error {
	for _, k := range keys {
		if _, ok := obj[k]; !ok {
			return fmt.Errorf("missing key %q", k)
		}
	}
	if len(obj) != len(keys) {
		for k := range obj {
			found := false
			for _, want := range keys {
				if k == want {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("unknown key %q", k)
			}
		}
	}
	return nil
}

func isNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

func intField(raw json.RawMessage, name string) (int64, error) {
	// json.Number also accepts a quoted number; a string is not an integer.
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] == '"' {
		return 0, fmt.Errorf("%s: not an integer", name)
	}
	var n json.Number
	if err := json.Unmarshal(trimmed, &n); err != nil {
		return 0, fmt.Errorf("%s: not an integer", name)
	}
	if !reInteger.MatchString(n.String()) {
		return 0, fmt.Errorf("%s: not an integer", name)
	}
	v, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %v", name, err)
	}
	return v, nil
}

func stringField(raw json.RawMessage, name string) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || isNull(raw) {
		return "", fmt.Errorf("%s: not a string", name)
	}
	return s, nil
}

func boolField(raw json.RawMessage, name string) (bool, error) {
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil || isNull(raw) {
		return false, fmt.Errorf("%s: not a boolean", name)
	}
	return b, nil
}

func nullableString(raw json.RawMessage, name string) (*string, error) {
	if isNull(raw) {
		return nil, nil
	}
	s, err := stringField(raw, name)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func nullableInt(raw json.RawMessage, name string) (*int64, error) {
	if isNull(raw) {
		return nil, nil
	}
	n, err := intField(raw, name)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func nullableHash(raw json.RawMessage, name string) (*string, error) {
	s, err := nullableString(raw, name)
	if err != nil {
		return nil, err
	}
	if s != nil && !reHash.MatchString(*s) {
		return nil, fmt.Errorf("%s: not a lower-case SHA-256 hex string", name)
	}
	return s, nil
}

func stringArray(raw json.RawMessage, name string) ([]string, error) {
	if isNull(raw) {
		return nil, fmt.Errorf("%s: not an array", name)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("%s: not an array", name)
	}
	out := make([]string, 0, len(items))
	for i, it := range items {
		s, err := stringField(it, fmt.Sprintf("%s[%d]", name, i))
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func timestampField(raw json.RawMessage, name string) (string, error) {
	s, err := stringField(raw, name)
	if err != nil {
		return "", err
	}
	if _, err := parseTimestamp(s); err != nil {
		return "", fmt.Errorf("%s: %v", name, err)
	}
	return s, nil
}

// checkCommon verifies kind, version and observer as every kind shares them.
func checkCommon(obj rawObject, kind Kind) (observer string, err error) {
	k, err := stringField(obj["kind"], "kind")
	if err != nil {
		return "", err
	}
	if Kind(k) != kind {
		return "", fmt.Errorf("kind %q where %q is required", k, kind)
	}
	v, err := intField(obj["version"], "version")
	if err != nil {
		return "", err
	}
	if v != 1 {
		return "", fmt.Errorf("version %d is not 1", v)
	}
	observer, err = stringField(obj["observer"], "observer")
	if err != nil {
		return "", err
	}
	if observer == "" {
		return "", errors.New("observer is empty")
	}
	return observer, nil
}

// ---- heartbeat (SPEC 3.2) ----

// Heartbeat is a parsed heartbeat file.
type Heartbeat struct {
	Observer       string
	Sequence       int64
	Timestamp      string
	CadenceSeconds int64
	Checks         []string
	CheckCount     int64
	Observed       map[string]*string
	Previous       *string
	Boot           *BootRecord
	Stop           bool
}

var heartbeatKeys = []string{"kind", "version", "observer", "sequence", "timestamp", "cadence_seconds", "checks", "check_count", "observed", "previous", "boot", "stop"}

// parseHeartbeat parses b strictly under SPEC 3.2. members is the declared
// membership: observed must hold exactly the members other than the writer.
// It does not check observer or sequence against the place the file was
// found at; procedure C does that (C5).
func parseHeartbeat(b []byte, members []string) (*Heartbeat, error) {
	if classify(b) != KindHeartbeat {
		return nil, errors.New("does not begin with the heartbeat marker")
	}
	obj, err := decodeStrictObject(b, heartbeatKeys)
	if err != nil {
		return nil, err
	}
	hb := &Heartbeat{}
	if hb.Observer, err = checkCommon(obj, KindHeartbeat); err != nil {
		return nil, err
	}
	if hb.Sequence, err = intField(obj["sequence"], "sequence"); err != nil {
		return nil, err
	}
	if hb.Sequence < 1 || hb.Sequence > maxSequence {
		return nil, fmt.Errorf("sequence %d out of range", hb.Sequence)
	}
	if hb.Timestamp, err = timestampField(obj["timestamp"], "timestamp"); err != nil {
		return nil, err
	}
	if hb.CadenceSeconds, err = intField(obj["cadence_seconds"], "cadence_seconds"); err != nil {
		return nil, err
	}
	if hb.CadenceSeconds < 1 {
		return nil, fmt.Errorf("cadence_seconds %d is below 1", hb.CadenceSeconds)
	}
	if hb.Checks, err = stringArray(obj["checks"], "checks"); err != nil {
		return nil, err
	}
	if hb.CheckCount, err = intField(obj["check_count"], "check_count"); err != nil {
		return nil, err
	}
	if hb.CheckCount < 0 {
		return nil, errors.New("check_count is negative")
	}
	// observed: exactly the other members, each a hash or null, decoded
	// as strictly as the object around it: a key that repeats is refused,
	// not resolved to its last value. The gate reads the coordinator's
	// heartbeat by the same rule (ringtrace/jsonstrict.go), and the four
	// members and the gate must refuse the same bytes.
	if isNull(obj["observed"]) {
		return nil, errors.New("observed: not an object")
	}
	want := make([]string, 0, len(members))
	for _, m := range members {
		if m != hb.Observer {
			want = append(want, m)
		}
	}
	obs, err := decodeStrictSubobject(obj["observed"], want)
	if err != nil {
		return nil, fmt.Errorf("observed: %v", err)
	}
	hb.Observed = make(map[string]*string, len(obs))
	for k, v := range obs {
		h, err := nullableHash(v, "observed."+k)
		if err != nil {
			return nil, err
		}
		hb.Observed[k] = h
	}
	if hb.Previous, err = nullableHash(obj["previous"], "previous"); err != nil {
		return nil, err
	}
	if !isNull(obj["boot"]) {
		boot, err := decodeStrictSubobject(obj["boot"], []string{"started", "resumed_from"})
		if err != nil {
			return nil, fmt.Errorf("boot: %v", err)
		}
		hb.Boot = &BootRecord{}
		if hb.Boot.Started, err = timestampField(boot["started"], "boot.started"); err != nil {
			return nil, err
		}
		if hb.Boot.ResumedFrom, err = nullableInt(boot["resumed_from"], "boot.resumed_from"); err != nil {
			return nil, err
		}
	}
	if hb.Stop, err = boolField(obj["stop"], "stop"); err != nil {
		return nil, err
	}
	return hb, nil
}

// heartbeatJSON is the wire form; field order fixes the marker as the first
// bytes and encoding/json writes map keys sorted, which the strict reader
// does not need but people do.
type heartbeatJSON struct {
	Kind           string             `json:"kind"`
	Version        int                `json:"version"`
	Observer       string             `json:"observer"`
	Sequence       int64              `json:"sequence"`
	Timestamp      string             `json:"timestamp"`
	CadenceSeconds int64              `json:"cadence_seconds"`
	Checks         []string           `json:"checks"`
	CheckCount     int64              `json:"check_count"`
	Observed       map[string]*string `json:"observed"`
	Previous       *string            `json:"previous"`
	Boot           *bootJSON          `json:"boot"`
	Stop           bool               `json:"stop"`
}

type bootJSON struct {
	Started     string `json:"started"`
	ResumedFrom *int64 `json:"resumed_from"`
}

// encodeHeartbeat produces the file bytes for a heartbeat: the marker first,
// one trailing line feed (SPEC 3.1).
func encodeHeartbeat(hb *Heartbeat) ([]byte, error) {
	w := heartbeatJSON{
		Kind:           string(KindHeartbeat),
		Version:        1,
		Observer:       hb.Observer,
		Sequence:       hb.Sequence,
		Timestamp:      hb.Timestamp,
		CadenceSeconds: hb.CadenceSeconds,
		Checks:         hb.Checks,
		CheckCount:     hb.CheckCount,
		Observed:       hb.Observed,
		Previous:       hb.Previous,
		Stop:           hb.Stop,
	}
	if w.Checks == nil {
		w.Checks = []string{}
	}
	if w.Observed == nil {
		w.Observed = map[string]*string{}
	}
	if hb.Boot != nil {
		w.Boot = &bootJSON{Started: hb.Boot.Started, ResumedFrom: hb.Boot.ResumedFrom}
	}
	b, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ---- fault (SPEC 3.3) ----

// Fault is a parsed fault file.
type Fault struct {
	Observer string
	Failing  []Finding
}

var faultKeys = []string{"kind", "version", "observer", "failing"}

// parseFault parses b strictly under SPEC 3.3.
func parseFault(b []byte) (*Fault, error) {
	if classify(b) != KindFault {
		return nil, errors.New("does not begin with the fault marker")
	}
	obj, err := decodeStrictObject(b, faultKeys)
	if err != nil {
		return nil, err
	}
	f := &Fault{}
	if f.Observer, err = checkCommon(obj, KindFault); err != nil {
		return nil, err
	}
	if isNull(obj["failing"]) {
		return nil, errors.New("failing: not an array")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(obj["failing"], &items); err != nil {
		return nil, errors.New("failing: not an array")
	}
	if len(items) == 0 {
		return nil, errors.New("failing: empty")
	}
	for i, it := range items {
		entry, err := decodeStrictSubobject(it, []string{"check", "subject"})
		if err != nil {
			return nil, fmt.Errorf("failing[%d]: %v", i, err)
		}
		check, err := stringField(entry["check"], "check")
		if err != nil {
			return nil, fmt.Errorf("failing[%d]: %v", i, err)
		}
		subject, err := nullableString(entry["subject"], "subject")
		if err != nil {
			return nil, fmt.Errorf("failing[%d]: %v", i, err)
		}
		fd := Finding{Check: check}
		if subject != nil {
			fd.Subject = *subject
		}
		f.Failing = append(f.Failing, fd)
	}
	return f, nil
}

type faultJSON struct {
	Kind     string        `json:"kind"`
	Version  int           `json:"version"`
	Observer string        `json:"observer"`
	Failing  []findingJSON `json:"failing"`
}

type findingJSON struct {
	Check   string  `json:"check"`
	Subject *string `json:"subject"`
}

// encodeFault produces the file bytes for a fault. The same failing set
// always yields the same bytes (SPEC 3.3): entries are written in a fixed
// order, sorted by check then subject.
func encodeFault(observer string, failing []Finding) ([]byte, error) {
	sorted := append([]Finding(nil), failing...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Check != sorted[j].Check {
			return sorted[i].Check < sorted[j].Check
		}
		return sorted[i].Subject < sorted[j].Subject
	})
	w := faultJSON{Kind: string(KindFault), Version: 1, Observer: observer, Failing: []findingJSON{}}
	for _, f := range sorted {
		w.Failing = append(w.Failing, findingJSON{Check: f.Check, Subject: f.SubjectPtr()})
	}
	b, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ---- halt (SPEC 3.4) ----

// Halt is a parsed halt file.
type Halt struct {
	Observer string
	Reason   string
	Subject  *string
	Sequence int64
	When     string
	Detail   string
}

var haltKeys = []string{"kind", "version", "observer", "reason", "subject", "sequence", "when", "detail"}

// parseHalt parses b strictly under SPEC 3.4.
func parseHalt(b []byte) (*Halt, error) {
	if classify(b) != KindHalt {
		return nil, errors.New("does not begin with the halt marker")
	}
	obj, err := decodeStrictObject(b, haltKeys)
	if err != nil {
		return nil, err
	}
	h := &Halt{}
	if h.Observer, err = checkCommon(obj, KindHalt); err != nil {
		return nil, err
	}
	if h.Reason, err = stringField(obj["reason"], "reason"); err != nil {
		return nil, err
	}
	if h.Subject, err = nullableString(obj["subject"], "subject"); err != nil {
		return nil, err
	}
	if h.Sequence, err = intField(obj["sequence"], "sequence"); err != nil {
		return nil, err
	}
	if h.When, err = timestampField(obj["when"], "when"); err != nil {
		return nil, err
	}
	if h.Detail, err = stringField(obj["detail"], "detail"); err != nil {
		return nil, err
	}
	return h, nil
}

type haltJSON struct {
	Kind     string  `json:"kind"`
	Version  int     `json:"version"`
	Observer string  `json:"observer"`
	Reason   string  `json:"reason"`
	Subject  *string `json:"subject"`
	Sequence int64   `json:"sequence"`
	When     string  `json:"when"`
	Detail   string  `json:"detail"`
}

// encodeHalt produces the file bytes for a halt.
func encodeHalt(h *Halt) ([]byte, error) {
	b, err := json.Marshal(haltJSON{
		Kind: string(KindHalt), Version: 1, Observer: h.Observer, Reason: h.Reason,
		Subject: h.Subject, Sequence: h.Sequence, When: h.When, Detail: h.Detail,
	})
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
