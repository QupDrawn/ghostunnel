package main

// store.go reads the tree. Everything here opens files for reading and
// nothing else; a file that cannot be read or will not parse comes back as
// nil or as a marked state, never as a crash and never as a silent skip.
//
// The parsing is deliberately the small, loose kind an outsider needs: the
// members validate their files strictly against the spec, and this tool only
// has to display what they wrote. It does check the kind marker, because a
// file in a heartbeat folder that does not begin with the heartbeat marker is
// not a heartbeat whatever else it contains.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	markerHeartbeat = []byte(`{"kind":"heartbeat",`)
	markerFault     = []byte(`{"kind":"fault",`)
	markerHalt      = []byte(`{"kind":"halt",`)

	// The since file: exactly one timestamp and one line feed.
	reSince = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\n$`)
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func heartbeatName(seq int64) string { return fmt.Sprintf("%010d.hb", seq) }

// parseTimestamp accepts exactly YYYY-MM-DDTHH:MM:SSZ, round-tripped so a
// date that does not exist is not a date.
func parseTimestamp(s string) (time.Time, bool) {
	t, err := time.Parse(timestampLayout, s)
	if err != nil || t.UTC().Format(timestampLayout) != s {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// ---- heartbeats -----------------------------------------------------------

type heartbeat struct {
	Observer       string             `json:"observer"`
	Sequence       int64              `json:"sequence"`
	Timestamp      string             `json:"timestamp"`
	CadenceSeconds int64              `json:"cadence_seconds"`
	Checks         []string           `json:"checks"`
	CheckCount     *int64             `json:"check_count"`
	Observed       map[string]*string `json:"observed"`
	Boot           json.RawMessage    `json:"boot"`
	Stop           bool               `json:"stop"`
}

// booted reports whether the heartbeat carries a boot record.
func (hb *heartbeat) booted() bool {
	return len(hb.Boot) > 0 && !bytes.Equal(bytes.TrimSpace(hb.Boot), []byte("null"))
}

// checkCount is what the member reported, or the length of its list when it
// reported nothing.
func (hb *heartbeat) checkCount() int64 {
	if hb.CheckCount != nil {
		return *hb.CheckCount
	}
	return int64(len(hb.Checks))
}

// heartbeatFiles lists the .hb entries of a folder in name order, which is
// sequence order. Entries that are not regular files are listed too, so a
// folder whose newest entry cannot be read shows up as exactly that.
func heartbeatFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".hb") {
			out = append(out, e.Name())
		}
	}
	return out
}

// folder is a heartbeat folder by the hash of each file's bytes, because a
// hash over the whole file is what a reader records having seen. An entry
// whose bytes cannot be read is simply not in it: a hash that is not found
// among the readable files reads as past.
type folder struct {
	names []string       // readable entries, in sequence order
	index map[string]int // hash -> position in names
}

func scanFolder(dir string) folder {
	f := folder{index: map[string]int{}}
	for _, name := range heartbeatFiles(dir) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		f.index[sha256Hex(b)] = len(f.names)
		f.names = append(f.names, name)
	}
	return f
}

// behind returns how many publications the hash is behind the newest, or
// -1 when it is not in the folder at all.
func (f folder) behind(hash string) int {
	i, ok := f.index[hash]
	if !ok {
		return -1
	}
	return len(f.names) - 1 - i
}

func readHeartbeat(path string) *heartbeat {
	b, err := os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(b, markerHeartbeat) {
		return nil
	}
	var hb heartbeat
	if err := json.Unmarshal(b, &hb); err != nil {
		return nil
	}
	return &hb
}

// latestHeartbeat is the newest entry of a folder, or nil when there is none
// or it will not read as a heartbeat. The newest is what a gate reads, so a
// broken newest is a missing heartbeat whatever the older ones say.
func latestHeartbeat(dir string) *heartbeat {
	files := heartbeatFiles(dir)
	if len(files) == 0 {
		return nil
	}
	return readHeartbeat(filepath.Join(dir, files[len(files)-1]))
}

// sequenceOf is the sequence the newest entry's name carries, read without
// opening the file, so sampling it for the rate column costs nothing.
func sequenceOf(dir string) *int64 {
	files := heartbeatFiles(dir)
	if len(files) == 0 {
		return nil
	}
	name := files[len(files)-1]
	n, err := strconv.ParseInt(strings.TrimSuffix(name, ".hb"), 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

func sampleSequences(stores string) map[string]*int64 {
	out := make(map[string]*int64, len(members))
	for _, m := range members {
		out[m] = sequenceOf(filepath.Join(stores, m, "heartbeat"))
	}
	return out
}

// ratesBetween is seconds per cycle for each member, from two samplings of
// the sequence numbers a known interval apart. Measured this way rather than
// from the timestamps inside the files, which are whole seconds while a cycle
// takes a fraction of one. No progress, or a sequence that went backwards, or
// no interval, is no rate.
func ratesBetween(before, after map[string]*int64, seconds float64) map[string]*float64 {
	out := make(map[string]*float64, len(members))
	for _, m := range members {
		a, b := before[m], after[m]
		if a == nil || b == nil || *b <= *a || seconds <= 0 {
			out[m] = nil
			continue
		}
		r := seconds / float64(*b-*a)
		out[m] = &r
	}
	return out
}

// ---- since ----------------------------------------------------------------

// observingSince reads the file a member writes once and never rewrites. It
// is the only durable record of how long a store has been observed: the
// cadence is a ceiling rather than a pace, so a count of cycles is not a
// unit of time, and this is what makes the age column honest. Anything but
// the exact form is nil.
func observingSince(root string) *time.Time {
	b, err := os.ReadFile(filepath.Join(root, "since"))
	if err != nil {
		return nil
	}
	m := reSince.FindSubmatch(b)
	if m == nil {
		return nil
	}
	t, ok := parseTimestamp(string(m[1]))
	if !ok {
		return nil
	}
	return &t
}

// ---- fault, halt, slots ---------------------------------------------------

// faultFile is a member's fault file as found: present or not, and if
// present, either the failing set or the fact that it would not parse.
type faultFile struct {
	present  bool
	readable bool
	failing  []string // check:subject, unique, in file order
}

func readFault(path string) faultFile {
	b, err := os.ReadFile(path)
	if err != nil {
		if info, statErr := os.Lstat(path); statErr == nil && !info.IsDir() {
			return faultFile{present: true}
		}
		return faultFile{}
	}
	f := faultFile{present: true}
	if !bytes.HasPrefix(b, markerFault) {
		return f
	}
	var parsed struct {
		Failing []struct {
			Check   string  `json:"check"`
			Subject *string `json:"subject"`
		} `json:"failing"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		return f
	}
	f.readable = true
	seen := map[string]bool{}
	for _, e := range parsed.Failing {
		name := e.Check
		if e.Subject != nil && *e.Subject != "" {
			name += ":" + *e.Subject
		}
		if !seen[name] {
			seen[name] = true
			f.failing = append(f.failing, name)
		}
	}
	return f
}

type haltInfo struct {
	Observer string  `json:"observer"`
	Reason   string  `json:"reason"`
	Subject  *string `json:"subject"`
	When     string  `json:"when"`
}

// haltFile is a halt file or slot as found: present or not, and if present,
// what it says or nil when it would not parse.
type haltFile struct {
	present bool
	info    *haltInfo
}

func readHalt(path string) haltFile {
	b, err := os.ReadFile(path)
	if err != nil {
		if info, statErr := os.Lstat(path); statErr == nil && !info.IsDir() {
			return haltFile{present: true}
		}
		return haltFile{}
	}
	h := haltFile{present: true}
	if !bytes.HasPrefix(b, markerHalt) {
		return h
	}
	var parsed haltInfo
	if err := json.Unmarshal(b, &parsed); err != nil {
		return h
	}
	h.info = &parsed
	return h
}

// slotsIn lists the halts/ folder: each entry is a halt delivered by the
// member it is named after.
func slotsIn(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// readFileBytes is os.ReadFile under a name that says what the copy section
// does with it: read the deposit, hash it, compare.
func readFileBytes(path string) ([]byte, error) { return os.ReadFile(path) }
