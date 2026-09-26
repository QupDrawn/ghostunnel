package ringtrace

// gate.go is SPEC 19 for ghostunnel: what the work reads before it works.
// It writes nothing, repairs nothing and loads nothing. Every path that
// cannot be read or parsed is a refusal, never a question skipped.

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultRoot is the store tree the gate reads unless configured otherwise.
const DefaultRoot = "/var/lib/ghostunnel-ring/stores"

// DefaultMaxHeartbeatBytes bounds a heartbeat file before it is read.
const DefaultMaxHeartbeatBytes int64 = 64 * 1024

// Gate is what ghostunnel consults before serving a connection.
type Gate struct {
	// Root is the store tree; the members' stores are its children.
	Root string
	// Members are the store names, walked in identity (ASCII) order.
	Members []string
	// Coordinator is the member whose heartbeat must be current.
	Coordinator string
	// MaxHeartbeatAge is how far the coordinator's newest heartbeat may sit
	// from now, in either direction. Must be set above zero.
	MaxHeartbeatAge time.Duration
	// MaxHeartbeatBytes bounds a heartbeat file before it is read.
	MaxHeartbeatBytes int64
	// Now is the clock.
	Now func() time.Time

	// parsed is the last heartbeat parse, keyed by everything the parse
	// depends on: the SHA-256 of the bytes read, the coordinator, the
	// sequence the file name carries and the member list. The bytes are
	// still read within bound on every Check (the read is the check); only
	// the strict parse of identical bytes is reused, including its error.
	// The age is judged afresh on every call. Never keyed on size or mtime.
	parsedMu sync.Mutex
	parsed   heartbeatParse
}

// heartbeatParse is one remembered parseHeartbeat call.
type heartbeatParse struct {
	valid       bool
	sum         [32]byte
	coordinator string
	seq         int64
	members     string
	hb          *heartbeat
	err         error
}

// Decision is serve-or-refuse with the reason, which the caller logs.
type Decision struct {
	Serve  bool
	Reason string
	// hbAt is the timestamp of the heartbeat a serve decision rests on;
	// GateState judges its age again on every reuse.
	hbAt time.Time
}

// NewGate returns a gate with the defaults: the four members, super as
// coordinator, the default size bound and time.Now. MaxHeartbeatAge is
// left at zero and must be set; a zero window refuses everything.
func NewGate(root string) *Gate {
	if root == "" {
		root = DefaultRoot
	}
	return &Gate{
		Root:              root,
		Members:           []string{"admin", "material", "super", "tunnel"},
		Coordinator:       "super",
		MaxHeartbeatBytes: DefaultMaxHeartbeatBytes,
		Now:               time.Now,
	}
}

func refuse(format string, args ...interface{}) Decision {
	return Decision{Serve: false, Reason: fmt.Sprintf(format, args...)}
}

// Check reads the store tree and decides. It refuses when any member's
// store holds a halt, a fault or a delivered halt, when the coordinator's
// newest heartbeat is missing, stale, ahead of the clock, stopped or does
// not parse, and when anything it needs cannot be read.
func (g *Gate) Check() Decision {
	if g.MaxHeartbeatAge <= 0 {
		return refuse("gate: MaxHeartbeatAge is not set")
	}
	if g.MaxHeartbeatBytes <= 0 {
		return refuse("gate: MaxHeartbeatBytes is not set")
	}
	if g.Now == nil {
		return refuse("gate: no clock")
	}
	if len(g.Members) == 0 {
		return refuse("gate: no members")
	}
	members := append([]string(nil), g.Members...)
	sort.Strings(members)
	isMember := false
	for _, m := range members {
		if m == g.Coordinator {
			isMember = true
		}
	}
	if !isMember {
		return refuse("gate: coordinator %q is not a member", g.Coordinator)
	}
	if info, err := os.Stat(g.Root); err != nil {
		return refuse("gate: root: %v", err)
	} else if !info.IsDir() {
		return refuse("gate: root %s is not a directory", g.Root)
	}

	// Has anything halted? Presence, not content, in identity order.
	for _, m := range members {
		if d := g.checkStore(m); !d.Serve {
			return d
		}
	}

	// Is the coordinator alive?
	return g.checkHeartbeat(members)
}

// checkStore refuses on a halt, a fault or a delivered halt in one store,
// and on anything it cannot read on the way.
func (g *Gate) checkStore(m string) Decision {
	store := filepath.Join(g.Root, m)
	if info, err := os.Stat(store); err != nil {
		return refuse("gate: store %s: %v", m, err)
	} else if !info.IsDir() {
		return refuse("gate: store %s is not a directory", m)
	}
	for _, name := range []string{"halt", "fault"} {
		info, err := os.Lstat(filepath.Join(store, name))
		if err == nil {
			if info.Mode().IsRegular() {
				return refuse("gate: %s in force", path.Join(m, name))
			}
			return refuse("gate: %s is not a regular file", path.Join(m, name))
		}
		if !os.IsNotExist(err) {
			return refuse("gate: %s: %v", path.Join(m, name), err)
		}
	}
	des, err := os.ReadDir(filepath.Join(store, "halts"))
	if err != nil {
		return refuse("gate: %s: %v", path.Join(m, "halts"), err)
	}
	for _, de := range des {
		rel := path.Join(m, "halts", de.Name())
		if strings.HasSuffix(de.Name(), ".tmp") && de.Type().IsRegular() {
			continue
		}
		if !de.Type().IsRegular() {
			return refuse("gate: %s is not a regular file", rel)
		}
		return refuse("gate: %s in force", rel)
	}
	return Decision{Serve: true}
}

// checkHeartbeat finds the coordinator's newest heartbeat by name, reads
// it within the size bound, parses it strictly and judges its timestamp
// against the window in both directions.
func (g *Gate) checkHeartbeat(members []string) Decision {
	c := g.Coordinator
	dir := filepath.Join(g.Root, c, "heartbeat")
	rel := path.Join(c, "heartbeat")
	des, err := os.ReadDir(dir)
	if err != nil {
		return refuse("gate: %s: %v", rel, err)
	}
	var newest string
	for _, de := range des {
		name := de.Name()
		switch {
		case reStagingName.MatchString(name) && de.Type().IsRegular():
			continue
		case reHeartbeatName.MatchString(name) && de.Type().IsRegular():
			if name > newest {
				newest = name
			}
		default:
			return refuse("gate: unexpected entry %s", path.Join(rel, name))
		}
	}
	if newest == "" {
		return refuse("gate: %s holds no heartbeat", rel)
	}
	hbRel := path.Join(rel, newest)
	data, err := readBounded(filepath.Join(dir, newest), g.MaxHeartbeatBytes)
	if err != nil {
		return refuse("gate: %s: %v", hbRel, err)
	}
	hb, err := g.parseCached(data, c, numberOfName(newest), members)
	if err != nil {
		return refuse("gate: %s: %v", hbRel, err)
	}
	if hb.Stop {
		return refuse("gate: %s is a deliberate stop", hbRel)
	}
	now := g.Now().UTC()
	age := now.Sub(hb.Timestamp)
	if age > g.MaxHeartbeatAge {
		return refuse("gate: %s is stale: %s old, window %s", hbRel, age, g.MaxHeartbeatAge)
	}
	if -age > g.MaxHeartbeatAge {
		return refuse("gate: %s is ahead of the clock by %s, window %s", hbRel, -age, g.MaxHeartbeatAge)
	}
	return Decision{Serve: true, Reason: fmt.Sprintf("gate: no halt in force; %s is %s old", hbRel, age), hbAt: hb.Timestamp}
}

// parseCached is parseHeartbeat, reusing the last result when the bytes
// hash the same and the observer, the sequence and the members are the
// same: the parse is a pure function of those four, so the result,
// error included, is the one the parse would give. Different bytes are
// parsed anew.
func (g *Gate) parseCached(data []byte, observer string, seq int64, members []string) (*heartbeat, error) {
	sum := sha256.Sum256(data)
	key := strings.Join(members, "\x00")
	g.parsedMu.Lock()
	defer g.parsedMu.Unlock()
	if p := g.parsed; p.valid && p.sum == sum && p.coordinator == observer && p.seq == seq && p.members == key {
		return p.hb, p.err
	}
	hb, err := parseHeartbeat(data, observer, seq, members)
	g.parsed = heartbeatParse{valid: true, sum: sum, coordinator: observer, seq: seq, members: key, hb: hb, err: err}
	return hb, err
}
