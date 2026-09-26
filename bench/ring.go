package main

// ring.go builds the store tree the fork's gate reads and publishes the
// coordinator heartbeat it requires. The format follows the fork's
// ringtrace/heartbeat.go and observers/SPEC.md section 3.2 exactly: the
// marker as the first bytes, the twelve keys, sequence equal to the file
// name, a UTC whole-second timestamp, observed holding exactly the other
// three members, previous the SHA-256 of the previous file's bytes as
// stored (null only on sequence 1), boot only on sequence 1, one trailing
// line feed.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var ringMembers = []string{"tunnel", "admin", "material", "super"}

const (
	ringCoordinator  = "super"
	heartbeatPeriod  = 2 * time.Second
	heartbeatCadence = 10 // cadence_seconds declared in the file
	heartbeatKeep    = 4  // newest files kept when pruning
)

// storeTree is the fork's --ring-stores root and the gt/ trace root under it.
type storeTree struct {
	root string
	gt   string
}

// buildStoreTree creates <root>/{tunnel,admin,material,super}/{heartbeat,halts}
// and <root>/gt, empty.
func buildStoreTree(root string) (*storeTree, error) {
	if err := os.RemoveAll(root); err != nil {
		return nil, err
	}
	for _, m := range ringMembers {
		for _, sub := range []string{"heartbeat", "halts"} {
			if err := os.MkdirAll(filepath.Join(root, m, sub), 0o755); err != nil {
				return nil, err
			}
		}
	}
	gt := filepath.Join(root, "gt")
	if err := os.MkdirAll(gt, 0o755); err != nil {
		return nil, err
	}
	return &storeTree{root: root, gt: gt}, nil
}

// heartbeatPublisher writes the coordinator's heartbeats on a period.
type heartbeatPublisher struct {
	dir      string
	seq      int64
	prevHash string
	started  string
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	mu       sync.Mutex
	lastErr  error
}

func timestamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// startHeartbeats publishes sequence 1 synchronously (so the gate can
// serve as soon as the proxy is up) and then every heartbeatPeriod until
// stopped.
func startHeartbeats(tree *storeTree) (*heartbeatPublisher, error) {
	h := &heartbeatPublisher{
		dir:     filepath.Join(tree.root, ringCoordinator, "heartbeat"),
		started: timestamp(time.Now()),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	if err := h.publish(); err != nil {
		return nil, err
	}
	go func() {
		defer close(h.done)
		t := time.NewTicker(heartbeatPeriod)
		defer t.Stop()
		for {
			select {
			case <-h.stop:
				return
			case <-t.C:
				if err := h.publish(); err != nil {
					h.mu.Lock()
					h.lastErr = err
					h.mu.Unlock()
					progress("heartbeat: %v", err)
				}
			}
		}
	}()
	return h, nil
}

func (h *heartbeatPublisher) Stop() {
	h.stopOnce.Do(func() { close(h.stop) })
	<-h.done
}

func (h *heartbeatPublisher) err() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastErr
}

// heartbeatBytes renders one heartbeat file exactly as the gate parses it.
func heartbeatBytes(seq int64, now time.Time, prevHash, started string) []byte {
	var b strings.Builder
	b.WriteString(`{"kind":"heartbeat",`)
	b.WriteString(`"version":1,`)
	fmt.Fprintf(&b, `"observer":%q,`, ringCoordinator)
	fmt.Fprintf(&b, `"sequence":%d,`, seq)
	fmt.Fprintf(&b, `"timestamp":%q,`, timestamp(now))
	fmt.Fprintf(&b, `"cadence_seconds":%d,`, heartbeatCadence)
	b.WriteString(`"checks":["bench-publisher-alive","own-store-writable"],`)
	b.WriteString(`"check_count":2,`)
	others := make([]string, 0, len(ringMembers)-1)
	for _, m := range ringMembers {
		if m != ringCoordinator {
			others = append(others, m)
		}
	}
	sort.Strings(others)
	b.WriteString(`"observed":{`)
	for i, m := range others {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `%q:null`, m)
	}
	b.WriteString(`},`)
	if seq == 1 {
		b.WriteString(`"previous":null,`)
		fmt.Fprintf(&b, `"boot":{"started":%q,"resumed_from":null},`, started)
	} else {
		fmt.Fprintf(&b, `"previous":%q,`, prevHash)
		b.WriteString(`"boot":null,`)
	}
	b.WriteString(`"stop":false}`)
	b.WriteString("\n")
	return []byte(b.String())
}

// publish stages the next heartbeat as .hb.tmp, renames it into place,
// records its hash for the next file's previous and prunes old files.
func (h *heartbeatPublisher) publish() error {
	seq := h.seq + 1
	data := heartbeatBytes(seq, time.Now(), h.prevHash, h.started)
	name := fmt.Sprintf("%010d.hb", seq)
	final := filepath.Join(h.dir, name)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	// previous is the hash of the file's bytes as stored: re-read it.
	stored, err := os.ReadFile(final)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(stored)
	h.prevHash = hex.EncodeToString(sum[:])
	h.seq = seq
	return h.prune()
}

func (h *heartbeatPublisher) prune() error {
	des, err := os.ReadDir(h.dir)
	if err != nil {
		return err
	}
	var names []string
	for _, de := range des {
		if strings.HasSuffix(de.Name(), ".hb") {
			names = append(names, de.Name())
		}
	}
	sort.Strings(names)
	for len(names) > heartbeatKeep {
		if err := os.Remove(filepath.Join(h.dir, names[0])); err != nil {
			return err
		}
		names = names[1:]
	}
	return nil
}

// traceStat is the size of the fork's trace after a run.
type traceStat struct {
	bytes, lines int64
	files        int
}
