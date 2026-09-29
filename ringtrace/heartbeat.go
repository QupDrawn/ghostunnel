package ringtrace

// heartbeat.go is the gate's own reading of an observer heartbeat (SPEC
// 3.1, 3.2, 19.3): size checked before content, the marker classified
// before parsing, exactly the specified keys, and every value of the
// specified type. It shares nothing with the observers' decoders.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"
)

// heartbeatMarker is the exact first bytes of a heartbeat file.
var heartbeatMarker = []byte(`{"kind":"heartbeat",`)

var (
	reHeartbeatName = regexp.MustCompile(`^[0-9]{10}\.hb$`)
	reStagingName   = regexp.MustCompile(`^[0-9]{10}\.hb\.tmp$`)
)

var heartbeatKeys = []string{"kind", "version", "observer", "sequence", "timestamp", "cadence_seconds", "checks", "check_count", "observed", "previous", "boot", "stop"}

// heartbeat is the part of a parsed heartbeat the gate uses.
type heartbeat struct {
	Observer  string
	Sequence  int64
	Timestamp time.Time
	Stop      bool
}

// readBoundedHook, when set, runs between readBounded's lstat and its open
// (a test seam that changes what is at the name in that interval).
var readBoundedHook func(path string)

// readBounded returns a file's bytes, refusing without reading one whose
// size exceeds max (SPEC 3.1: sizes are checked before content). What is
// read is the file the lstat found and nothing else: the open neither
// follows a link nor waits (openRead), and the open file must be a regular
// file within the bound that is the same file as the lstat's, or nothing
// is read. The read itself is still bounded by max+1.
func readBounded(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > max {
		return nil, fmt.Errorf("%d bytes exceeds the bound of %d", info.Size(), max)
	}
	// On Windows os reads a file's identity from its path lazily, at its
	// first comparison; comparing the lstat's result with itself reads it
	// now, so the comparison below is with the file found here.
	if !os.SameFile(info, info) {
		return nil, errors.New("cannot be identified")
	}
	if readBoundedHook != nil {
		readBoundedHook(path)
	}
	f, err := openRead(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() {
		return nil, errors.New("not a regular file when opened")
	}
	if !os.SameFile(info, opened) {
		return nil, errors.New("changed between the lstat and the open")
	}
	if opened.Size() > max {
		return nil, fmt.Errorf("%d bytes exceeds the bound of %d", opened.Size(), max)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("more than %d bytes", max)
	}
	return data, nil
}

// parseHeartbeat parses b strictly as the heartbeat of observer at
// sequence seq, among members (which fixes the observed key set).
func parseHeartbeat(b []byte, observer string, seq int64, members []string) (*heartbeat, error) {
	if !bytes.HasPrefix(b, heartbeatMarker) {
		return nil, errors.New("does not begin with the heartbeat marker")
	}
	obj, err := decodeObject(b, true)
	if err != nil {
		return nil, err
	}
	if err := obj.exactKeys(heartbeatKeys); err != nil {
		return nil, err
	}
	hb := &heartbeat{}
	if k, err := stringField(obj.get("kind"), "kind"); err != nil || k != "heartbeat" {
		return nil, errors.New("kind is not heartbeat")
	}
	v, err := intField(obj.get("version"), "version")
	if err != nil {
		return nil, err
	}
	if v != 1 {
		return nil, fmt.Errorf("version %d is not 1", v)
	}
	if hb.Observer, err = stringField(obj.get("observer"), "observer"); err != nil {
		return nil, err
	}
	if hb.Observer != observer {
		return nil, fmt.Errorf("observer %q in the store of %q", hb.Observer, observer)
	}
	if hb.Sequence, err = intField(obj.get("sequence"), "sequence"); err != nil {
		return nil, err
	}
	if hb.Sequence != seq {
		return nil, fmt.Errorf("sequence %d in a file named %d", hb.Sequence, seq)
	}
	if hb.Timestamp, err = timestampField(obj.get("timestamp"), "timestamp"); err != nil {
		return nil, err
	}
	cadence, err := intField(obj.get("cadence_seconds"), "cadence_seconds")
	if err != nil {
		return nil, err
	}
	if cadence < 1 {
		return nil, fmt.Errorf("cadence_seconds %d is below 1", cadence)
	}
	checks, err := stringArray(obj.get("checks"), "checks")
	if err != nil {
		return nil, err
	}
	count, err := intField(obj.get("check_count"), "check_count")
	if err != nil {
		return nil, err
	}
	if count != int64(len(checks)) {
		return nil, fmt.Errorf("check_count %d but %d checks", count, len(checks))
	}
	others := make([]string, 0, len(members))
	for _, m := range members {
		if m != observer {
			others = append(others, m)
		}
	}
	observed, err := decodeSubobject(obj.get("observed"), others)
	if err != nil {
		return nil, fmt.Errorf("observed: %v", err)
	}
	for _, m := range others {
		if _, err := nullableHash(observed.get(m), "observed."+m); err != nil {
			return nil, err
		}
	}
	previous, err := nullableHash(obj.get("previous"), "previous")
	if err != nil {
		return nil, err
	}
	if (previous == nil) != (hb.Sequence == 1) {
		return nil, errors.New("previous is null exactly on sequence 1")
	}
	if !isNull(obj.get("boot")) {
		boot, err := decodeSubobject(obj.get("boot"), []string{"started", "resumed_from"})
		if err != nil {
			return nil, fmt.Errorf("boot: %v", err)
		}
		if _, err := timestampField(boot.get("started"), "boot.started"); err != nil {
			return nil, err
		}
		if _, err := nullableInt(boot.get("resumed_from"), "boot.resumed_from"); err != nil {
			return nil, err
		}
	}
	if hb.Stop, err = boolField(obj.get("stop"), "stop"); err != nil {
		return nil, err
	}
	return hb, nil
}
