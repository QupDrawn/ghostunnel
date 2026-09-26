package main

// traces.go implements SPEC 14: the JSON Lines trace format (14.1) and the
// four validations T1 to T4 (14.2), plus the post-condition answers of T4
// supplied through Config.DB.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// traceRun is one run's trace as read.
type traceRun struct {
	Run       int64
	Malformed bool
	Started   time.Time
	Finished  bool
	Completed map[string]bool
}

// readTrace parses one trace file under SPEC 14.1. A final line without a
// line feed is ignored; a missing first line or any complete line that does
// not parse makes the trace malformed.
func readTrace(disk, schedule string, run int64) *traceRun {
	tr := &traceRun{Run: run, Completed: map[string]bool{}}
	data, err := readFile(disk)
	if err != nil {
		tr.Malformed = true
		return tr
	}
	// Keep only complete lines.
	end := bytes.LastIndexByte(data, '\n')
	if end < 0 {
		tr.Malformed = true
		return tr
	}
	lines := bytes.Split(data[:end], []byte("\n"))
	for i, line := range lines {
		var head struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(line, &head); err != nil {
			tr.Malformed = true
			return tr
		}
		if tr.Finished {
			// Nothing follows the finish line in a well-formed trace.
			tr.Malformed = true
			return tr
		}
		switch {
		case i == 0:
			if head.Kind != "trace" {
				tr.Malformed = true
				return tr
			}
			obj, err := decodeStrictSubobject(line, []string{"kind", "version", "schedule", "run", "started"})
			if err != nil {
				tr.Malformed = true
				return tr
			}
			v, err := intField(obj["version"], "version")
			if err != nil || v != 1 {
				tr.Malformed = true
				return tr
			}
			s, err := stringField(obj["schedule"], "schedule")
			if err != nil || s != schedule {
				tr.Malformed = true
				return tr
			}
			n, err := intField(obj["run"], "run")
			if err != nil || n != run {
				tr.Malformed = true
				return tr
			}
			started, err := stringField(obj["started"], "started")
			if err != nil {
				tr.Malformed = true
				return tr
			}
			if tr.Started, err = parseTimestamp(started); err != nil {
				tr.Malformed = true
				return tr
			}
		case head.Kind == "task":
			obj, err := decodeStrictSubobject(line, []string{"kind", "id", "completed", "count"})
			if err != nil {
				tr.Malformed = true
				return tr
			}
			id, err := stringField(obj["id"], "id")
			if err != nil {
				tr.Malformed = true
				return tr
			}
			completed, err := boolField(obj["completed"], "completed")
			if err != nil {
				tr.Malformed = true
				return tr
			}
			if _, err := nullableInt(obj["count"], "count"); err != nil {
				tr.Malformed = true
				return tr
			}
			if completed {
				tr.Completed[id] = true
			}
		case head.Kind == "finish":
			obj, err := decodeStrictSubobject(line, []string{"kind", "finished"})
			if err != nil {
				tr.Malformed = true
				return tr
			}
			finished, err := stringField(obj["finished"], "finished")
			if err != nil {
				tr.Malformed = true
				return tr
			}
			if _, err := parseTimestamp(finished); err != nil {
				tr.Malformed = true
				return tr
			}
			tr.Finished = true
		default:
			tr.Malformed = true
			return tr
		}
	}
	return tr
}

// listRuns returns the run numbers present for a schedule, ascending.
func (r *reader) listRuns(schedule string) []int64 {
	des, err := os.ReadDir(filepath.Join(r.cfg.TracesRoot, schedule))
	if err != nil {
		return nil
	}
	var runs []int64
	for _, de := range des {
		if reTraceName.MatchString(de.Name()) && de.Type().IsRegular() {
			runs = append(runs, sequenceOfName(de.Name()))
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i] < runs[j] })
	return runs
}

// checkTraces runs T1 to T3 for each configured schedule and T4 over the
// post-condition answers (SPEC 14.2).
func (r *reader) checkTraces() {
	for _, s := range r.cfg.Traces {
		r.checkSchedule(s)
	}
	tasks := make([]string, 0, len(r.cfg.DB))
	for t := range r.cfg.DB {
		tasks = append(tasks, t)
	}
	sort.Strings(tasks)
	for _, t := range tasks {
		r.ran("postcondition:" + t)
		if r.cfg.DB[t] != 0 {
			r.fail("postcondition", t)
		}
	}
}

func (r *reader) checkSchedule(s TraceSchedule) {
	r.ran("trace-fresh:" + s.Schedule)
	r.ran("trace-complete:" + s.Schedule)
	r.ran("trace-coverage:" + s.Schedule)
	now := r.cfg.Now
	runs := r.listRuns(s.Schedule)
	dir := filepath.Join(r.cfg.TracesRoot, s.Schedule)
	traceOf := func(run int64) *traceRun {
		return readTrace(filepath.Join(dir, traceName(run)), s.Schedule, run)
	}

	// T1 freshness.
	if len(runs) == 0 {
		// Never run yet is not stale until the schedule is overdue, measured
		// from when this observer first ran (State.ObservingSince, the
		// once-written <own>/since), never from the process start, which a
		// restart resets, and never from the sequence times the cadence,
		// which is not a duration: cycles are not paced at the cadence. A
		// clock that cannot be read observes nothing, so nothing is due on
		// it; observing-since has already reported the clock itself.
		var observed time.Duration
		if since := r.st.ObservingSince; since != nil && now.After(*since) {
			observed = now.Sub(*since)
		}
		if observed < s.Period+s.Margin {
			return // not due yet: unknown, and unknown is not a fault
		}
		r.fail("trace-fresh", s.Schedule)
		return
	}
	latest := traceOf(runs[len(runs)-1])
	if !latest.Malformed && latest.Started.Before(now.Add(-(s.Period + s.Margin))) {
		r.fail("trace-fresh", s.Schedule)
	}

	// T2 completion. A malformed trace is a job not running correctly.
	if latest.Malformed {
		r.fail("trace-complete", s.Schedule)
	} else if !latest.Finished && now.Sub(latest.Started) > s.Deadline {
		r.fail("trace-complete", s.Schedule)
	}

	// T3 coverage, against the most recent finished run.
	var done *traceRun
	if latest.Finished && !latest.Malformed {
		done = latest
	} else {
		for i := len(runs) - 2; i >= 0; i-- {
			tr := traceOf(runs[i])
			if tr.Finished && !tr.Malformed {
				done = tr
				break
			}
		}
	}
	if done != nil {
		declared := make(map[string]bool, len(s.Declared))
		for _, id := range s.Declared {
			declared[id] = true
		}
		covered := len(done.Completed) == len(declared)
		for id := range done.Completed {
			if !declared[id] {
				covered = false
			}
		}
		for id := range declared {
			if !done.Completed[id] {
				covered = false
			}
		}
		if !covered {
			r.fail("trace-coverage", s.Schedule)
		}
	}
}

// traceName is the file name of a run (SPEC 14.1).
func traceName(run int64) string {
	return sprintf10(run) + ".trace"
}

// observingSinceName is the file at the store root that records when this
// observer first ran (observers/README). It is written once and never
// rewritten, which is what makes it a clock rather than an uptime: refreshed
// on each start it would grant a schedule that is never scheduled fresh
// grace on every restart, the one case T1 exists to catch. A wall-clock
// start stored once counts the time a deployment was down as well as up,
// which is the right answer to the question asked: a daily job that has
// never once run in a week is broken whether or not the host was off for
// some of it.
const observingSinceName = "since"

// writeObservingSinceOnce publishes <own>/since as the timestamp of SPEC 3.1
// and one line feed, through a staging file (SPEC 5), when nothing of that
// name exists. Whatever already exists is left exactly as it is, readable or
// not: readObservingSince and the observing-since check say what it holds,
// and nothing here guesses a new start over an old one.
func writeObservingSinceOnce(own string, now time.Time) error {
	p := filepath.Join(own, observingSinceName)
	if _, err := os.Lstat(p); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return stageAndRename(p, []byte(formatTimestamp(now)+"\n"))
}

// refreshObservingSince re-reads <own>/since into State before a cycle on
// the real disk. Read once on start, the value would outlive the record it
// stands for: a since deleted or overwritten while the observer runs would
// go unnoticed until the next restart, and observing-since would pass on a
// file that is not there. The fixture harness, whose stores carry no such
// file, supplies the value itself and does not call this.
func refreshObservingSince(cfg *Config, st *State) {
	st.ObservingSince = readObservingSince(filepath.Join(cfg.StoresRoot, cfg.Identity))
}

// readObservingSince reads <own>/since by the timestamp parser every other
// timestamp in the tree goes through, and returns nil when the store does
// not record when this observer began: the file is absent or unreadable, or
// its content is not exactly what writeObservingSinceOnce writes, the
// timestamp and one line feed. The parser is strict about the shape and
// round-trips what it parses; a second reader of one format is how such
// things go wrong.
func readObservingSince(own string) *time.Time {
	raw, err := readFile(filepath.Join(own, observingSinceName))
	if err != nil {
		return nil
	}
	if len(raw) != len(timestampLayout)+1 || raw[len(raw)-1] != '\n' {
		return nil
	}
	t, err := parseTimestamp(string(raw[:len(raw)-1]))
	if err != nil {
		return nil
	}
	return &t
}
