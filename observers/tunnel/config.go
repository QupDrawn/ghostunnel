package main

// config.go holds what one cycle needs to know about its world (Config), what
// the process carries between cycles (State, SPEC 4), and what a cycle decides
// (Outcome). The structural core is identity-driven: the reader's identity,
// the ring's membership, the coordinator and the copy cycle all come from
// Config and nothing below hardcodes a member name.

import (
	"sort"
	"time"
)

// Config is the declared world of one observer. Membership is declared, not
// discovered (SPEC 4).
type Config struct {
	// Identity is the reader's own identity: its store name, the observer
	// field of every file it writes, the name of its slot in others' halts/.
	Identity string
	// Members is the ring's declared membership, including the reader.
	Members []string
	// Coordinator is the member that decides the all-clear (SPEC 12.3) and
	// runs procedure K over every application store's copy/ (SPEC 9). It
	// writes copy-<Coordinator>/ into each other store (observers/README).
	Coordinator string
	// CopyAuthor maps an application store to the member that writes its
	// copy/ directory (the copy cycle of SPEC 2).
	CopyAuthor map[string]string
	// SlotOwners maps each declared member to the account it runs as, for
	// the owner clause of procedure H (SPEC 10.2 H7): an entry of the own
	// halts/ named for w must be owned by SlotOwners[w]. Given by
	// -slot-owners, which parseFlags requires to name every member. Nil
	// means the clause is not evaluated, which only the fixture harness
	// does, its trees carrying no ownership, as HeartbeatMaxAge zero leaves
	// V4b unevaluated.
	SlotOwners map[string]string

	// StoresRoot stands for /stores/; TracesRoot for the traces directory.
	StoresRoot string
	TracesRoot string

	// Values to be set (SPEC 18).
	Window            int           // WINDOW, 4 by design
	StaleSlack        float64       // STALE_SLACK (SPEC 8)
	StagingStaleAfter time.Duration // STAGING_STALE_AFTER_SECONDS
	MaxHeartbeatBytes int64
	MaxFaultBytes     int64
	MaxHaltBytes      int64
	// HeartbeatMaxAge is the V4b backstop. Zero means not evaluated; the
	// deployment must set it above every member's cadence (SPEC 8.1 V4b).
	HeartbeatMaxAge time.Duration
	// CadenceSeconds is the cadence this observer declares (SPEC 3.2).
	CadenceSeconds int64

	// Now is the reader's clock for this cycle (staging age, traces, V4b).
	Now time.Time

	// Traces are the schedules this observer validates (SPEC 14).
	Traces []TraceSchedule
	// DB holds the post-condition answers (SPEC 14.2 T4): task -> count.
	// Nil when this observer asks no post-condition questions.
	DB map[string]int64

	// Local supplies the per-observer checks (SPEC 13 step 7).
	Local LocalChecks

	// PolicyQuery is the proxy's --allow-query: the OPA query the policy
	// named by the start line's policy:<hash> rule is evaluated with,
	// which the trace does not record (-policy-query, the same on every
	// member; substance.go). Empty means a policy rule cannot be
	// re-judged, which fails acl-substance on every acl line under one.
	PolicyQuery string
	// MaterialBase is where a relative policy path of the start line
	// resolves for the substance rules; empty resolves it as given. The
	// fixture harness sets it to the fixture's copy; a deployment's
	// paths are absolute. The CA bundle has no path to resolve: it is
	// read from the trace root's material store by the recorded hash.
	MaterialBase string

	// OwnTree is the expected ownership of the own store's directories,
	// read once on start from the deployment's tree (ownstore.go,
	// deploy/tree.tsv) for own-store-private (SPEC 13 step 3). Nil when
	// the tree could not be read, which the check reports, or on an OS
	// where the check cannot run.
	OwnTree *StoreTree
	// AcceptNoStoreCheck is the value of -accept-no-store-check: the OS
	// this observer's operator accepts cannot run own-store-private, ""
	// when none. parseFlags refuses any value but runtime.GOOS, and any
	// value at all on linux; the rule is nevertheless judged on the value
	// given (ownStorePrivateSubjects).
	AcceptNoStoreCheck string

	// DryRun reports what would be written and touches nothing on disk;
	// it also skips the own-store-writable probe, which is a write.
	DryRun bool
	// Stopping marks the final cycle of a deliberate stop (SPEC 7).
	Stopping bool
}

// TraceSchedule is one schedule of SPEC 14 with its values to be set.
type TraceSchedule struct {
	Schedule string
	Period   time.Duration
	Margin   time.Duration
	Deadline time.Duration
	Declared []string
}

// Others is the membership minus the reader, in identity order (SPEC 1).
func (c *Config) Others() []string {
	out := make([]string, 0, len(c.Members))
	for _, m := range c.Members {
		if m != c.Identity {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// IsMember reports whether id is a declared member.
func (c *Config) IsMember(id string) bool {
	for _, m := range c.Members {
		if m == id {
			return true
		}
	}
	return false
}

// State is the reader's in-process state (SPEC 4): the basis, the memory and
// the per-subject unchanged durations. It is never read from the store during
// a cycle; the production driver rebuilds Memory from the own store on start
// (SPEC 7) and updates everything after each cycle's writes.
type State struct {
	// HasBasis is false on the first cycle after a process start (SPEC 7).
	HasBasis bool
	// Basis is observed[A] as recorded in the previous cycle.
	Basis map[string]*string
	// Memory maps a path relative to /stores/ (written <store>/<path>) to the
	// SHA-256 of the file as this observer last wrote it (SPEC 11.1 I5).
	Memory map[string]string
	// Unchanged is how long each subject's heartbeat has been unchanged as
	// this reader has measured it on its own clock (SPEC 8).
	Unchanged map[string]time.Duration
	// Started is when the process started, for the boot record.
	Started time.Time
	// ObservingSince is when this observer first ran, read on start (SPEC 7)
	// from <own>/since by readObservingSince; nil when the store does not
	// record it or records it unreadably, which observing-since reports. It
	// is the clock T1 measures a never-run schedule against: written once
	// and never rewritten, so a restart does not grant fresh grace, which
	// Started would.
	ObservingSince *time.Time
	// LastCycleEnd is the monotonic mark of the previous cycle's end, for
	// accumulating Unchanged.
	LastCycleEnd time.Time
	// RereadDiffers is set by the driver when the re-read of a published
	// heartbeat differed from what was written (SPEC 5) and cleared when a
	// later publish re-reads clean. While it is set own-store-writable
	// fails with subject re-read: the disagreement is learned after the
	// cycle that wrote, so it is the next cycle's finding.
	RereadDiffers bool
	// OwnStorePrivate is the own-store-private probe's result for this
	// cycle (SPEC 13 step 3): the failing subjects, empty when the probe
	// passed, nil when nothing probed, which fails. The driver refreshes it
	// before every cycle (refreshOwnStorePrivate); the fixture harness
	// supplies it satisfied, as it supplies ObservingSince, because a
	// fixture tree carries no ownership.
	OwnStorePrivate []string
	// TraceBoot and TraceSegments are the trace-consistent memory (SPEC
	// 14.3): the boot of the proxy's trace last read and, per segment of
	// it, the length of the prefix of complete lines then read and the
	// SHA-256 of that prefix. Held here so that a member's local checks
	// keep it across cycles; the structural core never reads it.
	TraceBoot     int64
	TraceSegments map[string]TraceSegment
	// TraceDecode is what this member decoded of the current boot last
	// cycle, keyed by the SHA-256 of the bytes it was decoded from
	// (gtDecodeMemory): the next read decodes only the lines beyond it.
	// Allocated by traceReadCurrent on first use; never read by the
	// structural core.
	TraceDecode *gtDecodeMemory
	// BootsEnded is boot-ended's memory (tracememory.go): the boots this
	// process read as current and then saw replaced by another, each
	// awaiting the one judgement of its ending, which forgets it. Nothing
	// else is kept: a boot judged, or never observed to end, is not here.
	BootsEnded []int64
	// BootEndedDecode is what this member decoded of a pending boot the
	// last time boot-ended looked at it, keyed as TraceDecode is by the
	// SHA-256 of the bytes it was decoded from: a pending boot that has
	// not ended yet is looked at every cycle until it has, and each look
	// decodes only the lines beyond it. Allocated by bootEndedFindings
	// while a boot is pending and dropped when none is.
	BootEndedDecode *gtDecodeMemory
	// Substance is the substance rules' memory (substance.go): chain
	// verifications, leaf judgements and compiled policies under content
	// hashes, emptied when the boot changes. Allocated by
	// substanceJudgeFor on first use; never read by the structural core.
	Substance *substanceCache
	// Parses is the strict parse of every heartbeat entry the last cycle
	// read, keyed by the SHA-256 of its bytes (parseMemory, chain.go): an
	// entry whose bytes hash the same this cycle is that parse. Allocated
	// by RunCycle on first use.
	Parses *parseMemory
}

// TraceSegment is what trace-consistent remembers of one segment of the
// proxy's trace: the length of the prefix of complete lines read and the
// SHA-256 of those bytes.
type TraceSegment struct {
	Length int64
	Hash   string
}

// PeerView is what the cycle read of one other member at step 4, handed to
// the local checks at step 7 (SPEC 13): its verdict, the identifiers its
// newest heartbeat lists as checked, and the failing set its root fault
// carries. The checks only read it.
type PeerView struct {
	Verdict Verdict
	// Checks are the identifiers the member's newest heartbeat lists; nil
	// when no heartbeat of the member parsed this cycle.
	Checks []string
	// FaultPresent reports a fault file at the member's store root.
	FaultPresent bool
	// FaultParsed is true when the fault was read and parsed this cycle,
	// and Failing is then its failing set. A fault present but not parsed
	// says nothing about what the member finds failing.
	FaultParsed bool
	Failing     []Finding
}

// Verdict is one of the six of SPEC 8.
type Verdict string

const (
	VerdictAbsent  Verdict = "absent"
	VerdictAlive   Verdict = "alive"
	VerdictStale   Verdict = "stale"
	VerdictRetired Verdict = "retired"
	VerdictFaulted Verdict = "faulted"
	VerdictUnknown Verdict = "unknown"
)

// Finding is one failing assertion: a check identifier (SPEC 15) and its
// subject. An empty Subject stands for null; no subject is ever the empty
// string.
type Finding struct {
	Check   string
	Subject string
}

// SubjectPtr returns the subject as a nullable string.
func (f Finding) SubjectPtr() *string {
	if f.Subject == "" {
		return nil
	}
	s := f.Subject
	return &s
}

// Outcome is everything one cycle decided, including what it would write.
type Outcome struct {
	// Verdicts holds one verdict per member of OTHERS.
	Verdicts map[string]Verdict
	// Failing is the complete set of failing assertions, in evaluation
	// order (SPEC 13), each pair listed once.
	Failing []Finding
	// HaltInForceBefore is SPEC 10.1 evaluated before the reader writes.
	HaltInForceBefore bool
	// Halt is the raise decision (SPEC 12.1).
	Halt HaltDecision
	// Publish is the heartbeat to publish (SPEC 13 step 8).
	Publish PublishRecord
	// Fault is the fault decision (SPEC 13 step 9).
	Fault FaultDecision
	// Relay is the relay decision (SPEC 12.2).
	Relay RelayDecision
	// Clears is nil when the clear-condition does not hold (SPEC 12.3).
	Clears *ClearDecision
	// Log carries the lines to write to standard output after acting
	// (SPEC 12.4), in order.
	Log []string
}

// HaltDecision says whether the reader raises a halt and what it names.
type HaltDecision struct {
	Writes  bool
	Reason  string
	Subject string // empty stands for null
	// Bytes is the halt file every slot receives this cycle.
	Bytes []byte
	// OwnHaltWritten is true when the reader writes <own>/halt this cycle.
	OwnHaltWritten bool
	// Slots lists the stores whose halts/<R> the reader writes, in order.
	Slots []string
}

// SubjectPtr returns the halt's subject as a nullable string.
func (h HaltDecision) SubjectPtr() *string {
	if h.Subject == "" {
		return nil
	}
	s := h.Subject
	return &s
}

// PublishRecord is the heartbeat of SPEC 3.2 as the reader will write it.
type PublishRecord struct {
	Sequence   int64
	Previous   *string
	Observed   map[string]*string
	Boot       *BootRecord
	Stop       bool
	Checks     []string
	CheckCount int64
	// Bytes is the exact file content, marker first, one trailing line feed.
	Bytes []byte
}

// BootRecord is the boot object of SPEC 3.2.
type BootRecord struct {
	Started     string
	ResumedFrom *int64
}

// FaultDecision says what happens to the reader's own fault file.
type FaultDecision struct {
	// Local is the failing subset the fault carries (SPEC 3.3).
	Local []Finding
	// Publish is true when the file is written (the set changed).
	Publish bool
	// Remove is true when the set is empty and a fault stands.
	Remove bool
	// Bytes is the file content when Publish is true.
	Bytes []byte
}

// RelayDecision is SPEC 12.2 as the reader would apply it.
type RelayDecision struct {
	// Active is true when the reader relays this cycle.
	Active bool
	// Writes lists the stores whose halts/<R> is absent and gets written.
	Writes []string
	// Leaves lists the stores whose halts/<R> already exists.
	Leaves []string
	// Bytes are those of the first halt found; From names it.
	Bytes []byte
	From  string
}

// ClearDecision is SPEC 12.3: the ordered list of paths the reader removes.
type ClearDecision struct {
	Removes []string
}
