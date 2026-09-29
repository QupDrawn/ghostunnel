package main

// cycle.go is SPEC 13: the cycle, in the order that fixes which finding is
// first, and the decisions of SPEC 12 computed as what the reader would
// write. RunCycle writes nothing; the driver in main.go applies an Outcome.

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// reader is the state of one cycle from the point of view of one observer.
type reader struct {
	cfg    *Config
	st     *State
	others []string

	// findings in evaluation order, each check/subject pair once.
	findings []Finding
	seen     map[Finding]bool

	verdicts map[string]Verdict
	observed map[string]*string
	// entries holds each member's own folder as read (own store at step 3,
	// others at V3), for I1(b).
	entries map[string]*chainResult
	// cur holds each member's current heartbeat, for I1(b).
	cur map[string]*Heartbeat
	// faults caches each store's root fault as read.
	faults map[string]*faultRead
	// parses is the heartbeat parse memory of st (chain.go), begun for
	// this cycle; membership is the declared membership as its key
	// spells it.
	parses *parseMemory
	// snap is this cycle's one look at the store (snapshot, below).
	snap       *snapshot
	membership string

	checks []string
	ranSet map[string]bool
	log    []string
}

func newReader(cfg *Config, st *State) *reader {
	if st.Parses == nil {
		st.Parses = &parseMemory{}
	}
	st.Parses.begin()
	return &reader{
		cfg:        cfg,
		st:         st,
		others:     cfg.Others(),
		seen:       map[Finding]bool{},
		verdicts:   map[string]Verdict{},
		observed:   map[string]*string{},
		entries:    map[string]*chainResult{},
		cur:        map[string]*Heartbeat{},
		faults:     map[string]*faultRead{},
		parses:     st.Parses,
		snap:       newSnapshot(),
		membership: strings.Join(cfg.Members, "\x00"),
		ranSet:     map[string]bool{},
	}
}

// fail records a failing assertion once, in evaluation order.
func (r *reader) fail(check, subject string) {
	f := Finding{Check: check, Subject: subject}
	if r.seen[f] {
		return
	}
	r.seen[f] = true
	r.findings = append(r.findings, f)
}

// ran lists a check identifier in the heartbeat's checks (SPEC 15).
func (r *reader) ran(id string) {
	if r.ranSet[id] {
		return
	}
	r.ranSet[id] = true
	r.checks = append(r.checks, id)
}

func (r *reader) logf(format string, args ...interface{}) {
	r.log = append(r.log, fmt.Sprintf(format, args...))
}

// storePath is the on-disk path of <store>/<parts...>.
func (r *reader) storePath(store string, parts ...string) string {
	return filepath.Join(append([]string{r.cfg.StoresRoot, store}, parts...)...)
}

// RunCycle runs one cycle (SPEC 13) and reports what it would write. It
// returns an error only when the own store cannot be read at all, which is
// the case in which the observer does not run (SPEC 7).
func RunCycle(cfg *Config, st *State) (*Outcome, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if st.Memory == nil {
		st.Memory = map[string]string{}
	}
	if st.Unchanged == nil {
		st.Unchanged = map[string]time.Duration{}
	}
	start := time.Now() // 1. start the clock (monotonic)
	r := newReader(cfg, st)
	self := cfg.Identity
	out := &Outcome{Verdicts: r.verdicts}

	// 2. Enumerate: membership is declared (SPEC 4); basis and memory are
	// in st.

	// 3. Own store.
	des, err := r.list(r.storePath(self))
	if err != nil {
		return nil, fmt.Errorf("own store %s cannot be read: %w", self, err)
	}
	r.checkRootShape(self, des)
	r.checkI5()
	var own *chainResult
	if info, err := r.stat(r.storePath(self, "heartbeat")); err == nil && info.IsDir() {
		own = r.runC(r.storePath(self, "heartbeat"), path.Join(self, "heartbeat"), self)
		r.entries[self] = own
	}
	r.checkOwnerI3(own)
	r.ran("halts-readable")
	r.runH()
	if !cfg.DryRun {
		r.ran("own-store-writable")
		if !r.probeOwnStoreWritable() {
			r.fail("own-store-writable", "")
		}
	}
	// The re-read after the last publish (SPEC 5) is learned after the
	// cycle that wrote, so it is this cycle's finding, until a publish
	// re-reads clean again.
	if st.RereadDiffers {
		r.ran("own-store-writable")
		r.fail("own-store-writable", "re-read")
	}
	// Ownership and mode of the own store against the deployment's tree
	// (ownstore.go). The driver probes it before every cycle on the real
	// disk; the fixture harness supplies it satisfied, its trees carrying
	// no ownership. Nothing probed is nothing passed.
	r.ran("own-store-private")
	if st.OwnStorePrivate == nil {
		r.fail("own-store-private", "unprobed")
	}
	for _, subject := range st.OwnStorePrivate {
		r.fail("own-store-private", subject)
	}

	// 4. Each member A in OTHERS, in identity order.
	for _, A := range r.others {
		r.ran("store-readable:" + A)
		r.ran("member-present:" + A)
		r.ran("member-fresh:" + A)
		r.verdictFor(A)
	}
	// Noted for 10.1 before anything is written.
	inForce, found := r.haltInForce()
	out.HaltInForceBefore = inForce

	// 5. Copies, in identity order of author, each read after its original
	//    was listed and read at step 4 (r.entries; the own folder at step 3).
	for _, cd := range r.copiesToValidate() {
		r.ran("copy-readable:" + cd.Author)
		r.ran("copy-current:" + cd.Author)
		r.runK(cd)
	}
	r.ran("staging-fresh")

	// 6. Third-party accounts.
	r.checkThirdPartyAccounts()
	for _, id := range []string{"I1", "I2", "I3", "I4", "I5", "I6", "I7", "I8", "S1", "S2", "S3", "S4", "S5"} {
		r.ran(id)
	}

	// 7. Local checks, the record of when this observer began, then the
	//    traces. The local checks are handed what step 4 read of every
	//    other member (peerViews), read before the proxy's trace is: what
	//    a member published is compared with a trace at least as new.
	if cfg.Local != nil {
		for _, id := range cfg.Local.Identifiers() {
			r.ran(id)
		}
		for _, id := range cfg.Local.RingIdentifiers() {
			r.ran(id)
		}
		for _, f := range cfg.Local.Run(cfg, st, r.peerViews()) {
			r.fail(f.Check, f.Subject)
		}
	}
	// How long this deployment has actually been observed, from the record
	// written into the own store the first time this observer ran (SPEC 7,
	// <own>/since) and never rewritten. Durable across restarts, which the
	// process clock and the cycle count are not. The driver reads it on
	// start; the fixture harness supplies it, a fixture store carrying no
	// such file. Nothing is due on a clock that cannot be read, and saying
	// so is the point: an unreadable start is a fault of its own rather than
	// a licence to skip every trace check underneath it.
	r.ran("observing-since")
	if st.ObservingSince == nil {
		r.fail("observing-since", "")
	}
	r.checkTraces()
	// 7b. The cycle is timed over its work, before publication.
	r.ran("cycle-within-cadence")
	if cfg.CadenceSeconds > 0 && time.Since(start) > time.Duration(cfg.CadenceSeconds)*time.Second {
		r.fail("cycle-within-cadence", "")
	}

	// 8. The heartbeat to publish.
	if err := r.buildPublish(out); err != nil {
		return nil, err
	}

	// 9. The fault, if the local failing set changed.
	if err := r.buildFault(out); err != nil {
		return nil, err
	}

	// 10. Copies out are the driver's writes; nothing to decide.

	// 11. Halts.
	r.decideHalts(out, inForce, found)

	// The parse memory keeps what this cycle read and nothing older.
	r.parses.end()
	out.Failing = append([]Finding{}, r.findings...)
	out.Log = r.log
	return out, nil
}

// peerViews is what step 4 read of each other member, as the local checks
// receive it at step 7: the verdict, the newest heartbeat's checks when one
// parsed, and the root fault as faultAtRoot read it. A member whose fault
// procedure V never reached (absent, stale, retired, unreadable, or I1) has
// its fault noted by presence only, unread and unparsed: nothing is read
// here that step 4 did not, so no finding is added.
func (r *reader) peerViews() map[string]PeerView {
	out := make(map[string]PeerView, len(r.others))
	for _, A := range r.others {
		v := PeerView{Verdict: r.verdicts[A]}
		if cur := r.cur[A]; cur != nil {
			v.Checks = append([]string{}, cur.Checks...)
		}
		if fr, read := r.faults[A]; read {
			v.FaultPresent = fr.Present
			if fr.Parsed != nil {
				v.FaultParsed = true
				v.Failing = append([]Finding{}, fr.Parsed.Failing...)
			}
		} else {
			v.FaultPresent = r.exists(A, "fault")
		}
		out[A] = v
	}
	return out
}

// buildPublish is SPEC 13 step 8: sequence and previous from memory, boot on
// the first cycle only, observed as recorded.
func (r *reader) buildPublish(out *Outcome) error {
	memHighest, memHash := r.memoryHighest()
	pub := PublishRecord{
		Sequence: memHighest + 1,
		Observed: make(map[string]*string, len(r.others)),
		Stop:     r.cfg.Stopping,
		Checks:   append([]string{}, r.checks...),
	}
	pub.CheckCount = int64(len(pub.Checks))
	if memHighest > 0 {
		h := memHash
		pub.Previous = &h
	}
	for _, A := range r.others {
		pub.Observed[A] = r.observed[A]
	}
	if !r.st.HasBasis {
		pub.Boot = &BootRecord{Started: formatTimestamp(r.st.Started)}
		if memHighest > 0 {
			n := memHighest
			pub.Boot.ResumedFrom = &n
		}
	}
	hb := &Heartbeat{
		Observer:       r.cfg.Identity,
		Sequence:       pub.Sequence,
		Timestamp:      formatTimestamp(r.cfg.Now),
		CadenceSeconds: r.cfg.CadenceSeconds,
		Checks:         pub.Checks,
		CheckCount:     pub.CheckCount,
		Observed:       pub.Observed,
		Previous:       pub.Previous,
		Boot:           pub.Boot,
		Stop:           pub.Stop,
	}
	b, err := encodeHeartbeat(hb)
	if err != nil {
		return err
	}
	pub.Bytes = b
	out.Publish = pub
	return nil
}

// buildFault is SPEC 13 step 9 and SPEC 3.3: the fault carries the failing
// local assertions; it is written when that set changes and removed when it
// becomes empty.
func (r *reader) buildFault(out *Outcome) error {
	self := r.cfg.Identity
	var local []Finding
	isLocal := localSet(r.cfg)
	for _, f := range r.findings {
		if isLocal[f.Check] {
			local = append(local, f)
		}
	}
	out.Fault.Local = local
	held, has := r.st.Memory[path.Join(self, "fault")]
	if len(local) == 0 {
		out.Fault.Remove = has
		if has {
			r.logf("fault cleared")
		}
		return nil
	}
	b, err := encodeFault(self, local)
	if err != nil {
		return err
	}
	out.Fault.Bytes = b
	if !has || held != sha256Hex(b) {
		out.Fault.Publish = true
		r.logf("fault set changed: %v", local)
	}
	return nil
}

// probeOwnStoreWritable creates and removes the writer's own staging file in
// its heartbeat/ (SPEC 13 step 3). It is skipped in a dry run.
func (r *reader) probeOwnStoreWritable() bool {
	memHighest, _ := r.memoryHighest()
	p := r.storePath(r.cfg.Identity, "heartbeat", heartbeatName(memHighest+1)+".tmp")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return false
	}
	if err := f.Close(); err != nil {
		return false
	}
	return os.Remove(p) == nil
}

// validateConfig refuses a configuration under which the cycle would read
// two things.
func validateConfig(cfg *Config) error {
	if cfg.Identity == "" {
		return fmt.Errorf("identity is empty")
	}
	if !cfg.IsMember(cfg.Identity) {
		return fmt.Errorf("identity %q is not among the declared members", cfg.Identity)
	}
	if cfg.Coordinator != "" && !cfg.IsMember(cfg.Coordinator) {
		return fmt.Errorf("coordinator %q is not among the declared members", cfg.Coordinator)
	}
	if cfg.Window < 1 {
		return fmt.Errorf("window must be at least 1")
	}
	if cfg.MaxHeartbeatBytes < 1 || cfg.MaxFaultBytes < 1 || cfg.MaxHaltBytes < 1 {
		return fmt.Errorf("size bounds must be positive")
	}
	if cfg.StoresRoot == "" {
		return fmt.Errorf("stores root is empty")
	}
	if cfg.Now.IsZero() {
		return fmt.Errorf("now is unset")
	}
	return nil
}

// sprintf10 writes n as ten zero-padded decimal digits.
func sprintf10(n int64) string {
	return fmt.Sprintf("%010d", n)
}

// ---- the cycle's one look at the store -----------------------------------

// snapshot is the reads of one cycle, steps 3 to 7. SPEC 13 fixes the
// cycle's read order so that its findings are decidable as one look at
// the store; within that look a directory listed a second time, a path
// stat'ed a second time or a file read a second time is served from the
// first listing, stat or read, so that every check of the cycle judges
// one version of each path (I5 and procedure C judge one version of the
// own heartbeat; V2 and procedure C one listing of a peer's folder; H and
// the in-force walk one listing of the own halts/).
//
// The bound. A change that lands between the first and a later read of a
// path within one cycle is judged by the next cycle's first read instead
// of by this cycle's later read: a latency of at most one cycle. Nothing
// in the snapshot outlives the reader, which RunCycle makes anew.
//
// What stays a live read, because its point is to see the disk now:
// freshCeiling (copies.go), which re-lists the author's folder to tell a
// race from a forgery; isGone and stagingStale (chain.go), which stat a
// path after a read failed or a listing found it; step 11 (decideHalts,
// halts.go, through existsNow), whose answers drive writes; readPrefix of
// a stray; the own-store-writable probe; and everything the driver reads
// and writes after the cycle (main.go), which never holds a reader.
type snapshot struct {
	dirs  map[string]*dirListing
	stats map[string]*statResult
	files map[string]*fileRead
}

type dirListing struct {
	entries []os.DirEntry
	err     error
}

type statResult struct {
	info os.FileInfo
	err  error
}

// fileRead is a file's bytes as first read: whole (readWhole, as I5 reads
// a path memory holds), or within a bound (readEntry, as procedures C, H,
// K and V read). A whole read serves a later bounded read, the bound
// applied to the bytes; a bounded read that fetched the bytes (not
// oversized, no error) serves a later whole read, since the bytes it
// fetched are the whole file. Any other pairing reads the disk.
type fileRead struct {
	whole     bool
	max       int64
	data      []byte
	oversized bool
	err       error
	// sum is the SHA-256 of data once a check has asked for it (hashOf),
	// "" before.
	sum string
}

// The reads beneath the snapshot. They are variables only so that a test
// can count them and act between two of them.
var (
	listDir   = os.ReadDir
	statPath  = os.Lstat
	readWhole = readFile
)

func newSnapshot() *snapshot {
	return &snapshot{dirs: map[string]*dirListing{}, stats: map[string]*statResult{}, files: map[string]*fileRead{}}
}

// list is disk listed, once per cycle.
func (r *reader) list(disk string) ([]os.DirEntry, error) {
	if l, ok := r.snap.dirs[disk]; ok {
		return l.entries, l.err
	}
	des, err := listDir(disk)
	r.snap.dirs[disk] = &dirListing{entries: des, err: err}
	return des, err
}

// stat is disk stat'ed (without following a link), once per cycle.
func (r *reader) stat(disk string) (os.FileInfo, error) {
	if s, ok := r.snap.stats[disk]; ok {
		return s.info, s.err
	}
	info, err := statPath(disk)
	r.snap.stats[disk] = &statResult{info: info, err: err}
	return info, err
}

// read is the whole file at disk, once per cycle.
func (r *reader) read(disk string) ([]byte, error) {
	if f, ok := r.snap.files[disk]; ok {
		switch {
		case f.whole:
			return f.data, f.err
		case f.err == nil && !f.oversized:
			return f.data, nil
		}
	}
	data, err := readWhole(disk)
	r.snap.files[disk] = &fileRead{whole: true, data: data, err: err}
	return data, err
}

// readWithin is the file at disk read within max, once per cycle
// (readEntry on the first read).
func (r *reader) readWithin(disk string, max int64) ([]byte, bool, error) {
	if f, ok := r.snap.files[disk]; ok {
		switch {
		case f.whole && f.err != nil:
			return nil, false, f.err
		case f.whole && int64(len(f.data)) > max:
			return nil, true, nil
		case f.whole:
			return f.data, false, nil
		case f.max == max:
			return f.data, f.oversized, f.err
		}
	}
	data, oversized, err := readEntry(disk, max)
	r.snap.files[disk] = &fileRead{max: max, data: data, oversized: oversized, err: err}
	return data, oversized, err
}

// hashOf is the SHA-256 (sha256Hex) of data, the bytes a read of disk
// returned this cycle: taken once for the bytes the snapshot holds for
// disk and served to every later check that hashes those very bytes (I5
// and procedure C over the own heartbeat). Bytes that are not the
// snapshot's own, the same slice, are hashed as they are.
func (r *reader) hashOf(disk string, data []byte) string {
	f, ok := r.snap.files[disk]
	if !ok || !sameBytes(f.data, data) {
		return snapshotSum(data)
	}
	if f.sum == "" {
		f.sum = snapshotSum(f.data)
	}
	return f.sum
}

// snapshotSum is the hash hashOf takes. It is a variable only so that a
// test can count the hashes a cycle takes.
var snapshotSum = sha256Hex

// sameBytes reports whether a and b are one slice: the same length over
// the same first byte.
func sameBytes(a, b []byte) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// exists reports whether a regular file exists at the store path, as this
// cycle first saw it.
func (r *reader) exists(store string, parts ...string) bool {
	info, err := r.stat(r.storePath(store, parts...))
	return err == nil && info.Mode().IsRegular()
}

// existsNow reports whether a regular file exists at the store path now:
// the read of step 11, whose answer decides a write.
func (r *reader) existsNow(store string, parts ...string) bool {
	info, err := os.Lstat(r.storePath(store, parts...))
	return err == nil && info.Mode().IsRegular()
}
