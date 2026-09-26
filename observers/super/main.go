package main

// main.go is the thin real-disk driver: it configures one observer from
// flags, rebuilds memory on start (SPEC 7), runs the cycle (SPEC 13) and
// applies each Outcome to the store tree by staged writes (SPEC 5), in the
// order of SPEC 5 and SPEC 12. The log follows every write (SPEC 12.4).
//
// This is the super member, the coordinator (observers/README): its flag
// defaults declare the ghostunnel ring as super sees it. The structural core
// selects the coordinator's behaviour from Config when Identity equals
// Coordinator; what this member adds is its local checks (superchecks.go),
// which read the proxy's trace and judge every surface against what its
// owner published, so -traces names the trace root here as everywhere.

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// readPublished is the re-read of a just-published heartbeat (SPEC 5). It
// is a variable so that a test can make the re-read return other bytes
// than were written, which nothing on a healthy disk does.
var readPublished = readFile

// exitFunc is the single reference to os.Exit; every process exit goes
// through it.
var exitFunc = os.Exit //nolint:forbidigo // the one allowed os.Exit indirection

func main() {
	cfg, minCycle, cycles, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "observer:", err)
		exitFunc(2)
	}
	st, err := startUp(cfg)
	if err != nil {
		// No store to write a fault into and no heartbeat to make silence
		// legible: the observer does not run (SPEC 7).
		fmt.Fprintln(os.Stderr, "observer:", err)
		exitFunc(1)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	if err := run(cfg, st, minCycle, cycles, stop); err != nil {
		fmt.Fprintln(os.Stderr, "observer:", err)
		exitFunc(1)
	}
}

// run is the cycle loop (SPEC 13 step 12): one cycle after another on the
// real disk, each applied by apply, with minCycle as the floor under a cycle
// and cycles bounding the run when positive. A signal on stop, or reaching
// the bound, makes the next cycle the final one of a clean stop (SPEC 7).
// It returns nil after that stop and an error when a cycle or its
// publication failed, on which the observer goes silent.
func run(cfg *Config, st *State, minCycle time.Duration, cycles int64, stop <-chan os.Signal) error {
	for n := int64(1); ; n++ {
		select {
		case <-stop:
			cfg.Stopping = true
		default:
		}
		if cycles > 0 && n == cycles {
			// A bounded run ends with a clean stop (SPEC 7).
			cfg.Stopping = true
		}
		start := time.Now()
		cfg.Now = time.Now().UTC()
		// The record of when this observer first ran is re-read before
		// every cycle, so its deletion is this cycle's finding rather than
		// the next start's; so is the ownership of the own store.
		refreshObservingSince(cfg, st)
		refreshOwnStorePrivate(cfg, st, runtime.GOOS)
		out, err := RunCycle(cfg, st)
		if err != nil {
			return err
		}
		if err := apply(cfg, st, out); err != nil {
			// A publication that fails despite the probe passing is learned
			// too late to record; the observer goes silent and its peers
			// see the heartbeat stop (SPEC 13).
			return fmt.Errorf("publication failed: %w", err)
		}
		if cfg.Stopping {
			return nil
		}
		if d := time.Since(start); d < minCycle {
			time.Sleep(minCycle - d)
		}
	}
}

// parseFlags builds a Config from the command line. Trace schedules and
// post-condition questions are this member's own constants (step 8) and are
// not flags.
//
// The defaults are super's place in the ring: identity super, coordinator
// super (itself), membership tunnel, admin, material, super, and the copy
// cycle of SPEC 2 in the README's order (tunnel writes admin/copy, admin
// writes material/copy, material writes tunnel/copy). The coordinator's own
// copies are not a flag: copyDirsOf derives copy-tunnel, copy-admin and
// copy-material in super's store from the membership, each authored by the
// member it is named after, and copyTargets derives copy-super/ in each of
// the three others' stores. The own store is <stores>/<identity>.
func parseFlags(args []string) (*Config, time.Duration, int64, error) {
	fs := flag.NewFlagSet("observer", flag.ContinueOnError)
	local := SuperChecks{}
	cfg := &Config{}
	var members, copyAuthors, slotOwners, tree string
	var minCycle time.Duration
	var cycles int64
	fs.DurationVar(&local.TunnelMargins.LifetimeMargin, "tunnel-lifetime-margin", defaultLifetimeMargin, "the tunnel member's -lifetime-margin, which this member judges the tunnel surface with")
	fs.DurationVar(&local.TunnelMargins.ACLGrace, "tunnel-acl-grace", defaultACLGrace, "the tunnel member's -acl-grace, which this member judges the tunnel surface with")
	fs.DurationVar(&local.TunnelMargins.TickMaxAge, "tick-max-age", defaultTickMaxAge, "how old the proxy's newest tick line may be before tick-fresh fails, and how far back accept-loop looks; must exceed the proxy's --ring-tick (default 5s) by a margin, and be the same on every member")
	fs.Int64Var(&cycles, "cycles", 0, "run this many cycles then stop cleanly; 0 runs until a signal")
	fs.StringVar(&cfg.Identity, "identity", "super", "this observer's identity (its store name)")
	fs.StringVar(&members, "members", "tunnel,admin,material,super", "the declared membership, comma-separated, including this identity")
	fs.StringVar(&cfg.Coordinator, "coordinator", "super", "the member that decides the all-clear")
	fs.StringVar(&copyAuthors, "copy-authors", "tunnel=material,admin=tunnel,material=admin", "the copy cycle as store=author pairs, comma-separated")
	fs.StringVar(&slotOwners, "slot-owners", "", "the account each declared member runs as, as member=account pairs, comma-separated, every member named; the own halts/ entry named for a member must be owned by that account (SPEC 10.2 H7)")
	fs.StringVar(&cfg.StoresRoot, "stores", "/var/lib/ghostunnel-ring/stores", "the directory standing for /stores/")
	fs.StringVar(&cfg.TracesRoot, "traces", "/var/lib/ghostunnel-ring/stores/gt", "the traces directory")
	fs.StringVar(&cfg.PolicyQuery, "policy-query", "", "the proxy's --allow-query: the OPA query the policy named by the start line's policy:<hash> rule is evaluated with, for acl-substance; the trace does not record it, so it is set here, the same on every member; empty means a policy rule cannot be re-judged and acl-substance fails on every acl line under one")
	fs.StringVar(&tree, "tree", "/etc/ghostunnel/tree.tsv", "the deployment's tree (deploy/tree.tsv): owner, group and mode of every directory of the store tree, for own-store-private; read on start, on linux only")
	fs.StringVar(&cfg.AcceptNoStoreCheck, "accept-no-store-check", "", "the OS this observer runs on, as Go names it, to accept that own-store-private cannot run there; refused unless it equals this OS exactly, and refused on linux, where the check runs")
	fs.IntVar(&cfg.Window, "window", 4, "WINDOW")
	fs.Float64Var(&cfg.StaleSlack, "stale-slack", 1, "STALE_SLACK")
	fs.DurationVar(&cfg.StagingStaleAfter, "staging-stale-after", 60*time.Second, "STAGING_STALE_AFTER_SECONDS")
	fs.Int64Var(&cfg.MaxHeartbeatBytes, "max-heartbeat-bytes", 8192, "MAX_HEARTBEAT_BYTES")
	fs.Int64Var(&cfg.MaxFaultBytes, "max-fault-bytes", 8192, "MAX_FAULT_BYTES")
	fs.Int64Var(&cfg.MaxHaltBytes, "max-halt-bytes", 8192, "MAX_HALT_BYTES")
	fs.DurationVar(&cfg.HeartbeatMaxAge, "heartbeat-max-age", 0, "HEARTBEAT_MAX_AGE_SECONDS, the V4b backstop; must exceed the cadence")
	fs.Int64Var(&cfg.CadenceSeconds, "cadence", 10, "the cadence this observer declares, in seconds")
	fs.DurationVar(&minCycle, "min-cycle", 300*time.Millisecond, "MIN_CYCLE, the floor under a cycle")
	if err := fs.Parse(args); err != nil {
		return nil, 0, 0, err
	}
	for _, m := range strings.Split(members, ",") {
		if m = strings.TrimSpace(m); m != "" {
			cfg.Members = append(cfg.Members, m)
		}
	}
	cfg.CopyAuthor = map[string]string{}
	if copyAuthors != "" {
		for _, pair := range strings.Split(copyAuthors, ",") {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
				return nil, 0, 0, fmt.Errorf("copy-authors: bad pair %q", pair)
			}
			cfg.CopyAuthor[kv[0]] = kv[1]
		}
	}
	owners, err := parseSlotOwners(slotOwners, cfg.Members)
	if err != nil {
		return nil, 0, 0, err
	}
	cfg.SlotOwners = owners
	cfg.Now = time.Now().UTC()
	if err := validateConfig(cfg); err != nil {
		return nil, 0, 0, err
	}
	if cfg.CadenceSeconds < 1 {
		return nil, 0, 0, fmt.Errorf("cadence must be at least 1 second")
	}
	if cfg.HeartbeatMaxAge <= time.Duration(cfg.CadenceSeconds)*time.Second {
		return nil, 0, 0, fmt.Errorf("heartbeat-max-age must exceed the cadence (SPEC 8.1 V4b)")
	}
	for _, m := range cfg.Members {
		if m != cfg.Coordinator {
			if _, ok := cfg.CopyAuthor[m]; !ok {
				return nil, 0, 0, fmt.Errorf("copy-authors: no author for store %q", m)
			}
		}
	}
	if local.TunnelMargins.LifetimeMargin <= 0 || local.TunnelMargins.ACLGrace <= 0 {
		return nil, 0, 0, fmt.Errorf("tunnel-lifetime-margin and tunnel-acl-grace must be positive")
	}
	if local.TunnelMargins.TickMaxAge <= 0 {
		return nil, 0, 0, fmt.Errorf("tick-max-age must be positive")
	}
	cfg.Local = local
	if err := acceptNoStoreCheckValid(cfg.AcceptNoStoreCheck, runtime.GOOS); err != nil {
		return nil, 0, 0, err
	}
	if tree == "" {
		return nil, 0, 0, fmt.Errorf("tree must name the deployment's tree")
	}
	if runtime.GOOS == "linux" {
		// Read once, on start (SPEC 13 step 3). A tree that cannot be read
		// leaves OwnTree nil, which own-store-private reports every cycle
		// with subject tree rather than refusing to start, so that the
		// finding is legible in the store.
		cfg.OwnTree, _ = readStoreTree(tree, cfg.Identity)
	}
	return cfg, minCycle, cycles, nil
}

// startUp is SPEC 7: the own store must be readable and heartbeat/ must
// exist or be creatable; memory is rebuilt from what the own store holds;
// there is no basis.
func startUp(cfg *Config) (*State, error) {
	self := cfg.Identity
	own := filepath.Join(cfg.StoresRoot, self)
	if _, err := os.ReadDir(own); err != nil {
		return nil, fmt.Errorf("own store cannot be read: %w", err)
	}
	hbDir := filepath.Join(own, "heartbeat")
	if err := os.MkdirAll(hbDir, 0o755); err != nil {
		return nil, fmt.Errorf("heartbeat/ cannot be created: %w", err)
	}
	st := &State{Started: time.Now().UTC(), Memory: map[string]string{}, Unchanged: map[string]time.Duration{}}
	des, err := os.ReadDir(hbDir)
	if err != nil {
		return nil, fmt.Errorf("heartbeat/ cannot be listed: %w", err)
	}
	for _, de := range des {
		if !reHeartbeatName.MatchString(de.Name()) || !de.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(hbDir, de.Name()))
		if err != nil {
			return nil, fmt.Errorf("own heartbeat %s cannot be read: %w", de.Name(), err)
		}
		st.Memory[path.Join(self, "heartbeat", de.Name())] = sha256Hex(b)
	}
	for _, f := range []string{"fault", "halt"} {
		b, err := os.ReadFile(filepath.Join(own, f))
		if err == nil {
			st.Memory[path.Join(self, f)] = sha256Hex(b)
		}
	}
	// When this observer first ran: written once, on the first start that
	// finds no record, and then only ever read (traces.go). Written here
	// because it is a write and this is the process allowed to make them; a
	// store root this process cannot write cannot hold its fault or halt
	// either, so the observer does not run. Whatever the file holds is read
	// by the strict parser into State, nil when it cannot be read, which the
	// observing-since check reports every cycle.
	if err := writeObservingSinceOnce(own, st.Started); err != nil {
		return nil, fmt.Errorf("since cannot be written: %w", err)
	}
	st.ObservingSince = readObservingSince(own)
	return st, nil
}

// stageAndRename is SPEC 5: write the whole content to <final>.tmp in the
// same directory, close it, and rename it over the final name. The rename,
// like every removal in this file, goes through renameFile and removeFile
// (retry_windows.go, retry_other.go): on Windows an open handle elsewhere
// can block either for an instant, and nowhere else can it.
func stageAndRename(final string, data []byte) error {
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return renameFile(tmp, final)
}

// copyTargets lists the copy directories this observer writes: an
// application member writes the copy/ of the store it authors and
// copy-<self>/ in the coordinator's store; the coordinator writes
// copy-<self>/ in every other store.
func copyTargets(cfg *Config) []string {
	var out []string
	self := cfg.Identity
	if self == cfg.Coordinator {
		for _, m := range cfg.Members {
			if m != self {
				out = append(out, filepath.Join(cfg.StoresRoot, m, "copy-"+self))
			}
		}
		return out
	}
	for _, m := range cfg.Members {
		if cfg.CopyAuthor[m] == self {
			out = append(out, filepath.Join(cfg.StoresRoot, m, "copy"))
		}
	}
	if cfg.Coordinator != "" {
		out = append(out, filepath.Join(cfg.StoresRoot, cfg.Coordinator, "copy-"+self))
	}
	return out
}

// apply performs the writes an Outcome decided, in the order of SPEC 5 and
// SPEC 13 steps 8 to 11, and updates the in-process state.
func apply(cfg *Config, st *State, out *Outcome) error {
	self := cfg.Identity
	own := filepath.Join(cfg.StoresRoot, self)
	var log []string
	logf := func(format string, args ...interface{}) {
		log = append(log, fmt.Sprintf("seq=%d ", out.Publish.Sequence)+fmt.Sprintf(format, args...))
	}

	// 8. Own heartbeat, then re-read and hash the bytes on disk.
	name := heartbeatName(out.Publish.Sequence)
	hbFinal := filepath.Join(own, "heartbeat", name)
	if err := stageAndRename(hbFinal, out.Publish.Bytes); err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	reread, err := readPublished(hbFinal)
	if err != nil {
		return fmt.Errorf("heartbeat re-read: %w", err)
	}
	// A re-read that differs is own-store-writable failing (SPEC 5), learned
	// after this cycle's step 3: it is recorded for the next cycle to report
	// and stands until a publish re-reads clean.
	st.RereadDiffers = !bytes.Equal(reread, out.Publish.Bytes)
	if st.RereadDiffers {
		logf("own-store-writable: re-read bytes differ from what was written")
	}
	st.Memory[path.Join(self, "heartbeat", name)] = sha256Hex(reread)
	elapsed := time.Duration(0)
	if !st.LastCycleEnd.IsZero() {
		elapsed = time.Since(st.LastCycleEnd)
	}
	for _, A := range cfg.Others() {
		obs := out.Publish.Observed[A]
		if st.HasBasis && obs != nil && st.Basis[A] != nil && *obs == *st.Basis[A] {
			st.Unchanged[A] += elapsed
		} else {
			st.Unchanged[A] = 0
		}
	}
	st.Basis = out.Publish.Observed
	st.HasBasis = true
	st.LastCycleEnd = time.Now()

	// 9. Own fault.
	faultRel := path.Join(self, "fault")
	if out.Fault.Publish {
		if err := stageAndRename(filepath.Join(own, "fault"), out.Fault.Bytes); err != nil {
			return fmt.Errorf("fault: %w", err)
		}
		st.Memory[faultRel] = sha256Hex(out.Fault.Bytes)
	} else if out.Fault.Remove {
		if err := removeFile(filepath.Join(own, "fault")); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("fault removal: %w", err)
		}
		delete(st.Memory, faultRel)
	}

	// 10. Copies out: heartbeat then fault; then prune copies and own folder.
	for _, dir := range copyTargets(cfg) {
		if err := os.MkdirAll(filepath.Join(dir, "heartbeat"), 0o755); err != nil {
			logf("copy %s: %v", dir, err)
			continue
		}
		if err := stageAndRename(filepath.Join(dir, "heartbeat", name), reread); err != nil {
			logf("copy %s: heartbeat: %v", dir, err)
		}
		copyFault := filepath.Join(dir, "fault")
		if len(out.Fault.Local) > 0 {
			cur, err := readFile(copyFault)
			if err != nil || !bytes.Equal(cur, out.Fault.Bytes) {
				if err := stageAndRename(copyFault, out.Fault.Bytes); err != nil {
					logf("copy %s: fault: %v", dir, err)
				}
			}
		} else if err := removeFile(copyFault); err != nil && !os.IsNotExist(err) {
			logf("copy %s: fault removal: %v", dir, err)
		}
		prune(filepath.Join(dir, "heartbeat"), out.Publish.Sequence, cfg.Window, nil, "")
	}
	prune(filepath.Join(own, "heartbeat"), out.Publish.Sequence, cfg.Window, st.Memory, path.Join(self, "heartbeat"))

	// 11. Halts: raise, or clear, or relay.
	if out.Halt.Writes {
		if out.Halt.OwnHaltWritten {
			if err := stageAndRename(filepath.Join(own, "halt"), out.Halt.Bytes); err != nil {
				return fmt.Errorf("halt: %w", err)
			}
			st.Memory[path.Join(self, "halt")] = sha256Hex(out.Halt.Bytes)
		}
		for _, s := range out.Halt.Slots {
			if err := writeSlot(cfg, st, s, out.Halt.Bytes); err != nil {
				logf("halt slot in %s: %v", s, err)
			}
		}
	} else if out.Clears != nil {
		for _, rel := range out.Clears.Removes {
			if err := removeFile(filepath.Join(cfg.StoresRoot, filepath.FromSlash(rel))); err != nil && !os.IsNotExist(err) {
				logf("clear %s: %v", rel, err)
				continue
			}
			delete(st.Memory, rel)
		}
	} else if out.Relay.Active {
		for _, s := range out.Relay.Writes {
			if err := writeSlot(cfg, st, s, out.Relay.Bytes); err != nil {
				logf("relay slot in %s: %v", s, err)
			}
		}
	}

	// 12.4: the log comes after all of it; a failure to log is swallowed.
	for _, line := range out.Log {
		fmt.Fprintf(os.Stdout, "seq=%d %s\n", out.Publish.Sequence, line)
	}
	for _, line := range log {
		fmt.Fprintln(os.Stdout, line)
	}
	return nil
}

// writeSlot writes halts/<self> in store s and records it in memory.
func writeSlot(cfg *Config, st *State, s string, data []byte) error {
	final := filepath.Join(cfg.StoresRoot, s, "halts", cfg.Identity)
	if err := stageAndRename(final, data); err != nil {
		return err
	}
	st.Memory[path.Join(s, "halts", cfg.Identity)] = sha256Hex(data)
	return nil
}

// prune removes every entry with a sequence lower than highest - window + 1
// (SPEC 6), dropping pruned own entries from memory when memRel is given.
func prune(dir string, highest int64, window int, memory map[string]string, memRel string) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	floor := highest - int64(window) + 1
	for _, de := range des {
		if !reHeartbeatName.MatchString(de.Name()) {
			continue
		}
		if sequenceOfName(de.Name()) < floor {
			if err := removeFile(filepath.Join(dir, de.Name())); err == nil && memory != nil {
				delete(memory, path.Join(memRel, de.Name()))
			}
		}
	}
}
