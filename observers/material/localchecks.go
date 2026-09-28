package main

// localchecks.go is the one per-member seam of the structural core. Which
// checks are local is an explicit list in each observer (SPEC 3.3); their
// identifiers are constants in the observer's own code (SPEC 15). The cycle
// calls Run at step 7 (SPEC 13) and lists Identifiers and RingIdentifiers in
// the heartbeat's checks.

// LocalChecks supplies the per-observer assertions about this member's own
// world: its own process, and the surface of the work it watches; and, since
// every member judges the proxy's trace for every surface (SPEC 14.3), the
// assertions it makes about what the other members published.
type LocalChecks interface {
	// Identifiers lists the check identifiers Run may report about this
	// member's own world, so the heartbeat can list what was checked and
	// the fault can tell a local finding from a structural one.
	Identifiers() []string
	// RingIdentifiers lists what Run may report about other members, once
	// per subject as SPEC 15 lists a structural check (surface-disagree:
	// admin). They are listed in the heartbeat's checks and never reach
	// the fault: a finding about another member is a halt (SPEC 3.3).
	RingIdentifiers() []string
	// Run evaluates the checks and returns the failing ones. st is the
	// reader's own state, which a check may keep memory in across cycles
	// (State.TraceSegments); peers is what step 4 read of every other
	// member.
	Run(cfg *Config, st *State, peers map[string]PeerView) []Finding
}

// NoLocalChecks is the stub the fixture harness runs with: the fixture set
// does not cover local checks. The material member's real checks (the trust
// material and its reload, observers/README) are MaterialChecks in
// materialchecks.go, which main.go selects. They are, one identifier each,
// plus trace-readable, the reading of gt/ they all rest on:
//
//   - material-loaded: the certificate, key, CA bundle and OPA policy files
//     on disk are the ones ghostunnel loaded, and each is inside its validity
//     window;
//   - binary-expected: the executable the start line names still hashes to
//     the recorded SHA-256, and that hash is the operator's
//     -expect-binary-sha256;
//   - key-private: the key file is a regular file readable by nobody but its
//     owner and its group, and this observer is neither;
//   - reload-succeeded: the last reload succeeded, and a failed reload halted
//     rather than kept serving on the old material;
//   - sandbox-applied: ghostunnel reported the process sandbox applied, or
//     the platform has none and an operator accepted that on both sides;
//   - resumption-bound: session resumption is configured so a resumed session
//     cannot bypass the access-control list.
//
// Each identifier is a constant of this member (SPEC 15) and its failure
// belongs in the fault file (SPEC 3.3). The stub reports nothing.
type NoLocalChecks struct{}

// Identifiers reports no identifiers.
func (NoLocalChecks) Identifiers() []string { return nil }

// RingIdentifiers reports no identifiers.
func (NoLocalChecks) RingIdentifiers() []string { return nil }

// Run reports nothing failing.
func (NoLocalChecks) Run(*Config, *State, map[string]PeerView) []Finding { return nil }

// structuralLocal lists the structural checks whose failure belongs in the
// fault file (SPEC 3.3): those about the reader's own store, process and the
// work on its own host. Everything else raises a halt and no fault.
var structuralLocal = map[string]bool{
	"own-store-writable":   true,
	"own-store-private":    true,
	"observing-since":      true,
	"halts-readable":       true,
	"I8":                   true,
	"cycle-within-cadence": true,
	"trace-fresh":          true,
	"trace-complete":       true,
	"trace-coverage":       true,
	"postcondition":        true,
}

// isLocal reports whether a failing check belongs in the fault file.
func isLocal(cfg *Config, check string) bool {
	if structuralLocal[check] {
		return true
	}
	if cfg.Local != nil {
		for _, id := range cfg.Local.Identifiers() {
			if id == check {
				return true
			}
		}
	}
	return false
}
