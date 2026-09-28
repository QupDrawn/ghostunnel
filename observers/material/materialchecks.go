package main

// materialchecks.go is the material member's surface (observers/README,
// "About ghostunnel"): the trust material and its reload as ghostunnel's
// own trace under gt/ records it, compared with the files on disk. The rules
// over the trace alone are surface_material.go, which every member carries;
// what is this member's alone is the disk (material-loaded, binary-expected,
// key-private), the process sandbox (sandbox-applied), the trace's own
// consistency across cycles (tracememory.go), the liveness of every boot's
// process (bootliveness.go), and the comparison of the other surfaces with
// what their owners published (surfaces.go). Every check reads the current
// boot through gtreader.go and fails closed: a trace that cannot be read, a
// current boot with no start line, a material entry with no path or no hash,
// a file that cannot be read or hashed, or a certificate that cannot be
// parsed is a finding, never a skip. A check that cannot run has not passed,
// and the heartbeat lists every identifier below as checked.
//
// Files are only ever read. The key file is never read at all: it is
// stat'ed, since the trace carries no hash for it and the observer does
// not need its content; that it is on disk is material-loaded, and that
// nobody but its owner and the proxy's group can read it, this observer
// included, is key-private (keyprivate.go).

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"
)

// The material member's own check identifiers (SPEC 15: constants of this
// member's own code). The surface's are in surface_material.go.
const (
	// checkBinaryExpected: the executable the start line names is the
	// build the operator expects, and it is still the file on disk. The
	// file at config.binary.path is a regular file of at most
	// maxBinaryBytes whose SHA-256 is config.binary.sha256, and that hash
	// is -expect-binary-sha256. Subject: "changed" when the file cannot be
	// read or hashes otherwise, since the proxy started from other bytes;
	// "unexpected" when the start line's hash is not the operator's. Both
	// can fail at once.
	checkBinaryExpected = "binary-expected"
	// checkTraceReadable: gt/ lists, the current boot reads under every
	// rule of ringtrace/README 1.4, and it holds a start line. Subject: the
	// path relative to gt/ where reading stopped, with the line when there
	// is one; "gt" for the root itself.
	checkTraceReadable = "trace-readable"
	// checkMaterialLoaded: every piece of material the process reports as
	// loaded (the start line, then each reload's list, last word wins per
	// kind and path) names a file, carries its hash unless it is the key,
	// and that file is on disk with that hash; a certificate or CA bundle
	// is PEM holding at least one certificate, every one inside its
	// validity window now; the key is a regular file. Subject: the kind.
	checkMaterialLoaded = "material-loaded"
	// checkKeyPrivate: the key the process reports as loaded is a regular
	// file with no permission bit beyond owner read and write and group
	// read, and this observer is neither its owner nor in a group that may
	// read it (keyprivate.go). Subject: no-path, unsupported-os:<GOOS>,
	// identity, stat, not-regular, mode:<octal>, readable-by-observer, or
	// none when the material list names no key.
	checkKeyPrivate = "key-private"
	// checkSandboxApplied: the start line says the process sandbox was
	// applied; or the platform has no sandbox facility (sandbox_state
	// "unsupported") and an operator accepted that on both sides of the
	// boundary for this very OS: ghostunnel's sandbox_accepted, this
	// observer's -accept-no-sandbox and runtime.GOOS all equal. The
	// sandbox itself is outside this package (it is the host's); what is
	// judged is that ghostunnel attempted it and reported truthfully, and
	// that where there is none somebody said so explicitly, in evidence,
	// and that the acceptance is invalid the moment a facility exists.
	// Subject: "" on pass; the state ("disabled", "failed", "skipped",
	// "unsupported"); "unsupported:not-accepted-by-observer",
	// "unsupported:not-accepted-by-proxy", "unsupported:acceptance-mismatch",
	// "unsupported:acceptance-not-this-os"; or "stale-acceptance" when
	// this observer carries an acceptance beside any state but
	// "unsupported". See sandboxSubjects.
	checkSandboxApplied = "sandbox-applied"
)

// MaterialChecks is the material member's LocalChecks.
type MaterialChecks struct {
	// AcceptNoSandbox is the value of -accept-no-sandbox: the OS this
	// observer's operator accepts has no process sandbox, "" when none.
	// parseFlags refuses any value but runtime.GOOS, and any value at all
	// on linux; the rule is nevertheless judged here on the value given.
	AcceptNoSandbox string
	// GOOS is the OS this observer runs on as Go names it (runtime.GOOS
	// in main.go; injected in tests). "" agrees with nothing.
	GOOS string
	// ProcRoot is where the kernel exposes each live process as <pid>/;
	// /proc on Linux, and meaningful only there (liveness_linux.go).
	ProcRoot string
	// Live reports whether a process is live. Nil selects the probe of
	// this build (platformLiveness); tests inject the process-table probe
	// over a synthetic table, or a failure.
	Live livenessProbe
	// KeyProbe lstats the key's path for key-private and says who is
	// asking. Nil selects the probe of this build (platformKeyProbe);
	// tests inject one over synthetic entries.
	KeyProbe keyProbe
	// ExpectBinarySHA256 is -expect-binary-sha256: the SHA-256 the
	// operator expects of the proxy's executable, as 64 lower-case hex
	// characters, taken from outside the host (the release's SBOM, or the
	// build's checksum at install). parseFlags refuses any other shape and
	// refuses the flag's absence; "" agrees with no start line.
	ExpectBinarySHA256 string
	// TunnelMargins are the tunnel surface's values this member judges
	// that surface with, which must be the tunnel member's own; its
	// TickMaxAge is also this member's own tick-fresh age (-tick-max-age,
	// one value on every member).
	TunnelMargins surfaceMargins
}

// Identifiers lists what Run may report about this member's own world, in
// evaluation order.
func (c MaterialChecks) Identifiers() []string {
	return []string{checkTraceReadable, checkMaterialLoaded, checkBinaryExpected, checkKeyPrivate, checkReloadSucceeded, checkSandboxApplied, checkResumptionBound, checkTickFresh, checkTraceConsistent, checkBootAmbiguous, checkBootEnded}
}

// RingIdentifiers lists what Run may report about the other members: the
// tunnel and admin surfaces, judged here and compared with what their
// owners published.
func (c MaterialChecks) RingIdentifiers() []string {
	return surfaceRingIdentifiers(surfaceMaterial)
}

// allFail is what an unreadable trace yields for the checks over the
// current boot: every one fails because none could run (tick-fresh among
// them: no reference to judge by), and trace-readable says where.
// trace-consistent, boot-ambiguous and boot-ended are not among them; they
// are judged separately.
func (c MaterialChecks) allFail(subject string) []Finding {
	out := []Finding{{Check: checkTraceReadable, Subject: subject}}
	for _, id := range c.Identifiers() {
		if id != checkTraceReadable && id != checkTraceConsistent && id != checkBootAmbiguous && id != checkBootEnded {
			out = append(out, Finding{Check: id})
		}
	}
	return out
}

// Run reads the current boot and judges it, then the trace's consistency
// with what was read last cycle, every boot's process, and the other
// surfaces against their owners' accounts.
func (c MaterialChecks) Run(cfg *Config, st *State, peers map[string]PeerView) []Finding {
	boot, listing, err := traceReadCurrent(st, cfg.TracesRoot)
	readable := err == nil && len(boot.Records) > 0 && boot.Records[0].Start != nil
	var out []Finding
	switch {
	case err != nil:
		out = c.allFail(gtSubject(err))
	case !readable:
		out = c.allFail(gtBootName(boot.Number))
	default:
		out = c.judge(boot, cfg.Now)
		out = append(out, tickFreshFindings(boot, cfg.Now, c.TunnelMargins.TickMaxAge)...)
	}
	live := c.Live
	if live == nil {
		live = platformLiveness(c.ProcRoot)
	}
	if err != nil {
		out = append(out, traceConsistentUnread()...)
		out = append(out, bootAmbiguousFindings(cfg.TracesRoot, listing, live)...)
	} else {
		previous := st.TraceBoot
		out = append(out, traceConsistentFindings(st, boot)...)
		out = append(out, bootAmbiguousFindings(cfg.TracesRoot, listing, live)...)
		out = append(out, bootEndedFindings(st, cfg.TracesRoot, previous, boot, cfg.Now, c.TunnelMargins.TickMaxAge)...)
	}
	out = append(out, surfaceDisagreements(surfaceMaterial, boot, readable, cfg.Now, c.TunnelMargins, substanceJudgeFor(cfg, st), peers)...)
	return out
}

// judge is the material member's own view of a readable current boot: the
// surface's rules, then the disk, the key's privacy and the sandbox, each
// finding once.
func (c MaterialChecks) judge(boot *gtBoot, now time.Time) []Finding {
	start := boot.Records[0].Start
	var out []Finding
	seen := map[Finding]bool{}
	fail := func(check string, subject string) {
		f := Finding{Check: check, Subject: subject}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}

	// The material now loaded: the start line's list, then each reload's,
	// the last word winning per kind and path, in first-seen order.
	type key struct{ kind, path string }
	loaded := map[key]gtMaterial{}
	var order []key
	apply := func(ms []gtMaterial) {
		for _, m := range ms {
			k := key{m.Material, m.Path}
			if _, ok := loaded[k]; !ok {
				order = append(order, k)
			}
			loaded[k] = m
		}
	}
	apply(start.Config.Material)
	for i := range boot.Records {
		if r := boot.Records[i].Reload; r != nil {
			apply(r.Material)
		}
	}
	for _, f := range materialSurfaceFindings(boot) {
		if f.Check == checkReloadSucceeded {
			fail(f.Check, f.Subject)
		}
	}
	for _, k := range order {
		if !materialOnDisk(loaded[k], now) {
			fail(checkMaterialLoaded, k.kind)
		}
	}
	for _, subject := range binarySubjects(start.Config.Binary, c.ExpectBinarySHA256) {
		fail(checkBinaryExpected, subject)
	}
	probe := c.KeyProbe
	if probe == nil {
		probe = platformKeyProbe
	}
	keys := 0
	for _, k := range order {
		if k.kind != "key" {
			continue
		}
		keys++
		if subject := keyPrivateSubject(k.path, probe); subject != "" {
			fail(checkKeyPrivate, subject)
		}
	}
	if keys == 0 {
		fail(checkKeyPrivate, "none")
	}

	for _, subject := range sandboxSubjects(start.Config.SandboxState, start.Config.SandboxAccepted, c.AcceptNoSandbox, c.GOOS) {
		fail(checkSandboxApplied, subject)
	}
	for _, f := range materialSurfaceFindings(boot) {
		if f.Check == checkResumptionBound {
			fail(f.Check, f.Subject)
		}
	}
	return out
}

// sandboxSubjects is the rule of sandbox-applied: the subjects it fails
// with, none when it passes, for a start line's sandbox_state and
// sandbox_accepted against this observer's own acceptance flag and OS.
//
//	state        flag   accepted           -> subjects
//	applied      ""     (never set)        -> pass
//	applied      set    (never set)        -> stale-acceptance
//	unsupported  ""     null               -> unsupported
//	unsupported  ""     set                -> unsupported:not-accepted-by-observer
//	unsupported  set    null               -> unsupported:not-accepted-by-proxy
//	unsupported  set    set, flag != goos  -> unsupported:acceptance-not-this-os
//	unsupported  set    set, != flag       -> unsupported:acceptance-mismatch
//	unsupported  goos   goos               -> pass
//	other        ""     (never set)        -> the state
//	other        set    (never set)        -> the state, stale-acceptance
//
// A flag beside any state but "unsupported" is stale: the platform has a
// facility, so there was nothing outside the process to accept and the
// acceptance must be withdrawn. The reader (gtreader.go) has already
// refused a trace whose acceptance sits beside any state but
// "unsupported", so accepted is nil in every row that says never set.
func sandboxSubjects(state string, accepted *string, flag, goos string) []string {
	var out []string
	switch state {
	case "applied":
		// nothing: the sandbox is applied
	case "unsupported":
		switch {
		case flag == "" && accepted == nil:
			out = append(out, "unsupported")
		case flag == "":
			out = append(out, "unsupported:not-accepted-by-observer")
		case accepted == nil:
			out = append(out, "unsupported:not-accepted-by-proxy")
		case flag != goos:
			out = append(out, "unsupported:acceptance-not-this-os")
		case *accepted != flag:
			out = append(out, "unsupported:acceptance-mismatch")
		}
		return out
	default:
		out = append(out, state)
	}
	if flag != "" {
		out = append(out, "stale-acceptance")
	}
	return out
}

// materialOnDisk reports whether one loaded entry is what is on disk: a
// path, a hash unless it is the key, the file readable with that hash, and
// a certificate or bundle inside its validity window at now.
func materialOnDisk(m gtMaterial, now time.Time) bool {
	if m.Path == "" {
		return false
	}
	if m.Material == "key" {
		info, err := os.Stat(m.Path)
		return err == nil && info.Mode().IsRegular()
	}
	if m.SHA256 == nil {
		return false
	}
	data, err := readRegular(m.Path)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != *m.SHA256 {
		return false
	}
	if m.Material == "cert" || m.Material == "ca" {
		return certificatesValid(data, now)
	}
	return true
}

// maxBinaryBytes bounds the read of the proxy's executable. A build is
// about 50 MB; a larger file is refused unread.
const maxBinaryBytes = 512 << 20

// binarySubjects is the rule of binary-expected over the start line's
// config.binary and the operator's expectation: "changed" when the file
// at the path is not the bytes the proxy hashed at start, "unexpected"
// when that hash is not the expected one; none when both hold. The file
// is hashed in full on every call.
func binarySubjects(b gtBinary, expect string) []string {
	var out []string
	if got, err := binaryDigest(b.Path); err != nil || got != b.SHA256 {
		out = append(out, "changed")
	}
	if b.SHA256 != expect {
		out = append(out, "unexpected")
	}
	return out
}

// binaryDigest returns the lower-case hex SHA-256 of the regular file at
// path. The file is judged by Lstat first: a symbolic link, a directory or
// a file above maxBinaryBytes is refused unread, and the file opened must
// be the one judged. The read is bounded by maxBinaryBytes as well, since
// the file may grow between the stat and the read. The open and the read
// run under readRetrying as one operation.
func binaryDigest(path string) (string, error) {
	var digest string
	err := readRetrying(func() error {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s: not a regular file", path)
		}
		if info.Size() > maxBinaryBytes {
			return fmt.Errorf("%s: %d bytes exceeds the bound", path, info.Size())
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		opened, err := f.Stat()
		if err != nil {
			return err
		}
		if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
			return fmt.Errorf("%s: the file opened is not the one judged", path)
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(f, maxBinaryBytes+1))
		if err != nil {
			return err
		}
		if n > maxBinaryBytes {
			return fmt.Errorf("%s: exceeds the bound", path)
		}
		digest = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	return digest, err
}

// readRegular reads a regular file whole.
func readRegular(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}
	return io.ReadAll(f)
}

// certificatesValid reports whether data is PEM holding at least one
// CERTIFICATE block, every one of which parses and is inside its validity
// window at now. Anything else, including a file with no certificate in it,
// cannot be judged and is not valid.
func certificatesValid(data []byte, now time.Time) bool {
	found := false
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		found = true
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false
		}
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return false
		}
	}
	return found
}
