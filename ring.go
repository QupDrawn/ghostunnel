/*-
 * Copyright 2026 Ghostunnel contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

// ring.go wires the observer ring into the proxy: the trace emitter under
// --ring-traces and the serving gate over --ring-stores. Neither is
// optional: ghostunnel never serves unobserved. The emitter is opened
// before any listener binds and the process refuses to start when it
// cannot be; the gate is consulted on every accept, and on a fresh ring
// every connection is refused until the coordinator's heartbeat is fresh
// and no halt or fault is in force (nothing stops the process from
// starting; what stops is the proxying). The trace format and the gate's
// refuse conditions are in ringtrace/README.md.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghostunnel/ghostunnel/auth"
	"github.com/ghostunnel/ghostunnel/certloader"
	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/ghostunnel/ghostunnel/proxy"
	"github.com/ghostunnel/ghostunnel/ringtrace"
)

// ringNow is the emitter's clock (a seam for tests).
var ringNow = time.Now

// ringGateDecided, when set, is called on every accept once the gate has
// decided and before Accepted returns (a seam for tests that place a halt
// at exactly that point: after the decision, before the connection).
var ringGateDecided func()

// ringWatchInterval is how often the refusal is re-evaluated for the
// connections already in flight. The gate is consulted on every accept; a
// connection accepted before a halt appeared is closed by the watch, within
// this interval of the halt.
const ringWatchInterval = time.Second

// ringGateWindow is how long a gate decision is reused by the accepts that
// follow it when no change notification is running (ringtrace.GateState):
// concurrent accepts share one scan and a burst pays one scan per window. It
// stays far below ringWatchInterval, which a test pins, so that a halt
// landing inside the window is caught by the watch as one landing during
// an accept already is.
const ringGateWindow = 10 * time.Millisecond

// validateRingFlags refuses a configuration that would leave the ring
// unable to work: the trace and store roots must be given (their defaults
// are the ring's standard tree; an empty value is not a way to turn the
// ring off) and the heartbeat window must be set explicitly, above zero,
// since the gate cannot judge a heartbeat without one and a default could
// not know the coordinator's cadence.
func validateRingFlags() error {
	if *ringTraces == "" {
		return errors.New("--ring-traces must not be empty: ghostunnel does not run without its trace")
	}
	if *ringStores == "" {
		return errors.New("--ring-stores must not be empty: ghostunnel does not run without its observer ring")
	}
	if *ringHeartbeatMaxAge <= 0 {
		return errors.New("--ring-heartbeat-max-age is required and must be above zero (longer than the observer ring coordinator's cadence)")
	}
	if *ringTick <= 0 {
		return errors.New("--ring-tick must be above zero: the trace's heartbeat cannot be turned off")
	}
	if *ringTick >= *ringHeartbeatMaxAge {
		return fmt.Errorf("--ring-tick (%s) must be below --ring-heartbeat-max-age (%s), and below the observers' cadence", *ringTick, *ringHeartbeatMaxAge)
	}
	return nil
}

// validateSandboxAcceptance decides whether the process may start, given
// --accept-no-sandbox (flagValue, "" when not given), the OS it runs on and
// the process sandbox's state as setupSandbox decided it. The kernel's
// sandbox belongs to the host; what belongs here is that the sandbox is
// attempted on every platform and that, where the platform has no facility
// at all, an operator has said so explicitly, in a way the trace records
// and that stops holding the moment the platform gains one:
//   - a state that has not been decided is refused (setupSandbox runs
//     before any validation; this is a programming error, not a
//     configuration);
//   - state unsupported without the flag: refused, naming the value that
//     would be accepted;
//   - state failed, disabled or skipped without the flag: refused, naming
//     the state, because the facility exists and did not restrict the
//     process; this build serves only sandboxed, or on a platform with no
//     facility explicitly accepted, so --disable-landlock and PKCS#11
//     (which landlock is not applied alongside) cannot be used with it;
//   - the flag on any state other than unsupported: refused, whatever that
//     state, because the facility exists there and there is nothing
//     outside the process to accept (this covers --disable-landlock and a
//     failed attempt alike, and a unit file copied from a build without a
//     sandbox to one with);
//   - the flag on state unsupported must equal the OS exactly (a unit file
//     copied to another OS without a sandbox must fail too).
func validateSandboxAcceptance(flagValue, goos, state string) error {
	if state == "" {
		return errors.New("the process sandbox state is undecided: setupSandbox must run before validation")
	}
	if flagValue == "" {
		switch state {
		case ringtrace.SandboxApplied:
			return nil
		case ringtrace.SandboxUnsupported:
			return fmt.Errorf("this build has no process sandbox; pass --accept-no-sandbox=%s to run without one", goos)
		}
		return fmt.Errorf("process sandbox state %s is refused: this build serves only sandboxed, or on a platform with no sandbox facility explicitly accepted with --accept-no-sandbox", state)
	}
	if state != ringtrace.SandboxUnsupported {
		return fmt.Errorf("--accept-no-sandbox=%s is refused: this build has a process sandbox (state %s), so there is nothing outside the process to accept", flagValue, state)
	}
	if flagValue != goos {
		return fmt.Errorf("--accept-no-sandbox=%s does not name this OS: this build is for %s; pass --accept-no-sandbox=%s", flagValue, goos, goos)
	}
	return nil
}

// ring is the emitter and the gate. It is the proxy's Observer and the
// status handler's refusal source. Both fields are set once the process
// listens; the nil checks below exist for unit tests that build an
// Environment by hand, not for any run path.
type ring struct {
	emitter *ringtrace.Emitter
	gate    *ringtrace.GateState
	mode    string
	acl     auth.ACL
	// verifier is whether a peer certificate verifier is installed on the
	// tunnel's TLS config; when it is, a handshake that completes has run it.
	verifier bool
	// loaded is what loaded the material, whose loads hand back the bytes
	// of the files they parsed (ringMaterial).
	loaded ringSources
	conns  atomic.Int64

	// failed is the first error the emitter or the chain store returned. It
	// is sticky here as well as in the emitter, because an event that could
	// not be recorded means serving cannot continue, whatever the reason;
	// once set, nothing more is written (emitAll), as nothing more could
	// be by a failed emitter.
	mu     sync.Mutex
	failed error
	// reloadFailed is the error of the last reload when it failed, or when
	// its material could not all be hashed: sticky until a later reload
	// succeeds with every hash, and a refusal to serve meanwhile, because
	// the material in memory is then not the material on disk that the
	// ring can check.
	reloadFailed error
	// statusFailed is the error the status listener's Serve returned, if
	// it did: sticky, a refusal to serve until restart, because the status
	// surface is part of what the ring observes.
	statusFailed error

	// stop ends the tick and watch goroutines; closed once by close, which
	// waits on loops for both to return before it closes the trace.
	stop     chan struct{}
	stopOnce sync.Once
	loops    sync.WaitGroup
}

// openRing opens the emitter (which stores the CA bundle the configuration
// hashed, ca, under gt/material/ and then writes the start line that
// names its hash) and builds the gate, before any listener binds. A trace
// that cannot be opened, the bundle that cannot be stored included, is an
// error on which the caller refuses to start, as is a sandbox state the
// operator has not accepted where acceptance is due (checked here again,
// against the state the start line is about to record, so nothing binds
// without it). The gate reads nothing here: whether the store tree is
// present and the coordinator alive is decided on every accept, and until
// it is, every connection is refused.
func openRing(cfg ringtrace.Config, ca []byte, acl auth.ACL, verifier bool, loaded ringSources) (*ring, error) {
	if err := validateRingFlags(); err != nil {
		return nil, err
	}
	if err := validateSandboxAcceptance(*acceptNoSandbox, runtime.GOOS, cfg.SandboxState); err != nil {
		return nil, err
	}
	r := &ring{mode: cfg.Mode, acl: acl, verifier: verifier, loaded: loaded, stop: make(chan struct{})}
	emitter, err := ringtrace.Open(*ringTraces, ringtrace.Options{Config: cfg, Now: ringNow, CABundle: ca})
	if err != nil {
		logger.Printf("error: unable to open the ring trace: %s", err)
		return nil, err
	}
	r.emitter = emitter
	logger.Printf("ring: tracing to %s as boot %d", *ringTraces, emitter.Boot())
	gate := ringtrace.NewGate(*ringStores)
	gate.MaxHeartbeatAge = *ringHeartbeatMaxAge
	r.gate = ringtrace.NewGateState(gate, ringGateWindow, ringWatchInterval)
	if err := r.gate.Watch(); err != nil {
		logger.Printf("ring: no change notification on %s (%s): the stores are scanned on every accept, %s after the last scan", *ringStores, err, ringGateWindow)
	} else {
		logger.Printf("ring: consulting the stores under %s on every accept: scanned on every change reported, and every %s regardless", *ringStores, ringWatchInterval)
	}
	r.startTick(*ringTick)
	return r, nil
}

// startTick starts tick on its own goroutine, one close waits for.
func (r *ring) startTick(interval time.Duration) {
	r.loops.Add(1)
	go func() {
		defer r.loops.Done()
		r.tick(interval)
	}()
}

// startWatch starts watch on its own goroutine, one close waits for.
func (r *ring) startWatch(p *proxy.Proxy) {
	r.loops.Add(1)
	go func() {
		defer r.loops.Done()
		r.watch(p)
	}()
}

// tick writes the trace's own heartbeat, a tick line every interval,
// through emit like every other line: a sticky failure stops the ticks,
// and their absence is what the ring reads as the trace having died. It
// runs until close.
func (r *ring) tick(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
		}
		_ = r.emit(&ringtrace.Tick{})
	}
}

// ringRules is what the start line's acl describes: the ACL handed to the
// verifier, the --allow-uri / --verify-uri patterns as given (the ACL holds
// them compiled), and whether --disable-authentication is set.
type ringRules struct {
	acl         auth.ACL
	uris        []string
	disableAuth bool
}

// aclRules is the rule in force in the start line's closed vocabulary
// (ringtrace.ACLTokens and ACLPrefixes): exactly what the verifier applies,
// sorted, without duplicates. In server mode: disable-authentication when no
// client certificate is requested; else the pins in pin mode; else
// allow-all, or every --allow-* value, and policy:<hash> when an OPA policy
// is evaluated. In client mode: the pins in pin mode (crypto/tls then
// verifies neither chain nor hostname); else verify-hostname, since
// crypto/tls verifies the server name on every dial, plus every --verify-*
// value and policy:<hash>; and disable-authentication when no client
// certificate is presented. The policy's hash is taken from the material
// list, which ringMaterial already hashed or failed on.
func aclRules(mode string, rules ringRules, material []ringtrace.Material) ([]string, error) {
	prefix := "allow"
	if mode == "client" {
		prefix = "verify"
	}
	var out []string
	acl := rules.acl
	switch {
	case mode != "client" && rules.disableAuth:
		return []string{"disable-authentication"}, nil
	case acl.PinningEnabled():
		for _, pin := range acl.AllowedPins {
			out = append(out, prefix+"-spki-pin:"+pin.String())
		}
	case mode != "client" && acl.AllowAll:
		out = append(out, "allow-all")
	default:
		if mode == "client" {
			out = append(out, "verify-hostname")
		}
		for _, cn := range acl.AllowedCNs {
			out = append(out, prefix+"-cn:"+cn)
		}
		for _, ou := range acl.AllowedOUs {
			out = append(out, prefix+"-ou:"+ou)
		}
		for _, dns := range acl.AllowedDNSs {
			out = append(out, prefix+"-dns:"+dns)
		}
		for _, ip := range acl.AllowedIPs {
			out = append(out, prefix+"-ip:"+ip.String())
		}
		for _, uri := range rules.uris {
			out = append(out, prefix+"-uri:"+uri)
		}
		if acl.AllowOPAQuery != nil {
			hash := ""
			for _, m := range material {
				if m.Material == "policy" && m.SHA256 != nil {
					hash = *m.SHA256
				}
			}
			if hash == "" {
				return nil, errors.New("an OPA policy is in force but its file has no hash")
			}
			out = append(out, "policy:"+hash)
		}
	}
	if mode == "client" && rules.disableAuth {
		out = append(out, "disable-authentication")
	}
	sort.Strings(out)
	return slices.Compact(out), nil
}

// ringProxyProtocol is the start line's name for the PROXY protocol mode
// the tunnel listener's connections are handed to the backend with. The
// mode is an enumeration of proxy's own; a value outside it is refused,
// so that a mode added there is recorded by name or not served.
func ringProxyProtocol(mode proxy.ProxyProtocolMode) (string, error) {
	switch mode {
	case proxy.ProxyProtocolOff:
		return ringtrace.ProxyProtocolOff, nil
	case proxy.ProxyProtocolConn:
		return ringtrace.ProxyProtocolConn, nil
	case proxy.ProxyProtocolTLS:
		return ringtrace.ProxyProtocolTLS, nil
	case proxy.ProxyProtocolTLSFull:
		return ringtrace.ProxyProtocolTLSFull, nil
	}
	return "", fmt.Errorf("ring: proxy protocol mode %d has no name in the trace", mode)
}

// ringConfig is the start line's summary of the configuration this process
// serves, from the parsed flags, the PROXY protocol mode the backend is
// dialed with, the TLS config actually handed to the tunnel listener (nil
// for a plaintext listener), the process sandbox's state as setupSandbox
// decided it, and the rules the verifier applies. Every value describes
// what the code at this revision does; nothing here is aspirational. The
// CA bundle's bytes as hashed are returned beside the configuration, for
// openRing to store before the start line names their hash; the material
// is what loaded handed back (ringMaterial).
func ringConfig(mode, listen, target string, proxyProtocol proxy.ProxyProtocolMode, tunnel *tls.Config, sandbox string, loaded ringSources, rules ringRules) (ringtrace.Config, []byte, error) {
	pp, err := ringProxyProtocol(proxyProtocol)
	if err != nil {
		return ringtrace.Config{}, nil, err
	}
	cfg := ringtrace.Config{
		Mode:          mode,
		Listen:        listen,
		Target:        target,
		ProxyProtocol: pp,
		// The status listener asks for a client certificate and verifies
		// it when given (VerifyClientCertIfGiven in serveStatus); it does
		// not require one.
		StatusClientCert: false,
		// cmdlineHandler serves /debug/pprof/cmdline with every value
		// replaced, and shutdownHandler acts only for a verified client
		// certificate; both whenever those endpoints are enabled.
		PprofCmdlineRedacted:       true,
		ShutdownRequiresClientCert: true,
		LifetimeCapSeconds:         lifetimeCapSeconds(*maxConnLifetime),
		SandboxState:               sandbox,
	}
	if *acceptNoSandbox != "" {
		accepted := *acceptNoSandbox
		cfg.SandboxAccepted = &accepted
	}
	if *statusAddress != "" {
		status := *statusAddress
		cfg.StatusListen = &status
	}
	if tunnel != nil {
		cfg.SessionTickets = !tunnel.SessionTicketsDisabled
		// reverifyResumedSessions (certloader) installs VerifyConnection
		// exactly when a VerifyPeerCertificate callback is present.
		cfg.VerifyOnResume = tunnel.VerifyPeerCertificate != nil && tunnel.VerifyConnection != nil
	}
	material, ca, err := ringMaterial(loaded)
	if err != nil {
		return cfg, nil, err
	}
	cfg.Material = material
	cfg.ACL, err = aclRules(mode, rules, material)
	if err != nil {
		return cfg, nil, err
	}
	if cfg.Binary, err = recordRingBinary(); err != nil {
		return cfg, nil, err
	}
	return cfg, ca, nil
}

// ringExecutable names the executable this process started from (a seam
// for tests).
var ringExecutable = os.Executable

// ringExecutableImage names the file ringBinary hashes for the resolved
// path. On Linux it is /proc/self/exe, the very file this process was
// executed from, even when the path has been replaced since the exec;
// elsewhere it is the path (a seam for tests).
var ringExecutableImage = func(path string) string {
	if runtime.GOOS == "linux" {
		return "/proc/self/exe"
	}
	return path
}

// ringBinaryRecord is ringBinary's result, taken once per process.
type ringBinaryRecord struct {
	once   sync.Once
	taken  bool
	binary ringtrace.Binary
	err    error
}

// ringStartBinary is this process's record (replaced by tests).
var ringStartBinary = &ringBinaryRecord{}

// recordRingBinary takes the record of the executable once per process and
// returns it. run calls it before the process sandbox is applied, since
// landlock grants no read of the executable; ringConfig then reads the
// record taken there.
func recordRingBinary() (ringtrace.Binary, error) {
	r := ringStartBinary
	r.once.Do(func() {
		r.binary, r.err = ringBinary()
		r.taken = true
	})
	return r.binary, r.err
}

// ringBinary is the start line's record of the executable this process
// started from: its path with every symbolic link resolved, and the
// SHA-256 of the executed file's bytes. The material observer holds the
// file at that path to this hash every cycle, and this hash to the
// operator's expectation (binary-expected). A path that cannot be
// resolved or a file that cannot be read is an error, and the process
// refuses to start on it.
func ringBinary() (ringtrace.Binary, error) {
	exe, err := ringExecutable()
	if err != nil {
		return ringtrace.Binary{}, fmt.Errorf("ring: executable: %w", err)
	}
	path, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return ringtrace.Binary{}, fmt.Errorf("ring: executable: %w", err)
	}
	f, err := os.Open(ringExecutableImage(path))
	if err != nil {
		return ringtrace.Binary{}, fmt.Errorf("ring: executable: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ringtrace.Binary{}, fmt.Errorf("ring: executable %s: %w", path, err)
	}
	return ringtrace.Binary{Path: path, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// lifetimeCapSeconds is --max-conn-lifetime in whole seconds, rounded up so
// a sub-second cap does not read as none.
func lifetimeCapSeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64(math.Ceil(d.Seconds()))
}

// ringSources is what loaded the trust material: the tunnel's TLS
// configuration source and, when --allow-policy or --verify-policy names
// one, the policy and its path.
type ringSources struct {
	tls        certloader.TLSConfigSource
	policy     policy.Policy
	policyPath string
}

// ringMaterial lists the trust material as configured, with the SHA-256 of
// each file as loaded. The certificate file, the CA bundle and the policy
// are hashed from the bytes their last successful load read and parsed or
// compiled (certloader.LoadedFiles, policy.LoadedFileOf), never from a
// second read of the path, so a file swapped after the load is not what is
// recorded; after a failed reload that is still the material of the last
// load, which is what is in use. A TLS source that does not hand its files
// back (PKCS#11, a keychain, SPIFFE) has them read here. A file that holds
// the private key (--key, or a --keystore, which holds both) is listed
// without a hash. Material that is not a file (the system trust store, a
// keychain, PKCS#11, SPIFFE, ACME) has an empty path. A file that cannot
// be read, or that its loader did not load from the configured path, is
// listed with no hash and reported in the returned error, as is a nil TLS
// source and a policy path with no policy loaded from it. The CA bundle's
// bytes, exactly those hashed, are returned beside the list (nil when
// there is no bundle file or it could not be read) for the material store
// (ringtrace.StoreMaterial, at Open and before every reload line): the
// members verify presented chains against the bundle by its hash, not by
// its path, so what was hashed must be kept.
func ringMaterial(sources ringSources) ([]ringtrace.Material, []byte, error) {
	var errs []error
	var ca []byte
	if sources.tls == nil {
		errs = append(errs, errors.New("ring: no TLS configuration source to take the loaded material from"))
	}
	loaded, fromLoader := certloader.LoadedFilesOf(sources.tls)
	// read is the file's bytes as its load read them, or as read now for
	// a TLS source that does not hand its files back.
	read := func(kind, path string) ([]byte, error) {
		if kind == "policy" {
			if loadedPath, data, ok := policy.LoadedFileOf(sources.policy); ok && loadedPath == path && data != nil {
				return data, nil
			}
			return nil, fmt.Errorf("no policy was loaded from %s", path)
		}
		if !fromLoader {
			return os.ReadFile(path)
		}
		if loaded != nil {
			switch {
			case kind == "cert" && loaded.CertificatePath == path && loaded.Certificate != nil:
				return loaded.Certificate, nil
			case kind == "ca" && loaded.CABundlePath == path && loaded.CABundle != nil:
				return loaded.CABundle, nil
			}
		}
		return nil, fmt.Errorf("the TLS configuration source did not load %s", path)
	}
	hashed := func(kind, path string) ringtrace.Material {
		m := ringtrace.Material{Material: kind, Path: path}
		if path == "" {
			return m
		}
		data, err := read(kind, path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", kind, err))
			return m
		}
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		m.SHA256 = &digest
		if kind == "ca" {
			ca = data
		}
		return m
	}
	material := []ringtrace.Material{}
	switch {
	case *keystorePath != "":
		material = append(material,
			ringtrace.Material{Material: "cert", Path: *keystorePath},
			ringtrace.Material{Material: "key", Path: *keystorePath})
	case *certPath != "":
		material = append(material, hashed("cert", *certPath), ringtrace.Material{Material: "key", Path: *keyPath})
	default:
		material = append(material, ringtrace.Material{Material: "cert"}, ringtrace.Material{Material: "key"})
	}
	material = append(material, hashed("ca", *caBundlePath))
	if sources.policyPath != "" {
		material = append(material, hashed("policy", sources.policyPath))
	}
	return material, ca, errors.Join(errs...)
}

// emit records one event. Any error, from the emitter's sticky failure or
// from a body the format refuses, stops serving: refusal reports it from
// then on. The first failure is logged.
func (r *ring) emit(body ringtrace.Body) error {
	return r.emitAll(body)
}

// emitAll records the events as consecutive lines in one write under one
// fsync (ringtrace.Emitter.EmitAll), all or nothing; otherwise as emit.
// Under a sticky failure nothing is written and the failure is returned.
func (r *ring) emitAll(bodies ...ringtrace.Body) error {
	if r == nil || r.emitter == nil {
		return nil
	}
	if err := r.stickyFailed(); err != nil {
		return err
	}
	_, err := r.emitter.EmitAll(bodies...)
	return r.noteFailure(err, bodies)
}

// stickyFailed is the ring's sticky failure, if any (noteFailure).
func (r *ring) stickyFailed() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failed
}

// emitAllAsync is emitAll with the commit left running
// (ringtrace.Emitter.EmitAllAsync): when it returns nil the lines are
// written and sequenced, and the returned wait blocks until they are
// durable and returns the commit's outcome, sticky here as any other
// failure. A failure to write is returned at once, with no wait.
func (r *ring) emitAllAsync(bodies ...ringtrace.Body) (wait func() error, err error) {
	if r == nil || r.emitter == nil {
		return func() error { return nil }, nil
	}
	if err := r.stickyFailed(); err != nil {
		return nil, err
	}
	_, w, err := r.emitter.EmitAllAsync(bodies...)
	if err != nil {
		return nil, r.noteFailure(err, bodies)
	}
	return func() error { return r.noteFailure(w(), bodies) }, nil
}

// noteFailure records the emitter's or the chain store's error, if any, as
// the ring's sticky failure, logging the first, and returns it.
func (r *ring) noteFailure(err error, bodies []ringtrace.Body) error {
	if err == nil {
		return nil
	}
	r.mu.Lock()
	first := r.failed == nil
	if first {
		r.failed = err
	}
	r.mu.Unlock()
	if first {
		kinds := make([]string, 0, len(bodies))
		for _, b := range bodies {
			if b != nil {
				kinds = append(kinds, string(b.Kind()))
			}
		}
		logger.Printf("ring: a %s event could not be recorded, refusing to serve until restart: %s", strings.Join(kinds, "+"), err)
	}
	return err
}

// statusServeFailed records that the status listener's Serve returned an
// error. Sticky: refusal reports it until restart. The first failure is
// also the one line in the trace that says why the proxy refuses from now
// on (ringtrace.Refusal, source status-listener), which every member reads
// as the admin surface's status-listener-up (SPEC 14.3). The refusal is
// in force before the line is attempted, so a trace that cannot take the
// line refuses all the same.
func (r *ring) statusServeFailed(err error) {
	if r == nil {
		return
	}
	r.mu.Lock()
	first := r.statusFailed == nil
	if first {
		r.statusFailed = err
	}
	r.mu.Unlock()
	if first {
		_ = r.emit(&ringtrace.Refusal{Source: "status-listener", Error: err.Error()})
	}
}

// stickyRefusal reports the refusals that only a restart (or, for a failed
// reload, a reload that succeeds) clears: a trace that can no longer be
// written, a reload that failed, a status listener that died. It is ""
// when none is in force. The watchdog's health is judged on these alone.
func (r *ring) stickyRefusal() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	failed, reloadFailed, statusFailed := r.failed, r.reloadFailed, r.statusFailed
	r.mu.Unlock()
	if failed != nil {
		return "ring: trace failed: " + failed.Error()
	}
	if r.emitter != nil {
		if err := r.emitter.Err(); err != nil {
			return "ring: trace failed: " + err.Error()
		}
	}
	if reloadFailed != nil {
		return "ring: last reload failed, refusing to serve until a reload succeeds: " + reloadFailed.Error()
	}
	if statusFailed != nil {
		return "ring: status listener is down, refusing to serve until restart: " + statusFailed.Error()
	}
	return ""
}

// refusal reports why serving must be refused right now: a sticky refusal,
// or the gate's reason. It is "" when serving may proceed. The gate's
// decision is the standing one when one stands (ringtrace.GateState: no
// change reported on the store tree since the scan that made it, younger
// than ringGateWindow, or than ringWatchInterval under a running watcher,
// and its heartbeat still within the window), else one full scan, shared
// with the accepts arriving while it runs. Nothing is keyed on a size or
// a modification time.
func (r *ring) refusal() string {
	return r.refusalBy(func(g *ringtrace.GateState) ringtrace.Decision { return g.Check() })
}

// refusalScanned is refusal with the store tree read afresh, whatever
// stands: the watch's call every ringWatchInterval, which is what bounds
// every standing decision to that interval.
func (r *ring) refusalScanned() string {
	return r.refusalBy(func(g *ringtrace.GateState) ringtrace.Decision { return g.Scan() })
}

func (r *ring) refusalBy(decide func(*ringtrace.GateState) ringtrace.Decision) string {
	if r == nil {
		return ""
	}
	if reason := r.stickyRefusal(); reason != "" {
		return reason
	}
	if r.gate != nil {
		if d := decide(r.gate); !d.Serve {
			return d.Reason
		}
	}
	return ""
}

// Accepted implements proxy.Observer: the gate is consulted (refusal, a
// standing decision or a shared scan) and the connection proceeds only
// when it serves. A connection the gate refuses is closed by the proxy,
// its accept and its close with reason halt recorded together, and the
// reason logged. Nothing is written for a connection that proceeds: its
// accept line is the first of the batch its handshake writes (ringConn),
// so the connection pays one sync rather than two, and the trace still
// reads start, accept, handshake, acl, close. A halt that lands after the
// decision and before the connection is served is a halt during an
// accept: the watch closes it within ringWatchInterval.
func (r *ring) Accepted(conn net.Conn) (proxy.ConnObserver, error) {
	c := &ringConn{ring: r, conn: conn, id: r.conns.Add(1), start: time.Now(),
		listener: addrString(conn.LocalAddr()), remote: addrString(conn.RemoteAddr())}
	reason := r.refusal()
	if ringGateDecided != nil {
		ringGateDecided()
	}
	if reason != "" {
		logger.Printf("ring: refusing connection from %s: %s", c.remote, reason)
		_ = c.record(&ringtrace.Close{Conn: c.id, Reason: "halt", DurationMS: c.elapsedMS()})
		return nil, errors.New(reason)
	}
	return c, nil
}

// AcceptError implements proxy.Observer: a failed Accept is recorded with
// its error and the backoff the loop sleeps, one line per backoff step. A
// line that cannot be written is the emitter's sticky failure, which
// refusal reports from then on.
func (r *ring) AcceptError(err error, backoff time.Duration) {
	_ = r.emit(&ringtrace.AcceptError{Error: err.Error(), BackoffMS: int64(backoff / time.Millisecond)})
}

// watch re-evaluates the refusal every ringWatchInterval with the store
// tree read afresh, for the connections that were accepted while serving
// was allowed: the moment it turns non-empty every connection in flight is
// closed at once, each with a close line of reason halt. A connection
// accepted while refusing never gets this far; Accepted closes it unserved.
// The scan here is also what refreshes the gate's standing decision, so no
// accept ever reuses one older than this interval. The watch runs until
// close.
func (r *ring) watch(p *proxy.Proxy) {
	ticker := time.NewTicker(ringWatchInterval)
	defer ticker.Stop()
	refusing := false
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
		}
		reason := r.refusalScanned()
		if reason == "" {
			if refusing {
				logger.Printf("ring: serving again")
				refusing = false
			}
			continue
		}
		closed := p.CloseAll(proxy.CloseHalt)
		if closed > 0 || !refusing {
			logger.Printf("ring: refusing to serve, closed %d in-flight connection(s): %s", closed, reason)
		}
		refusing = true
	}
}

// close stops the watch, the ticks and the store tree's change
// notification, then syncs and closes the trace once the proxy has drained.
// The tick and the watch have returned before the trace is closed, so
// neither writes to a closed trace.
func (r *ring) close() {
	if r == nil {
		return
	}
	r.gate.Close()
	if r.emitter == nil {
		return
	}
	r.stopOnce.Do(func() { close(r.stop) })
	r.loops.Wait()
	if err := r.emitter.Close(); err != nil {
		logger.Printf("ring: closing the trace: %s", err)
	}
}

// reloaded records the outcome of a reload and reports whether the process
// may serve after it. A reload that failed, or whose material could not all
// be hashed, or whose CA bundle could not be stored under gt/material/
// (ringtrace.StoreMaterial, before the line that would name its hash: the
// bundle a rotation in place replaced stays on record under its old hash
// and the new one is stored under the new), is a failed reload: serving is
// refused (refusal reports it) until a later reload succeeds with every
// hash and the bundle stored, and the line says so, with serving false.
// The line's serving is whether serving is allowed once this reload is
// accounted for, so a gate refusal in force shows there too.
func (r *ring) reloaded(reloadErr error) bool {
	if r == nil || r.emitter == nil {
		return reloadErr == nil
	}
	material, ca, hashErr := ringMaterial(r.loaded)
	if hashErr != nil {
		logger.Printf("ring: unable to hash the reloaded material: %s", hashErr)
	}
	storeErr := ringtrace.StoreMaterial(r.emitter.Root(), material, ca)
	if storeErr != nil {
		logger.Printf("ring: unable to store the reloaded material: %s", storeErr)
	}
	failure := errors.Join(reloadErr, hashErr, storeErr)
	r.mu.Lock()
	r.reloadFailed = failure
	r.mu.Unlock()
	serving := r.refusal() == ""
	line := &ringtrace.Reload{Outcome: "ok", Serving: serving, Material: material}
	if failure != nil {
		msg := failure.Error()
		line.Outcome, line.Error = "failed", &msg
		logger.Printf("ring: last reload failed, refusing to serve until a reload succeeds: %s", msg)
	}
	_ = r.emit(line)
	return failure == nil
}

// shutdownAllowed holds a /_shutdown caller whose certificate the status
// listener verified to the rule the tunnel applies to its clients: the
// server ACL's verifier, on the caller's certificates and verified chains.
// Where there is no such rule, in client mode or with no client
// certificate required on the tunnel (--disable-authentication, whose ACL
// allows nobody), nobody is allowed; a ring that is not there allows
// nobody either.
func (r *ring) shutdownAllowed(state *tls.ConnectionState) error {
	if r == nil {
		return errors.New("no observer ring to hold the caller to")
	}
	if r.mode != "server" {
		return errors.New("client mode has no tunnel ACL to hold the caller to")
	}
	if !r.verifier {
		return errors.New("the tunnel requires no client certificate (--disable-authentication), so no rule allows a caller")
	}
	return r.acl.VerifyPeerCertificateServer(rawCerts(state), state.VerifiedChains)
}

// shutdownRequested records a request to stop the process, from the status
// endpoint (with whether it passed the client certificate check and who
// asked), a signal, or the service manager.
func (r *ring) shutdownRequested(source string, authorized bool, peer *string, detail string) {
	_ = r.emit(&ringtrace.Shutdown{Source: source, Authorized: authorized, Peer: peer, Detail: detail})
}

// ringConn follows one accepted connection. Its accept line is written
// with the first batch recorded about it: the handshake's (with the acl
// line), or the close's when nothing else was recorded (a gate refusal, a
// dial that never reached TLS). Every batch is one write under one fsync,
// so the lines of a connection are consecutive and in order, and all of
// them are durable before any byte is forwarded. In server mode the
// handshake batch of a connection that will be forwarded (an allow) is
// written before the proxy dials and its commit is waited for in Dialed,
// after the dial and before the PROXY header and the copy loops, so the
// commit overlaps the dial; every other batch is durable when its callback
// returns.
type ringConn struct {
	ring     *ring
	conn     net.Conn
	id       int64
	start    time.Time
	listener string
	remote   string
	// accepted is whether the accept line has gone out (or been refused by
	// a failed emitter, after which nothing more is written). The
	// observer's callbacks on one connection run in sequence.
	accepted bool
	// pending waits for the handshake batch's commit when that commit was
	// left running (server mode, an allow): set by Handshake, taken by
	// Dialed, or by Closed if Dialed never ran.
	pending func() error
	// refuse is set by recordHandshake when a completed handshake was
	// recorded as denied because no rule names the peer: Dialed returns
	// it, and the proxy forwards nothing.
	refuse error
}

// errNoRule is why a completed handshake that no rule names is refused
// and recorded as a deny: the verifier could not have allowed it, so an
// allow line with rule none would be a record of a decision nobody made.
var errNoRule = errors.New("ring: the handshake completed but no rule names the peer; not forwarded")

func (c *ringConn) elapsedMS() int64 {
	return int64(time.Since(c.start) / time.Millisecond)
}

// record writes the bodies as one batch, with the accept line first when
// it has not gone out yet. A batch that cannot be recorded is the
// emitter's sticky failure, which refusal reports from then on.
func (c *ringConn) record(bodies ...ringtrace.Body) error {
	return c.ring.emitAll(c.withAccept(bodies)...)
}

// recordAsync is record with the commit left running (ring.emitAllAsync).
func (c *ringConn) recordAsync(bodies ...ringtrace.Body) (wait func() error, err error) {
	return c.ring.emitAllAsync(c.withAccept(bodies)...)
}

// withAccept prefixes the accept line to the first batch of the connection.
func (c *ringConn) withAccept(bodies []ringtrace.Body) []ringtrace.Body {
	if !c.accepted {
		c.accepted = true
		bodies = append([]ringtrace.Body{&ringtrace.Accept{Conn: c.id, Listener: c.listener, Remote: c.remote}}, bodies...)
	}
	return bodies
}

// awaitRecord waits for the handshake batch's commit when one is pending
// and clears it: the batch is durable when it returns nil. On failure the
// connection is abandoned as one whose batch could not be written is, the
// backend is closed when there is one, and the error is returned for the
// proxy to refuse the connection before it forwards anything. Nothing is
// pending in client mode, or after a deny, an error or a refusal.
func (c *ringConn) awaitRecord(backend net.Conn) error {
	if c.pending == nil {
		return nil
	}
	wait := c.pending
	c.pending = nil
	if err := wait(); err != nil {
		c.abandon()
		if backend != nil {
			_ = backend.Close()
		}
		return err
	}
	return nil
}

// abandon closes the connection whose handshake batch could not be
// recorded, or whose record's commit failed (Dialed, in which case the
// proxy closes the backend too and forwards nothing): the proxy would
// otherwise forward it with nothing recorded (the watch would close it
// within its interval; this is immediate).
func (c *ringConn) abandon() {
	if c.conn == nil {
		return
	}
	logger.Printf("ring: closing connection %d from %s: its trace could not be recorded", c.id, c.remote)
	_ = c.conn.Close()
}

// Handshake implements proxy.ConnObserver for the tunnel listener's TLS
// handshake (server mode). The verifier ran on this handshake, resumed or
// not, whenever one is installed and the handshake completed: Go runs
// VerifyPeerCertificate on a full handshake and the VerifyConnection hook
// runs it again on a resumed one. A TLS-ALPN-01 challenge probe completes
// its handshake with no client certificate asked for, so it is never
// verified, and it is denied rather than forwarded.
func (c *ringConn) Handshake(state *tls.ConnectionState, err error) {
	if err != nil {
		c.recordHandshake(state, err, false, "")
		return
	}
	if state.NegotiatedProtocol == "acme-tls/1" {
		c.recordHandshake(state, nil, false, "acme-tls/1")
		return
	}
	if !c.ring.verifier {
		c.recordHandshake(state, nil, false, "disable-authentication")
		return
	}
	// The rule is the verifier's own, named again from what this
	// connection carries: the leaf crypto/tls parsed for this handshake
	// and handed to the verifier, state.PeerCertificates[0]. The rule of
	// an allow is a function of that leaf and of configuration that lives
	// for the process (auth.ACL.ServerRule, decideServer), so the leaf as
	// a chain of one names it whoever built the verified chain, and
	// nothing read here can change between the verifier's decision and
	// this record: not the verify cache, which a reload empties, and not
	// tls.ConnectionState.VerifiedChains, which the ACL leaves empty when
	// it verifies the chain itself. A handshake that completed with no
	// certificate is one the verifier never judged (crypto/tls refuses it
	// before the callback under RequireAnyClientCert, so it is not
	// expected): nothing was verified, no rule names it, and
	// recordHandshake refuses it rather than record an allow. ServerRule
	// reads the leaf alone, never the presented bytes, so none are handed
	// to it.
	rule, verified := "none", false
	if len(state.PeerCertificates) > 0 {
		rule = c.ring.acl.ServerRule(nil, [][]*x509.Certificate{{state.PeerCertificates[0]}})
		verified = true
	}
	c.recordHandshake(state, nil, verified, rule)
}

// Dialed implements proxy.ConnObserver. In server mode it is where the
// handshake batch's commit, left running while the proxy dialed, is waited
// for: the proxy calls Dialed after the dial and before the PROXY header
// and the copy loops, so when it returns nil the connection's accept,
// handshake and acl lines are durable and no byte has been forwarded; when
// the commit failed the connection is abandoned, the backend closed, and
// the error returned, on which the proxy forwards nothing. It waits whether
// or not the dial succeeded, so the record is durable before the close
// line either way. In client mode the TLS handshake of a connection is the
// one to the target, made by the dialer, so it is recorded here, in full,
// before Dialed returns; the server's certificate is what crypto/tls, the
// pin or the --verify-* rules verified. A dial that never reached TLS (a
// connect error) records no handshake; the close that follows says error.
func (c *ringConn) Dialed(backend net.Conn, err error) error {
	if c.ring.mode != "client" {
		if err := c.awaitRecord(backend); err != nil {
			return err
		}
		return c.refuse
	}
	var opErr *net.OpError
	if err != nil && errors.As(err, &opErr) {
		return nil
	}
	var state *tls.ConnectionState
	if tlsConn, ok := backend.(*tls.Conn); ok {
		s := tlsConn.ConnectionState()
		state = &s
	}
	if err != nil {
		c.recordHandshake(state, err, false, "")
		return nil
	}
	// A backend that presented no certificate was verified by nobody: no
	// rule names it, and it is recorded as the deny it is and refused.
	rule, verified := "none", false
	if state != nil && len(state.PeerCertificates) > 0 {
		rule = c.ring.acl.ClientRule(rawCerts(state), state.VerifiedChains)
		verified = true
	}
	c.recordHandshake(state, nil, verified, rule)
	return c.refuse
}

// Closed implements proxy.ConnObserver. A connection nothing else was
// recorded about gets its accept line here, with the close. A handshake
// batch whose commit is still pending (Dialed never ran) is waited for
// first, so the close line is never written before the record is durable,
// and a failed commit is the sticky failure that refuses the close line.
func (c *ringConn) Closed(reason proxy.CloseReason) {
	if c.pending != nil {
		wait := c.pending
		c.pending = nil
		_ = wait()
	}
	_ = c.record(&ringtrace.Close{Conn: c.id, Reason: reason.String(), DurationMS: c.elapsedMS()})
}

// recordHandshake writes the accept line, the handshake line and, when an
// identity was judged, the acl line: allow under rule when the handshake
// completed and a rule names the peer, deny under acme-tls/1 for a
// challenge probe, deny under none when the handshake was refused over the
// peer's certificate or completed with no rule naming the peer (which is
// then refused at Dialed: an allow is never written under none). A
// handshake that failed before any certificate was judged (a timeout, a
// protocol error) has no acl line. The lines are one write under one fsync
// (record): nothing happens on the connection between them, and all are
// durable before any byte is forwarded. In server mode, for an allow, the
// one batch that precedes a dial, the write is done here and the commit is
// left running for Dialed to wait on (recordAsync), so it overlaps the
// dial; every other outcome (a deny, an error, a challenge probe, client
// mode) is closed right after, or is the dial itself, and is durable
// before this returns. A crash during the handshake therefore leaves no
// accept line for the connection, rather than one with no verdict; no
// plaintext flowed either way (ringtrace/README.md, accept).
//
// When the peer presented a chain, full handshake or resumed, the chain
// goes into the chain store first (storeChain) and the handshake line
// names it: the chain file is durable under its name before the line that
// names it is written, so a durable handshake line never names an absent
// chain (ringtrace/README.md section 1.5). A chain that cannot be stored
// is a record that cannot be written: the ring's sticky failure, the
// connection abandoned, nothing written for it.
func (c *ringConn) recordHandshake(state *tls.ConnectionState, err error, verified bool, rule string) {
	line := &ringtrace.Handshake{Conn: c.id, Outcome: "ok", Verified: verified}
	if state != nil {
		line.Resumed = state.DidResume
		if err == nil {
			line.Protocol = tls.VersionName(state.Version)
		}
		if len(state.PeerCertificates) > 0 {
			line.Peer = peerSummary(state.PeerCertificates[0])
			hash, chainErr := c.ring.storeChain(state)
			if chainErr != nil {
				_ = c.ring.noteFailure(chainErr, []ringtrace.Body{line})
				c.abandon()
				return
			}
			line.Chain = hash
		}
	}
	if err != nil {
		msg := err.Error()
		line.Outcome, line.Verified, line.Error = "refused", false, &msg
	}
	var acl *ringtrace.ACL
	switch {
	case err == nil && rule == "acme-tls/1":
		acl = &ringtrace.ACL{Conn: c.id, Decision: "deny", Rule: rule, Reason: "TLS-ALPN-01 challenge probe, not forwarded"}
	case err == nil && rule == "none":
		// Never an allow: the verifier allows under a rule, and a
		// completed handshake no rule names is one it never judged (no
		// certificate presented). Recorded as the deny it is, with the
		// handshake unverified, and refused before any byte is forwarded
		// (Dialed).
		c.refuse = errNoRule
		acl = &ringtrace.ACL{Conn: c.id, Decision: "deny", Rule: rule, Reason: errNoRule.Error()}
	case err == nil:
		acl = &ringtrace.ACL{Conn: c.id, Decision: "allow", Rule: rule, Reason: allowReason(rule)}
	case isIdentityRefusal(err):
		acl = &ringtrace.ACL{Conn: c.id, Decision: "deny", Rule: "none", Reason: err.Error()}
	}
	if acl != nil && acl.Decision == "allow" && c.ring.mode == "server" {
		// The proxy dials next: the commit overlaps the dial, and Dialed
		// waits for it before anything is forwarded.
		wait, err := c.recordAsync(line, acl)
		if err != nil {
			c.abandon()
			return
		}
		c.pending = wait
		return
	}
	var recErr error
	if acl == nil {
		recErr = c.record(line)
	} else {
		recErr = c.record(line, acl)
	}
	if recErr != nil {
		c.abandon()
	}
}

// allowReason is the human line for an allow under rule: "allowed by
// --<rule>" for a flag rule, spelled out for the rules the verifier names
// so that no line is built per connection.
func allowReason(rule string) string {
	switch rule {
	case "policy":
		return "allowed by the OPA policy"
	case "hostname":
		return "server name verified by crypto/tls, no --verify-* rule configured"
	case "disable-authentication":
		return "no client certificate requested (--disable-authentication)"
	case "allow-all":
		return "allowed by --allow-all"
	case "allow-cn":
		return "allowed by --allow-cn"
	case "allow-ou":
		return "allowed by --allow-ou"
	case "allow-dns":
		return "allowed by --allow-dns"
	case "allow-ip":
		return "allowed by --allow-ip"
	case "allow-uri":
		return "allowed by --allow-uri"
	case "allow-spki-pin":
		return "allowed by --allow-spki-pin"
	}
	return "allowed by --" + rule
}

// isIdentityRefusal reports whether a handshake error is about the peer's
// certificate: the verifier's refusal, a chain that did not verify, or a
// certificate that was required and not presented.
func isIdentityRefusal(err error) bool {
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		return true
	}
	msg := err.Error()
	return strings.HasPrefix(msg, "unauthorized:") || strings.Contains(msg, "certificate")
}

func rawCerts(state *tls.ConnectionState) [][]byte {
	raw := make([][]byte, len(state.PeerCertificates))
	for i, cert := range state.PeerCertificates {
		raw[i] = cert.Raw
	}
	return raw
}

// storeChain puts the chain the peer presented into the chain store under
// the trace root (ringtrace.WriteChain) and returns its name: exactly the
// bytes of every presented certificate (PeerCertificates[i].Raw, what
// rawCerts holds), concatenated in presented order, which
// x509.ParseCertificates parses back. On a resumed handshake the presented
// chain is the stored session's, which is what the verifier re-verified,
// so it is stored the same way. A chain seen before costs one stat; a
// first-seen one is written once. A ring without an emitter (unit tests
// that build an Environment by hand) stores nothing and names nothing.
func (r *ring) storeChain(state *tls.ConnectionState) (string, error) {
	if r == nil || r.emitter == nil {
		return "", nil
	}
	n := 0
	for _, cert := range state.PeerCertificates {
		n += len(cert.Raw)
	}
	der := make([]byte, 0, n)
	for _, cert := range state.PeerCertificates {
		der = append(der, cert.Raw...)
	}
	return ringtrace.WriteChain(r.emitter.Root(), der)
}

// peerSummary is the non-secret identity of a certificate.
func peerSummary(cert *x509.Certificate) *ringtrace.Peer {
	// Never nil, so a peer with no SAN records [] rather than null.
	sans := make([]string, 0, len(cert.DNSNames)+len(cert.URIs)+len(cert.IPAddresses)+len(cert.EmailAddresses))
	for _, name := range cert.DNSNames {
		sans = append(sans, "dns:"+name)
	}
	for _, uri := range cert.URIs {
		sans = append(sans, "uri:"+uri.String())
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, "ip:"+ip.String())
	}
	for _, email := range cert.EmailAddresses {
		sans = append(sans, "email:"+email)
	}
	sum := sha256.Sum256(cert.Raw)
	return &ringtrace.Peer{
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		Serial:      cert.SerialNumber.Text(16),
		SANs:        sans,
		Fingerprint: hex.EncodeToString(sum[:]),
	}
}

// addrString is an address for the trace: never empty, as a unix socket
// peer's can be.
func addrString(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	if s := addr.String(); s != "" {
		return s
	}
	return addr.Network()
}
