// Package ringtrace is ghostunnel's half of the observer ring: the trace it
// appends under gt/ (Emitter), the reference reader of that trace (Read),
// and the gate it consults before serving a connection (Gate).
//
// It shares no code with the observers. Everything here that reads the
// store tree is an independent implementation of the observer
// specification, which is the point: two readers that agree only by being
// written to the same description. README.md in this directory is that
// description for the trace.
package ringtrace

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Version is the trace format version every line carries.
const Version = 1

// MaxLineBytes bounds one trace line including its line feed. The emitter
// refuses to write a longer line and the reader treats a longer complete
// line as malformed.
const MaxLineBytes = 64 * 1024

// ErrLineTooLong is returned when a line would exceed MaxLineBytes.
var ErrLineTooLong = errors.New("ringtrace: line exceeds MaxLineBytes")

// Kind is the value of the "kind" key, the first key of every line.
type Kind string

// The trace kinds.
const (
	KindStart       Kind = "start"
	KindAccept      Kind = "accept"
	KindHandshake   Kind = "handshake"
	KindACL         Kind = "acl"
	KindClose       Kind = "close"
	KindReload      Kind = "reload"
	KindShutdown    Kind = "shutdown"
	KindTick        Kind = "tick"
	KindAcceptError Kind = "accept-error"
	KindRefusal     Kind = "refusal"
)

// kinds is every kind, in the order the README lists them.
var kinds = []Kind{KindStart, KindAccept, KindHandshake, KindACL, KindClose, KindReload, KindShutdown, KindTick, KindAcceptError, KindRefusal}

// Body is the kind-specific part of a line.
type Body interface {
	Kind() Kind
	validate() error
}

// Record is one trace line: the header shared by every kind and the body.
type Record struct {
	Sequence int64
	At       time.Time
	Body     Body
}

// Start is the first line of every boot: what this process is serving.
type Start struct {
	Boot   int64  `json:"boot"`
	PID    int64  `json:"pid"`
	Config Config `json:"config"`
}

// Config is the non-secret summary of the configuration the process serves.
type Config struct {
	Mode   string `json:"mode"`
	Listen string `json:"listen"`
	Target string `json:"target"`
	// ProxyProtocol is the PROXY protocol v2 header the backend receives
	// ahead of each connection's bytes, one of ProxyProtocols: off, or
	// the mode of --proxy-protocol-mode (conn, tls, tls-full; tls-full
	// hands the backend the client's whole certificate). It changes what
	// the target is given, so it is compared, like the target itself.
	ProxyProtocol    string  `json:"proxy_protocol"`
	StatusListen     *string `json:"status_listen"`
	StatusClientCert bool    `json:"status_client_cert"`
	// PprofCmdlineRedacted and ShutdownRequiresClientCert describe the
	// admin surface: whether /debug/pprof/cmdline, when served, redacts
	// every argument value, and whether /_shutdown, when served, acts only
	// for a caller with a verified client certificate.
	PprofCmdlineRedacted       bool `json:"pprof_cmdline_redacted"`
	ShutdownRequiresClientCert bool `json:"shutdown_requires_client_cert"`
	SessionTickets             bool `json:"session_tickets"`
	VerifyOnResume             bool `json:"verify_on_resume"`
	// ACL is the rule in force, exactly what the verifier applies, as
	// non-secret strings from the closed vocabulary of ACLTokens and
	// ACLPrefixes, sorted and without duplicates. Never empty: ghostunnel
	// never serves under no rule.
	ACL                []string `json:"acl"`
	LifetimeCapSeconds int64    `json:"lifetime_cap_seconds"`
	// SandboxState is the outcome of the process sandbox attempt at
	// startup, one of SandboxStates; landlock is the facility on Linux.
	// SandboxAccepted is the OS an operator named with --accept-no-sandbox
	// to run a build whose state is unsupported, else nil.
	SandboxState    string     `json:"sandbox_state"`
	SandboxAccepted *string    `json:"sandbox_accepted"`
	Material        []Material `json:"material"`
	// Binary is the proxy's own executable as this process started from
	// it. Always present: a start line that does not say which file was
	// executed cannot be held to the operator's expectation of it.
	Binary Binary `json:"binary"`
}

// Binary is the executable a process started from: the path it was
// executed from with every symbolic link resolved, and the lower-case hex
// SHA-256 of the executed file's bytes, read once at startup.
type Binary struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// The PROXY protocol v2 modes a start line reports: what the backend is
// handed ahead of each connection.
const (
	// ProxyProtocolOff: no header; the backend receives the bytes alone.
	ProxyProtocolOff = "off"
	// ProxyProtocolConn: the connection's addresses only.
	ProxyProtocolConn = "conn"
	// ProxyProtocolTLS: the addresses and the TLS version, ALPN and SNI.
	ProxyProtocolTLS = "tls"
	// ProxyProtocolTLSFull: all of the above and the client's certificate,
	// its common name and its whole DER encoding.
	ProxyProtocolTLSFull = "tls-full"
)

// The process sandbox states a start line reports.
const (
	// SandboxApplied: the platform sandbox was applied and the kernel
	// enforces it.
	SandboxApplied = "applied"
	// SandboxUnsupported: this build has no sandbox facility at all.
	SandboxUnsupported = "unsupported"
	// SandboxDisabled: the operator turned the sandbox off
	// (--disable-landlock).
	SandboxDisabled = "disabled"
	// SandboxFailed: the facility exists but the attempt errored or the
	// kernel does not enforce it; nothing was restricted.
	SandboxFailed = "failed"
	// SandboxSkipped: the sandbox was not attempted because PKCS#11 is in
	// use, which landlock is not applied alongside.
	SandboxSkipped = "skipped"
)

// Material is one piece of trust material as loaded.
type Material struct {
	Material string  `json:"material"`
	Path     string  `json:"path"`
	SHA256   *string `json:"sha256"`
}

// Accept is a connection accepted on the tunnel listener.
type Accept struct {
	Conn     int64  `json:"conn"`
	Listener string `json:"listener"`
	Remote   string `json:"remote"`
}

// Handshake is the outcome of the TLS handshake on a connection.
type Handshake struct {
	Conn     int64   `json:"conn"`
	Outcome  string  `json:"outcome"`
	Resumed  bool    `json:"resumed"`
	Verified bool    `json:"verified"`
	Protocol string  `json:"protocol"`
	Peer     *Peer   `json:"peer"`
	Error    *string `json:"error"`
	// Chain names the chain the peer presented in the chain store
	// (README.md section 1.5; WriteChain, ReadChain): the lower-case hex
	// SHA-256 of the presented certificates' DER concatenated in presented
	// order, which is the file gt/chains/<chain>.der. The one optional key
	// of the format: absent when no certificate was presented.
	Chain string `json:"chain,omitempty"`
}

// Peer is the non-secret identity of a client certificate.
type Peer struct {
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	Serial      string   `json:"serial"`
	SANs        []string `json:"sans"`
	Fingerprint string   `json:"fingerprint"`
}

// ACL is an access-control decision on a connection.
type ACL struct {
	Conn     int64  `json:"conn"`
	Decision string `json:"decision"`
	Rule     string `json:"rule"`
	Reason   string `json:"reason"`
}

// Close is the end of a connection.
type Close struct {
	Conn       int64  `json:"conn"`
	Reason     string `json:"reason"`
	DurationMS int64  `json:"duration_ms"`
}

// Reload is the outcome of a reload of trust material.
type Reload struct {
	Outcome  string     `json:"outcome"`
	Error    *string    `json:"error"`
	Serving  bool       `json:"serving"`
	Material []Material `json:"material"`
}

// Shutdown is a request to stop the process.
type Shutdown struct {
	Source     string  `json:"source"`
	Authorized bool    `json:"authorized"`
	Peer       *string `json:"peer"`
	Detail     string  `json:"detail"`
}

// Tick is the trace's own heartbeat: a line with the header and nothing
// else, written on a fixed cadence through the same path as every other
// line, so that an emitter that has stopped can be told from one that has
// nothing to say.
type Tick struct{}

// AcceptError is a failed Accept on the tunnel listener: the error (no
// secret is ever in one) and the backoff the accept loop sleeps before its
// next attempt, in milliseconds. One line per failed Accept, which is one
// per backoff step.
type AcceptError struct {
	Error     string `json:"error"`
	BackoffMS int64  `json:"backoff_ms"`
}

// Refusal is the process refusing to serve until restart for a reason no
// other line records: Source is what failed, one of RefusalSources, and
// Error the error as it was reported (never a secret). Written once, when
// the status listener's Serve returns an error; the other sticky refusals
// need no line of their own (a failed reload writes reload, a trace that
// can no longer be written cannot write one).
type Refusal struct {
	Source string `json:"source"`
	Error  string `json:"error"`
}

func (*Tick) Kind() Kind        { return KindTick }
func (*AcceptError) Kind() Kind { return KindAcceptError }
func (*Refusal) Kind() Kind     { return KindRefusal }
func (*Start) Kind() Kind       { return KindStart }
func (*Accept) Kind() Kind      { return KindAccept }
func (*Handshake) Kind() Kind   { return KindHandshake }
func (*ACL) Kind() Kind         { return KindACL }
func (*Close) Kind() Kind       { return KindClose }
func (*Reload) Kind() Kind      { return KindReload }
func (*Shutdown) Kind() Kind    { return KindShutdown }

// Key sets, documented in README.md. headerKeys lead every line.
var (
	headerKeys   = []string{"kind", "version", "sequence", "at"}
	ConfigKeys   = []string{"mode", "listen", "target", "proxy_protocol", "status_listen", "status_client_cert", "pprof_cmdline_redacted", "shutdown_requires_client_cert", "session_tickets", "verify_on_resume", "acl", "lifetime_cap_seconds", "sandbox_state", "sandbox_accepted", "material", "binary"}
	MaterialKeys = []string{"material", "path", "sha256"}
	BinaryKeys   = []string{"path", "sha256"}
	PeerKeys     = []string{"subject", "issuer", "serial", "sans", "fingerprint"}

	bodyKeys = map[Kind][]string{
		KindStart:       {"boot", "pid", "config"},
		KindAccept:      {"conn", "listener", "remote"},
		KindHandshake:   {"conn", "outcome", "resumed", "verified", "protocol", "peer", "error", "chain"},
		KindACL:         {"conn", "decision", "rule", "reason"},
		KindClose:       {"conn", "reason", "duration_ms"},
		KindReload:      {"outcome", "error", "serving", "material"},
		KindShutdown:    {"source", "authorized", "peer", "detail"},
		KindTick:        {},
		KindAcceptError: {"error", "backoff_ms"},
		KindRefusal:     {"source", "error"},
	}

	// optionalKeys are the keys a line of a kind may leave out: written
	// only when they have a value, tolerated absent by the reader, refused
	// present with a value outside their type. Every other key is required.
	optionalKeys = map[Kind][]string{
		KindHandshake: {"chain"},
	}
)

// The enumerations. Each is closed; a value outside it is refused by the
// emitter and malformed to the reader.
var (
	Modes            = []string{"server", "client"}
	Materials        = []string{"cert", "key", "ca", "policy"}
	HandshakeOutcome = []string{"ok", "refused"}
	Decisions        = []string{"allow", "deny"}
	CloseReasons     = []string{"eof", "error", "lifetime", "shutdown", "halt", "refused"}
	ReloadOutcomes   = []string{"ok", "failed"}
	ShutdownSources  = []string{"signal", "status-endpoint", "service-control", "ring-halt", "internal"}
	// RefusalSources is what a refusal line may name as having failed: a
	// closed set of one, so that a later refusal with a source of its own
	// extends the set rather than the format.
	RefusalSources = []string{"status-listener"}
	ProxyProtocols = []string{ProxyProtocolOff, ProxyProtocolConn, ProxyProtocolTLS, ProxyProtocolTLSFull}
	SandboxStates  = []string{SandboxApplied, SandboxUnsupported, SandboxDisabled, SandboxFailed, SandboxSkipped}

	// The config.acl vocabulary. ACLTokens stand alone; an ACLPrefixes
	// entry is followed by the rule's value, which is non-empty, and for
	// policy is the SHA-256 of the policy file.
	ACLTokens   = []string{"allow-all", "verify-hostname", "disable-authentication"}
	ACLPrefixes = []string{"allow-cn:", "allow-ou:", "allow-dns:", "allow-ip:", "allow-uri:", "allow-spki-pin:", "verify-cn:", "verify-ou:", "verify-dns:", "verify-ip:", "verify-uri:", "verify-spki-pin:", "policy:"}
)

// Keys returns the exact key set of a line of the given kind, in the order
// written, or nil for an unknown kind.
func Keys(kind Kind) []string {
	body, ok := bodyKeys[kind]
	if !ok {
		return nil
	}
	return append(append([]string{}, headerKeys...), body...)
}

// OptionalKeys returns the keys of Keys(kind) a line may leave out, or nil
// when every key is required (every kind but handshake, whose chain is
// absent when no certificate was presented).
func OptionalKeys(kind Kind) []string {
	return append([]string{}, optionalKeys[kind]...)
}

// ClassifyLine returns the kind a line's first bytes declare, or "" when
// they do not begin with a trace marker. A marker is exactly
// {"kind":"<kind>", with no whitespace; classification reads no further.
func ClassifyLine(line []byte) Kind {
	for _, k := range kinds {
		if bytes.HasPrefix(line, marker(k)) {
			return k
		}
	}
	return ""
}

func marker(k Kind) []byte { return []byte(`{"kind":"` + string(k) + `",`) }

// ---- validation shared by encoder and decoder ----

func oneOf(value string, set []string, name string) error {
	for _, s := range set {
		if value == s {
			return nil
		}
	}
	return fmt.Errorf("%s: %q is not one of %v", name, value, set)
}

func nonEmpty(value, name string) error {
	if value == "" {
		return fmt.Errorf("%s: empty", name)
	}
	return nil
}

func positive(v int64, name string) error {
	if v < 1 {
		return fmt.Errorf("%s: %d is not positive", name, v)
	}
	return nil
}

func nonNegative(v int64, name string) error {
	if v < 0 {
		return fmt.Errorf("%s: %d is negative", name, v)
	}
	return nil
}

// noPEM refuses any string that carries a PEM header: a caller that put
// key material or a certificate body into a field is refused, not recorded.
func noPEM(value, name string) error {
	if strings.Contains(value, "-----BEGIN") {
		return fmt.Errorf("%s: contains a PEM block", name)
	}
	return nil
}

func noPEMPtr(value *string, name string) error {
	if value == nil {
		return nil
	}
	return noPEM(*value, name)
}

func validateMaterials(ms []Material, name string) error {
	if ms == nil {
		return fmt.Errorf("%s: nil", name)
	}
	for i, m := range ms {
		n := fmt.Sprintf("%s[%d]", name, i)
		if err := oneOf(m.Material, Materials, n+".material"); err != nil {
			return err
		}
		if err := noPEM(m.Path, n+".path"); err != nil {
			return err
		}
		if m.SHA256 != nil {
			if m.Material == "key" {
				return fmt.Errorf("%s: a key never carries a hash", n)
			}
			if !reHash.MatchString(*m.SHA256) {
				return fmt.Errorf("%s.sha256: not a lower-case SHA-256 hex string", n)
			}
		}
	}
	return nil
}

// validateACL holds config.acl to the closed vocabulary: non-empty, every
// entry a token or a prefix with a non-empty value (a hash after policy),
// no PEM, and strictly ascending so the list is sorted and has no
// duplicates.
func validateACL(rules []string) error {
	if rules == nil {
		return errors.New("config.acl: nil")
	}
	if len(rules) == 0 {
		return errors.New("config.acl: empty")
	}
	for i, rule := range rules {
		name := fmt.Sprintf("config.acl[%d]", i)
		if err := noPEM(rule, name); err != nil {
			return err
		}
		if i > 0 && rule <= rules[i-1] {
			return fmt.Errorf("%s: %q is not sorted after %q, or repeats it", name, rule, rules[i-1])
		}
		if err := validateACLRule(rule, name); err != nil {
			return err
		}
	}
	return nil
}

func validateACLRule(rule, name string) error {
	for _, token := range ACLTokens {
		if rule == token {
			return nil
		}
	}
	for _, prefix := range ACLPrefixes {
		if !strings.HasPrefix(rule, prefix) {
			continue
		}
		value := rule[len(prefix):]
		if value == "" {
			return fmt.Errorf("%s: %q has no value", name, rule)
		}
		if prefix == "policy:" && !reHash.MatchString(value) {
			return fmt.Errorf("%s: policy is not followed by a lower-case SHA-256 hex string", name)
		}
		return nil
	}
	return fmt.Errorf("%s: %q is not in the vocabulary %v %v", name, rule, ACLTokens, ACLPrefixes)
}

func (s *Start) validate() error {
	if err := positive(s.Boot, "boot"); err != nil {
		return err
	}
	if err := positive(s.PID, "pid"); err != nil {
		return err
	}
	c := &s.Config
	if err := oneOf(c.Mode, Modes, "config.mode"); err != nil {
		return err
	}
	for name, v := range map[string]string{"config.listen": c.Listen, "config.target": c.Target} {
		if err := nonEmpty(v, name); err != nil {
			return err
		}
		if err := noPEM(v, name); err != nil {
			return err
		}
	}
	if err := oneOf(c.ProxyProtocol, ProxyProtocols, "config.proxy_protocol"); err != nil {
		return err
	}
	if err := noPEMPtr(c.StatusListen, "config.status_listen"); err != nil {
		return err
	}
	if err := validateACL(c.ACL); err != nil {
		return err
	}
	if err := nonNegative(c.LifetimeCapSeconds, "config.lifetime_cap_seconds"); err != nil {
		return err
	}
	if err := oneOf(c.SandboxState, SandboxStates, "config.sandbox_state"); err != nil {
		return err
	}
	if c.SandboxAccepted != nil {
		if err := nonEmpty(*c.SandboxAccepted, "config.sandbox_accepted"); err != nil {
			return err
		}
		if err := noPEM(*c.SandboxAccepted, "config.sandbox_accepted"); err != nil {
			return err
		}
	}
	if err := validateMaterials(c.Material, "config.material"); err != nil {
		return err
	}
	return validateBinary(c.Binary)
}

// validateBinary holds config.binary to its shape: a path that is not
// empty and carries no PEM, and a lower-case SHA-256 hex string.
func validateBinary(b Binary) error {
	if err := nonEmpty(b.Path, "config.binary.path"); err != nil {
		return err
	}
	if err := noPEM(b.Path, "config.binary.path"); err != nil {
		return err
	}
	if !reHash.MatchString(b.SHA256) {
		return errors.New("config.binary.sha256: not a lower-case SHA-256 hex string")
	}
	return nil
}

func (a *Accept) validate() error {
	if err := positive(a.Conn, "conn"); err != nil {
		return err
	}
	for name, v := range map[string]string{"listener": a.Listener, "remote": a.Remote} {
		if err := nonEmpty(v, name); err != nil {
			return err
		}
		if err := noPEM(v, name); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handshake) validate() error {
	if err := positive(h.Conn, "conn"); err != nil {
		return err
	}
	if err := oneOf(h.Outcome, HandshakeOutcome, "outcome"); err != nil {
		return err
	}
	if err := noPEM(h.Protocol, "protocol"); err != nil {
		return err
	}
	if err := noPEMPtr(h.Error, "error"); err != nil {
		return err
	}
	if p := h.Peer; p != nil {
		for name, v := range map[string]string{"peer.subject": p.Subject, "peer.issuer": p.Issuer, "peer.serial": p.Serial} {
			if err := noPEM(v, name); err != nil {
				return err
			}
		}
		if p.SANs == nil {
			return errors.New("peer.sans: nil")
		}
		for i, s := range p.SANs {
			if err := noPEM(s, fmt.Sprintf("peer.sans[%d]", i)); err != nil {
				return err
			}
		}
		if !reHash.MatchString(p.Fingerprint) {
			return errors.New("peer.fingerprint: not a lower-case SHA-256 hex string")
		}
	}
	if h.Chain != "" && !reHash.MatchString(h.Chain) {
		return errors.New("chain: not a lower-case SHA-256 hex string")
	}
	return nil
}

func (a *ACL) validate() error {
	if err := positive(a.Conn, "conn"); err != nil {
		return err
	}
	if err := oneOf(a.Decision, Decisions, "decision"); err != nil {
		return err
	}
	if err := nonEmpty(a.Rule, "rule"); err != nil {
		return err
	}
	for name, v := range map[string]string{"rule": a.Rule, "reason": a.Reason} {
		if err := noPEM(v, name); err != nil {
			return err
		}
	}
	return nil
}

func (c *Close) validate() error {
	if err := positive(c.Conn, "conn"); err != nil {
		return err
	}
	if err := oneOf(c.Reason, CloseReasons, "reason"); err != nil {
		return err
	}
	return nonNegative(c.DurationMS, "duration_ms")
}

func (r *Reload) validate() error {
	if err := oneOf(r.Outcome, ReloadOutcomes, "outcome"); err != nil {
		return err
	}
	if err := noPEMPtr(r.Error, "error"); err != nil {
		return err
	}
	return validateMaterials(r.Material, "material")
}

func (s *Shutdown) validate() error {
	if err := oneOf(s.Source, ShutdownSources, "source"); err != nil {
		return err
	}
	if err := noPEMPtr(s.Peer, "peer"); err != nil {
		return err
	}
	return noPEM(s.Detail, "detail")
}

func (*Tick) validate() error { return nil }

func (a *AcceptError) validate() error {
	if err := nonEmpty(a.Error, "error"); err != nil {
		return err
	}
	if err := noPEM(a.Error, "error"); err != nil {
		return err
	}
	return nonNegative(a.BackoffMS, "backoff_ms")
}

func (r *Refusal) validate() error {
	if err := oneOf(r.Source, RefusalSources, "source"); err != nil {
		return err
	}
	if err := nonEmpty(r.Error, "error"); err != nil {
		return err
	}
	return noPEM(r.Error, "error")
}

// ---- encoding ----

// lineSizeHint is the capacity a line is started with: every kind but a
// start line fits, so encoding is one allocation. A start line carries
// the whole config, with its rule set and several materials (about 900
// bytes with three materials and a policy), so it starts at
// startLineSizeHint and is one allocation too rather than three growths.
const (
	lineSizeHint      = 512
	startLineSizeHint = 2048
)

// EncodeLine produces the bytes of one line, ending in exactly one LF. The
// record is validated first; nothing invalid is ever encoded.
//
// The line is written by hand, key by key in the order Keys documents, and
// is byte-identical to what encoding/json's Marshal produces from the
// tagged structs above (oldEncodeLine in the tests, the oracle of
// TestEncodeLineMatchesJSON): integers in plain decimal,
// booleans as true/false, strings escaped exactly as appendString says, a
// nil *string, *Peer, []string or []Material as null, an empty slice as [],
// nested objects with their keys in the documented order, and chain (the
// one omitempty key) left out when empty. The struct tags stay what
// TestDocumentedKeysMatchStructs pins them to, so the two descriptions of
// the format cannot drift apart unnoticed.
func EncodeLine(r Record) ([]byte, error) {
	hint := lineSizeHint
	if r.Body != nil && r.Body.Kind() == KindStart {
		hint = startLineSizeHint
	}
	out, err := AppendLine(make([]byte, 0, hint), r)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AppendLine appends the line EncodeLine produces for r to dst and returns
// the extended slice: the same bytes, into a buffer the caller sized, so
// that a batch of lines is one allocation (the emitter's write). On an
// error nothing has been appended and dst is returned as given.
func AppendLine(dst []byte, r Record) ([]byte, error) {
	if r.Body == nil {
		return dst, errors.New("ringtrace: nil body")
	}
	if err := positive(r.Sequence, "sequence"); err != nil {
		return dst, fmt.Errorf("ringtrace: %v", err)
	}
	if r.At.IsZero() {
		return dst, errors.New("ringtrace: zero time")
	}
	if err := r.Body.validate(); err != nil {
		return dst, fmt.Errorf("ringtrace: %s: %v", r.Body.Kind(), err)
	}
	out := dst
	out = append(out, `{"kind":`...)
	out = appendString(out, string(r.Body.Kind()))
	out = append(out, `,"version":`...)
	out = strconv.AppendInt(out, Version, 10)
	out = append(out, `,"sequence":`...)
	out = strconv.AppendInt(out, r.Sequence, 10)
	out = append(out, `,"at":"`...)
	// timestampLayout is digits, '-', ':', 'T' and a literal 'Z': nothing
	// appendString would escape, so the bytes are what quoting
	// formatTimestamp(r.At) gives, written in place.
	out = r.At.UTC().AppendFormat(out, timestampLayout)
	out = append(out, '"')
	switch b := r.Body.(type) {
	case *Start:
		out = append(out, `,"boot":`...)
		out = strconv.AppendInt(out, b.Boot, 10)
		out = append(out, `,"pid":`...)
		out = strconv.AppendInt(out, b.PID, 10)
		out = append(out, `,"config":`...)
		out = appendConfig(out, &b.Config)
	case *Accept:
		out = append(out, `,"conn":`...)
		out = strconv.AppendInt(out, b.Conn, 10)
		out = append(out, `,"listener":`...)
		out = appendString(out, b.Listener)
		out = append(out, `,"remote":`...)
		out = appendString(out, b.Remote)
	case *Handshake:
		out = append(out, `,"conn":`...)
		out = strconv.AppendInt(out, b.Conn, 10)
		out = append(out, `,"outcome":`...)
		out = appendString(out, b.Outcome)
		out = append(out, `,"resumed":`...)
		out = strconv.AppendBool(out, b.Resumed)
		out = append(out, `,"verified":`...)
		out = strconv.AppendBool(out, b.Verified)
		out = append(out, `,"protocol":`...)
		out = appendString(out, b.Protocol)
		out = append(out, `,"peer":`...)
		out = appendPeer(out, b.Peer)
		out = append(out, `,"error":`...)
		out = appendStringPtr(out, b.Error)
		if b.Chain != "" {
			out = append(out, `,"chain":`...)
			out = appendString(out, b.Chain)
		}
	case *ACL:
		out = append(out, `,"conn":`...)
		out = strconv.AppendInt(out, b.Conn, 10)
		out = append(out, `,"decision":`...)
		out = appendString(out, b.Decision)
		out = append(out, `,"rule":`...)
		out = appendString(out, b.Rule)
		out = append(out, `,"reason":`...)
		out = appendString(out, b.Reason)
	case *Close:
		out = append(out, `,"conn":`...)
		out = strconv.AppendInt(out, b.Conn, 10)
		out = append(out, `,"reason":`...)
		out = appendString(out, b.Reason)
		out = append(out, `,"duration_ms":`...)
		out = strconv.AppendInt(out, b.DurationMS, 10)
	case *Reload:
		out = append(out, `,"outcome":`...)
		out = appendString(out, b.Outcome)
		out = append(out, `,"error":`...)
		out = appendStringPtr(out, b.Error)
		out = append(out, `,"serving":`...)
		out = strconv.AppendBool(out, b.Serving)
		out = append(out, `,"material":`...)
		out = appendMaterials(out, b.Material)
	case *Shutdown:
		out = append(out, `,"source":`...)
		out = appendString(out, b.Source)
		out = append(out, `,"authorized":`...)
		out = strconv.AppendBool(out, b.Authorized)
		out = append(out, `,"peer":`...)
		out = appendStringPtr(out, b.Peer)
		out = append(out, `,"detail":`...)
		out = appendString(out, b.Detail)
	case *Tick:
		// The header and nothing else.
	case *AcceptError:
		out = append(out, `,"error":`...)
		out = appendString(out, b.Error)
		out = append(out, `,"backoff_ms":`...)
		out = strconv.AppendInt(out, b.BackoffMS, 10)
	case *Refusal:
		out = append(out, `,"source":`...)
		out = appendString(out, b.Source)
		out = append(out, `,"error":`...)
		out = appendString(out, b.Error)
	default:
		return dst, fmt.Errorf("ringtrace: unknown body type %T", r.Body)
	}
	out = append(out, '}', '\n')
	if len(out)-len(dst) > MaxLineBytes {
		return dst, ErrLineTooLong
	}
	return out, nil
}

// appendConfig appends the config object, its keys in ConfigKeys order.
func appendConfig(out []byte, c *Config) []byte {
	out = append(out, `{"mode":`...)
	out = appendString(out, c.Mode)
	out = append(out, `,"listen":`...)
	out = appendString(out, c.Listen)
	out = append(out, `,"target":`...)
	out = appendString(out, c.Target)
	out = append(out, `,"proxy_protocol":`...)
	out = appendString(out, c.ProxyProtocol)
	out = append(out, `,"status_listen":`...)
	out = appendStringPtr(out, c.StatusListen)
	out = append(out, `,"status_client_cert":`...)
	out = strconv.AppendBool(out, c.StatusClientCert)
	out = append(out, `,"pprof_cmdline_redacted":`...)
	out = strconv.AppendBool(out, c.PprofCmdlineRedacted)
	out = append(out, `,"shutdown_requires_client_cert":`...)
	out = strconv.AppendBool(out, c.ShutdownRequiresClientCert)
	out = append(out, `,"session_tickets":`...)
	out = strconv.AppendBool(out, c.SessionTickets)
	out = append(out, `,"verify_on_resume":`...)
	out = strconv.AppendBool(out, c.VerifyOnResume)
	out = append(out, `,"acl":`...)
	out = appendStrings(out, c.ACL)
	out = append(out, `,"lifetime_cap_seconds":`...)
	out = strconv.AppendInt(out, c.LifetimeCapSeconds, 10)
	out = append(out, `,"sandbox_state":`...)
	out = appendString(out, c.SandboxState)
	out = append(out, `,"sandbox_accepted":`...)
	out = appendStringPtr(out, c.SandboxAccepted)
	out = append(out, `,"material":`...)
	out = appendMaterials(out, c.Material)
	out = append(out, `,"binary":{"path":`...)
	out = appendString(out, c.Binary.Path)
	out = append(out, `,"sha256":`...)
	out = appendString(out, c.Binary.SHA256)
	return append(out, '}', '}')
}

// appendMaterials appends a material list: null when nil, else an array of
// objects with their keys in MaterialKeys order.
func appendMaterials(out []byte, ms []Material) []byte {
	if ms == nil {
		return append(out, `null`...)
	}
	out = append(out, '[')
	for i := range ms {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, `{"material":`...)
		out = appendString(out, ms[i].Material)
		out = append(out, `,"path":`...)
		out = appendString(out, ms[i].Path)
		out = append(out, `,"sha256":`...)
		out = appendStringPtr(out, ms[i].SHA256)
		out = append(out, '}')
	}
	return append(out, ']')
}

// appendPeer appends a peer: null when nil, else an object with its keys in
// PeerKeys order.
func appendPeer(out []byte, p *Peer) []byte {
	if p == nil {
		return append(out, `null`...)
	}
	out = append(out, `{"subject":`...)
	out = appendString(out, p.Subject)
	out = append(out, `,"issuer":`...)
	out = appendString(out, p.Issuer)
	out = append(out, `,"serial":`...)
	out = appendString(out, p.Serial)
	out = append(out, `,"sans":`...)
	out = appendStrings(out, p.SANs)
	out = append(out, `,"fingerprint":`...)
	out = appendString(out, p.Fingerprint)
	return append(out, '}')
}

// appendStrings appends a string list: null when nil (a nil slice is what
// encoding/json writes as null), [] when empty, else the strings.
func appendStrings(out []byte, ss []string) []byte {
	if ss == nil {
		return append(out, `null`...)
	}
	out = append(out, '[')
	for i, s := range ss {
		if i > 0 {
			out = append(out, ',')
		}
		out = appendString(out, s)
	}
	return append(out, ']')
}

// appendStringPtr appends null for nil, else the string.
func appendStringPtr(out []byte, s *string) []byte {
	if s == nil {
		return append(out, `null`...)
	}
	return appendString(out, *s)
}

// jsonSafe marks the ASCII bytes a JSON string carries as they are: 0x20
// through 0x7f (DEL included) except the quote and the backslash, and
// except '<', '>' and '&', which encoding/json escapes by default so that a
// line served into HTML cannot carry markup.
var jsonSafe = func() (safe [utf8.RuneSelf]bool) {
	for b := 0x20; b < utf8.RuneSelf; b++ {
		safe[b] = b != '"' && b != '\\' && b != '<' && b != '>' && b != '&'
	}
	return safe
}()

// appendString appends s as a JSON string exactly as encoding/json writes
// one (with its default HTML escaping): the quote and the backslash escaped
// with a backslash; \b, \f, \n, \r and \t by their letters; every other
// byte below 0x20, and '<', '>' and '&', as \u00XX with lower-case hex;
// U+2028 and U+2029 as their JSON escapes (backslash, u, 2028 or 2029);
// each byte of an invalid UTF-8 sequence as the replacement character
// U+FFFD itself, its three UTF-8 bytes, not an escape; everything else,
// DEL and every other valid rune included, copied through as it is.
// TestAppendStringMatchesJSON holds it to json.Marshal over every byte,
// every pair of bytes and every rune.
func appendString(out []byte, s string) []byte {
	const hex = "0123456789abcdef"
	out = append(out, '"')
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if jsonSafe[b] {
				i++
				continue
			}
			out = append(out, s[start:i]...)
			switch b {
			case '\\', '"':
				out = append(out, '\\', b)
			case '\b':
				out = append(out, '\\', 'b')
			case '\f':
				out = append(out, '\\', 'f')
			case '\n':
				out = append(out, '\\', 'n')
			case '\r':
				out = append(out, '\\', 'r')
			case '\t':
				out = append(out, '\\', 't')
			default:
				out = append(out, '\\', 'u', '0', '0', hex[b>>4], hex[b&0xF])
			}
			i++
			start = i
			continue
		}
		c, size := utf8.DecodeRuneInString(s[i:])
		if c == utf8.RuneError && size == 1 {
			out = append(out, s[start:i]...)
			out = utf8.AppendRune(out, utf8.RuneError)
			i++
			start = i
			continue
		}
		if c == 0x2028 || c == 0x2029 { // LINE SEPARATOR, PARAGRAPH SEPARATOR
			out = append(out, s[start:i]...)
			out = append(out, '\\', 'u', '2', '0', '2', hex[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	out = append(out, s[start:]...)
	return append(out, '"')
}

// ---- decoding ----

// DecodeLine parses one complete line (without its LF) strictly: the
// marker first, then exactly the documented keys with the documented types,
// then the same validation the encoder applies.
func DecodeLine(line []byte) (Record, error) {
	if len(line)+1 > MaxLineBytes {
		return Record{}, ErrLineTooLong
	}
	kind := ClassifyLine(line)
	if kind == "" {
		return Record{}, errors.New("line does not begin with a trace marker")
	}
	obj, err := decodeObject(line, false)
	if err != nil {
		return Record{}, err
	}
	if err := obj.allowedKeys(Keys(kind), optionalKeys[kind]); err != nil {
		return Record{}, err
	}
	if k, err := stringField(obj.get("kind"), "kind"); err != nil || Kind(k) != kind {
		return Record{}, errors.New("kind does not match the marker")
	}
	v, err := intField(obj.get("version"), "version")
	if err != nil {
		return Record{}, err
	}
	if v != Version {
		return Record{}, fmt.Errorf("version %d is not %d", v, Version)
	}
	rec := Record{}
	if rec.Sequence, err = intField(obj.get("sequence"), "sequence"); err != nil {
		return Record{}, err
	}
	if err := positive(rec.Sequence, "sequence"); err != nil {
		return Record{}, err
	}
	if rec.At, err = timestampField(obj.get("at"), "at"); err != nil {
		return Record{}, err
	}
	switch kind {
	case KindStart:
		rec.Body, err = decodeStart(obj)
	case KindAccept:
		rec.Body, err = decodeAccept(obj)
	case KindHandshake:
		rec.Body, err = decodeHandshake(obj)
	case KindACL:
		rec.Body, err = decodeACL(obj)
	case KindClose:
		rec.Body, err = decodeClose(obj)
	case KindReload:
		rec.Body, err = decodeReload(obj)
	case KindShutdown:
		rec.Body, err = decodeShutdown(obj)
	case KindTick:
		rec.Body = &Tick{}
	case KindAcceptError:
		rec.Body, err = decodeAcceptError(obj)
	case KindRefusal:
		rec.Body, err = decodeRefusal(obj)
	}
	if err != nil {
		return Record{}, err
	}
	if err := rec.Body.validate(); err != nil {
		return Record{}, err
	}
	return rec, nil
}

func decodeMaterials(raw json.RawMessage, name string) ([]Material, error) {
	items, err := objectArray(raw, name)
	if err != nil {
		return nil, err
	}
	out := make([]Material, 0, len(items))
	for i, it := range items {
		n := fmt.Sprintf("%s[%d]", name, i)
		obj, err := decodeSubobject(it, MaterialKeys)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", n, err)
		}
		var m Material
		if m.Material, err = stringField(obj.get("material"), n+".material"); err != nil {
			return nil, err
		}
		if m.Path, err = stringField(obj.get("path"), n+".path"); err != nil {
			return nil, err
		}
		if m.SHA256, err = nullableHash(obj.get("sha256"), n+".sha256"); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func decodeStart(obj *rawObject) (Body, error) {
	s := &Start{}
	var err error
	if s.Boot, err = intField(obj.get("boot"), "boot"); err != nil {
		return nil, err
	}
	if s.PID, err = intField(obj.get("pid"), "pid"); err != nil {
		return nil, err
	}
	c, err := decodeSubobject(obj.get("config"), ConfigKeys)
	if err != nil {
		return nil, fmt.Errorf("config: %v", err)
	}
	cfg := &s.Config
	if cfg.Mode, err = stringField(c.get("mode"), "config.mode"); err != nil {
		return nil, err
	}
	if cfg.Listen, err = stringField(c.get("listen"), "config.listen"); err != nil {
		return nil, err
	}
	if cfg.Target, err = stringField(c.get("target"), "config.target"); err != nil {
		return nil, err
	}
	if cfg.ProxyProtocol, err = stringField(c.get("proxy_protocol"), "config.proxy_protocol"); err != nil {
		return nil, err
	}
	if cfg.StatusListen, err = nullableString(c.get("status_listen"), "config.status_listen"); err != nil {
		return nil, err
	}
	if cfg.StatusClientCert, err = boolField(c.get("status_client_cert"), "config.status_client_cert"); err != nil {
		return nil, err
	}
	if cfg.PprofCmdlineRedacted, err = boolField(c.get("pprof_cmdline_redacted"), "config.pprof_cmdline_redacted"); err != nil {
		return nil, err
	}
	if cfg.ShutdownRequiresClientCert, err = boolField(c.get("shutdown_requires_client_cert"), "config.shutdown_requires_client_cert"); err != nil {
		return nil, err
	}
	if cfg.SessionTickets, err = boolField(c.get("session_tickets"), "config.session_tickets"); err != nil {
		return nil, err
	}
	if cfg.VerifyOnResume, err = boolField(c.get("verify_on_resume"), "config.verify_on_resume"); err != nil {
		return nil, err
	}
	if cfg.ACL, err = stringArray(c.get("acl"), "config.acl"); err != nil {
		return nil, err
	}
	if cfg.LifetimeCapSeconds, err = intField(c.get("lifetime_cap_seconds"), "config.lifetime_cap_seconds"); err != nil {
		return nil, err
	}
	if cfg.SandboxState, err = stringField(c.get("sandbox_state"), "config.sandbox_state"); err != nil {
		return nil, err
	}
	if cfg.SandboxAccepted, err = nullableString(c.get("sandbox_accepted"), "config.sandbox_accepted"); err != nil {
		return nil, err
	}
	if cfg.Material, err = decodeMaterials(c.get("material"), "config.material"); err != nil {
		return nil, err
	}
	b, err := decodeSubobject(c.get("binary"), BinaryKeys)
	if err != nil {
		return nil, fmt.Errorf("config.binary: %v", err)
	}
	if cfg.Binary.Path, err = stringField(b.get("path"), "config.binary.path"); err != nil {
		return nil, err
	}
	if cfg.Binary.SHA256, err = stringField(b.get("sha256"), "config.binary.sha256"); err != nil {
		return nil, err
	}
	return s, nil
}

func decodeAccept(obj *rawObject) (Body, error) {
	a := &Accept{}
	var err error
	if a.Conn, err = intField(obj.get("conn"), "conn"); err != nil {
		return nil, err
	}
	if a.Listener, err = stringField(obj.get("listener"), "listener"); err != nil {
		return nil, err
	}
	if a.Remote, err = stringField(obj.get("remote"), "remote"); err != nil {
		return nil, err
	}
	return a, nil
}

func decodeHandshake(obj *rawObject) (Body, error) {
	h := &Handshake{}
	var err error
	if h.Conn, err = intField(obj.get("conn"), "conn"); err != nil {
		return nil, err
	}
	if h.Outcome, err = stringField(obj.get("outcome"), "outcome"); err != nil {
		return nil, err
	}
	if h.Resumed, err = boolField(obj.get("resumed"), "resumed"); err != nil {
		return nil, err
	}
	if h.Verified, err = boolField(obj.get("verified"), "verified"); err != nil {
		return nil, err
	}
	if h.Protocol, err = stringField(obj.get("protocol"), "protocol"); err != nil {
		return nil, err
	}
	if !isNull(obj.get("peer")) {
		p, err := decodeSubobject(obj.get("peer"), PeerKeys)
		if err != nil {
			return nil, fmt.Errorf("peer: %v", err)
		}
		peer := &Peer{}
		if peer.Subject, err = stringField(p.get("subject"), "peer.subject"); err != nil {
			return nil, err
		}
		if peer.Issuer, err = stringField(p.get("issuer"), "peer.issuer"); err != nil {
			return nil, err
		}
		if peer.Serial, err = stringField(p.get("serial"), "peer.serial"); err != nil {
			return nil, err
		}
		if peer.SANs, err = stringArray(p.get("sans"), "peer.sans"); err != nil {
			return nil, err
		}
		if peer.Fingerprint, err = stringField(p.get("fingerprint"), "peer.fingerprint"); err != nil {
			return nil, err
		}
		h.Peer = peer
	}
	if h.Error, err = nullableString(obj.get("error"), "error"); err != nil {
		return nil, err
	}
	if raw := obj.get("chain"); raw != nil {
		// Present: a string, never null (absence is the way to say none).
		if h.Chain, err = stringField(raw, "chain"); err != nil {
			return nil, err
		}
		if h.Chain == "" {
			return nil, errors.New("chain: empty (leave the key out when no certificate was presented)")
		}
	}
	return h, nil
}

func decodeACL(obj *rawObject) (Body, error) {
	a := &ACL{}
	var err error
	if a.Conn, err = intField(obj.get("conn"), "conn"); err != nil {
		return nil, err
	}
	if a.Decision, err = stringField(obj.get("decision"), "decision"); err != nil {
		return nil, err
	}
	if a.Rule, err = stringField(obj.get("rule"), "rule"); err != nil {
		return nil, err
	}
	if a.Reason, err = stringField(obj.get("reason"), "reason"); err != nil {
		return nil, err
	}
	return a, nil
}

func decodeClose(obj *rawObject) (Body, error) {
	c := &Close{}
	var err error
	if c.Conn, err = intField(obj.get("conn"), "conn"); err != nil {
		return nil, err
	}
	if c.Reason, err = stringField(obj.get("reason"), "reason"); err != nil {
		return nil, err
	}
	if c.DurationMS, err = intField(obj.get("duration_ms"), "duration_ms"); err != nil {
		return nil, err
	}
	return c, nil
}

func decodeReload(obj *rawObject) (Body, error) {
	r := &Reload{}
	var err error
	if r.Outcome, err = stringField(obj.get("outcome"), "outcome"); err != nil {
		return nil, err
	}
	if r.Error, err = nullableString(obj.get("error"), "error"); err != nil {
		return nil, err
	}
	if r.Serving, err = boolField(obj.get("serving"), "serving"); err != nil {
		return nil, err
	}
	if r.Material, err = decodeMaterials(obj.get("material"), "material"); err != nil {
		return nil, err
	}
	return r, nil
}

func decodeAcceptError(obj *rawObject) (Body, error) {
	a := &AcceptError{}
	var err error
	if a.Error, err = stringField(obj.get("error"), "error"); err != nil {
		return nil, err
	}
	if a.BackoffMS, err = intField(obj.get("backoff_ms"), "backoff_ms"); err != nil {
		return nil, err
	}
	return a, nil
}

func decodeRefusal(obj *rawObject) (Body, error) {
	r := &Refusal{}
	var err error
	if r.Source, err = stringField(obj.get("source"), "source"); err != nil {
		return nil, err
	}
	if r.Error, err = stringField(obj.get("error"), "error"); err != nil {
		return nil, err
	}
	return r, nil
}

func decodeShutdown(obj *rawObject) (Body, error) {
	s := &Shutdown{}
	var err error
	if s.Source, err = stringField(obj.get("source"), "source"); err != nil {
		return nil, err
	}
	if s.Authorized, err = boolField(obj.get("authorized"), "authorized"); err != nil {
		return nil, err
	}
	if s.Peer, err = nullableString(obj.get("peer"), "peer"); err != nil {
		return nil, err
	}
	if s.Detail, err = stringField(obj.get("detail"), "detail"); err != nil {
		return nil, err
	}
	return s, nil
}
