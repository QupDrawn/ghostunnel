package main

// fixtures.go writes the substance- fixtures (observers/testdata/FIXTURES.md)
// from the committed PKI: for each, the proxy's trace under gt/ (one boot,
// every line encoded by ringtrace.EncodeLine, so the bytes are exactly
// what the emitter writes), the chain store under gt/chains/ as the
// fixture needs it (complete, a .tmp only, or the wrong bytes under a
// name), the material store under gt/material/ holding every CA bundle a
// start or reload line hashes (or, as the fixture needs it, a .tmp only
// for the reload's), the material the start line names under material/,
// the stores/ and traces/ of the base fixture, and the manifest. It reads keys from
// nowhere: the committed certificates and chains are its inputs, so it
// is reproducible from the tree as checked out, and a regenerated PKI
// (-gen-pki) is followed by a regeneration of the fixtures.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ghostunnel/ghostunnel/ringtrace"
)

// fixtureNow is the reader's clock in every substance fixture, the base
// fixture's; the lines are written in the minute before it.
const fixtureNow = "2026-09-20T10:07:25Z"

// fixtureQuery is the proxy's --allow-query the policy fixtures assume,
// which the harness passes as the members' -policy-query.
const fixtureQuery = "data.policy.allow"

// The chain names the fixtures use, by their role in the PKI.
const (
	chainClient  = "client"
	chainOther   = "other"
	chainRogue   = "rogue"
	chainExpired = "expired"
)

// The CA bundles the fixtures use, by their role in the PKI.
const (
	caCommitted = "ca"
	caRogue     = "rogue-ca"
)

// fixtureConn is one connection of a fixture's boot.
type fixtureConn struct {
	chain    string // the chain presented, by role; "" for none
	outcome  string // ok or refused
	resumed  bool
	verified bool
	decision string // allow or deny
	rule     string
	closeAs  string // the close reason
	err      string // the handshake error on a refusal
	// reloadCA, when set, is a successful reload line written before
	// this connection's lines, recording that bundle's hash for the ca
	// material at the path the start line names: a rotation in place.
	reloadCA string
}

// withReload is c preceded by a successful reload to the bundle.
func withReload(bundle string, c fixtureConn) fixtureConn {
	c.reloadCA = bundle
	return c
}

func served(chain, rule string) fixtureConn {
	return fixtureConn{chain: chain, outcome: "ok", verified: true, decision: "allow", rule: rule, closeAs: "eof"}
}

func denied(chain string) fixtureConn {
	return fixtureConn{chain: chain, outcome: "ok", verified: true, decision: "deny", rule: "none", closeAs: "refused"}
}

func refused(chain, err string) fixtureConn {
	return fixtureConn{chain: chain, outcome: "refused", decision: "deny", rule: "none", closeAs: "refused", err: err}
}

type finding struct {
	Check   string `json:"check"`
	Subject string `json:"subject"`
}

// fixtureSpec is one substance fixture.
type fixtureSpec struct {
	name        string
	description string
	rules       []string
	acl         []string // the start line's rule set; policy:<hash> is filled in
	policy      bool     // the start line names the policy file
	conns       []fixtureConn
	// store is how gt/chains/ is written: "complete" (every chain a
	// line names), "tmp-only" (the named chain under <hash>.tmp only),
	// "mishashed" (the client chain's name over the other chain's bytes).
	store string
	// materialStore is how gt/material/ is written: "" or "complete"
	// (every bundle a start or reload line hashes, under its hash),
	// "reload-tmp-only" (the start line's bundle under its hash, a
	// reload's under <hash>.tmp only: a write that never renamed).
	materialStore string
	// onDisk is the bundle at material/ca.pem, the path the start line
	// names: "" or caCommitted, or caRogue when a reload rotated the file
	// in place.
	onDisk   string
	findings []finding
}

func hs(conn int) finding  { return finding{"handshake-substance", fmt.Sprint(conn)} }
func acl(conn int) finding { return finding{"acl-substance", fmt.Sprint(conn)} }

// fixtureSpecs is the set, in the order FIXTURES.md lists it.
func fixtureSpecs(spki map[string]string) []fixtureSpec {
	allowCN := []string{"allow-cn:client.example"}
	return []fixtureSpec{
		{
			name:        "substance-agree",
			description: "The proxy's account of three connections is what the members re-judge from the chains and the CA on disk: the client chain, verified and allowed under allow-cn; the other chain, verified and denied under none; the client chain again on a resumed, re-verified session. Nothing fires on the tunnel surface.",
			rules:       []string{"SPEC 14.3", "ringtrace/README.md 1.5"},
			acl:         allowCN,
			conns:       []fixtureConn{served(chainClient, "allow-cn"), denied(chainOther), {chain: chainClient, outcome: "ok", resumed: true, verified: true, decision: "allow", rule: "allow-cn", closeAs: "eof"}},
			store:       "complete",
		},
		{
			name:        "substance-acl-disagree",
			description: "Two decisions the rules on the leaf do not give: the other chain (CN other.example) recorded as allowed under allow-cn, and the client chain recorded as denied under none although allow-cn:client.example allows it. Both chains verify, so handshake-substance is silent; acl-substance names both connections, the deny the members would allow as much as the allow they would deny.",
			rules:       []string{"SPEC 14.3"},
			acl:         allowCN,
			conns:       []fixtureConn{served(chainOther, "allow-cn"), denied(chainClient)},
			store:       "complete",
			findings:    []finding{acl(1), acl(2)},
		},
		{
			name:        "substance-chain-fails",
			description: "Two handshakes recorded as verified whose chains do not verify against the CA the start line names at the handshake's time: a leaf signed by a CA the bundle does not hold, and a leaf that expired in 2021. Both are recorded as allowed under allow-cn, which the members would deny, since a chain that does not verify is not judged by the rules.",
			rules:       []string{"SPEC 14.3", "ringtrace/README.md 1.5"},
			acl:         allowCN,
			conns:       []fixtureConn{served(chainRogue, "allow-cn"), served(chainExpired, "allow-cn")},
			store:       "complete",
			findings:    []finding{hs(1), hs(2), acl(1), acl(2)},
		},
		{
			name:        "substance-chain-missing",
			description: "A handshake names a chain the store does not hold: only <hash>.tmp is there, a write that never renamed, which the reader never opens. Both rules fail on the connection: nothing recorded about it has been confirmed.",
			rules:       []string{"SPEC 14.3", "ringtrace/README.md 1.5 rule 2"},
			acl:         allowCN,
			conns:       []fixtureConn{served(chainClient, "allow-cn")},
			store:       "tmp-only",
			findings:    []finding{hs(1), acl(1)},
		},
		{
			name:        "substance-chain-mishashed",
			description: "The chain file a handshake names holds another chain's bytes: the other chain, which verifies and parses, under the client chain's name. The reader holds the content to the name and refuses it before anything is parsed; both rules fail on the connection.",
			rules:       []string{"SPEC 14.3", "ringtrace/README.md 1.5 rule 4"},
			acl:         allowCN,
			conns:       []fixtureConn{served(chainClient, "allow-cn")},
			store:       "mishashed",
			findings:    []finding{hs(1), acl(1)},
		},
		{
			name:        "substance-policy-agree",
			description: "An OPA policy alone decides: the policy on disk, hashed as the rule set records it, allows CN client.example and denies the rest. The client chain allowed under policy and the other chain denied under none are what the members compute with the same query. Nothing fires.",
			rules:       []string{"SPEC 14.3"},
			acl:         []string{"policy:"},
			policy:      true,
			conns:       []fixtureConn{served(chainClient, "policy"), denied(chainOther)},
			store:       "complete",
		},
		{
			name:        "substance-policy-disagree",
			description: "The policy's decisions inverted: the other chain recorded as allowed under policy, which denies it, and the client chain recorded as denied, which it allows. acl-substance names both.",
			rules:       []string{"SPEC 14.3"},
			acl:         []string{"policy:"},
			policy:      true,
			conns:       []fixtureConn{served(chainOther, "policy"), denied(chainClient)},
			store:       "complete",
			findings:    []finding{acl(1), acl(2)},
		},
		{
			name:        "substance-unknown-rule",
			description: "The start line's rule set holds an entry the members cannot evaluate in server mode, verify-cn (a client-mode rule the proxy never records on a server). A set the members cannot read confirms nothing: both rules fail on the one verified, allowed connection.",
			rules:       []string{"SPEC 14.3"},
			acl:         []string{"allow-cn:client.example", "verify-cn:client.example"},
			conns:       []fixtureConn{served(chainClient, "allow-cn")},
			store:       "complete",
			findings:    []finding{hs(1), acl(1)},
		},
		{
			name:        "substance-pin-agree",
			description: "Pin mode: the rule set is one SPKI pin, the client leaf's key. The client chain verified and allowed under allow-spki-pin, and the other chain refused at the handshake (the proxy's pin check fails it, verified false, denied under none), are what the members compute from the leaves' keys; the CA is not consulted. Nothing fires.",
			rules:       []string{"SPEC 14.3"},
			acl:         []string{"allow-spki-pin:sha256:" + spki["leaf-client"]},
			conns:       []fixtureConn{served(chainClient, "allow-spki-pin"), refused(chainOther, "unauthorized: pin verification failed")},
			store:       "complete",
		},
		{
			name:        "substance-pin-disagree",
			description: "Pin mode with the other chain recorded as verified and allowed under allow-spki-pin: its leaf's key is not the pinned one. Both rules fail on the connection.",
			rules:       []string{"SPEC 14.3"},
			acl:         []string{"allow-spki-pin:sha256:" + spki["leaf-client"]},
			conns:       []fixtureConn{served(chainOther, "allow-spki-pin")},
			store:       "complete",
			findings:    []finding{hs(1), acl(1)},
		},
		{
			name:        "substance-ca-rotated",
			description: "The CA bundle rotated in place by a reload. The boot starts on the committed CA at material/ca.pem and serves the client chain; a successful reload records the rogue CA's hash for the same path, whose file now holds the rogue bundle; the rogue chain (CN client.example, signed by the rogue CA) is served under allow-cn, then the client chain again. The members read each bundle from gt/material/ by the hash in force at the line and never from the path: the first connection verifies under the replaced bundle, the second under the new one, and the third fails, the rogue CA not having signed the client chain. Both rules name the third connection only.",
			rules:       []string{"SPEC 14.3", "ringtrace/README.md 1.6"},
			acl:         allowCN,
			conns:       []fixtureConn{served(chainClient, "allow-cn"), withReload(caRogue, served(chainRogue, "allow-cn")), served(chainClient, "allow-cn")},
			store:       "complete",
			onDisk:      caRogue,
			findings:    []finding{hs(3), acl(3)},
		},
		{
			name:          "substance-ca-unstored",
			description:   "A reload records a hash the material store does not hold: the rogue CA's, whose file under gt/material/ has only its .tmp, a write that never renamed, which the reader never opens. The client chain served before the reload is judged under the committed CA, which the store holds; the rogue chain served after it cannot be judged, and both rules fail on that connection.",
			rules:         []string{"SPEC 14.3", "ringtrace/README.md 1.6 rule 2"},
			acl:           allowCN,
			conns:         []fixtureConn{served(chainClient, "allow-cn"), withReload(caRogue, served(chainRogue, "allow-cn"))},
			store:         "complete",
			materialStore: "reload-tmp-only",
			onDisk:        caRogue,
			findings:      []finding{hs(2), acl(2)},
		},
	}
}

// pkiFiles is the committed PKI as read: the chain bytes by role, the
// leaf of each, the CA and policy bytes with their hashes.
type pkiFiles struct {
	chains map[string][]byte
	leaves map[string]*x509.Certificate
	// bundles is each CA bundle's bytes by role (caCommitted, caRogue).
	bundles map[string][]byte
	ca      []byte
	caHash  string
	policy  []byte
	polH    string
	spki    map[string]string
}

func readPKI(dir string) *pkiFiles {
	p := &pkiFiles{chains: map[string][]byte{}, leaves: map[string]*x509.Certificate{}, bundles: map[string][]byte{}, spki: map[string]string{}}
	var err error
	if p.ca, err = os.ReadFile(filepath.Join(dir, "ca.pem")); err != nil {
		log.Fatal(err)
	}
	if p.policy, err = os.ReadFile(filepath.Join(dir, "policy.rego")); err != nil {
		log.Fatal(err)
	}
	p.caHash, p.polH = hashOf(p.ca), hashOf(p.policy)
	p.bundles[caCommitted] = p.ca
	if p.bundles[caRogue], err = os.ReadFile(filepath.Join(dir, "rogue-ca.pem")); err != nil {
		log.Fatal(err)
	}
	// Each role's chain is found by its leaf's PEM: the chain whose
	// first certificate is that leaf.
	entries, err := os.ReadDir(filepath.Join(dir, "chains"))
	if err != nil {
		log.Fatal(err)
	}
	var chains [][]byte
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, "chains", e.Name()))
		if err != nil {
			log.Fatal(err)
		}
		if hashOf(b)+".der" != e.Name() {
			log.Fatalf("%s does not hash to its name", e.Name())
		}
		chains = append(chains, b)
	}
	for role, leafFile := range map[string]string{chainClient: "leaf-client.pem", chainOther: "leaf-other.pem", chainRogue: "leaf-rogue.pem", chainExpired: "leaf-expired.pem"} {
		pemBytes, err := os.ReadFile(filepath.Join(dir, leafFile))
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			log.Fatalf("%s: no PEM block", leafFile)
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		p.leaves[role] = leaf
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		p.spki[strings.TrimSuffix(leafFile, ".pem")] = hex.EncodeToString(sum[:])
		for _, c := range chains {
			if len(c) >= len(block.Bytes) && string(c[:len(block.Bytes)]) == string(block.Bytes) {
				p.chains[role] = c
			}
		}
		if p.chains[role] == nil {
			log.Fatalf("no chain begins with %s", leafFile)
		}
	}
	return p
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// peerSummary is ring.go's peerSummary: the non-secret identity of a leaf.
func peerSummary(cert *x509.Certificate) *ringtrace.Peer {
	sans := []string{}
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
	return &ringtrace.Peer{Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), Serial: cert.SerialNumber.Text(16), SANs: sans, Fingerprint: hex.EncodeToString(sum[:])}
}

// The manifest as the substance fixtures write it, in the key order the
// other manifests use.
type manifest struct {
	Fixture      string          `json:"fixture"`
	Description  string          `json:"description"`
	Rules        []string        `json:"rules"`
	Reader       string          `json:"reader"`
	ReaderBooted bool            `json:"reader_booted"`
	Parameters   json.RawMessage `json:"parameters"`
	Directories  []string        `json:"directories"`
	Traces       json.RawMessage `json:"traces"`
	Expect       manifestExpect  `json:"expect"`
}

type manifestExpect struct {
	Verdicts          json.RawMessage    `json:"verdicts"`
	Failing           []finding          `json:"failing"`
	HaltInForceBefore bool               `json:"halt_in_force_before"`
	Halt              json.RawMessage    `json:"halt"`
	Trace             manifestTrace      `json:"trace"`
	Surface           *manifestSurface   `json:"surface,omitempty"`
	BootEnded         *manifestBootEnded `json:"boot_ended,omitempty"`
}

type manifestTrace struct {
	Boot     int64            `json:"boot"`
	Records  int              `json:"records"`
	Torn     bool             `json:"torn"`
	Segments map[string]int64 `json:"segments"`
}

type manifestSurface struct {
	Owner       string    `json:"owner,omitempty"`
	PolicyQuery string    `json:"policy_query,omitempty"`
	Findings    []finding `json:"findings"`
}

type manifestBootEnded struct {
	Previous int64     `json:"previous"`
	Findings []finding `json:"findings"`
}

// indexRow is one row of index.json.
type indexRow struct {
	Fixture  string          `json:"fixture"`
	Reader   string          `json:"reader"`
	Rules    []string        `json:"rules"`
	Verdicts json.RawMessage `json:"verdicts"`
	Failing  []finding       `json:"failing"`
	Halt     json.RawMessage `json:"halt"`
}

// genFixtures writes every substance fixture under fixtures/ from the PKI
// under pki, on the stores and traces of fixtures/<base>, and appends
// their rows to fixtures/index.json (replacing rows of the same name).
func genFixtures(pki, fixtures, base string) {
	p := readPKI(pki)
	baseDir := filepath.Join(fixtures, base)
	baseManifest := readBaseManifest(baseDir)
	var rows []indexRow
	for _, spec := range fixtureSpecs(p.spki) {
		rows = append(rows, writeFixture(p, spec, fixtures, baseDir, baseManifest))
		fmt.Printf("wrote %s\n", spec.name)
	}
	for _, write := range []fixtureWriter{writeStatusListenerDownFixture, writeBootEndedFixture} {
		row := write(p, fixtures, baseDir, baseManifest)
		rows = append(rows, row)
		fmt.Printf("wrote %s\n", row.Fixture)
	}
	writeIndex(filepath.Join(fixtures, "index.json"), rows)
}

// fixtureWriter writes one fixture that is not a substance fixture on the
// base's stores and traces and returns its index row.
type fixtureWriter func(p *pkiFiles, fixtures, baseDir string, base *baseManifest) indexRow

// fixtureStart is the start line's body every fixture of this tool
// writes, for the given boot and pid, with the material the substance
// fixtures name (the CA under material/ca.pem) and the rule set.
func fixtureStart(p *pkiFiles, boot, pid int64, rules []string) *ringtrace.Start {
	status := "127.0.0.1:6060"
	return &ringtrace.Start{Boot: boot, PID: pid, Config: ringtrace.Config{
		Mode: "server", Listen: "localhost:8443", Target: "localhost:8080", ProxyProtocol: ringtrace.ProxyProtocolOff, StatusListen: &status,
		PprofCmdlineRedacted: true, ShutdownRequiresClientCert: true, SessionTickets: true, VerifyOnResume: true,
		ACL: rules, LifetimeCapSeconds: 300, SandboxState: ringtrace.SandboxApplied,
		Material: []ringtrace.Material{
			{Material: "cert", Path: "/etc/gt/cert.pem", SHA256: ptr(strings.Repeat("0", 64))},
			{Material: "key", Path: "/etc/gt/key.pem"},
			{Material: "ca", Path: "material/ca.pem", SHA256: ptr(p.caHash)},
		},
		Binary: fixtureBinary,
	}}
}

// fixtureBinary is the executable every fixture's start line names. The
// fixtures judge the trace-only rules, which never open it.
var fixtureBinary = ringtrace.Binary{Path: "/usr/local/bin/ghostunnel", SHA256: strings.Repeat("b", 64)}

// encodeBoot encodes records as one segment, each line by
// ringtrace.EncodeLine, with the sequences 1, 2, 3, ... in order.
func encodeBoot(name string, bodies []ringtrace.Body, ats []time.Time) []byte {
	var segment []byte
	for i, body := range bodies {
		line, err := ringtrace.EncodeLine(ringtrace.Record{Sequence: int64(i + 1), At: ats[i], Body: body})
		if err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		segment = append(segment, line...)
	}
	return segment
}

// fixtureAt is the reader's clock in every fixture, offset by seconds.
func fixtureAt(offset int) time.Time {
	now, err := time.Parse(time.RFC3339, fixtureNow)
	if err != nil {
		log.Fatal(err)
	}
	return now.Add(time.Duration(offset) * time.Second)
}

// beginFixture removes and recreates a fixture directory on the base's
// stores and traces, with the CA under material/.
func beginFixture(p *pkiFiles, name, fixtures, baseDir string) string {
	dir := filepath.Join(fixtures, name)
	if err := os.RemoveAll(dir); err != nil {
		log.Fatal(err)
	}
	for _, sub := range []string{"stores", "traces"} {
		copyTree(filepath.Join(baseDir, sub), filepath.Join(dir, sub))
	}
	must(os.MkdirAll(filepath.Join(dir, "material"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "material", "ca.pem"), p.ca, 0o644))
	return dir
}

// finishFixture writes the manifest and returns the index row.
func finishFixture(dir, name, description string, rules []string, base *baseManifest, dirs []string, expect manifestExpect) indexRow {
	dirs = append(append([]string{}, dirs...), base.Directories...)
	sort.Strings(dirs)
	expect.Verdicts, expect.Failing, expect.HaltInForceBefore, expect.Halt = base.Expect.Verdicts, []finding{}, base.Expect.HaltInForceBefore, base.Expect.Halt
	m := manifest{
		Fixture: name, Description: description, Rules: rules, Reader: "tunnel", ReaderBooted: false,
		Parameters: base.Parameters, Directories: dirs, Traces: base.Traces, Expect: expect,
	}
	out, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	must(os.WriteFile(filepath.Join(dir, "manifest.json"), append(out, '\n'), 0o644))
	return indexRow{Fixture: name, Reader: "tunnel", Rules: rules, Verdicts: base.Expect.Verdicts, Failing: []finding{}, Halt: base.Expect.Halt}
}

// writeStatusListenerDownFixture writes admin-status-listener-down: one
// boot whose status listener died, recorded by the one refusal line the
// proxy writes (ringtrace/README.md 1.2), which the admin surface reads as
// status-listener-up for the rest of the boot (SPEC 14.3).
func writeStatusListenerDownFixture(p *pkiFiles, fixtures, baseDir string, base *baseManifest) indexRow {
	const name = "admin-status-listener-down"
	const errText = "accept tcp 127.0.0.1:6060: use of closed network connection"
	dir := beginFixture(p, name, fixtures, baseDir)
	bodies := []ringtrace.Body{
		fixtureStart(p, 1, 4242, []string{"allow-cn:client.example"}),
		&ringtrace.Tick{},
		&ringtrace.Refusal{Source: "status-listener", Error: errText},
		&ringtrace.Tick{},
	}
	ats := []time.Time{fixtureAt(-25), fixtureAt(-20), fixtureAt(-15), fixtureAt(-5)}
	segment := encodeBoot(name, bodies, ats)
	must(os.MkdirAll(filepath.Join(dir, "gt", "0000000001"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "gt", "0000000001", "0000000001.trace"), segment, 0o644))
	rules := []string{"SPEC 14.3", "ringtrace/README.md 1.2"}
	return finishFixture(dir, name,
		"The status listener died: the proxy wrote the one refusal line naming it and refuses to serve until restart. Every member computes the admin surface's status-listener-up on that line, with the error text as subject, for the rest of the boot; the admin member publishes it.",
		rules, base, []string{"gt", "gt/0000000001", "material"},
		manifestExpect{
			Trace:   manifestTrace{Boot: 1, Records: len(bodies), Torn: false, Segments: map[string]int64{"0000000001.trace": int64(len(segment))}},
			Surface: &manifestSurface{Owner: "admin", Findings: []finding{{"status-listener-up", errText}}},
		})
}

// writeBootEndedFixture writes boot-ended-mid-connection: two boots. Boot
// 1 served the client chain and never closed the connection, then failed
// an accept and died mid-line with no shutdown line, more than
// -tick-max-age before now; boot 2 is the process that came back, current
// and clean. A member that read boot 1 last cycle judges its ending once
// (SPEC 14.3 boot-ended).
func writeBootEndedFixture(p *pkiFiles, fixtures, baseDir string, base *baseManifest) indexRow {
	const name = "boot-ended-mid-connection"
	const errText = "accept tcp 127.0.0.1:8443: too many open files"
	dir := beginFixture(p, name, fixtures, baseDir)
	leaf := p.leaves[chainClient]
	h := &ringtrace.Handshake{Conn: 1, Outcome: "ok", Verified: true, Protocol: "TLS 1.3", Peer: peerSummary(leaf), Chain: hashOf(p.chains[chainClient])}
	one := []ringtrace.Body{
		fixtureStart(p, 1, 4242, []string{"allow-cn:client.example"}),
		&ringtrace.Accept{Conn: 1, Listener: "127.0.0.1:8443", Remote: "10.0.0.7:50001"},
		h,
		&ringtrace.ACL{Conn: 1, Decision: "allow", Rule: "allow-cn", Reason: "allowed by --allow-cn"},
		&ringtrace.Tick{},
		&ringtrace.AcceptError{Error: errText, BackoffMS: 5},
	}
	oneAts := []time.Time{fixtureAt(-145), fixtureAt(-143), fixtureAt(-143), fixtureAt(-143), fixtureAt(-140), fixtureAt(-135)}
	segment := encodeBoot(name, one, oneAts)
	// The torn tail: the next accept-error line, cut where the process died.
	torn, err := ringtrace.EncodeLine(ringtrace.Record{Sequence: 7, At: fixtureAt(-135), Body: &ringtrace.AcceptError{Error: errText, BackoffMS: 10}})
	if err != nil {
		log.Fatal(err)
	}
	segment = append(segment, torn[:len(torn)/2]...)
	must(os.MkdirAll(filepath.Join(dir, "gt", "0000000001"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "gt", "0000000001", "0000000001.trace"), segment, 0o644))
	chainsDir := filepath.Join(dir, "gt", "chains")
	must(os.MkdirAll(chainsDir, 0o755))
	must(os.WriteFile(filepath.Join(chainsDir, hashOf(p.chains[chainClient])+".der"), p.chains[chainClient], 0o644))
	two := []ringtrace.Body{fixtureStart(p, 2, 4343, []string{"allow-cn:client.example"}), &ringtrace.Tick{}}
	twoAts := []time.Time{fixtureAt(-25), fixtureAt(-5)}
	second := encodeBoot(name, two, twoAts)
	must(os.MkdirAll(filepath.Join(dir, "gt", "0000000002"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "gt", "0000000002", "0000000001.trace"), second, 0o644))
	rules := []string{"SPEC 14.3"}
	return finishFixture(dir, name,
		"The proxy restarted after an abort. Boot 2 is current and clean. Boot 1, which a member read last cycle, ended more than -tick-max-age ago with no shutdown line, a torn last line, connection 1 accepted and allowed but never closed, and a failed accept in the seconds before the end: that member judges it once, boot-ended with the boot as subject, and never again; a member that never read boot 1 judges nothing.",
		rules, base, []string{"gt", "gt/0000000001", "gt/0000000002", "gt/chains", "material"},
		manifestExpect{
			Trace: manifestTrace{Boot: 2, Records: len(two), Torn: false, Segments: map[string]int64{"0000000001.trace": int64(len(second))}},
			BootEnded: &manifestBootEnded{Previous: 1, Findings: []finding{
				{"boot-ended", "0000000001:aborted"},
				{"boot-ended", "0000000001:torn"},
				{"boot-ended", "0000000001:conn:1"},
				{"boot-ended", "0000000001:accept-error:" + errText},
			}},
		})
}

// baseManifest is what the substance fixtures take from the base: the
// parameters, the directories, the traces and the cycle's expectations.
type baseManifest struct {
	Parameters  json.RawMessage `json:"parameters"`
	Directories []string        `json:"directories"`
	Traces      json.RawMessage `json:"traces"`
	Expect      struct {
		Verdicts          json.RawMessage `json:"verdicts"`
		Failing           []finding       `json:"failing"`
		HaltInForceBefore bool            `json:"halt_in_force_before"`
		Halt              json.RawMessage `json:"halt"`
	} `json:"expect"`
}

func readBaseManifest(dir string) *baseManifest {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		log.Fatal(err)
	}
	m := new(baseManifest)
	if err := json.Unmarshal(raw, m); err != nil {
		log.Fatal(err)
	}
	var params struct {
		Now string `json:"now"`
	}
	if err := json.Unmarshal(m.Parameters, &params); err != nil || params.Now != fixtureNow {
		log.Fatalf("the base fixture's now is %q, not %s", params.Now, fixtureNow)
	}
	if len(m.Expect.Failing) != 0 {
		log.Fatal("the base fixture has failing assertions; the substance fixtures need a clean cycle")
	}
	return m
}

func writeFixture(p *pkiFiles, spec fixtureSpec, fixtures, baseDir string, base *baseManifest) indexRow {
	dir := filepath.Join(fixtures, spec.name)
	if err := os.RemoveAll(dir); err != nil {
		log.Fatal(err)
	}
	for _, sub := range []string{"stores", "traces"} {
		copyTree(filepath.Join(baseDir, sub), filepath.Join(dir, sub))
	}
	// The material the start line names, relative to the fixture root:
	// the CA file as it stands at the end of the boot (rotated in place
	// when a reload says so; the substance rules never read it) and the
	// policy file, which they do read.
	must(os.MkdirAll(filepath.Join(dir, "material"), 0o755))
	onDisk := p.ca
	switch spec.onDisk {
	case "", caCommitted:
	case caRogue:
		onDisk = p.bundles[caRogue]
	default:
		log.Fatalf("%s: onDisk %q", spec.name, spec.onDisk)
	}
	must(os.WriteFile(filepath.Join(dir, "material", "ca.pem"), onDisk, 0o644))
	material := []ringtrace.Material{
		{Material: "cert", Path: "/etc/gt/cert.pem", SHA256: ptr(strings.Repeat("0", 64))},
		{Material: "key", Path: "/etc/gt/key.pem"},
		{Material: "ca", Path: "material/ca.pem", SHA256: ptr(p.caHash)},
	}
	rules := append([]string{}, spec.acl...)
	if spec.policy {
		must(os.WriteFile(filepath.Join(dir, "material", "policy.rego"), p.policy, 0o644))
		material = append(material, ringtrace.Material{Material: "policy", Path: "material/policy.rego", SHA256: ptr(p.polH)})
		for i, r := range rules {
			if r == "policy:" {
				rules[i] = "policy:" + p.polH
			}
		}
	}
	sort.Strings(rules)

	// The boot: start, then each connection's four lines, then a tick.
	at := func(offset int) time.Time {
		now, err := time.Parse(time.RFC3339, fixtureNow)
		if err != nil {
			log.Fatal(err)
		}
		return now.Add(-25 * time.Second).Add(time.Duration(offset) * time.Second)
	}
	var records []ringtrace.Record
	add := func(t time.Time, body ringtrace.Body) {
		records = append(records, ringtrace.Record{Sequence: int64(len(records) + 1), At: t, Body: body})
	}
	status := "127.0.0.1:6060"
	add(at(0), &ringtrace.Start{Boot: 1, PID: 4242, Config: ringtrace.Config{
		Mode: "server", Listen: "localhost:8443", Target: "localhost:8080", ProxyProtocol: ringtrace.ProxyProtocolOff, StatusListen: &status,
		PprofCmdlineRedacted: true, ShutdownRequiresClientCert: true, SessionTickets: true, VerifyOnResume: true,
		ACL: rules, LifetimeCapSeconds: 300, SandboxState: ringtrace.SandboxApplied, Material: material,
		Binary: fixtureBinary,
	}})
	named := map[string]bool{}
	// stored is every bundle a start or reload line hashes, by role; the
	// last reload's is what the store holds only as a .tmp under
	// "reload-tmp-only".
	stored := map[string]bool{caCommitted: true}
	lastReload := ""
	for i, c := range spec.conns {
		conn := int64(i + 1)
		t := at(2 + 2*i)
		if c.reloadCA != "" {
			// A successful reload a second before the connection, the
			// ca entry's hash now the bundle's: the file at the path
			// was rewritten in place.
			bundle, ok := p.bundles[c.reloadCA]
			if !ok {
				log.Fatalf("%s: reload to %q", spec.name, c.reloadCA)
			}
			reloaded := append([]ringtrace.Material{}, material...)
			for k := range reloaded {
				if reloaded[k].Material == "ca" {
					reloaded[k].SHA256 = ptr(hashOf(bundle))
				}
			}
			add(t.Add(-time.Second), &ringtrace.Reload{Outcome: "ok", Serving: true, Material: reloaded})
			stored[c.reloadCA] = true
			lastReload = c.reloadCA
		}
		add(t, &ringtrace.Accept{Conn: conn, Listener: "127.0.0.1:8443", Remote: fmt.Sprintf("10.0.0.7:5%04d", conn)})
		h := &ringtrace.Handshake{Conn: conn, Outcome: c.outcome, Resumed: c.resumed, Verified: c.verified, Protocol: "TLS 1.3"}
		if c.chain != "" {
			h.Peer = peerSummary(p.leaves[c.chain])
			h.Chain = hashOf(p.chains[c.chain])
			named[c.chain] = true
		}
		if c.err != "" {
			h.Error = ptr(c.err)
		}
		add(t, h)
		reason := "allowed by --" + c.rule
		if c.decision == "deny" {
			reason = "no rule allowed the peer"
			if c.err != "" {
				reason = c.err
			}
		}
		add(t, &ringtrace.ACL{Conn: conn, Decision: c.decision, Rule: c.rule, Reason: reason})
		add(t.Add(time.Second), &ringtrace.Close{Conn: conn, Reason: c.closeAs, DurationMS: 1000})
	}
	add(at(24), &ringtrace.Tick{})
	var segment []byte
	for _, r := range records {
		line, err := ringtrace.EncodeLine(r)
		if err != nil {
			log.Fatalf("%s: %v", spec.name, err)
		}
		segment = append(segment, line...)
	}
	must(os.MkdirAll(filepath.Join(dir, "gt", "0000000001"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "gt", "0000000001", "0000000001.trace"), segment, 0o644))

	// The chain store.
	chainsDir := filepath.Join(dir, "gt", "chains")
	must(os.MkdirAll(chainsDir, 0o755))
	for role := range named {
		content := p.chains[role]
		name := hashOf(content) + ".der"
		switch spec.store {
		case "complete":
		case "tmp-only":
			name = hashOf(content) + ".tmp"
		case "mishashed":
			if role == chainClient {
				content = p.chains[chainOther]
			}
		default:
			log.Fatalf("%s: store %q", spec.name, spec.store)
		}
		must(os.WriteFile(filepath.Join(chainsDir, name), content, 0o644))
	}

	// The material store: every bundle a start or reload line hashes,
	// under its hash and no suffix, as the proxy stores it before the
	// line that names it.
	materialDir := filepath.Join(dir, "gt", "material")
	must(os.MkdirAll(materialDir, 0o755))
	for role := range stored {
		content := p.bundles[role]
		name := hashOf(content)
		switch spec.materialStore {
		case "", "complete":
		case "reload-tmp-only":
			if role == lastReload {
				name += ".tmp"
			}
		default:
			log.Fatalf("%s: material store %q", spec.name, spec.materialStore)
		}
		must(os.WriteFile(filepath.Join(materialDir, name), content, 0o644))
	}

	// The manifest.
	dirs := append([]string{"gt", "gt/0000000001", "gt/chains", "gt/material", "material"}, base.Directories...)
	sort.Strings(dirs)
	findings := spec.findings
	if findings == nil {
		findings = []finding{}
	}
	m := manifest{
		Fixture: spec.name, Description: spec.description, Rules: spec.rules, Reader: "tunnel", ReaderBooted: false,
		Parameters: base.Parameters, Directories: dirs, Traces: base.Traces,
		Expect: manifestExpect{
			Verdicts: base.Expect.Verdicts, Failing: []finding{}, HaltInForceBefore: base.Expect.HaltInForceBefore, Halt: base.Expect.Halt,
			Trace:   manifestTrace{Boot: 1, Records: len(records), Torn: false, Segments: map[string]int64{"0000000001.trace": int64(len(segment))}},
			Surface: &manifestSurface{PolicyQuery: fixtureQuery, Findings: findings},
		},
	}
	out, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	must(os.WriteFile(filepath.Join(dir, "manifest.json"), append(out, '\n'), 0o644))
	return indexRow{Fixture: spec.name, Reader: "tunnel", Rules: spec.rules, Verdicts: base.Expect.Verdicts, Failing: []finding{}, Halt: base.Expect.Halt}
}

// writeIndex appends the rows to index.json, replacing rows of the same
// fixture name, keeping every other row's bytes as they are.
func writeIndex(path string, rows []indexRow) {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var existing []json.RawMessage
	if err := json.Unmarshal(raw, &existing); err != nil {
		log.Fatal(err)
	}
	names := map[string]bool{}
	for _, r := range rows {
		names[r.Fixture] = true
	}
	var kept []json.RawMessage
	for _, e := range existing {
		var head struct {
			Fixture string `json:"fixture"`
		}
		if err := json.Unmarshal(e, &head); err != nil {
			log.Fatal(err)
		}
		if !names[head.Fixture] {
			kept = append(kept, e)
		}
	}
	for _, r := range rows {
		b, err := json.Marshal(r)
		if err != nil {
			log.Fatal(err)
		}
		kept = append(kept, b)
	}
	out, err := json.MarshalIndent(kept, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	must(os.WriteFile(path, append(out, '\n'), 0o644))
}

func copyTree(src, dst string) {
	must(filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		return os.Chtimes(target, info.ModTime(), info.ModTime())
	}))
}

func ptr(s string) *string { return &s }
