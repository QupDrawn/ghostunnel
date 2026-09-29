package main

// judgememory_test.go holds the kept judgement of the tunnel surface
// (judgememory.go) to the full one. Over random traces grown cycle by
// cycle (random new lines at random cut points, torn tails, new segments,
// a line rewritten in the prefix, the start line rewritten, a new boot, a
// chain, CA bundle or policy file changed, deleted or made unreadable and
// restored between cycles, cycles read but not judged, the clock moved
// across the grace, the lifetime cap and the accept-loop window, the
// margins changed) the findings of the kept judgement equal, finding for
// finding and in order, every cycle, those of the rules written as one
// walk over every record with nothing remembered (refTunnelFindings), and
// those of the members' own judgement of every record. Every member
// carries a byte-identical copy of this file.

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- the reference ----

// refTunnelConn is one connection's lines in the current boot.
type refTunnelConn struct {
	accept    *gtRecord
	handshake *gtRecord
	acl       *gtRecord
	close     *gtRecord
}

// refTunnelSurfaceFindings is the rules of surface_tunnel.go as one walk
// over every record of the boot, nothing kept.
func refTunnelSurfaceFindings(boot *gtBoot, now time.Time, lifetimeMargin, aclGrace, tickMaxAge time.Duration) []Finding {
	if lifetimeMargin == 0 {
		lifetimeMargin = defaultLifetimeMargin
	}
	if aclGrace == 0 {
		aclGrace = defaultACLGrace
	}
	if tickMaxAge <= 0 {
		tickMaxAge = defaultTickMaxAge
	}
	start := boot.Records[0].Start
	var out []Finding
	fail := func(check string, subject string) {
		out = append(out, Finding{Check: check, Subject: subject})
	}
	conns := map[int64]*refTunnelConn{}
	var order []int64
	inconsistent := map[int64]bool{}
	get := func(id int64) *refTunnelConn {
		cn := conns[id]
		if cn == nil {
			inconsistent[id] = true
			cn = &refTunnelConn{}
			conns[id] = cn
			order = append(order, id)
		}
		return cn
	}
	for i := range boot.Records {
		rec := &boot.Records[i]
		switch rec.Kind {
		case "accept":
			if conns[rec.Accept.Conn] != nil {
				inconsistent[rec.Accept.Conn] = true
				continue
			}
			conns[rec.Accept.Conn] = &refTunnelConn{accept: rec}
			order = append(order, rec.Accept.Conn)
		case "handshake":
			cn := get(rec.Handshake.Conn)
			if cn.handshake != nil {
				inconsistent[rec.Handshake.Conn] = true
				continue
			}
			cn.handshake = rec
		case "acl":
			cn := get(rec.ACL.Conn)
			if cn.acl != nil {
				inconsistent[rec.ACL.Conn] = true
				continue
			}
			cn.acl = rec
		case "close":
			cn := get(rec.Close.Conn)
			if cn.close != nil {
				inconsistent[rec.Close.Conn] = true
				continue
			}
			cn.close = rec
		}
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	for _, id := range order {
		if inconsistent[id] {
			fail(checkConnConsistent, strconv.FormatInt(id, 10))
		}
	}
	for _, id := range order {
		cn := conns[id]
		subject := strconv.FormatInt(id, 10)
		hs := cn.handshake
		if hs == nil || hs.Handshake.Outcome != "ok" {
			continue
		}
		if !hs.Handshake.Verified {
			if hs.Handshake.Resumed {
				fail(checkResumptionVerified, subject)
			} else {
				fail(checkHandshakeVerified, subject)
			}
		}
		switch {
		case cn.acl != nil && cn.acl.ACL.Decision == "allow":
		case cn.close != nil:
			if cn.close.Close.Reason != "refused" {
				fail(checkACLBeforeServe, subject)
			}
		default:
			since := hs.At
			if cn.acl != nil && cn.acl.At.After(since) {
				since = cn.acl.At
			}
			if now.Sub(since) > aclGrace {
				fail(checkACLBeforeServe, subject)
			}
		}
	}
	if cap := start.Config.LifetimeCapSeconds; cap > 0 {
		capMS := cap*1000 + lifetimeMargin.Milliseconds()
		for _, id := range order {
			cn := conns[id]
			subject := strconv.FormatInt(id, 10)
			switch {
			case cn.close != nil:
				if cn.close.Close.DurationMS > capMS {
					fail(checkLifetimeCap, subject)
				}
			case cn.accept != nil:
				if now.Sub(cn.accept.At) > time.Duration(cap)*time.Second+lifetimeMargin {
					fail(checkLifetimeCap, subject)
				}
			}
		}
	}
	seenErr := map[string]bool{}
	for i := range boot.Records {
		rec := &boot.Records[i]
		if rec.Kind != "accept-error" || now.Sub(rec.At) > tickMaxAge {
			continue
		}
		subject := boundBytes(rec.AcceptError.Error, acceptLoopSubjectBytes)
		if !seenErr[subject] {
			seenErr[subject] = true
			fail(checkAcceptLoop, subject)
		}
	}
	return out
}

// refSubstanceFindings is the two substance rules as one walk over every
// record of the boot, on a memory of its own that starts empty: every
// chain, CA bundle and policy file read afresh.
func refSubstanceFindings(boot *gtBoot, j substanceJudge) []Finding {
	j.Cache, j.Kept = nil, nil
	cy := newSubstanceCycle(boot, j)
	start := boot.Records[0].Start
	rules := substanceParseRules(start.Config.ACL)
	server := start.Config.Mode == "server"
	mat := substanceMaterial{}
	mat.apply(start.Config.Material)
	type judged struct {
		record   *gtRecord
		material substanceMaterial
	}
	handshakes := map[int64]judged{}
	var acls []*gtRecord
	var out []Finding
	seen := map[Finding]bool{}
	fail := func(check string, conn int64) {
		f := Finding{Check: check, Subject: strconv.FormatInt(conn, 10)}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	for i := range boot.Records {
		rec := &boot.Records[i]
		switch rec.Kind {
		case "reload":
			if rec.Reload.Outcome == "ok" && len(rec.Reload.Material) > 0 {
				next := substanceMaterial{}
				for k, v := range mat {
					next[k] = v
				}
				next.apply(rec.Reload.Material)
				mat = next
			}
		case "handshake":
			hs := rec.Handshake
			if _, ok := handshakes[hs.Conn]; !ok {
				handshakes[hs.Conn] = judged{record: rec, material: mat}
			}
			if !hs.Verified {
				continue
			}
			if !server || hs.Chain == "" || len(rules.unknown) > 0 {
				fail(checkHandshakeSubstance, hs.Conn)
				continue
			}
			c := cy.chain(hs.Chain)
			if c.certs == nil {
				fail(checkHandshakeSubstance, hs.Conn)
				continue
			}
			if len(rules.pins) > 0 {
				if !rules.pinned(c.certs[0]) {
					fail(checkHandshakeSubstance, hs.Conn)
				}
				continue
			}
			if !cy.verified(c, cy.ca(mat["ca"]), rec.At) {
				fail(checkHandshakeSubstance, hs.Conn)
			}
		case "acl":
			acls = append(acls, rec)
		}
	}
	for _, rec := range acls {
		a := rec.ACL
		hs, ok := handshakes[a.Conn]
		if !ok || !server {
			fail(checkACLSubstance, a.Conn)
			continue
		}
		h := hs.record.Handshake
		if a.Decision == "deny" && a.Rule == substanceACMEProbeRule && !h.Verified && h.Chain == "" {
			continue
		}
		var c *substanceChain
		if h.Chain != "" {
			c = cy.chain(h.Chain)
			if c.certs == nil {
				fail(checkACLSubstance, a.Conn)
				continue
			}
		}
		decision, rule, err := cy.decide(rules, c, hs.material, hs.record.At)
		if err != nil || decision != a.Decision || (decision == "allow" && rule != a.Rule) {
			fail(checkACLSubstance, a.Conn)
		}
	}
	return out
}

// refTunnelFindings is the reference for the whole tunnel surface.
func refTunnelFindings(boot *gtBoot, now time.Time, m surfaceMargins, j substanceJudge) []Finding {
	out := refTunnelSurfaceFindings(boot, now, m.LifetimeMargin, m.ACLGrace, m.TickMaxAge)
	return append(out, refSubstanceFindings(boot, j)...)
}

// ---- the random trace ----

// Policies the random traces name: the committed test PKI's, one that
// allows only other.example, and one that consults the clock, which is
// never remembered.
const (
	jmPolicyOther = "package policy\n\ndefault allow = false\n\nallow {\n\tinput.certificate.Subject.CommonName == \"other.example\"\n}\n"
	jmPolicyClock = "package policy\n\ndefault allow = false\n\nallow {\n\ttime.now_ns() > 0\n\tinput.certificate.Subject.CommonName == \"client.example\"\n}\n"
)

// jmTrace is one random trace: a root with the test PKI's chain and
// material stores, a material base holding the policy files, and the
// current boot's lines (sequence placeholders, renumbered on write) split
// into segments.
type jmTrace struct {
	t        *testing.T
	rng      *rand.Rand
	root     string
	base     string
	boot     int
	lines    []string
	ats      []time.Time
	segments []int // the index of each segment's first line
	// torn is a line of which only the first half is written yet, at
	// tornAt.
	torn     string
	tornAt   time.Time
	at       time.Time
	conns    []int
	nextConn int
	policies map[string]string // file name -> hash
	// served is the rule the start line's set allows the test PKI's
	// client chain under, which an honest connection records.
	served string
	// files are the store and policy files a cycle may break, with the
	// bytes that restore them.
	files map[string][]byte
}

func jmNewTrace(t *testing.T, seed int64) *jmTrace {
	t.Helper()
	tr := &jmTrace{t: t, rng: rand.New(rand.NewSource(seed)), root: t.TempDir(), base: t.TempDir(), policies: map[string]string{}, files: map[string][]byte{}}
	gtInstallChains(t, tr.root)
	gtInstallMaterial(t, tr.root)
	pkiPolicy, err := os.ReadFile(filepath.Join(gtPKI, "policy.rego"))
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"policy.rego": pkiPolicy, "other.rego": []byte(jmPolicyOther), "clock.rego": []byte(jmPolicyClock)} {
		p := filepath.Join(tr.base, name)
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
		tr.policies[name] = substanceHash(content)
		tr.files[p] = content
	}
	for _, hash := range []string{gtChainClient, gtChainOther} {
		p := filepath.Join(tr.root, substanceChainsDir, hash+".der")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		tr.files[p] = b
	}
	p := filepath.Join(tr.root, substanceMaterialDir, gtCAHash)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	tr.files[p] = b
	tr.at = time.Date(2026, 9, 24, 11, 0, 0, 0, time.UTC)
	tr.newBoot()
	return tr
}

func (tr *jmTrace) pick(n int) int { return tr.rng.Intn(n) }

func (tr *jmTrace) chance(p float64) bool { return tr.rng.Float64() < p }

func (tr *jmTrace) stamp() string { return tr.at.UTC().Format(gtTimestampLayout) }

func jmMaterial(kind, path, hash string) string {
	return fmt.Sprintf(`{"material":%q,"path":%q,"sha256":%q}`, kind, path, hash)
}

// startLine is a random start line: the mode, the rule set, the lifetime
// cap and the material in force.
func (tr *jmTrace) startLine() string {
	sets := [][]string{
		{"allow-cn:client.example"},
		{"policy:" + tr.policies["policy.rego"]},
		{"allow-all"},
		{"allow-cn:other.example", "policy:" + tr.policies["policy.rego"]},
		{"policy:" + tr.policies["clock.rego"]},
		{"allow-cn:client.example", "disable-authentication"},
		{"allow-dns:client.example", "allow-ou:policy-ou"},
	}
	served := []string{"allow-cn", "policy", "allow-all", "policy", "policy", "allow-cn", "allow-dns"}
	k := tr.pick(len(sets))
	acl := sets[k]
	tr.served = served[k]
	material := []string{jmMaterial("ca", "ca.pem", gtCAHash)}
	for _, r := range acl {
		if strings.HasPrefix(r, "policy:") {
			name := "policy.rego"
			if r == "policy:"+tr.policies["clock.rego"] {
				name = "clock.rego"
			}
			material = append(material, jmMaterial("policy", name, tr.policies[name]))
		}
	}
	mode := "server"
	if tr.chance(0.05) {
		mode = "client"
	}
	sort.Strings(acl)
	config := subConfigMode(mode, acl, material...)
	if tr.chance(0.2) {
		config = strings.Replace(config, `"lifetime_cap_seconds":300`, `"lifetime_cap_seconds":0`, 1)
	}
	return subStart(tr.stamp(), tr.boot, config)
}

func (tr *jmTrace) newBoot() {
	tr.boot++
	tr.lines, tr.ats, tr.segments, tr.torn = nil, nil, []int{0}, ""
	tr.conns, tr.nextConn = nil, 1
	tr.lines = append(tr.lines, tr.startLine())
	tr.ats = append(tr.ats, tr.at)
}

// conn is a connection for a line: mostly a recent one, sometimes any,
// sometimes one no accept opened.
func (tr *jmTrace) conn() int {
	switch {
	case len(tr.conns) == 0 || tr.chance(0.08):
		tr.nextConn++
		return tr.nextConn + 1000
	case tr.chance(0.75):
		return tr.conns[len(tr.conns)-1-tr.pick(min(3, len(tr.conns)))]
	}
	return tr.conns[tr.pick(len(tr.conns))]
}

// line is one random line at the trace's clock, never a start line.
func (tr *jmTrace) line() string {
	at := tr.stamp()
	chains := []string{gtChainClient, gtChainClient, gtChainClient, gtChainOther, gtChainRogue, gtChainExpired, "", strings.Repeat("a", 64)}
	switch r := tr.rng.Float64(); {
	case r < 0.18:
		id := tr.nextConn
		if len(tr.conns) > 0 && tr.chance(0.06) {
			id = tr.conns[tr.pick(len(tr.conns))]
		} else {
			tr.nextConn++
			tr.conns = append(tr.conns, id)
		}
		return subAccept(at, id)
	case r < 0.36:
		outcome := "ok"
		if tr.chance(0.12) {
			outcome = "refused"
		}
		return subHandshake(at, tr.conn(), outcome, tr.chance(0.1), tr.chance(0.85), chains[tr.pick(len(chains))])
	case r < 0.54:
		if tr.chance(0.75) {
			rules := []string{"allow-cn", "allow-cn", "policy", "allow-all", "disable-authentication", "allow-dns"}
			return subACL(at, tr.conn(), "allow", rules[tr.pick(len(rules))])
		}
		rules := []string{"none", "none", substanceACMEProbeRule}
		return subACL(at, tr.conn(), "deny", rules[tr.pick(len(rules))])
	case r < 0.70:
		reason := "eof"
		if tr.chance(0.3) {
			reason = "refused"
		}
		duration := 3
		if tr.chance(0.1) {
			duration = 301500 + tr.pick(2000)
		}
		return fmt.Sprintf(`%s,"conn":%d,"reason":"%s","duration_ms":%d}`, subHdr("close", at), tr.conn(), reason, duration)
	case r < 0.76:
		texts := []string{"accept tcp: too many open files", "accept tcp: connection reset", strings.Repeat("é", 40)}
		return fmt.Sprintf(`%s,"error":%q,"backoff_ms":5}`, subHdr("accept-error", at), texts[tr.pick(len(texts))])
	case r < 0.80:
		if tr.chance(0.3) {
			return fmt.Sprintf(`%s,"outcome":"failed","error":"bad","serving":true,"material":[]}`, subHdr("reload", at))
		}
		var ms []string
		if tr.chance(0.7) {
			hash := gtCAHash
			if tr.chance(0.3) {
				b, err := os.ReadFile(filepath.Join(gtPKI, "rogue-ca.pem"))
				if err != nil {
					tr.t.Fatal(err)
				}
				hash = substanceHash(b)
			}
			ms = append(ms, jmMaterial("ca", "ca.pem", hash))
		}
		if tr.chance(0.5) {
			names := []string{"policy.rego", "other.rego", "clock.rego"}
			name := names[tr.pick(len(names))]
			ms = append(ms, jmMaterial("policy", name, tr.policies[name]))
		}
		return subReload(at, "ok", ms...)
	case r < 0.82:
		return fmt.Sprintf(`%s,"source":"signal","authorized":true,"peer":null,"detail":"SIGHUP"}`, subHdr("shutdown", at))
	}
	return fmt.Sprintf(`{"kind":"tick","version":1,"sequence":0,"at":"%s"}`, at)
}

// grow appends n lines, the clock moving on by up to three seconds each:
// random lines, and now and then an honest connection, whose lines add up
// and whose substance holds, so that a verdict that should change has a
// passing one to change from.
func (tr *jmTrace) grow(n int) {
	for i := 0; i < n; i++ {
		tr.at = tr.at.Add(time.Duration(tr.pick(4)) * time.Second)
		if tr.chance(0.25) {
			id := tr.nextConn
			tr.nextConn++
			tr.conns = append(tr.conns, id)
			for _, l := range subServed(tr.stamp(), id, gtChainClient, tr.served) {
				tr.lines = append(tr.lines, l)
				tr.ats = append(tr.ats, tr.at)
			}
			continue
		}
		tr.lines = append(tr.lines, tr.line())
		tr.ats = append(tr.ats, tr.at)
	}
}

// rewrite replaces one line of the prefix with another at its time.
func (tr *jmTrace) rewrite() {
	if len(tr.lines) < 2 {
		return
	}
	i := 1 + tr.pick(len(tr.lines)-1)
	saved := tr.at
	tr.at = tr.ats[i]
	tr.lines[i] = tr.line()
	tr.at = saved
}

// rewriteStart replaces the start line with another at its time.
func (tr *jmTrace) rewriteStart() {
	saved := tr.at
	tr.at = tr.ats[0]
	tr.lines[0] = tr.startLine()
	tr.at = saved
}

// breakFile changes, removes, makes a directory of, or restores one of the
// files the substance rules read.
func (tr *jmTrace) breakFile() {
	names := make([]string, 0, len(tr.files))
	for p := range tr.files {
		names = append(names, p)
	}
	sort.Strings(names)
	p := names[tr.pick(len(names))]
	if err := os.RemoveAll(p); err != nil {
		tr.t.Fatal(err)
	}
	var err error
	switch tr.pick(4) {
	case 0:
		err = os.WriteFile(p, append(append([]byte{}, tr.files[p]...), '\n'), 0o644)
	case 1:
	case 2:
		err = os.Mkdir(p, 0o755)
	default:
		err = os.WriteFile(p, tr.files[p], 0o644)
	}
	if err != nil {
		tr.t.Fatal(err)
	}
}

// restoreFiles puts every file back as it was.
func (tr *jmTrace) restoreFiles() {
	for p, b := range tr.files {
		if err := os.RemoveAll(p); err != nil {
			tr.t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			tr.t.Fatal(err)
		}
	}
}

// write puts the current boot on the disk: every segment, the last with
// the torn tail.
func (tr *jmTrace) write() {
	dir := filepath.Join(tr.root, gtBootName(int64(tr.boot)))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tr.t.Fatal(err)
	}
	lines := tRenumberLines(tr.lines)
	for k, first := range tr.segments {
		end := len(lines)
		if k+1 < len(tr.segments) {
			end = tr.segments[k+1]
		}
		data := gtJoin(lines[first:end]...)
		if k == len(tr.segments)-1 && tr.torn != "" {
			// Renumbered as the line it will be.
			whole := tRenumberLines(append(append([]string{}, tr.lines...), tr.torn))
			torn := whole[len(whole)-1]
			data = append(data, torn[:len(torn)/2]...)
		}
		name := fmt.Sprintf("%010d.trace", first+1)
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			tr.t.Fatal(err)
		}
	}
}

// cycle changes the trace at random, as a proxy, a disk or anyone who can
// write the tree might between two cycles.
func (tr *jmTrace) cycle() {
	if tr.torn != "" {
		if !tr.chance(0.6) {
			// Still being written: nothing after it yet.
			tr.write()
			return
		}
		tr.lines = append(tr.lines, tr.torn)
		tr.ats = append(tr.ats, tr.tornAt)
		tr.torn = ""
	}
	if tr.chance(0.1) && len(tr.lines) > tr.segments[len(tr.segments)-1] {
		tr.segments = append(tr.segments, len(tr.lines))
	}
	if tr.chance(0.8) {
		tr.grow(tr.pick(13))
	}
	if tr.chance(0.08) {
		tr.rewrite()
	}
	if tr.chance(0.03) {
		tr.rewriteStart()
	}
	if tr.chance(0.03) {
		tr.newBoot()
	}
	if tr.chance(0.06) {
		// A line half written: its first half is on the disk.
		tr.at = tr.at.Add(time.Second)
		tr.torn, tr.tornAt = tr.line(), tr.at
	}
	tr.write()
}

// ---- the differential ----

// now is a clock for the cycle: around the newest line, across the
// grace, the accept-loop window and the lifetime cap.
func (tr *jmTrace) now() time.Time {
	offsets := []time.Duration{-5 * time.Second, 0, time.Second, 2 * time.Second, 3 * time.Second, 6 * time.Second, 11 * time.Second, 29 * time.Second, 31 * time.Second, 45 * time.Second, 299 * time.Second, 303 * time.Second, 400 * time.Second}
	return tr.at.Add(offsets[tr.pick(len(offsets))])
}

// jmStats counts what the differential exercised.
type jmStats struct {
	traces, cycles, judged, kept, rebuilt, unread, skipped int
	findings                                               map[string]int
}

// jmFindingsEqual is findings equal in order, nil and empty alike.
func jmFindingsEqual(a, b []Finding) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// jmRun grows one random trace over cycles and compares, every cycle it
// judges, the kept judgement with the reference and with the members' own
// judgement of every record.
func jmRun(t *testing.T, seed int64, cycles int, stats *jmStats) {
	tr := jmNewTrace(t, seed)
	st := &State{}
	margins := []surfaceMargins{{}, {LifetimeMargin: time.Second, ACLGrace: 5 * time.Second, TickMaxAge: 10 * time.Second}}
	m := margins[tr.pick(len(margins))]
	query := gtPolicyQueryPKI
	for c := 0; c < cycles; c++ {
		stats.cycles++
		tr.cycle()
		if tr.chance(0.12) {
			tr.breakFile()
		}
		if tr.chance(0.06) {
			tr.restoreFiles()
		}
		if tr.chance(0.03) {
			m = margins[tr.pick(len(margins))]
		}
		if tr.chance(0.02) {
			query = "data.policy.nothing"
			if tr.chance(0.5) {
				query = gtPolicyQueryPKI
			}
		}
		boot, _, err := traceReadCurrent(st, tr.root)
		if err != nil || len(boot.Records) == 0 || boot.Records[0].Start == nil {
			stats.unread++
			continue
		}
		if tr.chance(0.08) {
			// Read, and not judged: the owner's account was not current,
			// say, so surface-disagree did not look.
			stats.skipped++
			continue
		}
		now := tr.now()
		cfg := &Config{MaterialBase: tr.base, PolicyQuery: query}
		j := substanceJudgeFor(cfg, st)
		before := st.TunnelJudgement.tunnel
		got := tunnelFindings(boot, now, m, j)
		stats.judged++
		if before != nil && st.TunnelJudgement.tunnel == before {
			stats.kept++
		} else {
			stats.rebuilt++
		}
		plain := substanceJudge{MaterialBase: tr.base, PolicyQuery: query}
		want := refTunnelFindings(boot, now, m, plain)
		if !jmFindingsEqual(got, want) {
			t.Fatalf("seed %d cycle %d (%d records, carried %d): kept judgement\n %v\nreference\n %v", seed, c, len(boot.Records), boot.Carried, got, want)
		}
		if full := tunnelFindings(boot, now, m, plain); !jmFindingsEqual(full, want) {
			t.Fatalf("seed %d cycle %d: full judgement\n %v\nreference\n %v", seed, c, full, want)
		}
		for _, f := range got {
			stats.findings[f.Check]++
		}
	}
}

// TestTunnelJudgementDifferential: the kept judgement equals the full one
// on every cycle of every random trace, and the traces exercise every rule
// of the surface failing and the judgement both kept and rebuilt.
func TestTunnelJudgementDifferential(t *testing.T) {
	traces, cycles := 80, 40
	if testing.Short() {
		traces = 20
	}
	stats := &jmStats{findings: map[string]int{}}
	for seed := int64(1); seed <= int64(traces); seed++ {
		stats.traces++
		jmRun(t, seed, cycles, stats)
	}
	t.Logf("%d traces, %d cycles: %d judged (%d kept, %d rebuilt), %d unreadable, %d read and not judged; findings %v", stats.traces, stats.cycles, stats.judged, stats.kept, stats.rebuilt, stats.unread, stats.skipped, stats.findings)
	if stats.kept == 0 || stats.rebuilt == 0 {
		t.Fatalf("the judgement was kept %d times and rebuilt %d times", stats.kept, stats.rebuilt)
	}
	for _, id := range tunnelSurfaceIdentifiers {
		if stats.findings[id] == 0 {
			t.Errorf("no cycle found against %s", id)
		}
	}
}

// ---- the key, one part at a time ----

// jmKeyTree is a trace of connections that all pass, and the state that
// has judged it once.
func jmKeyTree(t *testing.T) (root string, st *State, j substanceJudge, now time.Time) {
	t.Helper()
	end := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	root = t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtSynthLines(200, end)...))
	st = &State{}
	j = substanceJudgeFor(&Config{PolicyQuery: gtPolicyQueryPKI}, st)
	boot, _, err := traceReadCurrent(st, root)
	if err != nil {
		t.Fatal(err)
	}
	if f := tunnelFindings(boot, end, surfaceMargins{}, j); len(f) != 0 {
		t.Fatalf("the healthy trace: %v", f)
	}
	return root, st, j, end
}

// A read whose Carried claims the judged records but that is of another
// boot is judged from none: the boot's identity is part of the key even
// where the reader's Carried is wrong.
func TestTunnelJudgementRefusesAnotherBoot(t *testing.T) {
	_, st, j, now := jmKeyTree(t)
	kept := st.TunnelJudgement
	lines := gtSynthLines(200, now)
	// The same number of records, one connection denied and served.
	for i, l := range lines {
		if strings.Contains(l, `"kind":"acl"`) {
			lines[i] = strings.Replace(l, `"decision":"allow","rule":"allow-cn"`, `"decision":"deny","rule":"none"`, 1)
			break
		}
	}
	other := t.TempDir()
	gtWriteSegment(t, other, "0000000001", "0000000001.trace", gtJoin(lines...))
	boot, err := gtReadLatest(other)
	if err != nil {
		t.Fatal(err)
	}
	// A forged read: the kept judgement's memory, the next read, every
	// record carried.
	boot.Memory, boot.Read, boot.Carried = kept.decode, kept.read+1, len(boot.Records)
	got := tunnelFindings(boot, now, surfaceMargins{}, j)
	want := refTunnelFindings(boot, now, surfaceMargins{}, substanceJudge{PolicyQuery: gtPolicyQueryPKI})
	if len(want) == 0 || !jmFindingsEqual(got, want) {
		t.Fatalf("another boot under a forged read: %v, want %v", got, want)
	}
}

// A read made with the memory and not judged breaks the chain of proof: the
// next read's Carried speaks of that read, not of the one judged, so the
// judgement is rebuilt. Between the two, the prefix was rewritten and the
// boot then grew past the judged length.
func TestTunnelJudgementAReadNotJudgedRebuilds(t *testing.T) {
	root, st, j, now := jmKeyTree(t)
	lines := gtSynthLines(200, now)
	for i, l := range lines {
		if strings.Contains(l, `"kind":"acl"`) {
			lines[i] = strings.Replace(l, `"decision":"allow","rule":"allow-cn"`, `"decision":"deny","rule":"none"`, 1)
			break
		}
	}
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(lines...))
	if _, _, err := traceReadCurrent(st, root); err != nil {
		t.Fatal(err)
	}
	more := append(append([]string{}, lines[:len(lines)-1]...), fmt.Sprintf(`{"kind":"tick","version":1,"sequence":%d,"at":"%s"}`, len(lines), now.UTC().Format(gtTimestampLayout)), fmt.Sprintf(`{"kind":"tick","version":1,"sequence":%d,"at":"%s"}`, len(lines)+1, now.UTC().Format(gtTimestampLayout)))
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(more...))
	boot, _, err := traceReadCurrent(st, root)
	if err != nil {
		t.Fatal(err)
	}
	if boot.Carried < len(lines)-1 {
		t.Fatalf("carried %d: the read did not resume from the read not judged", boot.Carried)
	}
	got := tunnelFindings(boot, now, surfaceMargins{}, j)
	want := refTunnelFindings(boot, now, surfaceMargins{}, substanceJudge{PolicyQuery: gtPolicyQueryPKI})
	if len(want) == 0 || !jmFindingsEqual(got, want) {
		t.Fatalf("after a read not judged: %v, want %v", got, want)
	}
}

// The kept judgement extends from the records it has not judged and no
// others: a cycle with new lines adds only those.
func TestTunnelJudgementExtendsOnlyTheNewRecords(t *testing.T) {
	root, st, j, now := jmKeyTree(t)
	kept := st.TunnelJudgement
	tunnel, judged := kept.tunnel, kept.judged
	lines := gtSynthLines(200, now)
	lines = append(lines[:len(lines):len(lines)], fmt.Sprintf(`{"kind":"accept","version":1,"sequence":%d,"at":"%s","conn":9999,"listener":"127.0.0.1:8443","remote":"10.0.0.7:51000"}`, len(lines)+1, now.UTC().Format(gtTimestampLayout)))
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(lines...))
	boot, _, err := traceReadCurrent(st, root)
	if err != nil {
		t.Fatal(err)
	}
	if boot.Carried != judged {
		t.Fatalf("carried %d, judged %d", boot.Carried, judged)
	}
	got := tunnelFindings(boot, now.Add(time.Hour), surfaceMargins{}, j)
	if kept.tunnel != tunnel || kept.judged != len(boot.Records) {
		t.Fatalf("the judgement was not extended: judged %d of %d", kept.judged, len(boot.Records))
	}
	want := refTunnelFindings(boot, now.Add(time.Hour), surfaceMargins{}, substanceJudge{PolicyQuery: gtPolicyQueryPKI})
	if !jmFindingsEqual(got, want) || len(want) != 1 || want[0].Check != checkLifetimeCap {
		t.Fatalf("extended: %v, want %v (the new connection over the cap)", got, want)
	}
}

// The start line's bytes are its identity.
func TestGTStartLineHash(t *testing.T) {
	boot := &gtBoot{Segments: []gtSegment{{Prefix: []byte("{\"kind\":\"start\"}\n{\"kind\":\"tick\"}\n")}}}
	if got, want := gtStartLineHash(boot), hashPrefix([]byte("{\"kind\":\"start\"}\n")); got != want {
		t.Fatalf("hash %s, want %s", got, want)
	}
	for _, b := range []*gtBoot{{}, {Segments: []gtSegment{{Prefix: bytes.Repeat([]byte("x"), 10)}}}} {
		if gtStartLineHash(b) != "" {
			t.Fatal("a read with no complete first line has an identity")
		}
	}
}
