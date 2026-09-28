package ringtrace

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// testBinary is the config.binary every sample start line carries.
var testBinary = Binary{Path: "/usr/local/bin/ghostunnel", SHA256: strings.Repeat("b", 64)}

// sampleBodies is one well-formed body of every kind, used by the round-trip
// tests here and by the emitter and reader tests.
func sampleBodies() []Body {
	ca := "a" + strings.Repeat("0", 63)
	cert := "b" + strings.Repeat("1", 63)
	status := "127.0.0.1:6060"
	hsErr := "tls: bad certificate"
	peer := "CN=ops,O=example"
	return []Body{
		&Start{
			Boot: 1, PID: 4242,
			Config: Config{
				Mode: "server", Listen: "0.0.0.0:8443", Target: "127.0.0.1:8080", ProxyProtocol: ProxyProtocolOff,
				StatusListen: &status, StatusClientCert: false,
				SessionTickets: false, VerifyOnResume: true, ACL: []string{"allow-cn:client", "policy:" + ca},
				LifetimeCapSeconds: 300, SandboxState: SandboxApplied, SandboxAccepted: nil,
				Material: []Material{
					{Material: "cert", Path: "/etc/gt/server.crt", SHA256: &cert},
					{Material: "key", Path: "/etc/gt/server.key", SHA256: nil},
					{Material: "ca", Path: "/etc/gt/ca.pem", SHA256: &ca},
					{Material: "policy", Path: "", SHA256: nil},
				},
				Binary: testBinary,
			},
		},
		&Accept{Conn: 1, Listener: "0.0.0.0:8443", Remote: "10.0.0.7:51234"},
		&Handshake{
			Conn: 1, Outcome: "ok", Resumed: false, Verified: true, Protocol: "TLS1.3",
			Peer: &Peer{
				Subject: "CN=client,OU=eng,O=example", Issuer: "CN=example-ca",
				Serial: "1a2b3c", SANs: []string{"dns:client.example", "uri:spiffe://example/client"},
				Fingerprint: cert,
			},
			Error: nil,
		},
		&Handshake{Conn: 2, Outcome: "refused", Resumed: true, Verified: false, Protocol: "", Peer: nil, Error: &hsErr},
		&Handshake{
			Conn: 3, Outcome: "ok", Resumed: true, Verified: true, Protocol: "TLS1.3",
			Peer:  &Peer{Subject: "CN=client", Issuer: "CN=example-ca", Serial: "1a2b3c", SANs: []string{}, Fingerprint: cert},
			Error: nil, Chain: "c" + strings.Repeat("2", 63),
		},
		&ACL{Conn: 1, Decision: "allow", Rule: "allow-cn", Reason: "CN=client matched --allow-cn client"},
		&ACL{Conn: 2, Decision: "deny", Rule: "none", Reason: "no rule matched"},
		&Close{Conn: 1, Reason: "eof", DurationMS: 1532},
		&Reload{Outcome: "ok", Error: nil, Serving: true, Material: []Material{{Material: "cert", Path: "/etc/gt/server.crt", SHA256: &cert}, {Material: "key", Path: "/etc/gt/server.key", SHA256: nil}}},
		&Reload{Outcome: "failed", Error: &hsErr, Serving: false, Material: []Material{{Material: "policy", Path: "/etc/gt/policy.rego", SHA256: nil}}},
		&Shutdown{Source: "status-endpoint", Authorized: true, Peer: &peer, Detail: "POST /_shutdown"},
		&Tick{},
		&AcceptError{Error: "accept tcp 0.0.0.0:8443: too many open files", BackoffMS: 5},
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	for i, body := range sampleBodies() {
		rec := Record{Sequence: int64(i + 1), At: at, Body: body}
		line, err := EncodeLine(rec)
		if err != nil {
			t.Fatalf("%d %s: encode: %v", i, body.Kind(), err)
		}
		if !bytes.HasSuffix(line, []byte("\n")) || bytes.Count(line, []byte("\n")) != 1 {
			t.Fatalf("%d %s: line must end in exactly one LF: %q", i, body.Kind(), line)
		}
		got, err := DecodeLine(bytes.TrimSuffix(line, []byte("\n")))
		if err != nil {
			t.Fatalf("%d %s: decode: %v\n%s", i, body.Kind(), err, line)
		}
		if !reflect.DeepEqual(got, rec) {
			t.Fatalf("%d %s: round trip differs\nwant %#v\ngot  %#v", i, body.Kind(), rec, got)
		}
	}
}

func TestKindIsFirstKey(t *testing.T) {
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	for i, body := range sampleBodies() {
		line, err := EncodeLine(Record{Sequence: int64(i + 1), At: at, Body: body})
		if err != nil {
			t.Fatal(err)
		}
		want := `{"kind":"` + string(body.Kind()) + `","version":1,"sequence":`
		if !bytes.HasPrefix(line, []byte(want)) {
			t.Fatalf("%s: line does not begin with %q: %q", body.Kind(), want, line)
		}
		if ClassifyLine(line) != body.Kind() {
			t.Fatalf("%s: ClassifyLine returned %q", body.Kind(), ClassifyLine(line))
		}
	}
	if ClassifyLine([]byte(`{"version":1,"kind":"accept"}`)) != "" {
		t.Fatal("kind not first must classify as nothing")
	}
	if ClassifyLine([]byte(`{"kind":"heartbeat",`)) != "" {
		t.Fatal("a heartbeat marker is not a trace kind")
	}
}

func TestEncodeTruncatesToWholeSeconds(t *testing.T) {
	at := time.Date(2026, 9, 24, 10, 7, 0, 999_000_000, time.FixedZone("x", 3600))
	line, err := EncodeLine(Record{Sequence: 1, At: at, Body: &Accept{Conn: 1, Listener: "a:1", Remote: "b:2"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(line, []byte(`"at":"2026-09-24T09:07:00Z"`)) {
		t.Fatalf("at must be UTC whole seconds: %s", line)
	}
}

func TestDecodeRejects(t *testing.T) {
	good := `{"kind":"accept","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"listener":"0.0.0.0:8443","remote":"10.0.0.7:51234"}`
	if _, err := DecodeLine([]byte(good)); err != nil {
		t.Fatalf("control line must decode: %v", err)
	}
	cases := map[string]string{
		"unknown key":          `{"kind":"accept","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"listener":"a","remote":"b","extra":1}`,
		"missing key":          `{"kind":"accept","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"listener":"a"}`,
		"wrong type":           `{"kind":"accept","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":"1","listener":"a","remote":"b"}`,
		"null non-nullable":    `{"kind":"accept","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":null,"listener":"a","remote":"b"}`,
		"float sequence":       `{"kind":"accept","version":1,"sequence":3.0,"at":"2026-09-24T10:07:00Z","conn":1,"listener":"a","remote":"b"}`,
		"zero sequence":        `{"kind":"accept","version":1,"sequence":0,"at":"2026-09-24T10:07:00Z","conn":1,"listener":"a","remote":"b"}`,
		"version 2":            `{"kind":"accept","version":2,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"listener":"a","remote":"b"}`,
		"unknown kind":         `{"kind":"connect","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"listener":"a","remote":"b"}`,
		"kind not first":       `{"version":1,"kind":"accept","sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"listener":"a","remote":"b"}`,
		"whitespace in prefix": `{ "kind":"accept","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"listener":"a","remote":"b"}`,
		"bad timestamp":        `{"kind":"accept","version":1,"sequence":3,"at":"2026-09-24T10:07:00.5Z","conn":1,"listener":"a","remote":"b"}`,
		"non-utc timestamp":    `{"kind":"accept","version":1,"sequence":3,"at":"2026-09-24T10:07:00+01:00","conn":1,"listener":"a","remote":"b"}`,
		"duplicate key":        `{"kind":"accept","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"conn":2,"listener":"a","remote":"b"}`,
		"trailing bytes":       good + ` x`,
		"embedded LF":          `{"kind":"accept","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"listener":"a","remote":"b"}` + "\n",
		"not an object":        `["kind","accept"]`,
		"empty":                ``,
		"bom":                  "\xEF\xBB\xBF" + good,
		"invalid utf8":         `{"kind":"accept","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"listener":"\xff","remote":"b"}`,
		"bad enum":             `{"kind":"acl","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"decision":"maybe","rule":"r","reason":"x"}`,
		"key with hash":        `{"kind":"reload","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","outcome":"ok","error":null,"serving":true,"material":[{"material":"key","path":"/k","sha256":"` + strings.Repeat("0", 64) + `"}]}`,
		"bad hash":             `{"kind":"reload","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","outcome":"ok","error":null,"serving":true,"material":[{"material":"cert","path":"/c","sha256":"abc"}]}`,
		"nested unknown key":   `{"kind":"reload","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","outcome":"ok","error":null,"serving":true,"material":[{"material":"cert","path":"/c","sha256":null,"x":1}]}`,
		"nested missing key":   `{"kind":"reload","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","outcome":"ok","error":null,"serving":true,"material":[{"material":"cert","path":"/c"}]}`,
		"material null":        `{"kind":"reload","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","outcome":"ok","error":null,"serving":true,"material":null}`,
		"peer null sans":       `{"kind":"handshake","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"outcome":"ok","resumed":false,"verified":true,"protocol":"TLS1.3","peer":{"subject":"s","issuer":"i","serial":"1","sans":null,"fingerprint":"` + strings.Repeat("0", 64) + `"},"error":null}`,
		"config null":          `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T10:07:00Z","boot":1,"pid":1,"config":null}`,
		"pem in string":        `{"kind":"acl","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"decision":"deny","rule":"r","reason":"-----BEGIN RSA PRIVATE KEY-----"}`,
		"negative duration":    `{"kind":"close","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"reason":"eof","duration_ms":-1}`,
		"chain not a hash":     `{"kind":"handshake","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"outcome":"ok","resumed":false,"verified":true,"protocol":"TLS1.3","peer":null,"error":null,"chain":"abc"}`,
		"chain upper case":     `{"kind":"handshake","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"outcome":"ok","resumed":false,"verified":true,"protocol":"TLS1.3","peer":null,"error":null,"chain":"` + strings.Repeat("A", 64) + `"}`,
		"chain null":           `{"kind":"handshake","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"outcome":"ok","resumed":false,"verified":true,"protocol":"TLS1.3","peer":null,"error":null,"chain":null}`,
		"chain empty":          `{"kind":"handshake","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"outcome":"ok","resumed":false,"verified":true,"protocol":"TLS1.3","peer":null,"error":null,"chain":""}`,
		"chain not a string":   `{"kind":"handshake","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"outcome":"ok","resumed":false,"verified":true,"protocol":"TLS1.3","peer":null,"error":null,"chain":1}`,
		"chain elsewhere":      `{"kind":"acl","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":1,"decision":"allow","rule":"r","reason":"x","chain":"` + strings.Repeat("0", 64) + `"}`,
	}
	for name, line := range cases {
		if _, err := DecodeLine([]byte(line)); err == nil {
			t.Errorf("%s: decoded but must be rejected: %s", name, line)
		}
	}
}

func TestEncodeRejects(t *testing.T) {
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	hash := strings.Repeat("0", 64)
	cases := map[string]Record{
		"nil body":         {Sequence: 1, At: at, Body: nil},
		"zero sequence":    {Sequence: 0, At: at, Body: &Accept{Conn: 1, Listener: "a", Remote: "b"}},
		"zero time":        {Sequence: 1, Body: &Accept{Conn: 1, Listener: "a", Remote: "b"}},
		"bad decision":     {Sequence: 1, At: at, Body: &ACL{Conn: 1, Decision: "permit", Rule: "r", Reason: "x"}},
		"bad outcome":      {Sequence: 1, At: at, Body: &Handshake{Conn: 1, Outcome: "fine", Protocol: "TLS1.3"}},
		"bad close reason": {Sequence: 1, At: at, Body: &Close{Conn: 1, Reason: "whatever", DurationMS: 1}},
		"bad material":     {Sequence: 1, At: at, Body: &Reload{Outcome: "ok", Serving: true, Material: []Material{{Material: "keystore", Path: "/x"}}}},
		"key with hash":    {Sequence: 1, At: at, Body: &Reload{Outcome: "ok", Serving: true, Material: []Material{{Material: "key", Path: "/x", SHA256: &hash}}}},
		"bad source":       {Sequence: 1, At: at, Body: &Shutdown{Source: "telnet", Authorized: false, Detail: "x"}},
		"pem in string":    {Sequence: 1, At: at, Body: &ACL{Conn: 1, Decision: "deny", Rule: "r", Reason: "-----BEGIN CERTIFICATE-----"}},
		"pem in san":       {Sequence: 1, At: at, Body: &Handshake{Conn: 1, Outcome: "ok", Verified: true, Protocol: "TLS1.3", Peer: &Peer{Subject: "s", Issuer: "i", Serial: "1", SANs: []string{"-----BEGIN EC PRIVATE KEY-----"}, Fingerprint: hash}}},
		"empty listener":   {Sequence: 1, At: at, Body: &Accept{Conn: 1, Listener: "", Remote: "b"}},
		"zero conn":        {Sequence: 1, At: at, Body: &Accept{Conn: 0, Listener: "a", Remote: "b"}},
		"start boot zero":  {Sequence: 1, At: at, Body: &Start{Boot: 0, PID: 1, Config: Config{Mode: "server", Listen: "a", Target: "b", ProxyProtocol: ProxyProtocolOff, ACL: []string{"allow-all"}, SandboxState: SandboxApplied, Material: []Material{}, Binary: testBinary}}},
		"start bad mode":   {Sequence: 1, At: at, Body: &Start{Boot: 1, PID: 1, Config: Config{Mode: "proxy", Listen: "a", Target: "b", ProxyProtocol: ProxyProtocolOff, ACL: []string{"allow-all"}, SandboxState: SandboxApplied, Material: []Material{}, Binary: testBinary}}},
		"bad chain":        {Sequence: 1, At: at, Body: &Handshake{Conn: 1, Outcome: "ok", Verified: true, Protocol: "TLS1.3", Chain: "abc"}},
		"upper-case chain": {Sequence: 1, At: at, Body: &Handshake{Conn: 1, Outcome: "ok", Verified: true, Protocol: "TLS1.3", Chain: strings.ToUpper(hash[:63]) + "A"}},
	}
	for name, rec := range cases {
		if _, err := EncodeLine(rec); err == nil {
			t.Errorf("%s: encoded but must be rejected", name)
		}
	}
}

// TestHandshakeChainKey: chain is the one optional key of the format. A
// handshake without a chain is encoded without the key and decodes with
// Chain empty; one with a chain ends in the key and decodes with it;
// Keys(handshake) lists it last and OptionalKeys names it alone.
func TestHandshakeChainKey(t *testing.T) {
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	hash := "c" + strings.Repeat("2", 63)
	without := &Handshake{Conn: 1, Outcome: "ok", Verified: true, Protocol: "TLS1.3"}
	line, err := EncodeLine(Record{Sequence: 2, At: at, Body: without})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(line, []byte(`"chain"`)) {
		t.Fatalf("no certificate presented, yet a chain key: %s", line)
	}
	if !bytes.HasSuffix(line, []byte(`"peer":null,"error":null}`+"\n")) {
		t.Fatalf("unexpected tail: %s", line)
	}
	got, err := DecodeLine(bytes.TrimSuffix(line, []byte("\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got.Body.(*Handshake).Chain != "" {
		t.Fatal("an absent chain decodes as empty")
	}

	with := &Handshake{Conn: 1, Outcome: "ok", Verified: true, Protocol: "TLS1.3", Chain: hash}
	line, err = EncodeLine(Record{Sequence: 2, At: at, Body: with})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(line, []byte(`"peer":null,"error":null,"chain":"`+hash+`"}`+"\n")) {
		t.Fatalf("chain is the last key: %s", line)
	}
	got, err = DecodeLine(bytes.TrimSuffix(line, []byte("\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got.Body.(*Handshake).Chain != hash {
		t.Fatalf("chain = %q", got.Body.(*Handshake).Chain)
	}

	keys := Keys(KindHandshake)
	if keys[len(keys)-1] != "chain" {
		t.Fatalf("Keys(handshake) = %v: chain must be last", keys)
	}
	if !reflect.DeepEqual(OptionalKeys(KindHandshake), []string{"chain"}) {
		t.Fatalf("OptionalKeys(handshake) = %v", OptionalKeys(KindHandshake))
	}
	for _, k := range kinds {
		if k != KindHandshake && len(OptionalKeys(k)) != 0 {
			t.Fatalf("OptionalKeys(%s) = %v: only handshake has an optional key", k, OptionalKeys(k))
		}
	}
	// The struct tag is omitempty and it is the only one.
	rt := reflect.TypeOf(Handshake{})
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if (strings.HasSuffix(tag, ",omitempty")) != (rt.Field(i).Name == "Chain") {
			t.Fatalf("field %s tag %q: only Chain is omitempty", rt.Field(i).Name, tag)
		}
	}
}

// TestDocumentedKeysMatchStructs pins the README's key lists to the code: the
// json tags of each body (and the nested objects) must be exactly the keys
// Keys() documents, in order. The observers' localchecks are written against
// Keys(), so a field added to a struct without updating the list fails here.
func TestDocumentedKeysMatchStructs(t *testing.T) {
	tags := func(v interface{}) []string {
		rt := reflect.TypeOf(v)
		if rt.Kind() == reflect.Pointer {
			rt = rt.Elem()
		}
		var out []string
		for i := 0; i < rt.NumField(); i++ {
			tag := rt.Field(i).Tag.Get("json")
			if tag == "" || tag == "-" {
				continue
			}
			out = append(out, strings.Split(tag, ",")[0])
		}
		return out
	}
	header := []string{"kind", "version", "sequence", "at"}
	for _, body := range sampleBodies() {
		want := Keys(body.Kind())
		got := append(append([]string{}, header...), tags(body)...)
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%s: Keys() = %v, struct tags = %v", body.Kind(), want, got)
		}
	}
	if Keys("nonsense") != nil {
		t.Error("Keys of an unknown kind must be nil")
	}
	if !reflect.DeepEqual(ConfigKeys, tags(Config{})) {
		t.Errorf("ConfigKeys = %v, tags = %v", ConfigKeys, tags(Config{}))
	}
	if !reflect.DeepEqual(MaterialKeys, tags(Material{})) {
		t.Errorf("MaterialKeys = %v, tags = %v", MaterialKeys, tags(Material{}))
	}
	if !reflect.DeepEqual(PeerKeys, tags(Peer{})) {
		t.Errorf("PeerKeys = %v, tags = %v", PeerKeys, tags(Peer{}))
	}
}

func TestLineBound(t *testing.T) {
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	huge := &ACL{Conn: 1, Decision: "deny", Rule: "r", Reason: strings.Repeat("x", MaxLineBytes)}
	if _, err := EncodeLine(Record{Sequence: 1, At: at, Body: huge}); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("an over-long line must be refused with ErrLineTooLong, got %v", err)
	}
	long := []byte(`{"kind":"acl","version":1,"sequence":1,"at":"2026-09-24T10:07:00Z","conn":1,"decision":"deny","rule":"r","reason":"` + strings.Repeat("x", MaxLineBytes) + `"}`)
	if _, err := DecodeLine(long); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("decoder must refuse an over-long line with ErrLineTooLong, got %v", err)
	}
}

// TestConfigCarriesAdminSurface pins the two fields the admin observer reads
// from the start line: whether /debug/pprof/cmdline is served redacted and
// whether /_shutdown requires a verified client certificate. They follow
// status_client_cert, and a start line without them is malformed.
func TestConfigCarriesAdminSurface(t *testing.T) {
	want := []string{"status_client_cert", "pprof_cmdline_redacted", "shutdown_requires_client_cert", "session_tickets"}
	joined := strings.Join(ConfigKeys, ",")
	if !strings.Contains(joined, strings.Join(want, ",")) {
		t.Fatalf("ConfigKeys = %v, want %v in that order", ConfigKeys, want)
	}
	old := `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T10:07:00Z","boot":1,"pid":1,"config":{"mode":"server","listen":"a","target":"b","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"session_tickets":false,"verify_on_resume":true,"acl":["allow-all"],"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`
	if _, err := DecodeLine([]byte(old)); err == nil {
		t.Fatal("a start line without the admin-surface fields must be malformed")
	}
	line := `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T10:07:00Z","boot":1,"pid":1,"config":{"mode":"server","listen":"a","target":"b","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":false,"verify_on_resume":true,"acl":["allow-all"],"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`
	rec, err := DecodeLine([]byte(line))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	cfg := rec.Body.(*Start).Config
	if !cfg.PprofCmdlineRedacted || !cfg.ShutdownRequiresClientCert {
		t.Fatalf("fields not decoded: %#v", cfg)
	}
}

// TestConfigCarriesProxyProtocol pins the start line's record of what the
// backend is handed ahead of each connection: the key is required, its
// set closed, and a line without it is malformed rather than a mode of
// off, since a proxy that does not say what it hands the backend cannot
// be compared with an expectation.
func TestConfigCarriesProxyProtocol(t *testing.T) {
	if !strings.Contains(strings.Join(ConfigKeys, ","), "target,proxy_protocol,status_listen") {
		t.Fatalf("ConfigKeys = %v, want proxy_protocol after target", ConfigKeys)
	}
	line := func(pp string) string {
		return `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T10:07:00Z","boot":1,"pid":1,"config":{"mode":"server","listen":"a","target":"b",` + pp + `"status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":false,"verify_on_resume":true,"acl":["allow-all"],"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`
	}
	if _, err := DecodeLine([]byte(line(``))); err == nil {
		t.Fatal("a start line without proxy_protocol must be malformed")
	}
	for _, bad := range []string{`"proxy_protocol":"",`, `"proxy_protocol":null,`, `"proxy_protocol":true,`, `"proxy_protocol":"TLS-FULL",`, `"proxy_protocol":"v2",`} {
		if _, err := DecodeLine([]byte(line(bad))); err == nil {
			t.Errorf("%s decoded; the set is closed", bad)
		}
	}
	for _, pp := range ProxyProtocols {
		rec, err := DecodeLine([]byte(line(`"proxy_protocol":"` + pp + `",`)))
		if err != nil {
			t.Fatalf("%s: %v", pp, err)
		}
		if got := rec.Body.(*Start).Config.ProxyProtocol; got != pp {
			t.Fatalf("%s decoded as %q", pp, got)
		}
	}
	// The emitter refuses what the reader would: a mode outside the set,
	// or none.
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	for _, pp := range []string{"", "v2", "TLS"} {
		rec := Record{Sequence: 1, At: at, Body: &Start{Boot: 1, PID: 1, Config: Config{
			Mode: "server", Listen: "a", Target: "b", ProxyProtocol: pp, ACL: []string{"allow-all"}, SandboxState: SandboxApplied, Material: []Material{}, Binary: testBinary,
		}}}
		if _, err := EncodeLine(rec); err == nil {
			t.Errorf("proxy_protocol %q encoded", pp)
		}
	}
}

// TestConfigCarriesSandboxState pins the start line's record of the process
// sandbox: sandbox_state is the closed outcome of the sandbox attempt and
// sandbox_accepted is null or the OS an operator named with
// --accept-no-sandbox. A line with a landlock key in their place, a state
// outside the enumeration or an empty acceptance is malformed.
func TestConfigCarriesSandboxState(t *testing.T) {
	want := []string{"lifetime_cap_seconds", "sandbox_state", "sandbox_accepted", "material"}
	joined := strings.Join(ConfigKeys, ",")
	if !strings.Contains(joined, strings.Join(want, ",")) {
		t.Fatalf("ConfigKeys = %v, want %v in that order", ConfigKeys, want)
	}
	for _, k := range ConfigKeys {
		if k == "landlock" {
			t.Fatal("landlock is no longer a start-line key")
		}
	}
	if !reflect.DeepEqual(SandboxStates, []string{"applied", "unsupported", "disabled", "failed", "skipped"}) {
		t.Fatalf("SandboxStates = %v", SandboxStates)
	}
	if SandboxApplied != "applied" || SandboxUnsupported != "unsupported" || SandboxDisabled != "disabled" || SandboxFailed != "failed" || SandboxSkipped != "skipped" {
		t.Fatal("the state constants must spell the enumeration")
	}

	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	start := func(state string, accepted *string) Record {
		return Record{Sequence: 1, At: at, Body: &Start{Boot: 1, PID: 1, Config: Config{
			Mode: "server", Listen: "a", Target: "b", ProxyProtocol: ProxyProtocolOff, ACL: []string{"allow-all"}, SandboxState: state, SandboxAccepted: accepted, Material: []Material{}, Binary: testBinary,
		}}}
	}
	windows := "windows"
	for _, state := range SandboxStates {
		line, err := EncodeLine(start(state, nil))
		if err != nil {
			t.Fatalf("%s: %v", state, err)
		}
		rec, err := DecodeLine(bytes.TrimSuffix(line, []byte("\n")))
		if err != nil {
			t.Fatalf("%s: decode: %v", state, err)
		}
		cfg := rec.Body.(*Start).Config
		if cfg.SandboxState != state || cfg.SandboxAccepted != nil {
			t.Fatalf("%s: round trip gave %#v", state, cfg)
		}
	}
	line, err := EncodeLine(start(SandboxUnsupported, &windows))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(line, []byte(`"lifetime_cap_seconds":0,"sandbox_state":"unsupported","sandbox_accepted":"windows","material":[]`)) {
		t.Fatalf("wire form: %s", line)
	}
	rec, err := DecodeLine(bytes.TrimSuffix(line, []byte("\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.Body.(*Start).Config.SandboxAccepted; got == nil || *got != "windows" {
		t.Fatalf("sandbox_accepted not decoded: %v", got)
	}

	empty, pem := "", "-----BEGIN CERTIFICATE-----"
	for name, rec := range map[string]Record{
		"empty state":       start("", nil),
		"state outside":     start("on", nil),
		"state upper case":  start("Applied", nil),
		"empty acceptance":  start(SandboxUnsupported, &empty),
		"pem in acceptance": start(SandboxUnsupported, &pem),
	} {
		if _, err := EncodeLine(rec); err == nil {
			t.Errorf("%s: encoded but must be rejected", name)
		}
	}
	prefix := `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T10:07:00Z","boot":1,"pid":1,"config":{"mode":"server","listen":"a","target":"b","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":false,"verify_on_resume":true,"acl":["allow-all"],"lifetime_cap_seconds":0,`
	for name, tail := range map[string]string{
		"landlock key":        `"landlock":false,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"landlock and state":  `"landlock":false,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"state missing":       `"sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"acceptance missing":  `"sandbox_state":"applied","material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"state outside":       `"sandbox_state":"on","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"state null":          `"sandbox_state":null,"sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"state boolean":       `"sandbox_state":true,"sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"acceptance empty":    `"sandbox_state":"unsupported","sandbox_accepted":"","material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"acceptance boolean":  `"sandbox_state":"unsupported","sandbox_accepted":true,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"acceptance with pem": `"sandbox_state":"unsupported","sandbox_accepted":"-----BEGIN X-----","material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
	} {
		if _, err := DecodeLine([]byte(prefix + tail)); err == nil {
			t.Errorf("%s: decoded but must be rejected", name)
		}
	}
	if _, err := DecodeLine([]byte(prefix + `"sandbox_state":"unsupported","sandbox_accepted":"windows","material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`)); err != nil {
		t.Fatalf("control line must decode: %v", err)
	}
}

// TestConfigCarriesACL pins the start line's record of the rule in force:
// config.acl follows verify_on_resume, is a non-empty array of strings from
// the closed vocabulary (bare tokens, or a prefix with a non-empty value;
// policy carries the policy file's hash), sorted and without duplicates. A
// start line without it, or with anything outside that, is malformed.
func TestConfigCarriesACL(t *testing.T) {
	want := []string{"verify_on_resume", "acl", "lifetime_cap_seconds"}
	joined := strings.Join(ConfigKeys, ",")
	if !strings.Contains(joined, strings.Join(want, ",")) {
		t.Fatalf("ConfigKeys = %v, want %v in that order", ConfigKeys, want)
	}
	if !reflect.DeepEqual(ACLTokens, []string{"allow-all", "verify-hostname", "disable-authentication"}) {
		t.Fatalf("ACLTokens = %v", ACLTokens)
	}
	if !reflect.DeepEqual(ACLPrefixes, []string{"allow-cn:", "allow-ou:", "allow-dns:", "allow-ip:", "allow-uri:", "allow-spki-pin:", "verify-cn:", "verify-ou:", "verify-dns:", "verify-ip:", "verify-uri:", "verify-spki-pin:", "policy:"}) {
		t.Fatalf("ACLPrefixes = %v", ACLPrefixes)
	}

	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	start := func(acl []string) Record {
		return Record{Sequence: 1, At: at, Body: &Start{Boot: 1, PID: 1, Config: Config{
			Mode: "server", Listen: "a", Target: "b", ProxyProtocol: ProxyProtocolOff, ACL: acl, SandboxState: SandboxApplied, Material: []Material{}, Binary: testBinary,
		}}}
	}
	hash := "c" + strings.Repeat("2", 63)
	good := [][]string{
		{"allow-all"},
		{"allow-cn:alice", "allow-cn:bob", "allow-ou:eng"},
		{"allow-dns:a.example", "allow-ip:10.0.0.1", "allow-uri:spiffe://example/*"},
		{"allow-spki-pin:sha256:" + hash},
		{"policy:" + hash},
		{"allow-cn:alice", "policy:" + hash},
		{"disable-authentication"},
		{"verify-hostname"},
		{"verify-cn:server", "verify-hostname"},
		{"verify-spki-pin:sha256:" + hash},
		{"disable-authentication", "verify-dns:s.example", "verify-hostname"},
	}
	for _, acl := range good {
		line, err := EncodeLine(start(acl))
		if err != nil {
			t.Fatalf("%v: %v", acl, err)
		}
		rec, err := DecodeLine(bytes.TrimSuffix(line, []byte("\n")))
		if err != nil {
			t.Fatalf("%v: decode: %v", acl, err)
		}
		if got := rec.Body.(*Start).Config.ACL; !reflect.DeepEqual(got, acl) {
			t.Fatalf("%v: round trip gave %v", acl, got)
		}
	}
	line, err := EncodeLine(start([]string{"allow-cn:alice"}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(line, []byte(`"verify_on_resume":false,"acl":["allow-cn:alice"],"lifetime_cap_seconds":0,`)) {
		t.Fatalf("wire form: %s", line)
	}

	bad := map[string][]string{
		"nil":                nil,
		"empty":              {},
		"unknown token":      {"allow-everyone"},
		"unknown prefix":     {"permit-cn:alice"},
		"token with value":   {"allow-all:yes"},
		"prefix no value":    {"allow-cn:"},
		"policy not a hash":  {"policy:/etc/policy.rego"},
		"unsorted":           {"allow-ou:eng", "allow-cn:alice"},
		"duplicate":          {"allow-cn:alice", "allow-cn:alice"},
		"pem":                {"allow-cn:-----BEGIN CERTIFICATE-----"},
		"empty string":       {""},
		"upper case":         {"Allow-All"},
		"hostname with name": {"verify-hostname:example"},
	}
	for name, acl := range bad {
		if _, err := EncodeLine(start(acl)); err == nil {
			t.Errorf("%s: encoded but must be rejected", name)
		}
	}
	prefix := `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T10:07:00Z","boot":1,"pid":1,"config":{"mode":"server","listen":"a","target":"b","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":false,"verify_on_resume":true,`
	suffix := `"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`
	for name, acl := range map[string]string{
		"missing":     ``,
		"null":        `"acl":null,`,
		"empty":       `"acl":[],`,
		"not strings": `"acl":[1],`,
		"unknown":     `"acl":["allow-everyone"],`,
		"unsorted":    `"acl":["allow-ou:eng","allow-cn:alice"],`,
		"duplicate":   `"acl":["allow-all","allow-all"],`,
	} {
		if _, err := DecodeLine([]byte(prefix + acl + suffix)); err == nil {
			t.Errorf("%s: decoded but must be rejected", name)
		}
	}
	rec, err := DecodeLine([]byte(prefix + `"acl":["allow-cn:alice","policy:` + hash + `"],` + suffix))
	if err != nil {
		t.Fatalf("control line must decode: %v", err)
	}
	if got := rec.Body.(*Start).Config.ACL; !reflect.DeepEqual(got, []string{"allow-cn:alice", "policy:" + hash}) {
		t.Fatalf("acl not decoded: %v", got)
	}
}

// TestTickLine pins the trace's own heartbeat: a tick line carries the
// header and nothing else, and is one of the kinds a reader classifies.
func TestTickLine(t *testing.T) {
	if !reflect.DeepEqual(Keys(KindTick), []string{"kind", "version", "sequence", "at"}) {
		t.Fatalf("Keys(tick) = %v", Keys(KindTick))
	}
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	line, err := EncodeLine(Record{Sequence: 7, At: at, Body: &Tick{}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"kind":"tick","version":1,"sequence":7,"at":"2026-09-24T10:07:00Z"}` + "\n"; string(line) != want {
		t.Fatalf("wire form %q, want %q", line, want)
	}
	if ClassifyLine(line) != KindTick {
		t.Fatal("a tick line must classify as tick")
	}
	rec, err := DecodeLine(bytes.TrimSuffix(line, []byte("\n")))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Sequence != 7 || rec.Body.Kind() != KindTick {
		t.Fatalf("decoded %#v", rec)
	}
	for name, bad := range map[string]string{
		"extra key":  `{"kind":"tick","version":1,"sequence":7,"at":"2026-09-24T10:07:00Z","conn":1}`,
		"missing at": `{"kind":"tick","version":1,"sequence":7}`,
		"version 2":  `{"kind":"tick","version":2,"sequence":7,"at":"2026-09-24T10:07:00Z"}`,
	} {
		if _, err := DecodeLine([]byte(bad)); err == nil {
			t.Errorf("%s: decoded but must be rejected", name)
		}
	}
}

// TestAcceptErrorLine pins the record of a failed Accept: the error text
// (never empty, never a secret) and the backoff the loop sleeps before the
// next attempt, in milliseconds.
func TestAcceptErrorLine(t *testing.T) {
	if !reflect.DeepEqual(Keys(KindAcceptError), []string{"kind", "version", "sequence", "at", "error", "backoff_ms"}) {
		t.Fatalf("Keys(accept-error) = %v", Keys(KindAcceptError))
	}
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	line, err := EncodeLine(Record{Sequence: 9, At: at, Body: &AcceptError{Error: "accept tcp 127.0.0.1:8443: too many open files", BackoffMS: 5}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"kind":"accept-error","version":1,"sequence":9,"at":"2026-09-24T10:07:00Z","error":"accept tcp 127.0.0.1:8443: too many open files","backoff_ms":5}` + "\n"; string(line) != want {
		t.Fatalf("wire form %q, want %q", line, want)
	}
	if ClassifyLine(line) != KindAcceptError {
		t.Fatal("an accept-error line must classify as accept-error, not accept")
	}
	if ClassifyLine([]byte(`{"kind":"accept","version":1,`)) != KindAccept {
		t.Fatal("an accept line still classifies as accept")
	}
	rec, err := DecodeLine(bytes.TrimSuffix(line, []byte("\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.Body.(*AcceptError); got.Error != "accept tcp 127.0.0.1:8443: too many open files" || got.BackoffMS != 5 {
		t.Fatalf("decoded %#v", got)
	}
	for name, body := range map[string]Body{
		"empty error":      &AcceptError{Error: "", BackoffMS: 5},
		"negative backoff": &AcceptError{Error: "x", BackoffMS: -1},
		"pem in error":     &AcceptError{Error: "-----BEGIN RSA PRIVATE KEY-----", BackoffMS: 5},
	} {
		if _, err := EncodeLine(Record{Sequence: 1, At: at, Body: body}); err == nil {
			t.Errorf("%s: encoded but must be rejected", name)
		}
	}
	for name, bad := range map[string]string{
		"missing backoff": `{"kind":"accept-error","version":1,"sequence":9,"at":"2026-09-24T10:07:00Z","error":"x"}`,
		"backoff string":  `{"kind":"accept-error","version":1,"sequence":9,"at":"2026-09-24T10:07:00Z","error":"x","backoff_ms":"5"}`,
		"error null":      `{"kind":"accept-error","version":1,"sequence":9,"at":"2026-09-24T10:07:00Z","error":null,"backoff_ms":5}`,
	} {
		if _, err := DecodeLine([]byte(bad)); err == nil {
			t.Errorf("%s: decoded but must be rejected", name)
		}
	}
}

// TestRefusalLine: the refusal kind, written once when the status
// listener's Serve returns an error: its keys, wire form, classification,
// and what the emitter and the reader refuse.
func TestRefusalLine(t *testing.T) {
	if !reflect.DeepEqual(Keys(KindRefusal), []string{"kind", "version", "sequence", "at", "source", "error"}) {
		t.Fatalf("Keys(refusal) = %v", Keys(KindRefusal))
	}
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	line, err := EncodeLine(Record{Sequence: 9, At: at, Body: &Refusal{Source: "status-listener", Error: "accept tcp 127.0.0.1:6060: use of closed network connection"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"kind":"refusal","version":1,"sequence":9,"at":"2026-09-24T10:07:00Z","source":"status-listener","error":"accept tcp 127.0.0.1:6060: use of closed network connection"}` + "\n"; string(line) != want {
		t.Fatalf("wire form %q, want %q", line, want)
	}
	if ClassifyLine(line) != KindRefusal {
		t.Fatal("a refusal line must classify as refusal")
	}
	rec, err := DecodeLine(bytes.TrimSuffix(line, []byte("\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.Body.(*Refusal); got.Source != "status-listener" || got.Error != "accept tcp 127.0.0.1:6060: use of closed network connection" {
		t.Fatalf("decoded %#v", got)
	}
	for name, body := range map[string]Body{
		"empty error":    &Refusal{Source: "status-listener", Error: ""},
		"unknown source": &Refusal{Source: "emitter", Error: "x"},
		"empty source":   &Refusal{Source: "", Error: "x"},
		"pem in error":   &Refusal{Source: "status-listener", Error: "-----BEGIN RSA PRIVATE KEY-----"},
	} {
		if _, err := EncodeLine(Record{Sequence: 1, At: at, Body: body}); err == nil {
			t.Errorf("%s: encoded but must be rejected", name)
		}
	}
	for name, bad := range map[string]string{
		"missing error":        `{"kind":"refusal","version":1,"sequence":9,"at":"2026-09-24T10:07:00Z","source":"status-listener"}`,
		"source outside set":   `{"kind":"refusal","version":1,"sequence":9,"at":"2026-09-24T10:07:00Z","source":"emitter","error":"x"}`,
		"error null":           `{"kind":"refusal","version":1,"sequence":9,"at":"2026-09-24T10:07:00Z","source":"status-listener","error":null}`,
		"error empty":          `{"kind":"refusal","version":1,"sequence":9,"at":"2026-09-24T10:07:00Z","source":"status-listener","error":""}`,
		"with a backoff key":   `{"kind":"refusal","version":1,"sequence":9,"at":"2026-09-24T10:07:00Z","source":"status-listener","error":"x","backoff_ms":5}`,
		"reload body under it": `{"kind":"refusal","version":1,"sequence":9,"at":"2026-09-24T10:07:00Z","outcome":"failed","error":"x","serving":false,"material":[]}`,
	} {
		if _, err := DecodeLine([]byte(bad)); err == nil {
			t.Errorf("%s: decoded but must be rejected", name)
		}
	}
}

// TestConfigCarriesBinary: config.binary is required, after material, and
// holds exactly a non-empty path and a lower-case SHA-256 hex string. A
// start line without it is malformed, as one without proxy_protocol is.
func TestConfigCarriesBinary(t *testing.T) {
	if ConfigKeys[len(ConfigKeys)-1] != "binary" || strings.Join(BinaryKeys, ",") != "path,sha256" {
		t.Fatalf("ConfigKeys = %v, BinaryKeys = %v", ConfigKeys, BinaryKeys)
	}
	hash := strings.Repeat("b", 64)
	line := func(binary string) string {
		return `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T10:07:00Z","boot":1,"pid":1,"config":{"mode":"server","listen":"a","target":"b","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":false,"verify_on_resume":true,"acl":["allow-all"],"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"material":[]` + binary + `}}`
	}
	rec, err := DecodeLine([]byte(line(`,"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"` + hash + `"}`)))
	if err != nil {
		t.Fatalf("control line: %v", err)
	}
	if got := rec.Body.(*Start).Config.Binary; got != (Binary{Path: "/usr/local/bin/ghostunnel", SHA256: hash}) {
		t.Fatalf("binary = %+v", got)
	}
	for name, binary := range map[string]string{
		"missing":       ``,
		"null":          `,"binary":null`,
		"string":        `,"binary":"/usr/local/bin/ghostunnel"`,
		"no path":       `,"binary":{"sha256":"` + hash + `"}`,
		"no hash":       `,"binary":{"path":"/usr/local/bin/ghostunnel"}`,
		"extra key":     `,"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"` + hash + `","size":1}`,
		"empty path":    `,"binary":{"path":"","sha256":"` + hash + `"}`,
		"null path":     `,"binary":{"path":null,"sha256":"` + hash + `"}`,
		"null hash":     `,"binary":{"path":"/usr/local/bin/ghostunnel","sha256":null}`,
		"short hash":    `,"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"` + hash[:63] + `"}`,
		"upper hash":    `,"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"` + strings.ToUpper(hash) + `"}`,
		"pem in path":   `,"binary":{"path":"-----BEGIN CERTIFICATE-----","sha256":"` + hash + `"}`,
		"duplicate key": `,"binary":{"path":"/a","path":"/b","sha256":"` + hash + `"}`,
	} {
		if _, err := DecodeLine([]byte(line(binary))); err == nil {
			t.Errorf("%s: decoded but must be rejected", name)
		}
	}
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	for name, b := range map[string]Binary{
		"zero":        {},
		"empty path":  {SHA256: hash},
		"no hash":     {Path: "/usr/local/bin/ghostunnel"},
		"upper hash":  {Path: "/usr/local/bin/ghostunnel", SHA256: strings.ToUpper(hash)},
		"pem in path": {Path: "-----BEGIN CERTIFICATE-----", SHA256: hash},
	} {
		rec := Record{Sequence: 1, At: at, Body: &Start{Boot: 1, PID: 1, Config: Config{
			Mode: "server", Listen: "a", Target: "b", ProxyProtocol: ProxyProtocolOff, ACL: []string{"allow-all"}, SandboxState: SandboxApplied, Material: []Material{}, Binary: b,
		}}}
		if _, err := EncodeLine(rec); err == nil {
			t.Errorf("%s: encoded but must be refused", name)
		}
	}
}
