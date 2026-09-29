package ringtrace

import (
	"regexp"
	"strings"
	"testing"
)

// reHashOracle is the pattern isHash is held to.
var reHashOracle = regexp.MustCompile(`^[0-9a-f]{64}$`)

func hashCases() []string {
	h := strings.Repeat("0123456789abcdef", 4)
	cases := []string{
		"", h, h[:63], h + "0", h + "\n", "\n" + h, h[:63] + "\n",
		strings.ToUpper(h), h[:63] + "A", h[:63] + "g", h[:63] + "/", h[:63] + ":",
		h[:63] + "`", h[:63] + "@", h[:63] + " ", h[:63] + "\x00", "0" + h[:62] + "\xff",
		strings.Repeat("f", 64), strings.Repeat("0", 64), strings.Repeat("a", 32) + "é" + strings.Repeat("a", 30),
		strings.Repeat("a", 62) + "é", strings.Repeat("a", 128),
	}
	for i := 0; i < 64; i++ {
		for _, c := range []byte{'/', ':', '@', '`', 'g', 'A', 'F', 0x80} {
			b := []byte(h)
			b[i] = c
			cases = append(cases, string(b))
		}
	}
	return cases
}

func TestIsHashMatchesTheRegexp(t *testing.T) {
	for _, s := range hashCases() {
		if got, want := isHash(s), reHashOracle.MatchString(s); got != want {
			t.Fatalf("isHash(%q) = %v, the regexp says %v", s, got, want)
		}
	}
}

func FuzzIsHashMatchesTheRegexp(f *testing.F) {
	for _, s := range hashCases() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := isHash(s), reHashOracle.MatchString(s); got != want {
			t.Fatalf("isHash(%q) = %v, the regexp says %v", s, got, want)
		}
	})
}

// A line that fails on several fields at once is refused naming the first
// in the fixed order the validator checks them, every time.
func TestValidatorsNameTheFirstFailingField(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----"
	hash := strings.Repeat("ab", 32)
	start := &Start{Boot: 1, PID: 1, Config: testConfig()}
	start.Config.Listen, start.Config.Target = "", ""
	cases := []struct {
		body Body
		want string
	}{
		{&Accept{Conn: 1}, "listener: empty"},
		{&Accept{Conn: 1, Listener: pem, Remote: pem}, "listener: contains a PEM block"},
		{start, "config.listen: empty"},
		{&Handshake{Conn: 1, Outcome: "ok", Protocol: "TLS1.3", Peer: &Peer{Subject: pem, Issuer: pem, Serial: pem, SANs: []string{}, Fingerprint: hash}}, "peer.subject: contains a PEM block"},
		{&Handshake{Conn: 1, Outcome: "ok", Protocol: "TLS1.3", Peer: &Peer{Subject: "s", Issuer: pem, Serial: pem, SANs: []string{}, Fingerprint: hash}}, "peer.issuer: contains a PEM block"},
		{&Handshake{Conn: 1, Outcome: "ok", Protocol: "TLS1.3", Peer: &Peer{Subject: "s", Issuer: "i", Serial: "1", SANs: []string{"a", pem, pem}, Fingerprint: hash}}, "peer.sans[1]: contains a PEM block"},
		{&Handshake{Conn: 1, Outcome: "ok", Protocol: "TLS1.3", Peer: &Peer{Subject: "s", Issuer: "i", Serial: "1", SANs: []string{"a"}, Fingerprint: strings.ToUpper(hash)}}, "peer.fingerprint: not a lower-case SHA-256 hex string"},
		{&ACL{Conn: 1, Decision: "allow", Rule: pem, Reason: pem}, "rule: contains a PEM block"},
	}
	for _, c := range cases {
		for i := 0; i < 200; i++ {
			err := c.body.validate()
			if err == nil || err.Error() != c.want {
				t.Fatalf("%s: got %v, want %q", c.body.Kind(), err, c.want)
			}
		}
	}
}
