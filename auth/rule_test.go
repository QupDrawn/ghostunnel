package auth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/ghostunnel/ghostunnel/wildcard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServerRuleIsTheVerifiersRule holds ServerRule to decideServer: for
// every shape of ACL and every leaf the verifier allows, the rule the
// verifier stopped at is the rule ServerRule names from the presented leaf
// alone, as a chain of one, with no verified chain and no cache; and
// where the verifier refuses, ServerRule on that leaf names "none" or a
// rule the verifier did not reach only through the policy, which it does
// not evaluate. The ring records a served connection from the leaf this
// way (ring.go, Handshake), so this is the proof that the record is the
// verifier's decision whatever a reload did to the cache in between.
func TestServerRuleIsTheVerifiersRule(t *testing.T) {
	now := time.Now()
	root := newIssuer(t, "root", nil, now.Add(-time.Hour), now.Add(time.Hour))
	gopher := newLeaf(t, "gopher", root, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	nobody := newLeaf(t, "nobody", root, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	pin := spkiPin(t, gopher.Raw, crypto.SHA256)
	uri, err := url.Parse("spiffe://example/gopher")
	require.NoError(t, err)
	// A leaf with every kind of SAN, so each --allow-* list can be the
	// first to match.
	sans := newLeafSANs(t, root, now, []string{"gopher.example"}, []net.IP{net.IPv4(10, 0, 0, 7)}, []*url.URL{uri}, []string{"eng"})
	matcher, err := wildcard.CompileWithSeparator("spiffe://example/*", '/')
	require.NoError(t, err)
	opa := policy.WrapForTest(prepareQuery(t, allowGopherPolicy))

	acls := []struct {
		name string
		acl  ACL
	}{
		{"allow-all", ACL{AllowAll: true}},
		{"allow-cn", ACL{AllowedCNs: []string{"gopher"}}},
		{"allow-ou", ACL{AllowedOUs: []string{"eng"}}},
		{"allow-dns", ACL{AllowedDNSs: []string{"gopher.example"}}},
		{"allow-ip", ACL{AllowedIPs: []net.IP{net.IPv4(10, 0, 0, 7)}}},
		{"allow-uri", ACL{AllowedURIs: []wildcard.Matcher{matcher}}},
		{"cn before ou", ACL{AllowedCNs: []string{"gopher"}, AllowedOUs: []string{"eng"}}},
		{"ou before dns", ACL{AllowedOUs: []string{"eng"}, AllowedDNSs: []string{"gopher.example"}}},
		{"policy", ACL{AllowOPAQuery: opa, OPAQueryTimeout: 10 * time.Second}},
		{"cn before policy", ACL{AllowedCNs: []string{"gopher"}, AllowOPAQuery: opa, OPAQueryTimeout: 10 * time.Second}},
		{"pin", ACL{AllowedPins: []SPKIPin{pin}}},
		{"nobody allowed", ACL{AllowedCNs: []string{"someone"}}},
		{"empty", ACL{}},
	}
	allowed := 0
	for _, tc := range acls {
		for _, leaf := range []*x509.Certificate{gopher, nobody, sans} {
			raw := rawOf(leaf, root.cert)
			chain := [][]*x509.Certificate{{leaf, root.cert}}
			rule, err, _ := tc.acl.decideServer(raw, chain)
			named := tc.acl.ServerRule(raw, [][]*x509.Certificate{{leaf}})
			if err == nil {
				allowed++
				assert.NotEmpty(t, rule, "%s/%s: an allow names its rule", tc.name, leaf.Subject.CommonName)
				assert.Equal(t, rule, named, "%s/%s: ServerRule on the presented leaf is the verifier's rule", tc.name, leaf.Subject.CommonName)
				continue
			}
			assert.Empty(t, rule, "%s/%s: a refusal names no rule", tc.name, leaf.Subject.CommonName)
			switch {
			case tc.acl.PinningEnabled():
				assert.Equal(t, "allow-spki-pin", named, "%s/%s: the pin is not checked again", tc.name, leaf.Subject.CommonName)
			case tc.acl.AllowOPAQuery != nil:
				assert.Equal(t, "policy", named, "%s/%s: the policy is not evaluated again", tc.name, leaf.Subject.CommonName)
			default:
				assert.Equal(t, "none", named, "%s/%s: nothing names a refused leaf", tc.name, leaf.Subject.CommonName)
			}
		}
	}
	require.Greater(t, allowed, 8, "the matrix exercises every allow")
}

func TestClientRuleNamesTheDecidingFlag(t *testing.T) {
	assert.Equal(t, "hostname", ACL{}.ClientRule(nil, fakeChains))
	assert.Equal(t, "verify-cn", ACL{AllowedCNs: []string{"gopher"}}.ClientRule(nil, fakeChains))
	assert.Equal(t, "verify-dns", ACL{AllowedDNSs: []string{"circle"}}.ClientRule(nil, fakeChains))
	assert.Equal(t, "none", ACL{AllowedCNs: []string{"other"}}.ClientRule(nil, fakeChains))
	assert.Equal(t, "none", ACL{}.ClientRule(nil, [][]*x509.Certificate{}))
	assert.Equal(t, "verify-spki-pin", ACL{AllowedPins: []SPKIPin{{}}}.ClientRule(nil, nil))
}

// TestSPKIPinString: a pin describes itself as <algo>:<hex-digest>, the
// non-secret form the ring's start line records.
func TestSPKIPinString(t *testing.T) {
	pins, err := ParseSPKIPins([]string{"sha256:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32)), "SHA384:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 48))})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sha256:" + strings.Repeat("ab", 32), "sha384:" + strings.Repeat("01", 48)}
	for i, pin := range pins {
		if got := pin.String(); got != want[i] {
			t.Errorf("pin %d: String() = %q, want %q", i, got, want[i])
		}
	}
}

// newLeafSANs issues a leaf with the given SANs and organizational units
// from parent, valid around now, for client authentication.
func newLeafSANs(t testing.TB, parent *issuer, now time.Time, dns []string, ips []net.IP, uris []*url.URL, ous []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial++
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "sans", OrganizationalUnit: ous},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent.cert, &key.PublicKey, parent.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
