// Command substancepki generates the test PKI under observers/testdata/pki
// that the substance fixtures (observers/testdata/FIXTURES.md, the
// substance- rows) and the members' unit tests draw on: a CA, an
// intermediate it signed, a rogue CA nothing signed, the leaves, the chain
// files as the proxy writes them under gt/chains/, an OPA policy, and
// hashes.txt with every hash the fixtures and tests quote; and it writes
// the substance- fixtures from that PKI (fixtures.go).
//
// It is run by hand and its output is committed; the committed bytes are
// the oracle, not this program. The two modes:
//
//	go run ./observers/testdata/tools/substancepki -gen-pki [-out observers/testdata/pki]
//
// generates a new PKI. Keys are generated fresh on every run and never
// written, so this produces a PKI whose hashes must be pasted anew
// wherever hashes.txt is quoted (gtreader_test.go in the four members),
// and the fixtures regenerated after it.
//
//	go run ./observers/testdata/tools/substancepki -gen-fixtures [-out observers/testdata/pki] [-fixtures observers/testdata/fixtures] [-base trace-fresh-complete]
//
// writes the substance- fixtures from the committed PKI, on the stores and
// traces of the base fixture, and their rows in index.json. It reads no
// key and generates nothing random: the same tree gives the same bytes.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	validFrom  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	validUntil = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
)

type entity struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func main() {
	out := flag.String("out", "observers/testdata/pki", "the PKI directory")
	genPKIFlag := flag.Bool("gen-pki", false, "generate a new PKI under -out (new keys: every quoted hash moves)")
	genFixturesFlag := flag.Bool("gen-fixtures", false, "write the substance- fixtures from the PKI under -out")
	fixtures := flag.String("fixtures", "observers/testdata/fixtures", "the fixture set")
	base := flag.String("base", "trace-fresh-complete", "the fixture whose stores and traces the substance fixtures run on")
	flag.Parse()
	if !*genPKIFlag && !*genFixturesFlag {
		fmt.Fprintln(os.Stderr, "substancepki: nothing to do; pass -gen-pki and/or -gen-fixtures")
		flag.Usage()
		os.Exit(2)
	}
	if *genPKIFlag {
		genPKI(*out)
	}
	if *genFixturesFlag {
		genFixtures(*out, *fixtures, *base)
	}
}

// genPKI writes a fresh PKI under out.
func genPKI(out string) {
	if err := os.MkdirAll(filepath.Join(out, "chains"), 0o755); err != nil {
		log.Fatal(err)
	}
	var serial int64 = 0x1000
	next := func() *big.Int { serial++; return big.NewInt(serial) }

	ca := issue(next(), &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Substance Test CA", Organization: []string{"ghostunnel observers"}},
		NotBefore:             validFrom,
		NotAfter:              validUntil,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil)
	intermediate := issue(next(), &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Substance Test Intermediate", Organization: []string{"ghostunnel observers"}},
		NotBefore:             validFrom,
		NotAfter:              validUntil,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, ca)
	rogue := issue(next(), &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Substance Rogue CA", Organization: []string{"nobody"}},
		NotBefore:             validFrom,
		NotAfter:              validUntil,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil)

	clientURI, _ := url.Parse("spiffe://example.org/ns/prod/sa/client")
	otherURI, _ := url.Parse("spiffe://example.org/ns/dev/sa/other")
	leaf := func(cn string, ous []string, dns []string, ips []net.IP, uris []*url.URL, from, until time.Time, issuer *entity) *entity {
		return issue(next(), &x509.Certificate{
			Subject:     pkix.Name{CommonName: cn, OrganizationalUnit: ous, Organization: []string{"ghostunnel observers"}},
			NotBefore:   from,
			NotAfter:    until,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			DNSNames:    dns,
			IPAddresses: ips,
			URIs:        uris,
		}, issuer)
	}
	client := leaf("client.example", []string{"ops"}, []string{"client.example", "client.internal"}, []net.IP{net.ParseIP("10.0.0.7")}, []*url.URL{clientURI}, validFrom, validUntil, intermediate)
	other := leaf("other.example", []string{"guests"}, []string{"other.example"}, []net.IP{net.ParseIP("192.0.2.9")}, []*url.URL{otherURI}, validFrom, validUntil, ca)
	rogueLeaf := leaf("client.example", []string{"ops"}, []string{"client.example"}, nil, []*url.URL{clientURI}, validFrom, validUntil, rogue)
	expired := leaf("client.example", []string{"ops"}, []string{"client.example"}, nil, nil, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC), ca)

	writePEM(out, "ca.pem", ca)
	writePEM(out, "intermediate.pem", intermediate)
	writePEM(out, "rogue-ca.pem", rogue)
	writePEM(out, "leaf-client.pem", client)
	writePEM(out, "leaf-other.pem", other)
	writePEM(out, "leaf-rogue.pem", rogueLeaf)
	writePEM(out, "leaf-expired.pem", expired)

	policy := "package policy\n\ndefault allow = false\n\nallow {\n\tinput.certificate.Subject.CommonName == \"client.example\"\n}\n\nallow {\n\tinput.certificate.Subject.OrganizationalUnit[_] == \"policy-ou\"\n}\n"
	must(os.WriteFile(filepath.Join(out, "policy.rego"), []byte(policy), 0o644))

	var hashes strings.Builder
	hashes.WriteString("# Hashes of the committed bytes, for quoting in fixtures and tests.\n")
	fmt.Fprintf(&hashes, "ca.pem sha256 %s\n", fileHash(out, "ca.pem"))
	fmt.Fprintf(&hashes, "policy.rego sha256 %s\n", fileHash(out, "policy.rego"))
	chain := func(name string, certs ...*entity) {
		var content []byte
		for _, c := range certs {
			content = append(content, c.der...)
		}
		sum := sha256.Sum256(content)
		h := hex.EncodeToString(sum[:])
		must(os.WriteFile(filepath.Join(out, "chains", h+".der"), content, 0o644))
		fmt.Fprintf(&hashes, "chain %s %s\n", name, h)
	}
	chain("client (leaf-client + intermediate)", client, intermediate)
	chain("other (leaf-other)", other)
	chain("rogue (leaf-rogue + rogue-ca)", rogueLeaf, rogue)
	chain("expired (leaf-expired)", expired)
	for _, e := range []struct {
		name string
		ent  *entity
	}{{"leaf-client", client}, {"leaf-other", other}, {"leaf-rogue", rogueLeaf}, {"leaf-expired", expired}} {
		sum := sha256.Sum256(e.ent.cert.RawSubjectPublicKeyInfo)
		fmt.Fprintf(&hashes, "spki %s sha256 %s\n", e.name, hex.EncodeToString(sum[:]))
	}
	must(os.WriteFile(filepath.Join(out, "hashes.txt"), []byte(hashes.String()), 0o644))
	fmt.Print(hashes.String())
}

func issue(serial *big.Int, tmpl *x509.Certificate, issuer *entity) *entity {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl.SerialNumber = serial
	parent, signer := tmpl, key
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	return &entity{cert: cert, key: key, der: der}
}

func writePEM(dir, name string, e *entity) {
	must(os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.der}), 0o644))
}

func fileHash(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		log.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
