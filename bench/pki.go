package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// pki is a throwaway CA with a server and a client leaf, written as PEM.
type pki struct {
	dir                     string
	caPEM                   string
	serverPEM, serverKeyPEM string
	clientPEM, clientKeyPEM string
	caPool                  *x509.CertPool
	clientCert              tls.Certificate
	serverCert              tls.Certificate
	caCert                  *x509.Certificate
	caKey                   *ecdsa.PrivateKey
	serialSource            int64
}

func generatePKI(dir string) (*pki, error) {
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	p := &pki{dir: dir, serialSource: time.Now().UnixNano()}
	notBefore := time.Now().Add(-time.Hour)
	notAfter := notBefore.Add(48 * time.Hour)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          p.serial(),
		Subject:               pkix.Name{CommonName: "bench throwaway CA", Organization: []string{"bench"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	p.caCert, err = x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	p.caKey = caKey
	p.caPool = x509.NewCertPool()
	p.caPool.AddCert(p.caCert)
	p.caPEM = filepath.Join(dir, "ca.pem")
	if err := writePEM(p.caPEM, "CERTIFICATE", caDER); err != nil {
		return nil, err
	}

	serverTmpl := &x509.Certificate{
		SerialNumber: p.serial(),
		Subject:      pkix.Name{CommonName: "localhost", Organization: []string{"bench"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	p.serverPEM, p.serverKeyPEM = filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem")
	p.serverCert, err = p.issue(serverTmpl, p.serverPEM, p.serverKeyPEM)
	if err != nil {
		return nil, err
	}

	clientTmpl := &x509.Certificate{
		SerialNumber: p.serial(),
		Subject:      pkix.Name{CommonName: "bench-client", Organization: []string{"bench"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"bench-client"},
	}
	p.clientPEM, p.clientKeyPEM = filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	p.clientCert, err = p.issue(clientTmpl, p.clientPEM, p.clientKeyPEM)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *pki) serial() *big.Int {
	p.serialSource++
	return big.NewInt(p.serialSource)
}

func (p *pki) issue(tmpl *x509.Certificate, certPath, keyPath string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := writePEM(certPath, "CERTIFICATE", der); err != nil {
		return tls.Certificate{}, err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER); err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func writePEM(path, typ string, der []byte) error {
	data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if data == nil {
		return fmt.Errorf("encoding %s", path)
	}
	return os.WriteFile(path, data, 0o600)
}
