/*-
 * Copyright 2018 Square Inc.
 * SPDX-License-Identifier: Apache-2.0
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

package certloader

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync/atomic"
)

type keystoreCertificate struct {
	baseCertificate
	// loaded is the files of the last successful load, stored with the
	// certificate and trust store parsed from them.
	loaded atomic.Pointer[LoadedFiles]
	// Keystore or PEM files path
	keystorePaths []string
	// Password for keystore (may be empty)
	keystorePassword string
	// Root CA bundle path
	caBundlePath string
	// File format indicator (e.g. "PEM", "PKCS12", "JCEKS", "DER", or "" for auto-detect)
	format string
}

// CertificateFromPEMFiles creates a reloadable certificate from a set of PEM files.
func CertificateFromPEMFiles(certificatePath, keyPath, caBundlePath string) (Certificate, error) {
	c := keystoreCertificate{
		keystorePaths: []string{certificatePath, keyPath},
		caBundlePath:  caBundlePath,
		format:        "PEM",
	}
	err := c.Reload()
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// CertificateFromKeystore creates a reloadable certificate from a PKCS#12 keystore.
func CertificateFromKeystore(keystorePath, keystorePassword, caBundlePath string) (Certificate, error) {
	c := keystoreCertificate{
		keystorePaths:    []string{keystorePath},
		keystorePassword: keystorePassword,
		caBundlePath:     caBundlePath,
		format:           "",
	}
	err := c.Reload()
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Reload transparently reloads the certificate.
func (c *keystoreCertificate) Reload() error {
	var pemBlocks []*pem.Block
	loaded := &LoadedFiles{CABundlePath: c.caBundlePath}
	for i, path := range c.keystorePaths {
		blocks, data, err := readCertificateFile(path, c.keystorePassword, c.format)
		if err != nil {
			return fmt.Errorf("reading certificate file %q: %w", path, err)
		}
		pemBlocks = append(pemBlocks, blocks...)
		// The first of the PEM files is the certificate; a keystore holds
		// the key as well and is not kept.
		if i == 0 && c.format == "PEM" {
			loaded.CertificatePath, loaded.Certificate = path, data
		}
	}

	var pemBytes []byte
	for _, block := range pemBlocks {
		pemBytes = append(pemBytes, pem.EncodeToMemory(block)...)
	}

	certAndKey, err := tls.X509KeyPair(pemBytes, pemBytes)
	if err != nil {
		return fmt.Errorf("parsing X509 key pair: %w", err)
	}

	certAndKey.Leaf, err = x509.ParseCertificate(certAndKey.Certificate[0])
	if err != nil {
		return fmt.Errorf("parsing leaf certificate: %w", err)
	}

	bundle, caBytes, err := loadTrustStore(c.caBundlePath)
	if err != nil {
		return fmt.Errorf("loading trust store: %w", err)
	}
	loaded.CABundle = caBytes

	c.cachedCertificate.Store(&certAndKey)
	c.cachedCertPool.Store(bundle)
	c.loaded.Store(loaded)

	return nil
}

func (c *keystoreCertificate) loadedFiles() *LoadedFiles {
	return c.loaded.Load()
}
