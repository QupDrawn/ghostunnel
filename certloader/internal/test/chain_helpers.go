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

package spiffetest

import (
	"crypto"
	"crypto/x509"
	"time"
)

// CreateX509Certificate issues a leaf from the CA and returns it with the CA's
// chain, without the root.
func (ca *CA) CreateX509Certificate(options ...CertificateOption) ([]*x509.Certificate, crypto.Signer) {
	cert, key := CreateX509Certificate(ca.tb, ca.cert, ca.key, options...)
	return append([]*x509.Certificate{cert}, ca.chain(false)...), key
}

// WithLifetime sets a certificate's validity window.
func WithLifetime(notBefore, notAfter time.Time) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.NotBefore = notBefore
		c.NotAfter = notAfter
	})
}
