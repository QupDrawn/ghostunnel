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

package certloader

import (
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadedFilesArePEMFilesAsRead: the certificate source hands back the
// certificate file and the CA bundle as its last successful load read and
// parsed them: unchanged by a rewrite on disk until a reload, replaced by
// a reload that succeeds, kept by one that fails.
func TestLoadedFilesArePEMFilesAsRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "combined.pem")
	first := []byte(testCombinedCertificateAndKey)
	require.NoError(t, os.WriteFile(path, first, 0o600))

	cert, err := CertificateFromPEMFiles(path, path, path)
	require.NoError(t, err)
	source := TLSConfigSourceFromCertificate(cert, log.New(os.Stderr, "", 0))
	files, ok := LoadedFilesOf(source)
	require.True(t, ok, "PEM files are loaded by this package")
	assert.Equal(t, &LoadedFiles{CertificatePath: path, Certificate: first, CABundlePath: path, CABundle: first}, files)

	// The bytes kept are the bytes parsed: the leaf served is in them.
	block, _ := pem.Decode(files.Certificate)
	require.NotNil(t, block)
	served, err := cert.GetCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, served.Leaf.Raw, block.Bytes)

	second := append(append([]byte{}, first...), '\n')
	require.NoError(t, os.WriteFile(path, second, 0o600))
	files, _ = LoadedFilesOf(source)
	assert.Equal(t, first, files.Certificate, "a rewrite on disk is not a load")
	require.NoError(t, source.Reload())
	files, _ = LoadedFilesOf(source)
	assert.Equal(t, second, files.Certificate, "a reload replaces the files")
	assert.Equal(t, second, files.CABundle)

	require.NoError(t, os.WriteFile(path, []byte("not a certificate"), 0o600))
	require.Error(t, source.Reload())
	files, _ = LoadedFilesOf(source)
	assert.Equal(t, second, files.Certificate, "a failed reload keeps the files in use")
	assert.Equal(t, second, files.CABundle)
}

// TestLoadedFilesOfOtherSources: a CA bundle alone, the system trust store
// and an ACME source hand back what they read; a source that is not loaded
// from files by this package does not.
func TestLoadedFilesOfOtherSources(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	bundle := []byte(testCertificate)
	require.NoError(t, os.WriteFile(ca, bundle, 0o644))
	logger := log.New(os.Stderr, "", 0)

	onlyCA, err := NoCertificate(ca)
	require.NoError(t, err)
	files, ok := LoadedFilesOf(TLSConfigSourceFromCertificate(onlyCA, logger))
	require.True(t, ok)
	assert.Equal(t, &LoadedFiles{CABundlePath: ca, CABundle: bundle}, files)

	system, err := NoCertificate("")
	require.NoError(t, err)
	files, ok = LoadedFilesOf(TLSConfigSourceFromCertificate(system, logger))
	require.True(t, ok)
	assert.Equal(t, &LoadedFiles{}, files, "the system trust store has no file")

	acme, err := newACMETLSConfigSource(certmagic.NewDefault(), &ACMEConfig{CABundlePath: ca})
	require.NoError(t, err)
	files, ok = LoadedFilesOf(acme)
	require.True(t, ok)
	assert.Equal(t, &LoadedFiles{CABundlePath: ca, CABundle: bundle}, files, "ACME's certificate has no file; its CA bundle does")
	rotated := append(append([]byte{}, bundle...), '\n')
	require.NoError(t, os.WriteFile(ca, rotated, 0o644))
	require.NoError(t, acme.Reload())
	files, _ = LoadedFilesOf(acme)
	assert.Equal(t, rotated, files.CABundle)

	_, ok = LoadedFilesOf(TLSConfigSourceFromCertificate(&baseOnly{}, logger))
	assert.False(t, ok, "a certificate that keeps no files hands none back")
	_, ok = LoadedFilesOf(nil)
	assert.False(t, ok)
}

// baseOnly is a Certificate that keeps no files, as the PKCS#11 and
// keychain certificates do not.
type baseOnly struct {
	baseCertificate
}

func (*baseOnly) Reload() error { return nil }

// TestReadCertificateFileRefusesMoreThanTheParsersRead: a file larger than
// the parsers take is refused, so the bytes returned are always the whole
// file and exactly the bytes parsed.
func TestReadCertificateFileRefusesMoreThanTheParsersRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.pem")
	data := append([]byte(testCombinedCertificateAndKey), make([]byte, maxReadSize)...)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	_, _, err := readCertificateFile(path, "", "PEM")
	assert.ErrorContains(t, err, "larger than")

	require.NoError(t, os.WriteFile(path, data[:maxReadSize], 0o600))
	blocks, got, err := readCertificateFile(path, "", "PEM")
	require.NoError(t, err)
	assert.NotEmpty(t, blocks)
	assert.Equal(t, data[:maxReadSize], got)
}
