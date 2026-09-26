package ringtrace

// chain.go is the chain store under gt/chains/: the certificate chain a
// peer presented, kept by content hash so a handshake line can name it
// (Handshake.Chain) and a member can re-verify the chain itself and re-run
// the recorded rule on its leaf, instead of trusting that the proxy said it
// did. README.md section 1.5 is the description the observers' own reader
// is written to; nothing here is shared with them. The write and read
// protocol is the content-addressed store's (store.go), which the material
// store (material.go) shares; what is the chain store's own is the DER
// content, the .der suffix and the bound.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"path/filepath"
)

// ChainsDirName is the directory under the trace root that is the chain
// store, one of the two directories there that are not a boot (the other
// is MaterialDirName).
const ChainsDirName = "chains"

// MaxChainBytes bounds a chain file. crypto/tls refuses a handshake message
// above 64 KiB, so no presented chain approaches this; the writer refuses
// a longer one and the reader treats a longer file as malformed, so a
// reader never hashes an unbounded file.
const MaxChainBytes = 1 << 20

// ErrChainTooLong is returned when a chain would exceed MaxChainBytes.
var ErrChainTooLong = errors.New("ringtrace: chain exceeds MaxChainBytes")

// chainStore is the chain store's shape: gt/chains/<sha256>.der.
var chainStore = store{dir: ChainsDirName, suffix: ".der", max: MaxChainBytes, what: "chain"}

// ChainHash is the name a chain is stored under: the lower-case hex SHA-256
// of the presented chain's DER, concatenated in presented order.
func ChainHash(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ChainPath is the path of the chain file named hash under root. It does
// not check that hash is well-formed; ReadChain does.
func ChainPath(root, hash string) string {
	return filepath.Join(root, ChainsDirName, hash+".der")
}

// WriteChain stores der, the DER of every certificate a peer presented
// concatenated in presented order, under root/chains/<sha256>.der and
// returns the sha256. It is idempotent: when the file exists nothing is
// written. Otherwise the content is written to <sha256>.tmp, that file is
// synced, renamed to <sha256>.der, and the directory is synced, so when
// WriteChain returns nil the chain is durable under its name. The chains
// directory is created (DirMode, 0750) the first time and the root synced
// after it; a chain file is FileMode, 0640, like a segment.
// An empty der is refused: a peer that presented nothing has no chain.
func WriteChain(root string, der []byte) (string, error) {
	if len(der) == 0 {
		return "", errors.New("ringtrace: chain: no certificate presented")
	}
	if len(der) > MaxChainBytes {
		return "", ErrChainTooLong
	}
	return chainStore.write(root, der)
}

// ReadChain reads the chain named hash under root and returns its
// certificates in presented order with the bytes read. It fails closed:
// hash must be 64 lower-case hex characters; the file must exist as a
// regular file (a symbolic link is refused, a <hash>.tmp is never read),
// be at most MaxChainBytes, hash to its name, and parse as a concatenation
// of at least one DER certificate. Nothing is returned with an error.
func ReadChain(root, hash string) ([]*x509.Certificate, []byte, error) {
	data, err := chainStore.read(root, hash)
	if err != nil {
		return nil, nil, err
	}
	path := ChainPath(root, hash)
	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, nil, malformed(path, 0, "not a concatenation of DER certificates: %v", err)
	}
	if len(certs) == 0 {
		return nil, nil, malformed(path, 0, "holds no certificate")
	}
	return certs, data, nil
}
