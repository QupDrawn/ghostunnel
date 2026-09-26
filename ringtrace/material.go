package ringtrace

// material.go is the material store under gt/material/: the bytes of a
// trust material file as the proxy hashed them for a start or reload line
// (Material.SHA256), kept by that hash so a member can verify a presented
// chain against the CA bundle the proxy verified against, whatever the
// file at the material's path holds now. A bundle rotated in place by a
// reload is still on record under its old hash for the handshakes judged
// before the reload, and under its new hash for those after. README.md
// section 1.6 is the description the observers' own reader is written to;
// nothing here is shared with them.

import (
	"errors"
	"fmt"
	"path/filepath"
)

// MaterialDirName is the directory under the trace root that is the
// material store, one of the two directories there that are not a boot
// (the other is ChainsDirName).
const MaterialDirName = "material"

// MaxMaterialBytes bounds a stored material file. A CA bundle is a few
// hundred KiB at the largest in common use; the writer refuses a longer
// one, which refuses the start or fails the reload that would have named
// it, and the reader treats a longer file as malformed, so a reader never
// hashes an unbounded file.
const MaxMaterialBytes = 16 << 20

// ErrMaterialTooLong is returned when a material file would exceed
// MaxMaterialBytes.
var ErrMaterialTooLong = errors.New("ringtrace: material exceeds MaxMaterialBytes")

// materialStore is the material store's shape: gt/material/<sha256>, no
// suffix, since the bytes are the file's as read, whatever its format.
var materialStore = store{dir: MaterialDirName, suffix: "", max: MaxMaterialBytes, what: "material"}

// MaterialHash is the name material is stored under: the lower-case hex
// SHA-256 of the file's bytes, which is Material.SHA256.
func MaterialHash(data []byte) string {
	return hashOf(data)
}

// MaterialPath is the path of the material file named hash under root. It
// does not check that hash is well-formed; ReadMaterial does.
func MaterialPath(root, hash string) string {
	return filepath.Join(root, MaterialDirName, hash)
}

// WriteMaterial stores data, the bytes of a material file exactly as they
// were hashed for the line that names them, under root/material/<sha256>
// and returns the sha256. It is idempotent and durable as WriteChain is:
// when the file exists nothing is written; otherwise the content goes
// through a synced <sha256>.tmp, a rename and a directory sync, so when
// WriteMaterial returns nil the bytes are durable under their name. Empty
// content is refused: a file with no bytes holds no material.
func WriteMaterial(root string, data []byte) (string, error) {
	if len(data) == 0 {
		return "", errors.New("ringtrace: material: no content")
	}
	if len(data) > MaxMaterialBytes {
		return "", ErrMaterialTooLong
	}
	return materialStore.write(root, data)
}

// ReadMaterial reads the material named hash under root and returns its
// bytes. It fails closed as ReadChain does: hash must be 64 lower-case hex
// characters; the file must exist as a regular file (a symbolic link is
// refused, a <hash>.tmp is never read), be at most MaxMaterialBytes and
// hash to its name. Nothing is returned with an error. What the bytes
// parse as is the caller's to judge.
func ReadMaterial(root, hash string) ([]byte, error) {
	return materialStore.read(root, hash)
}

// StoreMaterial puts the CA bundle's bytes into the material store under
// root for the material list a start or reload line is about to record:
// for the entry of kind ca that carries a hash, ca (the bundle's bytes
// exactly as they were hashed for that entry) is held to the entry's hash
// and then written under root/material/<sha256> (WriteMaterial). A list
// with no hashed ca entry stores nothing and ca is not consulted. It is
// called before the line that names the hash is written (Open, through
// Options.CABundle; ghostunnel's reload before its reload line), and a
// refusal is that line not written: a hashed entry with no bytes, bytes
// that hash to something else, or a store that cannot be written each
// refuse with nothing stored.
func StoreMaterial(root string, material []Material, ca []byte) error {
	for _, m := range material {
		if m.Material != "ca" || m.SHA256 == nil {
			continue
		}
		if ca == nil {
			return errors.New("ringtrace: material: the ca entry carries a hash but no bytes were given to store")
		}
		if got := MaterialHash(ca); got != *m.SHA256 {
			return fmt.Errorf("ringtrace: material: the ca bundle given hashes to %s, not to the recorded %s", got, *m.SHA256)
		}
		if _, err := WriteMaterial(root, ca); err != nil {
			return err
		}
	}
	return nil
}
