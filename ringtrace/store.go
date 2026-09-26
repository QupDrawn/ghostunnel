package ringtrace

// store.go is the content-addressed store under the trace root that the
// chain store (chain.go, gt/chains/) and the material store (material.go,
// gt/material/) are two instances of: a directory of files named by the
// SHA-256 of their content, written once through a synced temporary file,
// a rename and a directory sync, never modified, read back by name and
// held to it. README.md sections 1.5 and 1.6 describe the protocol; the observers'
// readers are written to that section and share nothing here.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// hasDirSync is whether the platform syncs a directory (syncDir): Windows
// has no directory sync and there it is a no-op.
var hasDirSync = runtime.GOOS != "windows"

// storeMu serialises the stores' writes: two writers of the same first-seen
// content at once would otherwise both write <hash>.tmp. Under it the
// second finds the final file and writes nothing. The lock is per process,
// and the trace root has one writer, so that is every writer.
var storeMu sync.Mutex

// chainSyncHook, when set, is called in place of every sync the stores
// make (SetChainSyncHook).
var (
	chainSyncMu   sync.RWMutex
	chainSyncHook func(path string, f *os.File) error
)

// SetChainSyncHook installs hook in place of every sync the chain store and
// the material store make: of a stored file after its bytes are written (f
// is that file, open for writing) and of the store's directory after the
// rename (f is the directory, opened for the sync, or nil on Windows, which
// has no directory sync and where that sync is a no-op). It exists for the
// proxy's tests of the durability order, which record the syncs and pass
// them through. A nil hook restores the platform's syncs.
func SetChainSyncHook(hook func(path string, f *os.File) error) {
	chainSyncMu.Lock()
	chainSyncHook = hook
	chainSyncMu.Unlock()
}

func currentChainSyncHook() func(path string, f *os.File) error {
	chainSyncMu.RLock()
	defer chainSyncMu.RUnlock()
	return chainSyncHook
}

// syncChainFile syncs a stored file, through the hook when one is set.
func syncChainFile(path string, f *os.File) error {
	if hook := currentChainSyncHook(); hook != nil {
		return hook(path, f)
	}
	return f.Sync()
}

// syncChainDir syncs a directory of a store, through the hook when one is
// set. As syncDir, it is a no-op on Windows (the hook is still told, with
// a nil file).
func syncChainDir(path string) error {
	hook := currentChainSyncHook()
	if hook == nil {
		return syncDir(path)
	}
	if !hasDirSync {
		return hook(path, nil)
	}
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return hook(path, d)
}

// store is one content-addressed store under the trace root: its
// directory name, the suffix its files carry after the hash ("" for none;
// the temporary file always carries ".tmp" in its place), the bound on a
// file, and the word its errors are prefixed with.
type store struct {
	dir    string
	suffix string
	max    int64
	what   string
}

// hashOf is the name content is stored under: its lower-case hex SHA-256.
func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s store) path(root, hash string) string {
	return filepath.Join(root, s.dir, hash+s.suffix)
}

func (s store) errorf(format string, args ...interface{}) error {
	return fmt.Errorf("ringtrace: "+s.what+": "+format, args...)
}

// write stores data under root/<dir>/<sha256><suffix> and returns the
// sha256. It is idempotent: when the file exists nothing is written.
// Otherwise the content is written to <sha256>.tmp, that file is synced,
// renamed to its final name, and the directory is synced, so when write
// returns nil the content is durable under its name. The directory is
// created (DirMode, 0750) the first time and the root synced after it. The caller
// has refused empty and oversize content already.
func (s store) write(root string, data []byte) (string, error) {
	hash := hashOf(data)
	storeMu.Lock()
	defer storeMu.Unlock()
	dir := filepath.Join(root, s.dir)
	if err := s.ensureDir(root, dir); err != nil {
		return "", err
	}
	final := s.path(root, hash)
	if info, err := os.Lstat(final); err == nil {
		if !info.Mode().IsRegular() {
			return "", s.errorf("%s is not a regular file", final)
		}
		return hash, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", s.errorf("%w", err)
	}
	tmp := filepath.Join(dir, hash+".tmp")
	if err := s.writeTmp(tmp, data); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return "", s.errorf("%w", err)
	}
	if err := syncChainDir(dir); err != nil {
		return "", s.errorf("sync %s: %w", dir, err)
	}
	return hash, nil
}

// ensureDir creates root/<dir> when it is absent and syncs root so the
// entry is durable; an existing entry that is not a directory is an error.
func (s store) ensureDir(root, dir string) error {
	info, err := os.Lstat(dir)
	if err == nil {
		if !info.IsDir() {
			return s.errorf("%s is not a directory", dir)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return s.errorf("%w", err)
	}
	if err := os.Mkdir(dir, DirMode); err != nil {
		return s.errorf("%w", err)
	}
	if err := syncChainDir(root); err != nil {
		return s.errorf("sync %s: %w", root, err)
	}
	return nil
}

// writeTmp writes data to tmp (created or truncated, FileMode, 0640), syncs it and
// closes it.
func (s store) writeTmp(tmp string, data []byte) error {
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, FileMode)
	if err != nil {
		return s.errorf("%w", err)
	}
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = fmt.Errorf("short write: %d of %d bytes", n, len(data))
	}
	if err != nil {
		f.Close()
		return s.errorf("write %s: %w", tmp, err)
	}
	if err := syncChainFile(tmp, f); err != nil {
		f.Close()
		return s.errorf("sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return s.errorf("close %s: %w", tmp, err)
	}
	return nil
}

// read reads the content named hash under root and returns its bytes. It
// fails closed: hash must be 64 lower-case hex characters; the file must
// exist as a regular file (a symbolic link is refused, a <hash>.tmp is
// never read), be at most the store's bound (checked by size before any
// content is read, and the read bounded by it), and hash to its name.
// Nothing is returned with an error.
func (s store) read(root, hash string) ([]byte, error) {
	if !reHash.MatchString(hash) {
		return nil, s.errorf("%q is not a lower-case SHA-256 hex string", hash)
	}
	path := s.path(root, hash)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, s.errorf("%w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, malformed(path, 0, "not a regular file")
	}
	if info.Size() > s.max {
		return nil, malformed(path, 0, "%d bytes exceeds the bound of %d", info.Size(), s.max)
	}
	data, err := readBounded(path, s.max)
	if err != nil {
		return nil, s.errorf("%s: %w", path, err)
	}
	if got := hashOf(data); got != hash {
		return nil, malformed(path, 0, "content hashes to %s, not to its name", got)
	}
	return data, nil
}
