//go:build linux

package main

// ownstore_linux.go collects the own store's entries for own-store-private
// on the one OS whose ownership the deployment's tree describes: an lstat of
// each path (a symbolic link is not followed; it is the link's own
// ownership that is judged, and a link where a directory is expected is
// not a directory), its owner and group ids and its twelve permission
// bits, and who this process runs as.

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// fileOwnerUID is the owning uid of a stat'ed path, for the owner clause
// of procedure H (halts.go, H7): what the kernel recorded when the entry
// was created, which no writer chooses.
func fileOwnerUID(info os.FileInfo) (uint32, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, errors.New("no ownership in the stat result")
	}
	return st.Uid, nil
}

// probeOwnStore stats every path own-store-private compares and returns
// them with this member's identity. An error is returned only when the
// identity itself cannot be read; a path that cannot be stat'ed is returned
// as absent, which the comparison fails when the path is required.
func probeOwnStore(cfg *Config) ([]storeEntry, storeIdentity, error) {
	who := storeIdentity{UID: uint32(os.Getuid())}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, who, err
	}
	who.Groups = sortedGroups(append(groups, os.Getgid()))
	entries := ownStorePaths(cfg)
	for i := range entries {
		var st syscall.Stat_t
		if err := syscall.Lstat(ownStoreDisk(cfg, entries[i].Rel), &st); err != nil {
			continue
		}
		entries[i].Exists = true
		entries[i].IsDir = st.Mode&syscall.S_IFMT == syscall.S_IFDIR
		entries[i].UID = st.Uid
		entries[i].GID = st.Gid
		entries[i].Mode = st.Mode & 0o7777
	}
	return entries, who, nil
}

// ownStoreDisk is the on-disk path of a store-relative path.
func ownStoreDisk(cfg *Config, rel string) string {
	return filepath.Join(cfg.StoresRoot, filepath.FromSlash(rel))
}

// sortedGroups returns the ids sorted, for a stable identity.
func sortedGroups(ids []int) []uint32 {
	out := make([]uint32, 0, len(ids))
	for _, id := range ids {
		if id >= 0 {
			out = append(out, uint32(id))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
