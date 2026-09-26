//go:build !linux

package ringtrace

import "os"

// syncData makes a segment's written data durable. Off Linux there is no
// data-only sync to speak of (Windows has none; the platforms that expose
// fdatasync are not ones the ring is deployed on), so it is the full
// sync.
func syncData(f *os.File) error {
	return f.Sync()
}
