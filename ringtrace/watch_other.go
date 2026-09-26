//go:build !linux && !windows

package ringtrace

import (
	"errors"
	"runtime"
)

// startWatcher: no change notification on this OS. The state then reuses
// a decision only within its window, and every other Check is a scan.
func startWatcher(root string, dirs []string, s *GateState) (treeWatcher, error) {
	return nil, errors.New("no directory change notification on " + runtime.GOOS)
}
