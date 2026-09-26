//go:build !windows

package main

// readretry_windows_test.go has no counterpart outside Windows: no open
// handle held elsewhere blocks a read there, so there is nothing to retry
// and nothing to hold. The reads it exercises are the plain calls
// (retry_other.go), covered by every other test of the package.
