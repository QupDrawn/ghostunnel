//go:build !windows

package main

import "os"

// enableVirtualTerminal is a no-op where terminals speak the escapes natively.
func enableVirtualTerminal(*os.File) {}
