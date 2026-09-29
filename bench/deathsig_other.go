//go:build !linux

package main

import "os/exec"

// dieWithTool does nothing here: only Linux has a parent-death signal.
func dieWithTool(cmd *exec.Cmd) {}
