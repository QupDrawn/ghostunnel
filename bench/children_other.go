//go:build !unix

package main

import (
	"os"
	"os/exec"
)

var stopSignals = []os.Signal{os.Interrupt}

// ownGroup does nothing here: there are no process groups to kill.
func ownGroup(cmd *exec.Cmd) {}

// killTree kills cmd itself.
func killTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
