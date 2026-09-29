package main

import (
	"os/exec"
	"syscall"
)

// dieWithTool asks the kernel to kill cmd when the tool dies, so a proxy
// does not outlive a tool killed by a signal it cannot catch (SIGKILL).
// The kernel ties the signal to the thread that started the child; the
// tool locks no goroutine to a thread, so its threads last as long as it.
func dieWithTool(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}
