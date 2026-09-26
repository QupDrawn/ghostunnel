//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// enableVirtualTerminal asks the Windows console to interpret the escapes
// this tool paints with. Windows Terminal does so already; the classic
// console does not until told. This touches the console's mode and nothing
// else, and a console that refuses is left as it was.
func enableVirtualTerminal(f *os.File) {
	const enableVirtualTerminalProcessing = 0x0004
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getMode := kernel32.NewProc("GetConsoleMode")
	setMode := kernel32.NewProc("SetConsoleMode")
	h := f.Fd()
	var mode uint32
	if r, _, _ := getMode.Call(h, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return
	}
	setMode.Call(h, uintptr(mode|enableVirtualTerminalProcessing))
}
