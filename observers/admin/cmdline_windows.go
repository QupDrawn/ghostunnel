//go:build windows

package main

// cmdline_windows.go reads another process's command line the way Windows
// keeps it: in the process's own address space, in the
// RTL_USER_PROCESS_PARAMETERS block its PEB points at, as one UTF-16
// string that CommandLineToArgvW splits by the rules the C runtime and Go
// both use. The walk is OpenProcess (query and read), then
// NtQueryInformationProcess for the PEB address, ReadProcessMemory for the
// ProcessParameters pointer, again for the CommandLine UNICODE_STRING,
// again for its buffer, then the split. Only the standard library's
// syscall package is used, and only the 64-bit layout is walked: a 32-bit
// observer, or a 32-bit (WOW64) target whose parameters are not where a
// 64-bit walk looks, fails closed as a bitness mismatch rather than being
// misread. Every other failure fails closed with the subject that names
// it: access denied, or the parameter block unreadable; a process that
// does not exist names the pid alone, as on Linux.
//
// There is no opt-in: reading the proxy's command line is this member's
// own competence on every OS it has a reader for.

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	cmdlineNtdll    = syscall.NewLazyDLL("ntdll.dll")
	cmdlineKernel32 = syscall.NewLazyDLL("kernel32.dll")
	cmdlineShell32  = syscall.NewLazyDLL("shell32.dll")

	procNtQueryInformationProcess = cmdlineNtdll.NewProc("NtQueryInformationProcess")
	procReadProcessMemory         = cmdlineKernel32.NewProc("ReadProcessMemory")
	procIsWow64Process            = cmdlineKernel32.NewProc("IsWow64Process")
	procLocalFree                 = cmdlineKernel32.NewProc("LocalFree")
	procCommandLineToArgvW        = cmdlineShell32.NewProc("CommandLineToArgvW")
)

const (
	processQueryInformation = 0x0400
	processVMRead           = 0x0010
	// processBasicInformation is the PROCESSINFOCLASS that yields the
	// PEB address.
	processBasicInformation = 0
	// The 64-bit layouts: PEB.ProcessParameters, and
	// RTL_USER_PROCESS_PARAMETERS.CommandLine (after ImagePathName).
	pebProcessParametersOffset = 0x20
	rtlCommandLineOffset       = 0x70
)

// processBasicInformationT is PROCESS_BASIC_INFORMATION on a 64-bit build.
type processBasicInformationT struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 uintptr
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

// unicodeString is UNICODE_STRING on a 64-bit build: a byte length, a
// byte capacity, padding, and the buffer's address in the other process.
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             [4]byte
	Buffer        uintptr
}

// platformCmdline is the reader of this build; procRoot is ignored.
func platformCmdline(string) cmdlineReader {
	return readWindowsCmdline
}

func readWindowsCmdline(pid int64) ([]string, error) {
	fail := func(what string, err error) error {
		return &cmdlineError{Subject: fmt.Sprintf("pid:%d:%s", pid, what), Err: err}
	}
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return nil, fail("bitness-mismatch", errors.New("this observer is a 32-bit build and walks only the 64-bit layout"))
	}
	if pid < 1 || pid > 0xFFFFFFFF {
		return nil, errors.New("pid out of range")
	}
	for _, p := range []*syscall.LazyProc{procNtQueryInformationProcess, procReadProcessMemory, procIsWow64Process, procLocalFree, procCommandLineToArgvW} {
		if err := p.Find(); err != nil {
			return nil, fail("unreadable", err)
		}
	}
	h, err := syscall.OpenProcess(processQueryInformation|processVMRead, false, uint32(pid))
	if err != nil {
		if err == syscall.ERROR_ACCESS_DENIED {
			return nil, fail("access-denied", err)
		}
		// ERROR_INVALID_PARAMETER: no such process. Anything else is as
		// unreadable, and names the pid the same way.
		return nil, err
	}
	defer func() { _ = syscall.CloseHandle(h) }()

	// Both sides must be 64-bit: this build is (above), and the target is
	// not a WOW64 process.
	self, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, fail("unreadable", err)
	}
	var wowSelf, wowTarget int32
	if r, _, e := procIsWow64Process.Call(uintptr(self), uintptr(unsafe.Pointer(&wowSelf))); r == 0 {
		return nil, fail("unreadable", e)
	}
	if r, _, e := procIsWow64Process.Call(uintptr(h), uintptr(unsafe.Pointer(&wowTarget))); r == 0 {
		return nil, fail("unreadable", e)
	}
	if wowSelf != 0 || wowTarget != 0 {
		return nil, fail("bitness-mismatch", errors.New("the process is 32-bit under WOW64, or this observer is"))
	}

	var pbi processBasicInformationT
	var retLen uint32
	status, _, _ := procNtQueryInformationProcess.Call(uintptr(h), processBasicInformation, uintptr(unsafe.Pointer(&pbi)), unsafe.Sizeof(pbi), uintptr(unsafe.Pointer(&retLen)))
	if status != 0 || uintptr(retLen) != unsafe.Sizeof(pbi) || pbi.PebBaseAddress == 0 {
		return nil, fail("unreadable", fmt.Errorf("NtQueryInformationProcess: status 0x%x, %d bytes, peb 0x%x", status, retLen, pbi.PebBaseAddress))
	}
	var params uintptr
	if err := readProcessMemory(h, pbi.PebBaseAddress+pebProcessParametersOffset, unsafe.Pointer(&params), unsafe.Sizeof(params)); err != nil {
		return nil, fail("unreadable", fmt.Errorf("PEB.ProcessParameters: %w", err))
	}
	if params == 0 {
		return nil, fail("unreadable", errors.New("PEB.ProcessParameters is null"))
	}
	var cl unicodeString
	if err := readProcessMemory(h, params+rtlCommandLineOffset, unsafe.Pointer(&cl), unsafe.Sizeof(cl)); err != nil {
		return nil, fail("unreadable", fmt.Errorf("RTL_USER_PROCESS_PARAMETERS.CommandLine: %w", err))
	}
	n := int(cl.Length) / 2 // Length is in bytes; a UTF-16 unit is two
	if n == 0 || cl.Buffer == 0 {
		return nil, errors.New("empty command line")
	}
	buf := make([]uint16, n+1) // NUL-terminated for the splitter
	if err := readProcessMemory(h, cl.Buffer, unsafe.Pointer(&buf[0]), uintptr(n*2)); err != nil {
		return nil, fail("unreadable", fmt.Errorf("CommandLine.Buffer: %w", err))
	}
	buf[n] = 0
	for _, u := range buf[:n] {
		if u == 0 {
			return nil, fail("unreadable", errors.New("a NUL inside the command line"))
		}
	}

	var argc int32
	r, _, e := procCommandLineToArgvW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&argc)))
	if r == 0 {
		return nil, fail("unreadable", fmt.Errorf("CommandLineToArgvW: %w", e))
	}
	defer func() { _, _, _ = procLocalFree.Call(r) }()
	if argc <= 0 {
		return nil, errors.New("empty command line")
	}
	var argvPtr **uint16
	*(*uintptr)(unsafe.Pointer(&argvPtr)) = r
	argv := make([]string, 0, argc)
	for _, p := range unsafe.Slice(argvPtr, int(argc)) {
		argv = append(argv, utf16PtrToString(p))
	}
	return argv, nil
}

// readProcessMemory reads exactly size bytes at addr in h into dst.
func readProcessMemory(h syscall.Handle, addr uintptr, dst unsafe.Pointer, size uintptr) error {
	var read uintptr
	r, _, e := procReadProcessMemory.Call(uintptr(h), addr, uintptr(dst), size, uintptr(unsafe.Pointer(&read)))
	if r == 0 {
		return e
	}
	if read != size {
		return fmt.Errorf("short read: %d of %d bytes", read, size)
	}
	return nil
}

// utf16PtrToString is the string a NUL-terminated UTF-16 pointer holds.
func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	n := 0
	for q := unsafe.Pointer(p); *(*uint16)(q) != 0; q = unsafe.Add(q, 2) {
		n++
	}
	return syscall.UTF16ToString(unsafe.Slice(p, n))
}
