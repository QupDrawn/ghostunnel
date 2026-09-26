package main

// cmdline_proc.go reads a command line in the form the Linux kernel exposes
// it: <root>/<pid>/cmdline, the arguments NUL-separated and NUL-terminated.
// It is the reader cmdline_linux.go selects over /proc, and it is portable
// so that the rules of cmdline-carries-no-secret are proved on every host
// over a synthetic table of that shape (localchecks_test.go). Nothing here
// is Linux-specific but the format.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
)

// procCmdline is the reader of <root>/<pid>/cmdline. An empty root reads
// nothing; a file that is missing, unreadable or empty (a process that is
// gone, or a zombie) is an error naming the pid.
func procCmdline(root string) cmdlineReader {
	return func(pid int64) ([]string, error) {
		if root == "" {
			return nil, errors.New("no process table configured")
		}
		data, err := os.ReadFile(filepath.Join(root, strconv.FormatInt(pid, 10), "cmdline"))
		if err != nil {
			return nil, err
		}
		if len(data) == 0 {
			return nil, errors.New("empty command line")
		}
		raw := bytes.Split(bytes.TrimSuffix(data, []byte{0}), []byte{0})
		argv := make([]string, 0, len(raw))
		for _, a := range raw {
			argv = append(argv, string(a))
		}
		return argv, nil
	}
}
