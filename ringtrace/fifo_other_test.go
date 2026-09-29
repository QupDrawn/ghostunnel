//go:build !unix

package ringtrace

import "errors"

// noFIFO is why the named pipe tests are skipped here.
const noFIFO = "no named pipe in this platform's filesystem (Windows keeps its pipes in a namespace of their own), so none can be planted at a heartbeat's name"

func mkfifo(string) error { return errors.New(noFIFO) }

func releaseFIFO(string) {}
