package main

// disk.go states the disk a run wrote to. The fork's trace is fsynced line
// by line on every connection, so a slow work volume is measured as a slow
// fork; the report header names the work directory, the filesystem it is
// on where that is cheap to know, and the fsync latency measured there.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	fsyncProbeLines = 200
	fsyncProbeWidth = 80 // bytes per line, line feed included
	fsyncWarnAt     = time.Millisecond
)

// diskInfo is what the header says about the work directory.
type diskInfo struct {
	dir      string
	fs       string        // filesystem description, or "" when not determined
	fsync    time.Duration // median per appended and synced line
	fsyncErr error         // the probe could not run (reported, not fatal)
}

// describeDisk resolves the work directory's filesystem and probes fsync.
func describeDisk(dir string) *diskInfo {
	d := &diskInfo{dir: dir, fs: filesystemOf(dir)}
	d.fsync, d.fsyncErr = fsyncLatency(dir)
	return d
}

func (d *diskInfo) slow() bool { return d.fsyncErr == nil && d.fsync > fsyncWarnAt }

func (d *diskInfo) fsyncString() string {
	if d.fsyncErr != nil {
		return fmt.Sprintf("not measured: %v", d.fsyncErr)
	}
	return fmt.Sprintf("%d µs median per call (%d lines of %d bytes appended and synced one by one)",
		d.fsync.Microseconds(), fsyncProbeLines, fsyncProbeWidth)
}

// filesystemOf names the filesystem holding dir: on Linux the /proc/mounts
// entry with the longest mount point that contains dir, on Windows the
// volume, elsewhere "".
func filesystemOf(dir string) string {
	switch runtime.GOOS {
	case "windows":
		if v := filepath.VolumeName(dir); v != "" {
			return "volume " + v
		}
		return ""
	case "linux":
		data, err := os.ReadFile("/proc/mounts")
		if err != nil {
			return ""
		}
		var bestMP, bestDev, bestType string
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 3 {
				continue
			}
			mp := unescapeMount(f[1])
			contains := mp == "/" || dir == mp || strings.HasPrefix(dir, strings.TrimSuffix(mp, "/")+"/")
			if !contains || len(mp) < len(bestMP) {
				continue
			}
			bestMP, bestDev, bestType = mp, unescapeMount(f[0]), f[2]
		}
		if bestMP == "" {
			return ""
		}
		return fmt.Sprintf("%s on %s (%s)", bestType, bestMP, bestDev)
	}
	return ""
}

// unescapeMount decodes the octal escapes /proc/mounts uses for space,
// tab, line feed and backslash in a path.
func unescapeMount(s string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}

// fsyncLatency appends fsyncProbeLines lines of fsyncProbeWidth bytes to
// a temporary file in dir, syncing after each, and returns the median
// time of one append-and-sync. The file is removed afterwards.
func fsyncLatency(dir string) (time.Duration, error) {
	f, err := os.CreateTemp(dir, "fsync-probe-*.tmp")
	if err != nil {
		return 0, err
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	line := make([]byte, fsyncProbeWidth)
	samples := make([]float64, 0, fsyncProbeLines)
	for i := 0; i < fsyncProbeLines; i++ {
		head := fmt.Sprintf("fsync-probe %03d ", i)
		copy(line, head)
		for j := len(head); j < len(line)-1; j++ {
			line[j] = 'x'
		}
		line[len(line)-1] = '\n'
		start := time.Now()
		if _, err := f.Write(line); err != nil {
			return 0, err
		}
		if err := f.Sync(); err != nil {
			return 0, err
		}
		samples = append(samples, float64(time.Since(start)))
	}
	if err := f.Close(); err != nil {
		return 0, err
	}
	return time.Duration(median(samples)), nil
}
