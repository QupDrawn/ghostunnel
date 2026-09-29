package main

// bootliveness_test.go proves boot-ambiguous (bootliveness.go) over
// synthetic process tables, and the probe this build selects over real
// child processes: two live proxies are ambiguous, one is not, and a build
// with no probe fails closed naming the OS rather than skipping. Each
// member that reads the trace carries a byte-identical copy of this file.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLivenessHelperProcess is not a test of anything: re-executed by
// startLivenessChild as a child process, it sleeps until it is killed.
// Run directly it does nothing.
func TestLivenessHelperProcess(t *testing.T) {
	if os.Getenv("GT_OBSERVER_LIVENESS_HELPER") != "1" {
		return
	}
	time.Sleep(time.Minute)
}

// startLivenessChild starts this test binary as a child that lives until
// the test ends.
func startLivenessChild(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLivenessHelperProcess$")
	cmd.Env = append(os.Environ(), "GT_OBSERVER_LIVENESS_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

// blBoots writes one boot directory per pid, in order, each with a start
// line naming that pid; a pid below 1 writes a boot whose first line is not
// a start line.
func blBoots(t *testing.T, pids ...int) string {
	t.Helper()
	root := t.TempDir()
	for i, pid := range pids {
		boot := gtBootName(int64(i + 1))
		line := strings.Replace(strings.Replace(gtLines[0], `"boot":1`, `"boot":`+strconv.Itoa(i+1), 1), `"pid":4242`, `"pid":`+strconv.Itoa(pid), 1)
		if pid < 1 {
			line = "not a start line"
		}
		gtWriteSegment(t, root, boot, "0000000001.trace", gtJoin(line))
	}
	return root
}

// blTable builds a process table holding the given pids.
func blTable(t *testing.T, pids ...int) string {
	t.Helper()
	root := t.TempDir()
	for _, pid := range pids {
		if err := os.Mkdir(filepath.Join(root, strconv.Itoa(pid)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// blFind lists root now and judges that listing, as a cycle does with its
// one listing of the trace root.
func blFind(root string, live livenessProbe) []Finding {
	return bootAmbiguousFindings(root, gtListRoot(root), live, nil)
}

func blWant(t *testing.T, got []Finding, subject string) {
	t.Helper()
	if subject == "" {
		if len(got) != 0 {
			t.Fatalf("findings %v, want none", got)
		}
		return
	}
	if len(got) != 1 || got[0].Check != "boot-ambiguous" || got[0].Subject != subject {
		t.Fatalf("findings %v, want boot-ambiguous(%s)", got, subject)
	}
}

func TestBootAmbiguousOverATable(t *testing.T) {
	boots := blBoots(t, 100, 200)
	// The highest boot's process must be live: dead, the check fails
	// naming that boot, whether the older one lives or not.
	blWant(t, blFind(boots, procLiveness(blTable(t))), "0000000002:not-live")
	blWant(t, blFind(boots, procLiveness(blTable(t, 200))), "")
	blWant(t, blFind(boots, procLiveness(blTable(t, 100))), "0000000002:not-live")
	blWant(t, blFind(boots, procLiveness(blTable(t, 100, 200))), "0000000001,0000000002")
	// Three boots, the two older ones live: the highest is dead and two
	// are ambiguous, two findings in that order.
	boots = blBoots(t, 100, 200, 300)
	blWantAll(t, blFind(boots, procLiveness(blTable(t, 100, 200))), "0000000003:not-live", "0000000001,0000000002")
	blWant(t, blFind(boots, procLiveness(blTable(t, 300))), "")
	// One boot: the probe is asked about it all the same. Live passes; a
	// process table that does not show it fails closed; a build with no
	// probe names the OS.
	blWant(t, blFind(blBoots(t, 100), procLiveness(blTable(t, 100))), "")
	blWant(t, blFind(blBoots(t, 100), procLiveness(blTable(t))), "0000000001:not-live")
	blWant(t, blFind(blBoots(t, 100), unsupportedOSLiveness("plan9")), "unsupported-os:plan9")
	// No boot: nothing to judge.
	blWant(t, blFind(blBoots(t), procLiveness(blTable(t))), "")
	// A boot whose start line cannot be read counts as live, the highest
	// included: it cannot be shown dead.
	boots = blBoots(t, 0, 200)
	blWant(t, blFind(boots, procLiveness(blTable(t))), "0000000002:not-live")
	blWant(t, blFind(boots, procLiveness(blTable(t, 200))), "0000000001,0000000002")
	blWant(t, blFind(blBoots(t, 100, 0), procLiveness(blTable(t))), "")
	// An empty boot directory too.
	boots = blBoots(t, 100, 200)
	if err := os.Mkdir(filepath.Join(boots, "0000000003"), 0o755); err != nil {
		t.Fatal(err)
	}
	blWant(t, blFind(boots, procLiveness(blTable(t, 100))), "0000000001,0000000003")
	// A probe that cannot answer makes the boot count as live; a probe
	// with no facility names the OS.
	boots = blBoots(t, 100, 200)
	blWant(t, blFind(boots, func(int64) (bool, error) { return false, errors.New("boom") }), "0000000001,0000000002")
	blWant(t, blFind(boots, unsupportedOSLiveness("plan9")), "unsupported-os:plan9")
	blWant(t, blFind(boots, procLiveness("")), "0000000001,0000000002")
	// A root that cannot be listed is trace-readable's finding.
	blWant(t, blFind(filepath.Join(t.TempDir(), "gt"), procLiveness(blTable(t))), "")
}

// blWantAll checks the findings' subjects in order.
func blWantAll(t *testing.T, got []Finding, subjects ...string) {
	t.Helper()
	if len(got) != len(subjects) {
		t.Fatalf("findings %v, want subjects %v", got, subjects)
	}
	for i, f := range got {
		if f.Check != checkBootAmbiguous || f.Subject != subjects[i] {
			t.Fatalf("finding %d is %v, want %s %q", i, f, checkBootAmbiguous, subjects[i])
		}
	}
}

func TestBootStartPID(t *testing.T) {
	root := blBoots(t, 4242)
	pid, err := bootStartPID(root, "0000000001", nil)
	if err != nil || pid != 4242 {
		t.Fatalf("pid %d, %v", pid, err)
	}
	// A torn first line, a line that is not a start line, and no first
	// segment are all unreadable.
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", []byte(gtLines[0]))
	if _, err := bootStartPID(root, "0000000002", nil); err == nil {
		t.Fatal("a torn start line read")
	}
	gtWriteSegment(t, root, "0000000003", "0000000001.trace", gtJoin(gtLines[1]))
	if _, err := bootStartPID(root, "0000000003", nil); err == nil {
		t.Fatal("an accept line read as a start line")
	}
	gtWriteSegment(t, root, "0000000004", "0000000002.trace", gtJoin(gtLines[0]))
	if _, err := bootStartPID(root, "0000000004", nil); err == nil {
		t.Fatal("a boot with no first segment read")
	}
}

// The start lines are read every cycle and decoded once per content: an
// unchanged line is judged from the memory, a line rewritten in place to
// name another pid is decoded again and that pid is the one asked about,
// and a boot gone from the listing is forgotten.
func TestBootAmbiguousRemembersDecodesByContent(t *testing.T) {
	root := blBoots(t, 4242, 4343)
	mem := &contentMemo[startLineDecode]{}
	decodes := gtCountDecodes(t)
	asked := map[int64]int{}
	live := func(pid int64) (bool, error) { asked[pid]++; return pid == 4343 || pid == 4444, nil }
	blWant(t, bootAmbiguousFindings(root, gtListRoot(root), live, mem), "")
	if *decodes != 2 || len(mem.entries) != 2 {
		t.Fatalf("first look: %d decodes, %d remembered; want 2 and 2", *decodes, len(mem.entries))
	}
	*decodes = 0
	blWant(t, bootAmbiguousFindings(root, gtListRoot(root), live, mem), "")
	if *decodes != 0 || asked[4242] != 2 || asked[4343] != 2 {
		t.Fatalf("unchanged: %d decodes, asked %v; want none and every pid asked again", *decodes, asked)
	}
	// Boot 1's start line now names a live pid, at the same length.
	line := strings.Replace(gtLines[0], `"pid":4242`, `"pid":4444`, 1)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(line))
	blWant(t, bootAmbiguousFindings(root, gtListRoot(root), live, mem), "0000000001,0000000002")
	if *decodes != 1 || asked[4444] != 1 {
		t.Fatalf("rewritten: %d decodes, asked %v; want the one line decoded and its pid asked", *decodes, asked)
	}
	if len(mem.entries) != 2 {
		t.Fatalf("%d decodes remembered, want the two lines listed now", len(mem.entries))
	}
	// A line that does not decode is remembered as not decoding.
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[1]))
	*decodes = 0
	for i := 0; i < 2; i++ {
		blWant(t, bootAmbiguousFindings(root, gtListRoot(root), live, mem), "0000000001,0000000002")
	}
	if *decodes != 1 {
		t.Fatalf("a line that is not a start line decoded %d times over two looks, want once", *decodes)
	}
}

func TestBootAmbiguousLiveProcesses(t *testing.T) {
	live := platformLiveness("/proc")
	a := startLivenessChild(t)
	b := startLivenessChild(t)
	gone := startLivenessChild(t)
	_ = gone.Process.Kill()
	_ = gone.Wait()
	switch runtime.GOOS {
	case "linux", "windows":
		for _, c := range []*exec.Cmd{a, b} {
			if ok, err := live(int64(c.Process.Pid)); err != nil || !ok {
				t.Fatalf("a live child reads as %v, %v", ok, err)
			}
		}
		if ok, err := live(int64(gone.Process.Pid)); err != nil || ok {
			t.Fatalf("a dead child reads as %v, %v", ok, err)
		}
		blWant(t, blFind(blBoots(t, a.Process.Pid, b.Process.Pid), live), "0000000001,0000000002")
		blWant(t, blFind(blBoots(t, gone.Process.Pid, b.Process.Pid), live), "")
		// The highest boot's process is the one that must be live.
		blWant(t, blFind(blBoots(t, a.Process.Pid, gone.Process.Pid), live), "0000000002:not-live")
	default:
		blWant(t, blFind(blBoots(t, a.Process.Pid, b.Process.Pid), live), "unsupported-os:"+runtime.GOOS)
	}
}
