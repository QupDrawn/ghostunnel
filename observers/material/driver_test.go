package main

// driver_test.go proves, through the real driver (main.go: startUp,
// RunCycle, apply), that a published heartbeat whose re-read differs from
// what was written is own-store-writable failing on the next cycle (SPEC
// 5), with subject re-read, in the fault, until a publish re-reads clean.
// The re-read is made to differ by rewriting the file on disk between the
// write and the re-read, so that what the driver hashes into memory is what
// is on disk and the chain stays whole. Every member carries a
// byte-identical copy of this file.

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// driverRing is a ring of one member on a real store tree under tmp.
func driverRing(t *testing.T) (*Config, *State) {
	t.Helper()
	tmp := t.TempDir()
	own := filepath.Join(tmp, "stores", "solo")
	if err := os.MkdirAll(filepath.Join(own, "halts"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Identity: "solo", Members: []string{"solo"}, Coordinator: "solo", CopyAuthor: map[string]string{},
		StoresRoot: filepath.Join(tmp, "stores"), TracesRoot: filepath.Join(tmp, "traces"),
		Window: 4, StaleSlack: 1, StagingStaleAfter: 60 * time.Second,
		MaxHeartbeatBytes: 8192, MaxFaultBytes: 8192, MaxHaltBytes: 8192,
		CadenceSeconds: 10, Local: NoLocalChecks{},
	}
	st, err := startUp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, st
}

// driverCycle runs one cycle on the real disk and applies it.
func driverCycle(t *testing.T, cfg *Config, st *State) *Outcome {
	t.Helper()
	cfg.Now = time.Now().UTC()
	refreshObservingSince(cfg, st)
	st.OwnStorePrivate = []string{}
	out, err := RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(cfg, st, out); err != nil {
		t.Fatal(err)
	}
	return out
}

func driverHas(out *Outcome, check, subject string) bool {
	for _, f := range out.Failing {
		if f.Check == check && f.Subject == subject {
			return true
		}
	}
	return false
}

func TestRereadDifferenceFailsTheNextCycle(t *testing.T) {
	cfg, st := driverRing(t)
	out := driverCycle(t, cfg, st)
	if len(out.Failing) != 0 || st.RereadDiffers {
		t.Fatalf("first cycle: failing %v, re-read differs %v", out.Failing, st.RereadDiffers)
	}

	// The next publish lands on a disk that hands back a different, still
	// valid, heartbeat: the same record with a cadence of 11.
	prev := readPublished
	t.Cleanup(func() { readPublished = prev })
	readPublished = func(p string) ([]byte, error) {
		b, err := prev(p)
		if err != nil {
			return nil, err
		}
		hb, err := parseHeartbeat(b, cfg.Members)
		if err != nil {
			return nil, err
		}
		hb.CadenceSeconds = 11
		altered, err := encodeHeartbeat(hb)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, altered, 0o644); err != nil {
			return nil, err
		}
		return prev(p)
	}
	out = driverCycle(t, cfg, st)
	if driverHas(out, "own-store-writable", "re-read") {
		t.Fatal("the cycle that wrote already reports the re-read")
	}
	if !st.RereadDiffers {
		t.Fatal("the driver did not record the differing re-read")
	}

	// The next cycle reports it, as a local finding, and the halt names it.
	readPublished = prev
	out = driverCycle(t, cfg, st)
	if !driverHas(out, "own-store-writable", "re-read") {
		t.Fatalf("the next cycle does not report the re-read: %v", out.Failing)
	}
	if !out.Fault.Publish || len(out.Fault.Local) != 1 || out.Fault.Local[0] != (Finding{Check: "own-store-writable", Subject: "re-read"}) {
		t.Fatalf("fault %+v", out.Fault)
	}
	if !out.Halt.Writes || out.Halt.Reason != "own-store-writable" || out.Halt.Subject != "re-read" {
		t.Fatalf("halt %+v", out.Halt)
	}
	// That cycle's publish re-read clean, so the one after is clear.
	if st.RereadDiffers {
		t.Fatal("a clean re-read did not clear the record")
	}
	out = driverCycle(t, cfg, st)
	if driverHas(out, "own-store-writable", "re-read") {
		t.Fatalf("still reported after a clean publish: %v", out.Failing)
	}
	if !out.Fault.Remove {
		t.Fatalf("the fault is not cleared: %+v", out.Fault)
	}
}
