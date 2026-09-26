package main

// cycle_bench_test.go measures one cycle of this member over the
// healthy-ring fixture with the proxy's trace at three sizes: about 300,
// 10,000 and 100,000 lines of one boot. The trace work of step 7 is done
// here as every member does it (the tunnel surface, tick-fresh,
// trace-consistent and the surface comparison; no host probe), once with
// every line decoded every cycle (full) and once with the decode memory
// (memory: the lines beyond what last cycle decoded). Every member carries
// a byte-identical copy of this file.

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// benchTraceChecks is step 7's trace work. Full selects the read that
// decodes every line.
type benchTraceChecks struct {
	Full bool
}

func (benchTraceChecks) Identifiers() []string {
	ids := append([]string{checkTraceReadable}, tunnelSurfaceIdentifiers...)
	return append(ids, checkTickFresh, checkTraceConsistent)
}

func (benchTraceChecks) RingIdentifiers() []string { return surfaceRingIdentifiers(surfaceTunnel) }

func (c benchTraceChecks) Run(cfg *Config, st *State, peers map[string]PeerView) []Finding {
	var boot *gtBoot
	var err error
	if c.Full {
		boot, err = gtReadLatest(cfg.TracesRoot)
	} else {
		boot, _, err = traceReadCurrent(st, cfg.TracesRoot)
	}
	readable := err == nil && len(boot.Records) > 0 && boot.Records[0].Start != nil
	var out []Finding
	switch {
	case err != nil:
		out = append(out, Finding{Check: checkTraceReadable, Subject: gtSubject(err)})
		out = append(out, tickFreshUnread()...)
		out = append(out, traceConsistentUnread()...)
	case !readable:
		out = append(out, Finding{Check: checkTraceReadable, Subject: gtBootName(boot.Number)})
		out = append(out, tickFreshUnread()...)
		out = append(out, traceConsistentFindings(st, boot)...)
	default:
		out = tunnelSurfaceFindings(boot, cfg.Now, 0, 0, 0)
		out = append(out, substanceFindings(boot, substanceJudgeFor(cfg, st))...)
		out = append(out, tickFreshFindings(boot, cfg.Now, 0)...)
		out = append(out, traceConsistentFindings(st, boot)...)
	}
	return append(out, surfaceDisagreements(surfaceTunnel, boot, readable, cfg.Now, surfaceMargins{}, substanceJudgeFor(cfg, st), peers)...)
}

// benchRing recreates the healthy-ring fixture under a fresh directory as
// the fixture harness does (recreateFixture: the manifest's directories,
// then the files), writes one boot of n lines as the proxy's trace, ending
// at the cycle's clock, and returns the tunnel member's configuration and
// state as the fixture harness supplies them.
func benchRing(tb testing.TB, n int, local LocalChecks) (*Config, *State) {
	tb.Helper()
	_, tmp := recreateFixture(tb, filepath.Join(fixtureRoot(), "healthy-ring"))
	now, _ := time.Parse(time.RFC3339, "2026-09-20T10:07:25Z")
	traces := filepath.Join(tmp, "traces")
	if err := os.MkdirAll(filepath.Join(traces, "0000000001"), 0o755); err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(traces, "0000000001", "0000000001.trace"), gtJoin(gtSynthLines(n, now)...), 0o644); err != nil {
		tb.Fatal(err)
	}
	// The chain every synthetic handshake names and the CA bundle the
	// start line hashes, as the proxy's root carries them, so the
	// substance rules re-judge each connection.
	gtInstallChains(tb, traces)
	gtInstallMaterial(tb, traces)
	cfg := &Config{
		Identity: "tunnel", Members: sampleMembers, Coordinator: "super", CopyAuthor: fixtureCopyAuthor,
		StoresRoot: filepath.Join(tmp, "stores"), TracesRoot: traces,
		Window: 4, StaleSlack: 1, StagingStaleAfter: 60 * time.Second,
		MaxHeartbeatBytes: 8192, MaxFaultBytes: 8192, MaxHaltBytes: 8192,
		CadenceSeconds: 10, Now: now, Local: local, DryRun: true,
	}
	st := &State{Started: now, Memory: map[string]string{}, Unchanged: map[string]time.Duration{}}
	since := now.Add(-365 * 24 * time.Hour)
	st.ObservingSince = &since
	st.OwnStorePrivate = []string{}
	own := filepath.Join(cfg.StoresRoot, "tunnel", "heartbeat")
	des, err := os.ReadDir(own)
	if err != nil {
		tb.Fatal(err)
	}
	var last []byte
	for _, de := range des {
		if !reHeartbeatName.MatchString(de.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(own, de.Name()))
		if err != nil {
			tb.Fatal(err)
		}
		st.Memory["tunnel/heartbeat/"+de.Name()] = sha256Hex(b)
		last = b
	}
	hb, err := parseHeartbeat(last, sampleMembers)
	if err != nil {
		tb.Fatal(err)
	}
	st.HasBasis = true
	st.Basis = hb.Observed
	return cfg, st
}

// The synthetic boot is healthy under every trace check the benchmark
// runs, so the benchmark measures a passing cycle rather than a halt.
func TestBenchRingTraceIsHealthy(t *testing.T) {
	for _, n := range []int{300, 10000} {
		cfg, st := benchRing(t, n, benchTraceChecks{})
		out, err := RunCycle(cfg, st)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range out.Failing {
			if f.Check != "surface-disagree" {
				t.Errorf("%d lines: %v", n, f)
			}
		}
		// The second cycle, resumed from memory, judges the same.
		again, err := RunCycle(cfg, st)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(again.Failing) != fmt.Sprint(out.Failing) {
			t.Errorf("%d lines: second cycle %v, first %v", n, again.Failing, out.Failing)
		}
	}
}

// BenchmarkCycle is one cycle of this member at three trace sizes, the
// trace unchanged between cycles (no new connection), with every line
// decoded (full) and with the decode memory (memory).
func BenchmarkCycle(b *testing.B) {
	for _, n := range []int{300, 10000, 100000} {
		for _, mode := range []string{"full", "memory"} {
			b.Run(fmt.Sprintf("%s/%d", mode, n), func(b *testing.B) {
				cfg, st := benchRing(b, n, benchTraceChecks{Full: mode == "full"})
				if _, err := RunCycle(cfg, st); err != nil {
					b.Fatal(err)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := RunCycle(cfg, st); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
