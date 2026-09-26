package main

// tunnelchecks_bench_test.go is BenchmarkCycle with this member's real
// local checks (TunnelChecks) in place of the shared trace work, so that
// the per-cycle time reported for the tunnel member is the member's own.
// The liveness probe is injected; with one boot it is never consulted.

import (
	"fmt"
	"testing"
)

func BenchmarkTunnelCycle(b *testing.B) {
	for _, n := range []int{300, 10000, 100000} {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			local := TunnelChecks{Live: func(int64) (bool, error) { return true, nil }}
			cfg, st := benchRing(b, n, local)
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
