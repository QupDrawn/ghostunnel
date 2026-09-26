package ringtrace

import (
	"runtime"
	"testing"
	"time"
)

// benchGoroutines is the SetParallelism value that runs n goroutines in
// RunParallel, which multiplies it by GOMAXPROCS (the count is exact when
// GOMAXPROCS divides n).
func benchGoroutines(n int) int {
	if p := runtime.GOMAXPROCS(0); p < n {
		return n / p
	}
	return 1
}

// benchEmitter opens an emitter under SyncEveryLine with a real clock, the
// configuration the proxy runs with.
func benchEmitter(b *testing.B) *Emitter {
	b.Helper()
	e, err := Open(b.TempDir(), Options{Config: testConfig(), PID: 4242, Now: time.Now, Sync: SyncEveryLine})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = e.Close() })
	return e
}

func benchLine(i int64) Body {
	proto := "TLS 1.3"
	return &Handshake{Conn: i, Outcome: "ok", Verified: true, Protocol: proto, Peer: &Peer{
		Subject: "CN=allowed,O=ghostunnel", Issuer: "CN=ca,O=ghostunnel", Serial: "1234567890",
		SANs:        []string{"allowed.example"},
		Fingerprint: "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
	}}
}

// BenchmarkEmitSerial: one goroutine, one Emit at a time, under
// SyncEveryLine. This is the sequential cost of a line.
func BenchmarkEmitSerial(b *testing.B) {
	e := benchEmitter(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Emit(benchLine(int64(i + 1))); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(e.SyncCount())/float64(b.N), "fsync/line")
}

// BenchmarkEmitParallel16: sixteen goroutines emitting at once under
// SyncEveryLine. The reported ns/op is wall time per line.
func BenchmarkEmitParallel16(b *testing.B) {
	e := benchEmitter(b)
	b.SetParallelism(benchGoroutines(16))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var i int64
		for pb.Next() {
			i++
			if _, err := e.Emit(benchLine(i)); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.ReportMetric(float64(e.SyncCount())/float64(b.N), "fsync/line")
}
