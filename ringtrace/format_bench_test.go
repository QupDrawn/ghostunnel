package ringtrace

import (
	"testing"
	"time"
)

// BenchmarkEncodeLine is the cost of encoding one line, per kind that
// matters on the hot path: the handshake with a peer the emitter benchmarks
// write, the start line (the largest), and a tick (the smallest).
func BenchmarkEncodeLine(b *testing.B) {
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	cases := []struct {
		name string
		body Body
	}{
		{"handshake", benchLine(1)},
		{"start", sampleBodies()[0]},
		{"tick", &Tick{}},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			rec := Record{Sequence: 1, At: at, Body: c.body}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := EncodeLine(rec); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
