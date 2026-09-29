package ringtrace

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkGateCheck is one full scan of a healthy tree.
func BenchmarkGateCheck(b *testing.B) {
	root := b.TempDir()
	for _, m := range []string{"admin", "material", "super", "tunnel"} {
		for _, d := range []string{"heartbeat", "halts"} {
			if err := os.MkdirAll(filepath.Join(root, m, d), 0o755); err != nil {
				b.Fatal(err)
			}
		}
	}
	hb := heartbeatLine("super", 42, gateNow.Add(-2*time.Second).Format("2006-01-02T15:04:05Z"), false)
	if err := os.WriteFile(filepath.Join(root, "super", "heartbeat", "0000000042.hb"), []byte(hb), 0o644); err != nil {
		b.Fatal(err)
	}
	g := testGate(root)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d := g.Check(); !d.Serve {
			b.Fatal(d.Reason)
		}
	}
}
