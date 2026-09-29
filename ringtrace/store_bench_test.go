package ringtrace

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// BenchmarkWriteChainStoredWhileNewAreWritten is the handshake's chain
// write for a chain stored already, from sixteen goroutines, while another
// goroutine keeps writing first-seen chains (each a file sync and a
// directory sync).
func BenchmarkWriteChainStoredWhileNewAreWritten(b *testing.B) {
	root := b.TempDir()
	stored := []byte("a chain stored already")
	if _, err := WriteChain(root, stored); err != nil {
		b.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			if _, err := WriteChain(root, []byte(fmt.Sprintf("first-seen chain %d", i))); err != nil {
				b.Error(err)
				return
			}
		}
	}()
	b.SetParallelism(benchGoroutines(16))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := WriteChain(root, stored); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	stop.Store(true)
	wg.Wait()
}
