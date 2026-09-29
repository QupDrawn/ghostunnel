package ringtrace

import (
	"bytes"
	"path/filepath"
	"testing"
)

// The bytes the emitter writes for a run of batches, large and small, one
// after another through its one encode buffer and with one timestamp per
// batch, are the bytes EncodeLine gives for each line on its own.
func TestEmitterBatchesAreEncodeLineBytes(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{Sync: SyncOnRotateAndClose})
	clock := fixedClock()
	want, err := EncodeLine(Record{Sequence: 1, At: clock(), Body: &Start{Boot: 1, PID: 4242, Config: testConfig()}})
	if err != nil {
		t.Fatal(err)
	}
	bodies := sampleBodies()[1:]
	var many []Body
	for len(many) < 400 {
		many = append(many, bodies...)
	}
	batches := [][]Body{
		bodies[:1], bodies, bodies[:1], bodies[3:6], many, bodies[:2], bodies, many[:1], bodies[len(bodies)-1:],
	}
	seq := int64(2)
	for i, batch := range batches {
		first, err := e.EmitAll(batch...)
		if err != nil {
			t.Fatalf("batch %d: %v", i, err)
		}
		if first != seq {
			t.Fatalf("batch %d: first sequence %d, want %d", i, first, seq)
		}
		at := clock()
		for _, body := range batch {
			line, err := EncodeLine(Record{Sequence: seq, At: at, Body: body})
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, line...)
			seq++
		}
	}
	if cap(e.enc) > maxEncodeBytes {
		t.Fatalf("an encode buffer of %d bytes was kept", cap(e.enc))
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	got := requireExactSize(t, filepath.Join(root, "0000000001", "0000000001.trace"))
	if !bytes.Equal(got, want) {
		n := 0
		for n < len(got) && n < len(want) && got[n] == want[n] {
			n++
		}
		t.Fatalf("the segment is not the lines EncodeLine gives: %d bytes, want %d, first difference at %d", len(got), len(want), n)
	}
}
