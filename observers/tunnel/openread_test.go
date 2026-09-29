package main

// openread_test.go proves the reads beneath every check (encoding.go): the
// file a bounded read returns is the one its Lstat judged, a name replaced
// between the two is judged afresh and a name replaced on every attempt is
// refused, a stored chain or CA bundle replaced between the two is refused
// (substance.go), and the buffer a read is sized from a stat changes only
// the allocation. Every member carries a byte-identical copy of this file.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// swapAfterLstat makes every bounded read's Lstat of path, for the rest of
// the test, replace the file it judged with a regular file holding
// next(attempt) before the open, through a rename as a writer replaces a
// file (SPEC 5); next returning nil leaves the file alone.
func swapAfterLstat(t *testing.T, path string, next func(attempt int) []byte) *int {
	t.Helper()
	prev := lstatForRead
	t.Cleanup(func() { lstatForRead = prev })
	attempts := 0
	lstatForRead = func(p string) (os.FileInfo, error) {
		info, err := prev(p)
		if p != path {
			return info, err
		}
		attempts++
		if data := next(attempts); data != nil {
			if werr := os.WriteFile(p+".new", data, 0o644); werr != nil {
				return nil, werr
			}
			if rerr := renameFile(p+".new", p); rerr != nil {
				return nil, rerr
			}
		}
		return info, err
	}
	return &attempts
}

// A file replaced once between the judgement and the open is judged again
// and read as it now is: the ordinary rename of a writer is no finding.
func TestReadBoundedJudgesAReplacedFileAfresh(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fault")
	if err := os.WriteFile(p, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	attempts := swapAfterLstat(t, p, func(n int) []byte {
		if n == 1 {
			return []byte("second")
		}
		return nil
	})
	data, oversized, err := readBounded(p, 4096)
	if err != nil || oversized || string(data) != "second" {
		t.Fatalf("read %q oversized=%v %v; want the replacement", data, oversized, err)
	}
	if *attempts != 2 {
		t.Fatalf("judged %d times, want 2", *attempts)
	}
}

// A file replaced on every attempt is never read: after judgeAttempts
// judgements the read fails, and nothing it opened is returned.
func TestReadBoundedRefusesAFileReplacedEveryTime(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fault")
	if err := os.WriteFile(p, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	attempts := swapAfterLstat(t, p, func(n int) []byte { return []byte("replacement") })
	data, oversized, err := readBounded(p, 4096)
	if err == nil || !errors.Is(err, errNotJudged) || data != nil || oversized {
		t.Fatalf("read %q oversized=%v %v; want the file opened refused as not the one judged", data, oversized, err)
	}
	if *attempts != judgeAttempts {
		t.Fatalf("judged %d times, want %d", *attempts, judgeAttempts)
	}
	// A replacement past the bound is judged oversized, as the Lstat of
	// the replacement sees it, and never read.
	big := bytes.Repeat([]byte{'x'}, 5000)
	swapAfterLstat(t, p, func(n int) []byte {
		if n == 1 {
			return big
		}
		return nil
	})
	if data, oversized, err := readBounded(p, 4096); !oversized || data != nil || err != nil {
		t.Fatalf("a replacement past the bound: %d bytes oversized=%v %v", len(data), oversized, err)
	}
}

// A stored file of the substance rules replaced between its judgement and
// the open is refused as not the one judged, on every platform, and
// nothing it held is returned: not the replacement, whatever it holds,
// and not the file judged, which is no longer at the name. The name is
// judged once; the next cycle reads it again.
func TestSubstanceReadStoredRefusesAReplacedFile(t *testing.T) {
	chain := []byte("the chain judged")
	p := filepath.Join(t.TempDir(), substanceHash(chain)+".der")
	if err := os.WriteFile(p, chain, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, replacement := range [][]byte{[]byte("another chain"), chain} {
		t.Run(string(replacement), func(t *testing.T) {
			attempts := swapAfterLstat(t, p, func(int) []byte { return replacement })
			data, err := substanceReadStored(p, substanceHash(chain), substanceMaxChainBytes)
			if !errors.Is(err, errNotJudged) || data != nil {
				t.Fatalf("replaced by %q: %q, %v; want the file opened refused as not the one judged", replacement, data, err)
			}
			if *attempts != 1 {
				t.Fatalf("judged %d times, want 1", *attempts)
			}
		})
	}
	// Left alone, the file is read.
	if data, err := substanceReadStored(p, substanceHash(chain), substanceMaxChainBytes); err != nil || !bytes.Equal(data, chain) {
		t.Fatalf("the stored file: %q, %v", data, err)
	}
}

// oneByteReader hands out one byte per read, the worst a reader may do.
type oneByteReader struct{ r *bytes.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return o.r.Read(p)
}

// readAtMost returns what io.ReadAll over a reader limited to max+1 bytes
// returns, whatever size it is told: too small, too large, negative, past
// the bound.
func TestReadAtMostIgnoresAWrongSize(t *testing.T) {
	for _, n := range []int{0, 1, 511, 512, 513, 4096, 4097, 70000} {
		data := bytes.Repeat([]byte{'y'}, n)
		for _, max := range []int64{0, 1, 4096, 1 << 20} {
			want := data
			if int64(len(want)) > max+1 {
				want = want[:max+1]
			}
			for _, size := range []int64{-5, 0, 1, int64(n) - 1, int64(n), int64(n) + 1, 10 * int64(n), max, max + 1, 1 << 40} {
				got, err := readAtMost(bytes.NewReader(data), size, max)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("n=%d max=%d size=%d: %d bytes, %v; want %d", n, max, size, len(got), err, len(want))
				}
				if got, err := readAtMost(oneByteReader{bytes.NewReader(data)}, size, max); err != nil || !bytes.Equal(got, want) {
					t.Fatalf("one byte a read, n=%d max=%d size=%d: %d bytes, %v", n, max, size, len(got), err)
				}
			}
		}
	}
	// The size a file reports sizes the buffer once: an unchanged file is
	// read with no growth.
	got, _ := readAtMost(bytes.NewReader(bytes.Repeat([]byte{'z'}, 3000)), 3000, 4096)
	if cap(got) != 3001 {
		t.Fatalf("a read of a file of the size it reported grew: cap %d", cap(got))
	}
	if _, err := readAtMost(errReader{}, 10, 10); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("a failing read: %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("broken") }
