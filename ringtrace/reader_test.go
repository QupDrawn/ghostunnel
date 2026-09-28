package ringtrace

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeBoot writes one boot directory by hand: segs maps a segment name to
// the records it holds (in order). Records are encoded with EncodeLine.
func writeBoot(t *testing.T, root string, boot int64, segs map[string][]Record) string {
	t.Helper()
	dir := filepath.Join(root, BootName(boot))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, recs := range segs {
		var buf bytes.Buffer
		for _, r := range recs {
			line, err := EncodeLine(r)
			if err != nil {
				t.Fatal(err)
			}
			buf.Write(line)
		}
		if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// bootRecords returns a start line followed by n-1 accept lines.
func bootRecords(boot int64, n int) []Record {
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	recs := []Record{{Sequence: 1, At: at, Body: &Start{Boot: boot, PID: 1, Config: testConfig()}}}
	for i := 2; i <= n; i++ {
		recs = append(recs, Record{Sequence: int64(i), At: at.Add(time.Duration(i) * time.Second), Body: &Accept{Conn: int64(i), Listener: "0.0.0.0:8443", Remote: "10.0.0.1:1"}})
	}
	return recs
}

func appendRaw(t *testing.T, path string, raw string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(raw); err != nil {
		t.Fatal(err)
	}
}

func expectMalformed(t *testing.T, root string, what string) *MalformedError {
	t.Helper()
	_, err := Read(root)
	if err == nil {
		t.Fatalf("%s: Read must fail", what)
	}
	var me *MalformedError
	if !errors.As(err, &me) {
		t.Fatalf("%s: want *MalformedError, got %T %v", what, err, err)
	}
	return me
}

func TestReaderHealthyTree(t *testing.T) {
	root := t.TempDir()
	recs := bootRecords(1, 5)
	writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs[:3], "0000000004.trace": recs[3:]})
	tr, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Boots) != 1 || tr.Boots[0].Number != 1 || len(tr.Boots[0].Records) != 5 || tr.Boots[0].Torn {
		t.Fatalf("bad read: %#v", tr.Boots)
	}
	if tr.Boots[0].Segments[0] != "0000000001.trace" || tr.Boots[0].Segments[1] != "0000000004.trace" {
		t.Fatalf("segments: %v", tr.Boots[0].Segments)
	}
	if last := tr.Latest(); last == nil || last.Sequence != 5 {
		t.Fatalf("Latest: %#v", last)
	}
	if _, ok := tr.Boots[0].Records[0].Body.(*Start); !ok {
		t.Fatal("first record must be the start line")
	}
}

func TestReaderEmptyRoot(t *testing.T) {
	tr, err := Read(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Boots) != 0 || tr.Latest() != nil {
		t.Fatal("an empty gt/ has no boots and no latest line")
	}
}

func TestReaderTornFinalLineIgnored(t *testing.T) {
	root := t.TempDir()
	dir := writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": bootRecords(1, 3)})
	appendRaw(t, filepath.Join(dir, "0000000001.trace"), `{"kind":"accept","version":1,"sequence":4,"at":"2026-09-24T10:07:0`)
	tr, err := Read(root)
	if err != nil {
		t.Fatalf("a torn final line must be ignored: %v", err)
	}
	b := tr.Boots[0]
	if len(b.Records) != 3 || !b.Torn {
		t.Fatalf("want 3 records and Torn=true, got %d records, Torn=%v", len(b.Records), b.Torn)
	}
	if tr.Latest().Sequence != 3 {
		t.Fatalf("Latest must be the last complete line")
	}
}

func TestReaderTornLineInEarlierSegmentIsMalformed(t *testing.T) {
	root := t.TempDir()
	recs := bootRecords(1, 4)
	dir := writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs[:2], "0000000003.trace": recs[2:]})
	appendRaw(t, filepath.Join(dir, "0000000001.trace"), `{"kind":"acc`)
	expectMalformed(t, root, "torn line in a non-final segment")
}

func TestReaderMalformedLine(t *testing.T) {
	cases := map[string]string{
		"garbage":         "not json\n",
		"unknown kind":    `{"kind":"connect","version":1,"sequence":4,"at":"2026-09-24T10:07:00Z"}` + "\n",
		"heartbeat":       `{"kind":"heartbeat","version":1}` + "\n",
		"extra key":       `{"kind":"accept","version":1,"sequence":4,"at":"2026-09-24T10:07:00Z","conn":4,"listener":"a","remote":"b","x":1}` + "\n",
		"empty line":      "\n",
		"crlf":            `{"kind":"accept","version":1,"sequence":4,"at":"2026-09-24T10:07:00Z","conn":4,"listener":"a","remote":"b"}` + "\r\n",
		"second start":    `{"kind":"start","version":1,"sequence":4,"at":"2026-09-24T10:07:00Z","boot":1,"pid":1,"config":{"mode":"server","listen":"a","target":"b","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":false,"verify_on_resume":true,"acl":["allow-all"],"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}` + "\n",
		"sequence repeat": `{"kind":"accept","version":1,"sequence":3,"at":"2026-09-24T10:07:00Z","conn":4,"listener":"a","remote":"b"}` + "\n",
		"sequence skip":   `{"kind":"accept","version":1,"sequence":5,"at":"2026-09-24T10:07:00Z","conn":4,"listener":"a","remote":"b"}` + "\n",
		"time goes back":  `{"kind":"accept","version":1,"sequence":4,"at":"2026-09-24T10:06:59Z","conn":4,"listener":"a","remote":"b"}` + "\n",
		"line too long":   `{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T10:07:00Z","conn":1,"decision":"deny","rule":"r","reason":"` + string(bytes.Repeat([]byte("x"), MaxLineBytes)) + `"}` + "\n",
		"torn then more":  `{"kind":"acc` + "\n" + `{"kind":"accept","version":1,"sequence":4,"at":"2026-09-24T10:07:04Z","conn":4,"listener":"a","remote":"b"}` + "\n",
	}
	for name, raw := range cases {
		root := t.TempDir()
		dir := writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": bootRecords(1, 3)})
		appendRaw(t, filepath.Join(dir, "0000000001.trace"), raw)
		me := expectMalformed(t, root, name)
		if me.Path == "" || me.Line == 0 {
			t.Errorf("%s: malformed error must locate the line: %#v", name, me)
		}
	}
}

func TestReaderSequenceGapAcrossSegments(t *testing.T) {
	root := t.TempDir()
	recs := bootRecords(1, 6)
	// Segment 2 claims to start at 4 but the line inside is 5.
	writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs[:3], "0000000004.trace": recs[4:]})
	expectMalformed(t, root, "gap across segments")

	root = t.TempDir()
	// Segment name does not match its first line.
	writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs[:3], "0000000005.trace": recs[3:]})
	expectMalformed(t, root, "segment name mismatch")

	root = t.TempDir()
	// A whole segment missing from the middle.
	writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs[:2], "0000000005.trace": recs[4:]})
	expectMalformed(t, root, "missing segment")

	root = t.TempDir()
	// The first segment is missing.
	writeBoot(t, root, 1, map[string][]Record{"0000000003.trace": recs[2:]})
	expectMalformed(t, root, "missing first segment")
}

func TestReaderStartLineRules(t *testing.T) {
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	root := t.TempDir()
	// First line is not a start.
	writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": {{Sequence: 1, At: at, Body: &Accept{Conn: 1, Listener: "a", Remote: "b"}}}})
	expectMalformed(t, root, "first line not start")

	root = t.TempDir()
	// The start line names a different boot than its directory.
	writeBoot(t, root, 2, map[string][]Record{"0000000001.trace": bootRecords(1, 2)})
	expectMalformed(t, root, "boot number mismatch")
}

func TestReaderEmptyBootAndEmptyTrailingSegmentAreBenign(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "0000000001"), 0o755); err != nil {
		t.Fatal(err)
	}
	recs := bootRecords(2, 3)
	dir := writeBoot(t, root, 2, map[string][]Record{"0000000001.trace": recs, "0000000004.trace": nil})
	tr, err := Read(root)
	if err != nil {
		t.Fatalf("empty boot and empty trailing segment are benign: %v", err)
	}
	if len(tr.Boots) != 2 || len(tr.Boots[0].Records) != 0 || len(tr.Boots[1].Records) != 3 || len(tr.Boots[1].Segments) != 2 {
		t.Fatalf("bad read: %#v", tr.Boots)
	}
	// An empty trailing segment whose name is not the next sequence is a gap.
	if err := os.Rename(filepath.Join(dir, "0000000004.trace"), filepath.Join(dir, "0000000009.trace")); err != nil {
		t.Fatal(err)
	}
	expectMalformed(t, root, "empty trailing segment misnamed")
}

func TestReaderEmptyMiddleSegmentIsMalformed(t *testing.T) {
	root := t.TempDir()
	recs := bootRecords(1, 4)
	writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs[:2], "0000000003.trace": nil, "0000000004.trace": recs[3:]})
	expectMalformed(t, root, "empty middle segment")
}

func TestReaderStrayEntries(t *testing.T) {
	root := t.TempDir()
	writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": bootRecords(1, 2)})
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectMalformed(t, root, "stray file in root")

	root = t.TempDir()
	dir := writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": bootRecords(1, 2)})
	if err := os.WriteFile(filepath.Join(dir, "0000000001.trace.tmp"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectMalformed(t, root, "stray file in boot")

	root = t.TempDir()
	dir = writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": bootRecords(1, 2)})
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectMalformed(t, root, "subdirectory in boot")

	root = t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "0000000001"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectMalformed(t, root, "boot entry is a file")
}

func TestReaderUnreadableRoot(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing root must be an error")
	}
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(f); err == nil {
		t.Fatal("a root that is a file must be an error")
	}
}

func TestReaderBootsAreOrderedByNumber(t *testing.T) {
	root := t.TempDir()
	writeBoot(t, root, 12, map[string][]Record{"0000000001.trace": bootRecords(12, 2)})
	writeBoot(t, root, 3, map[string][]Record{"0000000001.trace": bootRecords(3, 4)})
	tr, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Boots[0].Number != 3 || tr.Boots[1].Number != 12 {
		t.Fatalf("order: %d %d", tr.Boots[0].Number, tr.Boots[1].Number)
	}
	if tr.Latest().Sequence != 2 {
		t.Fatal("Latest comes from the highest boot")
	}
	if got := tr.Boots[1].Records[1].Body.(*Accept).Conn; got != 2 {
		t.Fatalf("records carry their bodies: conn %d", got)
	}
}

func TestReadBootSingle(t *testing.T) {
	root := t.TempDir()
	dir := writeBoot(t, root, 5, map[string][]Record{"0000000001.trace": bootRecords(5, 3)})
	b, err := ReadBoot(dir, 5)
	if err != nil || len(b.Records) != 3 || b.Number != 5 {
		t.Fatalf("ReadBoot: %v %#v", err, b)
	}
	if _, err := ReadBoot(dir, 6); err == nil {
		t.Fatal("ReadBoot with the wrong number must fail")
	}
}

// TestReaderTickLines: ticks read like any other line, in sequence.
func TestReaderTickLines(t *testing.T) {
	root := t.TempDir()
	at := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	recs := bootRecords(1, 2)
	recs = append(recs, Record{Sequence: 3, At: at.Add(5 * time.Second), Body: &Tick{}}, Record{Sequence: 4, At: at.Add(10 * time.Second), Body: &Tick{}})
	writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs})
	tr, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(tr.Boots[0].Records); n != 4 {
		t.Fatalf("want 4 records, got %d", n)
	}
	if tr.Latest().Body.Kind() != KindTick {
		t.Fatal("the latest line is a tick")
	}
	appendRaw(t, filepath.Join(root, "0000000001", "0000000001.trace"), `{"kind":"tick","version":1,"sequence":6,"at":"2026-09-24T10:07:20Z"}`+"\n")
	if me := expectMalformed(t, root, "tick with a sequence gap"); me.Line != 5 {
		t.Fatalf("want line 5, got %d", me.Line)
	}
}

// TestReaderLockFileIsTheOneAllowedFile: the regular file gt/lock is part
// of the tree; anything else at that name, or any other file under the
// root, is malformed.
func TestReaderLockFileIsTheOneAllowedFile(t *testing.T) {
	root := t.TempDir()
	writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": bootRecords(1, 2)})
	if err := os.WriteFile(filepath.Join(root, "lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	tr, err := Read(root)
	if err != nil {
		t.Fatalf("a regular lock file is benign: %v", err)
	}
	if len(tr.Boots) != 1 {
		t.Fatalf("want 1 boot, got %d", len(tr.Boots))
	}
	if err := os.WriteFile(filepath.Join(root, "lock.tmp"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	expectMalformed(t, root, "a file other than lock under the root")
	if err := os.Remove(filepath.Join(root, "lock.tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "lock"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectMalformed(t, root, "a directory named lock")
}

// writeSegmentBytes writes a segment file by hand, bytes as given.
func writeSegmentBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// padNUL appends NULs to data until it is size bytes long: the unwritten
// tail of a pre-extended segment.
func padNUL(data []byte, size int) []byte {
	out := make([]byte, size)
	copy(out, data)
	return out
}

// TestReaderSegmentRule: a segment's content is its bytes before the first
// NUL. Complete lines, a partial line and then NULs read as those lines
// plus a torn tail; complete lines and then NULs read as those lines, not
// torn; zeros inside the last line (pages of an unacknowledged group
// persisted out of order) cut the content at the first zero, so the line
// is the torn tail; and a NUL tail in a segment that is not the last (a
// crash between the truncation at rotation and its fsync) is not a fault.
func TestReaderSegmentRule(t *testing.T) {
	const size = 4096
	recs := bootRecords(1, 5)
	encode := func(rs []Record) []byte {
		var buf bytes.Buffer
		for _, r := range rs {
			line, err := EncodeLine(r)
			if err != nil {
				t.Fatal(err)
			}
			buf.Write(line)
		}
		return buf.Bytes()
	}
	three := encode(recs[:3])
	fourth, err := EncodeLine(recs[3])
	if err != nil {
		t.Fatal(err)
	}

	t.Run("partial line then NULs is torn", func(t *testing.T) {
		root := t.TempDir()
		dir := writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs[:3]})
		writeSegmentBytes(t, filepath.Join(dir, "0000000001.trace"), padNUL(append(append([]byte{}, three...), fourth[:len(fourth)/2]...), size))
		tr, err := Read(root)
		if err != nil {
			t.Fatal(err)
		}
		if b := tr.Boots[0]; len(b.Records) != 3 || !b.Torn {
			t.Fatalf("want 3 records and Torn, got %d records, Torn=%v", len(b.Records), b.Torn)
		}
	})
	t.Run("complete lines then NULs is not torn", func(t *testing.T) {
		root := t.TempDir()
		dir := writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs[:3]})
		writeSegmentBytes(t, filepath.Join(dir, "0000000001.trace"), padNUL(three, size))
		tr, err := Read(root)
		if err != nil {
			t.Fatal(err)
		}
		if b := tr.Boots[0]; len(b.Records) != 3 || b.Torn {
			t.Fatalf("want 3 records and not Torn, got %d records, Torn=%v", len(b.Records), b.Torn)
		}
		if tr.Latest().Sequence != 3 {
			t.Fatal("Latest must be sequence 3")
		}
	})
	t.Run("zeros inside the last line cut it there", func(t *testing.T) {
		root := t.TempDir()
		dir := writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs[:3]})
		holed := append([]byte{}, fourth...)
		for i := len(holed) / 3; i < len(holed)/2; i++ {
			holed[i] = 0
		}
		writeSegmentBytes(t, filepath.Join(dir, "0000000001.trace"), padNUL(append(append([]byte{}, three...), holed...), size))
		tr, err := Read(root)
		if err != nil {
			t.Fatal(err)
		}
		if b := tr.Boots[0]; len(b.Records) != 3 || !b.Torn {
			t.Fatalf("want 3 records and Torn, got %d records, Torn=%v", len(b.Records), b.Torn)
		}
	})
	t.Run("NUL tail in a segment that is not the last", func(t *testing.T) {
		root := t.TempDir()
		dir := writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs[:3], "0000000004.trace": recs[3:]})
		writeSegmentBytes(t, filepath.Join(dir, "0000000001.trace"), padNUL(three, size))
		tr, err := Read(root)
		if err != nil {
			t.Fatal(err)
		}
		if b := tr.Boots[0]; len(b.Records) != 5 || b.Torn {
			t.Fatalf("want 5 records and not Torn, got %d records, Torn=%v", len(b.Records), b.Torn)
		}
	})
	t.Run("all-NUL last segment is an empty last segment", func(t *testing.T) {
		root := t.TempDir()
		dir := writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs[:3]})
		writeSegmentBytes(t, filepath.Join(dir, "0000000004.trace"), make([]byte, size))
		tr, err := Read(root)
		if err != nil {
			t.Fatalf("a pre-extended segment nothing was written to is an empty last segment: %v", err)
		}
		if b := tr.Boots[0]; len(b.Records) != 3 || b.Torn || len(b.Segments) != 2 {
			t.Fatalf("bad read: %#v", b)
		}
	})
	t.Run("all-NUL middle segment is an empty middle segment", func(t *testing.T) {
		root := t.TempDir()
		dir := writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs[:2], "0000000004.trace": recs[3:]})
		writeSegmentBytes(t, filepath.Join(dir, "0000000003.trace"), make([]byte, size))
		expectMalformed(t, root, "all-NUL middle segment")
	})
	t.Run("partial line then NULs in a segment that is not the last", func(t *testing.T) {
		root := t.TempDir()
		dir := writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": recs[:3], "0000000004.trace": recs[3:]})
		writeSegmentBytes(t, filepath.Join(dir, "0000000001.trace"), padNUL(append(append([]byte{}, three...), fourth[:len(fourth)/2]...), size))
		expectMalformed(t, root, "torn line before a NUL tail in a non-final segment")
	})
}

// TestReadSegmentContentBounds: the content read is bounded and exact at
// the chunk boundary: a file of exactly one chunk with no NUL is all
// content; content one chunk and a little more, then NULs, is read to the
// byte; a NUL exactly at the chunk boundary ends the content there; an
// all-NUL file and an empty file have no content; a missing file is an
// error.
func TestReadSegmentContentBounds(t *testing.T) {
	dir := t.TempDir()
	const chunk = ContentChunkBytes
	fill := func(n int) []byte { return bytes.Repeat([]byte("a"), n) }
	cases := []struct {
		name string
		data []byte
		want int
	}{
		{"exactly one chunk, no NUL", fill(chunk), chunk},
		{"one chunk and five, then NULs", padNUL(fill(chunk+5), 3*chunk), chunk + 5},
		{"NUL at the chunk boundary", padNUL(fill(chunk), 2*chunk), chunk},
		{"NUL just before the boundary", padNUL(fill(chunk-1), 2*chunk), chunk - 1},
		{"all NUL", make([]byte, 2*chunk), 0},
		{"empty", nil, 0},
		{"short, no NUL", fill(17), 17},
	}
	for _, c := range cases {
		path := filepath.Join(dir, "seg")
		writeSegmentBytes(t, path, c.data)
		got, err := ReadSegmentContent(path)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(got) != c.want || !bytes.Equal(got, c.data[:c.want]) {
			t.Fatalf("%s: got %d bytes, want %d", c.name, len(got), c.want)
		}
	}
	if _, err := ReadSegmentContent(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing segment must be an error")
	}
}
