package ringtrace

// reader.go is the reference reader of gt/. The observers' localchecks
// mirror it without importing it; README.md states every rule it applies.
//
// The segment rule (README.md section 1.3): A segment's content is its
// bytes before the first NUL byte (0x00), or all of its bytes when it has
// none. Bytes from the first NUL onward are unwritten space of a
// pre-extended segment and are not part of the trace. A reader reads a
// segment in bounded chunks from its start and stops at the first chunk
// holding a NUL or at end of file; it never reads a whole pre-extended
// segment. The complete-line prefix and the torn tail are then taken of
// the content.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// ContentChunkBytes is the size of the bounded reads ReadSegmentContent
// makes: it reads at most this much past a segment's content.
const ContentChunkBytes = 1 << 20

// ReadSegmentContent returns the content of the segment at path by the
// segment rule: its bytes before the first NUL byte (0x00), or all of its
// bytes when it has none. Bytes from the first NUL onward are unwritten
// space of a pre-extended segment and are not part of the trace. The file
// is read in chunks of ContentChunkBytes from its start and the read stops
// at the first chunk holding a NUL or at end of file, so a live segment
// pre-extended to MaxSegmentBytes is never read whole. Lines are JSON
// objects, which never carry a raw NUL (encoding/json escapes it), so the
// cut is exact.
func ReadSegmentContent(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readContent(f)
}

// readContent is ReadSegmentContent on an open reader.
func readContent(r io.Reader) ([]byte, error) {
	var out []byte
	buf := make([]byte, ContentChunkBytes)
	for {
		n, err := io.ReadFull(r, buf)
		chunk := buf[:n]
		if i := bytes.IndexByte(chunk, 0); i >= 0 {
			return append(out, chunk[:i]...), nil
		}
		out = append(out, chunk...)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// MalformedError locates a trace that does not parse. Line is 1-based and
// 0 when the finding is about a file or directory rather than a line.
type MalformedError struct {
	Path   string
	Line   int
	Reason string
}

func (e *MalformedError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("ringtrace: %s:%d: %s", e.Path, e.Line, e.Reason)
	}
	return fmt.Sprintf("ringtrace: %s: %s", e.Path, e.Reason)
}

func malformed(path string, line int, format string, args ...interface{}) error {
	return &MalformedError{Path: path, Line: line, Reason: fmt.Sprintf(format, args...)}
}

// Boot is one process's trace as read.
type Boot struct {
	Number   int64
	Dir      string
	Segments []string // segment file names, ascending
	Records  []Record // every complete line, in sequence order
	Torn     bool     // the last segment ends in a line without a line feed
}

// Trace is the whole gt/ tree as read.
type Trace struct {
	Root  string
	Boots []Boot // ascending by number
}

// Latest returns the last complete line of the highest boot that has one,
// or nil when no boot holds a line.
func (t *Trace) Latest() *Record {
	for i := len(t.Boots) - 1; i >= 0; i-- {
		if n := len(t.Boots[i].Records); n > 0 {
			r := t.Boots[i].Records[n-1]
			return &r
		}
	}
	return nil
}

// Read reads every boot under root. Any file or line that does not follow
// the format is a *MalformedError and nothing is returned: a trace that
// cannot be read has not been read.
func Read(root string) (*Trace, error) {
	boots, err := listBoots(root)
	if err != nil {
		return nil, err
	}
	tr := &Trace{Root: root}
	for _, n := range boots {
		b, err := ReadBoot(filepath.Join(root, BootName(n)), n)
		if err != nil {
			return nil, err
		}
		tr.Boots = append(tr.Boots, *b)
	}
	return tr, nil
}

// ReadBoot reads one boot directory that is said to hold boot number. Each
// segment is read by the segment rule (ReadSegmentContent): its content is
// its bytes before the first NUL, and the complete-line prefix and the
// torn tail are taken of that content.
func ReadBoot(dir string, number int64) (*Boot, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	b := &Boot{Number: number, Dir: dir}
	for _, de := range des {
		if !de.Type().IsRegular() || !reSegmentName.MatchString(de.Name()) {
			return nil, malformed(filepath.Join(dir, de.Name()), 0, "unexpected entry in a boot directory")
		}
		b.Segments = append(b.Segments, de.Name())
	}
	sort.Strings(b.Segments)
	if len(b.Segments) == 0 {
		// A process that died between creating its directory and writing
		// its first line. Benign.
		return b, nil
	}
	next := int64(1)
	for i, name := range b.Segments {
		path := filepath.Join(dir, name)
		last := i == len(b.Segments)-1
		if got := numberOfName(name); got != next {
			return nil, malformed(path, 0, "segment is named %d but the next sequence is %d", got, next)
		}
		data, err := ReadSegmentContent(path)
		if err != nil {
			return nil, err
		}
		lines, torn := splitLines(data)
		if torn && !last {
			return nil, malformed(path, len(lines)+1, "torn line in a segment that is not the last")
		}
		if len(lines) == 0 && !last {
			return nil, malformed(path, 0, "empty segment that is not the last")
		}
		for j, line := range lines {
			rec, err := DecodeLine(line)
			if err != nil {
				return nil, malformed(path, j+1, "%v", err)
			}
			if rec.Sequence != next {
				return nil, malformed(path, j+1, "sequence %d where %d is expected", rec.Sequence, next)
			}
			if next == 1 {
				st, ok := rec.Body.(*Start)
				if !ok {
					return nil, malformed(path, j+1, "the first line of a boot is not a start line")
				}
				if st.Boot != number {
					return nil, malformed(path, j+1, "start line names boot %d in the directory of boot %d", st.Boot, number)
				}
			} else if rec.Body.Kind() == KindStart {
				return nil, malformed(path, j+1, "a start line after the first line")
			}
			if n := len(b.Records); n > 0 && rec.At.Before(b.Records[n-1].At) {
				return nil, malformed(path, j+1, "timestamp goes back")
			}
			b.Records = append(b.Records, rec)
			next++
		}
		if last {
			b.Torn = torn
		}
	}
	return b, nil
}

// splitLines returns the complete lines of data (without their line feeds)
// and whether a torn final line follows them.
func splitLines(data []byte) ([][]byte, bool) {
	end := bytes.LastIndexByte(data, '\n')
	if end < 0 {
		return nil, len(data) > 0
	}
	lines := bytes.Split(data[:end], []byte("\n"))
	return lines, end+1 < len(data)
}
