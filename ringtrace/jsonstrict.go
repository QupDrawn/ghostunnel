package ringtrace

// jsonstrict.go is the strict object decoder every reader in this package
// uses: UTF-8 without a byte-order mark, exactly one JSON object, no
// duplicate keys, nothing after the object but at most one line feed, and
// exactly the expected key set. It is written here independently of the
// observers' decoders; it agrees with them only by agreeing with the
// specification.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

// timestampLayout is the one timestamp form: YYYY-MM-DDTHH:MM:SSZ, UTC,
// whole seconds.
const timestampLayout = "2006-01-02T15:04:05Z"

var reInteger = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// isHash reports whether s is a lower-case SHA-256 hex string: exactly 64
// bytes, each 0-9 or a-f.
func isHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// rawObject holds a decoded object's raw values by key, and the key order.
type rawObject struct {
	values map[string]json.RawMessage
	order  []string
}

func (o *rawObject) get(k string) json.RawMessage { return o.values[k] }

// decodeObject decodes b as one strict object. trailingLF says whether a
// single trailing line feed after the object is tolerated (a file) or not
// (a line that has already had its line feed removed).
func decodeObject(b []byte, trailingLF bool) (*rawObject, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("not valid UTF-8")
	}
	if bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, errors.New("byte-order mark")
	}
	obj, off, err := decodeObjectAt(b)
	if err != nil {
		return nil, err
	}
	rest := b[off:]
	if len(rest) != 0 && (!trailingLF || !bytes.Equal(rest, []byte("\n"))) {
		return nil, errors.New("bytes after the object")
	}
	return obj, nil
}

// decodeObjectAt decodes one object from the start of b and returns the
// offset just past it.
func decodeObjectAt(b []byte) (*rawObject, int64, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, 0, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, 0, errors.New("not a JSON object")
	}
	obj := &rawObject{values: map[string]json.RawMessage{}}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, 0, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, 0, errors.New("object key is not a string")
		}
		if _, dup := obj.values[key]; dup {
			return nil, 0, fmt.Errorf("duplicate key %q", key)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, 0, err
		}
		obj.values[key] = raw
		obj.order = append(obj.order, key)
	}
	if _, err := dec.Token(); err != nil {
		return nil, 0, err
	}
	return obj, dec.InputOffset(), nil
}

// decodeSubobject decodes a nested value as a strict object with exactly
// the given keys.
func decodeSubobject(raw json.RawMessage, keys []string) (*rawObject, error) {
	if isNull(raw) {
		return nil, errors.New("not an object")
	}
	obj, off, err := decodeObjectAt(raw)
	if err != nil {
		return nil, err
	}
	if rest := bytes.TrimSpace(raw[off:]); len(rest) != 0 {
		return nil, errors.New("bytes after the object")
	}
	if err := obj.exactKeys(keys); err != nil {
		return nil, err
	}
	return obj, nil
}

// exactKeys checks the object holds exactly keys, in any order.
func (o *rawObject) exactKeys(keys []string) error {
	return o.allowedKeys(keys, nil)
}

// allowedKeys checks the object holds every key of keys that is not in
// optional, any subset of optional, and nothing else, in any order.
func (o *rawObject) allowedKeys(keys, optional []string) error {
	opt := map[string]bool{}
	for _, k := range optional {
		opt[k] = true
	}
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
		if _, ok := o.values[k]; !ok && !opt[k] {
			return fmt.Errorf("missing key %q", k)
		}
	}
	for _, k := range o.order {
		if !want[k] {
			return fmt.Errorf("unknown key %q", k)
		}
	}
	return nil
}

func isNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

func intField(raw json.RawMessage, name string) (int64, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] == '"' || isNull(raw) {
		return 0, fmt.Errorf("%s: not an integer", name)
	}
	var n json.Number
	if err := json.Unmarshal(trimmed, &n); err != nil || !reInteger.MatchString(n.String()) {
		return 0, fmt.Errorf("%s: not an integer", name)
	}
	v, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %v", name, err)
	}
	return v, nil
}

func stringField(raw json.RawMessage, name string) (string, error) {
	if isNull(raw) {
		return "", fmt.Errorf("%s: not a string", name)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("%s: not a string", name)
	}
	return s, nil
}

func boolField(raw json.RawMessage, name string) (bool, error) {
	if isNull(raw) {
		return false, fmt.Errorf("%s: not a boolean", name)
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false, fmt.Errorf("%s: not a boolean", name)
	}
	return b, nil
}

func nullableString(raw json.RawMessage, name string) (*string, error) {
	if isNull(raw) {
		return nil, nil
	}
	s, err := stringField(raw, name)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func nullableInt(raw json.RawMessage, name string) (*int64, error) {
	if isNull(raw) {
		return nil, nil
	}
	n, err := intField(raw, name)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func nullableHash(raw json.RawMessage, name string) (*string, error) {
	s, err := nullableString(raw, name)
	if err != nil {
		return nil, err
	}
	if s != nil && !isHash(*s) {
		return nil, fmt.Errorf("%s: not a lower-case SHA-256 hex string", name)
	}
	return s, nil
}

func stringArray(raw json.RawMessage, name string) ([]string, error) {
	if isNull(raw) {
		return nil, fmt.Errorf("%s: not an array", name)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("%s: not an array", name)
	}
	out := make([]string, 0, len(items))
	for i, it := range items {
		s, err := stringField(it, fmt.Sprintf("%s[%d]", name, i))
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func objectArray(raw json.RawMessage, name string) ([]json.RawMessage, error) {
	if isNull(raw) {
		return nil, fmt.Errorf("%s: not an array", name)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("%s: not an array", name)
	}
	return items, nil
}

// parseTimestamp accepts exactly the form YYYY-MM-DDTHH:MM:SSZ.
func parseTimestamp(s string) (time.Time, error) {
	if len(s) != len(timestampLayout) {
		return time.Time{}, fmt.Errorf("timestamp %q is not of the form YYYY-MM-DDTHH:MM:SSZ", s)
	}
	t, err := time.Parse(timestampLayout, s)
	if err != nil {
		return time.Time{}, err
	}
	if t.UTC().Format(timestampLayout) != s {
		return time.Time{}, fmt.Errorf("timestamp %q is not canonical", s)
	}
	return t.UTC(), nil
}

func formatTimestamp(t time.Time) string { return t.UTC().Format(timestampLayout) }

func timestampField(raw json.RawMessage, name string) (time.Time, error) {
	s, err := stringField(raw, name)
	if err != nil {
		return time.Time{}, err
	}
	t, err := parseTimestamp(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %v", name, err)
	}
	return t, nil
}
