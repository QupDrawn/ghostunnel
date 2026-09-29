package ringtrace

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var gateNow = time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)

// heartbeatLine builds a SPEC 3.2 heartbeat for observer at sequence seq
// with the given timestamp, in the exact marker form.
func heartbeatLine(observer string, seq int64, ts string, stop bool) string {
	others := []string{}
	for _, m := range []string{"admin", "material", "super", "tunnel"} {
		if m != observer {
			others = append(others, fmt.Sprintf("%q:null", m))
		}
	}
	return fmt.Sprintf(`{"kind":"heartbeat","version":1,"observer":%q,"sequence":%d,"timestamp":%q,"cadence_seconds":1,"checks":["member-fresh:tunnel"],"check_count":1,"observed":{%s},"previous":%s,"boot":null,"stop":%v}`+"\n",
		observer, seq, ts, strings.Join(others, ","), previousFor(seq), stop)
}

func previousFor(seq int64) string {
	if seq == 1 {
		return "null"
	}
	return `"` + strings.Repeat("ab", 32) + `"`
}

// healthyTree lays out the four stores with a fresh super heartbeat.
func healthyTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, m := range []string{"admin", "material", "super", "tunnel"} {
		for _, d := range []string{"heartbeat", "halts"} {
			if err := os.MkdirAll(filepath.Join(root, m, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeHB(t, root, "super", 42, gateNow.Add(-2*time.Second).Format("2006-01-02T15:04:05Z"), false)
	return root
}

func writeHB(t *testing.T, root, member string, seq int64, ts string, stop bool) {
	t.Helper()
	writeRaw(t, filepath.Join(root, member, "heartbeat", fmt.Sprintf("%010d.hb", seq)), heartbeatLine(member, seq, ts, stop))
}

func writeRaw(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testGate(root string) *Gate {
	g := NewGate(root)
	g.MaxHeartbeatAge = 10 * time.Second
	g.Now = func() time.Time { return gateNow }
	return g
}

func expectRefuse(t *testing.T, g *Gate, what string) Decision {
	t.Helper()
	d := g.Check()
	if d.Serve {
		t.Fatalf("%s: gate served, must refuse", what)
	}
	if d.Reason == "" {
		t.Fatalf("%s: a refusal must carry a reason", what)
	}
	return d
}

func expectServe(t *testing.T, g *Gate, what string) {
	t.Helper()
	d := g.Check()
	if !d.Serve {
		t.Fatalf("%s: gate refused: %s", what, d.Reason)
	}
}

func TestGateDefaults(t *testing.T) {
	g := NewGate("")
	if g.Root != DefaultRoot || g.Coordinator != "super" || len(g.Members) != 4 || g.MaxHeartbeatBytes <= 0 || g.Now == nil {
		t.Fatalf("defaults: %#v", g)
	}
	if strings.Join(g.Members, ",") != "admin,material,super,tunnel" {
		t.Fatalf("members must be in identity order: %v", g.Members)
	}
}

func TestGateServesHealthyTree(t *testing.T) {
	root := healthyTree(t)
	expectServe(t, testGate(root), "healthy tree")
	// Staging files and .tmp halt slots are nothing at all.
	writeRaw(t, filepath.Join(root, "super", "heartbeat", "0000000043.hb.tmp"), "{")
	writeRaw(t, filepath.Join(root, "tunnel", "halts", "admin.tmp"), "{")
	writeRaw(t, filepath.Join(root, "admin", "fault.tmp"), "{")
	writeRaw(t, filepath.Join(root, "admin", "halt.tmp"), "{")
	expectServe(t, testGate(root), "staging files present")
	// A fresher heartbeat exactly at the window edge is current.
	writeHB(t, root, "super", 44, gateNow.Add(-10*time.Second).Format("2006-01-02T15:04:05Z"), false)
	expectServe(t, testGate(root), "heartbeat at the edge of the window")
}

func TestGateRefusesHalt(t *testing.T) {
	for _, m := range []string{"admin", "material", "super", "tunnel"} {
		root := healthyTree(t)
		writeRaw(t, filepath.Join(root, m, "halt"), `{"kind":"halt",`)
		d := expectRefuse(t, testGate(root), m+" halt")
		if !strings.Contains(d.Reason, m+"/halt") {
			t.Fatalf("reason must name the file: %s", d.Reason)
		}
	}
	for _, m := range []string{"admin", "material", "super", "tunnel"} {
		root := healthyTree(t)
		// Content is not read: an empty delivered halt is in force.
		writeRaw(t, filepath.Join(root, m, "halts", "material"), "")
		d := expectRefuse(t, testGate(root), m+" delivered halt")
		if !strings.Contains(d.Reason, m+"/halts/material") {
			t.Fatalf("reason must name the file: %s", d.Reason)
		}
	}
}

func TestGateRefusesFault(t *testing.T) {
	root := healthyTree(t)
	writeRaw(t, filepath.Join(root, "tunnel", "fault"), `{"kind":"fault",`)
	d := expectRefuse(t, testGate(root), "fault")
	if !strings.Contains(d.Reason, "tunnel/fault") {
		t.Fatalf("reason must name the file: %s", d.Reason)
	}
}

func TestGateRefusesStaleSuper(t *testing.T) {
	root := healthyTree(t)
	writeHB(t, root, "super", 43, gateNow.Add(-11*time.Second).Format("2006-01-02T15:04:05Z"), false)
	d := expectRefuse(t, testGate(root), "stale super")
	if !strings.Contains(d.Reason, "0000000043.hb") {
		t.Fatalf("reason must name the heartbeat: %s", d.Reason)
	}
}

func TestGateRefusesFutureSuper(t *testing.T) {
	root := healthyTree(t)
	writeHB(t, root, "super", 43, gateNow.Add(11*time.Second).Format("2006-01-02T15:04:05Z"), false)
	expectRefuse(t, testGate(root), "future super")
}

func TestGateNewestIsHighestSequence(t *testing.T) {
	// An old stale entry below a fresh one: serve.
	root := healthyTree(t)
	writeHB(t, root, "super", 41, gateNow.Add(-time.Hour).Format("2006-01-02T15:04:05Z"), false)
	expectServe(t, testGate(root), "older stale entry")
	// The highest is stale even though a lower one is fresh: refuse.
	writeHB(t, root, "super", 99, gateNow.Add(-time.Hour).Format("2006-01-02T15:04:05Z"), false)
	expectRefuse(t, testGate(root), "highest entry stale")
}

func TestGateRefusesMissingSuperHeartbeat(t *testing.T) {
	root := healthyTree(t)
	if err := os.Remove(filepath.Join(root, "super", "heartbeat", "0000000042.hb")); err != nil {
		t.Fatal(err)
	}
	expectRefuse(t, testGate(root), "empty heartbeat folder")
	writeRaw(t, filepath.Join(root, "super", "heartbeat", "0000000043.hb.tmp"), heartbeatLine("super", 43, gateNow.Format("2006-01-02T15:04:05Z"), false))
	expectRefuse(t, testGate(root), "only a staging file")
	if err := os.RemoveAll(filepath.Join(root, "super", "heartbeat")); err != nil {
		t.Fatal(err)
	}
	expectRefuse(t, testGate(root), "no heartbeat folder")
	if err := os.RemoveAll(filepath.Join(root, "super")); err != nil {
		t.Fatal(err)
	}
	expectRefuse(t, testGate(root), "no super store")
}

func TestGateRefusesUnparseableHeartbeat(t *testing.T) {
	fresh := gateNow.Format("2006-01-02T15:04:05Z")
	good := heartbeatLine("super", 43, fresh, false)
	cases := map[string]string{
		"truncated":         good[:len(good)/2],
		"empty":             "",
		"wrong marker":      `{"kind":"halt","version":1}` + "\n",
		"whitespace prefix": `{ "kind":"heartbeat"` + good[len(`{"kind":"heartbeat"`):],
		"wrong observer":    heartbeatLine("tunnel", 43, fresh, false),
		"wrong sequence":    heartbeatLine("super", 44, fresh, false),
		"version 2":         strings.Replace(good, `"version":1`, `"version":2`, 1),
		"extra key":         strings.Replace(good, `"stop":false`, `"stop":false,"x":1`, 1),
		"missing key":       strings.Replace(good, `,"boot":null`, ``, 1),
		"wrong type":        strings.Replace(good, `"sequence":43`, `"sequence":"43"`, 1),
		"bad timestamp":     strings.Replace(good, fresh, "2026-09-24 10:07:00", 1),
		"bad observed set":  strings.Replace(good, `"tunnel":null`, `"web":null`, 1),
		"trailing bytes":    good + "x",
		"two objects":       good + good,
		"bom":               "\xEF\xBB\xBF" + good,
		"duplicate key":     strings.Replace(good, `"stop":false`, `"stop":false,"stop":false`, 1),
		"null previous >1":  strings.Replace(good, previousFor(43), "null", 1),
		"stop true":         heartbeatLine("super", 43, fresh, true),
		"cadence 0":         strings.Replace(good, `"cadence_seconds":1`, `"cadence_seconds":0`, 1),
	}
	for name, content := range cases {
		root := healthyTree(t)
		writeRaw(t, filepath.Join(root, "super", "heartbeat", "0000000043.hb"), content)
		d := expectRefuse(t, testGate(root), name)
		if !strings.Contains(d.Reason, "0000000043.hb") {
			t.Errorf("%s: reason must name the heartbeat: %s", name, d.Reason)
		}
	}
}

func TestGateRefusesOversizedHeartbeat(t *testing.T) {
	root := healthyTree(t)
	g := testGate(root)
	g.MaxHeartbeatBytes = 64
	expectRefuse(t, g, "oversized")
}

func TestGateRefusesStrayEntriesInHeartbeatFolder(t *testing.T) {
	root := healthyTree(t)
	writeRaw(t, filepath.Join(root, "super", "heartbeat", "latest"), "x")
	expectRefuse(t, testGate(root), "stray file")
	root = healthyTree(t)
	if err := os.Mkdir(filepath.Join(root, "super", "heartbeat", "0000000050.hb"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectRefuse(t, testGate(root), "directory named like a heartbeat")
}

func TestGateRefusesUnreadableTree(t *testing.T) {
	g := testGate(filepath.Join(t.TempDir(), "missing"))
	expectRefuse(t, g, "missing root")

	root := healthyTree(t)
	if err := os.RemoveAll(filepath.Join(root, "material")); err != nil {
		t.Fatal(err)
	}
	expectRefuse(t, testGate(root), "missing member store")

	root = healthyTree(t)
	if err := os.RemoveAll(filepath.Join(root, "admin", "halts")); err != nil {
		t.Fatal(err)
	}
	expectRefuse(t, testGate(root), "halts folder cannot be listed")

	root = healthyTree(t)
	if err := os.RemoveAll(filepath.Join(root, "tunnel", "halts")); err != nil {
		t.Fatal(err)
	}
	writeRaw(t, filepath.Join(root, "tunnel", "halts"), "x")
	expectRefuse(t, testGate(root), "halts is a file")

	root = healthyTree(t)
	if err := os.Mkdir(filepath.Join(root, "tunnel", "halts", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectRefuse(t, testGate(root), "subdirectory in halts")

	root = healthyTree(t)
	if err := os.Mkdir(filepath.Join(root, "tunnel", "halt"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectRefuse(t, testGate(root), "halt is a directory")
}

// A root or a store that is not a directory is refused by the reads under
// it: a regular file in its place, or a link to nothing.
func TestGateRefusesARootOrStoreThatIsNotADirectory(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "stores")
		writeRaw(t, file, "x")
		expectRefuse(t, testGate(file), "root is a file")
		for _, m := range []string{"admin", "material", "super", "tunnel"} {
			root := healthyTree(t)
			if err := os.RemoveAll(filepath.Join(root, m)); err != nil {
				t.Fatal(err)
			}
			writeRaw(t, filepath.Join(root, m), "x")
			d := expectRefuse(t, testGate(root), m+" store is a file")
			if !strings.Contains(d.Reason, m+"/") {
				t.Fatalf("%s store is a file: the reason must name the store: %s", m, d.Reason)
			}
		}
	})
	t.Run("dangling link", func(t *testing.T) {
		dangling := filepath.Join(t.TempDir(), "stores")
		danglingLink(t, dangling)
		expectRefuse(t, testGate(dangling), "root is a dangling link")
		for _, m := range []string{"admin", "material", "super", "tunnel"} {
			root := healthyTree(t)
			if err := os.RemoveAll(filepath.Join(root, m)); err != nil {
				t.Fatal(err)
			}
			danglingLink(t, filepath.Join(root, m))
			d := expectRefuse(t, testGate(root), m+" store is a dangling link")
			if !strings.Contains(d.Reason, m+"/") {
				t.Fatalf("%s store is a dangling link: the reason must name the store: %s", m, d.Reason)
			}
		}
	})
}

// danglingLink makes link a link to a directory that does not exist: a
// symbolic link, or on Windows without the privilege for one a junction,
// which needs none.
func danglingLink(t *testing.T, link string) {
	t.Helper()
	target := filepath.Join(filepath.Dir(link), "nothing")
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	if runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	if out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); jerr != nil {
		t.Skipf("neither a symbolic link (%v) nor a junction (%v: %s) can be made here", err, jerr, out)
	}
}

func TestGateRefusesBadConfiguration(t *testing.T) {
	root := healthyTree(t)
	g := testGate(root)
	g.MaxHeartbeatAge = 0
	expectRefuse(t, g, "zero max age")
	// An empty root is not the working directory, even one that holds a
	// healthy tree.
	t.Chdir(root)
	g = testGate(root)
	g.Root = ""
	expectRefuse(t, g, "no root")
	g = testGate(root)
	g.Members = nil
	expectRefuse(t, g, "no members")
	g = testGate(root)
	g.Coordinator = "boss"
	expectRefuse(t, g, "coordinator not a member")
	g = testGate(root)
	g.Now = nil
	expectRefuse(t, g, "no clock")
	g = testGate(root)
	g.MaxHeartbeatBytes = 0
	expectRefuse(t, g, "no size bound")
}

func TestGateWalksMembersInIdentityOrder(t *testing.T) {
	root := healthyTree(t)
	writeRaw(t, filepath.Join(root, "tunnel", "halt"), "")
	writeRaw(t, filepath.Join(root, "admin", "halts", "super"), "")
	d := expectRefuse(t, testGate(root), "two halts")
	if !strings.Contains(d.Reason, "admin/halts/super") {
		t.Fatalf("the first finding in identity order is reported: %s", d.Reason)
	}
}

func TestGateReasonOnServe(t *testing.T) {
	root := healthyTree(t)
	d := testGate(root).Check()
	if !d.Serve || !strings.Contains(d.Reason, "0000000042.hb") {
		t.Fatalf("a serve decision names the heartbeat it rests on: %#v", d)
	}
}

// TestGateHeartbeatRewrittenInPlaceIsReparsed: the same gate instance
// judges the same heartbeat file rewritten with different bytes of the
// same size: a stale timestamp refuses, a one-byte corruption refuses, the
// original bytes serve again. The bytes are read and hashed on every
// Check; the parse of identical bytes is what is reused.
func TestGateHeartbeatRewrittenInPlaceIsReparsed(t *testing.T) {
	root := healthyTree(t)
	g := testGate(root)
	expectServe(t, g, "healthy tree")
	path := filepath.Join(root, "super", "heartbeat", "0000000042.hb")
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fresh := gateNow.Add(-2 * time.Second).Format("2006-01-02T15:04:05Z")
	stale := gateNow.Add(-2*time.Second - 10*365*24*time.Hour).Format("2006-01-02T15:04:05Z")
	if len(stale) != len(fresh) || !strings.Contains(string(good), fresh) {
		t.Fatalf("test setup: %q %q", fresh, stale)
	}
	rewrites := map[string][]byte{
		"stale, same size":     []byte(strings.Replace(string(good), fresh, stale, 1)),
		"corrupted, same size": []byte(strings.Replace(string(good), `"stop":false`, `"stop":fals3`, 1)),
		"stop true, same size": []byte(strings.Replace(string(good), `"stop":false`, `"stop":true `, 1)),
		"wrong seq, same size": []byte(strings.Replace(string(good), `"sequence":42`, `"sequence":43`, 1)),
	}
	for name, content := range rewrites {
		if len(content) != len(good) {
			t.Fatalf("%s: %d bytes, the original has %d", name, len(content), len(good))
		}
		writeRaw(t, path, string(content))
		d := expectRefuse(t, g, name)
		if !strings.Contains(d.Reason, "0000000042.hb") {
			t.Fatalf("%s: reason must name the heartbeat: %s", name, d.Reason)
		}
		writeRaw(t, path, string(good))
		expectServe(t, g, name+", restored")
	}
}

// TestGateHeartbeatParseIsReusedForIdenticalBytes: identical bytes on a
// later Check are not parsed again and give the same decision; the age is
// judged afresh on every call, so the cached parse refuses once the clock
// has moved past the window; different bytes are parsed again.
func TestGateHeartbeatParseIsReusedForIdenticalBytes(t *testing.T) {
	root := healthyTree(t)
	g := testGate(root)
	expectServe(t, g, "first check")
	first := g.parsed
	if !first.valid || first.hb == nil || first.err != nil {
		t.Fatalf("the first check must remember its parse: %+v", first)
	}
	expectServe(t, g, "second check")
	if g.parsed.hb != first.hb {
		t.Fatal("identical bytes must reuse the parsed heartbeat")
	}
	// The clock moves past the window: the cached parse is judged afresh.
	g.Now = func() time.Time { return gateNow.Add(time.Minute) }
	d := expectRefuse(t, g, "stale by the clock")
	if !strings.Contains(d.Reason, "stale") {
		t.Fatalf("want a stale refusal, got %s", d.Reason)
	}
	if g.parsed.hb != first.hb {
		t.Fatal("the clock does not change the bytes: the parse is still the remembered one")
	}
	g.Now = func() time.Time { return gateNow }
	// A newer heartbeat is different bytes under a different name: parsed anew.
	writeHB(t, root, "super", 43, gateNow.Add(-time.Second).Format("2006-01-02T15:04:05Z"), false)
	expectServe(t, g, "newer heartbeat")
	if g.parsed.hb == first.hb || g.parsed.seq != 43 {
		t.Fatal("different bytes must be parsed anew")
	}
	// A parse error is remembered like a result: the same bad bytes give
	// the same refusal without a second parse, and good bytes clear it.
	writeRaw(t, filepath.Join(root, "super", "heartbeat", "0000000043.hb"), "{")
	expectRefuse(t, g, "unparseable")
	bad := g.parsed
	expectRefuse(t, g, "unparseable again")
	if g.parsed.err != bad.err || bad.err == nil {
		t.Fatal("the same bad bytes must give the remembered error")
	}
	writeHB(t, root, "super", 43, gateNow.Add(-time.Second).Format("2006-01-02T15:04:05Z"), false)
	expectServe(t, g, "good bytes again")
}
