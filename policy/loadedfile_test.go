/*-
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/compile"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// annotatedPolicyV0 is Rego v0 (a rule body with no if) whose decision
// depends on its own annotations: parsed as anything but a v0 module with
// annotations processed, it either fails to parse or allows nobody.
const annotatedPolicyV0 = `
package policy
import input

default allow := false

# METADATA
# title: allow foobar
allow {
    input.name == "foobar"
    rego.metadata.rule().title == "allow foobar"
}
`

// annotatedPolicyV1 is annotatedPolicyV0 in Rego v1, for a bundle.
const annotatedPolicyV1 = `
package policy

default allow := false

# METADATA
# title: allow foobar
allow if {
    input.name == "foobar"
    rego.metadata.rule().title == "allow foobar"
}
`

// allowAllPolicyV1 allows everyone, in Rego v1, for a bundle.
const allowAllPolicyV1 = `
package policy

default allow := true
`

// decisionInputs are the inputs the decisions are compared on.
var decisionInputs = []map[string]any{{"name": "foobar"}, {"name": "barfoo"}, {}}

// decisions evaluates eval on every decision input, the whole result set
// of each.
func decisions(t *testing.T, eval func(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error)) []rego.ResultSet {
	t.Helper()
	var out []rego.ResultSet
	for _, in := range decisionInputs {
		rs, err := eval(context.Background(), rego.EvalInput(in))
		require.NoError(t, err)
		out = append(out, rs)
	}
	return out
}

// buildBundle compiles the v1 policy module into a bundle tarball at path.
func buildBundle(t *testing.T, dir, path, module string) []byte {
	t.Helper()
	src := filepath.Join(dir, "src.rego")
	require.NoError(t, os.WriteFile(src, []byte(module), 0o644))
	var out bytes.Buffer
	require.NoError(t, compile.New().WithPaths(src).WithOutput(&out).WithRegoVersion(ast.RegoV1).Build(context.Background()))
	require.NoError(t, os.WriteFile(path, out.Bytes(), 0o644))
	return out.Bytes()
}

// TestPolicyLoadedFileIsTheBytesCompiled: the bytes a policy hands back are
// the file's as the last successful load read them, and the query in use is
// compiled from them: a rewrite on disk changes neither until a reload, a
// reload replaces both, a failed reload keeps both.
func TestPolicyLoadedFileIsTheBytesCompiled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.rego")
	first := []byte(allowFoobarPolicyV0)
	require.NoError(t, os.WriteFile(path, first, 0o644))
	p, err := LoadFromPath(path, "data.policy.allow")
	require.NoError(t, err)

	gotPath, data, ok := LoadedFileOf(p)
	require.True(t, ok)
	assert.Equal(t, path, gotPath)
	assert.Equal(t, first, data)

	second := []byte(allowAllPolicy)
	require.NoError(t, os.WriteFile(path, second, 0o644))
	_, data, _ = LoadedFileOf(p)
	assert.Equal(t, first, data, "a rewrite on disk is not a load")
	rs, err := p.Eval(context.Background(), rego.EvalInput(map[string]any{"name": "barfoo"}))
	require.NoError(t, err)
	assert.False(t, rs.Allowed(), "the query in use is still the first file's")

	require.NoError(t, p.Reload())
	_, data, _ = LoadedFileOf(p)
	assert.Equal(t, second, data)
	rs, err = p.Eval(context.Background(), rego.EvalInput(map[string]any{"name": "barfoo"}))
	require.NoError(t, err)
	assert.True(t, rs.Allowed(), "the reload's bytes are the query in use")

	require.NoError(t, os.WriteFile(path, []byte("package policy\nallow {"), 0o644))
	require.Error(t, p.Reload())
	_, data, _ = LoadedFileOf(p)
	assert.Equal(t, second, data, "a failed reload keeps the bytes in use")
	rs, err = p.Eval(context.Background(), rego.EvalInput(map[string]any{"name": "barfoo"}))
	require.NoError(t, err)
	assert.True(t, rs.Allowed(), "and the query compiled from them")

	_, _, ok = LoadedFileOf(WrapForTest(&rego.PreparedEvalQuery{}))
	assert.False(t, ok, "a wrapped query has no file")
	_, _, ok = LoadedFileOf(nil)
	assert.False(t, ok)
}

// TestPrepareAgreesWithAFreshCompile: the query prepared from the bytes of
// a .rego file decides exactly as the same bytes compiled afresh, both as
// rego.Load compiles the file and as the members compile the bytes they
// hash (a Rego v0 module parsed with annotations processed, given as a
// parsed module); for a bundle tarball, exactly as rego.LoadBundle compiles
// the file.
func TestPrepareAgreesWithAFreshCompile(t *testing.T) {
	dir := t.TempDir()
	query := "data.policy.allow"

	path := filepath.Join(dir, "policy.rego")
	data := []byte(annotatedPolicyV0)
	require.NoError(t, os.WriteFile(path, data, 0o644))
	prepared, err := Prepare(path, query, data)
	require.NoError(t, err)
	got := decisions(t, prepared.Eval)
	require.True(t, got[0].Allowed(), "the annotated rule allows foobar")
	require.False(t, got[1].Allowed())

	loaded, err := rego.New(rego.Query(query), rego.Load([]string{path}, nil), rego.SetRegoVersion(ast.RegoV0)).PrepareForEval(context.Background())
	require.NoError(t, err)
	assert.Equal(t, decisions(t, loaded.Eval), got, "as rego.Load compiles the file")

	mod, err := ast.ParseModuleWithOpts(path, string(data), ast.ParserOptions{RegoVersion: ast.RegoV0, ProcessAnnotation: true})
	require.NoError(t, err)
	member, err := rego.New(rego.Query(query), rego.ParsedModule(mod), rego.SetRegoVersion(ast.RegoV0)).PrepareForEval(context.Background())
	require.NoError(t, err)
	assert.Equal(t, decisions(t, member.Eval), got, "as the members compile the bytes")

	bundlePath := filepath.Join(dir, "policy.tar.gz")
	tarball := buildBundle(t, dir, bundlePath, annotatedPolicyV1)
	prepared, err = Prepare(bundlePath, query, tarball)
	require.NoError(t, err)
	got = decisions(t, prepared.Eval)
	require.True(t, got[0].Allowed())
	require.False(t, got[1].Allowed())
	// rego.LoadBundle leaves the bundle file open, which Windows will not
	// remove under it: that copy is in a directory removed best effort.
	leaked, err := os.MkdirTemp("", "policy-loadbundle")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(leaked) })
	copyPath := filepath.Join(leaked, "policy.tar.gz")
	require.NoError(t, os.WriteFile(copyPath, tarball, 0o644))
	fromPath, err := rego.New(rego.Query(query), rego.LoadBundle(copyPath)).PrepareForEval(context.Background())
	require.NoError(t, err)
	assert.Equal(t, decisions(t, fromPath.Eval), got, "as rego.LoadBundle compiles the bundle file")
}

// malformedMetadataPolicy is a policy whose METADATA block is not YAML:
// refused where annotations are processed at parse, loaded where they are
// not (the compiler parses them only for a rego.metadata call).
const malformedMetadataPolicy = `
package policy

# METADATA
# title: [unclosed
allow := true
`

// tarball is a bundle tarball holding the given files, by path.
func tarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// TestPrepareRefusesWhatAFreshCompileRefuses: a policy the file loaders
// refuse (annotations that do not parse) is refused by Prepare too, for a
// .rego file and for a bundle, so a query is never prepared from bytes the
// members could not compile.
func TestPrepareRefusesWhatAFreshCompileRefuses(t *testing.T) {
	dir := t.TempDir()
	query := "data.policy.allow"

	path := filepath.Join(dir, "policy.rego")
	require.NoError(t, os.WriteFile(path, []byte(malformedMetadataPolicy), 0o644))
	_, err := rego.New(rego.Query(query), rego.Load([]string{path}, nil), rego.SetRegoVersion(ast.RegoV0)).PrepareForEval(context.Background())
	require.Error(t, err, "rego.Load refuses the file")
	_, err = ast.ParseModuleWithOpts(path, malformedMetadataPolicy, ast.ParserOptions{RegoVersion: ast.RegoV0, ProcessAnnotation: true})
	require.Error(t, err, "the members refuse the bytes")
	_, err = Prepare(path, query, []byte(malformedMetadataPolicy))
	assert.Error(t, err)

	data := tarball(t, map[string]string{"/policy.rego": malformedMetadataPolicy})
	leaked, err := os.MkdirTemp("", "policy-loadbundle")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(leaked) })
	bundlePath := filepath.Join(leaked, "policy.tar.gz")
	require.NoError(t, os.WriteFile(bundlePath, data, 0o644))
	_, err = rego.New(rego.Query(query), rego.LoadBundle(bundlePath)).PrepareForEval(context.Background())
	require.Error(t, err, "rego.LoadBundle refuses the bundle")
	_, err = Prepare(bundlePath, query, data)
	assert.Error(t, err)

	// The same bundle with a module that parses is loaded, so the refusal
	// above is the annotations'.
	good := tarball(t, map[string]string{"/policy.rego": allowFoobarPolicyV1})
	prepared, err := Prepare(bundlePath, query, good)
	require.NoError(t, err)
	rs, err := prepared.Eval(context.Background(), rego.EvalInput(map[string]any{"name": "foobar"}))
	require.NoError(t, err)
	assert.True(t, rs.Allowed())
}

// TestPolicyBundleIsOneRead: a bundle tarball is loaded from the one read
// of its file, which is what the policy hands back and what it decides
// from; a rewrite on disk changes neither until a reload.
func TestPolicyBundleIsOneRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.tar.gz")
	first := buildBundle(t, dir, path, allowFoobarPolicyV1)
	p, err := LoadFromPath(path, "data.policy.allow")
	require.NoError(t, err)
	_, data, ok := LoadedFileOf(p)
	require.True(t, ok)
	assert.Equal(t, first, data)

	second := buildBundle(t, dir, path, "package policy\ndefault allow := true\n")
	_, data, _ = LoadedFileOf(p)
	assert.Equal(t, first, data)
	rs, err := p.Eval(context.Background(), rego.EvalInput(map[string]any{"name": "barfoo"}))
	require.NoError(t, err)
	assert.False(t, rs.Allowed())
	require.NoError(t, p.Reload())
	_, data, _ = LoadedFileOf(p)
	assert.Equal(t, second, data)
	rs, err = p.Eval(context.Background(), rego.EvalInput(map[string]any{"name": "barfoo"}))
	require.NoError(t, err)
	assert.True(t, rs.Allowed())
}

// swapAfterRead makes the policy file read return the file's bytes and
// then rewrites the file with swapped, for the rest of the test: the window
// between the read and the compile.
func swapAfterRead(t *testing.T, swapped string) {
	t.Helper()
	orig := readFile
	t.Cleanup(func() { readFile = orig })
	readFile = func(path string) ([]byte, error) {
		data, err := orig(path)
		require.NoError(t, os.WriteFile(path, []byte(swapped), 0o644))
		return data, err
	}
}

// TestPolicyCompilesTheBytesItRead: the query is compiled from the bytes
// the load read, and those are the bytes handed back, even when the file
// is rewritten between the read and the compile; for a .rego file and for
// a bundle.
func TestPolicyCompilesTheBytesItRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.rego")
	first := []byte(allowFoobarPolicyV0)
	require.NoError(t, os.WriteFile(path, first, 0o644))
	swapAfterRead(t, allowAllPolicy)
	p, err := LoadFromPath(path, "data.policy.allow")
	require.NoError(t, err)
	_, data, _ := LoadedFileOf(p)
	assert.Equal(t, first, data)
	rs, err := p.Eval(context.Background(), rego.EvalInput(map[string]any{"name": "barfoo"}))
	require.NoError(t, err)
	assert.False(t, rs.Allowed(), "compiled from the bytes read, not from the file as rewritten")

	bundlePath := filepath.Join(dir, "policy.tar.gz")
	tarball := buildBundle(t, dir, bundlePath, allowFoobarPolicyV1)
	allowAll := buildBundle(t, t.TempDir(), filepath.Join(t.TempDir(), "all.tar.gz"), allowAllPolicyV1)
	swapAfterRead(t, string(allowAll))
	p, err = LoadFromPath(bundlePath, "data.policy.allow")
	require.NoError(t, err)
	_, data, _ = LoadedFileOf(p)
	assert.Equal(t, tarball, data)
	rs, err = p.Eval(context.Background(), rego.EvalInput(map[string]any{"name": "barfoo"}))
	require.NoError(t, err)
	assert.False(t, rs.Allowed(), "the bundle is compiled from the bytes read")
}

// TestPolicyRefusesWhatIsNotOneFile: a bundle directory is many files and
// is refused, as is a UNC path, which OPA's loader never reads, and a URL;
// neither of the last two is read at all.
func TestPolicyRefusesWhatIsNotOneFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(allowFoobarPolicyV1), 0o644))
	_, err := LoadFromPath(dir, "data.policy.allow")
	assert.Error(t, err, "a bundle directory is not loaded")

	orig := readFile
	t.Cleanup(func() { readFile = orig })
	readFile = func(path string) ([]byte, error) {
		t.Errorf("%s was read", path)
		return nil, errors.New("not read, for test")
	}
	_, err = LoadFromPath(`\\server\share\policy.rego`, "data.policy.allow")
	assert.ErrorContains(t, err, "UNC path")
	_, err = LoadFromPath("//server/share/policy.rego", "data.policy.allow")
	assert.ErrorContains(t, err, "UNC path")
	_, err = LoadFromPath("file://"+filepath.ToSlash(filepath.Join(dir, "policy.rego")), "data.policy.allow")
	assert.ErrorContains(t, err, "URL")
}
