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
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/open-policy-agent/opa/v1/rego"
)

// readFile reads the policy file, once per load (a seam for tests).
var readFile = os.ReadFile

type filePolicy struct {
	// Path to policy file
	policyPath string

	// Query to run on eval
	policyQuery string

	// loaded is the prepared query and the file's bytes it was compiled
	// from, stored together by a successful load.
	loaded atomic.Pointer[loadedPolicy]
}

// loadedPolicy is one successful load: the query prepared from data, the
// policy file's bytes exactly as they were read, once.
type loadedPolicy struct {
	query rego.PreparedEvalQuery
	data  []byte
}

// FilePolicy is a Policy loaded from one file that can say which bytes the
// query in use was compiled from.
type FilePolicy interface {
	// LoadedFile returns the path and the bytes of the file the query in
	// use was prepared from, exactly as the last successful load read them.
	LoadedFile() (path string, data []byte)
}

// LoadedFileOf is p's LoadedFile, or false for a policy that is not a
// FilePolicy (WrapForTest) or is nil.
func LoadedFileOf(p Policy) (path string, data []byte, ok bool) {
	if f, isFile := p.(FilePolicy); isFile {
		path, data = f.LoadedFile()
		return path, data, true
	}
	return "", nil, false
}

// LoadFromPath creates a reloadable policy from a rego file.
func LoadFromPath(policyPath, policyQuery string) (Policy, error) {
	p := filePolicy{
		policyPath:  policyPath,
		policyQuery: policyQuery,
	}
	err := p.Reload()
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Reload transparently reloads the policy. The file is read once, and the
// query is prepared from those bytes, which LoadedFile then returns. A
// path OPA's loader refuses to read, a UNC path, is refused before any
// read, as is a URL: the bytes are read from the path as given.
func (p *filePolicy) Reload() error {
	if isUNC(p.policyPath) {
		return fmt.Errorf("UNC path read is not allowed: %s", p.policyPath)
	}
	if strings.Contains(p.policyPath, "://") {
		return fmt.Errorf("a URL is not a policy path: %s", p.policyPath)
	}
	data, err := readFile(p.policyPath)
	if err != nil {
		return err
	}
	peq, err := Prepare(p.policyPath, p.policyQuery, data)
	if err != nil {
		return err
	}

	p.loaded.Store(&loadedPolicy{query: peq, data: data})
	return nil
}

// Prepare prepares query from the bytes of the policy file at path, read
// by the caller, with no further read. A .rego file is a Rego v0 module
// parsed with annotations processed, as rego.Load parses one; anything
// else is a bundle tarball, read as rego.LoadBundle reads a bundle file.
// A bundle directory is many files and cannot be one read: reading it is
// an error before Prepare is reached.
func Prepare(path, query string, data []byte) (rego.PreparedEvalQuery, error) {
	var r *rego.Rego
	if strings.HasSuffix(path, ".rego") {
		// For backwards compatibility with old versions of Ghostunnel,
		// we load Rego files as v0 policies. This may change in the future.
		mod, err := ast.ParseModuleWithOpts(path, string(data), ast.ParserOptions{RegoVersion: ast.RegoV0, ProcessAnnotation: true})
		if err != nil {
			return rego.PreparedEvalQuery{}, err
		}
		r = rego.New(
			rego.Query(query),
			rego.ParsedModule(mod),
			rego.SetRegoVersion(ast.RegoV0),
		)
	} else {
		// In newer version of Ghostunnel, we recommend loading policies
		// via a bundle. This allows bundling data and policy files as well
		// specifying the Rego version (v0 or v1) in the bundle manifest.
		// The options are rego.LoadBundle's for a rego.New without any.
		b, err := loader.NewFileLoader().
			WithReader(bytes.NewReader(data)).
			WithProcessAnnotation(true).
			WithBundleLazyLoadingMode(bundle.HasExtension()).
			WithSkipBundleVerification(false).
			WithRegoVersion(ast.RegoUndefined).
			AsBundle(path)
		if err != nil {
			return rego.PreparedEvalQuery{}, fmt.Errorf("loading error: %s", err)
		}
		r = rego.New(
			rego.Query(query),
			rego.ParsedBundle(path, b),
		)
	}
	return r.PrepareForEval(context.Background())
}

// isUNC is OPA's loader's test for a UNC path (two leading slashes of
// either kind), which it never reads.
func isUNC(path string) bool {
	isSlash := func(c byte) bool { return c == '\\' || c == '/' }
	return len(path) > 1 && isSlash(path[0]) && isSlash(path[1])
}

// LoadedFile implements FilePolicy.
func (p *filePolicy) LoadedFile() (string, []byte) {
	return p.policyPath, p.loaded.Load().data
}

// Eval runs the underlying policy.
func (p *filePolicy) Eval(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error) {
	return p.loaded.Load().query.Eval(ctx, options...)
}
