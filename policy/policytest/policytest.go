/*-
 * Copyright 2026 Ghostunnel contributors
 *
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

// Package policytest adapts a prepared query to policy.Policy for tests. It is
// imported only by test files, so it is never linked into the proxy.
package policytest

import (
	"context"

	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/open-policy-agent/opa/v1/rego"
)

type wrappedPolicy struct {
	wrapped *rego.PreparedEvalQuery
}

// Wrap creates a policy from a prepared query. The policy cannot reload.
func Wrap(query *rego.PreparedEvalQuery) policy.Policy {
	return &wrappedPolicy{query}
}

// Reload does nothing: a wrapped query has no file to reload from.
func (w *wrappedPolicy) Reload() error {
	return nil
}

// Eval runs the wrapped query.
func (w *wrappedPolicy) Eval(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error) {
	return w.wrapped.Eval(ctx, options...)
}
