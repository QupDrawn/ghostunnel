//go:build !linux

/*-
 * Copyright 2024, Ghostunnel
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

package main

import "github.com/ghostunnel/ghostunnel/ringtrace"

// setupSandbox is the process sandbox attempt on a build with no sandbox
// facility: there is nothing to attempt, whatever the flags, and the state
// is unsupported. Ghostunnel then starts only under --accept-no-sandbox
// naming this OS (validateSandboxAcceptance). A platform that gains a
// sandbox (a landlock_windows.go, say) replaces this file with an attempt
// that returns applied or failed, and nothing else has to change: the
// acceptance is refused and the start line reports the outcome from the
// state alone.
func setupSandbox(pkcs11Enabled bool) string {
	return ringtrace.SandboxUnsupported
}

func setupLandlock() error {
	return nil
}
