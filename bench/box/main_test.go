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

package main

import "testing"

// TestShellWord: every argument reaches the remote shell as one word, a
// space or a quote inside it included, and a bare ~ or a leading ~/ still
// expands.
func TestShellWord(t *testing.T) {
	for in, want := range map[string]string{
		"/var/lib/ghostunnel-ring/benchwork": `'/var/lib/ghostunnel-ring/benchwork'`,
		"C:/Program Files/Git/var/lib":       `'C:/Program Files/Git/var/lib'`,
		"--warm-backend-connections 0":       `'--warm-backend-connections 0'`,
		"it's":                               `'it'\''s'`,
		"~/ghostunnel/bench":                 `~/'ghostunnel/bench'`,
		"~/":                                 `~/''`,
		"~":                                  `~`,
		"":                                   `''`,
	} {
		if got := shellWord(in); got != want {
			t.Errorf("shellWord(%q) = %s, want %s", in, got, want)
		}
	}
}

// TestCheckRemotePath: a path Git Bash rewrote into a Windows path is
// refused before anything runs; absolute and home-relative paths pass.
func TestCheckRemotePath(t *testing.T) {
	for _, ok := range []string{"", "/var/lib/ghostunnel-ring/benchwork", "~/ghostunnel", "~"} {
		if err := checkRemotePath(ok); err != nil {
			t.Errorf("checkRemotePath(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"C:/Program Files/Git/var/lib/ghostunnel-ring/benchwork", "relative/dir", `C:\work`} {
		if err := checkRemotePath(bad); err == nil {
			t.Errorf("checkRemotePath(%q) = nil, want an error", bad)
		}
	}
}
