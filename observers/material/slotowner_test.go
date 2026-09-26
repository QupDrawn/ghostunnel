package main

// slotowner_test.go proves the owner clause of procedure H (halts.go, SPEC
// 10.2 H7, I8): the mapping is parsed as -slot-owners is written, the rule
// over one entry names the file and what was found for every way the owner
// can fail to be the named member's account, and, in the cycle over a real
// store on this host, a slot named for a member whose account is not the
// file's owner is I8 on linux, every slot is I8 naming the OS elsewhere,
// an empty halts/ is clean everywhere, and the fixture harness's case (no
// mapping) evaluates nothing. Every member carries a byte-identical copy
// of this file.

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func TestParseSlotOwners(t *testing.T) {
	members := []string{"tunnel", "admin", "material", "super"}
	got, err := parseSlotOwners("tunnel=gtobs-tunnel, admin=gtobs-admin,material=gtobs-material,super=gtobs-super", members)
	if err != nil {
		t.Fatalf("full mapping: %v", err)
	}
	if len(got) != 4 || got["admin"] != "gtobs-admin" || got["super"] != "gtobs-super" {
		t.Fatalf("parsed %v", got)
	}
	bad := map[string]string{
		"empty":            "",
		"blank":            "  ",
		"missing member":   "tunnel=a,admin=b,material=c",
		"bad pair":         "tunnel=a,admin=b,material=c,super",
		"empty account":    "tunnel=a,admin=b,material=c,super=",
		"empty member":     "tunnel=a,admin=b,material=c,=d",
		"not a member":     "tunnel=a,admin=b,material=c,super=d,stranger=e",
		"named twice":      "tunnel=a,admin=b,material=c,super=d,tunnel=a",
		"one member twice": "tunnel=a,tunnel=b,admin=c,material=d",
	}
	for name, s := range bad {
		if m, err := parseSlotOwners(s, members); err == nil {
			t.Errorf("%s: %q parsed to %v", name, s, m)
		}
	}
}

// TestSlotOwnerRule is the rule over one entry, with the lookups injected,
// on every host: the subject names the entry and then the mismatch.
func TestSlotOwnerRule(t *testing.T) {
	owners := map[string]string{"admin": "gtobs-admin", "material": "gtobs-material", "super": ""}
	uidOf := func(name string) (uint32, error) {
		if name == "gtobs-admin" {
			return 1002, nil
		}
		return 0, errors.New("unknown " + name)
	}
	is := func(uid uint32) func() (uint32, error) { return func() (uint32, error) { return uid, nil } }
	fails := func(err error) func() (uint32, error) { return func() (uint32, error) { return 0, err } }
	unreached := func() (uint32, error) { t.Fatal("the owner was probed where the rule fails before it"); return 0, nil }
	cases := []struct {
		name  string
		rel   string
		w     string
		goos  string
		owner func() (uint32, error)
		want  string
	}{
		{"owned by the account", "tunnel/halts/admin", "admin", "linux", is(1002), ""},
		{"staging file owned by the account", "tunnel/halts/admin.tmp", "admin", "linux", is(1002), ""},
		{"owned by another uid", "tunnel/halts/admin", "admin", "linux", is(1003), "tunnel/halts/admin:owner:1003"},
		{"staging file owned by another uid", "tunnel/halts/admin.tmp", "admin", "linux", is(0), "tunnel/halts/admin.tmp:owner:0"},
		{"account unknown to the host", "tunnel/halts/material", "material", "linux", unreached, "tunnel/halts/material:no-account:gtobs-material"},
		{"member without an account", "tunnel/halts/super", "super", "linux", unreached, "tunnel/halts/super:unmapped"},
		{"member not in the mapping", "tunnel/halts/other", "other", "linux", unreached, "tunnel/halts/other:unmapped"},
		{"entry gone since the listing", "tunnel/halts/admin", "admin", "linux", fails(errSlotGone), ""},
		{"entry cannot be stat'ed", "tunnel/halts/admin", "admin", "linux", fails(errors.New("EIO")), "tunnel/halts/admin:unprobed"},
		{"no ownership on windows", "tunnel/halts/admin", "admin", "windows", unreached, "tunnel/halts/admin:unsupported-os:windows"},
		{"no ownership on darwin, even mapped and owned", "tunnel/halts/admin", "admin", "darwin", unreached, "tunnel/halts/admin:unsupported-os:darwin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := slotOwnerSubject(c.rel, c.w, owners, c.goos, uidOf, c.owner)
			if got != c.want {
				t.Fatalf("subject %q, want %q", got, c.want)
			}
		})
	}
}

// testAccount is the account this test runs as, by uid, as the host's
// account database names it; the files the test writes are owned by it.
// A linux host with no account for the test's uid cannot prove the rule
// and the test fails rather than skips. Off linux the rule fails on the
// OS before it consults the mapping, so the name is never resolved and
// any name serves.
func testAccount(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		return "test-account"
	}
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Fatalf("no account for uid %d on this host: %v", os.Getuid(), err)
	}
	return u.Username
}

// otherAccount is an account of this host that is not the test's, when
// one of the usual ones exists; otherwise a name no host has, which the
// rule fails as no-account. Either way the test's uid is wrong for it.
// Off linux, as testAccount, the name is never resolved.
func otherAccount(t *testing.T) (name string, exists bool) {
	t.Helper()
	if runtime.GOOS != "linux" {
		return "other-account", false
	}
	me := strconv.Itoa(os.Getuid())
	for _, cand := range []string{"root", "nobody", "daemon", "bin"} {
		if u, err := user.Lookup(cand); err == nil && u.Uid != me {
			return cand, true
		}
	}
	return "no-such-account-for-h7", false
}

// TestSlotOwnerInTheCycle writes, into the own halts/ of a healthy ring on
// this host, a slot named for admin, a slot named for material and a fresh
// staging file named for super, every one owned by the test's uid, and
// maps material and super to the test's account and admin to another. On
// linux the admin slot is I8 with the test's uid as the owner found (or
// the account as unknown, on a host with no second account), the others
// are clean, and the finding is the owner's own, in its fault, so the ring
// cannot report all clear while the slot stands. On any other OS every
// entry is I8 naming the OS. With no mapping nothing is evaluated, and
// with the mapping over an empty halts/ nothing fails on any OS.
func TestSlotOwnerInTheCycle(t *testing.T) {
	me := testAccount(t)
	other, otherExists := otherAccount(t)
	owners := map[string]string{"tunnel": me, "admin": other, "material": me, "super": me}

	// An empty halts/ is clean everywhere, mapping or no mapping.
	cfg, st, _ := fixtureCopy(t, "healthy-ring")
	cfg.SlotOwners = owners
	got, out := cycleFindings(t, cfg, st)
	if len(got) != 0 {
		t.Fatalf("healthy ring, empty halts/, mapping given, on %s: %v", runtime.GOOS, got)
	}
	if !contains(out.Publish.Checks, "I8") {
		t.Fatalf("checks %v do not list I8", out.Publish.Checks)
	}

	// Three entries the test's uid wrote under other members' names.
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	halts := filepath.Join(tmp, "stores", "tunnel", "halts")
	for _, w := range []string{"admin", "material"} {
		b, err := encodeHalt(&Halt{Observer: w, Reason: "I2", Sequence: 7, When: "2026-09-20T10:07:20Z", Detail: "d"})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(halts, w), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(halts, "super.tmp"), []byte("staging\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The fixture harness's case: no mapping, nothing evaluated; the slots
	// are in force and relayed, and nothing fails.
	cfg.SlotOwners = nil
	got, out = cycleFindings(t, cfg, st)
	if len(got) != 0 || !out.HaltInForceBefore {
		t.Fatalf("no mapping: findings %v, in force %v", got, out.HaltInForceBefore)
	}

	cfg.SlotOwners = owners
	got, out = cycleFindings(t, cfg, st)
	var want []string
	if runtime.GOOS == "linux" {
		adminSubject := fmt.Sprintf("tunnel/halts/admin:owner:%d", os.Getuid())
		if !otherExists {
			adminSubject = "tunnel/halts/admin:no-account:" + other
		}
		want = []string{"I8(" + adminSubject + ")"}
	} else {
		want = []string{
			"I8(tunnel/halts/admin:unsupported-os:" + runtime.GOOS + ")",
			"I8(tunnel/halts/material:unsupported-os:" + runtime.GOOS + ")",
			"I8(tunnel/halts/super.tmp:unsupported-os:" + runtime.GOOS + ")",
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("findings %v, want %v", got, want)
	}
	if !out.HaltInForceBefore {
		t.Fatal("the forged slot is not in force")
	}
	if !out.Halt.Writes || out.Halt.Reason != "I8" {
		t.Fatalf("halt %+v does not name I8", out.Halt)
	}
	if len(out.Fault.Local) != len(want) || !out.Fault.Publish || out.Fault.Local[0].Check != "I8" {
		t.Fatalf("I8 is the owner's own finding and belongs in its fault: %+v", out.Fault)
	}
	if out.Clears != nil {
		t.Fatalf("the owner cleared %v while its own assertion fails", out.Clears.Removes)
	}
}
