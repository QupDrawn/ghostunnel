#!/usr/bin/env bash
# check-units.sh: verify the ghostunnel observer ring deployment against its
# write matrix. Stages, each selectable, each independent:
#
#   --static     any host, no root. Parse every unit under systemd/: every
#                non-comment line is [Section] or Key=Value; the User=,
#                ReadWritePaths= and ReadOnlyPaths= sets equal the writer's
#                rows of write-matrix.tsv exactly; every path is in tree.tsv
#                with an owner, group and mode that give that writer and only
#                that writer the directory; ExecStart carries the required
#                flags; the cadence contract holds (every heartbeat-max-age
#                and ghostunnel's --ring-heartbeat-max-age exceed super's
#                cadence; any --ring-tick is below it; every member's
#                -tick-max-age, passed or default, is at least twice the
#                tick in force and the same on all four; admin, material
#                and super judge the tunnel surface with tunnel's own
#                -lifetime-margin and -acl-grace; every member's
#                -slot-owners is the User= of each member's unit, one
#                string on all four; every member's -window, passed or
#                default, is the same on all four); the tunnel unit reads
#                observers.env and never ring.env, and passes
#                -expect-listen/-expect-target/-expect-acl (each tested
#                non-empty) and -expect-proxy-protocol= from it; the
#                material unit passes -expect-binary-sha256 from it (tested
#                non-empty); each of those flags and every -policy-query=
#                appears exactly once in its ExecStart;
#                ghostunnel.service reads ring.env only and carries
#                WatchdogSec=, which no member carries; no unit carries an
#                -accept-no-* flag; ghostunnel.service carries UMask=0027
#                (so what the emitter creates under gt/ lands 0750/0640) and
#                every member unit grants SupplementaryGroups=gtring-trace
#                (the group that reads gt/, which is gt:gtring-trace 2750);
#                the target wants all five. This is what ran on the
#                authoring host.
#   --verify     Linux, units installed: each installed unit is byte for
#                byte the one under systemd/ (the install copies them
#                verbatim), and systemd-analyze verify passes on each.
#   --tree       Linux, root: walk tree.tsv and compare owner:group:mode;
#                check the halts/ groups' membership, and that gtring-pem
#                holds the five and gtring-trace exactly the four observers
#                (never gt, and no account's primary group); check that the copy
#                the members read (/etc/ghostunnel/tree.tsv) is this file;
#                check the owner, group and mode of every file under
#                /etc/ghostunnel against the README (the key ring.env names
#                root:gt 0640, cert, CA and policy root:gtring-pem 0640,
#                the environment files and the tree root:root 0644, any
#                other PEM root's with nothing for other); check that
#                /proc is not mounted hidepid in a way that hides
#                ghostunnel from gtobs-admin.
#   --probe      Linux, root, ring stopped: the DAC write-boundary probe. As
#                each of the five users, attempt forbidden writes (another
#                member's store root and heartbeat/, gt/, the own halts/, a
#                copy it does not author, and rename-over / unlink / append of
#                another member's halts/ slot) and assert they are denied
#                (EACCES from the mode bits, EPERM from the sticky bit); then
#                permitted writes (own store, own heartbeat/, the copies it
#                authors, its own halts/ slot via <self>.tmp and rename) and
#                assert success. Then the read boundary of gt/: as nobody,
#                an account in no ring group, listing gt/ is denied, and as
#                each observer it succeeds. Then the forged slot: as each
#                member's user,
#                create a slot under another member's name in a third
#                member's halts/, which the DAC permits (no per-name create
#                permission exists), and prove that the kernel records the
#                creator and that the store's owner, run for one cycle from
#                its unit's binary, faults on it (I8) within that cycle; on
#                a scratch copy of the tree, so no file of the real stores
#                is written. Cleans up after itself; never touches a halt
#                file that already exists.
#   --namespace  Linux, root, ring stopped, systemd-run present: replay each
#                unit's sandbox lines with systemd-run and assert that a write
#                outside its ReadWritePaths= fails with EROFS (the namespace
#                layer, independent of the DAC) and a write inside succeeds.
#   --all        every stage above, in that order.
#
# Exit status 0 only if every selected stage passed.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
UNITS_DIR="$HERE/systemd"
MATRIX="$HERE/write-matrix.tsv"
TREE="$HERE/tree.tsv"
ROOT=/var/lib/ghostunnel-ring/stores
MEMBERS=(tunnel admin material super)
OBSERVER_USERS=(gtobs-tunnel gtobs-admin gtobs-material gtobs-super)
ALL_UNITS=(ghostunnel-ring.target ghostunnel.service ghostunnel-obs-tunnel.service ghostunnel-obs-admin.service ghostunnel-obs-material.service ghostunnel-obs-super.service)
PROBE_NAME=check-units.probe

FAILED=0
pass() { printf 'ok    %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; FAILED=1; }
note() { printf 'note  %s\n' "$*"; }
die()  { printf 'check-units.sh: %s\n' "$*" >&2; exit 2; }

# Join backslash-newline continuations, drop comments and blanks.
unit_lines() {
  sed -e ':a' -e '/\\$/N; s/\\\n//; ta' "$1" | sed -e 's/^[[:space:]]*//' | grep -v -e '^#' -e '^$' || true
}
# Values of one key, one per line, whitespace-split.
unit_values() { # file key
  unit_lines "$1" | awk -F= -v k="$2" '$1==k {sub("^[^=]*=",""); print}' | tr ' ' '\n' | grep -v '^$' || true
}
sorted() { sort -u; }
# "30s" or "2m" to seconds; anything else ("500ms", "1h", "30") is a
# failure, not a guess.
to_seconds() {
  case "$1" in
    *ms) return 1 ;;
    *m) [[ ${1%m} =~ ^[0-9]+$ ]] || return 1; echo $(( ${1%m} * 60 )) ;;
    *s) [[ ${1%s} =~ ^[0-9]+$ ]] || return 1; echo "${1%s}" ;;
    *)  return 1 ;;
  esac
}
tree_row() { awk -F'\t' -v p="$1" '$1==p {print $2 "\t" $3 "\t" $4}' "$TREE"; }
# The value after a flag in an ExecStart line, or "" when the flag is absent.
# The flag is matched with its leading space, so -lifetime-margin does not
# match inside -tunnel-lifetime-margin.
flag_value() { # exec_line flag
  local re; re=$(printf '%s' "$2" | sed 's/[][\\.*^$]/\\&/g')
  sed -n "s/.* $re \([^ ]*\).*/\1/p" <<<"$1"
}
# How many times a flag's name appears in an ExecStart line, in any
# spelling (-f, --f, -f=v). Go's flag package keeps the last value of a
# repeated flag, so a second occurrence would override the first.
flag_count() { # exec_line flag
  grep -o -- "$2" <<<"$1" | wc -l | tr -d ' '
}
# Fail unless each named flag appears exactly once in the ExecStart line.
flags_once() { # unit exec_line flag...
  local u=$1 line=$2 fl n; shift 2
  for fl in "$@"; do
    n=$(flag_count "$line" "$fl")
    [[ $n == 1 ]] || fail "$u: ExecStart carries $fl $n times; exactly once, or the last one wins"
  done
}
# The mapping every member judges the owner of its halts/ entries by (SPEC
# 10.2 H7): member=account for each member, the account being the User= of
# that member's unit. Derived from the units so it is spelled once, there.
slot_owners_from_units() {
  local m u out=""
  for m in "${MEMBERS[@]}"; do
    u=$(unit_values "$UNITS_DIR/ghostunnel-obs-$m.service" User | head -1)
    [[ -n $u ]] || return 1
    out+="${out:+,}$m=$u"
  done
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
stage_static() {
  echo "== static: units against write-matrix.tsv and tree.tsv"
  [[ -r $MATRIX && -r $TREE ]] || die "write-matrix.tsv or tree.tsv missing"
  for u in "${ALL_UNITS[@]}"; do
    [[ -r $UNITS_DIR/$u ]] || fail "unit $u missing"
  done

  # 0. Every path in the matrix is a directory of tree.tsv, and its
  #    owner/group/mode give the writer that directory as the "how" says.
  while IFS=$'\t' read -r writer path grant how; do
    [[ -z $writer || $writer == \#* ]] && continue
    row=$(tree_row "$path")
    if [[ -z $row ]]; then fail "matrix: $path not in tree.tsv"; continue; fi
    IFS=$'\t' read -r owner group mode <<<"$row"
    [[ $grant == rw ]] || continue
    case "$how" in
      *"DAC owner, group gtring-trace reads"*)
        # The trace root: one writer, its owner; readable by the group of
        # readers and by nobody else, so 2750 (the setgid bit makes what gt creates inside inherit the group) and the group is gtring-trace.
        [[ $owner == "$writer" && $group == gtring-trace && $mode == 2750 ]] || fail "matrix: $path for $writer: want $writer:gtring-trace:2750, tree has $owner:$group:$mode" ;;
      *"DAC owner"*)
        [[ $owner == "$writer" && $mode == 0755 ]] || fail "matrix: $path for $writer: want $writer:*:0755, tree has $owner:$group:$mode" ;;
      *"root-owned sticky root"*)
        [[ $owner == root && $group == "$writer" && $mode == 1775 ]] || fail "matrix: $path for $writer: want root:$writer:1775, tree has $owner:$group:$mode" ;;
      *"DAC group gtring-halts-"*)
        store=${path#$ROOT/}; store=${store%/halts}
        [[ $owner == root && $group == "gtring-halts-$store" && $mode == 1775 ]] || fail "matrix: $path: want root:gtring-halts-$store:1775, tree has $owner:$group:$mode"
        [[ $writer != "gtobs-$store" ]] || fail "matrix: $path: the store owner is listed as a writer of its own halts/" ;;
      *) fail "matrix: $path for $writer: unrecognised enforcement '$how'" ;;
    esac
  done < "$MATRIX"
  pass "matrix rows have a tree.tsv directory with the enforcing owner:group:mode"

  # 1. tree.tsv sanity: parents listed first, modes are 0755, 1775 or 2750,
  #    every 1775 directory is root-owned (the sticky bit lets the directory
  #    owner remove anything, so it must be nobody who runs), and 0750 is
  #    the trace root alone: owned by gt, group gtring-trace.
  seen=()
  while IFS=$'\t' read -r path owner group mode; do
    [[ -z $path || $path == \#* ]] && continue
    parent=$(dirname "$path")
    if [[ $parent != /var/lib ]]; then
      printf '%s\n' "${seen[@]}" | grep -qx "$parent" || fail "tree: $path listed before its parent $parent"
    fi
    seen+=("$path")
    case "$mode" in
      0755) ;;
      1775) [[ $owner == root ]] || fail "tree: $path is 1775 but owned by $owner, not root" ;;
      2750) [[ $path == "$ROOT/gt" && $owner == gt && $group == gtring-trace ]] || fail "tree: $path is 2750; only the trace root $ROOT/gt is, as gt:gtring-trace (tree has $owner:$group)" ;;
      *) fail "tree: $path has mode $mode; only 0755, 1775 and 2750 (the trace root) are used" ;;
    esac
  done < "$TREE"
  row=$(tree_row "$ROOT/gt")
  [[ $row == $'gt\tgtring-trace\t2750' ]] || fail "tree: $ROOT/gt must be gt:gtring-trace 2750 (readable by the observers' group and nobody else); tree has '${row//$'\t'/:}'"
  pass "tree.tsv: parents first; modes 0755/1775, 2750 on the trace root alone; every 1775 directory is root's"

  # 2. Each unit. The proxy's tick cadence is read first: the members'
  #    -tick-max-age (passed or default) is checked against it and they are
  #    parsed before ghostunnel.service. Neither flag is passed by the
  #    shipped units; the defaults are the proxy's and the observers' own.
  #    The tunnel surface's values to be set are collected per member for
  #    the cross-unit comparison in 2g.
  super_cadence=""
  RING_TICK_DEFAULT=5; TICK_MAX_AGE_DEFAULT=30
  LIFETIME_MARGIN_DEFAULT=2s; ACL_GRACE_DEFAULT=2s; WINDOW_DEFAULT=3
  declare -A LM=() AG=() TMA=() WIN=()
  ring_tick=$RING_TICK_DEFAULT
  if [[ -r $UNITS_DIR/ghostunnel.service ]]; then
    gt_exec=$(unit_lines "$UNITS_DIR/ghostunnel.service" | grep '^ExecStart=' | head -1)
    if [[ $gt_exec == *"--ring-tick "* ]]; then
      ring_tick=$(to_seconds "$(sed -n 's/.*--ring-tick \([^ ]*\).*/\1/p' <<<"$gt_exec")") || ring_tick=""
    fi
  fi
  for u in ghostunnel-obs-super.service ghostunnel-obs-tunnel.service ghostunnel-obs-admin.service ghostunnel-obs-material.service ghostunnel.service; do
    f="$UNITS_DIR/$u"
    [[ -r $f ]] || continue
    # 2a. well-formed
    while IFS= read -r line; do
      [[ $line =~ ^\[[A-Za-z]+\]$ ]] && continue
      [[ $line =~ ^[A-Za-z][A-Za-z0-9]*=.*$ ]] || fail "$u: malformed line: $line"
    done < <(unit_lines "$f")
    # 2b. identity
    user=$(unit_values "$f" User); group=$(unit_values "$f" Group)
    [[ $(wc -l <<<"$user") -eq 1 && -n $user ]] || { fail "$u: exactly one User= required"; continue; }
    [[ $group == "$user" ]] || fail "$u: Group= must equal User= ($user)"
    # 2b'. the trace root's read boundary. gt/ is gt:gtring-trace 2750 and
    #      everything the emitter creates in it is 0750/0640 (directories 2750 by the root's setgid bit, group gtring-trace) under the
    #      proxy's umask, so ghostunnel.service must carry exactly
    #      UMask=0027 (0022 would leave a wider request readable by all;
    #      the emitter requests 0750/0640, and 0027 is what lets exactly
    #      that land and no more), and every member must be granted the
    #      group on the unit itself: a member without it cannot open the
    #      trace and halts on trace-readable; the static check refuses the
    #      unit first. gt is the owner and needs no group.
    umask_=$(unit_values "$f" UMask | tail -1)
    sgroups=$(unit_values "$f" SupplementaryGroups | sorted)
    if [[ $user == gt ]]; then
      [[ $umask_ == 0027 ]] && pass "$u: UMask=0027 (boot directories and chains/ land 0750, segments, lock and chain files 0640)" || fail "$u: UMask= must be exactly 0027 (have '${umask_:-none}'): the trace under gt/ must not be created readable by every account"
    else
      grep -qx gtring-trace <<<"$sgroups" && pass "$u: SupplementaryGroups= grants gtring-trace (reads gt/, which is gt:gtring-trace 2750)" || fail "$u: SupplementaryGroups= must grant gtring-trace, the group that reads the trace root gt/ (gt:gtring-trace 2750); without it the member cannot open the trace"
      [[ $umask_ == 0022 ]] || fail "$u: UMask= must be 0022 (have '${umask_:-none}'): a member's files are read by every other member and by ringstatus"
    fi
    # 2c. write grants equal the matrix
    have_rw=$(unit_values "$f" ReadWritePaths | sorted)
    want_rw=$(awk -F'\t' -v w="$user" '$1==w && $3=="rw" {print $2}' "$MATRIX" | sorted)
    if [[ $have_rw == "$want_rw" ]]; then
      pass "$u: ReadWritePaths= is exactly the $user rw rows ($(wc -l <<<"$have_rw") dirs)"
    else
      fail "$u: ReadWritePaths= differs from the matrix"; diff <(echo "$want_rw") <(echo "$have_rw") >&2 || true
    fi
    have_ro=$(unit_values "$f" ReadOnlyPaths | sorted)
    want_ro=$( { awk -F'\t' -v w="$user" '$1==w && $3=="ro" {print $2}' "$MATRIX"; echo "$ROOT"; } | sorted)
    if [[ $have_ro == "$want_ro" ]]; then
      pass "$u: ReadOnlyPaths= is the tree root plus the $user ro rows"
    else
      fail "$u: ReadOnlyPaths= differs from the matrix"; diff <(echo "$want_ro") <(echo "$have_ro") >&2 || true
    fi
    for p in $have_rw $have_ro; do
      [[ $p == /* ]] || fail "$u: $p is not absolute"
      [[ $p == "$ROOT" || $p == "$ROOT"/* ]] || fail "$u: $p is outside $ROOT"
      [[ -n $(tree_row "$p") ]] || fail "$u: $p is not a directory of tree.tsv"
    done
    # 2d. the sandbox lines the design rests on
    for kv in ProtectSystem=strict ProtectHome=yes PrivateTmp=yes NoNewPrivileges=yes Restart=on-failure PartOf=ghostunnel-ring.target WantedBy=ghostunnel-ring.target; do
      grep -qx "$kv" <(unit_lines "$f") || fail "$u: missing $kv"
    done
    case $u in
      ghostunnel-obs-admin.service)
        grep -qx "ProtectProc=default" <(unit_lines "$f") || fail "$u: admin must keep ProtectProc=default to read /proc/<pid>/cmdline" ;;
      ghostunnel-obs-tunnel.service|ghostunnel-obs-material.service)
        grep -qx "ProtectProc=default" <(unit_lines "$f") || fail "$u: must keep ProtectProc=default: boot-ambiguous stats /proc/<pid> of ghostunnel, which ProtectProc=invisible hides" ;;
    esac
    # 2e. flags and the cadence contract
    #     A continuation is a backslash at the end of a line and nothing
    #     else. The two characters backslash-n inside a line are not one:
    #     they reach the command as bytes, and a flag string after them is
    #     no flag. Refuse the sequence anywhere in the unit, and refuse any
    #     backslash left in ExecStart after the continuations are joined.
    grep -q '\\[nt]' "$f" && fail "$u: a literal backslash-n or backslash-t in the unit (a continuation that lost its line break)" || true
    exec_line=$(unit_lines "$f" | grep '^ExecStart=' | head -1)
    [[ $exec_line == *'\'* ]] && fail "$u: ExecStart holds a backslash after continuations are joined" || true
    if [[ $user == gt ]]; then
      for want in "--ring-traces $ROOT/gt" "--ring-stores $ROOT" "--ring-heartbeat-max-age " "--status "; do
        [[ $exec_line == *"$want"* ]] || fail "$u: ExecStart lacks '$want'"
      done
      grep -q 'ReadWritePaths=' "$f" && [[ $have_rw == "$ROOT/gt" ]] || fail "$u: gt may write gt/ and nothing else"
      age=$(sed -n 's/.*--ring-heartbeat-max-age \([^ ]*\).*/\1/p' <<<"$exec_line")
      secs=$(to_seconds "$age") || fail "$u: --ring-heartbeat-max-age '$age' is not Ns or Nm"
      if [[ -n $super_cadence && -n ${secs:-} ]]; then
        (( secs > super_cadence )) && pass "$u: --ring-heartbeat-max-age ${secs}s exceeds super's cadence ${super_cadence}s" || fail "$u: --ring-heartbeat-max-age ${secs}s must exceed super's cadence ${super_cadence}s"
      fi
      # --ring-tick: the tick line the members judge tick-fresh by. It must
      # be well below the members' cadence; absent, the default (5 s) is.
      if [[ $exec_line == *"--ring-tick "* ]]; then
        tick=$(sed -n 's/.*--ring-tick \([^ ]*\).*/\1/p' <<<"$exec_line")
        tsecs=$(to_seconds "$tick") || fail "$u: --ring-tick '$tick' is not Ns or Nm"
        if [[ -n ${tsecs:-} && -n $super_cadence ]]; then
          (( tsecs < super_cadence )) && pass "$u: --ring-tick ${tsecs}s is below super's cadence ${super_cadence}s" || fail "$u: --ring-tick ${tsecs}s must be below super's cadence ${super_cadence}s"
        fi
      else
        pass "$u: no --ring-tick; the default ${RING_TICK_DEFAULT}s is below super's cadence ${super_cadence:-?}s"
      fi
    else
      ident=${user#gtobs-}
      for want in "-identity $ident" "-stores $ROOT" "-traces $ROOT/gt" "-cadence " "-heartbeat-max-age " "-coordinator super" "-copy-authors tunnel=material,admin=tunnel,material=admin"; do
        [[ $exec_line == *"$want"* ]] || fail "$u: ExecStart lacks '$want'"
      done
      # -slot-owners: the account each member runs as, which every member
      # judges the owner of each entry of its own halts/ against (SPEC 10.2
      # H7). It must be the User= of each member's unit, every member
      # named, one string on all four: an account a member does not run as
      # would fault that member's every honest slot, and a member's real
      # account under another member's name would pass a slot it forged.
      so=$(flag_value "$exec_line" -slot-owners)
      want_so=$(slot_owners_from_units) || want_so=""
      if [[ -z $so ]]; then fail "$u: ExecStart lacks -slot-owners"
      elif [[ -z $want_so ]]; then fail "$u: -slot-owners cannot be checked: a member unit has no User="
      elif [[ $so == "$want_so" ]]; then pass "$u: -slot-owners is each member's User= ($so)"
      else fail "$u: -slot-owners '$so' is not the members' User= lines '$want_so'"; fi
      cad=$(sed -n 's/.*-cadence \([0-9]*\).*/\1/p' <<<"$exec_line")
      age=$(sed -n 's/.*-heartbeat-max-age \([^ ]*\).*/\1/p' <<<"$exec_line")
      secs=$(to_seconds "$age") || fail "$u: -heartbeat-max-age '$age' is not Ns or Nm"
      [[ -n $cad ]] || fail "$u: -cadence has no integer value"
      if [[ -n $cad && -n ${secs:-} ]]; then
        (( secs > cad )) && pass "$u: -heartbeat-max-age ${secs}s exceeds its -cadence ${cad}s" || fail "$u: -heartbeat-max-age ${secs}s must exceed -cadence ${cad}s"
        if [[ $ident == super ]]; then super_cadence=$cad; elif [[ -n $super_cadence ]]; then
          (( secs > super_cadence )) || fail "$u: -heartbeat-max-age ${secs}s must exceed super's cadence ${super_cadence}s"
        fi
      fi
      # -tick-max-age: how old the proxy's newest tick may be (tick-fresh)
      # and how far back accept-loop looks. The value in force, the
      # default when the flag is absent, must be at least twice the
      # --ring-tick in force, so that one tick late by a whole interval is
      # not yet a fault; and it is compared across the members in 2g.
      tma=$(flag_value "$exec_line" -tick-max-age)
      tsecs=""
      if [[ -n $tma ]]; then
        tsecs=$(to_seconds "$tma") || { fail "$u: -tick-max-age '$tma' is not Ns or Nm"; tsecs=""; }
        spelled="-tick-max-age $tma"
      else
        tma="${TICK_MAX_AGE_DEFAULT}s"; tsecs=$TICK_MAX_AGE_DEFAULT
        spelled="-tick-max-age absent (default $tma)"
      fi
      TMA[$ident]=$tma
      # -window: how many heartbeat entries each owner keeps (SPEC 6).
      # Every reader's chain test assumes the writer's window, so it is
      # compared across the members in 2g; absent stands for the default.
      n=$(flag_count "$exec_line" -window)
      (( n <= 1 )) || fail "$u: ExecStart carries -window $n times; at most once, or the last one wins"
      win=$(flag_value "$exec_line" -window)
      WIN[$ident]=${win:-$WINDOW_DEFAULT}
      if [[ -n $tsecs && -n $ring_tick ]]; then
        (( tsecs >= 2 * ring_tick )) && pass "$u: $spelled is at least twice --ring-tick ${ring_tick}s" || fail "$u: $spelled must be at least twice --ring-tick ${ring_tick}s"
      fi
      # The tunnel surface's margins: tunnel's own on the tunnel unit, the
      # -tunnel-* copies on the others; absent stands for the default.
      if [[ $ident == tunnel ]]; then
        lm=$(flag_value "$exec_line" -lifetime-margin); ag=$(flag_value "$exec_line" -acl-grace)
      else
        lm=$(flag_value "$exec_line" -tunnel-lifetime-margin); ag=$(flag_value "$exec_line" -tunnel-acl-grace)
      fi
      LM[$ident]=${lm:-$LIFETIME_MARGIN_DEFAULT}; AG[$ident]=${ag:-$ACL_GRACE_DEFAULT}
    fi
    # 2f. What each unit is fed, and what none may carry.
    #     The tunnel observer's expectations (-expect-listen, -expect-target,
    #     -expect-acl, -expect-proxy-protocol) are read from observers.env
    #     and never from ring.env: an expectation taken from the proxy's own
    #     configuration compares a value with itself. The check is on the
    #     whole file, comments included, so the unit cannot even name the
    #     proxy's file. The listener, target and ACL are tested non-empty
    #     before the start; the proxy protocol mode is passed with '=' and
    #     may be empty, which the member reads as off.
    envs=$(unit_values "$f" EnvironmentFile | sorted)
    case "$user" in
      gt)
        [[ $envs == /etc/ghostunnel/ring.env ]] || fail "$u: EnvironmentFile= must be exactly /etc/ghostunnel/ring.env"
        grep -q 'observers\.env' "$f" && fail "$u: names observers.env; the observer's expectation is not the proxy's input" || true
        wd=$(unit_values "$f" WatchdogSec | tail -1)
        [[ ${wd:-} =~ ^[1-9][0-9]*s?$ ]] && pass "$u: WatchdogSec=$wd (a wedged proxy is aborted and restarted)" || fail "$u: WatchdogSec= missing or not a positive count of seconds"
        ;;
      gtobs-tunnel)
        [[ $envs == /etc/ghostunnel/observers.env ]] || fail "$u: EnvironmentFile= must be exactly /etc/ghostunnel/observers.env"
        grep -q 'ring\.env' "$f" && fail "$u: names ring.env; the expected listener and ACL must not come from the proxy's own configuration" || true
        for v in GT_EXPECT_LISTEN GT_EXPECT_TARGET GT_EXPECT_ACL; do
          grep -qx "ExecStartPre=/usr/bin/test -n \"\${$v}\"" <(unit_lines "$f") || fail "$u: no ExecStartPre test -n for \${$v}"
        done
        [[ $exec_line == *'-expect-listen ${GT_EXPECT_LISTEN}'* ]] || fail "$u: ExecStart lacks '-expect-listen \${GT_EXPECT_LISTEN}'"
        [[ $exec_line == *'-expect-target ${GT_EXPECT_TARGET}'* ]] || fail "$u: ExecStart lacks '-expect-target \${GT_EXPECT_TARGET}'"
        [[ $exec_line == *'-expect-acl ${GT_EXPECT_ACL}'* ]] || fail "$u: ExecStart lacks '-expect-acl \${GT_EXPECT_ACL}'"
        [[ $exec_line == *'-expect-proxy-protocol=${GT_EXPECT_PROXY_PROTOCOL}'* ]] || fail "$u: ExecStart lacks '-expect-proxy-protocol=\${GT_EXPECT_PROXY_PROTOCOL}'"
        [[ $exec_line == *'-policy-query=${GT_EXPECT_POLICY_QUERY}'* ]] || fail "$u: ExecStart lacks '-policy-query=\${GT_EXPECT_POLICY_QUERY}'"
        flags_once "$u" "$exec_line" -expect-listen -expect-target -expect-acl -expect-proxy-protocol -policy-query
        pass "$u: expectations from observers.env only, each flag once (-expect-listen, -expect-target, -expect-acl, each tested non-empty; -expect-proxy-protocol= and -policy-query= may be empty; ring.env unnamed)"
        ;;
      *)
        # Every member re-judges the tunnel surface, so the policy query
        # (acl-substance) is read by all four from observers.env, the
        # operator's expectation; ring.env stays gt's alone.
        [[ $envs == /etc/ghostunnel/observers.env ]] || fail "$u: EnvironmentFile= must be exactly /etc/ghostunnel/observers.env (for GT_EXPECT_POLICY_QUERY)"
        grep -q 'ring\.env' "$f" && fail "$u: names ring.env; an observer's expectation must not come from the proxy's own configuration" || true
        [[ $exec_line == *'-policy-query=${GT_EXPECT_POLICY_QUERY}'* ]] || fail "$u: ExecStart lacks '-policy-query=\${GT_EXPECT_POLICY_QUERY}'"
        flags_once "$u" "$exec_line" -policy-query
        pass "$u: -policy-query= from observers.env once, the same variable as tunnel's; ring.env unnamed"
        # The material observer's binary-expected: the checksum the
        # operator expects of the proxy's executable, from observers.env,
        # tested non-empty before the start.
        if [[ $user == gtobs-material ]]; then
          grep -qx 'ExecStartPre=/usr/bin/test -n "${GT_EXPECT_BINARY_SHA256}"' <(unit_lines "$f") || fail "$u: no ExecStartPre test -n for \${GT_EXPECT_BINARY_SHA256}"
          [[ $exec_line == *'-expect-binary-sha256 ${GT_EXPECT_BINARY_SHA256}'* ]] || fail "$u: ExecStart lacks '-expect-binary-sha256 \${GT_EXPECT_BINARY_SHA256}'"
          flags_once "$u" "$exec_line" -expect-binary-sha256
          pass "$u: -expect-binary-sha256 once, from observers.env, tested non-empty"
        fi
        ;;
    esac
    if [[ $user != gt ]]; then
      grep -q '^WatchdogSec=' <(unit_lines "$f") && fail "$u: WatchdogSec= belongs on ghostunnel.service only; a member is judged by the ring, not by systemd" || true
    fi
    grep -q -e 'accept-no-store-check' -e 'accept-no-sandbox' <(unit_lines "$f") && fail "$u: carries an -accept-no-* flag; on Linux the facility exists and the flag must not appear" || true
  done
  pass "no unit carries -accept-no-store-check or -accept-no-sandbox; WatchdogSec= on ghostunnel.service only"

  # 2g. Every member judges the tunnel surface (surfaces.go), so the three
  #     judges must run with the tunnel member's own values, or the two
  #     disagree and the ring halts on a healthy proxy: admin, material and
  #     super's -tunnel-lifetime-margin / -tunnel-acl-grace equal tunnel's
  #     -lifetime-margin / -acl-grace, and -tick-max-age (tick-fresh's
  #     age and accept-loop's window) is the same on all four. Compared as
  #     spelled, an absent flag standing for its default spelling (2s, 2s,
  #     30s), so 2000ms against 2s is a failure to spell them alike, not a
  #     guess that they agree.
  if [[ -n ${LM[tunnel]:-} ]]; then
    for m in admin material super; do
      [[ -n ${LM[$m]:-} ]] || continue
      u="ghostunnel-obs-$m.service"
      if [[ ${LM[$m]} == "${LM[tunnel]}" && ${AG[$m]} == "${AG[tunnel]}" ]]; then
        pass "$u: -tunnel-lifetime-margin ${LM[$m]} and -tunnel-acl-grace ${AG[$m]} equal tunnel's -lifetime-margin and -acl-grace"
      else
        fail "$u: -tunnel-lifetime-margin ${LM[$m]} / -tunnel-acl-grace ${AG[$m]} differ from tunnel's -lifetime-margin ${LM[tunnel]} / -acl-grace ${AG[tunnel]}; every judge of the tunnel surface must run with the tunnel member's values"
      fi
      if [[ ${TMA[$m]} == "${TMA[tunnel]}" ]]; then
        pass "$u: -tick-max-age ${TMA[$m]} equals tunnel's"
      else
        fail "$u: -tick-max-age ${TMA[$m]} differs from tunnel's ${TMA[tunnel]}; tick-fresh and accept-loop must be judged with one value on every member"
      fi
    done
  fi

  # 2h. One window on all four: a reader holding a peer's hash from further
  #     back than that peer's window finds no entry and fires I1.
  if [[ -n ${WIN[tunnel]:-} ]]; then
    for m in admin material super; do
      [[ -n ${WIN[$m]:-} ]] || continue
      u="ghostunnel-obs-$m.service"
      if [[ ${WIN[$m]} == "${WIN[tunnel]}" ]]; then
        pass "$u: -window ${WIN[$m]} equals tunnel's"
      else
        fail "$u: -window ${WIN[$m]} differs from tunnel's ${WIN[tunnel]}; every member must keep and read the same window"
      fi
    done
  fi

  # 3. The target wants all five; every service is wanted by the target.
  t="$UNITS_DIR/ghostunnel-ring.target"
  if [[ -r $t ]]; then
    wants=$(unit_values "$t" Wants | sorted)
    for u in "${ALL_UNITS[@]}"; do
      [[ $u == ghostunnel-ring.target ]] && continue
      grep -qx "$u" <<<"$wants" || fail "target: does not want $u"
    done
    grep -qx 'Requires=.*' <(unit_lines "$t") && fail "target: must use Wants=, not Requires=" || true
    pass "target wants all five units"
  fi
}

# ---------------------------------------------------------------------------
# The install copies the units verbatim (README, Install step 6), so an
# installed unit that differs from systemd/ in any byte is not the unit
# --static checked, however valid it is.
unit_installed_as_repo() { # installed-dir unit
  if [[ ! -e $1/$2 ]]; then fail "$2 not installed in $1"; return 1; fi
  if cmp -s -- "$UNITS_DIR/$2" "$1/$2"; then pass "$2 in $1 is systemd/$2 byte for byte"; else fail "$2 in $1 differs from systemd/$2"; fi
}

stage_verify() {
  echo "== verify: the installed units are systemd/'s, and systemd-analyze verify on each"
  command -v cmp >/dev/null || { fail "cmp not found"; return; }
  command -v systemd-analyze >/dev/null || { fail "systemd-analyze not found"; return; }
  for u in "${ALL_UNITS[@]}"; do
    unit_installed_as_repo /etc/systemd/system "$u" || continue
    if systemd-analyze verify "/etc/systemd/system/$u"; then pass "$u verifies"; else fail "$u: systemd-analyze verify reported problems"; fi
  done
}

# ---------------------------------------------------------------------------
in_group() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qx "$2"; }
require_root() { [[ $(id -u) -eq 0 ]] || die "stage needs root"; }

stage_tree() {
  echo "== tree: owner:group:mode of every directory, group membership, /proc"
  require_root
  while IFS=$'\t' read -r path owner group mode; do
    [[ -z $path || $path == \#* ]] && continue
    if [[ ! -d $path ]]; then fail "$path missing"; continue; fi
    actual=$(stat -c '%U:%G:%a' "$path"); want="$owner:$group:${mode#0}"
    [[ $actual == "$want" ]] && pass "$path $actual" || fail "$path: have $actual want $want"
  done < "$TREE"
  for m in "${MEMBERS[@]}"; do
    g="gtring-halts-$m"
    for w in "${MEMBERS[@]}"; do
      [[ $w == "$m" ]] && continue
      in_group "gtobs-$w" "$g" || fail "group $g lacks gtobs-$w"
    done
    in_group "gtobs-$m" "$g" && fail "group $g holds its store owner gtobs-$m" || true
    in_group gt "$g" && fail "group $g holds gt" || true
  done
  # Every member re-verifies each served handshake's chain against the CA
  # on disk and re-runs the policy (handshake-substance, acl-substance), so
  # all four read the PEM material; the key stays root:gt, read by nobody.
  for u in gt gtobs-tunnel gtobs-admin gtobs-material gtobs-super; do in_group "$u" gtring-pem || fail "$u not in gtring-pem"; done
  # The trace root gt/ is gt:gtring-trace 2750: the four observers read it
  # through the group, gt as its owner, and nobody else reads a byte. So the
  # group holds exactly the four (an operator may join it to read the trace;
  # that shows here as a note, not a pass), never gt, and it is nobody's
  # primary group, which id -nG would not show as a membership.
  if ! getent group gtring-trace >/dev/null; then
    fail "group gtring-trace missing: the trace root's read group (setup-tree.sh)"
  else
    for u in "${OBSERVER_USERS[@]}"; do in_group "$u" gtring-trace || fail "$u not in gtring-trace: it cannot read gt/"; done
    in_group gt gtring-trace && fail "group gtring-trace holds gt; gt owns gt/ and is not one of its readers" || true
    members=$(getent group gtring-trace | cut -d: -f4 | tr ',' '\n' | grep -v '^$' | sorted)
    extra=$(comm -23 <(echo "$members") <(printf '%s\n' "${OBSERVER_USERS[@]}" | sorted))
    [[ -z $extra ]] && pass "gtring-trace holds exactly the four observers" || note "gtring-trace also holds: $(tr '\n' ' ' <<<"$extra")(an operator reading the trace; every one of these reads every peer's certificate)"
    gid=$(getent group gtring-trace | cut -d: -f3)
    primary=$(getent passwd | awk -F: -v g="$gid" '$4==g {print $1}')
    [[ -z $primary ]] && pass "gtring-trace is no account's primary group" || fail "gtring-trace is the primary group of: $(tr '\n' ' ' <<<"$primary")"
  fi
  pass "group membership as setup-tree.sh defines it"
  # The installed tree the members read for own-store-private is this one.
  if [[ ! -r /etc/ghostunnel/tree.tsv ]]; then
    fail "/etc/ghostunnel/tree.tsv missing: the members read it for own-store-private (README, Install step 3)"
  elif cmp -s "$TREE" /etc/ghostunnel/tree.tsv; then
    pass "/etc/ghostunnel/tree.tsv is identical to tree.tsv"
  else
    fail "/etc/ghostunnel/tree.tsv differs from tree.tsv; the members would fault on the difference"
  fi
  stage_tree_etc
  # hidepid: gtobs-admin must be able to read /proc/<pid>/cmdline of a process
  # it does not own. pid 1 stands in for ghostunnel here.
  opts=$(findmnt -no OPTIONS /proc 2>/dev/null || true)
  case ",$opts," in
    *,hidepid=0,*|*,hidepid=off,*) pass "/proc has hidepid off" ;;
    *hidepid=*) note "/proc is mounted with '$opts'; gtobs-admin must be in its gid= group" ;;
    *) pass "/proc has no hidepid option" ;;
  esac
  if setpriv --reuid gtobs-admin --regid gtobs-admin --init-groups -- cat /proc/1/cmdline >/dev/null 2>&1; then
    pass "gtobs-admin can read /proc/1/cmdline (so it can read ghostunnel's)"
  else
    fail "gtobs-admin cannot read /proc/1/cmdline: hidepid hides ghostunnel from the admin observer"
  fi
}

# The files outside the tree (README, Install steps 3 to 5), each a regular
# file with exactly the owner, group and mode the README states. The key
# is root:gt 0640: the proxy reads it through its group and no observer
# can (the material member's key-private holds the same from its own side,
# every cycle). Cert, CA and policy are root:gtring-pem 0640, read by the
# five accounts that load, hash and re-verify them. The paths are the ones
# ring.env gives ghostunnel; a PEM or policy file under /etc/ghostunnel
# that ring.env does not name is a stray, and must still be root's with
# nothing for other and no write for its group.
ETC=/etc/ghostunnel
etc_file() { # path want(owner:group:mode) what
  if [[ -L $1 || ! -f $1 ]]; then fail "$3 $1: not a regular file"; return; fi
  local actual; actual=$(stat -c '%U:%G:%a' "$1")
  [[ $actual == "$2" ]] && pass "$3 $1 $actual" || fail "$3 $1: have $actual want $2"
}
env_value() { # file var: the last assignment, surrounding quotes dropped
  sed -n "s/^$2=//p" "$1" | tail -1 | tr -d '"'"'"
}
stage_tree_etc() {
  if [[ ! -d $ETC ]]; then fail "$ETC missing (README, Install step 3)"; return; fi
  local actual; actual=$(stat -c '%U:%G:%a' "$ETC")
  [[ $actual == root:root:755 ]] && pass "$ETC $actual" || fail "$ETC: have $actual want root:root:755"
  for f in ring.env observers.env tree.tsv; do etc_file "$ETC/$f" root:root:644 "config"; done
  local -A named=()
  if [[ -r $ETC/ring.env ]]; then
    local key cert ca acl policy p
    key=$(env_value "$ETC/ring.env" GT_KEY); cert=$(env_value "$ETC/ring.env" GT_CERT); ca=$(env_value "$ETC/ring.env" GT_CACERT)
    acl=$(env_value "$ETC/ring.env" GT_ACL); policy=$(sed -n 's/.*--allow-policy \([^ ]*\).*/\1/p' <<<"$acl")
    if [[ -n $key ]]; then etc_file "$key" root:gt:640 "key"; named[$key]=1; else fail "$ETC/ring.env sets no GT_KEY; the key's owner and mode cannot be checked"; fi
    [[ -n $cert && -n $ca ]] || fail "$ETC/ring.env sets no GT_CERT or no GT_CACERT"
    for p in "$cert" "$ca" "$policy"; do
      [[ -n $p ]] || continue
      etc_file "$p" root:gtring-pem:640 "material"; named[$p]=1
    done
  fi
  local f
  for f in "$ETC"/*.pem "$ETC"/*.rego; do
    [[ -e $f || -L $f ]] || continue
    [[ -n ${named[$f]:-} ]] && continue
    if [[ -L $f || ! -f $f ]]; then fail "stray $f: not a regular file"; continue; fi
    actual=$(stat -c '%U:%G:%a' "$f")
    case "$actual" in
      root:*:640|root:*:600|root:*:440|root:*:400) pass "stray $f $actual (not named by ring.env; root's, nothing for other)" ;;
      *) fail "stray $f: $actual; not named by ring.env, and not root's with nothing for other and no group write" ;;
    esac
  done
}

# ---------------------------------------------------------------------------
ring_must_be_stopped() {
  command -v systemctl >/dev/null || return 0
  for u in "${ALL_UNITS[@]}"; do
    [[ $u == *.target ]] && continue
    if systemctl is-active --quiet "$u"; then die "$u is active; stop ghostunnel-ring.target before probing (a probe file is a stray or a halt to a running ring)"; fi
  done
}
# The account's primary group is looked up rather than assumed to share its
# name: nobody's is nogroup on Debian and Ubuntu.
as_user() { setpriv --reuid "$1" --regid "$(id -g "$1")" --init-groups -- "${@:2}"; }

# Run a command as a user; expect failure with one of the given errno words.
expect_denied() { # user errnos(list, |-separated) desc cmd...
  local user=$1 errnos=$2 desc=$3; shift 3
  local out rc=0
  out=$(as_user "$user" "$@" 2>&1) || rc=$?
  if (( rc == 0 )); then fail "$user: $desc: succeeded, must be denied"; return; fi
  local got=other
  case "$out" in
    *"Permission denied"*) got=EACCES ;;
    *"Operation not permitted"*) got=EPERM ;;
    *"Read-only file system"*) got=EROFS ;;
  esac
  case "|$errnos|" in
    *"|$got|"*) pass "$user: $desc: denied ($got)" ;;
    *) fail "$user: $desc: denied but with '$out' (want $errnos)" ;;
  esac
}
expect_ok() { # user desc cmd...
  local user=$1 desc=$2; shift 2
  local out rc=0
  out=$(as_user "$user" "$@" 2>&1) || rc=$?
  (( rc == 0 )) && pass "$user: $desc" || fail "$user: $desc: failed: $out"
}

CLEANUP=()
cleanup() { for p in "${CLEANUP[@]:-}"; do [[ -n $p ]] && rm -rf -- "$p"; done; }

# The forged slot (SPEC 10.2 H7, I8). The DAC permits every writer of a
# halts/ to create any new name in it: POSIX has no per-name create
# permission (README, "The halts/ slot problem"), so a slot created under
# another member's name is not refused, and the DAC is not weakened here to
# pretend otherwise. What the deployment relies on instead is that the
# kernel records who created the entry and that the store's owner refuses
# a name whose owner is not the member it is named for, within a cycle.
# Both are proved on a scratch copy of the tree, owned and moded as
# tree.tsv says, so no file of the real stores is written: as gtobs-<m>,
# create <peer>/halts/<other> holding a well-formed halt; the kernel must
# record gtobs-<m>, not gtobs-<other>, as its owner; then the peer's own
# binary (its unit's ExecStart) runs one cycle as gtobs-<peer> against the
# scratch tree, and its fault must name I8 with the forged entry and
# gtobs-<m>'s uid, and its halt must stand. A binary that is not installed
# fails the probe, since the detection cannot be shown without it.
probe_forged_slot() { # m peer other
  local m=$1 peer=$2 other=$3 W="gtobs-$1" P="gtobs-$2"
  local unit="$UNITS_DIR/ghostunnel-obs-$peer.service" exec_line bin so
  exec_line=$(unit_lines "$unit" | grep '^ExecStart=' | head -1); exec_line=${exec_line#ExecStart=}
  bin=${exec_line%% *}
  if [[ ! -x $bin ]]; then fail "$W: forged slot: $bin (the $peer unit's ExecStart) is not installed, so its detection cannot be shown"; return; fi
  so=$(slot_owners_from_units) || { fail "$W: forged slot: -slot-owners cannot be derived from the units"; return; }
  local scratch; scratch=$(mktemp -d /var/tmp/check-units.XXXXXX); CLEANUP+=("$scratch")
  chmod 0755 "$scratch"
  local S="$scratch/stores" stree="$scratch/tree.tsv" path owner group mode
  # tree.tsv with the store root moved under the scratch directory. The
  # members key their rows by the /stores/<identity> marker, which survives.
  awk -F'\t' -v r="$ROOT" -v s="$S" 'BEGIN{OFS="\t"} /^#/ || NF!=4 {next} $1==r || index($1, r "/")==1 {$1=s substr($1, length(r)+1); print}' "$TREE" > "$stree"
  while IFS=$'\t' read -r path owner group mode; do
    mkdir -p "$path" && chown "$owner:$group" "$path" && chmod "$mode" "$path" || { fail "$W: forged slot: cannot build $path in the scratch tree"; return; }
  done < "$stree"
  local slot="$S/$peer/halts/$other" members
  members=$(IFS=,; printf '%s' "${MEMBERS[*]}")
  local halt='{"kind":"halt","version":1,"observer":"'"$other"'","reason":"probe","subject":null,"sequence":1,"when":"2026-01-01T00:00:00Z","detail":"check-units.sh --probe: created by '"$W"' under the name of '"$other"'"}'
  expect_ok "$W" "create $peer/halts/$other, a slot under $other's name, in the scratch tree (the DAC permits it)" sh -c "printf '%s\n' '$halt' > $slot"
  [[ -e $slot ]] || return
  local creator; creator=$(stat -c %U "$slot" || echo unknown)
  [[ $creator == "$W" ]] && pass "$W: the kernel recorded $W, not gtobs-$other, as the owner of $peer/halts/$other" || fail "$W: $peer/halts/$other is owned by $creator, not $W"
  # The material member refuses to start without an expected checksum;
  # any well-formed one serves here, since the probe judges I8 alone.
  local extra=()
  [[ $peer == material ]] && extra=(-expect-binary-sha256 "$(printf '%064d' 0)")
  expect_ok "$P" "the $peer member ran one cycle on the scratch tree from $bin" "$bin" -identity "$peer" -members "$members" -coordinator super -copy-authors tunnel=material,admin=tunnel,material=admin -slot-owners "$so" -stores "$S" -traces "$S/gt" -tree "$stree" -cadence 10 -heartbeat-max-age 30s -cycles 1 "${extra[@]}"
  local uid; uid=$(id -u "$W")
  local want="\"check\":\"I8\",\"subject\":\"$peer/halts/$other:owner:$uid\""
  if [[ -r $S/$peer/fault ]] && grep -qF "$want" "$S/$peer/fault"; then
    pass "$W: the $peer member found it within one cycle: its fault holds $want"
  else
    fail "$W: the $peer member's fault does not name I8 on $peer/halts/$other with uid $uid: $(cat "$S/$peer/fault" 2>/dev/null || echo 'no fault written')"
  fi
  [[ -e $S/$peer/halt ]] && pass "$W: the $peer member raised its halt on the forged slot" || fail "$W: the $peer member raised no halt on the forged slot"
  rm -rf -- "$scratch"
}

stage_probe() {
  echo "== probe: DAC write boundary as each user (ring stopped)"
  require_root; ring_must_be_stopped
  command -v setpriv >/dev/null || die "setpriv (util-linux) not found"
  trap cleanup EXIT
  for m in "${MEMBERS[@]}"; do
    W="gtobs-$m"
    peer=""; for x in "${MEMBERS[@]}"; do [[ $x != "$m" ]] && { peer=$x; break; }; done
    other=""; for x in "${MEMBERS[@]}"; do [[ $x != "$m" && $x != "$peer" ]] && { other=$x; break; }; done
    # Forbidden.
    expect_denied "$W" EACCES "create in $peer's store root"   sh -c ": > $ROOT/$peer/$PROBE_NAME"
    expect_denied "$W" EACCES "create in $peer's heartbeat/"   sh -c ": > $ROOT/$peer/heartbeat/$PROBE_NAME"
    expect_denied "$W" EACCES "create in gt/"                  sh -c ": > $ROOT/gt/$PROBE_NAME"
    expect_denied "$W" EACCES "create in own halts/"           sh -c ": > $ROOT/$m/halts/$PROBE_NAME"
    if [[ $m == super ]]; then
      expect_denied "$W" EACCES "create in super/copy-tunnel (tunnel's)" sh -c ": > $ROOT/super/copy-tunnel/$PROBE_NAME"
    else
      expect_denied "$W" EACCES "create in own copy/ (the author's)"     sh -c ": > $ROOT/$m/copy/$PROBE_NAME"
      expect_denied "$W" EACCES "create in own copy-super/ (super's)"    sh -c ": > $ROOT/$m/copy-super/$PROBE_NAME"
    fi
    # Another member's slot in a halts/ this member writes: fixture owned by
    # that member, then rename-over, unlink and append must all be denied.
    fixture="$ROOT/$peer/halts/$other"
    if [[ -e $fixture || -e $fixture.tmp ]]; then
      note "$fixture exists (a real halt); slot-boundary probe for $W skipped"
    else
      printf 'probe\n' > "$fixture"; chown "gtobs-$other:gtobs-$other" "$fixture"; chmod 0644 "$fixture"
      CLEANUP+=("$fixture" "$ROOT/$peer/halts/$m.tmp")
      expect_ok     "$W" "stage own $m.tmp in $peer/halts/"             sh -c ": > $ROOT/$peer/halts/$m.tmp"
      expect_denied "$W" EPERM  "rename own .tmp over $other's slot"     mv -f "$ROOT/$peer/halts/$m.tmp" "$fixture"
      expect_denied "$W" EPERM  "unlink $other's slot"                   rm -f "$fixture"
      expect_denied "$W" EACCES "append to $other's slot"                sh -c ": >> $fixture"
      expect_denied "$W" EACCES "truncate $other's slot"                 sh -c ": > $fixture"
      [[ $(cat "$fixture") == probe ]] && pass "$W: $other's slot intact" || fail "$W: $other's slot was altered"
      rm -f "$fixture" "$ROOT/$peer/halts/$m.tmp"
    fi
    # Permitted.
    expect_ok "$W" "create and remove in own store root"  sh -c ": > $ROOT/$m/$PROBE_NAME && rm $ROOT/$m/$PROBE_NAME"
    expect_ok "$W" "create and remove in own heartbeat/"  sh -c ": > $ROOT/$m/heartbeat/$PROBE_NAME && rm $ROOT/$m/heartbeat/$PROBE_NAME"
    while read -r dir; do
      [[ -z $dir ]] && continue
      case "$dir" in
        "$ROOT/$m") ;;
        */halts)
          if [[ -e $dir/$m || -e $dir/$m.tmp ]]; then note "$dir/$m exists (a real halt); slot write probe skipped"; else
            CLEANUP+=("$dir/$m.tmp" "$dir/$m")
            expect_ok "$W" "stage, rename and remove own slot in $dir" sh -c ": > $dir/$m.tmp && mv $dir/$m.tmp $dir/$m && rm $dir/$m"
          fi ;;
        *) expect_ok "$W" "create and remove in $dir and its heartbeat/" sh -c ": > $dir/$PROBE_NAME && rm $dir/$PROBE_NAME && : > $dir/heartbeat/$PROBE_NAME && rm $dir/heartbeat/$PROBE_NAME" ;;
      esac
    done < <(awk -F'\t' -v w="$W" '$1==w && $3=="rw" {print $2}' "$MATRIX")
  done
  # gt: traces only.
  expect_denied gt EACCES "create in tunnel's store root" sh -c ": > $ROOT/tunnel/$PROBE_NAME"
  expect_denied gt EACCES "create in super's heartbeat/"  sh -c ": > $ROOT/super/heartbeat/$PROBE_NAME"
  expect_denied gt EACCES "create halts/gt in tunnel"     sh -c ": > $ROOT/tunnel/halts/gt"
  expect_denied gt EACCES "create in tunnel/copy"         sh -c ": > $ROOT/tunnel/copy/$PROBE_NAME"
  CLEANUP+=("$ROOT/gt/$PROBE_NAME")
  expect_ok gt "mkdir and rmdir in gt/" sh -c "mkdir $ROOT/gt/$PROBE_NAME && rmdir $ROOT/gt/$PROBE_NAME"
  # The read boundary of gt/ (gt:gtring-trace 2750): an account in no ring
  # group cannot list it, so it cannot reach a segment or a chain file by
  # name either (no x on the directory); every observer can. nobody stands
  # for every other account on the host; it must exist and be outside the
  # group, or the probe cannot run and fails.
  if ! getent passwd nobody >/dev/null; then
    fail "no account 'nobody' to probe the gt/ read boundary with"
  elif in_group nobody gtring-trace; then
    fail "nobody is in gtring-trace; the gt/ read boundary cannot be probed"
  else
    expect_denied nobody EACCES "list gt/ (the trace root, gt:gtring-trace 2750)" ls "$ROOT/gt"
    expect_denied nobody EACCES "stat gt/lock by name (no x on gt/)"          sh -c "stat $ROOT/gt/lock"
  fi
  for m in "${MEMBERS[@]}"; do
    expect_ok "gtobs-$m" "list gt/ through gtring-trace" ls "$ROOT/gt"
  done
  # The forged slot: each member as the creator, the next member as the
  # owner that must find it, the one after as the name forged, so every
  # member's account creates once and every member's binary judges once.
  local i n=${#MEMBERS[@]}
  for i in "${!MEMBERS[@]}"; do
    probe_forged_slot "${MEMBERS[$i]}" "${MEMBERS[$(( (i + 1) % n ))]}" "${MEMBERS[$(( (i + 2) % n ))]}"
  done
}

# ---------------------------------------------------------------------------
SANDBOX_KEYS=(User Group SupplementaryGroups UMask NoNewPrivileges ProtectSystem ProtectHome PrivateTmp PrivateDevices PrivateNetwork ProtectProc ProcSubset ProtectKernelTunables ProtectKernelModules ProtectControlGroups RestrictSUIDSGID RestrictRealtime LockPersonality SystemCallArchitectures CapabilityBoundingSet)

# Run a shell snippet inside a transient unit carrying the unit file's
# sandbox lines. Prints combined output; returns the snippet's status.
in_sandbox() { # unitfile snippet
  local f=$1 snippet=$2 props=() k v
  for k in "${SANDBOX_KEYS[@]}"; do
    v=$(unit_lines "$f" | awk -F= -v k="$k" '$1==k {sub("^[^=]*=",""); print}' | tail -1)
    if unit_lines "$f" | grep -q "^$k="; then props+=(-p "$k=$v"); fi
  done
  props+=(-p "ReadOnlyPaths=$(unit_values "$f" ReadOnlyPaths | tr '\n' ' ')")
  props+=(-p "ReadWritePaths=$(unit_values "$f" ReadWritePaths | tr '\n' ' ')")
  systemd-run --quiet --wait --pipe --collect "${props[@]}" -- /bin/sh -c "$snippet"
}
ns_expect() { # unit want(ok|EROFS) desc snippet
  local u=$1 want=$2 desc=$3 snippet=$4 out rc=0
  out=$(in_sandbox "$UNITS_DIR/$u" "$snippet" 2>&1) || rc=$?
  if [[ $want == ok ]]; then
    (( rc == 0 )) && pass "$u: $desc" || fail "$u: $desc: failed: $out"
  else
    if (( rc == 0 )); then fail "$u: $desc: succeeded, must be $want"; elif [[ $out == *"Read-only file system"* ]]; then pass "$u: $desc: EROFS"; else fail "$u: $desc: denied but not by the namespace: $out"; fi
  fi
}

stage_namespace() {
  echo "== namespace: each unit's sandbox lines replayed with systemd-run (ring stopped)"
  require_root; ring_must_be_stopped
  command -v systemd-run >/dev/null || die "systemd-run not found"
  trap cleanup EXIT
  for m in "${MEMBERS[@]}"; do
    u="ghostunnel-obs-$m.service"
    peer=""; for x in "${MEMBERS[@]}"; do [[ $x != "$m" ]] && { peer=$x; break; }; done
    ns_expect "$u" EROFS "write in $peer's store root is outside ReadWritePaths"  ": > $ROOT/$peer/$PROBE_NAME"
    ns_expect "$u" EROFS "write in gt/ is outside ReadWritePaths"                 ": > $ROOT/gt/$PROBE_NAME"
    ns_expect "$u" EROFS "own halts/ is remasked read-only"                       ": > $ROOT/$m/halts/$PROBE_NAME"
    if [[ $m != super ]]; then
      ns_expect "$u" EROFS "own copy/ is remasked read-only"                      ": > $ROOT/$m/copy/$PROBE_NAME"
      ns_expect "$u" EROFS "own copy-super/ is remasked read-only"                ": > $ROOT/$m/copy-super/$PROBE_NAME"
    else
      ns_expect "$u" EROFS "super/copy-tunnel is remasked read-only"              ": > $ROOT/super/copy-tunnel/$PROBE_NAME"
    fi
    ns_expect "$u" EROFS "/etc is read-only"                                      ": > /etc/$PROBE_NAME"
    CLEANUP+=("$ROOT/$m/$PROBE_NAME")
    ns_expect "$u" ok "own store root is writable"                                ": > $ROOT/$m/$PROBE_NAME && rm $ROOT/$m/$PROBE_NAME"
  done
  u=ghostunnel.service
  ns_expect "$u" EROFS "gt: tunnel's store is outside ReadWritePaths"  ": > $ROOT/tunnel/$PROBE_NAME"
  ns_expect "$u" EROFS "gt: super/halts is outside ReadWritePaths"     ": > $ROOT/super/halts/gt"
  CLEANUP+=("$ROOT/gt/$PROBE_NAME")
  ns_expect "$u" ok    "gt: gt/ is writable"                            "mkdir $ROOT/gt/$PROBE_NAME && rmdir $ROOT/gt/$PROBE_NAME"
}

# ---------------------------------------------------------------------------
# Usage is the header comment: every line from the second up to the first
# that is not a comment.
[[ $# -ge 1 ]] || { awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"; exit 2; }
for arg in "$@"; do
  case "$arg" in
    --static) stage_static ;;
    --verify) stage_verify ;;
    --tree) stage_tree ;;
    --probe) stage_probe ;;
    --namespace) stage_namespace ;;
    --all) stage_static; stage_verify; stage_tree; stage_probe; stage_namespace ;;
    *) die "unknown stage $arg" ;;
  esac
done
if (( FAILED )); then echo "check-units.sh: FAILED" >&2; exit 1; fi
echo "check-units.sh: all selected stages passed"
