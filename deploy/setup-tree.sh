#!/usr/bin/env bash
# setup-tree.sh: users, groups and the store tree of the ghostunnel observer
# ring. Run once as root on the Linux host. Idempotent: every step checks
# before it acts, and re-running on a finished tree changes nothing.
#
#   setup-tree.sh            create what is missing, set owner and mode on every
#                            directory of tree.tsv, then verify all of it
#   setup-tree.sh --pem DIR  also install DIR/cert.pem, DIR/ca.pem, DIR/key.pem
#                            and, if present, DIR/policy.rego into
#                            /etc/ghostunnel with the owner and mode the README
#                            states (Install, step 3): the key root:gt 0640,
#                            the rest root:gtring-pem 0640, by install(1), so
#                            the copy and its mode are one step
#   setup-tree.sh --dry-run  print every command instead of running it; needs
#                            nothing from the host (runs anywhere, even here)
#
# What it never does: chmod -R, chown -R, touch any file inside the tree,
# create any file inside it. Every file in the tree is written at run time
# by its one writer (README, "The write matrix"); pre-creating a halts/ slot
# would be a halt in force (SPEC 10.1) and pre-creating `since` would be a
# stray (S1). The PEM material lives outside the tree, and the verify step
# checks whatever of it /etc/ghostunnel holds, installed here or by hand.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TREE="$HERE/tree.tsv"
ETC=/etc/ghostunnel
DRY=0
PEM_SRC=""
usage() { echo "usage: $0 [--dry-run] [--pem DIR]" >&2; exit 2; }
while (( $# )); do
  case "$1" in
    --dry-run) DRY=1 ;;
    --pem) [[ -n ${2:-} ]] || usage; PEM_SRC=$2; shift ;;
    *) usage ;;
  esac
  shift
done

# ---- the accounts: users and groups ----------------------------------------
# One user per process, each with a primary group of its own name.
USERS=(gt gtobs-tunnel gtobs-admin gtobs-material gtobs-super)

# One group per halts/ directory: its members are the three members that
# deliver halts there, never the store's owner, never gt.
declare -A HALTS_GROUP_MEMBERS=(
  [gtring-halts-tunnel]="gtobs-admin gtobs-material gtobs-super"
  [gtring-halts-admin]="gtobs-tunnel gtobs-material gtobs-super"
  [gtring-halts-material]="gtobs-tunnel gtobs-admin gtobs-super"
  [gtring-halts-super]="gtobs-tunnel gtobs-admin gtobs-material"
)
# The shared read groups. gtring-pem is for the PEM material: ghostunnel
# loads the files, the material observer hashes cert, CA and policy. The key
# is NOT in this group's reach (root:gt 0640, README "PEM material").
# gtring-trace is the group of the trace root gt/ (gt:gtring-trace 2750,
# README "The trace root is group-readable"): the four observers read the
# trace through it; gt owns the root and is not a member; an operator who
# needs to read the trace joins it. Nobody else reads a byte of gt/.
declare -A READ_GROUP_MEMBERS=(
  [gtring-pem]="gt gtobs-tunnel gtobs-admin gtobs-material gtobs-super"
  [gtring-trace]="gtobs-tunnel gtobs-admin gtobs-material gtobs-super"
)

# ---- helpers ---------------------------------------------------------------
run() {
  if (( DRY )); then
    printf '+'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}
have_group() { (( DRY )) && return 1; getent group "$1" >/dev/null; }
have_user()  { (( DRY )) && return 1; getent passwd "$1" >/dev/null; }
in_group()   { (( DRY )) && return 1; id -nG "$1" | tr ' ' '\n' | grep -qx "$2"; }

if (( ! DRY )) && [[ $(id -u) -ne 0 ]]; then
  echo "setup-tree.sh: must run as root (or use --dry-run)" >&2
  exit 1
fi
[[ -r $TREE ]] || { echo "setup-tree.sh: $TREE not readable" >&2; exit 1; }

# ---- 1. users, each with its own primary group -----------------------------
for u in "${USERS[@]}"; do
  if have_user "$u"; then
    echo "user $u: present"
  else
    # System account, no home, no shell. --user-group creates the primary
    # group of the same name.
    run useradd --system --user-group --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin \
      --comment "ghostunnel observer ring, $u" "$u"
  fi
done

# ---- 2. the halts/ groups and the read groups (PEM, trace) -----------------
for g in gtring-halts-tunnel gtring-halts-admin gtring-halts-material gtring-halts-super gtring-pem gtring-trace; do
  if have_group "$g"; then
    echo "group $g: present"
  else
    run groupadd --system "$g"
  fi
done
for g in "${!HALTS_GROUP_MEMBERS[@]}"; do
  for u in ${HALTS_GROUP_MEMBERS[$g]}; do
    if in_group "$u" "$g"; then
      echo "group $g: $u is a member"
    else
      run gpasswd -a "$u" "$g"
    fi
  done
done
for g in "${!READ_GROUP_MEMBERS[@]}"; do
  for u in ${READ_GROUP_MEMBERS[$g]}; do
    if in_group "$u" "$g"; then
      echo "group $g: $u is a member"
    else
      run gpasswd -a "$u" "$g"
    fi
  done
done

# ---- 3. the tree, exactly tree.tsv, parent before child --------------------
# mkdir without -p: a parent that tree.tsv does not list is an error, not
# something to create with default ownership. chown and chmod on each
# directory only, never recursive: a re-run must not widen or narrow any
# file the writers have since created.
while IFS=$'\t' read -r path owner group mode; do
  [[ -z $path || $path == \#* ]] && continue
  parent=$(dirname "$path")
  if (( ! DRY )) && [[ ! -d $parent ]]; then
    echo "setup-tree.sh: parent $parent of $path missing; tree.tsv must list parents first" >&2
    exit 1
  fi
  if (( ! DRY )) && [[ -e $path && ! -d $path ]]; then
    echo "setup-tree.sh: $path exists and is not a directory" >&2
    exit 1
  fi
  if (( DRY )) || [[ ! -d $path ]]; then
    run mkdir "$path"
  fi
  run chown "$owner:$group" "$path"
  run chmod "$mode" "$path"
done < "$TREE"

# ---- 3b. the PEM material outside the tree, when asked (--pem DIR) ---------
# The README's install lines (Install, step 3), and nothing else: install(1)
# copies each file and sets its owner and mode in one step, so there is no
# moment at which the key is on disk with a wider mode. Only these names are
# installed; ring.env must name them.
if [[ -n $PEM_SRC ]]; then
  if (( ! DRY )); then
    for f in cert.pem ca.pem key.pem; do
      [[ -f $PEM_SRC/$f ]] || { echo "setup-tree.sh: $PEM_SRC/$f missing" >&2; exit 1; }
    done
  fi
  run install -d -m 0755 -o root -g root "$ETC"
  run install -m 0640 -o root -g gtring-pem "$PEM_SRC/cert.pem" "$PEM_SRC/ca.pem" "$ETC/"
  if (( DRY )) || [[ -f $PEM_SRC/policy.rego ]]; then
    run install -m 0640 -o root -g gtring-pem "$PEM_SRC/policy.rego" "$ETC/"
  fi
  run install -m 0640 -o root -g gt "$PEM_SRC/key.pem" "$ETC/"
fi

# ---- 4. verify: every directory has exactly the owner, group and mode -------
if (( DRY )); then
  echo "dry run: verification skipped (nothing was created)"
  exit 0
fi
bad=0
# The PEM material: whatever /etc/ghostunnel holds under the README's names,
# installed above or by hand, has exactly the owner, group and mode the
# README states; with --pem, the four files must be there. check-units.sh
# --tree checks the same by the paths ring.env names.
pem_want() { # path want(owner:group:mode)
  if [[ -L $1 || ! -f $1 ]]; then echo "MISMATCH $1: not a regular file" >&2; bad=1; return; fi
  local actual; actual=$(stat -c '%U:%G:%a' "$1")
  [[ $actual == "$2" ]] || { echo "MISMATCH $1: have $actual want $2" >&2; bad=1; }
}
if [[ -d $ETC ]]; then
  for f in cert.pem ca.pem policy.rego; do
    [[ -e $ETC/$f || -L $ETC/$f ]] && pem_want "$ETC/$f" root:gtring-pem:640
  done
  [[ -e $ETC/key.pem || -L $ETC/key.pem ]] && pem_want "$ETC/key.pem" root:gt:640
  if [[ -n $PEM_SRC ]]; then
    for f in cert.pem ca.pem key.pem; do [[ -f $ETC/$f ]] || { echo "MISMATCH $ETC/$f missing after install" >&2; bad=1; }; done
  fi
fi
while IFS=$'\t' read -r path owner group mode; do
  [[ -z $path || $path == \#* ]] && continue
  actual=$(stat -c '%U:%G:%a' "$path")
  want="$owner:$group:${mode#0}"
  if [[ $actual != "$want" ]]; then
    echo "MISMATCH $path: have $actual want $want" >&2
    bad=1
  fi
done < "$TREE"
for g in "${!HALTS_GROUP_MEMBERS[@]}"; do
  for u in ${HALTS_GROUP_MEMBERS[$g]}; do
    in_group "$u" "$g" || { echo "MISMATCH group $g lacks $u" >&2; bad=1; }
  done
  # The store owner must not be in its own halts/ group, nor gt in any.
  store=${g#gtring-halts-}
  in_group "gtobs-$store" "$g" && { echo "MISMATCH group $g holds the store owner gtobs-$store" >&2; bad=1; }
  in_group gt "$g" && { echo "MISMATCH group $g holds gt" >&2; bad=1; }
done
for g in "${!READ_GROUP_MEMBERS[@]}"; do
  for u in ${READ_GROUP_MEMBERS[$g]}; do
    in_group "$u" "$g" || { echo "MISMATCH group $g lacks $u" >&2; bad=1; }
  done
done
# gt owns the trace root and reads it as its owner; it is not in the
# readers' group, so the group's membership is exactly the readers.
in_group gt gtring-trace && { echo "MISMATCH group gtring-trace holds gt" >&2; bad=1; }
if (( bad )); then
  echo "setup-tree.sh: verification failed" >&2
  exit 1
fi
echo "setup-tree.sh: tree verified against $TREE"
echo "next: install the units (README, Install), then check-units.sh --all"
