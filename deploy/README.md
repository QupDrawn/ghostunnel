# Deploying the observer ring

Five processes, five users, systemd, one Linux host. No containers. Everything
here rests on one property: **every path in the store tree has exactly one
writer, and the operating system enforces it**, by ownership and mode on the
tree and by the mount namespace of each unit. The programs are not trusted to
behave; they are given nothing they must not write.

What is in this directory:

| File | What |
|---|---|
| `tree.tsv` | every directory of the tree with owner, group and mode; the one source `setup-tree.sh` creates from and `check-units.sh` walks |
| `write-matrix.tsv` | writer × directory × how it is enforced; the one source the units are checked against |
| `setup-tree.sh` | run once as root: users, groups, the tree; with `--pem DIR`, the PEM material too, installed with the owners and modes below. Idempotent. `--dry-run` prints instead |
| `systemd/` | `ghostunnel-ring.target`, `ghostunnel.service`, `ghostunnel-obs-{tunnel,admin,material,super}.service` |
| `ring.env.example` | the operator's own values for `ghostunnel.service` (`--listen`, `--target`, PEM paths, loopback `--status`, ACL); read by `gt` alone |
| `observers.env.example` | the operator's EXPECTED listener, backend target, ACL and PROXY protocol mode for the tunnel observer, and the expected OPA query (`GT_EXPECT_POLICY_QUERY`, for `acl-substance`) read by all four observers; never derived from `ring.env` ("Two files, two sources") |
| `check-units.sh` | `--static` anywhere; `--verify`, `--tree`, `--probe`, `--namespace` on the host |

## Landlock and the ring

ghostunnel applies landlock at startup (`landlock_linux.go`, `setupSandbox`)
with an allow-list of `/dev`, `/run`, `/proc`, `/tmp` read-write, `/etc` and
the CA stores read-only, the listener and target addresses, and the parent
directories of `--cert`, `--key`, `--cacert`, `--allow-policy` and
`--keystore`. Landlock is applied before the ring is opened, so the ring's
two paths are in that allow-list too:
`--ring-traces` read-write, because the emitter creates the boot directory
and appends segments under it, and `--ring-stores` read-only, because the
gate only reads the store tree. The trace root rule is not ignore-if-missing:
a missing `gt/` fails landlock setup loud rather than being dropped.
`--disable-landlock` is refused at start ("Refused configurations" below),
so there is no getting around a landlock problem with it; the material
observer's `sandbox-applied` is the second line and halts the ring on every
state but `applied` (`failed`, `skipped`, and `disabled` should a build that
still accepts the flag ever be run), and on `unsupported` unless an operator
accepted the absence on both sides of the boundary for the OS the build runs
on: `--accept-no-sandbox=<os>` on ghostunnel, recorded in the start line as
`sandbox_accepted`, and `-accept-no-sandbox=<os>` on the material unit. The
material unit in this deployment does NOT carry that flag, and must not: on
Linux the facility exists, ghostunnel and the observer both refuse the flag,
and the ring halts on anything but `applied`. `check-units.sh --static`
refuses any unit that carries an `-accept-no-*` flag.

## The write matrix

Directories only; every file in the tree is created at run time by the
directory's writer, and no file is pre-created (why not: below, under
`halts/`). `heartbeat/` inside a writer's directory is inside that grant.

| Writer | Directory (under `/var/lib/ghostunnel-ring/stores/`) | Writes there | Enforced by |
|---|---|---|---|
| `gtobs-tunnel` | `tunnel/` | `heartbeat/<seq>.hb` (+`.tmp`), `fault`, `halt` (+`.tmp`), the writability probe | root-owned `1775`, group `gtobs-tunnel`; `ReadWritePaths=` |
| | `admin/copy/` | `heartbeat/`, `fault` (+`.tmp`): tunnel is admin's copy author | owner `gtobs-tunnel` `0755`; `ReadWritePaths=` |
| | `super/copy-tunnel/` | the same, in the coordinator's store | owner `gtobs-tunnel` `0755`; `ReadWritePaths=` |
| | `admin/halts/`, `material/halts/`, `super/halts/` | `tunnel` and `tunnel.tmp` only | root-owned `1775`, group `gtring-halts-<store>`, sticky; `ReadWritePaths=` |
| `gtobs-admin` | `admin/` | own store | root-owned `1775`, group `gtobs-admin`; `ReadWritePaths=` |
| | `material/copy/` | admin is material's copy author | owner `gtobs-admin` `0755` |
| | `super/copy-admin/` | | owner `gtobs-admin` `0755` |
| | `tunnel/halts/`, `material/halts/`, `super/halts/` | `admin` and `admin.tmp` only | group + sticky as above |
| `gtobs-material` | `material/` | own store | root-owned `1775`, group `gtobs-material` |
| | `tunnel/copy/` | material is tunnel's copy author | owner `gtobs-material` `0755` |
| | `super/copy-material/` | | owner `gtobs-material` `0755` |
| | `tunnel/halts/`, `admin/halts/`, `super/halts/` | `material` and `material.tmp` only | group + sticky as above |
| `gtobs-super` | `super/` | own store | root-owned `1775`, group `gtobs-super` |
| | `tunnel/copy-super/`, `admin/copy-super/`, `material/copy-super/` | super's copy in every other store; super authors no `copy/` | owner `gtobs-super` `0755` |
| | `tunnel/halts/`, `admin/halts/`, `material/halts/` | `super` and `super.tmp` only | group + sticky as above |
| `gt` | `gt/` | `lock`, `<boot>/` and `<boot>/<seq>.trace`, `chains/<sha256>.der`, `material/<sha256>`; append only, never deletes | owner `gt`, group `gtring-trace`, `0750`; `ReadWritePaths=`; `UMask=0027` |

Everything not in a writer's rows is read-only to it twice over: by mode
(every directory is world `r-x` and every file `0644`, except the trace
root `gt/`, which is `gt:gtring-trace 2750` with `0750` directories and
`0640` files inside, readable by the four observers through the group and
by no other account ("The trace root is group-readable"); and the writer is
neither owner nor in the group of anything else) and by the unit's namespace
(`ProtectSystem=strict` makes the whole filesystem read-only; `ReadOnlyPaths=`
names the tree; `ReadWritePaths=` lists exactly the rows above; and the three
directories inside a member's own store that other members write, `copy/`,
`copy-super/` (or `copy-*/` for super) and `halts/`, are remasked
`ReadOnlyPaths=` inside the writable store, the more specific path winning per
systemd.exec(5)). ghostunnel's unit has no write access to any observer store:
only `gt/`.

The copy cycle is the observers' baked default, `tunnel=material,
admin=tunnel, material=admin` (store=author): material writes `tunnel/copy/`,
tunnel writes `admin/copy/`, admin writes `material/copy/`.

Each member writes `since` once into its own store root on first run and never
rewrites it, so the root grant already covers it and nothing is pre-created.

## Users and groups

| Account | Runs | Primary group | Supplementary groups |
|---|---|---|---|
| `gt` | `ghostunnel.service` | `gt` | `gtring-pem` |
| `gtobs-tunnel` | `ghostunnel-obs-tunnel.service` | `gtobs-tunnel` | `gtring-halts-admin`, `gtring-halts-material`, `gtring-halts-super`, `gtring-pem`, `gtring-trace` |
| `gtobs-admin` | `ghostunnel-obs-admin.service` | `gtobs-admin` | `gtring-halts-tunnel`, `gtring-halts-material`, `gtring-halts-super`, `gtring-pem`, `gtring-trace` |
| `gtobs-material` | `ghostunnel-obs-material.service` | `gtobs-material` | `gtring-halts-tunnel`, `gtring-halts-admin`, `gtring-halts-super`, `gtring-pem`, `gtring-trace` |
| `gtobs-super` | `ghostunnel-obs-super.service` | `gtobs-super` | `gtring-halts-tunnel`, `gtring-halts-admin`, `gtring-halts-material`, `gtring-pem`, `gtring-trace` |

All are system accounts, no home, `nologin`. `gtring-halts-<store>` holds the
three members that deliver halts into `<store>/halts/`: never the store's
owner, never `gt`. `gtring-pem` is the shared read group for the PEM
material: ghostunnel loads it, the material observer hashes it, and every
member re-runs the policy on served handshakes' chains (`acl-substance`;
the CA bundle it re-verifies those chains against it reads from
`gt/material/`, where ghostunnel keeps the bytes it hashed, for
`handshake-substance`); the key is in no observer's reach, and the material
observer checks every cycle that it is not (`key-private`, Install step 3).
`gtring-trace` is the read group of the trace root `gt/`:
exactly the four observers, never `gt` (which owns the root), and an
operator who needs to read the trace itself ("The trace root is
group-readable"). systemd applies a user's groups from `/etc/group` when
`User=` is set; the halts and PEM groups reach the units that way alone.
`gtring-trace` is also stated on each member unit as
`SupplementaryGroups=gtring-trace`, so that a member unit without the grant
is refused by `check-units.sh --static` instead of being found by the member
halting on `trace-readable` (systemd merges the line with the account's
`/etc/group` memberships; the group must still exist, or the unit fails to
start).

## The tree

`tree.tsv` is authoritative; this is it, with the reason for each mode.

```
/var/lib/ghostunnel-ring/                     root:root                     0755
  stores/                                     root:root                     0755  nobody but root creates a store
    tunnel/                                   root:gtobs-tunnel             1775  see "store roots" below
      heartbeat/                              gtobs-tunnel:gtobs-tunnel     0755
      copy/                                   gtobs-material:gtobs-material 0755  material's, whole
        heartbeat/                            gtobs-material:gtobs-material 0755
      copy-super/                             gtobs-super:gtobs-super       0755  super's, whole
        heartbeat/                            gtobs-super:gtobs-super       0755
      halts/                                  root:gtring-halts-tunnel      1775  see "halts/" below
    admin/                                    root:gtobs-admin              1775
      heartbeat/                              gtobs-admin:gtobs-admin       0755
      copy/                                   gtobs-tunnel:gtobs-tunnel     0755  tunnel's
        heartbeat/                            gtobs-tunnel:gtobs-tunnel     0755
      copy-super/  (+heartbeat/)              gtobs-super:gtobs-super       0755
      halts/                                  root:gtring-halts-admin       1775
    material/                                 root:gtobs-material           1775
      heartbeat/                              gtobs-material:gtobs-material 0755
      copy/  (+heartbeat/)                    gtobs-admin:gtobs-admin       0755  admin's
      copy-super/  (+heartbeat/)              gtobs-super:gtobs-super       0755
      halts/                                  root:gtring-halts-material    1775
    super/                                    root:gtobs-super              1775
      heartbeat/                              gtobs-super:gtobs-super       0755
      halts/                                  root:gtring-halts-super       1775
      copy-tunnel/  (+heartbeat/)             gtobs-tunnel:gtobs-tunnel     0755
      copy-admin/  (+heartbeat/)              gtobs-admin:gtobs-admin       0755
      copy-material/  (+heartbeat/)           gtobs-material:gtobs-material 0755
    gt/                                       gt:gtring-trace               2750  see "The trace root is group-readable"
      lock                                    gt:gt                         0640  the emitter's lock
      chains/                                 gt:gtring-trace               2750  the chain store
        <sha256>.der                          gt:gt                         0640
      material/                               gt:gtring-trace               2750  the material store
        <sha256>                              gt:gt                         0640
      <boot>/                                 gt:gtring-trace               2750  one per proxy start
        <seq>.trace                           gt:gt                         0640
```

Files: `0644`, owned by their writer, created by the writer with `UMask=0022`,
everywhere but under `gt/`, where ghostunnel requests `0750` on a directory
and `0640` on a file and runs with `UMask=0027`, so that is what lands.

**Store roots are root-owned `1775`, not owner-owned `0755`.** An
owner-owned root would be one writer too many. A member that owned its store root `0755` could `rmdir` its own
`halts/` while it is empty (which is whenever no halt is in force) and
recreate it as its own, or rename `copy/` away and make its own: it would
become a writer of paths it does not own, and its own shape rules would not
see it (the names are right). With the root owned by root and sticky, the
member creates `fault`, `halt` and their `.tmp` through the group bit and
removes only what it owns; `copy/`, `copy-super/`, `halts/` and `heartbeat/`
cannot be renamed, unlinked or replaced by anyone but root. Neither
`own-store-writable` (a create-and-remove of a staging file in its own
`heartbeat/`) nor `I5` (hash-against-memory) depends on the root's owner.
`own-store-private` does, on purpose: see below.

`copy/`, `copy-*/` and `gt/` have one writer for the whole subtree, so plain
ownership and `0755` are exact.

**`own-store-private`: the member checks the tree itself.** Every member
reads the rows of its own store from `tree.tsv` once at start and, each
cycle, `lstat`s the paths of that store and compares them: the root,
`heartbeat/` and `halts/` must exist and each directory of the store (those
three and every `copy*/` with its `heartbeat/`) must have exactly the owner,
group and mode its row says (`root:<self> 1775` on the root, `<self>:<self>
0755` on `heartbeat/`, the writer's ownership on the copies, `root:gtring-
halts-<self> 1775` on `halts/`); `fault` and `halt`, when present, must be
its own and carry no group or other write bit; and its own `halts/` must be
one its uid and groups could not create in (subject `<self>/halts:writable`
otherwise: the direct test that the store's owner is not in its own halts
group). A symbolic link is judged as the link, not its target. A tree file
that is missing or unparseable is not a pass: the check fails with subject
`tree`. Any mismatch is a fault of the member's own and halts the ring, so a
`chown`, a `chmod`, a re-created directory or an edited `/etc/group` after
setup is caught within a cycle, not at the next `check-units.sh --tree`.
The members read the tree from `/etc/ghostunnel/tree.tsv` (Install, step
3); `check-units.sh --tree` compares that copy with this one. The check is a
POSIX-ownership check and exists only where the platform has one: elsewhere
(`GOOS` other than Linux) it cannot run and fails closed, unless the
operator accepts the absence with `-accept-no-store-check=<os>` naming that
very OS, the rule of `-accept-no-sandbox=<os>` exactly. On Linux the check
runs, so there is nothing to accept: the observers refuse the flag
outright, a member started with it fails `own-store-private` with subject
`stale-acceptance`, and it must not appear in any unit here;
`check-units.sh --static` fails on it.

## The `halts/` slot problem

Each `halts/` is written by three members, one slot each (`halts/<writer>`
and `halts/<writer>.tmp`). A directory grant gives all three the whole
directory. POSIX has no per-name create permission, so the boundary is set
on what exists:

- `halts/` is `root:gtring-halts-<store> 1775`: the three writers may create
  in it; the store's owner and `gt` may only list it; the **sticky bit**
  means an entry can be renamed over, unlinked or renamed away only by the
  entry's owner, the directory's owner (root, which runs nothing) or a
  privileged process (rename(2), unlink(2): `EPERM` otherwise).
- every slot file is `0644` owned by the writer that created it: nobody else
  can open it for writing (`EACCES`), so it cannot be truncated or appended.

So a member can create its own `<self>.tmp`, rename it over its own
`<self>`, and unlink its own `<self>` when it clears. It cannot rename over,
unlink, truncate or append to a slot another member owns: the delivered halt
it did not raise stays. The OS enforces the property `observers/README.md`
states ("cannot clear a halt it did not raise").

**Why the slots are not pre-created.** Pre-creating `halts/<writer>` owned by
the writer would put the owner on the name before the first write. But a
regular non-`.tmp` file in `halts/` **is a halt in force by existence**
(SPEC 10.1; the gate reads it the same way, `ringtrace/README.md` §3), so
the ring would start halted; an empty one also fails the owner's parse
(`H6`, `S5`), which raises a halt of the owner's own, and since super's own
`halts/` would hold three such files super's clear-condition ("none of its own
assertions failed") could never hold: a permanent deadlock. Pre-creating
`<writer>.tmp` instead fails `staging-fresh` (`H4`) sixty seconds later. The
protocol leaves no name in `halts/` that may exist without meaning something,
so nothing is pre-created and the slot's ownership is set by its first
write.

**The residual, and what checks it.** Since any group member may create any
new name, a member could create a file in a peer's `halts/` under another
member's name while that slot is empty, or under a stray name. Every such
file is in the **stop** direction: any regular non-`.tmp` file there is a
halt in force to the gate and to every reader, and a stray name or a
subdirectory fires the owner's `H2` (`S1`/`S2`) and halts as well. Nothing a
member can create makes the ring serve when it should not. What it cannot do
is the other direction, remove or alter a halt it does not own. A file under
another member's name is a halt the named member never wrote and cannot
unlink (the sticky bit refuses); without an owner check, every member's
clear condition would hold around it and heartbeats and faults would show
nothing while the gate refused. The file carries its creator's uid
(`ls -ln`), which is why root, not any member, owns the directory, and that
uid is what the owner judges: every member is started with `-slot-owners
tunnel=gtobs-tunnel,admin=gtobs-admin,...`, the `User=` of each member's
unit (`check-units.sh --static` requires the two to agree, one string on
all four units), and procedure H's owner clause (SPEC 10.2 H7) `stat`s
every entry of the member's own `halts/` and fires `I8` with the entry's
path and the uid found (`<store>/halts/<writer>:owner:<uid>`) when the
owner is not the named member's account, or when the owner cannot be known
(`:unmapped`, `:no-account:<name>`, `:unprobed`). `I8` is the owner's own
failing check: its `fault` names the file and the uid for as long as the
file stands, so the ring does not report all clear around a halt nobody
raised. The slot itself is still in force (SPEC 10.1 is existence) and
stays until root, or the account that created it, removes it ("When a halt
persists"). The directory grant is what it has to be: a member must be able
to create its own slot, so creation under another name is not refused, it
is found. `check-units.sh --probe` proves both halves on a scratch copy of
the tree: that the DAC lets each member's account create a slot under
another member's name, that the kernel records the creator, and that the
store's owner, run for one cycle from its unit's binary, faults `I8` on it.

**Compatibility with `stageAndRename`.** `observers/*/main.go` `writeSlot`
calls `stageAndRename(<store>/halts/<self>, bytes)`: it opens
`<self>.tmp` with `O_CREATE|O_WRONLY|O_TRUNC` `0644`, writes, fsyncs,
closes, then `os.Rename(<self>.tmp, <self>)`. Every step is inside one
directory that is inside one `ReadWritePaths=` bind mount, so the rename
never crosses a mount (`EXDEV` cannot occur). Under the sticky bit:
`O_CREATE` on a new name needs only write on the directory (group);
`O_TRUNC` on an existing `<self>.tmp` needs write on the file (own, `0644`);
`rename` where `<self>` does not exist needs write on the directory; `rename`
over an existing `<self>` needs the caller to own `<self>` (it does). The
crash-recovery case, "a writer that finds its own staging file already
present truncates and reuses it" (SPEC 5), is the `O_TRUNC` on its own file.
Removal on clear is `os.Remove(<store>/halts/<self>)`, an unlink of an owned
entry. Every operation the code performs is permitted; every operation on
another member's slot is refused. `fs.protected_regular` (a systemd default
sysctl) additionally refuses `O_CREAT` on an existing file the caller does
not own in a group-writable sticky directory; it changes nothing here because
those opens are already refused by mode.

## The trace root is group-readable

The trace is the one part of the tree that holds somebody else's data:
every handshake line carries the presented leaf's subject, issuer, serial,
SANs and fingerprint, and `gt/chains/` holds the DER of every presented
chain, refused ones included (ringtrace/README.md 1.2, 1.5). Every other
directory holds the ring's own heartbeats and halts, which say nothing
about a client. So `gt/` is the one directory that is not world-readable:

- `gt/` is `gt:gtring-trace 2750` (`tree.tsv`): the setgid bit makes every
  directory and file the proxy creates inside inherit `gtring-trace`, which
  is what lets the four members read them (the proxy's own group is `gt`, so
  without the bit a boot directory would be `gt:gt` and unreadable by the
  group); `gt` writes it as its
  owner; the group reads it; no other account can list it, or reach a
  segment or a chain file by name (no `x` for others on the directory).
  Its parents stay `root:root 0755`, which is what lets anybody `stat`
  `gt/` and nobody open it.
- `gtring-trace` holds exactly the four observers (`setup-tree.sh`;
  `check-units.sh --tree` checks the membership and that it is nobody's
  primary group). `gt` is not in it and needs not be. An operator who has
  to read the trace joins it, and every member of the group reads every
  peer's certificate: keep it to the accounts that must.
- Every member unit grants the group on the unit itself
  (`SupplementaryGroups=gtring-trace`), and `check-units.sh --static`
  refuses a member unit without the line. A member that cannot open the
  trace fails `trace-readable` closed and halts the ring; the static check
  finds the missing grant first.
- The emitter and the two stores request `0750` on every directory they
  create (a boot, `chains/`, `material/`) and `0640` on every file (the
  lock, a segment, a chain file, a bundle): `ringtrace.DirMode` and `ringtrace.FileMode`, held by
  `TestEmitterCreatesGroupReadableOnly` and `TestWriteChainWritesOnce`. The
  files are `gt:gt`; the group reads them because the directories above
  them are group-executable and the files group-readable. `ghostunnel.
  service` runs under `UMask=0027`, which lets exactly those modes land
  and would narrow a wider request; `check-units.sh --static` requires the
  exact line. The proxy creates nothing else on disk: `--listen` and
  `--status` are TCP in `ring.env`, and `ring.env.example` says what the
  umask would do to a `unix:` socket (`0750 gt:gt`, connectable by `gt`
  and root alone).
- `check-units.sh --probe` proves the boundary on the host: as `nobody`,
  listing `gt/` and `stat`ing `gt/lock` by name are denied `EACCES`; as each
  observer, listing `gt/` succeeds; and no observer can create in `gt/`.

`ringstatus` reads the four stores and nothing under `gt/`, so it runs
without the group; reading the trace itself (`gt/<boot>/*.trace`,
`gt/chains/`), or copying the whole tree for a snapshot, needs an account in
`gtring-trace` or root (observers/ringstatus/README.md).

## Trace retention

Nothing in this tree deletes a boot, a segment or a chain file. The emitter
never deletes (ringtrace/README.md 1.3), no member writes `gt/` at all, and
the proxy does not prune its own trace: the trace is the record that
survives recovery (observers/SPEC.md 12.4), and a process that could
shorten its own record could also be made to. Retention is therefore the
operator's, as a deployment policy, under three rules the readers impose:

1. **Only a finished boot goes.** A finished boot is a directory under
   `gt/` that is not the highest-numbered one. The highest boot is the one
   every reader judges, alive or not; removing it, or any segment of it,
   makes the trace malformed and halts the ring.
2. **A boot goes whole, never a segment of it.** A boot missing its first
   segment has no start line; `boot-ambiguous` reads every boot's start
   line each cycle, cannot show such a boot's process dead, and counts it
   as ambiguous, and two ambiguous boots (the live one and it) halt the
   ring. A boot missing a later segment is a gap, malformed to any reader
   that opens it.
3. **`gt/chains/` and `gt/material/` are pruned only with their boots.** A
   chain file is named by handshake lines, and a bundle by `start` and
   `reload` lines; each is written once (the first boot that saw it) and
   is never rewritten when a later boot names it again, so its age says
   nothing about whether a retained boot still names it. The members judge
   the highest boot alone (`gtReadLatest`), so a chain or a bundle the live
   boot names and cannot read fails `handshake-substance` closed and halts
   the ring; one named only by finished boots is judged by nobody, and
   removing it halts nothing, but leaves every retained boot that names it
   a record with a hole, a handshake whose chain or bundle can no longer be
   produced, which is what retaining the boot was for. A chain or bundle
   file may go only when no retained boot's segment carries its hash
   (`grep -l <hash> gt/*/*.trace` finds none), which is a search over every
   retained segment. Under an age rule both stores are excluded and only
   grow; the chain store's size is one file per distinct presented chain,
   bounded by the client population, not by traffic, and the material
   store's one file per distinct bundle. `gt/lock` is never removed: the
   running proxy holds it.

The `systemd-tmpfiles` age rule over finished boots, and its limit. The
rule asked for is this, in `/etc/tmpfiles.d/ghostunnel-ring.conf`:

```
# Finished boots under gt/: entries not written or read for 90 days go.
# The lock, the chain store and the material store never age out (rule 3
# above). The mode, owner and group are spelled, as tree.tsv has them, so
# the line can only ever set gt/ to what it is: an "e" line adjusts the
# directory it names, and "-" would leave that to tmpfiles' defaults.
x /var/lib/ghostunnel-ring/stores/gt/lock
x /var/lib/ghostunnel-ring/stores/gt/chains
x /var/lib/ghostunnel-ring/stores/gt/material
e /var/lib/ghostunnel-ring/stores/gt 2750 gt gtring-trace 90d
```

Its limit, stated plainly: `systemd-tmpfiles` ages entries, not boots. It
removes each file whose own timestamps are older than the age and a
directory only once it is empty; it does not know the highest boot from a
finished one, and it never removes a boot whole. So the rule keeps rule 1
only if the age exceeds the longest a boot lives (the proxy's time between
restarts), because a sealed segment of the live boot older than the age
would be removed and the live boot made malformed; and it breaks rule 2 on
every finished boot with more than one segment, whose first segment ages
out before its last and which is then, for up to that boot's lifetime, a
boot with no start line, halting the ring on `boot-ambiguous` until the
rest is gone. (By default `tmpfiles` counts `atime` as well as `mtime`, and
the members read every boot's first line each cycle, so on a mount that
maintains `atime` the first segment of every finished boot stays young and
is never removed, which avoids the halt by keeping every boot's first
segment forever; on `noatime` it ages by `mtime` and the halt applies.)
The rule above is therefore safe only for a deployment whose boots have
one segment (64 MiB, `MaxSegmentBytes`, per boot) and whose proxy restarts
inside the age.

The form that keeps all three rules is a rename out of `gt/` followed by
the same age rule over the retired directory, because a rename on one
filesystem is atomic and the readers see a boot present or absent, never
partial, and nothing reads a retired boot:

```
install -d -m 0750 -o root -g gtring-trace /var/lib/ghostunnel-ring/retired   # outside stores/: a directory in stores/ is a member position (SPEC 2)
# retire every finished boot but the newest KEEP of them; as root, the ring may be running
KEEP=3; GT=/var/lib/ghostunnel-ring/stores/gt
ls -d "$GT"/[0-9]* | sort | head -n -$((KEEP + 1)) | while read -r b; do mv "$b" /var/lib/ghostunnel-ring/retired/; done
```

```
# /etc/tmpfiles.d/ghostunnel-ring.conf: retired boots age out whole in effect,
# since nothing reads them and a partial one is nobody's concern.
e /var/lib/ghostunnel-ring/retired 0750 root gtring-trace 90d
```

The chain and material stores stay under rule 3 in both forms. Run the
retire step from a timer or by hand; `head -n -$((KEEP + 1))` keeps the
highest boot and the `KEEP` newest finished ones. A retired boot still
names chains and bundles that the live boot may name too; that is why the
two stores are not retired with it.

## Install

On the Linux host, as root, in this order.

1. Build the five binaries from this repository and install them where the
   units expect them:
   ```
   go build -o /usr/local/bin/ghostunnel .
   for m in tunnel admin material super; do
     go build -o /usr/local/bin/ghostunnel-obs-$m ./observers/$m
   done
   ```
   (`ExecStart=` names `/usr/local/bin/...`; change the units if you install
   elsewhere.)
2. Users, groups, tree: `./setup-tree.sh` (preview with `--dry-run`). It
   refuses if a parent directory is missing or a path exists as a file, and
   verifies every directory's owner:group:mode and every group membership
   before it reports success.
3. PEM material, outside the tree:
   ```
   install -d -m 0755 -o root -g root /etc/ghostunnel
   install -m 0640 -o root -g gtring-pem cert.pem ca.pem  /etc/ghostunnel/   # and policy.rego if used
   install -m 0640 -o root -g gt         key.pem          /etc/ghostunnel/
   ```
   (or `./setup-tree.sh --pem DIR` with those files under `DIR`, which runs
   exactly these lines.) `gtobs-material` reads cert, CA and policy whole and
   hashes them (it is in `gtring-pem`); it only `stat`s the key, for which
   `x` on `/etc/ghostunnel` suffices and read on the file is neither needed
   nor granted. No observer can read the key, and the material observer
   holds that from its own side every cycle: `key-private` `lstat`s the key
   the start line (or the last reload) names and fails unless it is a
   regular file (a symbolic link is not) with no permission bit beyond
   owner read and write and group read (`0640` and tighter; subject
   `mode:<octal>` otherwise), owned by someone else and not group-readable
   by any group the observer holds (`readable-by-observer`; so `root:gt
   0640` passes and `root:gtring-pem 0640` halts). A key it cannot `stat`,
   a start line that names no key, or a build without POSIX ownership fails
   it too, with no flag to accept that. `check-units.sh --tree` checks the
   other half, the owner and group, by the paths `ring.env` names ("What
   was verified here"). In the same directory, the tree the members check
   their own store against (`own-store-private`, "The tree"):
   ```
   install -m 0644 -o root -g root tree.tsv /etc/ghostunnel/tree.tsv
   ```
   It is the same file `setup-tree.sh` built from; re-install it whenever
   `tree.tsv` changes, or the members fault on the difference.
4. `cp ring.env.example /etc/ghostunnel/ring.env`, edit, then
   `chown root:root /etc/ghostunnel/ring.env; chmod 0644`. Only
   `ghostunnel.service` (as `gt`) reads it. It holds addresses, paths and an
   ACL flag, never a secret; a passphrase does not belong there or on any
   command line (the admin observer halts on `--storepass`/`--pkcs11-pin` in
   `/proc/<pid>/cmdline`, and PKCS#11 is refused at start anyway).
5. `cp observers.env.example /etc/ghostunnel/observers.env`, fill in
   `GT_EXPECT_LISTEN`, `GT_EXPECT_TARGET`, `GT_EXPECT_ACL` and
   `GT_EXPECT_PROXY_PROTOCOL` **from the record of what the
   deployment is meant to be, not from `ring.env`**, then `chown root:root
   /etc/ghostunnel/observers.env; chmod 0644`. Only the tunnel unit (as
   `gtobs-tunnel`) reads it. See "Two files, two sources".
6. Units: `cp systemd/* /etc/systemd/system/ && systemctl daemon-reload`.
7. Verify before starting: `./check-units.sh --all` (see "What was not
   verified here"). The probe stages need the ring stopped; it is.
8. `systemctl enable --now ghostunnel-ring.target`.

## Two files, two sources

The tunnel observer's `listener-expected`, `target-expected`,
`acl-expected` and `proxy-protocol-expected` compare the proxy's start line
with an expectation. Where the expectation comes from decides whether the
check can ever fail. Read from `ring.env`, the file the proxy is started
from, `-expect-listen ${GT_LISTEN}` compares a value to itself: an edit to
`ring.env` moves both sides at once and the observer agrees with every
listener the proxy is given, including a wrong one. So the expectation is a
second file, `/etc/ghostunnel/observers.env` (`observers.env.example`),
holding:

| Variable | What | Form |
|---|---|---|
| `GT_EXPECT_LISTEN` | the listener the proxy is expected to bind | its `--listen` value verbatim |
| `GT_EXPECT_TARGET` | the backend it is expected to dial | its `--target` value verbatim; compared exactly, so two spellings of one address are two targets |
| `GT_EXPECT_ACL` | the access-control rules it is expected to run with | comma-separated, no spaces, as the start line carries them: `allow-cn:alice,allow-all`; vocabulary `allow-all`, `allow-cn:<v>`, `allow-ou:<v>`, `allow-dns:<v>`, `allow-uri:<v>`, `allow-ip:<v>`, `allow-spki-pin:<hex>`, `policy:<sha256>` |
| `GT_EXPECT_PROXY_PROTOCOL` | what the backend is expected to be handed ahead of each connection's bytes | the start line's `proxy_protocol`: `off` (no header), `conn` (a PROXY protocol v2 header with the addresses), `tls` (with the TLS version, ALPN and SNI too), `tls-full` (with the client's whole certificate as well); empty means `off`, and there is no way to expect nothing |

The tunnel unit reads `observers.env` and passes `-expect-listen
${GT_EXPECT_LISTEN} -expect-target ${GT_EXPECT_TARGET} -expect-acl
${GT_EXPECT_ACL}`, with an `ExecStartPre` `test -n` on each so an empty
value fails the start rather than shifting the next flag into its place,
and `-expect-proxy-protocol=${GT_EXPECT_PROXY_PROTOCOL}`, joined with `=`
so that an empty value reaches the member as an empty value, which it
reads as `off`. `ghostunnel.service` reads `ring.env` and never
`observers.env`; the other three observers read it for
`GT_EXPECT_POLICY_QUERY` alone. Both files are `root:root 0644` and hold
no secret; they are separate because they must come from different places
and be reviewed by different eyes: write `ring.env` from what the host
needs, write `observers.env` from the change record or inventory that
says what the proxy is supposed to expose, admit and hand to its backend,
and never generate one from the other. A deliberate change to the
listener, the target, the ACL or the PROXY protocol mode is two edits; a
change to `ring.env` alone halts the ring, which is the property being
bought. The PROXY protocol mode is here because it changes what the
backend receives: under `tls-full` every connection carries the client's
certificate to it, and a backend that was not written to expect that
should not be sent it because a flag was added to `ring.env`.

`check-units.sh --static` enforces the split: the tunnel unit's
`EnvironmentFile=` is exactly `observers.env`, its `ExecStart` carries both
`-expect-*` flags from those variables with both `ExecStartPre` tests, and
the string `ring.env` appears nowhere in the file, comments included;
`ghostunnel.service` reads exactly `ring.env` and does not name
`observers.env`; admin, material and super read no environment file.

## The cadence contract

Three numbers set explicitly in every unit and the rest left at their
defaults, all checked by `check-units.sh --static`, and the two checks the
tick numbers feed:

| Where | Flag | Value | Rule |
|---|---|---|---|
| all four observers | `-cadence` | `10` (seconds) | the ceiling a cycle may take and still count; the value each declares in its heartbeat |
| all four observers | `-heartbeat-max-age` | `30s` | no default; `parseFlags` refuses unless it exceeds `-cadence`; the V4b backstop |
| ghostunnel | `--ring-heartbeat-max-age` | `30s` | no default; `ring.go` refuses zero; must exceed super's `-cadence` |
| ghostunnel | `--ring-tick` | not passed; default `5s` | how often the emitter writes a `tick` line to the trace; must be well below the members' `-cadence` (checked: below 10 s) |
| all four observers | `-tick-max-age` | not passed; default `30s` | how old the newest `tick` may be before `tick-fresh` fails, and how far back `accept-loop` looks; the value in force (the default when absent) must be at least twice the `--ring-tick` in force and the same on all four members (checked, defaults included) |
| tunnel; admin, material, super | `-lifetime-margin`, `-acl-grace`; `-tunnel-lifetime-margin`, `-tunnel-acl-grace` | not passed; defaults `2s`, `2s` | the three judges of the tunnel surface must run with the tunnel member's own values (checked, as spelled, defaults included) |
| all four observers | `tick-fresh` (a check, fed by `-tick-max-age`) | | the newest `tick` of the current boot, or its start line before the first tick, is within `-tick-max-age` of the member's clock; each member judges it on its own and faults on it; an unreadable trace fails it too |
| tunnel (computed by all four) | `accept-loop` (a check, fed by `-tick-max-age`) | | any `accept-error` line of the current boot within the last `-tick-max-age` fails it, subject the error text; the tunnel member publishes it and the other three compare what they compute with its fault (`surface-disagree`) |
| all four observers | `boot-ended` (a check, fed by `-tick-max-age`) | | once a member reads a current boot other than the one it read last cycle, the old boot is judged the first cycle its newest line is older than `-tick-max-age` (younger, it may still be a live second process, which is `boot-ambiguous`'s to report): no `shutdown` line, a torn last line, a connection never closed, the failed accepts within `-tick-max-age` before its end; judged once per member process and never again (SPEC 14.3) |

Why 10 and 30. A member judges a peer stale first by V4a, the peer's own
declared cadence times `(1 + stale-slack)` = 20 s with the defaults; V4b is
the flat backstop and sits above it so V4a is the line that fires. A
heartbeat's timestamp is the cycle's start time, truncated to the second,
and it is visible at the cycle's end, so in the worst honest case (two
consecutive cycles each at the 10 s ceiling) the newest heartbeat is 2 × 10 +
1 s old: 30 s clears that with margin, 20 s does not, and 10 s would refuse
a healthy ring. ghostunnel's gate is the second line behind the members' own
V4a on super (the members halt a dead super at 20 s, the gate on its own at
30 s), so the same value serves. Cycles actually run every 300 ms (`-min-
cycle`), so in practice a heartbeat is at most a second or two old and a
dead member is seen within one cadence.

**The tick.** The proxy's trace emitter writes a `tick` line every
`--ring-tick` and an `accept-error` line for every failed accept, so the
trace says something at a known rate even when nothing connects, and the
members (all four: super reads the trace like the other three) judge
`tick-fresh` by the newest `tick`: older than `-tick-max-age`, or absent
after the first tick was due, is a fault. The constraint is the same shape
as the heartbeat one and sits one level down: the tick must be well below
the members' cadence (a member must see at least one new tick per cycle,
so a 10 s tick against a 10 s cadence would fail a healthy proxy on jitter
alone), and the max-age must exceed the tick by a margin that covers a
stalled emitter being noticed, not a busy one. The same `-tick-max-age` is
the window `accept-loop` looks back over for a failed Accept, and since
every member computes that check and compares its result with the tunnel
member's, the value must be one value on all four. The shipped units pass
neither flag and rely on the defaults, `5s` and `30s`; if you set them,
`check-units.sh --static` refuses a `--ring-tick` at or above super's
`-cadence`, a `-tick-max-age` in force (passed or default) below twice the
tick in force, and a `-tick-max-age` that differs between members.

## Health and the watchdog

`ghostunnel.service` carries `WatchdogSec=15`. The proxy's health notify
runs every 7.5 s (half the interval) and sends `WATCHDOG=1` only when all of
this is true at that moment (`healthy` in `main.go`): the accept loop has
run within the last 5 s (`acceptHealthWindow`; it iterates at least once a
second when idle, so a healthy loop is never that far behind), the proxy is
not shutting down and its listener is open, and the ring holds no sticky
refusal (a trace that failed, a reload that failed, a status listener that
died). Anything else and no notify is sent; two missed notifies (15 s) and
systemd aborts the process and, through `Restart=on-failure`, starts it
again. 15 s is the smallest interval those numbers allow: a ping every
7.5 s can only be missed by a loop already 5 s late. "Healthy" here means
the proxy can accept and its trace can be written, not that the ring is
up: during a gate refusal the accept loop is alive and refusing, so the
watchdog is fed and the proxy is not restarted for a condition that is the
ring's to lift. A proxy whose accept loop has wedged goes quiet in its
trace; the members halt the ring for a stale tick, systemd aborts and
restarts the proxy, the emitter starts a new boot directory, the members
see fresh ticks, and the halt clears by itself.

A watchdog abort does not drain: `SIGABRT` is immediate, and a proxy that
has not accepted for 15 s has nothing in flight it was going to finish. The clean stop path (`systemctl stop`) is unchanged and
still drains for `--shutdown-timeout`. `WatchdogSec=` implies
`NotifyAccess=main`; the notify socket is under `/run`, which landlock
allow-lists read-write. No member carries `WatchdogSec=`: a member's
liveness is judged by the ring (V4a, V4b) and a systemd restart of a
healthy-looking member would only churn its heartbeat; `check-units.sh
--static` fails a member unit that carries it.

## Refused configurations

The proxy refuses to start, before the ring is opened, with:

- `--disable-landlock`: the sandbox is not optional on a platform that has
  it; the flag exists only for platforms that do not, and there it is
  `--accept-no-sandbox=<os>` that is needed, on both sides.
- `--keystore` naming a PKCS#11 module, or any `--pkcs11-*` flag: only PEM
  files on disk satisfy `material-loaded`, and a PIN on the command line is
  a secret in `/proc/<pid>/cmdline`.
- client mode without a `--verify-*` rule, unless `--verify-hostname-only`
  is given explicitly: a client that verifies nothing about the server is a
  configuration, not an omission, and must be spelled out.

The observers refuse to start with `-accept-no-sandbox=<os>` or
`-accept-no-store-check=<os>` naming an OS that has the facility (Linux
has both). None of these can be reached from the shipped units;
`check-units.sh --static` fails a unit that carries an `-accept-no-*` flag.

## Cold start

Start order does not matter and is not enforced. Each observer's first cycle
finds the members that have not started yet, raises a halt for them, and
clears it once every store holds a fresh heartbeat and no fault. ghostunnel
consults the gate on every accept and refuses every connection until super's
newest heartbeat is present, well-formed and younger than
`--ring-heartbeat-max-age` and no `halt`, `fault` or delivered halt exists
anywhere; then it serves, without a restart. There is no grace period and no
"serve while the ring is not ready". Expect refused connections and
`/_status` 503 for the first few seconds after `systemctl start`. That is
the intended behaviour.

## When the ring halts

1. `systemctl status ghostunnel-ring.target` and `journalctl -u
   'ghostunnel-obs-*'`: every observer logs its failing set, every halt it
   raised (with reason and subject) and every one it relayed, with the cycle
   sequence.
2. Read the **fault** files: `cat /var/lib/ghostunnel-ring/stores/*/fault`.
   A fault is written by the member that found something, in its own store,
   and names the failing check and subject. `halt` in a store means that
   member found a violation itself; `halts/<w>` means member `w` delivered a
   halt there (raised or relayed).
3. Fix the cause (renew the certificate, move the status listener to
   loopback, restore a missing file, restart a dead member...).
4. Do nothing to the store. The member that raised the fault clears it when
   its checks pass again; super then removes its `halts/super` from the
   others and its own `halt`; each other member follows. ghostunnel resumes
   on the next accept. There is no dwell and no restart.
5. **Never delete another member's halt or fault.** The OS refuses it to the
   members; as root you can, and it would either be reinstated next cycle
   (the condition persists) or, worse, lift a stop whose cause you have not
   found. If a halt file must be removed by hand (a member permanently
   retired), stop that member first and remove only the files it wrote, as
   SPEC 12.3 says.

A member that will not come back up (`Restart=on-failure` gives up after the
start-limit) leaves its heartbeat stale, which halts the ring until it is
fixed; that is the ring working.

## When a halt persists

A halt that does not clear after the cause is fixed is one of three things.
Each has exactly one thing the operator removes; everything else stays.

| Symptom | What you remove, and only that | Why it is safe |
|---|---|---|
| a copy author crashed mid-write and its `staging-fresh` (`H4`) fault holds: a `*.hb.tmp` in a `copy*/heartbeat/` or a `copy*/fault.tmp` older than a minute, and the author's own store is fine | that staging file (`copy*/heartbeat/*.hb.tmp`, `copy*/fault.tmp`), as root, after confirming its mtime is old and the author is running again (a running author reuses its own `.tmp` by truncation; a stale one it never got back to is what you are removing) | a `.tmp` is never a halt, never a delivered slot and never read as a heartbeat; removing it takes nothing out of force |
| a member is retired for good (its unit disabled and stopped) and the others halt on its stale heartbeat | after `systemctl disable --now` on that member: its own store's `heartbeat/*`, `fault`, `halt`, `since`; its copy directory's contents in the peer store it authored and in `super/`; and its slot `halts/<member>` in the three other `halts/` (SPEC 12.3). Then shorten `-members` on the survivors, or the ring halts on it forever | you remove only files that member wrote, and only once it can no longer write; the OS would let nobody else |
| the proxy's emitter failed (trace quiet, `tick-fresh` fault on every member, `ghostunnel.service` still active) | nothing in the tree: `systemctl restart ghostunnel.service`. With `WatchdogSec=` this is what systemd already did within 15 s; if it is still needed, the emitter is failing on every start and the journal says why (usually `gt/` ownership or a full disk) | the emitter starts a new boot directory; the old segments are never deleted, and the members' next cycle sees fresh ticks |
| a store's owner faults `I8` with subject `<store>/halts/<writer>:owner:<uid>`: a slot under `writer`'s name that `writer` did not create (`ls -ln` shows the uid; SPEC 10.2 H7) | that one slot, as root or as the account `uid` names, with the member running as that account stopped, and only after learning why that account wrote a name not its own; nothing else. An `I8` with `:unmapped`, `:no-account:<name>` or `:unprobed` is the `-slot-owners` mapping, the host's accounts or the filesystem, not the slot: fix those and remove nothing | `writer` never wrote it and never clears it, so nothing in the protocol removes it (SPEC 12.3); the owner's `I8` clears on its next cycle once the file is gone, and every honest slot is still its own writer's to clear |

Never remove:

- **another member's `halt`** (`<store>/halt`): it is that member's own
  record and is reinstated on its next cycle if the condition holds;
  removed while the condition holds, it lifts a stop whose cause is not yet
  found.
- **a delivered slot** (`<store>/halts/<writer>`): it is `writer`'s
  assertion in a peer's store, and `writer` clears it itself when its own
  checks pass. A slot that stays is a member still failing something, or a
  retired member (the second row above, which removes the retired member's
  files only, from the retired member's side). The one exception is a slot
  the store owner's `fault` names under `I8` with `:owner:<uid>` (the
  fourth row above): `writer` never wrote it, so nobody's protocol will
  ever clear it, and it is removed as root or as the account that created
  it, after the cause is known.
- **a heartbeat, a `since` or a trace segment** of a running member or
  proxy: a gap in a heartbeat sequence is `I3`, a missing `since` is
  `observing-since`, a missing segment is `trace-readable` on every member.

Remove nothing to make the ring serve. The list above is what makes it
*able* to clear on its own; if it still does not, the fault files name the
check that still fails and that is what to fix.

## What the units and files enforce, and where

| Property | Enforced by |
|---|---|
| only PEM cert/key/CA/policy files on disk satisfy `material-loaded` | `ring.env` uses `--cert`/`--key`/`--cacert` (and `--allow-policy`) with file paths; no keystore, PKCS#11, keychain, SPIFFE or ACME (PKCS#11 is refused at start, "Refused configurations") |
| the observer users read cert, CA and policy, never the key | `gtring-pem` on cert, CA and policy, held by all four observers; key `root:gt 0640`; `gtobs-material` `stat`s it only, and halts on `key-private` if that stat shows a key it could read, or one with a bit beyond `0640` |
| the status listener binds loopback | `GT_STATUS` is loopback in `ring.env.example`; ghostunnel reports `status_client_cert: false`, so a routable address halts on the admin member's `status-listener-bound` |
| admin reads `/proc/<pid>/cmdline`; tunnel, admin and material stat `/proc/<pid>` | `ghostunnel-obs-admin.service` keeps `ProtectProc=default`, `ProcSubset=all`; tunnel and material keep `ProtectProc=default` too, because `boot-ambiguous` reads a hidden pid as a dead one and the highest boot's pid must read live; ghostunnel and super use `ProtectProc=invisible` for their own view, which does not affect what the three see |
| host `hidepid` | `/proc` must not be mounted `hidepid=1`/`2`, or `gid=` must name a group `gtobs-admin` is in. `check-units.sh --tree` reads `/proc/1/cmdline` as `gtobs-admin` to prove it |
| in-flight connections close on halt, drain on stop | the proxy's watch closes them within 1 s of a halt (`ring.go`, `watch`); `TimeoutStopSec=330s` on `ghostunnel.service` covers the drain (`--shutdown-timeout` default 5 m) on stop |
| a failed reload stops serving | the proxy refuses on its own until a reload succeeds (`ring.go`, `reloaded`); the material member's `reload-succeeded` halts the ring on the line |

The four observer units set `PrivateNetwork=yes` because no observer opens
a socket (the tunnel observer judges the listener from the trace; the admin
observer only parses the status address), and `PrivateDevices=yes`. If a
future observer needs the network, drop the line for that unit only.

## What `check-units.sh` checks, and where

`--static` runs anywhere and reads only this directory. It asserts:

- every unit's non-comment lines are `[Section]` or `Key=Value`;
- each unit's `ReadWritePaths=` set equals its writer's `rw` rows of
  `write-matrix.tsv` and its `ReadOnlyPaths=` set equals the tree root plus
  its `ro` rows (set equality, both directions); every such path is a
  directory in `tree.tsv` whose owner, group and mode give that writer and
  nobody else the directory in the way the row says (owner for `0755`
  directories; `root:<writer>` for store roots; `root:gtring-halts-<store>`
  for `halts/`, with the store owner not a writer); every `1775` directory
  is root's;
- the required sandbox lines are present; admin keeps `ProtectProc=default`;
- `ExecStart` carries `-identity`, `-stores`, `-traces` (all four members),
  `-cadence`, `-heartbeat-max-age`, the copy cycle, and `-slot-owners` equal
  to the four member units' `User=` lines as `member=account` pairs (one
  string on all four); for ghostunnel `--ring-traces`, `--ring-stores`,
  `--status`, `--ring-heartbeat-max-age`;
- every `-heartbeat-max-age` exceeds its own `-cadence` and super's, and
  `--ring-heartbeat-max-age` exceeds super's; any `--ring-tick` is below
  super's `-cadence`; every member's `-tick-max-age` in force (passed or
  default) is at least twice the tick in force and the same on all four;
  admin, material and super's `-tunnel-lifetime-margin` /
  `-tunnel-acl-grace` equal tunnel's `-lifetime-margin` / `-acl-grace` (as
  spelled, absent meaning the default);
- the tunnel unit's `EnvironmentFile=` is exactly `observers.env`, its
  `ExecStart` carries `-expect-listen ${GT_EXPECT_LISTEN}`, `-expect-target
  ${GT_EXPECT_TARGET}` and `-expect-acl ${GT_EXPECT_ACL}` with an
  `ExecStartPre` `test -n` on each, and
  `-expect-proxy-protocol=${GT_EXPECT_PROXY_PROTOCOL}`, and `ring.env` is
  not named anywhere in the file; `ghostunnel.service` reads exactly
  `ring.env`, does not name `observers.env`, and carries `WatchdogSec=` as
  a positive count of seconds; no member carries `WatchdogSec=`; no unit
  carries `-accept-no-store-check` or `-accept-no-sandbox`;
- `ghostunnel.service` carries exactly `UMask=0027` and every member unit
  `UMask=0022` and `SupplementaryGroups=gtring-trace`; `tree.tsv` has `gt/`
  as `gt:gtring-trace 2750` and no other `2750` row, and the matrix row for
  `gt` names that enforcement;
- the target `Wants=` all five units.

The other stages need the host; run them as root before the first start:

```
./check-units.sh --verify      # systemd-analyze verify /etc/systemd/system/ghostunnel*.{service,target}
./check-units.sh --tree        # stat -c %U:%G:%a on every tree.tsv directory and on every file under /etc/ghostunnel (the key ring.env names root:gt 0640, cert, CA and policy root:gtring-pem 0640, the env files and tree.tsv root:root 0644, any unnamed PEM root's with nothing for other); id -nG per user; /etc/ghostunnel/tree.tsv identical; /proc hidepid
./check-units.sh --probe       # setpriv as each user: forbidden writes denied (EACCES/EPERM), permitted ones succeed;
                               # then, on a scratch copy of the tree, a slot each user creates under another member's
                               # name is owned by its creator and faulted (I8) by the store's owner within one cycle
./check-units.sh --namespace   # systemd-run with each unit's sandbox lines: outside ReadWritePaths= is EROFS
namei -l /var/lib/ghostunnel-ring/stores/tunnel/halts   # the chain of owners and modes, by eye
systemd-analyze security ghostunnel-obs-admin.service   # what the sandbox leaves open, by eye
```

`--tree`'s checks of `/etc/ghostunnel` also run as an ordinary user over a
directory of that user's files: every file named by `ring.env` (a quoted
`GT_CERT`, the policy taken from `GT_ACL`) is found and compared, and a
wrong owner, a `0644` key, a symbolic link, a directory, an unnamed `0644`
PEM and a `ring.env` without `GT_KEY` each fail. The passing direction
needs root and the `gt` and `gtring-pem` accounts.

What those stages assume of the host: that `systemd-analyze verify` accepts
every directive as spelled (all are documented in systemd.exec(5) and
systemd.service(5) for systemd ≥ 247, `ProtectProc=` being the newest);
that systemd nests a `ReadOnlyPaths=` inside a `ReadWritePaths=` by path
specificity, as systemd.exec(5) describes; that `systemd-run -p` accepts a
space-separated `ReadWritePaths=` list; that `${VAR}` in
`ExecStartPre=/usr/bin/test -n "${VAR}"` expands to the empty argument when
unset (systemd.service(5) says it does); that `useradd --user-group` and
`gpasswd -a` exist (shadow-utils; on a distro without them, create the
same accounts with its own tools and re-run `setup-tree.sh`, whose verify
step will confirm or refuse); that the filesystem honours the sticky bit on
directories (ext4, xfs, btrfs do; a network or FUSE filesystem may not, and
then the `--probe` stage fails on the slot tests, which is the point of
running it).

The assumption no script can verify: that `/etc/group` on the host is not
later edited to put a store's owner, or `gt`, into a `gtring-halts-*`
group, a user other than `gt` and the four observers into `gtring-pem`, or
an account that must not read every peer's certificate into
`gtring-trace`. `check-units.sh --tree` re-checks it (and lists any account
in `gtring-trace` beyond the four as a note); run it after any account
change.
