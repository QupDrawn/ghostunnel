---
title: Observer Ring Threat Model
description: What the observer ring guarantees, what it does on a fault, the residual issues that hold in this tree, and the limits no deployment can establish about itself.
weight: 30
---

This page covers one deployment of this fork as the tree defines it: the
proxy, the four members (`tunnel`, `admin`, `material` and the coordinator
`super`), the store tree under `/var/lib/ghostunnel-ring/stores/` and the
trace root `gt/` with its chain store and material store. Every guarantee
names the code that enforces it, as `file:line` at this revision. The four
members share byte-identical copies of their structural files; a line cited
as `observers/tunnel/<file>:<line>` holds at the same line in every member,
except in `main.go`, which is each member's own.

Read each item by the position it needs and the entry point it uses. The
positions, lowest first: a network client; a local account on the host; an
operator with the files and the reload trigger; a member's own account; root
or the service manager. The entry points: the tunnel listener; an
established connection; the reload trigger with the material files; the
status listener; `/_shutdown`; the configuration and environment files; the
trace root; a member's store; the host itself.

## What the ring guarantees

Only what the code enforces. Nothing here rests on a program agreeing to
behave.

| Guarantee | Mechanism | Where |
|---|---|---|
| The proxy serves only while no store holds a `halt` or `fault`, no `halts/` holds a delivered slot, and the coordinator's newest heartbeat parses, is not a stop and sits within `--ring-heartbeat-max-age` of the clock in either direction. | `Gate.Check` walks every store, then the coordinator's heartbeat, and refuses on the first failure. `Accepted` consults it on every accept; a refused connection is closed unserved and `/_status` answers 503. | `ringtrace/gate.go:123-135`, `ringtrace/gate.go:143-168`, `ringtrace/gate.go:209-219`, `ring.go:750-761`, `status.go:281-283` |
| A read the gate cannot make refuses. | No root configured, a root or store that is missing or not a directory (its `lstat`s fail or its `halts/` will not list), an `lstat` that errs, a `halts/` that will not list, a heartbeat over its size bound, one that is not the regular file the `lstat` found once it is opened, or one that will not parse: each is a refusal, never a skipped question. The heartbeat opens without waiting, so a named pipe put in its place is refused rather than waited on. | `ringtrace/gate.go:119-121`, `ringtrace/gate.go:143-158`, `ringtrace/gate.go:179-207`, `ringtrace/heartbeat.go:46-92`, `ringtrace/openread_unix.go:17-28` |
| A serve decision is never reused past the heartbeat's window. | A standing decision is dropped on any change the kernel reports to a path the gate reads, after ten milliseconds with no watcher, after one second under a watcher, and on every reuse the heartbeat's age is judged again by the gate's clock. On Windows the watcher leaves out notifications under `gt\`, a store's `copy*\` and a non-coordinator's `heartbeat\`, and counts every notification once a store, a `halts\` or the coordinator's `heartbeat\` is a reparse point. | `ringtrace/gatestate.go:149-173`, `ring.go:68`, `ring.go:76`, `ringtrace/watch_windows.go:280-321`, `ringtrace/watch_windows.go:334-358` |
| A halt closes the connections in flight. | The watch scans the tree every second and, on a refusal, closes every accepted connection with a `close` of reason `halt`. | `ring.go:781-805`, `proxy/proxy.go:313-330` |
| No byte is forwarded before the connection's record is durable. | The accept, handshake and acl lines are one write under one fsync; the proxy waits for that commit after the dial and before the copy loops, and refuses the connection if the commit failed. | `ring.go:958-972`, `ring.go:1044-1050`, `proxy/proxy.go:801-818` |
| A handshake line never names a chain the store lacks. | The presented chain is written under its SHA-256 before the line that names it; a chain that cannot be stored abandons the connection. A second writer of the same chain returns only after the first's directory sync, and a directory sync that fails fails every later write into that store. | `ring.go:1121-1130`, `ringtrace/store.go:144-187`, `ringtrace/store.go:191-219`, `ringtrace/store.go:226-231` |
| A refused accept leaves a record. | The gate's refusal writes the connection's `accept` and a `close` of reason `halt`. | `ring.go:757-761` |
| A trace that cannot be written stops serving. | The first emitter or store error is sticky; every later accept is refused until restart. The emitter opens before any listener binds, and a failure to open it refuses the start. | `ring.go:634-654`, `ring.go:682-704`, `main.go:1086-1107` |
| Every served handshake is re-verified from bytes, and every access decision re-run. | Each member reads the chain by its hash, the CA bundle by the hash the start line or the last successful reload recorded, verifies at the recorded time, re-runs the rule set on the leaf with the policy included, and compares its decision and rule with the recorded ones. A file whose bytes do not hash to its name is refused. A line's verdict is kept across cycles only while every file it rests on reads and hashes clean on the cycle; on any other cycle the line is judged again. | `observers/tunnel/substance.go:663-687`, `observers/tunnel/substance.go:712-743`, `observers/tunnel/substance.go:758-795`, `observers/tunnel/substance.go:1184-1198`, `observers/tunnel/substance.go:1204-1235`, `observers/tunnel/substance.go:1253-1266`, `ringtrace/store.go:284-306` |
| The recorded rule is the verifier's own. | The rule of an allow is named again from the leaf the handshake parsed, by the same walk the verifier makes; the verify cache a reload empties is not consulted. A completed handshake no rule names is recorded as a deny and refused before the dial. | `ring.go:1023-1028`, `auth/auth.go:519-536`, `ring.go:1140-1147`, `signals.go:182` |
| A member's memory never answers for a policy that is no longer in force. | The rules' memory is keyed on the chain, the rule set, the policy hash in force at the line and the query; a reload that brings another policy starts a fresh memory. A verdict the policy gave answers from memory only after the policy file has read and hashed clean on the cycle. | `observers/tunnel/substance.go:572-583`, `observers/tunnel/substance.go:979-988` |
| A resumed session is verified again. | The re-verification hook runs the verifier on a resumed handshake; a handshake recorded as unverified fails `handshake-verified` or `resumption-verified`, and tickets without re-verification fail `resumption-bound`. | `certloader/tlsconfig.go:179-200`, `observers/tunnel/surface_tunnel.go:285-291`, `observers/tunnel/surface_material.go:57-59` |
| The listener, the backend target, the rule set and the PROXY protocol mode are held to a second file the proxy never reads. | `listener-expected`, `target-expected`, `acl-expected` and `proxy-protocol-expected` compare the start line with `observers.env`; the proxy's unit reads `ring.env` alone. | `observers/tunnel/tunnelchecks.go:236-247`, `deploy/systemd/ghostunnel-obs-tunnel.service:29`, `deploy/systemd/ghostunnel-obs-tunnel.service:59-62`, `deploy/systemd/ghostunnel.service:39` |
| The material on disk is what the proxy loaded, inside its validity window, and the key is private. | The proxy records the SHA-256 of the bytes its loaders read and parsed or compiled, never of a second read of the path, and after a failed reload the material still in use. `material-loaded` hashes each file against the recorded hash and refuses any certificate block outside its window; `key-private` refuses a key with any bit beyond owner read and write and group read, or one the member itself could read. | `ring.go:520-583`, `observers/material/materialchecks.go:315-340`, `observers/material/materialchecks.go:413-459`, `observers/material/keyprivate.go:56-73` |
| The installed proxy binary is the build the operator expects, and stays the file the proxy started from. | The proxy hashes the file it was executed from once, before the process sandbox applies, records it with its path resolved through symbolic links, and refuses to start when it cannot. `binary-expected` hashes the file at that path in full every cycle, refusing a link or a file above 512 MiB, and fails with `changed` when the bytes differ from the recorded hash and with `unexpected` when the recorded hash is not `-expect-binary-sha256`, which the member requires at start. The operator takes the expectation from the build output where the build is reviewed, before the binary is copied to the host, and the member reads it from `observers.env`; it never comes from the host. | `main.go:845-848`, `ring.go:410-412`, `ring.go:446-453`, `ring.go:462-481`, `observers/material/materialchecks.go:229-231`, `observers/material/materialchecks.go:351-400`, `observers/material/main.go:217-225`, `deploy/systemd/ghostunnel-obs-material.service:38`, `deploy/systemd/ghostunnel-obs-material.service:57` |
| The trace can only grow. | Each member remembers the length and hash of every segment prefix it read; a prefix that changed, shrank or vanished fails `trace-consistent` every cycle until the boot changes. A segment is read by content, up to the first NUL, never by size. | `observers/tunnel/tracememory.go:82-118`, `observers/tunnel/gtreader.go:743-788` |
| A quiet proxy and a dead one leave different traces. | The proxy writes a `tick` every five seconds; `tick-fresh` fails when the newest tick, or the start line before the first tick, is more than thirty seconds from the member's clock in either direction. | `ring.go:250-261`, `main.go:176`, `observers/tunnel/tracememory.go:45`, `observers/tunnel/tracememory.go:54-69` |
| One live proxy, and the one the trace names. | `boot-ambiguous` requires the highest boot's pid live and no second live pid among the boots; `proxy-process-alive` requires the process to have started within two minutes before its start line. The three members that run these keep `ProtectProc=default`. | `observers/tunnel/bootliveness.go:141-185`, `observers/admin/procstart.go:93-106`, `deploy/systemd/ghostunnel-obs-tunnel.service:81`, `deploy/systemd/ghostunnel-obs-admin.service:65`, `deploy/systemd/ghostunnel-obs-material.service:72` |
| A boot that ended is judged once. | The boot a member read last cycle, once another is current and its newest line is older than the tick age, is judged for an abort, a torn tail, every connection left open and the failed accepts before an abort. | `observers/tunnel/tracememory.go:199-238`, `observers/tunnel/tracememory.go:256-319` |
| The status listener's death is recorded and refuses until restart. | The first `Serve` error writes a `refusal` line and is sticky; `status-listener-up` fails on that line for the rest of the boot. | `ring.go:663-676`, `main.go:1471-1480`, `observers/tunnel/surface_admin.go:93-101` |
| A failed reload refuses until a reload succeeds. | A reload that failed, could not be hashed or could not store its bundle is sticky; `reload-succeeded` fails on the line. | `ring.go:836-861`, `observers/tunnel/surface_material.go:43-56` |
| The status surface binds loopback or asks for a certificate, redacts the command line, and gates `/_shutdown` by the tunnel's own rule. | `status-listener-bound`, `pprof-cmdline-redacted` and `shutdown-authorized` judge the start line and every shutdown line; a shutdown caller is held to the server ACL's verifier. | `observers/tunnel/surface_admin.go:64-92`, `main.go:1258-1274`, `ring.go:870-881`, `main.go:1295-1299` |
| Every member checks every other, with the gate's rules. | Each cycle runs the verdict procedure over the three others; a heartbeat's timestamp is judged in both directions and a duplicate key refuses the parse, as the gate refuses it. | `observers/tunnel/cycle.go:159-165`, `observers/tunnel/verdict.go:93-100`, `observers/tunnel/encoding.go:316-317`, `ringtrace/jsonstrict.go:92-94` |
| One writer per path, proved against the kernel. | Ownership, mode and the sticky bit on every directory, and each unit's `ReadWritePaths=`; each member `lstat`s its own store every cycle and fails `own-store-private` on any drift from the tree. | `deploy/tree.tsv:21-57`, `deploy/systemd/ghostunnel-obs-tunnel.service:91-109`, `observers/tunnel/ownstore.go:171-203` |
| A slot under another member's name is reported. | The owner of each `halts/` checks every entry's owning uid against the account the named member runs as (`-slot-owners`), and fails `I8` naming the file and the uid. | `observers/tunnel/halts.go:137-161`, `observers/tunnel/halts.go:187-210`, `observers/tunnel/ownstore_linux.go:22-28`, `deploy/systemd/ghostunnel-obs-tunnel.service:52` |
| Stopping is one member's decision; starting again is everyone's. | A member with any failing check writes its halt and a slot in every other store, the coordinator's first; it clears only when no store holds a `fault` and the coordinator's own `halt` is gone. | `observers/tunnel/halts.go:257-291`, `observers/tunnel/halts.go:294-329` |
| The trace is readable by the four members and nobody else. | `gt/` is `gt:gtring-trace 2750`; the emitter creates `0750` directories and `0640` files under `UMask=0027`; each member unit grants the group. | `deploy/tree.tsv:57`, `ringtrace/emitter.go:206-209`, `deploy/systemd/ghostunnel.service:38`, `deploy/systemd/ghostunnel-obs-tunnel.service:22` |
| A check that cannot run has not passed. | An unreadable trace fails every check over the current boot; a cycle past the cadence fails `cycle-within-cadence`. | `observers/tunnel/tunnelchecks.go:211-219`, `observers/tunnel/tunnelchecks.go:224-233`, `observers/tunnel/cycle.go:214-217` |
| The sandbox is attempted, and its state is recorded and judged. | The proxy refuses to start on any state but `applied`, or `unsupported` accepted by name on this OS; `sandbox-applied` halts on every other state. | `ring.go:127-147`, `observers/material/materialchecks.go:282-308` |
| Client mode and a tunnel without a verifier halt by construction. | A handshake in client mode fails `handshake-substance`; a handshake under `--disable-authentication` is recorded unverified and fails `handshake-verified`. | `observers/tunnel/substance.go:1187-1189`, `ring.go:1003-1005`, `observers/tunnel/surface_tunnel.go:285-291` |

## What the ring does on a fault

**A member's own failing check.** The member writes a `fault` in its own
store, its own `halt`, and a slot in every other store's `halts/`, the
coordinator's first (`observers/tunnel/halts.go:257-291`,
`observers/tunnel/main.go:397-408`). The gate refuses the next accept; the
watch closes the connections in flight at its next scan. The three other
members relay the halt into any store where their own slot is absent
(`observers/tunnel/halts.go:331-352`).

**The coordinator's heartbeat.** Absent, stale, ahead of the clock, a
deliberate stop, over its size bound or malformed: the gate refuses on its
own (`ringtrace/gate.go:175-220`), and the three members fail
`member-present` or `member-fresh` on the same heartbeat
(`observers/tunnel/verdict.go:51-64`, `observers/tunnel/verdict.go:79-100`).

**A member's heartbeat.** Absent, stale or retired: the three others each
halt as above.

**The trace.** Unreadable, inconsistent with what was read, or stale: every
member fails `trace-readable`, `trace-consistent` or `tick-fresh` on its
own. A second live proxy, or a highest boot whose process is dead, fails
`boot-ambiguous`. A boot that ended without a `shutdown` line fails
`boot-ended`.

**The proxy's sticky refusals.** An emitter or store error
(`ring.go:634-654`), a failed reload (`ring.go:836-861`), a status listener
that died (`ring.go:663-676`), or the emitter's clock running backwards
(`ringtrace/emitter.go:503-504`): the proxy refuses every accept. The
watchdog is fed only while no sticky refusal is in force, so the service
manager aborts and restarts the proxy after fifteen seconds
(`main.go:298-308`, `status_linux.go:83-94`,
`deploy/systemd/ghostunnel.service:79`). A failed reload clears earlier when
a later reload succeeds. A gate refusal is not unhealthy: the proxy keeps
ticking and is not restarted for a condition the ring will lift.

**A record whose commit failed.** The connection is closed, the backend
closed, nothing forwarded (`ring.go:958-972`); then the sticky refusal above.

**A surface owner that disagrees with a peer.** Every member computes every
surface's checks; one that finds a check failing that the owner did not
publish fails `surface-disagree` (`observers/tunnel/surfaces.go:121-165`).

**A refused shutdown request.** Any `shutdown` line not authorized, or one
over the status endpoint with no peer, fails `shutdown-authorized` for the
rest of the boot (`observers/tunnel/surface_admin.go:77-92`).

**A member that cannot start or publish.** It exits
(`observers/tunnel/main.go:38-57`, `observers/tunnel/main.go:83-92`); the
others halt on its stale heartbeat; the service manager restarts it
(`deploy/systemd/ghostunnel-obs-tunnel.service:64`).

**A halt beyond `-max-halt-bytes`.** In force, not relayed
(`observers/tunnel/halts.go:38-42`, `observers/tunnel/main.go:137`).

**The proxy's start.** An empty trace or store root, a missing or too-small
heartbeat window, a tick at or above it, a sandbox state not accepted, or a
status flag on a plain-HTTP listener refuses the start
(`ring.go:84-101`, `ring.go:127-147`, `main.go:1420-1425`).

### The bounded windows

| Window | Bound | Where |
|---|---|---|
| The standing gate decision | Ten milliseconds with no change notification; one second under a running watcher; dropped on any event the kernel reports to a path the gate reads. | `ring.go:68`, `ring.go:76`, `ringtrace/gatestate.go:149-173` |
| A connection accepted before a halt | Forwarded until the watch's next scan, one interval later, at most two when an accept's scan straddles the halt and a tick. | `ring.go:781-805` |
| A member's cycle | Floor 300 ms, ceiling 10 s; a check's result is applied at the cycle's end; a heartbeat more than 30 s from a reader's clock is stale. | `deploy/systemd/ghostunnel-obs-tunnel.service:56-58`, `observers/tunnel/cycle.go:232`, `deploy/systemd/ghostunnel-obs-tunnel.service:58` |
| A line written after a member's read | Judged by that member's next cycle. A substance halt lands within the remainder of the current cycle plus the next whole one, then the watch interval. | `observers/tunnel/cycle.go:189-199` |
| A member's first cycle after a restart | Has no basis: a peer's chain is accepted without a comparison until the next cycle. | `observers/tunnel/verdict.go:102-110` |
| A boot that ended | Judged once its newest line is older than the tick age; until then it may be a second live process, which is `boot-ambiguous`'s to report. | `observers/tunnel/tracememory.go:265-267` |

## Residual issues

Grouped by the lowest position that reaches each. Availability items are
listed, not ranked: what each records is whether the stop is true and
whether recovery needs an authority outside the ring.

### A network client

#### The members' work per cycle

Position: a network client at the tunnel listener, with or without a
certificate. A presented certificate need only parse: the chain is stored
whatever the handshake's outcome (`ring.go:1121-1130`), and a gate refusal
still writes two lines (`ring.go:757-761`).

Reaches: every cycle, every member reads and hashes every segment of the
current boot whole (`observers/tunnel/gtreader.go:593-634`,
`observers/tunnel/gtreader.go:807-827`). The decode resumes from memory
for bytes proven unchanged; the tunnel surface's judgement is kept for the
records the read proves unchanged and extended by the new ones
(`observers/tunnel/judgememory.go:63-100`); a chain's verification or
refusal is remembered under content hashes
(`observers/tunnel/substance.go:758-795`); and every chain file, CA bundle
and policy file a kept verdict rests on is read and hashed again
(`observers/tunnel/substance.go:1253-1266`). What the boot's length costs
each cycle is those reads and hashes, and walks over what was decoded and
kept: the admin and material surfaces' records and the tunnel surface's
connections.

What the ring does: a cycle past the cadence fails `cycle-within-cadence`
and halts (`observers/tunnel/cycle.go:214-217`), recorded as the member's
own overrun and naming no client; past thirty seconds the member is stale
to its peers. The member keeps cycling and clears when a cycle comes back
under the cadence. Availability, listed. The rate a client needs, and
whether cycles stay past the cadence once the gate refuses, are timing
facts the tree does not state.

#### The accept loop under descriptor exhaustion

Position: a network client holding TCP connections through the gate into
the handshake for the connect timeout (`main.go:149`), with no concurrency
cap by default (`main.go:152`, `proxy/proxy.go:542-544`).

Reaches: `Accept` fails and the loop backs off, writing an `accept-error`
line per step (`proxy/proxy.go:695-704`, `ring.go:769-771`). While
descriptors are exhausted, a first-seen chain that cannot be stored is the
proxy's sticky refusal (`ring.go:1121-1130`, `ringtrace/store.go:255-260`):
a watchdog abort and a restart into a new boot.

What the ring does: `accept-loop` fails on every member within thirty
seconds and halts, clearing thirty seconds after the errors stop
(`observers/tunnel/surface_tunnel.go:333-355`). After an abort,
`boot-ended` reports the failed accepts that preceded it
(`observers/tunnel/tracememory.go:303-317`). No unit sets a descriptor
limit; the limit is the host's. Availability, listed.

#### Trace growth

Position: a network client. Every connection appends to the current boot;
every first-seen presented chain adds a file of up to one mebibyte
(`ringtrace/chain.go:30`); nothing in the tree deletes a boot, a segment or
a chain file (`deploy/README.md:345-365`).

Reaches: disk exhaustion. A line or a chain that cannot be written is the
sticky refusal; the restart must create a boot directory and write a start
line to open (`ringtrace/emitter.go:312-324`), which a full filesystem
refuses; a member whose staged write fails exits
(`observers/tunnel/main.go:83-92`).

What the ring does: halts, fail-closed. Recovery is freeing disk and
restarting, outside the ring. Retention is a deployment policy the tree
states and does not run (`deploy/README.md:345-365`). Availability, listed.

### A local account on the host

#### Profiles for a trusted but unentitled identity

Position: a local account holding a certificate the trust store verifies
but the tunnel's rule set does not allow, when `--enable-pprof` is set (off
by default, `main.go:166`; absent from the proxy's unit,
`deploy/systemd/ghostunnel.service:58-68`). The status listener is loopback
by construction, or `status-listener-bound` halts.

Reaches: profiles, goroutine dumps and runtime traces. The profiling
endpoints require a verified client certificate and nothing more
(`main.go:1377-1387`); `/_shutdown` on the same listener is held to the
tunnel's rule as well (`main.go:1269`).

What the ring does: nothing. No trace line records a profile request. The
start line records that the command line is redacted, not that profiling is
served (`ringtrace/format.go:87-92`).

#### Metrics during a halt

Position: any local process reaching the status listener.

Reaches: `/_metrics` answers with counters and timers while serving is
refused (`main.go:1357-1371`). `/_status` answers 503 with the reason, to a
verified certificate only in its detailed form (`status.go:230-236`,
`status.go:281-283`).

What the ring does: nothing; the counters carry traffic shape and no
customer bytes. Listed.

#### A refused shutdown request

Position: any local process, with no certificate, when `--enable-shutdown`
is set (off by default, `main.go:167`; absent from the unit).

Reaches: a `POST /_shutdown` without a verified certificate is refused and
recorded with a constant source, no peer and a constant detail
(`main.go:1258-1262`, `ring.go:886-888`). The trace cannot say which
process asked.

What the ring does: `shutdown-authorized` fails on the line for the rest of
the boot (`observers/tunnel/surface_admin.go:77-92`), a deliberate halt
whose requester is unattributed. Availability, listed.

### An operator with the files

#### Flags the start line does not carry

Position: an operator who can edit `ring.env` and restart the proxy. The
file is `root:root 0644`; `$GT_ACL` is word-split on purpose
(`deploy/systemd/ghostunnel.service:57`,
`deploy/systemd/ghostunnel.service:65`).

Reaches: the start line records the mode, listener, target, PROXY protocol
mode, status address, rule set, lifetime cap, sandbox state, material and
executable (`ringtrace/format.go:75-112`). The tunnel member holds the
listener, target, rule set and PROXY protocol mode to `observers.env`
(`observers/tunnel/tunnelchecks.go:236-247`), and the material member
holds the executable's checksum to it
(`observers/material/materialchecks.go:351-360`). A flag carried in
`$GT_ACL` that the start line does not record, among them
`--enable-shutdown`, `--enable-pprof`, `--connect-timeout`,
`--max-concurrent-conns` and `--warm-backend-connections`, changes the
proxy with the ring green.

What the ring does: nothing on these flags. `/_shutdown` and the profiling
endpoints stay gated by a verified certificate and refuse to start on a
plain-HTTP listener (`main.go:1373-1387`, `main.go:1420-1425`).

#### A policy that consults the clock

Position: an operator deploying an OPA policy that reads time or the
environment.

Reaches: the member's evaluation and the proxy's differ whenever the clock
decides differently; such an evaluation is never remembered
(`observers/tunnel/substance.go:888-935`).

What the ring does: `acl-substance` fails on every line where the two
differ, for as long as they differ. Availability, listed.

#### Material outside its validity window

Position: an operator, or time.

Reaches: any `CERTIFICATE` block in the certificate or CA bundle outside its
window now, an intermediate the proxy never chains through included.

What the ring does: `material-loaded` fails from that instant until the
file is replaced and reloaded (`observers/material/materialchecks.go:413-459`).
A deliberate refusal. Availability, listed.

#### Client mode and a tunnel without a verifier

Position: an operator running client mode, or the server with
`--disable-authentication`.

Reaches: client mode's first connections are forwarded until the first
recorded handshake line is judged and the watch closes them: at most the
remainder of the current cycle plus the next, then the watch interval
(`observers/tunnel/substance.go:1187-1189`, `ring.go:781-805`). A tunnel
without a verifier records every handshake unverified (`ring.go:1003-1005`).

What the ring does: halts by construction, after the window above. A
deliberate refusal. Availability, listed.

#### An authorized stop

Position: an operator, through a signal or an allowed `/_shutdown`.

Reaches: the proxy drains and exits 0, which `Restart=on-failure` does not
restart (`deploy/systemd/ghostunnel.service:69`). A drain that overruns
exits 1 and is restarted. The trace closes last: `Wait` returns only once
every connection's `close` line is recorded, and the timed reloads, the
status handlers, the tick and the watch stop before the trace is closed
(`proxy/proxy.go:737-746`, `main.go:1145-1146`, `signals.go:149-153`,
`ring.go:811-824`).

What the ring does: halts until an operator starts the proxy. Deliberate.
Availability, listed.

#### Retention

Position: an operator holding the trace root.

Reaches: the tree deletes nothing and states retention as a deployment
policy with three rules the readers impose: only a finished boot goes, a
boot goes whole, and the chain and material stores go only with their
boots (`deploy/README.md:345-381`). A rule that breaks the second halts the
ring on `boot-ambiguous` until the rest of the boot is gone.

What the ring does: halts on a boot made partial; nothing on a boot removed
whole. Listed.

### A member's own account

#### A slot under another member's name

Position: a member's own account, in a peer's `halts/`. The grant is the
directory: `root:gtring-halts-<store> 1775`, so any of the three writers may
create any new name (`deploy/tree.tsv:27`, `deploy/tree.tsv:35`,
`deploy/tree.tsv:43`, `deploy/tree.tsv:47`,
`deploy/systemd/ghostunnel-obs-tunnel.service:101-103`).

Reaches: a halt in force by existence under a name the named member never
wrote. The named member's clear removes only its own slot and the sticky
bit refuses the unlink to everyone else (`observers/tunnel/halts.go:294-329`).

What the ring does: the store's owner fails `I8` with the file and the
creating uid every cycle the slot stands (`observers/tunnel/halts.go:137-161`),
so the ring reports the slot rather than all clear around it. The slot
stays until root, or the account that created it, removes it
(`deploy/README.md:741, 749-757`). Nothing a member can create makes the ring
serve when it should not. Availability, listed.

#### A fault past its size bound

Position: a member with many failing subjects.

Reaches: the writer does not bound its fault
(`observers/tunnel/cycle.go:317-345`); peers read it within `-max-fault-bytes`,
8192 by default (`observers/tunnel/main.go:136`). Past the bound every peer
fails `S4` on the file (`observers/tunnel/verdict.go:165-169`) and, with no
parsed fault, `surface-disagree` on each surface check it computes failing
(`observers/tunnel/surfaces.go:148-162`); the failing list does not reach
them.

What the ring does: halts. The first failing check, its subject and the
count still reach every store through the owner's halt and slots
(`observers/tunnel/halts.go:257-266`). Listed.

#### Every presented chain, readable by every member

Position: a member's own account, or any account in `gtring-trace`.

Reaches: the subject, issuer, serial, SANs and fingerprint of every
presented leaf (`ring.go:1249-1272`) and the DER of every presented chain,
refused ones included (`ring.go:1121-1130`), for as long as the files exist.
The group holds exactly the four members; an operator who joins it reads
the same (`deploy/README.md:314-318`).

What the ring does: nothing inside the ring reads less than the whole; the
members need the chains to re-verify them. No other local account can list
`gt/` or open a file in it by name. Listed.

### Faults with no actor

#### The emitter's own failure

Reaches: an emitter or store error is logged and made sticky, and by
definition writes no line (`ring.go:634-654`). The watchdog aborts and
restarts the proxy; the members judge the ended boot as aborted
(`observers/tunnel/tracememory.go:269-277`) and see the cause in no line.
When the restart cannot open a new boot, `tick-fresh` fails on every member
within thirty seconds.

What the ring does: refuses, restarts, and records the abort without its
cause. Listed.

#### A member past the service manager's start limit

Reaches: a member that keeps failing to start is given up on
(`deploy/systemd/ghostunnel-obs-tunnel.service:64`,
`deploy/README.md:727-729`); its heartbeat goes stale.

What the ring does: halts until an operator acts. Recovery is external.
Availability, listed.

#### No watchdog off Linux

Reaches: on a platform without a service-manager integration the watchdog
call is a no-op (`status_other.go:30-32`), and the Windows service reports
running on readiness whatever the gate says (`windows_service.go:196`).

What the ring does: the sticky refusals hold until an operator restarts the
proxy. Non-Linux only. Availability, listed.

#### A kernel without landlock network rules

Reaches: on a landlock ABI below four the network rules are dropped and the
filesystem rules kept; the process reports `applied`
(`landlock_linux.go:267-282`, `landlock_linux.go:452-455`,
`landlock_linux.go:61`).

What the ring does: `sandbox-applied` passes on the recorded state. Whether
best-effort mode restricts what `applied` implies is the kernel's and the
vendored library's. Listed.

#### The tail of a boot that ended

Reaches: a boot that ended is judged for its abort, its torn tail, its open
connections and its failed accepts, and for nothing else
(`observers/tunnel/tracememory.go:240-255`). A handshake or access decision
written after a member's last read of that boot and before its end is not
re-verified by that member. A member started after the restart judges the
ended boot not at all (`observers/tunnel/tracememory.go:187-190`).

What the ring does: judges the tail once per member. Listed.

#### Backend connections during a halt

Reaches: the warm pool dials the backend before any gate read
(`proxy/proxy.go:641`) and the status probe dials it on request. The pool is
drained on every `CloseAll` (`proxy/proxy.go:323-328`).

What the ring does: nothing; no customer bytes cross these connections.
Listed.

## Limits the ring declares

What no deployment can establish about itself, each with the line where the
limit shows (`observers/SPEC.md:909-911`).

**The build.** The material member holds the installed binary to the
SHA-256 the operator took from the build output where the build is
reviewed (`observers/material/materialchecks.go:351-360`). It cannot
establish that the build output, or the checksum taken from it, came from
the intended build: a tampered build hashes to its own bytes, and an SBOM
generated from it records them. That needs a signature or an attestation
from the build itself.

**The host, and the proxy's uid.** Every listener is opened with the
reuse-port option (`socket/net.go:120`); the emitter's lock is per trace
root (`ringtrace/emitter.go:260-271`); `boot-ambiguous` looks under one root
(`observers/tunnel/bootliveness.go:141-153`). A second process under uid
`gt` beside the observed proxy, or code already running inside it, serves
unobserved. The shipped `gt` account has no shell
(`deploy/setup-tree.sh:89-90`), so that position is root's or the proxy's
own. The same writer can forge a boot under `gt/`: one no process ticks
into fails `tick-fresh` within thirty seconds
(`observers/tunnel/tracememory.go:54-69`) and `proxy-process-alive` on its
start time (`observers/admin/procstart.go:93-106`); one the writer keeps
ticking is not distinguished. It can also substitute a line's chain and
peer before any member's first read: the memory starts at that read
(`observers/tunnel/tracememory.go:111-116`) and no member compares `peer`
with the chain it names (`observers/tunnel/substance.go:1227-1228`). Root
can widen a unit's `ReadWritePaths=`; `own-store-private` catches a change
to ownership or mode, not to a namespace
(`observers/tunnel/ownstore.go:171-203`).

**A member's legitimacy.** Membership is a declared constant
(`observers/tunnel/main.go:122`, `ringtrace/gate.go:80-81`). Nothing enrols
a member or establishes that a store bearing a member's name was meant to
be that member.

**A proxy rewritten not to consult the gate.** The members open no socket
and hold no capability (`deploy/systemd/ghostunnel-obs-tunnel.service:74`,
`deploy/systemd/ghostunnel-obs-tunnel.service:89`); the gate inside the
proxy is the only actuator (`ring.go:750-763`, `ring.go:781-805`); the
service manager acts on exit and on the proxy's own health ping, and a gate
refusal is not unhealthy (`main.go:291-308`). Such a proxy is detected, since
its connections are in a trace every member re-verifies and a trace that
stops is one every member reports, and it is not stopped. Its network rules
are port-only: it may connect to any host on the backend's port
(`landlock_linux.go:183-193`, `landlock_linux.go:97`).

**The ring's own code.** The members mirror the verifier rather than import
it, and the mirror is held to the original by tests
(`observers/tunnel/substance.go:24-29`). A process does not verify itself;
what binds the mirror is outside the running deployment.

## Delegations

Listed and not followed. Anything resting on one of these keeps its mark
where it is used.

- Go's `crypto/tls` and `crypto/x509`: the verifier runs on a full
  handshake, the peer certificates are set before it, and `Verify` compares
  the recorded time with the validity window.
- The vendored libraries: go-landlock's best-effort mode, OPA's evaluation
  and its non-deterministic builtins, go-systemd's notify and watchdog,
  go-reuseport, go-proxyproto, certmagic.
- The kernel: landlock enforcement, inotify delivery and overflow
  (`ringtrace/watch_linux.go:20-28`, `ringtrace/watch_linux.go:104-130`),
  `fdatasync` durability, the sticky bit, `flock` release on death,
  `/proc/<pid>/stat` and `btime`, reuse-port sharing among one uid's
  listeners, the descriptor limit.
- systemd: `${VAR}` expansion, `ReadOnlyPaths=` nested inside
  `ReadWritePaths=`, `Restart=on-failure` and the start limit,
  `WatchdogSec=`, `ProtectProc=`.
- The filesystem and the host: one writer per directory as the ownership
  says, the account database, the mode of `/var/lib`.
- The backend: that it is the intended one; no observer reads it.
- The policy author: that the policy admits only the intended principals.
- The CA: that it issues only to them.
- The test suites and the fixture oracle: they report to whoever edits the
  tree, at a time nothing is serving. A test is not an observer.

## Counts

| | |
|---|---|
| Guarantees stated | 30 |
| Halt paths | 11, and 6 bounded windows |
| Residual issues | 21, of which 11 are availability items, listed and not ranked |
| Limits declared | 5 |
| Delegations | 9 |
