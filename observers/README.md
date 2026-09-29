# The observer network

Four small programs that watch a ghostunnel deployment and each other. When any one of them finds something wrong, ghostunnel stops serving until every one of them agrees it is fine again.

The rest of this file is the detail of that idea. `SPEC.md` is the precise statement of every file, field and procedure the four members agree on, and `testdata/FIXTURES.md` describes the oracle each of them is judged against. `docs/security/threat-model.md` states what the ring guarantees, with the line that enforces each guarantee, the residual issues that hold in this tree, and the limits it declares.

## The four

Each observer runs as its own process, under its own user, writing to its own store. They are separate processes rather than goroutines in ghostunnel on purpose: goroutines share one address space and one trust domain, so a bug or a compromise in one would be a bug in all of them and could forge any other's verdict. A separate process under a separate user cannot read ghostunnel's memory, cannot write another observer's store, and cannot clear a halt it did not raise. The operating system enforces the boundary, not the code agreeing to behave.

ghostunnel is a single proxy process, so the three structural observers partition its **surfaces** rather than each sitting beside a separate work process.

| | Watches, besides the other three |
|---|---|
| **tunnel** | the mTLS data path: the listener and its port, that client-certificate verification runs on the full handshake and is not skipped on a resumed session, the backend dial target and what the backend is handed ahead of each connection (the PROXY protocol mode), and the per-connection lifetime cap |
| **admin** | the status and admin HTTP surface: that it binds loopback or requires a client certificate, that `pprof` does not expose `cmdline`, that `/_shutdown` is gated, that the status listener is up, and that the process command line carries no secret |
| **material** | the trust material and its reload: the certificate, key, CA bundle and OPA policy files and their validity, that the private key can be read by nobody but its owner and the proxy's group and not by the observer itself, that a failed reload does not keep serving on old material, that the process sandbox ghostunnel attempted at startup was applied (or, where the platform has none, that an operator accepted that on both sides), and that session resumption is configured so it cannot bypass the access-control list |
| **super** | nothing of its own. Only the other three, and ghostunnel's trace, which it reads to judge all three surfaces against what their owners published |

**Every member watches every other member.** Four members, twelve one-way edges, every pair mutual. There is no chain and no hierarchy.

**`super` is the coordinator**, and differs in two ways. It sees more: it holds a copy of all three others' stores, a whole-view comparison no other member can make. And its absence alone stops everything: if its heartbeat goes stale, the proxy's gate refuses on its own, without waiting for any member to decide anything.

## Event and continuous observation

ghostunnel does the work; the observers watch. Two kinds of observation meet in the store.

- **Event observers leave traces.** ghostunnel itself, at each moment that matters (a connection accepted, a handshake verified or refused, an access decision, a close, a reload outcome, a shutdown request, a failed accept, a refusal), appends one line to a trace it owns, one JSON object per line (`ringtrace/README.md`). ghostunnel holds no authority beyond appending: it can write traces and read the stores, nothing else. The worst a compromised data path can do is stop emitting, which reads as a dead trace. The heartbeats the members publish are what chain: each names the previous one, so a gap or a rewrite in a member's own record is visible.
- **Continuous observers validate those traces.** The four members read the traces continuously and check the invariants below. **If a continuous observer goes down, everything halts:** its heartbeat goes stale, and a stale member is treated exactly like a raised fault.

## What a member does, once per cycle

Cycles run back to back with a floor of 300 ms (`-min-cycle`) and a ceiling of 10 s (`-cadence`): the ceiling is the longest a cycle may take and still count, not a pace.

**About each of the other three**

- Is its store readable, and is there a heartbeat with something in it
- Has its heartbeat changed recently enough, and is its timestamp within `-heartbeat-max-age` of this member's clock, in either direction
- Does its heartbeat chain hang together, each entry naming the one before it
- Is the copy it wrote the same as the original it came from
- Does what it computes over ghostunnel's trace for that member's surface agree with what that member published: every check of the surface listed in the member's heartbeat, and every failure this member computes named in the member's fault (`surface-disagree`; every member, `super` included, carries its own copy of every surface's trace-only rules)

**About itself**

- Can it write its own store, and did its last heartbeat read back as written
- Is its own store still owned only by it, and not writable by the work beside it: the store root, `heartbeat/`, `halts/`, its own `fault` and `halt`, and the copy directories in it are owned and moded as `deploy/tree.tsv` says, and `halts/` is not writable by this member (`own-store-private`; on an OS with no such ownership the check fails unless the member is started with `-accept-no-store-check=<os>` naming that very OS, the rule of `-accept-no-sandbox` exactly)
- Did its last cycle finish inside the cadence
- Does its store hold only the files it is supposed to hold
- Is its own record of when it started observing readable (`observing-since`)
- Is ghostunnel's trace still what it read last cycle: a segment's content, its bytes before the first NUL (the live segment is pre-extended and read by the segment rule of SPEC 14), may only grow, never change or shrink or vanish under a reader (`trace-consistent`)
- Is ghostunnel's trace still ticking: the newest `tick` line of the current boot, or its start line before the first tick, is within `-tick-max-age` (default 30 s, above the proxy's `--ring-tick` of 5 s; the same value on every member) of this member's own clock (`tick-fresh`, all four members, each on its own; an unreadable trace fails it too)
- Is there one live ghostunnel, not two: the pid of every boot's start line is asked of the operating system, and more than one live is ambiguous (`boot-ambiguous`, the three members with a surface)
- How did the boot that just ended end: once, in the cycle after it observes a boot change and the old boot has stopped writing, each member reads the old boot's tail and reports it aborted when it holds no `shutdown` line, torn when its last line was cut, every connection it left without a close, and the failed accepts that preceded an abort (`boot-ended`, all four members, each on its own; SPEC 14.3 says exactly what once means)

**About ghostunnel** (its assigned surface)

- **tunnel:** the listener the proxy reports in its start line is the one the operator expects; every handshake the trace records as accepted completed client-certificate verification on that handshake, resumed or not (the configuration's promise to re-verify on resumption is not taken as evidence; what happened is); every connection served had an allow decision before it, and one refused was closed as refused; no connection outlives the configured lifetime cap; the accept loop is accepting: no `accept-error` line of the current boot within the last `-tick-max-age` (`accept-loop`, computed by every member and published by this one); every handshake the trace records as verified presented a chain, kept under `gt/chains/`, that the member itself verifies against the CA bundle kept under `gt/material/` by the hash the start line or the last successful reload recorded, and every access decision is the one the member itself reaches by re-running the recorded rule set on that chain's leaf, the OPA policy included (`handshake-substance`, `acl-substance`; computed by every member and published by this one, so the ring's judgement of the data path does not rest on the proxy's word about its own verification); when `-expect-acl` is set, the access-control rules the start line records are, as a set, exactly the ones the operator expects (`acl-expected`); when `-expect-target` is set, the backend target the start line records is exactly the one the operator expects (`target-expected`, as `listener-expected` for the listener); and, always, what the start line says the backend is handed ahead of each connection (`proxy_protocol`: nothing, or a PROXY protocol v2 header with the addresses, with the TLS metadata, or with the client's whole certificate) is the mode the operator expects, `off` when nothing was said (`proxy-protocol-expected`; there is no way to expect nothing). It opens no socket: the members run with no network at all, so whether the port answers is read from the trace, not probed.
- **admin:** the status listener binds loopback or requires a client certificate; `/debug/pprof/cmdline` is not served unredacted; `/_shutdown` requires authorization; the status listener is up: no `refusal` line of the current boot says it died (`status-listener-up`, computed by every member and published by this one; the proxy refuses to serve from that line on until restart); the process command line the admin surface could reveal carries no secret. Reading that command line is the admin observer's own competence, with no opt-in on any OS: on Linux it reads `/proc/<pid>/cmdline`, on Windows the process's own parameter block (the PEB's `RTL_USER_PROCESS_PARAMETERS`, split by `CommandLineToArgvW`), failing closed on a process it may not open or one of another word size; a build with neither reader fails the check. And the process the start line names is the process that wrote it: it exists, and its start time (Linux `/proc/<pid>/stat` over `btime`, Windows `GetProcessTimes`) is not after the start line and not more than two minutes before it, so a reused pid does not pass (`proxy-process-alive`).
- **material:** the certificate, key, CA bundle and OPA policy on disk are the ones ghostunnel loaded and are inside their validity window; the executable the start line names is still the file ghostunnel started from, and its SHA-256 is the one the operator expects from outside the host (`binary-expected`: `-expect-binary-sha256` is required, and the file is hashed in full every cycle; the value is taken where the build is produced and reviewed, before the binary is copied to the host, as `sha256sum` of the build output there or from the SPDX document `go tool mage sbom:generate` writes beside that output, and never from upstream's release SBOMs, which cover upstream's binaries only, carry no ring and are not this proxy); the private key the start line names is a regular file with no permission bit beyond owner read and write and group read, and this member is neither its owner nor in a group that may read it (`key-private`, from an `lstat`, never a read; a start line naming no key, a key that cannot be stat'ed, or a build without POSIX ownership fails it, and there is no flag to accept that); the last reload succeeded, and a failed reload halted rather than kept serving old material; the process sandbox ghostunnel attempted at startup was applied. The sandbox itself is the host's; what the ring holds is that ghostunnel attempted it and reported truthfully (`sandbox_state` in the start line), and that where the platform has no facility (`unsupported`) an operator said so explicitly on both sides of the boundary: `sandbox-applied` then passes only on three-way agreement, ghostunnel's `--accept-no-sandbox=<os>` as recorded in the start line, the material observer's own `-accept-no-sandbox=<os>`, and the OS the observer runs on all equal. Every other state (`disabled`, `failed`, `skipped`) halts, and an observer acceptance beside any state but `unsupported` is stale and halts too: the platform has a facility now.

## What happens when something is wrong

1. The member that found it writes a **fault** file in its own store when the failing check is one of its own, a **halt** file, and drops a copy of that halt into every other member's `halts/` folder.
2. Every other member sees the halt next cycle and passes it on.
3. ghostunnel stops serving: every new connection is refused unserved and the status surface answers 503. ghostunnel reads the stores on every accept; a halt, a fault, a delivered halt, or a stale `super` heartbeat refuses at once. A connection already being proxied is closed too, within one second of the halt, with a `close` of reason `halt` (`ringtrace/README.md`, section 3).

**Stopping is one member's decision. Starting again is everyone's.** A member clears only when no store holds a fault and no halt is in force anywhere. A member that deletes its own halt has changed nothing, because the other three still hold theirs.

**A halt nobody raised is still reported.** A file in a member's `halts/` under another member's name is a halt in force by existence, whoever created it. The owner of that `halts/` checks every cycle that each entry there is owned by the account of the member it is named for (`-slot-owners`, the account each member runs as, given to every member); one that is not is the owner's own failing check, `I8`, naming the file and the uid that wrote it, so the ring reports the forged slot in the owner's fault instead of reporting all clear around it. The named member never wrote it and cannot remove it; it stays until root, or the account that created it, removes it (`deploy/README.md`, "When a halt persists").

Nothing is stopped from *starting*. Processes come up, the observers keep cycling. What stops is the proxying.

## Where it keeps things

```
/var/lib/ghostunnel-ring/stores/
  tunnel/    heartbeat/    the last few, newest wins
             fault         what this member currently finds wrong
             halt          this member says stop
             halts/        halts other members have delivered here
             since         when this member first ran; written once, never rewritten
             copy/         the one peer's heartbeat this member holds for its author (material)
             copy-super/   super's heartbeat, for this member to check
  admin/     the same; copy/ is written by tunnel
  material/  the same; copy/ is written by admin
  super/     heartbeat/, fault, halt, halts/, since,
             and copy-tunnel/, copy-admin/, copy-material/
  gt/        the trace ghostunnel appends (start, accept, handshake, acl, close, reload,
             shutdown, tick, accept-error, refusal), with the chain store chains/ and
             the material store material/; read-only to the observers, written only by ghostunnel
```

Every path has exactly one writer, enforced by directory ownership and the systemd `ReadWritePaths` of each unit, not by the code. Outside its own store a member writes in three places and is the only writer of each: the `halts/` slot named after it in each of the other three (whose owner checks that every slot there is owned by the member it is named for), the one peer's `copy/` it authors, and its own `copy-<name>` in `super`'s store. `super` is the exception: it writes `copy-super/` in all three others, which is what corroborates its own store, the member whose unreachability stops everything and who alone decides the all-clear.

ghostunnel and the observers run as **different users**, and the trace store `gt/` belongs to ghostunnel while the four member stores do not. ghostunnel cannot write what an observer publishes, and an observer cannot write ghostunnel's traces.

## Recovery

The protocol runs backwards. The member whose own check failed clears its fault when the check passes again. `super` then sees no fault at any root and none of its own checks failing, removes its slot from the other three stores and its own halt. Each other member sees the same, plus `super`'s halt gone, and removes its own slots and halt. ghostunnel serves again on the next accept. Nobody restarts anything, and there is no dwell: a condition that flaps halts and resumes as it flaps (SPEC 12).

## Deployment

Five processes, five users, one Linux host, no containers (`deploy/README.md`).

- `ghostunnel` runs as user `gt`; it emits traces into `gt/` and reads the stores.
- `obs-tunnel`, `obs-admin`, `obs-material`, `obs-super` each run as their own user (`gtobs-tunnel`, and so on).
- systemd units set `User=`, and `ReadWritePaths=` grants each process only its own store plus the cross-write slots it authors. Everything else in the store tree is read-only to it.
- The store tree is created once by `deploy/setup-tree.sh` from `deploy/tree.tsv`: store roots root-owned `1775` with the member's group, so the member creates its files through the group bit and cannot rename or remove the directories other members write into; `heartbeat/` and each copy directory owned `0755` by their one writer; each `halts/` root-owned `1775` with a group of the three members that deliver there, the sticky bit keeping each slot to its creator. Files are `0644`, so every member can read every store and write only its own. The one exception is the trace root `gt/`, `gt:gtring-trace 2750` with `0750` directories and `0640` files inside: it names every peer that presented a certificate, so the four observers read it through the group `gtring-trace` and no other account does.

## `ringstatus`

`observers/ringstatus` prints what the ring looks like right now: the verdict banner, each member's state, sequence, last beat, cycle rate and observing time, who has read whose heartbeat, the copies, and any delivered halt slot. It reads the four stores and writes nothing (`observers/ringstatus/README.md`).

## Running the tests and the fixture oracle

Each member is its own package with its own copy of the structural core:

```
go test ./observers/tunnel ./observers/admin ./observers/material ./observers/super
```

Every package's `fixtures_test.go` runs the fixture set under `observers/testdata/fixtures/` (`testdata/FIXTURES.md`): one cycle per fixture over a snapshot of the store tree, compared with the manifest's expected verdicts, failing set, halt, publication, relay and clears. The fixtures need no proxy and no ring; they run anywhere `go test` does. Ownership (`I8`, `own-store-private`) and the process table (`boot-ambiguous`, `proxy-process-alive`) are not properties of a checkout, so each package's own suite covers them with real files and processes on the host it runs on. The substance rules are held to the proxy's verifier by a differential test in each package (`substance_diff_test.go`) that runs the two on the same chains and rule sets.

`observers/testdata/tools/substancepki` generates the committed PKI under `observers/testdata/pki` and the substance, admin and boot fixtures from it.

## Configuration

Every member takes the same structural flags; `deploy/systemd/*.service` carries the values the deployment uses.

| Flag | Default | What |
|---|---|---|
| `-identity` | the member's name | this observer's identity, its store name |
| `-members` | `tunnel,admin,material,super` | the declared membership, including this identity |
| `-coordinator` | `super` | the member that decides the all-clear |
| `-copy-authors` | `tunnel=material,admin=tunnel,material=admin` | the copy cycle as store=author pairs |
| `-slot-owners` | none; required | the account each member runs as, as member=account pairs, every member named |
| `-stores` | `/var/lib/ghostunnel-ring/stores` | the store tree |
| `-traces` | `/var/lib/ghostunnel-ring/stores/gt` | the trace root |
| `-tree` | `/etc/ghostunnel/tree.tsv` | the deployment's tree, for `own-store-private` |
| `-accept-no-store-check` | empty | the OS this member runs on, to accept that `own-store-private` cannot run there; refused on linux |
| `-window` | `3` | the heartbeat window |
| `-stale-slack` | `1` | the slack over a peer's declared cadence before it is stale |
| `-staging-stale-after` | `60s` | how old a staging file may be before it is a crash |
| `-max-heartbeat-bytes`, `-max-fault-bytes`, `-max-halt-bytes` | `8192` | the size bound of each file kind, checked before it is read |
| `-heartbeat-max-age` | none; required | the timestamp backstop; must exceed `-cadence` |
| `-cadence` | `10` | the cadence this observer declares, in seconds |
| `-min-cycle` | `300ms` | the floor under a cycle |
| `-cycles` | `0` | run this many cycles then stop cleanly; `0` runs until a signal |
| `-tick-max-age` | `30s` | how old the proxy's newest `tick` may be; one value on every member |
| `-policy-query` | empty | the proxy's `--allow-query`, for `acl-substance`; one value on every member |

The tunnel member adds `-expect-listen`, `-expect-target`, `-expect-acl`, `-expect-proxy-protocol` (its expectations of the start line), `-lifetime-margin` and `-acl-grace` (`2s` each), and `-proc` (`/proc`, the process table for `boot-ambiguous`). The admin and material members add `-proc` and `-tunnel-lifetime-margin`, `-tunnel-acl-grace` (the tunnel member's values, for the checks every member computes); the material member adds `-accept-no-sandbox` and `-expect-binary-sha256` (required: the SHA-256 of the proxy's executable, for `binary-expected`, taken from the build output where the build is reviewed, before the copy to the host; `deploy/README.md`, "Two files, two sources"); `super` adds `-tunnel-lifetime-margin` and `-tunnel-acl-grace`.

## Two things worth knowing

**The cadence is not the cycle time.** Cycles run as fast as they finish, with a floor. A count of cycles is not a measure of time, which is why `since` exists and is written once and never rewritten: it is the one durable record of how long a store has been observed, and it survives the restarts that reset a process's own clock and the pruning that drops the first heartbeat's boot record.

**A check that cannot run has not passed.** Being unable to answer a question counts as a bad answer. An unreadable store, a heartbeat that will not parse, a heartbeat chain that will not verify, a trace that will not parse, a clock that cannot be read: all of them stop the proxying rather than being skipped.
