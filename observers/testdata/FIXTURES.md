# The fixture set

This describes `fixtures/`, the observer ring's own oracle: what is in it, what a fixture claims, how an implementation is judged against it, and a table of every fixture with its expected verdict and the rule it exercises. `../SPEC.md` is the authority for every rule; a fixture is one concrete instance of a rule, and where the two seem to disagree the fixture is wrong and should be reported.

The fixtures are **data and expected verdicts only**. There is no code in `fixtures/` and nothing in it is executed by anything. Each implementation brings its own harness that loads a fixture, runs the implementation's reading of it, and compares the result with the manifest. Tests may be shared across the four implementations; runtime code may not, and a fixture is a test.

## Layout

```
fixtures/
  index.json                   one row per fixture: name, reader, rules, expected verdicts, failing, halt
  <fixture-name>/
    manifest.json              what the fixture assumes and what it expects
    stores/                    stands for /stores/: the four store roots and everything under them
      admin/  material/  super/  tunnel/
    traces/                    stands for the traces root the deployment mounts, present only in trace fixtures
      daily/
    gt/                        stands for the proxy's own trace root (SPEC 14, ringtrace/README.md), present only in the segment, substance, admin and boot fixtures
      0000000001/
        0000000001.trace       a segment as the emitter leaves it, NUL tail and all; stored verbatim (`-text`)
      0000000002/              a second boot, in the boot fixtures: the current one, the first having ended
      chains/                  the chain store (ringtrace/README.md 1.5): <sha256>.der, the DER of every certificate a peer presented, in presented order, named by its content's hash, present in the substance fixtures, as the fixture needs it (complete, a `.tmp` only, the wrong bytes under a name)
      material/                the material store (ringtrace/README.md 1.6): <sha256>, no suffix, the CA bundle a start or reload line hashed, named by its content's hash, present in the substance fixtures, as the fixture needs it (complete, or a reload's bundle as a `.tmp` only)
    material/                  the files the proxy's start line names by a path relative to the fixture root (`material/ca.pem`, `material/policy.rego`), present only in the substance fixtures; the harness resolves the start line's relative paths against the fixture root. The substance rules read the policy from here and the CA bundle from `gt/material/` by hash, so `ca.pem` stands for the file on the proxy's host as the boot ends (rotated in place in `substance-ca-rotated` and `substance-ca-unstored`)
```

A fixture is a **snapshot** of the tree as the reader would find it at the start of one cycle. Every file is a real file with the bytes an implementation would read; every heartbeat chain was produced by simulating the four members in lockstep, so the `previous` links and the recorded `observed` hashes are SHA-256 values over the bytes as stored, and an implementation that hashes anything but the file's bytes will disagree with them.

Two things a snapshot is not. It is not a claim that a consistent history produced every file in it: fixtures that are about verdicts or invariants omit the halts and faults that an earlier cycle of the same story would have left behind, because those would only add failing assertions unrelated to the rule under test. And it is not a claim about timing: no fixture exercises cycle duration, and `now` is given only for the places the specification uses a clock (staging-file age, the V4b backstop, traces).

**Empty directories matter.** A copy directory with no heartbeats and an empty `halts/` are part of what a fixture says. Tools that drop empty directories (git, some archivers) will change a fixture's meaning. Every manifest lists the directories that must exist under `directories`; a harness should recreate them before running.

**Modification times matter in a few fixtures.** Staging-file age is judged by modification time (SPEC C3, H4). Where it matters, the manifest lists the intended time under `mtimes`, and the files were written with those times; a harness that copies fixtures should reapply them.

## The manifest

```json
{
  "fixture": "verdict-stale",
  "description": "…",
  "rules": ["SPEC 8", "SPEC 8.1 V6"],
  "reader": "tunnel",
  "reader_booted": false,
  "parameters": { "window": 4, "stale_slack_cycles": 1, "staging_stale_after_seconds": 60,
                  "max_heartbeat_bytes": 8192, "max_fault_bytes": 8192, "max_halt_bytes": 8192,
                  "now": "<timestamp>" },
  "directories": ["stores/admin", "…"],
  "memory":  { "stores/tunnel/heartbeat/0000000044.hb": "<sha256>" },      // only when it differs from disk
  "mtimes":  { "stores/tunnel/copy/heartbeat/0000000045.hb.tmp": "…Z" },   // only where age matters
  "traces":  [ { "schedule": "daily", "period_seconds": 86400, "margin_seconds": 600,
                 "deadline_seconds": 3600, "declared": ["…"] } ],       // trace fixtures only
  "db":      { "expire-tokens": 3, "…": 0 },                              // post-condition fixtures only
  "expect":  { … }
}
```

| Key | Meaning |
|---|---|
| `reader` | the identity whose cycle is being judged. Its own store is `stores/<reader>/` |
| `reader_booted` | `false`: the reader has been running; its **basis** is its highest on-disk heartbeat (which is what its previous cycle wrote) and its **memory** is the hash of every file it owns on disk: its heartbeat entries, its `fault` and `halt` if present, and its slots in the other stores' `halts/`. `true`: the reader's process has just started; it has no basis and its memory is rebuilt from its own store on start (SPEC 7). |
| `parameters` | the fixture-time values for everything `../SPEC.md` lists under *Values to be set* that a reading needs. They are test inputs and imply nothing about production. `window` is 4, the value the fixture trees were built for; the members' default, and the deployment's `-window`, is 3. Every rule a fixture exercises is written in `WINDOW` (SPEC 6), and each member's own suite runs the rules that depend on it (the prune, the chain test, the count) at 3 over a fixture tree (`TestWindowThree`); the rest are chosen so the fixtures can exercise the rules and an implementation must accept them as configuration. `now` is the reader's clock for this cycle. `heartbeat_max_age_seconds` is V4b's limit and is set only by the fixtures that exercise V4b; absent, V4b is not evaluated, so no earlier fixture's reading changes. `slot_owners`, a map from member to the account it runs as, is the mapping H7 judges the owner of every `halts/` entry against (SPEC 10.2); absent, H7 is not evaluated, in the same way. No fixture sets it, because a fixture is files and a file's owner is whoever the harness's checkout gave it, not part of the fixture; the clause is judged in each implementation's own suite, with real files on the host (see below). |
| `unchanged` | per subject, how long its heartbeat has been unchanged in seconds, as this reader has measured it. In-process state, like `basis` and `memory`: cycles are not paced to the cadence, so a count of them is not a unit of time, and staleness is a duration on the reader's own clock (SPEC 8). Present only in the fixtures that exercise `V6` |
| `memory` | present only when the reader's memory must differ from what is on disk (the `I5` fixtures). A map from path to the SHA-256 the reader remembers writing. When absent, memory is as `reader_booted` describes. |
| `mtimes` | the modification time each listed file must carry, as it was written. |
| `traces` | for each schedule present, its period (the interval the schedule runs at), the fixture-time margin and deadline, and the declared task set. |
| `db` | for post-condition fixtures, the answer the database would give to each post-condition question (a count that must be zero). The implementation's query is not run; its classification of the answer is what is judged. |
| `expect` | what the reader must conclude and do. Below. |

### `expect`

| Key | Meaning | Judged how |
|---|---|---|
| `verdicts` | one verdict per other member: `absent`, `alive`, `stale`, `retired`, `faulted`, `unknown` | exact, per member |
| `failing` | the complete set of the reader's failing assertions this cycle, each `{check, subject}` with the identifiers of SPEC 15 | exact as a **set**. Order is judged only through `halt.reason` |
| `halt_in_force_before` | whether, before the reader writes anything, a halt is in force by SPEC 10.1 | exact |
| `halt` | `{"writes": false}` when the reader has nothing failing; otherwise `{"writes": true, "reason", "subject"}`: the reader raises a halt naming the **first** failing assertion in the evaluation order of SPEC 13 | exact |
| `publish` | fields of the heartbeat the reader publishes at the end of this cycle: `sequence`, `previous`, `observed`, `boot` (`null`, or `{"resumed_from": …}` on a boot), `stop` | exact. `timestamp`, `checks`, `check_count` and `cadence_seconds` are not judged, since they are the implementation's own; the harness must still check that `check_count` equals the size of `checks` |
| `relay` | present in halt fixtures: `writes`, the stores in whose `halts/` the reader writes its slot this cycle; `leaves`, stores where its slot already exists and must be left untouched; `bytes_of`, the fixture path whose bytes the written slots must equal; `own_halt_written`, `false` where the reader must **not** write its own `halt` | exact |
| `clears` | present in recovery fixtures: `false` when the clear-condition does not hold, or `{"removes": [ … ]}`, the exact ordered list of fixture paths the reader removes | exact, including order |
| `trace` | present in the segment and substance fixtures, which carry `gt/`: what the reader concludes of the proxy's own trace, `boot`, the boot judged; `records`, how many lines it holds; `torn`, whether its last segment ends in a line without a line feed; `segments`, the length of each segment's prefix of complete lines, which by the segment rule (SPEC 14) is a length of content, the bytes before the first NUL, never a file size | exact; the tree is read twice over the same bytes, as two cycles are, and the second read must leave `trace-consistent` (SPEC 14.3) nothing to report |
| `surface` | present in the substance and admin fixtures: what every member computes of one surface's trace-only rules over `gt/`, `owner`, the surface (`tunnel` when absent: SPEC 14.3 `conn-consistent`, `handshake-verified`, `resumption-verified`, `acl-before-serve`, `lifetime-cap`, `accept-loop`, `handshake-substance`, `acl-substance`; `admin`: `status-listener-bound`, `pprof-cmdline-redacted`, `shutdown-authorized`, `status-listener-up`); `policy_query`, the proxy's `--allow-query` the fixture assumes, which the members take as `-policy-query` (tunnel only); `findings`, the complete set of `{check, subject}` the surface yields, with the fixture's `now`, the start line's relative material paths resolved against the fixture root, and the chains read from `gt/chains/` | exact as a set; the tree is read twice over the same bytes with one memory, as two cycles are, and the second read, judging the chains from the first's memory, must find the same |
| `boot_ended` | present in the boot fixtures, which carry two boots: what a member that read boot `previous` last cycle concludes of it this cycle, now that a higher boot is current (SPEC 14.3 `boot-ended`), `findings`, the complete set of `{check, subject}` | exact as a set, in the cycle the change is observed; a second cycle over the same bytes with the same memory must find nothing (the judgement is made once), and a member with no memory of `previous` (one that started after the restart) must find nothing either |

Absent keys are not judged. An implementation must not write into the fixture tree; the harness either runs the implementation in a mode that reports what it would write, or gives it a copy and diffs.

## How an implementation is judged

For every fixture, in any order:

1. Recreate the directories listed in `directories`, place the files, and apply `mtimes`.
2. Configure the implementation with `parameters`, identity `reader`, and, where present, `memory`, `traces` and `db`.
3. Run one cycle of the implementation against `stores/` (as `/stores/`) and `traces/` (as the traces root), with the basis and memory that `reader_booted` describes.
4. Compare with `expect` as the table above says.
5. Where `expect.trace` is present, read `gt/` as the implementation's local checks read the proxy's trace, twice, and compare each read with `expect.trace`.
6. Where `expect.surface` is present, compute the named surface's trace-only rules over `gt/` as every member computes them for `surface-disagree`, with `parameters.now`, `material/` under the fixture root standing for the paths the start line names (the policy is read from there), `gt/chains/` as the chain store, `gt/material/` as the material store the CA bundles are read from by the hash in force at each line, and `policy_query` as the members' `-policy-query`, twice with one memory, and compare each computation with `expect.surface.findings` as a set.
7. Where `expect.boot_ended` is present, give the implementation the memory of having read boot `previous` last cycle, read `gt/` as its local checks do, and compare what it concludes of the ended boot with `expect.boot_ended.findings` as a set; then read again with the same memory and require nothing, and read once with no memory and require nothing.

An implementation passes the set when every fixture passes. There is no partial credit and no weighting: the benign fixtures are not less important than the invariant fixtures, because a benign case wrongly classified as a compromise halts a live deployment, and that is the failure this set exists to prevent.

The healthy fixtures carry `publish` expectations whose `observed` and `previous` values are SHA-256 over the files as stored. An implementation that passes them has demonstrated the one property everything else depends on: that it hashes the same bytes every other implementation hashes.

## What the set does not cover

- **A store that cannot be listed** (SPEC V1): a fixture cannot make a directory unreadable portably. Test it in the implementation's own suite with a permission change.
- **`own-store-writable`**, the re-read after publish, and atomic publication itself: these are about writing, and the fixtures are read-only snapshots.
- **Cycle timing** (`cycle-within-cadence`): not a property of files.
- **Local checks** (the listener, the status surface, the trust material, the process): per-observer content, with identifiers the observer's own code chooses. The segment fixtures judge the read of the proxy's trace that those checks rest on, not the checks.
- **The gate** (SPEC 19): `ringtrace`'s own tests cover it.
- **Post-condition queries**: the `db` map supplies the answer; the implementation runs no query.
- **A schedule that has never run and is not yet due** (SPEC 14.2 T1). No fixture carries an observed-since parameter and a schedule with no runs; the implementation's own suite covers it.
- **The owner of a `halts/` entry** (SPEC 10.2 H7, `I8`): ownership is not a property of a fixture's bytes, and a checkout cannot carry it, so the fixtures run with no `slot_owners` and H7 is not evaluated over the set. The implementation's own suite writes entries into a fixture copy's `halts/` under other members' names, maps one of those members to another account, and requires `I8` naming the file and the owner found on Linux, `I8` naming the OS for every entry elsewhere, and nothing on an empty `halts/` anywhere.
- **Behaviour across cycles**: each fixture is one cycle. `healthy-ring` and `healthy-ring-next-cycle` are two snapshots of one story, but each is judged alone.

## The fixtures

Grouping is by name prefix. `healthy-` and `benign-` fixtures must produce no compromise; the `benign-` ones are the cases that halt a live deployment if misclassified. `verdict-` fixtures exercise procedure V. `chain-` and `inv<n>-` fixtures exercise the chain rules and the invariants (`I1` to `I7`; `I8` is ownership, which the set cannot carry). `shape-` fixtures exercise `S1` to `S5` over a copy directory and over `halts/`. `halt-` and `recovery-` fixtures exercise raising, relay, idempotence and clearing. `trace-` fixtures exercise T1 to T4, and the two `trace-segment-` fixtures the segment rule of the proxy's own trace (SPEC 14). `order-` exercises which failing assertion a halt names. `substance-` fixtures exercise the two substance rules of the tunnel surface (SPEC 14.3, `handshake-substance` and `acl-substance`) over a boot with a chain store and material: each is a `trace-fresh-complete` cycle (its stores and traces, the same clean verdict) carrying a `gt/` written by `tools/substancepki -gen-fixtures` from the committed PKI under `../pki` (`ca.pem`, `policy.rego`, the chains; `hashes.txt` there lists every hash the fixtures quote), every line encoded by `ringtrace.EncodeLine`; the cycle's `failing` is empty in every one, since the harness runs the cycle without local checks, and the substance results are the `surface` column below, judged by `expect.surface`. The chains: `client` (CN client.example, OU ops, via the intermediate), `other` (CN other.example, OU guests, by the CA), `rogue` (CN client.example, by a CA the bundle does not hold), `expired` (CN client.example, valid in 2020 only). The `admin-` fixture exercises the admin surface the same way (`expect.surface` with `owner` `admin`), and the `boot-` fixture the judgement of a boot that ended (`expect.boot_ended`); both are written by the same tool on the same base and carry the same clean cycle.

| Fixture | Reader | Expected verdicts | Expected failing | Halt | Rule |
|---|---|---|---|---|---|
| `healthy-ring` | tunnel | all alive | none | none | SPEC 8.1, SPEC 9, SPEC 3.5 |
| `healthy-ring-next-cycle` | tunnel | all alive | none | none | SPEC 8.1, SPEC 6 |
| `healthy-super-view` | super | all alive | none | none | SPEC 9, SPEC 8.2 |
| `healthy-transient-fifth-entry` | tunnel | all alive | none | none | SPEC 6, SPEC 6.1 C2 |
| `healthy-young-chain` | tunnel | all alive | none | none | SPEC 6.1 C7, SPEC 7, SPEC 8.1 V7 |
| `benign-copy-one-behind` | tunnel | all alive | none | none | SPEC 9 K5, SPEC 9 K6 |
| `benign-cold-start-no-predecessor` | tunnel | admin unknown, material unknown, super unknown | none | none | SPEC 7, SPEC 8.1 V5 |
| `verdict-cold-start-all-absent` | tunnel | admin absent, material absent, super absent | `member-present` (admin); `member-present` (material); `member-present` (super) | raises `member-present` | SPEC 7, SPEC 8.1 V2 |
| `verdict-absent-never-ran` | tunnel | material absent | `member-present` (material) | raises `member-present` | SPEC 8.1 V2 |
| `verdict-stale` | tunnel | admin stale | `member-fresh` (admin) | raises `member-fresh` | SPEC 8, SPEC 8.1 V6 |
| `verdict-future-timestamp` | tunnel | super stale | `member-fresh` (super) | raises `member-fresh` | SPEC 8.1 V4b, SPEC 19.3 |
| `verdict-unchanged-within-tolerance` | tunnel | all alive | none | none | SPEC 8.1 V6 |
| `benign-clean-stop` | tunnel | admin retired | none | none | SPEC 7, SPEC 8.1 V4 |
| `verdict-retired-super` | tunnel | super retired | `member-fresh` (super) | raises `member-fresh` | SPEC 8.1 V4, SPEC 8.2 |
| `verdict-faulted` | tunnel | admin faulted | none | none | SPEC 8.1 V8, SPEC 12.3 |
| `chain-ancestor-in-window` | tunnel | all alive | none | none | SPEC 8.1 V7 |
| `chain-outside-window` | tunnel | admin unknown | `I1` (admin) | raises `I1` | SPEC 8.1 V7, SPEC 11.1 I1 |
| `chain-nowhere` | tunnel | admin unknown | `I1` (admin) | raises `I1` | SPEC 8.1 V7, SPEC 11.1 I1 |
| `inv1-peer-account-not-in-chain` | tunnel | all alive | `I1` (material) | raises `I1` | SPEC 11.1 I1(b) |
| `benign-dead-member-old-account` | tunnel | admin stale | `member-fresh` (admin) | raises `member-fresh` | SPEC 11.1 I1(b) |
| `inv2-count-mismatch` | tunnel | all alive | `I2` (admin) | raises `I2` | SPEC 6.1 C5, SPEC 11.1 I2 |
| `inv2-duplicate-check` | tunnel | all alive | `I2` (admin) | raises `I2` | SPEC 6.1 C5, SPEC 11.1 I2 |
| `inv3-gap-in-window` | tunnel | all alive | `I3` (admin) | raises `I3` | SPEC 6.1 C6, SPEC 11.1 I3 |
| `inv3-broken-link` | tunnel | all alive | `I3` (admin) | raises `I3` | SPEC 6.1 C7, SPEC 11.1 I3 |
| `inv3-null-previous-above-one` | tunnel | all alive | `I3` (admin) | raises `I3` | SPEC 6.1 C7, SPEC 11.1 I3 |
| `inv3-boot-wrong-resumed-from` | tunnel | all alive | `I3` (admin) | raises `I3` | SPEC 6.1 C8, SPEC 11.1 I3 |
| `inv3-stop-then-no-boot` | tunnel | all alive | `I3` (admin) | raises `I3` | SPEC 6.1 C9, SPEC 11.1 I3 |
| `inv4-folder-removed` | tunnel | admin absent | `I4` (admin); `member-present` (admin) | raises `I4` | SPEC 8.1 V2, SPEC 11.1 I4 |
| `inv1-folder-emptied` | tunnel | admin absent | `I1` (admin); `member-present` (admin) | raises `I1` | SPEC 8.1 V2 |
| `benign-folder-missing-on-boot` | tunnel | admin absent, material unknown, super unknown | `member-present` (admin) | raises `member-present` | SPEC 7, SPEC 8.1 V2, SPEC 11.1 I4 |
| `inv5-own-file-altered` | tunnel | all alive | `I5` (tunnel/heartbeat/0000000044.hb) | raises `I5` | SPEC 11.1 I5, SPEC 4 |
| `inv7-original-altered-peer-view` | admin | all alive | `I7` (tunnel) | raises `I7` | SPEC 9 K5, SPEC 11.1 I7 |
| `inv5-foreign-fault-file` | tunnel | all alive | `I5` (tunnel/fault) | raises `I5` | SPEC 11.1 I5 |
| `inv6-heartbeat-in-halts` | tunnel | all alive | `I6` (tunnel/halts/admin) | raises `I6` | SPEC 10.2 H2, SPEC 11.1 I6 |
| `inv6-heartbeat-in-copy-root` | tunnel | all alive | `I6` (tunnel/copy/0000000044.hb) | raises `I6` | SPEC 9 K2, SPEC 11.1 I6 |
| `inv7-copy-forged-entry` | tunnel | all alive | `I7` (material) | raises `I7` | SPEC 9 K5, SPEC 11.1 I7 |
| `inv7-copy-ahead` | tunnel | all alive | `I7` (material) | raises `I7` | SPEC 9 K5, SPEC 5 |
| `inv7-fault-copy-wrong-author` | tunnel | all alive | `I7` (material) | raises `I7` | SPEC 9 K7, SPEC 11.1 I7 |
| `benign-stale-staging-copy` | tunnel | all alive | `staging-fresh` (tunnel/copy/heartbeat/0000000045.hb.tmp) | raises `staging-fresh` | SPEC 6.1 C3, SPEC 11.3 |
| `benign-fresh-staging-copy` | tunnel | all alive | none | none | SPEC 6.1 C3 |
| `benign-stale-staging-halts` | tunnel | all alive | `staging-fresh` (tunnel/halts/admin.tmp) | raises `staging-fresh` | SPEC 10.2 H4, SPEC 10.1 |
| `benign-copy-behind` | tunnel | all alive | `copy-current` (material) | raises `copy-current` | SPEC 9 K5, SPEC 9 K6 |
| `benign-copy-empty` | tunnel | all alive | `copy-current` (material) | raises `copy-current` | SPEC 9 K6 |
| `benign-fault-copy-missing` | tunnel | material faulted | `copy-current` (material) | raises `copy-current` | SPEC 9 K7 |
| `benign-restart-boot-record` | tunnel | all alive | none | none | SPEC 7, SPEC 6.1 C8 |
| `benign-boot-fresh-chain` | tunnel | admin unknown | none | none | SPEC 7, SPEC 8.1 V5 |
| `shape-copy-too-many-entries` | tunnel | all alive | `S3` (tunnel/copy/heartbeat); `copy-current` (material) | raises `S3` | SPEC 6.1 C2, SPEC 11.2 |
| `shape-copy-subdirectory` | tunnel | all alive | `S2` (tunnel/copy/heartbeat/extra) | raises `S2` | SPEC 6.1 C1, SPEC 11.2 |
| `shape-copy-unexpected-name` | tunnel | all alive | `S1` (tunnel/copy/notes.txt) | raises `S1` | SPEC 9 K2, SPEC 11.2 |
| `shape-copy-oversized-fault` | tunnel | all alive | `S4` (tunnel/copy/fault) | raises `S4` | SPEC 3.1, SPEC 9 K2, SPEC 11.2 |
| `shape-copy-two-staging-files` | tunnel | all alive | `S3` (tunnel/copy/heartbeat) | raises `S3` | SPEC 6.1 C2, SPEC 11.2 |
| `shape-halts-unexpected-name` | tunnel | all alive | `S1` (tunnel/halts/stranger) | raises `S1` | SPEC 10.2 H2, SPEC 10.1 |
| `shape-halts-subdirectory` | tunnel | all alive | `S2` (tunnel/halts/evil) | raises `S2` | SPEC 10.2 H2 |
| `shape-halts-oversized` | tunnel | all alive | `S4` (tunnel/halts/admin) | raises `S4` | SPEC 10.2 H5, SPEC 10.1 |
| `halt-unparseable-in-force` | tunnel | all alive | `S5` (tunnel/halts/admin) | raises `S5` | SPEC 10.2 H6, SPEC 10.1, SPEC 3.1 |
| `shape-heartbeat-unknown-key` | tunnel | admin unknown | `S5` (admin/heartbeat/0000000044.hb) | raises `S5` | SPEC 3.1, SPEC 6.1 C5, SPEC 8.1 V3 |
| `shape-heartbeat-sequence-mismatch` | tunnel | admin unknown | `S5` (admin/heartbeat/0000000044.hb) | raises `S5` | SPEC 6.1 C5, SPEC 11.1 I6 |
| `shape-heartbeat-duplicate-observed-key` | tunnel | super unknown | `S5` (super/heartbeat/0000000045.hb) | raises `S5` | SPEC 3.1, SPEC 6.1 C5, SPEC 8.1 V3, SPEC 19.3 |
| `halt-relay` | tunnel | material faulted | none | none; relays to admin, material, super | SPEC 12.2, SPEC 10.1, SPEC 12.3 |
| `halt-relay-idempotent` | tunnel | material faulted | none | none; relays to admin, material | SPEC 12.2 |
| `halt-lifting-not-relayed` | tunnel | all alive | none | none | SPEC 12.2, SPEC 12.3 |
| `halt-relay-from-peer-own-halt` | tunnel | material faulted | none | none; relays to admin, material, super | SPEC 12.2, SPEC 10.1 |
| `recovery-all-clear` | tunnel | all alive | none | none; clears | SPEC 12.3 |
| `recovery-blocked-by-peer-fault` | tunnel | admin faulted | none | none | SPEC 12.3, SPEC 12.2 |
| `recovery-blocked-by-super-halt` | tunnel | all alive | none | none | SPEC 12.3 |
| `recovery-super-stands-down` | super | all alive | none | none; clears | SPEC 12.3 |
| `recovery-super-blocked-by-fault` | super | material faulted | none | none | SPEC 12.3 |
| `order-first-finding-names-halt` | tunnel | all alive | `I2` (admin); `staging-fresh` (tunnel/copy/heartbeat/0000000045.hb.tmp) | raises `I2` | SPEC 13, SPEC 3.4 |
| `trace-fresh-complete` | tunnel | all alive | none | none | SPEC 14.2 |
| `trace-stale` | tunnel | all alive | `trace-fresh` (daily) | raises `trace-fresh` | SPEC 14.2 T1 |
| `trace-incomplete-past-deadline` | tunnel | all alive | `trace-complete` (daily) | raises `trace-complete` | SPEC 14.2 T2, SPEC 14.2 T3 |
| `trace-in-progress` | tunnel | all alive | none | none | SPEC 14.2 T2 |
| `trace-missing-task` | tunnel | all alive | `trace-coverage` (daily) | raises `trace-coverage` | SPEC 14.2 T3 |
| `trace-task-not-completed` | tunnel | all alive | `trace-coverage` (daily) | raises `trace-coverage` | SPEC 14.2 T3 |
| `trace-partial-line-ignored` | tunnel | all alive | none | none | SPEC 14.1 |
| `trace-postcondition-nonzero` | tunnel | all alive | `postcondition` (expire-tokens) | raises `postcondition` | SPEC 14.2 T4 |
| `trace-segment-pre-extended` | tunnel | all alive | none | none; `gt/` reads as 9 records, not torn, prefix 2016 bytes of a 6112-byte file | SPEC 14 (the segment rule), SPEC 14.3 |
| `trace-segment-pre-extended-torn` | tunnel | all alive | none | none; `gt/` reads as 5 records, torn, prefix 1530 bytes of a 5660-byte file | SPEC 14 (the segment rule), SPEC 14.3, ringtrace/README.md 1.4 rule 5 |
| `substance-agree` | tunnel | all alive | none | none; surface: none (client chain allowed under `allow-cn`, other chain denied, client chain resumed and re-verified) | SPEC 14.3, ringtrace/README.md 1.5 |
| `substance-acl-disagree` | tunnel | all alive | none | none; surface: `acl-substance` (1), `acl-substance` (2) (other chain recorded allowed under `allow-cn`; client chain recorded denied) | SPEC 14.3 |
| `substance-chain-fails` | tunnel | all alive | none | none; surface: `handshake-substance` (1), `handshake-substance` (2), `acl-substance` (1), `acl-substance` (2) (rogue chain and expired chain recorded verified and allowed) | SPEC 14.3, ringtrace/README.md 1.5 |
| `substance-chain-missing` | tunnel | all alive | none | none; surface: `handshake-substance` (1), `acl-substance` (1) (the named chain has only its `.tmp`) | SPEC 14.3, ringtrace/README.md 1.5 rule 2 |
| `substance-chain-mishashed` | tunnel | all alive | none | none; surface: `handshake-substance` (1), `acl-substance` (1) (the other chain's bytes under the client chain's name) | SPEC 14.3, ringtrace/README.md 1.5 rule 4 |
| `substance-policy-agree` | tunnel | all alive | none | none; surface: none (`policy:<hash>` alone; client chain allowed under `policy`, other chain denied; `policy_query` `data.policy.allow`) | SPEC 14.3 |
| `substance-policy-disagree` | tunnel | all alive | none | none; surface: `acl-substance` (1), `acl-substance` (2) (the policy's decisions inverted) | SPEC 14.3 |
| `substance-unknown-rule` | tunnel | all alive | none | none; surface: `handshake-substance` (1), `acl-substance` (1) (`verify-cn` in a server's rule set) | SPEC 14.3 |
| `substance-pin-agree` | tunnel | all alive | none | none; surface: none (one `allow-spki-pin`, the client leaf's key; client chain allowed under it, other chain refused at the handshake) | SPEC 14.3 |
| `substance-pin-disagree` | tunnel | all alive | none | none; surface: `handshake-substance` (1), `acl-substance` (1) (the other chain recorded verified and allowed under the pin) | SPEC 14.3 |
| `substance-ca-rotated` | tunnel | all alive | none | none; surface: `handshake-substance` (3), `acl-substance` (3) (the CA rotated in place by a reload: the client chain before it judged under the replaced bundle, the rogue chain after it under the new one, the client chain after it not signed by the new one) | SPEC 14.3, ringtrace/README.md 1.6 |
| `substance-ca-unstored` | tunnel | all alive | none | none; surface: `handshake-substance` (2), `acl-substance` (2) (the reload's bundle has only its `.tmp` in `gt/material/`; the connection before the reload is judged, the one after it cannot be) | SPEC 14.3, ringtrace/README.md 1.6 rule 2 |
| `admin-status-listener-down` | tunnel | all alive | none | none; admin surface: `status-listener-up` (`accept tcp 127.0.0.1:6060: use of closed network connection`) (a `refusal` line names the status listener; the proxy refuses to serve until restart) | SPEC 14.3, ringtrace/README.md 1.2 |
| `boot-ended-mid-connection` | tunnel | all alive | none | none; boot 2 is current and clean; boot 1, read last cycle, ended with no `shutdown` line, a torn last line, connection 1 never closed and a failed accept before the end: `boot-ended` (`1:aborted`), (`1:torn`), (`1:conn:1`), (`1:accept-error:accept tcp 127.0.0.1:8443: too many open files`), once | SPEC 14.3 |

Ninety-two fixtures. "Halt" gives what the reader does about halts: raises one naming the reason shown, relays its slot into the stores named, clears its own halt and slots, or none of these. The `halt-` and `recovery-` rows carry the exact `relay` and `clears` expectations in their manifests.
