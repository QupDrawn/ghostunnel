# Observer network specification

`README.md` describes the observer ring. This document is the specification the four members implement: every file name, every field, every procedure, written so that four readers produced without sight of each other read the same store the same way. Where it says *step n* it refers to a step of the cycle in section 13.

The members share no runtime code. They agree by being written to this description. Anywhere an implementer could read two things, two implementations diverge, and in this structure a divergence is a halt on a live deployment. So this document prefers a determinate procedure to a description, and where it states a rule it says what the rule is for, so an implementer makes the same call in the corner the rule forgot.

Mechanical details (names, encodings, patterns) are decided here and listed under *Choices made here*. Values a deployment sets (a cadence, a size, a deadline) are not decided here; the constraint on each is stated and the value is listed under *Values to be set* with the flag that sets it.

Verification is offline: fixtures on disk and expected verdicts (`testdata/FIXTURES.md`). Nothing in this document is run against a live deployment.

---

## 1. Names

**Members.** There are four, and the set is declared to every member on its command line (`-members`) rather than discovered:

| Identity | Surface |
|---|---|
| `tunnel` | the mTLS data path: the listener, client-certificate verification, the backend dial, the lifetime cap |
| `admin` | the status and admin HTTP surface |
| `material` | the trust material and its reload |
| `super` | nothing of its own: the fourth member, in the ring, not above it |

An observer's **identity** is the string above. It is the name of its store, the value of the `observer` field in every file it writes, and the name of the file it writes into another store's `halts/`. There is exactly one spelling and it is lower-case ASCII.

**Identity order.** Wherever this document says "in identity order" it means ASCII order of the identity strings: `admin`, `material`, `super`, `tunnel`. Several procedures below produce a *first* failing assertion, and the order they walk in has to be the same in every implementation or the halt names a different one.

**The reader.** Procedures are written from the point of view of one observer, called the reader and written `R`, examining another member, called the subject and written `A`. Every observer is a reader of every other member each cycle.

---

## 2. Path layout

All four stores live under `/stores/`, which in this deployment is `/var/lib/ghostunnel-ring/stores/` (`-stores`). The tree is exactly this and nothing else. Every path has one writer, and the writer is given in the right-hand column.

```
/stores/
  tunnel/                            store root: tunnel
    heartbeat/                       tunnel
      0000000041.hb                  tunnel     one file per cycle
      0000000042.hb.tmp              tunnel     at most one staging file
    fault                            tunnel     present while an assertion fails
    fault.tmp                        tunnel     staging
    halt                             tunnel     present once tunnel itself found a violation
    halt.tmp                         tunnel     staging
    since                            tunnel     when tunnel first ran; written once, never rewritten
    since.tmp                        tunnel     staging, for that one write
    copy/                            directory, writable by material alone
      heartbeat/                     material   material's own heartbeat folder repeated
        0000000041.hb                material
        0000000042.hb.tmp            material   at most one staging file
      fault                          material   material's own fault, when it has one
      fault.tmp                      material   staging
    copy-super/                      directory, writable by super alone; same shape
    halts/                           directory, writable by admin, material, super
      admin                          admin      admin's halt, or one it is relaying
      admin.tmp                      admin      staging
      material                       material
      material.tmp                   material
      super                          super
      super.tmp                      super

  admin/                             as tunnel; copy/ is written by tunnel alone;
                                     halts/ holds tunnel, material, super
  material/                          as tunnel; copy/ is written by admin alone;
                                     halts/ holds tunnel, admin, super

  super/                             store root: super
    heartbeat/                       super
    fault, fault.tmp                 super
    halt, halt.tmp                   super
    since, since.tmp                 super      as tunnel's
    halts/                           directory, writable by tunnel, admin, material
      tunnel, tunnel.tmp             tunnel
      admin, admin.tmp               admin
      material, material.tmp         material
    copy-tunnel/                     directory, writable by tunnel alone
      heartbeat/                     tunnel     tunnel's own heartbeat folder repeated
      fault, fault.tmp               tunnel
    copy-admin/                      directory, writable by admin alone; same shape
    copy-material/                   directory, writable by material alone; same shape

  gt/                                the trace root: written by ghostunnel, read-only to observers
                                     (section 14, ringtrace/README.md). The one directory of the
                                     tree not readable by every account: gt:gtring-trace 2750,
                                     0750 directories and 0640 files inside, because the trace
                                     names every peer that presented a certificate; the four
                                     observers read it through the group gtring-trace
                                     (deploy/README.md, "The trace root is group-readable")
```

**The copy cycle** is given to every member as store=author pairs (`-copy-authors`, default `tunnel=material,admin=tunnel,material=admin`): material writes into `tunnel/copy/`, tunnel writes into `admin/copy/`, admin writes into `material/copy/`. Each of the three also writes into its own `copy-<identity>/` in the super store. The coordinator writes `copy-super/` into each of the other three stores and authors no `copy/`.

**The write matrix**, which the ownership and per-unit write paths of `deploy/` produce and which every ownership invariant rests on:

| Path | Read-write in | Read-only in |
|---|---|---|
| `/stores/tunnel/` (root, `heartbeat/`, `fault`, `halt`, `since`) | tunnel | admin, material, super |
| `/stores/tunnel/copy/` | material | tunnel, admin, super |
| `/stores/tunnel/copy-super/` | super | tunnel, admin, material |
| `/stores/tunnel/halts/` | admin, material, super | tunnel |
| `/stores/admin/` | admin | the other three |
| `/stores/admin/copy/` | tunnel | the other three |
| `/stores/admin/copy-super/` | super | the other three |
| `/stores/admin/halts/` | tunnel, material, super | admin |
| `/stores/material/` | material | the other three |
| `/stores/material/copy/` | admin | the other three |
| `/stores/material/copy-super/` | super | the other three |
| `/stores/material/halts/` | tunnel, admin, super | material |
| `/stores/super/` | super | the other three |
| `/stores/super/halts/` | tunnel, admin, material | super |
| `/stores/super/copy-tunnel/` | tunnel | the other three |
| `/stores/super/copy-admin/` | admin | the other three |
| `/stores/super/copy-material/` | material | the other three |
| `/stores/gt/` | ghostunnel | all four |

Each `copy/`, `copy-*/` and `halts/` directory is owned by its writer and is the only path in that store the writer's unit may write, so that a peer with write access to it has write access to nothing else in the store it sits in. The `heartbeat/` directory inside a copy directory is an ordinary directory created by the copy's writer. The `heartbeat/` directory at a store root is created by the store's owner on its first run and is never removed by anyone.

**Membership is declared, not discovered.** A reader carries the declared set and its own identity (section 4). A store root that is absent is a member whose store is missing, reported by the reads that follow. A directory under `/stores/` that is not a declared member is not a member whatever it is named.

**Nothing else may appear in a store.** Anything at any path not shown above is a shape violation (section 11). This includes entries a filesystem might create on its own: a filesystem that plants `lost+found` or similar at a store root cannot hold a store, and that is a deployment constraint rather than something the reader tolerates.

---

## 3. Files

Three kinds of file are written into stores: heartbeat, fault and halt. They share one encoding and one marker rule so that one parser serves all three and no file of one kind can be read as another.

### 3.1 Common rules

**Encoding.** Each file is a single JSON object (RFC 8259), UTF-8, no byte-order mark. The writer ends the file with exactly one line feed. A reader accepts the object with or without a trailing line feed and rejects anything else after it.

**The marker is the first key.** The file's bytes begin with exactly one of:

```
{"kind":"heartbeat",
{"kind":"fault",
{"kind":"halt",
```

The object's first key is `kind`, its value is the file's kind, and there is no whitespace before or within that prefix. A halt and a heartbeat carry a marker the other never carries, so that a truncated, half-written or misplaced file fails to parse as either rather than being mistaken for one. Putting the marker in the first bytes, in a fixed spelling, means a reader can classify a file by its first twenty bytes without a JSON parser, and a file that has lost its tail still cannot be classified as anything but what it is. The remainder of the file is any valid JSON.

**Classification comes before parsing.** A reader reads a file's prefix first. If the prefix is the heartbeat marker and the file is not at a heartbeat place (a `<seq>.hb` or `<seq>.hb.tmp` name inside a `heartbeat/` directory), that is invariant `I6` and the file is not parsed further. Otherwise the file is parsed as the kind its place requires, and a prefix that does not match that kind is malformed (`S5`). So `I6` takes precedence over the shape rules for the same file.

**Strict keys.** Every kind has an exact key set, given below. A file with a key missing, a key added, a key of the wrong type, or a `kind` that does not match the place it was found is **malformed**, and a malformed file is a shape violation (`S5`, section 11). Readers do not tolerate unknown keys: tolerance is a place for two implementations to differ, and four strict parsers agree where four lenient ones would not.

**Timestamps** are strings of exactly the form `YYYY-MM-DDTHH:MM:SSZ`, UTC, whole seconds. They are for people and for the two backstops that read a clock (V4b and the gate's window); no other verdict is computed from one.

**Hashes** are SHA-256, written as 64 lower-case hexadecimal characters.

**Sizes.** Each kind has a maximum size in bytes: `MAX_HEARTBEAT_BYTES`, `MAX_FAULT_BYTES`, `MAX_HALT_BYTES` (`-max-heartbeat-bytes`, `-max-fault-bytes`, `-max-halt-bytes`). Each must exceed the largest file an honest implementation can write, which is bounded because every field is bounded. A reader checks a file's size against the bound **before** reading its content, so an oversized file never reaches the parser.

### 3.2 The heartbeat

One file per cycle. Named by sequence: ten decimal digits, zero-padded, followed by `.hb`. `0000000001.hb` is the first heartbeat a store ever holds. The zero-padding makes lexical order equal numeric order, so a directory listing is the chain in order and an implementer cannot sort it wrongly by accident. The largest sequence is `9999999999`.

```json
{"kind":"heartbeat",
 "version":1,
 "observer":"tunnel",
 "sequence":42,
 "timestamp":"YYYY-MM-DDTHH:MM:SSZ",
 "cadence_seconds":10,
 "checks":["own-store-writable","member-fresh:admin","member-fresh:material","member-fresh:super"],
 "check_count":4,
 "observed":{"admin":"3f1c…","material":"9a02…","super":null},
 "previous":"77e4…",
 "boot":null,
 "stop":false}
```

(Shown wrapped for reading. The prefix rule of 3.1 applies to the real file; everything after the prefix may be formatted however the writer likes.)

| Key | Type | Meaning |
|---|---|---|
| `kind` | `"heartbeat"` | the marker; first key, exact spelling |
| `version` | integer `1` | the version of this specification's file format. A reader rejects any other value as malformed |
| `observer` | string | the writer's identity. Must equal the identity of the store the file is found in (or the author of the copy directory it is found in) |
| `sequence` | integer | the sequence number. Must equal the number in the file's name |
| `timestamp` | timestamp | wall clock at the start of the cycle that wrote it |
| `cadence_seconds` | integer ≥ 1 | the cadence this observer declares; readers derive their staleness tolerance from it (section 8) |
| `checks` | array of strings | the identifier of every check that ran this cycle. Each identifier is a constant in the observer's own code, except the structural identifiers of section 15, which every implementation must spell the same |
| `check_count` | integer | the number of identifiers in `checks`. It disagrees with `checks` only when the file is inconsistent, which is invariant `I2` |
| `observed` | object | one key per member other than the writer: exactly the declared membership minus itself. Each value is the hash of that member's current heartbeat as this writer read it this cycle, or `null` if the member had no current heartbeat (absent, empty, or unreadable) |
| `previous` | hash or `null` | the hash of this writer's own previous heartbeat file, re-read from disk after it was published (section 5). `null` only on `sequence` 1 |
| `boot` | `null` or object | `null` on every heartbeat except the first one a process writes. On that one: `{"started":<timestamp>,"resumed_from":<integer or null>}` where `resumed_from` is the highest sequence found in the folder at start, or `null` if the folder was empty. Section 7 |
| `stop` | boolean | `true` on the final heartbeat of a deliberate stop, `false` otherwise. Section 7 |

**The heartbeat does not carry the fault state.** No field of the heartbeat names, hashes or refers to the fault file. The two files are written separately and cannot be made atomic, so any test built on their agreement would fire on a benign crash between the two writes. An undecidable test cannot be in the compromise set, so the field is not there to be tested. An observer can therefore suppress its own fault: the ring detects lies about the structure, not lies about the world.

**A heartbeat cannot contain its own hash.** There is no fixed point. `previous` is the hash of the predecessor, and the hash of this file is only ever computed by whoever reads it.

### 3.3 The fault

Named `fault`, at the store root. Present while at least one of the owner's **own** assertions is failing; absent otherwise.

**It is a state file, not an account.** Presence is the verdict and the failing set is the state. When something began failing, and what it said at the time, belong in the log (12.4), not in a file the protocol keeps in two places and compares byte for byte.

**A problem with a different observer is a halt, not a fault.** Only the checks an observer makes about its own world reach this file: its own store, its own process, and the work on its own host. Everything about another member (absent, stale, unreadable, a copy out of date) and every structural violation raises a halt and does not appear here at all.

The reason is recovery. The clear-condition is *no store holds a fault*, so a fault has to mean something only its owner can fix and only its owner can clear. If a dead peer made every other member faulty, one member's failure would be recorded as three, the ring would report three healthy members as unwell, and the state every member needs to stand down would be written by the very condition that should lift it.

```json
{"kind":"fault",
 "version":1,
 "observer":"tunnel",
 "failing":[{"check":"own-store-writable","subject":null},
            {"check":"trace-fresh","subject":"daily"}]}
```

| Key | Type | Meaning |
|---|---|---|
| `kind` | `"fault"` | marker |
| `version` | integer `1` | |
| `observer` | string | the writer's identity. A copy naming anyone else is a record its author never published (section 9) |
| `failing` | non-empty array | one entry per failing local assertion: `check` (the identifier) and `subject` (string or `null`), sorted by check then subject |

**Which checks are local is an explicit list in each observer**, not something derived from the subject. A check that is not on the list is treated as being about somebody else, which is the safe direction: it costs a halt without a fault, and the halt is what stops the system anyway. The structural list is `own-store-writable`, `own-store-private`, `observing-since`, `halts-readable`, `I8` (an entry of the own `halts/` not owned by the member it is named for, 10.2 H7: the owner's own store), `cycle-within-cadence`, `trace-fresh`, `trace-complete`, `trace-coverage` and `postcondition`, plus the identifiers each member's own checks declare (`LocalChecks.Identifiers`; 14.3 lists the ones every member makes over the proxy's trace). `surface-disagree` (14.3) is about another member and is never on it.

**When it is written.** Published when the set of failing local `check`/`subject` pairs changes (when the first fails, when another joins, when one clears while others remain) and removed when the set becomes empty. It is **not** rewritten every cycle. Carrying no timestamp and no sequence, a file describing the same failing set has the same bytes every time, which is what makes a copy of it comparable at all.

### 3.4 The halt

Named `halt` at a store root (the owner's own record), or named after its writer inside a `halts/` directory (a delivered or relayed copy). Present once a violation has been found and until recovery removes it. Presence is the signal; nothing reads a halt's content to decide whether the system is halted.

```json
{"kind":"halt",
 "version":1,
 "observer":"material",
 "reason":"I7",
 "subject":"admin",
 "sequence":57,
 "when":"YYYY-MM-DDTHH:MM:SSZ",
 "detail":"material found I7 on admin (1 assertion(s) failing this cycle)"}
```

| Key | Type | Meaning |
|---|---|---|
| `kind` | `"halt"` | marker |
| `version` | integer `1` | |
| `observer` | string | the identity of the observer that **found** the violation. In a relayed copy this is still the finder, not the relayer; the relayer is named by the file's name |
| `reason` | string | the identifier of the invariant, shape rule or check that failed: `I1`…`I8`, `S1`…`S5`, or a check identifier (section 15) |
| `subject` | string or `null` | what the reason is about: a member identity, or a path relative to `/stores/` written `<store>/<path>`, or a schedule or task identifier, or `null` |
| `sequence` | integer | the finder's heartbeat sequence of the cycle that wrote the halt |
| `when` | timestamp | |
| `detail` | string | free text for people |

A halt names exactly one reason: the first failing assertion in the finder's evaluation order (section 13). Every failing assertion is listed in the finder's fault file; the halt is the stop, the fault is the account.

### 3.5 The hash

**SHA-256 over the whole file, as bytes on disk.** Never over a chosen subset of fields, never over a re-serialisation, never over the buffer the writer intended to write. Independently written implementations agree on this without any shared notion of how the content is structured: they are looking at the same bytes. The hash also covers the varying part of the file (the timestamp and sequence), so it changes every cycle and says something about liveness.

An implementation that hashes a parsed-and-reserialised object, or trims a trailing line feed before hashing, computes a different value from one that does not and accuses every peer of lying. The fixtures include heartbeats whose expected observed hashes are given, to catch this.

---

## 4. Membership and the reader's own state

Each cycle, before anything else, a reader:

1. takes the ring's membership from the set it was started with (`-members`, which must include its own identity; `-coordinator` names one of them). The set minus its own identity is `OTHERS`;
2. loads its **basis**: the record of what it observed in its previous cycle, held in process memory. On the first cycle after a process start there is no basis (section 7);
3. loads its **memory**: the hash of every file it has published and not since removed, held in process memory, initialised on start from what its own store holds (section 7).

**Membership is declared, not discovered.** Discovery from the directory names under `/stores/` would let whoever can write that root add a position or remove one. Adding one is loud: the new position has no heartbeat folder, reads as a member that never ran, and halts the ring. Removing one is silent: discovery returns a shorter list, every remaining member goes on agreeing with itself, and a member has left the ring without anybody's assertion failing. A declared set makes the removed member's store a store that is missing, which the reads that follow report.

The gate the proxy reads (section 19) carries the same declared set.

A reader's basis and memory are in-process state. They are not read from the reader's own store during a cycle, because the whole point of memory (invariant `I5`) is to notice when the store disagrees with it. So is the time each subject has been unchanged (section 8), accumulated in process.

---

## 5. Publication

**Every file is staged and renamed.** The writer creates the staging file in the same directory as the final name, writes the whole content, syncs and closes it, and renames it over the final name. The staging name is the final name followed by `.tmp`:

| Final | Staging |
|---|---|
| `heartbeat/0000000042.hb` | `heartbeat/0000000042.hb.tmp` |
| `fault` | `fault.tmp` |
| `halt` | `halt.tmp` |
| `halts/admin` | `halts/admin.tmp` |
| `since` | `since.tmp` |

Because the staging name is derived from the final name and every final name has one writer, a staging file also has one writer. A writer that finds its own staging file already present (it crashed between create and rename last time) truncates and reuses it: that file is its own and nothing published depends on it.

**Heartbeats are never overwritten.** Each cycle produces a new sequence, and no sequence name is ever reused (section 6). `fault`, `halt` and `halts/<writer>` are renamed over when their content changes, which rename makes atomic.

**Removal** is a plain unlink of the final name. Nothing else needs removing except a writer's own staging file, and only that writer removes it.

**After publishing a heartbeat the writer re-reads it.** It opens the published file, reads every byte, and hashes that. The result is what goes into `previous` next cycle and into memory now. The re-read hash and the intended hash differ exactly when something went wrong with the write, which is the case worth catching. If the re-read bytes differ from the bytes the writer intended, the writer's assertion `own-store-writable` fails in the next cycle with subject `re-read`, until a later publish re-reads clean, and it uses the re-read hash regardless, because the re-read hash is the one every other reader will compute.

**Order of writes within a cycle** (section 13 gives the whole cycle):

1. own heartbeat, into the own store;
2. own fault, into the own store, if the failing set changed;
3. the copy of the heartbeat, then the copy of the fault, into the peer's `copy/` and into `copy-<self>/` in the super store, in that order;
4. own heartbeat pruning (section 6), after the copies are written;
5. halts, in the order section 12 gives.

The own store is always first, because the own store is the record and the copies are the redundancy. A reader comparing a copy against its original reads the copy first (section 9) so that, whichever moment it looks, the copy can be behind the original and never ahead of it.

---

## 6. The heartbeat folder, the sequence and the window

**The sequence is durable.** On start, an observer lists its own `heartbeat/` folder. If the folder holds entries, its next sequence is the highest present plus one. If the folder is empty, or does not yet exist and the observer creates it, the next sequence is 1. An observer never chooses a sequence lower than or equal to any name already present. That keeps a restart from looking like a rollback.

**The window is the four most recent entries** (`WINDOW = 4`, `-window`). After publishing a new heartbeat, and after writing its copies, the owner removes every entry with a sequence lower than `highest − WINDOW + 1`. Publishing first and pruning afterwards means the folder briefly holds five entries. That transient is deliberate: it guarantees every reader, at every instant, can find the four most recent, which is the guarantee the chain test rests on (a reader whose recorded hash is three cycles old must still find it). So the folder holds at most `WINDOW + 1 = 5` entries, and a reader treats every entry present as part of the chain.

**What the owner may prune and what nobody may.** The owner removes its own entries beyond the window, and only those. The folder itself is never removed, by anyone, under any circumstance, because the folder's persistence is what makes silence legible: a stale heartbeat means death, no folder means never ran here. No janitor, no recreation of the tree, no tidy-up. A removed folder is invariant `I4`.

**Copies are pruned by the same rule by the same writer.** The writer prunes its copy of its own folder to the same window after writing the new entry into it, so a copy has the same names as the original, up to the race between the two.

### 6.1 Procedure C: is a heartbeat folder a well-formed chain?

Run over a heartbeat folder `F` said to belong to author `A`. Used on a member's own folder (by every reader, including the owner) and on every copy of it. Each step names what fires if it fails; `I`-codes are invariants, `S`-codes are shape rules (section 11).

- **C1 names.** Every entry in `F` is a regular file whose name matches `^[0-9]{10}\.hb$` (a heartbeat) or `^[0-9]{10}\.hb\.tmp$` (staging). Any other name, or any subdirectory, fires `S1` (unexpected name) or `S2` (subdirectory). If an unexpected file's first bytes are `{"kind":"heartbeat",` it fires `I6` instead of `S1`.
- **C2 counts.** At most `WINDOW + 1` heartbeat entries; more fires `S3`. At most one staging file; more fires `S3`.
- **C3 staging age.** If a staging file is present and its modification time is older than `now − STAGING_STALE_AFTER_SECONDS` (`-staging-stale-after`), the reader's assertion `staging-fresh` fails, with the file's path as subject. An old staging file is a writer that died between creating it and renaming it, which is a crash, which is benign. A fresh staging file is nothing at all.
- **C4 sizes.** Every heartbeat entry is at most `MAX_HEARTBEAT_BYTES`; larger fires `S4` before the file is read.
- **C5 parse.** Every heartbeat entry parses under section 3.2 with `observer == A` and `sequence` equal to the name's integer; otherwise `S5`. Then `check_count == length(checks)` and `checks` has no duplicate; otherwise `I2`.
- **C6 consecutive.** Sorted by name, the sequences form a run of consecutive integers with no gap. A gap fires `I3`.
- **C7 chained.** For every entry `e` that has a predecessor `p` in `F` (the entry named `e.sequence − 1`), `e.previous == sha256(bytes of p)`. Otherwise `I3`. For the lowest entry in `F`, whose predecessor may have been pruned: if `e.sequence == 1` then `e.previous` must be `null`; if `e.sequence > 1` then `e.previous` must be a hash (not `null`). A non-null value that cannot be checked is accepted; a `null` above sequence 1 is a chain that restarted without restarting its numbering and fires `I3`.
- **C8 boot records.** For every entry with a non-null `boot`: `boot.resumed_from` equals `sequence − 1` if `sequence > 1`, and is `null` if `sequence == 1`. Otherwise `I3`.
- **C9 stops.** For every entry with `stop == true` that has a successor in `F`, the successor has a non-null `boot`. A heartbeat following a deliberate stop without a boot record is a sequence continuing past its own end, which fires `I3`.

The procedure runs all steps it can and collects every failing assertion; a failure in C5 for one entry does not stop C6 to C9 over the entries that did parse. The first failing assertion in the order above is the one a halt names.

---

## 7. Start, restart, stop and cold start

**Every process start writes a boot record.** The first heartbeat a process publishes carries `boot: {"started": <now>, "resumed_from": <highest found or null>}`. Its `previous` is the hash of the highest entry found in the folder (re-read from disk at start), or `null` if the folder was empty. Its `sequence` is that highest plus one, or 1. So the chain **continues** across a restart: the numbering does not reset, the `previous` link is unbroken, and a reader walking the chain finds no discontinuity. What the boot record marks is the discontinuity that does exist and is invisible from the chain: the observer's memory and basis were lost, and the timestamps may show a gap.

**Restart is not rollback.** A rollback (the folder holding a lower highest sequence than it held before) cannot be produced by a restart under this rule, because a restarting observer reads the folder first and continues from it. Any observed decrease is therefore a write by something other than the owner and fires `I3`.

**Memory and basis on start.** Both are lost with the process. On start the observer rebuilds **memory** from what its store holds: it hashes every entry in its own `heartbeat/`, and `fault` and `halt` if present, and takes those as what it last wrote. It is trust on boot, and a limit: a file altered while the observer was down is not detected by `I5`, only by the chain rules and by peers whose basis predates the restart. The **basis** is not rebuilt: on its first cycle a process has no basis, every liveness verdict is `unknown`, and neither `I1` nor `I4` is evaluated by it.

A reader that has just started could in principle take its basis from its own highest on-disk heartbeat. It must not. That heartbeat may be hours old, and a subject that advanced ten cycles in the meantime would fail `I1` on a benign event.

**Clean stop.** An observer shut down deliberately (a signal, or the `-cycles` bound reached) publishes one final heartbeat with `stop: true`, after running its checks as normal, and then exits. It does not remove any file. It does not clear its fault if one is standing; the fault is removed by the owner's first clean cycle after it is started again. The next heartbeat in that folder, if any, carries a boot record (rule C9).

**Cold start.** The first time an observer ever runs against a store, `heartbeat/` does not exist. The observer creates it, writes `since` (14.2 T1) if the store does not hold one, and its first heartbeat is sequence 1 with `previous: null` and `boot: {"started": …, "resumed_from": null}`. Every reader that finds a store root with no `heartbeat/` concludes *absent* and records `member-present` failing for it. On a cold start of the whole ring, every member therefore finds every other absent in its first cycle and halts; `member-present` is about another member, so no fault is written. In the second cycle all are present, all verdicts are `unknown`, and the halts lift by the recovery procedure.

The first cycle publishes a heartbeat even when every check fails: a heartbeat is the registration and the liveness signal, and an observer that waited for its checks to pass before registering would be silent exactly when it is needed.

**If the own store cannot be read, `heartbeat/` cannot be created, or `since` cannot be written**, the observer does not run. It exits with an error. There is no store to write a fault into and no heartbeat to make silence legible; its peers find its folder stale or absent, which is the designed signal for this case.

---

## 8. Reading a member: the verdicts

A reader `R` produces exactly one verdict for each subject `A` in `OTHERS` each cycle, from the set: **absent, alive, stale, retired, faulted, unknown**. The verdict is one thing; failing assertions (faults and invariant violations) are another, and one read can produce both.

**Staleness tolerance.** `STALE_AFTER_SECONDS(A) = A.cadence_seconds * (1 + STALE_SLACK)`, where `A.cadence_seconds` is read from `A`'s current heartbeat and `STALE_SLACK` is `-stale-slack`.

The time a subject has been unchanged is a duration the reader accumulates on its own clock and holds in process, like the basis and the memory: after each cycle's writes, the time since the previous cycle's end is added to every subject whose observed hash equals the basis, and reset to zero for every other. A cycle begins the moment the previous one ends (subject to the floor of section 13), and the cadence is a ceiling on how long one may take rather than an interval to sleep, so a count of the reader's cycles is not a unit of time; a duration is. No two hosts' clocks are compared here: one reader times its own observations against an interval the subject declared.

### 8.1 Procedure V: the verdict for subject A

- **V1 readable.** If `/stores/A/` cannot be listed, the verdict is `unknown`, the reader's assertion `store-readable` fails with subject `A`, and `observed[A]` is recorded as `null`. Stop.
- **V2 present.** If `/stores/A/heartbeat/` does not exist, or exists and holds no `.hb` entry: the verdict is `absent` and `observed[A] = null`. First, if `R` has a basis and `basis.observed[A]` is not `null`: the folder or its entries existed when `R` last looked and are gone now, which is `I4` if the folder is missing and `I1` if the folder is present but empty (the recorded hash is nowhere in an empty chain). Then `member-present` fails with subject `A`. The compromise is recorded before the fault so that, when both fire, the halt names the compromise. Stop.
- **V3 chain.** Run procedure C over `/stores/A/heartbeat/` with author `A`. Every failing assertion is recorded. If the highest entry did not parse, the verdict is `unknown`, `observed[A] = null`, and the procedure stops. Otherwise `cur` is the highest entry and `h = sha256(bytes of cur)`; record `observed[A] = h`.
- **V4 retired.** If `cur.stop == true`, the verdict is `retired` and `member-fresh` fails with subject `A`, for every `A`. Stop.

  Retirement changes the reason, not the consequence. The verdict lets whoever reads the stores afterwards tell a deliberate stop from a death. What it must not do is excuse the absence: a member that has stopped is not verifying the stores, which is the same fact about the ring as a member that has died, and the ring acts on the fact. Stopping an observer deliberately stops the work it was watching; nothing runs unobserved for any reason. The halt lifts by itself when the member returns.
- **V4b the absolute backstop.** If `cur`'s own timestamp is more than `HEARTBEAT_MAX_AGE_SECONDS` (`-heartbeat-max-age`) from the reader's clock, behind it or ahead of it, or does not parse, the verdict is `stale` and `member-fresh` fails with subject `A`. Stop. Ahead counts for the reason 19.3 gives the gate: a clock that disagrees disagrees whichever way it runs, and the gate refuses a coordinator heartbeat ahead of its clock, so a member that accepted one would report a healthy ring around a proxy that serves nothing.

  This is the one place a verdict reads a timestamp. Every other liveness test measures whether a hash changed, so that no verdict depends on two machines agreeing about the time. That mechanism has a gap it cannot close: a reader that has just started holds no basis, so every hash looks new to it and it cannot tell a live member from one that died an hour ago. A timestamp needs no basis. **The threshold must exceed the cadence the observer declares**, or it cannot tell a member keeping its cadence from a dead one; the member refuses to start otherwise (`parseFlags`). The deployment sets it well above (`deploy/README.md`, "The cadence contract").

- **V5 no basis.** If `R` has no basis, or `basis.observed[A]` is `null`: if `/stores/A/fault` exists, the verdict is `faulted`, else `unknown`. Nothing fails; `I1` is not evaluated. Stop.
- **V6 unchanged.** Let `H = basis.observed[A]`. If `H == h`, the subject has not advanced since the last cycle. If the time it has been unchanged, as this reader has measured it, is at least `STALE_AFTER_SECONDS(A)`, the verdict is `stale` and `member-fresh` fails with subject `A`. Stop. Otherwise the subject is unchanged within tolerance; continue at V8.
- **V7 advanced.** `H ≠ h`. If `H` equals the hash of some entry present in `/stores/A/heartbeat/`, the subject has advanced and `R`'s record is an ancestor of its current state. Continue at V8. If `H` equals no entry's hash, `R` recorded a state `A` never published, or `A`'s chain no longer contains what `R` honestly read: `I1` fires with subject `A`, the verdict is `unknown`, and the procedure stops. There is no benefit of the doubt here: a hash outside the chain is either a lie or a member more than a window behind, and both are treated the same.
- **V8 faulted or alive.** If `/stores/A/fault` exists, the verdict is `faulted`; otherwise `alive`. A fault file that fails to parse, or names another observer, is still a fault by presence and additionally fires `S5` with subject `<A>/fault` (`S4` when oversized, `I6` when it carries the heartbeat marker).

The verdict priority this produces, for reference: absent, retired, stale, faulted, unknown, alive. A peer's own fault is never a failing assertion of the reader; a reader's failing assertions from this procedure are only `store-readable`, `member-present` and `member-fresh`, plus the invariants and shape rules.

### 8.2 The coordinator as subject

The coordinator is read by procedure V like any other member: `store-readable`, `member-present` and `member-fresh` fail for it as for anyone and raise a halt. What is asymmetric is recovery (section 12): only the coordinator's standing down lets a halt lift.

---

## 9. Copies: procedure K

A copy directory `D` is `copy/` in an application observer's store (author: the peer that writes it), or `copy-<author>/` in the super store, or `copy-super/` in an application store (author: the coordinator). The receiver `R` validates the shape of `D` before it looks at the content, because write access to a directory is write access to whatever a directory can hold. Then it compares the content against the author's own store.

**Who runs it.** Each application observer runs K over its own `copy/` and its own `copy-super/`. The coordinator runs K over all six copy directories: its three `copy-*/` and the three `copy/` in the application stores. Only the coordinator can make that whole-view comparison.

**Read order.** `R` reads `D` completely (lists it, reads every file) **before** it lists the author's own `heartbeat/`. The author writes its own store first and its copies second, so a copy read before its original can be behind it and never ahead of it. Any copy entry ahead of the original is therefore a record the author never published, with no race to explain it.

- **K1 readable.** If `D` cannot be listed, `copy-readable` fails with subject the author. Stop.
- **K2 root shape.** The entries of `D` may be exactly: a directory named `heartbeat`; a regular file `fault`; a regular file `fault.tmp`. Any other name fires `S1` (or `I6` if the file begins with the heartbeat marker); any other directory fires `S2`; `heartbeat` present as a regular file fires `S1` (or `I6`). `fault` larger than `MAX_FAULT_BYTES` fires `S4`, and that file is not read again this cycle. `fault.tmp` older than `STAGING_STALE_AFTER_SECONDS` fails `staging-fresh` with its path as subject.
- **K3 heartbeat shape.** If `D/heartbeat/` exists, run procedure C over it with the author as `A`. All failing assertions are recorded. If `D/heartbeat/` does not exist, the copy holds no heartbeats; that is treated as an empty folder in K5.
- **K4 original.** Take the author's own `heartbeat/` as step 4 listed and read it (procedure C over the author's folder). Let `W` be the set of entries listed there (the author's chain as it stood), and `names(W)` their sequences, bounded by what the listing showed and not by what could be read, so that an entry pruned between the listing and the read cannot lower the ceiling and make an honest copy look like a record the author never published. If the author's store could not be read, or held no entries, the copy cannot be judged this cycle: stop here with nothing from K (the author's own verdict has already recorded the problem).
- **K5 each copy entry.** For each parsed heartbeat entry `e` in `D/heartbeat/` with sequence `n`:
  - if `n > max(names(W))`: the copy is above the ceiling step 4 took. The ceiling may simply be stale: the author publishes to its own store first and to the copy second, so an author that advanced between step 4 and this read leaves an honest copy one entry above it. List the author's `heartbeat/` again now and take the fresh maximum; `I7` fires with subject the author only if `n` is still above it. A forged entry is above every ceiling for ever; a race is above only the stale one. If the folder cannot be listed now, the ceiling stays where it was.
  - if `n ∈ names(W)` and the original entry `n` was read: the bytes of `e` must equal its bytes. If they differ, `I7` fires with subject the author. (Whether the copy or the original was altered cannot be told from here and does not matter; one of them was written by something that is not their author.) An original entry that was listed but could not be read is not compared; its own failing assertion, if any, stands.
  - if `n < min(names(W))`: `e` is behind, an entry the author has since pruned from its own folder. It cannot be checked. Note it.
- **K6 behind.** If `D/heartbeat/` holds no entry whose sequence is in `names(W)` (because it is empty, or because everything in it is behind), `copy-current` fails with subject the author. A copy with some entries in the window and some behind also fails `copy-current`, because the writer prunes its copy by the same rule and an unpruned old entry means the copy is not being maintained. It is a fault, never a compromise: the ordinary causes are the copy directory unwritable, its ownership wrong, or the writer failing on that one path while succeeding at home. Without this split a copy directory failing would halt the proxy on a compromise. One transient is worth knowing about: on an author's very first cycle a receiver may read the copy before the author has written it and the original after, and report `copy-current` for one cycle. The ring is halted at that moment anyway (cold start), and it clears next cycle.
- **K7 the fault copy.** Compare `D/fault` against the author's own `fault`:
  - both absent: nothing.
  - `D/fault` present: it must parse as a fault under 3.3, else `S5` and K7 stops; its `observer` must equal the author, else `I7` (an honest author only ever names itself) and K7 stops. A `D/fault` that fired `S4` in K2 was never read and K7 does not run.
  - `D/fault` present, original absent: behind (the author cleared it and has not yet cleared the copy, or the copy cannot be cleared). `copy-current` fails with subject the author.
  - `D/fault` absent, original present: behind (the author wrote it and has not yet copied it, or cannot). `copy-current` fails.
  - both present and byte-equal: nothing.
  - both present and different, after the checks above pass: the author has rewritten its fault and the copy is one write behind, or the copy cannot be written. `copy-current` fails. A fault file has no chain, so "a record the author never published" is decidable only in the two forms given above (wrong author, sequence not reached). Every other disagreement has a benign cause and is a fault.

---

## 10. `halts/`: the in-force rule and the owner's shape check

### 10.1 A halt is in force

A halt is in force when **any** of the following exists, in any store:

- a regular file named `halt` at the store root;
- a regular file inside `halts/` whose name does not end in `.tmp`.

Existence, not content. A reader does not parse a file to decide whether the system is halted. No vote, no aggregation, no precedence.

A store that cannot be read is not a halt in force; it is `store-readable` failing, which raises a halt of its own. "No halt" and "cannot read the store" are kept distinct even though both stop the system: one is recorded as a halt found, the other as an assertion failing.

### 10.2 Procedure H: the owner validates its own `halts/`

Run by the owner over its own `halts/` every cycle, before it acts on anything found there. The permitted writers are `OTHERS`.

- **H1 readable.** If `halts/` cannot be listed, `halts-readable` fails (a local check; the directory is missing or broken). Stop.
- **H2 names.** Every entry is a regular file named `<w>` or `<w>.tmp` for some `w ∈ OTHERS`. Any other name fires `S1` (or `I6` if the file begins with the heartbeat marker). Any subdirectory fires `S2`.
- **H3 counts.** At most one `<w>.tmp` per writer `w`, which the naming rule already gives; a filesystem cannot present two entries of one name.
- **H4 staging age.** A `<w>.tmp` older than `STAGING_STALE_AFTER_SECONDS` fails `staging-fresh` with its path as subject. A crash, so a fault.
- **H5 sizes.** A `<w>` larger than `MAX_HALT_BYTES` fires `S4`, before it is read.
- **H6 parse.** Each `<w>` must parse as a halt under 3.4, else `S5` with subject `halts/<w>` (`I6` when it carries the heartbeat marker). It is in force whether or not it parses.
- **H7 owner.** Every entry named for a writer `w`, the slot `<w>` and its staging file `<w>.tmp`, must be owned by the account `w` runs as. The owner is what the kernel recorded when the entry was created, which no writer chooses; the account is what the deployment says `w` runs as, given to every member as a mapping from member to account name (`-slot-owners`, one string on every member, every declared member named, refused otherwise) and resolved through the host's account database. An entry owned by anyone else fires `I8` with subject the entry's path and what was found: `<store>/halts/<w>:owner:<uid>`. The clause fails closed at every step it cannot take: `:unmapped` when the mapping names no account for `w`, `:no-account:<name>` when the host has no such account, `:unprobed` when the entry cannot be stat'ed, and `:unsupported-os:<GOOS>` on any OS without POSIX ownership, where nothing can be known of any entry, so any entry at all fails and only an empty `halts/` reads clean. An entry the listing held and a stat now shows gone is its writer clearing it, and nothing fails. Every member of a group with write on `halts/` can create a name there, so the directory grant cannot narrow creation to one name; this clause is what does, after the fact and within a cycle.

**A slot that fails H7 is in force.** 10.1 is existence, not provenance: the gate and every reader stop on it as on any slot, and it is relayed as found. It stays until root, or the account that created it, removes it (12.3); the named member never wrote it, holds no memory of it, and could not unlink it if it tried. What H7 adds is that the ring says so: `I8` is the owner's own failing assertion (3.3), so its `fault` names the file and the uid that wrote it for as long as the file stands, no member's clear-condition holds (12.3), and the ring cannot report a clean set of stores around a halt nobody raised.

Two peers with write access to one directory could each remove the other's file where the directory's mode allows it. The delivered copies are reach, not the record: the record is the finder's own `halt`, in a store nobody else can write. The deployment's sticky bit refuses that removal (`deploy/README.md`, "The `halts/` slot problem"); H7 is the matching check on the other direction, creation.

---

## 11. The structural invariants and the classification

### 11.1 The eight invariants, as procedures

Each is a determinate question over files and the reader's in-process state. None involves a judgement, a clock comparison between hosts, or a threshold. Where a step is defined elsewhere, the reference is given.

**I1: a recorded hash is not in the subject's chain.**
Two forms, both evaluated by every reader.
*(a) Own record.* Procedure V, step V7: `R`'s `basis.observed[A]` is a hash that equals no entry in `A`'s folder. Also V2 when the folder is present but empty.
*(b) Another's account.* For each member `B` in `OTHERS` whose verdict this cycle is `alive` or `faulted` (a current account), and for each `C ≠ B` named in `B.cur.observed` with a non-null value: if `C`'s folder is present with entries and the value equals no entry's hash, `I1` fires with subject `B` (the detail names `C`). Accounts from members whose verdict is `stale`, `retired`, `absent` or `unknown` are not judged, because their account is not current and the reader already holds the failing assertion that explains it: a dead member's last heartbeat records hashes that are naturally stale, and a death must not fire a compromise.

**I2: check count disagrees with the check set.** Procedure C, step C5: `check_count ≠ length(checks)`, or `checks` contains a duplicate. Evaluated over every heartbeat parsed anywhere.

**I3: sequence moves backwards, or the window has a gap or a broken link.**
*Owner side:* the owner's memory holds the sequence it last published; if the highest entry now in its own folder is lower, `I3` fires with subject its own identity.
*Reader side:* procedure C, steps C6 to C9, over any folder: a gap, a `previous` that does not equal the predecessor's hash, a `null` `previous` above sequence 1, a boot record whose `resumed_from` is not `sequence − 1`, or an entry following a `stop: true` without a boot record.

**I4: a folder that existed is absent.** Procedure V, step V2: `basis.observed[A]` is non-null and `/stores/A/heartbeat/` does not exist. Only the in-process basis counts; a reader that has just started has no basis and finds *absent*, which is a fault. A missing mount and a removed folder look the same on disk; they are told apart by when: a reader with a basis that recorded the member finds it gone during a run, which is `I4`; a reader starting up finds it absent, which is `member-present`. Both halt.

**I5: the owner's own file differs from what it last wrote.** Each cycle the owner, for every path in its memory: if the file is missing, or its bytes hash to something other than memory holds, `I5` fires with subject that path. And for `fault` and `halt`: if the file exists in the own store but memory holds no entry for it, someone else wrote it; `I5` fires. Memory covers own heartbeat entries (within the window), own `fault`, own `halt`, and the owner's slots in others' `halts/`.

**I6: a heartbeat appears where the store's owner does not write its own.** Any file, at any path in any store, that begins with `{"kind":"heartbeat",` and is not at `<store>/heartbeat/<seq>.hb`, `<store>/heartbeat/<seq>.hb.tmp`, `<copy dir>/heartbeat/<seq>.hb` or `<copy dir>/heartbeat/<seq>.hb.tmp`. Found by the shape checks of C1, K2, H2 and by the store-root shape check of 11.2. Takes precedence over `S1` for the same file. (A heartbeat under the right name but with the wrong `observer` is `S5`, not `I6`: it is in the right place with the wrong content.)

**I7: a copy holds a record the author never published.** Procedure K, steps K5 and K7: an entry ahead of the original, an entry in the window whose bytes differ from the original, a fault copy naming another author. A copy that is merely behind is `copy-current`, a fault.

**I8: an entry of the owner's `halts/` was not written by the member it is named for.** Procedure H, step H7: the entry `<w>` or `<w>.tmp` in the owner's own `halts/` is owned by a uid other than the account the deployment maps `w` to, or its owner cannot be established (the mapping, the account, the stat or the OS). Subject: the entry's path and what was found, `<store>/halts/<w>:owner:<uid>`, `:unmapped`, `:no-account:<name>`, `:unprobed`, `:unsupported-os:<GOOS>`. Evaluated by the owner alone, since only the owner's `halts/` is one it never writes; `w` cannot see it (its memory holds only what it wrote) and the other writers do not read it. The entry is in force while it stands (10.2).

### 11.2 The shape rules

The shape rules are not numbered among the eight but sit with the compromise set: none of them has a benign cause, because no honest writer produces them and no crash produces them (a crash produces a staging file, which is handled separately). They are evaluated over every directory the reader examines, including the store root of every member, whose permitted entries are: `heartbeat` (directory), `fault`, `fault.tmp`, `halt`, `halt.tmp`, `since`, `since.tmp`, `halts` (directory), and `copy` and `copy-super` (directories) in an application store or `copy-tunnel`, `copy-admin`, `copy-material` (directories) in the super store.

| Rule | Fires when |
|---|---|
| `S1` | an entry exists under a name not permitted at that place |
| `S2` | a directory exists where none is permitted |
| `S3` | a count is exceeded: more than `WINDOW + 1` heartbeat entries, more than one staging file in a directory (or per writer in `halts/`), more than one `fault` |
| `S4` | a file is larger than the bound for its kind |
| `S5` | a file fails to parse as the kind its place requires (section 3), including a `version` other than 1, an `observer` that is not the expected writer, or a `sequence` that does not match its name |

### 11.3 Classification

The governing rule: **if a condition can fire on a benign event, it is a fault, not a compromise.** A fault is expected to fire on ordinary conditions and clear; a compromise assertion must be decidable and must never fire on a benign event. Both raise a halt, so the classification decides not *whether* the system stops but how carefully the test had to be written and what a person is told when they open the halt.

| Condition | Class | Identifier | Why |
|---|---|---|---|
| a member's store cannot be listed | fault | `store-readable` | a mount can be missing |
| a member's `heartbeat/` absent or empty | fault | `member-present` | never ran here, or crashed before first write |
| a member unchanged for longer than its staleness tolerance | fault | `member-fresh` | a process can die |
| a member's heartbeat older than the backstop, or ahead of the clock | fault | `member-fresh` | a process can die; a clock can be wrong |
| any member retired | fault | `member-fresh` (subject the member) | a person can stop it, and stopping an observer stops the work it watched |
| a peer has a `fault` file | none | none | that peer's fault, not the reader's; recorded, not mirrored |
| a copy directory cannot be listed | fault | `copy-readable` | a directory can be missing |
| a copy behind its original, empty, or one fault-write behind | fault | `copy-current` | a directory can be unwritable; the author can be mid-write |
| a staging file older than the threshold | fault | `staging-fresh` | a crash between create and rename |
| own `halts/` cannot be listed | fault | `halts-readable` | a directory can be missing |
| own store not writable, or re-read bytes differ from what was written | fault | `own-store-writable` | a disk can fail |
| own cycle exceeded declared cadence | fault | `cycle-within-cadence` | a slow host |
| own `since` absent or unreadable | fault | `observing-since` | a file can be lost |
| a schedule trace late, incomplete, or missing tasks | fault | `trace-fresh`, `trace-complete`, `trace-coverage` | a job can be slow or die |
| a post-condition count not zero | fault | `postcondition` | a query can match nothing |
| the per-member checks of a surface (14.3) | fault | per-observer identifiers | ordinary causes exist |
| recorded hash not in the subject's chain | compromise | `I1` | nothing benign records an unpublished state |
| check count disagrees with check set | compromise | `I2` | nothing benign writes an inconsistent file; atomic publication rules out truncation |
| sequence backwards; gap; broken link; stop without boot after it | compromise | `I3` | the owner never does this; a restart continues the chain |
| a folder that existed is gone | compromise | `I4` | nothing prunes the tree |
| own file altered or missing | compromise | `I5` | the store is read-only to everyone else |
| a heartbeat where its owner does not write | compromise | `I6` | a member cannot write there |
| a copy holding an unpublished record | compromise | `I7` | nothing benign writes another's heartbeat |
| an entry of own `halts/` owned by anyone but the member it is named for, or whose owner cannot be established | compromise | `I8` | a member writes only its own slot, and the kernel records who wrote each; a check that cannot know the owner has not passed (10.2 H7) |
| unexpected name, subdirectory, count, size, malformed file | compromise | `S1` to `S5` | no honest writer, no crash, produces these |
| own store, or a directory in it, owned or moded other than the deployment's tree says; own `halts/` writable by this member | compromise | `own-store-private` | nothing benign changes the ownership of a store; on an OS with no ownership the check fails unless the operator accepted that (13, step 3) |
| a prefix of the proxy's trace read last cycle hashes differently now, or a segment shrank or vanished | compromise | `trace-consistent` | a trace is appended, never rewritten (14.3) |
| more than one boot's process live at once | fault | `boot-ambiguous` | a pid can be reused by an unrelated process (14.3) |
| the process the start line names is gone, or started after the line or long before it | fault | `proxy-process-alive` | a process can die, and a pid can be reused (14.3) |
| a surface's owner does not list a check of its surface, or does not publish a failure another member computes over the same trace | fault | `surface-disagree` (subject `<owner>:<identifier>`) | about another member: a halt without a fault; a condition that begins between two members' cycles is computed by one before the other publishes it (14.3) |

There is one kind of halt, and every failing assertion raises it: fault or compromise, local or about another member. The difference between the classes is the discipline that went into writing the test, not what happens when it fires.

**The classification here is not the same question as what goes in the fault file.** This table says how carefully a test had to be written and what a person is told when they open the halt. The `fault` file is narrower still: it carries only the failing assertions an observer makes about its own world (3.3), so `member-fresh` is classified as a fault here and yet never appears in one. A dead peer halts every member and makes none of them faulty.

---

## 12. Halting and recovery

### 12.1 Raising a halt

When any assertion of `R`'s fails this cycle (a check, an invariant, a shape rule), `R` does the following, in this order, skipping any step whose file already exists (it never overwrites a halt):

1. publishes (or republishes, if the failing set changed) its `fault`;
2. writes `halt` in its **own store**: the record, in the one place no other member can write or erase;
3. writes `halts/R` in the **coordinator's store** (if `R` is not the coordinator), because the coordinator decides when the halt ends and cannot decide about what it has not been told;
4. writes `halts/R` in each remaining store in identity order.

The content of every halt file `R` writes in one cycle is the same bytes: the halt describing the first failing assertion in `R`'s evaluation order (section 13). The fault copies travel by the ordinary copy route (section 5) and need no step here.

If `R` is the coordinator, steps 3 and 4 collapse into: `halts/super` in `admin`, `material`, `tunnel`, in that order.

### 12.2 Relay: a halt spreads by being received

If `R` raised nothing itself this cycle, and its clear-condition (12.3) does not hold, and a halt is in force anywhere (10.1), then `R` ensures a file named `R` exists in the `halts/` of every other store. It writes one where it is absent and does nothing where it is present, which is the idempotence: a relay never overwrites, so a halt that has reached everyone produces no further writes and cannot echo.

The bytes `R` writes are the bytes of the first halt it found, walking: its own store's `halt`; its own `halts/` in listing order; then each other store in identity order, that store's `halt` and then its `halts/`. Copying the bytes preserves the finder's name and reason for the person who opens it. A found file that is in force but does not parse is still relayed as found. A found file larger than `MAX_HALT_BYTES` is in force but is not relayed; the walk goes on to the next, and when every halt in force is beyond the bound nothing is written.

Relay does not write `R`'s own `halt`. That file means *R itself found a violation* and nothing else.

### 12.3 Recovery

The condition that halted the system is usually temporary, and the protocol runs backwards.

**The faulting observer clears its own fault.** When every assertion in its `failing` set passes again, it removes `fault` from its own store and, by the copy route, from its copies. If some clear and others remain, it republishes the file with the smaller set. Nobody else can clear it and nobody else has to.

**The coordinator decides the all-clear.** Each cycle, after its reads, the coordinator evaluates its clear-condition: no `fault` file exists at the root of any declared store (the originals; copies are records), and none of its own assertions failed this cycle. If it holds, the coordinator removes `halts/super` from `tunnel`, `material`, `admin` (reverse identity order, the reverse of the order it wrote them) and then its own `halt`. If it does not hold, the coordinator removes nothing.

**Each application observer follows.** Its clear-condition: no `fault` file at the root of any declared store, `/stores/super/halt` does not exist, and none of its own assertions failed this cycle. If it holds, `R` removes `halts/R` from the two peers in reverse identity order, then from `super`, then its own `halt`. If it does not hold, `R` removes nothing and relays as 12.2 says.

**Who may clear what.** Every file is removed only by the writer that created it: a `fault` by its owner, a `halt` by the finder, a `halts/<w>` entry by `w`. A person intervening does so as the owner of the file they remove, and only with the file's owner stopped. Nothing in this protocol removes a file it did not write.

**A slot nobody's protocol wrote.** An entry of `halts/` that H7 finds owned by an account other than the named member's (`I8`, 10.2) has no writer in this protocol: the named member never wrote it and holds no memory of it, and the account that did create it is not running the code that removes `halts/<self>` under that name. So nothing here removes it, and the ring stays halted, with the owner's `fault` naming the file and the uid, until a person removes it as root or as that account, with the member running as that account stopped, after learning why that account wrote a name that is not its own. A name in `halts/` that a member did not put there is a member, or something running as one, doing what the write matrix says it never does, and the ring does not resume over it.

**Execution resumes on its own.** The proxy keeps reading the same files; when the last halt is gone it serves again. Nobody restarts anything.

**There is no dwell.** An intermittent fault halts and resumes as it flaps. A dependency failing sixty times an hour is reported sixty times an hour.

**Detection is unilateral, recovery is agreed.** Any one observer halts everything at once and alone. Nothing restarts until the coordinator stands down and every member sees a clean ring, and each member sees that for itself rather than being told.

### 12.4 The log is the record that survives recovery

Every file this protocol writes is **state**, not history. A `fault` says an assertion is failing *now*; a `halt` says the system is stopped *now*. Recovery removes them, and it must: a halt file that outlived its condition would assert something untrue, and the next reader would stop a healthy system on it. Presence is the whole signal, so presence has to end when the condition does.

That leaves nothing in the store to answer "has this ever happened", and nothing should be added to the store to answer it. **Each observer writes a log**, to its standard output, where the deployment's ordinary collection takes it: its failing set each time that set changes, every halt it raises with the reason and subject, every halt it relays and from where, every file it removes on recovery, and every write that failed, each carrying the sequence number of the cycle, so that the log and the chain can be lined up afterwards.

**Logging always follows the halt. Never the other way round.** The halt is what stops the system; the log only explains it afterwards. Written in the other order, a slow or blocked log write delays the stop by however long it takes, and an observer that dies between the two has recorded the explanation for a stop that never happened. So section 12.1's order stands and the log comes after all of it, and the same holds for a relay and for a clear: act, then record.

**A failure to log never prevents or delays a halt.** Logging errors are swallowed. The log is not load-bearing for detection: the store carries the state, the ring reads the store, and nothing in the protocol consults a log.

**The format is not specified.** A log is the one thing in this design that no other member reads, so four implementations logging differently cannot disagree about anything.

**The trace under `gt/` is the other record that survives recovery, and it is not the ring's to shorten.** Everything ghostunnel writes there (section 14) stays: the emitter never deletes, no member writes `gt/` at all, and the proxy does not prune its own trace, because a process that could shorten its own record could be made to, and the record of a halt is worth most exactly when the process that wrote it is the one in question. Retention of finished boots is a deployment policy, set and run by the operator outside every process of the ring, under the readers' rules (a finished boot only, whole, and the chain store only with the boots that name its entries); the rule and its limits are in `deploy/README.md` ("Trace retention"). The trace is also the one part of the tree that holds somebody else's data, the presented certificates, so it is readable by the four observers through their group and by nobody else (section 2).

---

## 13. The cycle

Every observer runs the same cycle, in this order. The order is part of the specification because it fixes which failing assertion is *first*, which is what a halt names, and because it fixes the read order that makes copy comparison decidable.

1. **Start the clock** (monotonic).
2. **Membership** is the declared set (section 4). Basis and memory are in process.
3. **Own store.** Check the store root's shape (11.2); check `I5` over memory; run procedure C over the own `heartbeat/` and the owner side of `I3`; check own `halts/` with procedure H, its owner clause H7 over the member-to-account mapping the member was started with (`-slot-owners`); check `own-store-writable` by creating and removing a staging file in own `heartbeat/`, and fail it with subject `re-read` while the last publish's re-read (section 5) differed from what was written; check `own-store-private`: the store root, `heartbeat/`, `halts/`, `fault` and `halt` when present, and each copy directory the store holds are owned and moded as the deployment's tree (`deploy/tree.tsv`, given by `-tree`, read once on start) says, and `halts/` is not writable by this member's uid (not the owner, not in the group, or the bits deny). Subject: the path, `<store>/<path>`, with `:writable` appended for the last; `tree` when the tree could not be read; `unprobed` when nothing was probed. The tree describes Linux ownership; on any other OS the check cannot run and fails with subject `unsupported`, unless the member was started with `-accept-no-store-check=<os>` naming that very OS (refused unless it equals the OS the member runs on; refused on linux; judged `stale-acceptance` when set on linux). The ownership probe runs before the cycle, by the driver, on the real disk; the fixture harness supplies it satisfied.
4. **Each member `A` in `OTHERS`, in identity order.** Check `A`'s store-root shape. Run procedure V, which runs procedure C over `A`'s folder and records `observed[A]`. Note whether a halt is in force anywhere (10.1) before anything is written.
5. **Copies.** For each copy directory this observer is responsible for (section 9), in identity order of author: procedure K, reading the copy before re-listing the author's folder.
6. **Third-party accounts.** `I1(b)` over every current account (11.1).
7. **Local checks**: the member's own surface, the checks every member makes over the proxy's trace (14.3), then `observing-since` and the schedule traces (section 14). These are this observer's own constants. The local checks receive what step 4 read of every other member (its verdict, its newest heartbeat's `checks`, its root `fault`), read before the proxy's trace is, so what a member published is compared with a trace at least as new.
   - **7b.** `cycle-within-cadence`: the time since step 1 must not exceed the declared cadence. The cycle is timed over its work, before publication, so an overrun is a failing assertion of the cycle that overran, not of the next one.
8. **Publish the heartbeat**: `checks` is the set of identifiers of every check that ran in steps 3 to 7 (the structural identifiers of section 15 for the structural checks, the observer's own for the local ones), `check_count` its size, `observed` as recorded, `previous` from memory, `boot` on the first cycle only, `stop` on a clean stop. Re-read, hash, update memory.
9. **Publish or clear the fault**, if the failing set changed. Update memory.
10. **Copies out**: heartbeat then fault, into the peer's `copy/`, then into `copy-<self>/` in the super store (the coordinator: into `copy-super/` in every other store). Prune own folder and copies to the window.
11. **Halts**: raise (12.1) if anything failed; otherwise evaluate the clear-condition and either clear (12.3) or relay (12.2). The reads that decide these writes (does this slot exist now) are live, not from the cycle's earlier look.
12. **Begin the next cycle**, as soon as this one ends, unless it finished faster than `MIN_CYCLE` (`-min-cycle`), in which case it waits for that. The cadence is a ceiling on how long a cycle may take and still count as verifying the system, not a pace to keep.

**One look at the store.** Within steps 3 to 7 a directory listed a second time, a path stat'ed a second time or a file read a second time is served from the first listing, stat or read, so that every check of the cycle judges one version of each path. A change that lands between the first and a later read of a path within one cycle is judged by the next cycle's first read: a latency of at most one cycle. The reads whose point is to see the disk now stay live: the fresh ceiling of K5, the stat of a path after a read failed, the `own-store-writable` probe, and step 11.

**Why there is a floor as well as a ceiling.** Left to run flat out, each observer cycles as fast as its own workload allows, and those differ. A reader's recorded hash then falls out of a fast subject's window between two of its own reads, and every member reports `I1` against every other: a compromise fired by nothing worse than one member having less to do. The floor equalises them: every cycle is longer than it, so every observer runs at about the same rate.

**Nothing is deferred to the next cycle** except what is learned after the cycle's writes: the re-read of the published heartbeat (section 5), which is the next cycle's `own-store-writable` with subject `re-read`. A publication that fails despite the probe passing is the one thing learned too late to record, and at that moment the store cannot take a fault or a halt either, so there is nowhere to defer it *to*. The observer exits and its peers see the heartbeat stop advancing, which is the designed signal for exactly this case. The log still records it, because the log is not the store.

**The first cycle** differs in two ways only: there is no basis (every verdict is `unknown` or `absent`, `I1` and `I4` do not fire) and the heartbeat carries a boot record. The first cycle still runs every check, still publishes, and still raises halts: on a cold start, for absent members.

**A clean stop** is a final cycle identical to any other except that step 8 publishes `stop: true` and the process exits after step 11.

---

## 14. Traces

Work that only runs when asked cannot report its own liveness; it leaves a trace and the observer on the same host reads it. Traces live under the traces root the member is started with (`-traces`, the deployment's `/stores/gt/`), read-only to observers, because observers never write traces and the single-writer rule has to survive contact with the writer.

**ghostunnel's own per-connection trace** (accept, handshake, acl, close, reload, shutdown, tick, accept-error, refusal) is that root's content; its format is documented in `ringtrace/README.md` and it is read by each member's local checks (step 7). That trace is written in segments, `gt/<boot>/<sequence>.trace`, and the emitter pre-extends the segment it is writing to its maximum size, writes within it, and truncates it to its written length when it closes it: an at-rest segment is exact, and the live one, or the last segment of a boot that crashed, carries a tail of NUL bytes. Every reader of a segment, in every member, applies one rule, **the segment rule**: a segment's content is its bytes before the first NUL byte (0x00), or all of its bytes when it has none. Bytes from the first NUL onward are unwritten space of a pre-extended segment and are not part of the trace. A reader reads a segment in bounded chunks from its start and stops at the first chunk holding a NUL or at end of file; it never reads a whole pre-extended segment. The complete-line prefix and the torn tail are then taken of the content. Lines are JSON objects, which never carry a raw NUL, so the rule is exact; and a segment's file size is nowhere a length of the trace.

Beside the boot directories the root holds two more directories, neither of which a reader that lists the root walks; each is read by name.

**The chain store** `gt/chains/` (ringtrace/README.md 1.5): the certificate chain a peer presented on a handshake, kept whole, content-addressed. A file `gt/chains/<sha256>.der` holds the concatenation, in presented order, of the DER of every certificate the peer presented, and is named by the lower-case hexadecimal SHA-256 of that content; ghostunnel writes it once, to `<sha256>.tmp` then renamed, durable before the `handshake` line that names it in its optional `chain` key is written, so a durable handshake line never names an absent chain. The `chain` key is present, and a 64-character hash, whenever the peer presented a certificate (full or resumed handshake, accepted or refused), and absent otherwise; never `null`, never empty. A chain is judged when read by name, by the members' own reader written to these rules, the proxy's `ReadChain` mirrored and not shared: the name is 64 lower-case hexadecimal characters (so a name is never a path); `<root>/chains/<name>.der` exists and is a regular file as `Lstat` sees it (a symbolic link is judged as the link and refused, a directory is refused; a `<name>.tmp` is never opened, so a chain that only has its `.tmp` is absent); the file's size is at most 1 MiB, checked before any content is read, and the read is bounded by it; the content's SHA-256 is the name (a tampered byte, or the right content under another name, is refused); and the content parses as a concatenation of at least one DER certificate. Any refusal is the chain unreadable, and what the chain was to prove is not proved.

**The material store** `gt/material/` (ringtrace/README.md 1.6): the CA bundle ghostunnel hashed for a `start` line's `material` entry of kind `ca`, and for every successful `reload` line's, kept as the bytes hashed, in the file `gt/material/<sha256>`, no suffix, named by that hash; ghostunnel writes it once, `<sha256>.tmp` then renamed, durable before the line that names the hash is written (a start that cannot store its bundle does not start; a reload that cannot is a failed reload, its line `failed` with `serving` `false`), so a durable line never names a bundle the store lacks. A rotation in place, a new bundle written over the old path and reloaded, leaves the old bytes under the old hash and the new under the new, and the substance rules judge each handshake under the bundle in force at its line by that hash, never by the path, which they do not read. A bundle is read by the hash a line records, by the chain store's rules with the bound 16 MiB and no parse: the name is 64 lower-case hexadecimal characters; `<root>/material/<name>` exists and is a regular file as `Lstat` sees it (a symbolic link or a directory is refused; a `<name>.tmp` is never opened); the size is at most the bound, checked before any content is read, and the read is bounded by it; the content's SHA-256 is the name. Any refusal is the bundle unreadable, and every verified handshake judged under that hash is not confirmed.

What the members do with a chain and a bundle they have read is section 14.3, the two substance rules. What follows in 14.1 and 14.2 is the schedule, run and task trace machinery: every member implements it (`traces.go`) and the trace fixtures exercise it. The schedules a member validates and the post-condition answers it judges are configuration (`Config.Traces`, `Config.DB`) with no command-line flag; the fixture harness supplies them and the production driver supplies none, so a deployed member validates no schedule and asks no post-condition question.

### 14.1 Format

One file per run, at `<traces root>/<schedule>/<run>.trace`, where `<schedule>` is the schedule's name and `<run>` is ten zero-padded decimal digits, durable in the same way as a heartbeat sequence: a run reads the folder it is about to write into and takes the highest present plus one, or 1.

A trace is **appended**, not staged and renamed. A start with no finish must be visible, because the failure worth catching is a job that dies part-way through. So the file is JSON Lines, one object per line, each line ending in a line feed, written in this order:

```
{"kind":"trace","version":1,"schedule":"daily","run":123,"started":"YYYY-MM-DDTHH:MM:SSZ"}
{"kind":"task","id":"prune-metrics","completed":true,"count":0}
{"kind":"task","id":"reset-daily-counters","completed":true,"count":null}
{"kind":"task","id":"expire-tokens","completed":false,"count":null}
{"kind":"finish","finished":"YYYY-MM-DDTHH:MM:SSZ"}
```

| Line | Keys |
|---|---|
| first | `kind: "trace"`, `version: 1`, `schedule` (must match the directory), `run` (must match the name), `started` |
| per task, in the order run | `kind: "task"`, `id` (a constant in that job's own code), `completed` (boolean), `count` (integer or `null`) |
| last | `kind: "finish"`, `finished` |

A reader ignores a final line that does not end in a line feed (a job that died mid-line) and treats the file as ending at the last complete line. A first line missing, any complete line that does not parse, or a line after the `finish` line makes the trace malformed, which fails `trace-complete` for that schedule (a job that writes garbage is a job not running correctly; this is a fault, since a trace is written by the work and not by a member of the ring).

**Task identifiers** are constants in each job's code. The fixtures use one name per task, with the argument appended after a colon where a task runs more than once (`rollover:new-day`).

**Periods** are part of the schedule's configuration (`TraceSchedule.Period`).

### 14.2 The four validations

For each schedule `s`, with `now` from the reader's own clock (the trace and the reader are on the same host, so this is the one place a wall-clock comparison is exact):

- **T1 freshness.** Let `latest` be the run with the highest number. If it exists, parses, and `latest.started < now − (PERIOD(s) + TRACE_MARGIN(s))`, `trace-fresh` fails with subject `s`. The margin is set per schedule and is small against the period.

  **Never run yet is not the same as stale.** If there is no run at all, `trace-fresh` fails only once the schedule is overdue, that is, once this deployment has been observed for longer than `PERIOD(s) + TRACE_MARGIN(s)`. Before that the schedule is not due, and nothing is reported. Without this a fresh deployment halts for a day waiting on the daily job and a week waiting on the weekly one, and those two are precisely the schedules that cannot be run once at startup to avoid it.

  **How long the deployment has been observed is measured from `since`**, the record at the observer's store root of when it first ran (section 2), written once and never rewritten; never from the process's uptime, and not from the sequence times the cadence, which is not a duration because cycles are not paced at the cadence. `since` is durable across restarts; uptime is not. The file holds one timestamp of the form 3.1 fixes and one line feed, nothing else; it is written by the member on its first start against a store that holds none (section 7) and re-read before every cycle. A `since` that is absent, unreadable or not of that exact form is reported by `observing-since` (section 15), and on it nothing has been observed and so nothing is due: the clock itself is the failing assertion, not the schedule. Measured by uptime, a schedule that is never scheduled *at all* would be granted a fresh period of grace every time its process bounced and would never be reported, and that is the single case this check exists for. The grace applies only while a schedule has no run whatever; the moment one exists, ordinary staleness governs and the deployment's age stops mattering.
- **T2 completion.** If `latest` is malformed, or has no `finish` line and `now − latest.started > TRACE_DEADLINE(s)`, `trace-complete` fails with subject `s`. The deadline exceeds the job's honest running time and is less than the period. A run within its deadline and unfinished is in progress and produces nothing.
- **T3 coverage.** Let `done` be the most recent run that has a `finish` line and is not malformed. The set of `id`s of its `task` lines with `completed: true` must equal `DECLARED(s)`, the set of task identifiers that schedule declares. Missing, extra, or `completed: false` fails `trace-coverage` with subject `s`. This makes visible a schedule whose declared tasks its code no longer runs.
- **T4 post-conditions.** Independently of any trace, for each task named in the post-condition answers (`Config.DB`, a map from task identifier to a count that must be zero), a non-zero answer fails `postcondition` with subject the task identifier. The member does not run a query; it judges the answer it is given.

### 14.3 The proxy's own trace: what every member judges

ghostunnel's per-connection trace under `gt/` (ringtrace/README.md) is read by every member, not only by the member whose surface a line belongs to. A surface with a single judge is a surface whose judge can stop judging unseen; a trace read by one reader only, and judged for its newest boot only, can be rewritten behind that reader, or written by a second process beside the one it watches, and a boot that ended is never judged again once a newer one appears. The checks below close these, each a constant of every member's own code, each implemented as that member's own copy (no member imports another's; the observers are a trust domain of their own).

- **`surface-disagree`.** Each surface's checks divide into those that need nothing but the trace and the files it names (tunnel: `conn-consistent`, `handshake-verified`, `resumption-verified`, `acl-before-serve`, `lifetime-cap`, `accept-loop`, `handshake-substance`, `acl-substance`; admin: `status-listener-bound`, `pprof-cmdline-redacted`, `shutdown-authorized`, `status-listener-up`; material: `reload-succeeded`, `resumption-bound`) and those that read the owner's host (`material-loaded`, `key-private`, `sandbox-applied`, `cmdline-carries-no-secret`, `proxy-process-alive`), which stay with their owner, as do the tunnel member's expectations (`listener-expected`, `target-expected`, `acl-expected`, `proxy-protocol-expected`: each is that member's own configuration). Every member, `super` included, runs the trace-only checks of every surface it does not own over the current boot, with the tunnel surface's margins set to the tunnel member's own (`-tunnel-lifetime-margin`, `-tunnel-acl-grace`, and `-tick-max-age`, which is one flag with one value on all four, and `-policy-query`, the proxy's `--allow-query`, one value on all four), and compares at the identifier: every identifier of the surface must be in the owner's newest heartbeat's `checks`, and an identifier this member computes as failing must be the `check` of some entry of the owner's `fault`. Either failing fails `surface-disagree` with subject `<owner>:<identifier>`. An owner whose account is not current (verdict `stale` or `retired`, or no heartbeat parsed) is not judged; a fault present that could not be read confirms nothing. A trace this member cannot read is every check of every surface computed failing, which an owner in the same state publishes too. The comparison is one-sided by the cycle's order: the owner's fault is read at step 4 and the trace at step 7, so a condition the owner saw clear has cleared for this member as well; a condition that begins between the two members' cycles is computed here before the owner publishes it, and the halt this raises is the one the owner raises a cycle later. `surface-disagree` is about another member: a halt, never in the fault; listed in `checks` once per owner as `surface-disagree:<owner>`.
- **`trace-consistent`.** A trace is appended and never rewritten, so what a member read of the current boot last cycle must be there, byte for byte, this cycle. Each member keeps in its in-process state, for the boot last read and each segment of it, the length of the prefix of complete lines it read and the SHA-256 of that prefix (a torn tail is not in it). On the next read the same prefix must hash the same: a segment may only grow. The prefix, its length and its growth are of the segment's content by the segment rule of this section, its bytes before the first NUL: a segment the emitter pre-extended keeps a constant file size while its content grows, which is the normal case, and a file size is nowhere compared, remembered or bounded. A changed prefix, a segment shorter than remembered, or a segment of the current boot that is gone fails with the segment as subject (`<boot>/<segment>`), every cycle until the boot changes, which resets the memory. A trace that cannot be read fails it with subject `null` and leaves the memory as it was.
- **`boot-ambiguous`.** The readers judge the highest-numbered boot and nothing else, so a second proxy process live beside the one whose boot is judged is a process nobody watches. Each of the three members that own a surface lists every boot directory, reads each start line's `pid` and asks the operating system whether that process is live (Linux: `<proc>/<pid>` exists, `-proc` naming the process table; Windows: the process opens and reports `STILL_ACTIVE`; any other build fails closed with subject `unsupported-os:<GOOS>` whenever there is a boot at all). Two rules. The highest boot's process must be live: a dead pid there is a proxy that has died or a process table this member cannot read, and either fails, with subject `<boot>:not-live`. Then more than one live pid fails with those boots as subject, comma-separated. A boot whose start line cannot be read counts as live: it cannot be shown dead. A reused pid counts as live; this is a fault, not a compromise. The first rule is what makes a member that cannot see the proxy's process halt rather than pass: under a service manager's `ProtectProc=invisible` every other user's pid reads as absent, and a check that passed on that reading would be blind by construction.
- **`boot-ended`.** The readers judge the highest boot, so the moment a proxy restarts, the boot that just ended leaves every member's view: a process the watchdog aborted mid-connection, a torn last line, a boot with no `shutdown` line at all, leave a tail nobody reads. Every member, `super` included, judges that tail once. **Once** means: in the first cycle in which this member's process reads a current boot other than the one it read the cycle before (the boot `trace-consistent` remembers), the boot it read before becomes **pending**; a pending boot is judged in the first cycle in which it has ended, that is, the current boot read under every rule and the pending boot's newest complete line is older than `-tick-max-age` on the member's clock (a boot whose newest line is younger may still be a second live process writing, which is `boot-ambiguous`'s to report, not this check's), or it holds no line at all, or it cannot be read; it is then forgotten, and this member's process never judges it again, whatever later cycles show. A member that started after the restart never observed the change and judges nothing; the judgement is made by the members that saw the boot end, and by each of them once, so it halts the ring for one cycle set and clears as they publish. The memory is in process, as `trace-consistent`'s is: the pending boots and, while one waits to end, what the last look decoded of it under the SHA-256 of the bytes it was decoded from (every look still reads and hashes every byte, and a byte changed anywhere is decoded afresh), which goes with the judgement; nothing else. What is judged of the ended boot, each a failing assertion with the boot as subject, in this order: `<boot>:unreadable` when the boot directory cannot be read under the rules of ringtrace/README.md 1.4 (the check has not passed); `<boot>:aborted` when it holds no `shutdown` line, a `shutdown` line being how every requested stop is recorded, so its absence is a process that was killed, crashed or was aborted by the watchdog, or one that died before its first line; `<boot>:torn` when its last segment ends in a line without a line feed, a write the process died inside; `<boot>:conn:<id>` for every connection with an `accept` line and no `close` line, whether the boot was aborted or its drain ran out; and, when the boot was aborted, `<boot>:accept-error:<text>` once per distinct error text (cut to 64 bytes on a rune boundary) of the `accept-error` lines within the last `-tick-max-age` before the boot's newest line, the failed accepts that preceded the abort, which `accept-loop` never saw because the boot was gone. Nothing else of the ended boot is judged again: its connections' decisions, its material and its status surface were judged while it was current, and the boot's own `start` line says nothing of its predecessor, so no start line excuses an abort.
- **The substance rules** `handshake-substance` and `acl-substance` (tunnel surface). The rules above hold the proxy to its own account of a connection: a handshake line that says `verified`, an acl line that says `allow` under `allow-cn`. These two hold the account to the bytes, from the chain store and the material store (section 14) and the policy file the start line's `material` names, so that the ring's judgement of the data path does not rest on the proxy's word about its own verification. Both are trace-only rules of the tunnel surface, published by the tunnel member in its heartbeat `checks`, computed by every member for `surface-disagree`, exactly as `accept-loop`; both fail with subject `null` when the trace cannot be read; both name the connection id otherwise. The members do not import the proxy's code: each rule is the members' own mirror of it, held to the original by a differential test.

  - **`handshake-substance`.** For every `handshake` line of the current boot with `verified: true`: it must name a chain (else fail, subject the conn); the chain is read by the reader's rules of section 14 (any refusal fails, subject the conn); it is verified with `x509.Verify`: `Roots` = the CA bundle whose hash the start line's `material` (or the last successful `reload`'s, per kind, in force at the line) records under `ca`, read from the material store `gt/material/` by that hash (section 14) and never from the entry's path, which may have been rotated since and is not read: the bundle in force at a line is the one the proxy hashed for it; its content must hash to the name and hold at least one certificate (else fail: a hash the store lacks, holds only as a `.tmp`, or holds under bytes that do not hash to it, is a handshake this member cannot confirm; a bundle with no path or no hash, the system trust store, cannot be judged and fails); `Intermediates` = the presented chain minus the leaf; `KeyUsages` = `ExtKeyUsageClientAuth`; `CurrentTime` = the line's `at`; no `DNSName`. In pin mode (the rule set is `allow-spki-pin:<algo>:<hex-digest>` entries, as the proxy records its pins) the substance is the leaf's SPKI hash being one of the pins, and chain verification is not required. A failure names the conn. In client mode (`config.mode` `client`) the chain is the server's, verified by crypto/tls against a server name the trace does not carry: not mirrored, fails on every verified handshake. A rule set holding an entry the member cannot read (below) fails on every verified handshake too.
  - **`acl-substance`.** For every `acl` line of the current boot: the `handshake` line of the same conn, wherever it lies, gives the chain (no handshake line: fail, subject the conn; a chain named that cannot be read: fail); the member evaluates the start line's rule set on the leaf itself, exactly as the proxy's verifier does: the chain is verified as above first (in pin mode the pin check stands in for it), and a chain that does not verify is `deny`; `allow-all` allows every verified chain; else the first of `allow-cn` (the subject's common name equal to a value), `allow-ou` (an organizational unit equal to a value), `allow-dns` (a DNS SAN equal to a value), `allow-ip` (an IP SAN equal to a value), `allow-uri` (a URI SAN, serialized, matching a value as a wildcard pattern over `/`-separated segments: `*` one segment, a trailing `**` the rest, a bare `**` anything, a single trailing `/` optional on both sides), in that order, is the rule; else `policy:<hash>` compiles the `.rego` file the material names under `policy` (its hash equal to the rule's and to the file's on disk; else fail), as a Rego v0 module with annotations, queried with the member's `-policy-query` on the input `{"certificate": <the leaf as crypto/x509 parses it>}`, allowed when the result set says so, and is the rule when it allows; else `deny` under `none`. `disable-authentication` alone allows every connection under that rule; a `deny` under `acme-tls/1` on an unverified handshake that presented no chain is the proxy's refusal of a TLS-ALPN-01 challenge probe, agreed as recorded, since the ALPN is not in the trace. The member's decision, and on `allow` the rule, must equal the recorded `decision` and `rule`; a `deny` the member would `allow` fails as much as an `allow` it would `deny`; a rule kind the member cannot evaluate (a client-mode `verify-*` entry or `verify-hostname` on a server, `disable-authentication` beside anything, a pin with an unsupported algorithm or a digest of the wrong length, an address or a pattern that does not parse), a policy that does not compile, errs, times out, or has no query configured, fails the check on every line under the set: a check that cannot run has not passed. Subject the conn.
  - **Memory.** Verdicts are remembered across cycles, in process, emptied when the boot changes, under content hashes and never a size or a modification time: a chain's verification under (chain hash, CA hash) with the window in which every certificate of the verified chain is valid, so a later `at` inside it is judged from memory, and a chain's refusal under (chain hash, CA hash, the recorded second), so a line once refused is refused from memory rather than verified again every cycle; the rules' verdict on a leaf under (chain hash, rule set, the policy hash in force at the line, query), unless the policy consulted the clock or the environment, which is never remembered; the hash in that key is the material's at the line being judged, the start line's or the last successful reload's, never the start line's alone, so a reload that brings another policy starts a fresh memory for every chain and a verdict reached under the replaced policy answers for no line after it; a policy's compilation under (policy hash, query). Every chain file a line names, every CA bundle in force (from the material store, by the recorded hash, remembered within the cycle under that hash and never under a path, so two entries recording different hashes at one path never answer for each other) and every policy file in force is read and hashed once per cycle, which is what makes the keys content.

- **`proxy-process-alive`** (admin). The start line names a pid, and a pid is reused. The process by that number exists, and its start time as the operating system records it (Linux: `/proc/<pid>/stat` field 22 in USER_HZ ticks over `btime` from `/proc/stat`; Windows: the creation time of `GetProcessTimes`) is not after the start line's `at` by more than 2 s (the precisions involved) and not more than 120 s before it. Subjects: `pid:<pid>` (gone), `pid:<pid>:started-after`, `pid:<pid>:started-before`, `pid:<pid>:unreadable`, `pid:<pid>:access-denied`, `unsupported-os:<GOOS>`. Every read failure fails closed.

---

## 15. Standard check identifiers

Local check identifiers are constants in each observer's own code and this document does not name them all. Structural checks must be spelled the same by every implementation, because every implementation's fault files and halts are read by every other, and the fixtures judge them by name.

| Identifier | Subject | Section |
|---|---|---|
| `store-readable` | member | V1 |
| `member-present` | member | V2 |
| `member-fresh` | member | V4, V4b, V6 |
| `copy-readable` | author | K1 |
| `copy-current` | author | K6, K7 |
| `staging-fresh` | path, relative to `/stores/`, written `<store>/<path>` | C3, K2, H4 |
| `halts-readable` | `null` | H1 |
| `own-store-writable` | `null`; `re-read` when the last publish's re-read differed | 5, 13 step 3 |
| `own-store-private` | path, `<store>/<path>`, with `:writable` for own `halts/`; `tree`, `unsupported`, `unsupported:acceptance-not-this-os`, `stale-acceptance`, `unprobed` | 13 step 3 |
| `surface-disagree` | `<owner>:<identifier>`; listed in `checks` as `surface-disagree:<owner>` | 14.3 |
| `trace-consistent` | segment, `<boot>/<segment>`; `null` when the trace cannot be read | 14.3 |
| `trace-readable` | the path relative to `gt/` where reading stopped, with the line when there is one; `gt` for the root itself | 14 |
| `tick-fresh` | the reference line's `at` as the trace writes it (`YYYY-MM-DDTHH:MM:SSZ`): the newest `tick` of the current boot, or the start line before the first tick, when it is more than `-tick-max-age` from the member's clock; `null` when the trace cannot be read or the current boot has no start line | 14.3 |
| `accept-loop` (tunnel surface; every member computes it, the tunnel member publishes it) | the `accept-error` line's `error` text, cut to 64 bytes on a rune boundary, once per distinct text, for every such line of the current boot within the last `-tick-max-age`; `null` when the trace cannot be read | 14.3 |
| `listener-expected` (tunnel only; listed only when `-expect-listen` is set) | the start line's `listen` when it is not, exactly, the expected listener; `null` when the trace cannot be read | 14.3 |
| `target-expected` (tunnel only; listed only when `-expect-target` is set) | the start line's `target` when it is not, exactly, the expected backend target; `null` when the trace cannot be read | 14.3 |
| `acl-expected` (tunnel only; listed only when `-expect-acl` is set) | the start line's `acl` joined by commas, cut to 256 bytes on a rune boundary, when it is not, as a set, the expected rules; `null` when the trace cannot be read | 14.3 |
| `proxy-protocol-expected` (tunnel only; always listed) | the start line's `proxy_protocol` (`off`, `conn`, `tls`, `tls-full`: what the backend is handed ahead of each connection) when it is not the expected mode, which is `off` when `-expect-proxy-protocol` is empty; a value outside the set is refused at start; `null` when the trace cannot be read | 14.3 |
| `key-private` (material only) | the first that applies of `no-path` (the key entry names no file); `unsupported-os:<GOOS>` (a build without POSIX ownership); `identity` (the member's own ids cannot be read); `stat` (the path cannot be `lstat`ed); `not-regular` (a link, a directory); `mode:<octal>` (the twelve permission bits, four digits, when any bit outside owner read and write and group read is set); `readable-by-observer` (the file is the member's own, or group-readable by a group the member holds); `none` when the material in force names no key; `null` when the trace cannot be read | 14.3 |
| `handshake-substance` (tunnel surface; every member computes it, the tunnel member publishes it) | the connection id of a `handshake` line recorded as verified whose chain this member cannot read, or cannot verify against the CA bundle in force at the line's `at` (or, in pin mode, whose leaf's key is not pinned); `null` when the trace cannot be read | 14, 14.3 |
| `acl-substance` (tunnel surface; every member computes it, the tunnel member publishes it) | the connection id of an `acl` line whose recorded decision, or on allow whose recorded rule, is not what the start line's rule set gives this member on the connection's chain, or whose rule set this member cannot evaluate; `null` when the trace cannot be read | 14, 14.3 |
| `boot-ambiguous` | `<boot>:not-live` for the highest boot; the live boots, comma-separated; `unsupported-os:<GOOS>` | 14.3 |
| `boot-ended` (all four members, each on its own, once per ended boot per member process) | `<boot>:unreadable`, `<boot>:aborted`, `<boot>:torn`, `<boot>:conn:<id>`, `<boot>:accept-error:<text>` (the text cut to 64 bytes on a rune boundary), the boot being the one that ended | 14.3 |
| `status-listener-up` (admin surface; every member computes it, the admin member publishes it) | the `error` text of a `refusal` line of the current boot whose `source` is `status-listener`, cut to 64 bytes on a rune boundary, once per distinct text; `null` when the trace cannot be read | 14.3 |
| `proxy-process-alive` | `pid:<pid>`, `pid:<pid>:<why>`, `unsupported-os:<GOOS>` | 14.3 |
| `cycle-within-cadence` | `null` | 13 step 7b |
| `observing-since` | `null` | 7, 14.2 |
| `trace-fresh`, `trace-complete`, `trace-coverage` | schedule | 14.2 |
| `postcondition` | task identifier | 14.2 |
| `I1`…`I7` | member, or path for `I5`/`I6` | 11.1 |
| `I8` | the entry's path, `<store>/halts/<w>` or `<store>/halts/<w>.tmp`, then `:owner:<uid>` (the uid found), `:unmapped`, `:no-account:<name>`, `:unprobed` or `:unsupported-os:<GOOS>` | 10.2 H7, 11.1 |
| `S1`…`S5` | path, relative to `/stores/`, written `<store>/<path>` | 11.2 |

In `checks` a structural check that was run against several subjects is listed once per subject as `<identifier>:<subject>` (`member-fresh:admin`), so that the set says what was checked and not only what kind of check exists. `I`- and `S`-rules are listed once, without a subject, since they are evaluated everywhere.

---

## 16. Reserved

This section is intentionally empty; the number is kept so that later sections keep theirs.

---

## 17. Choices made here

Every mechanical decision this document took, one line each.

1. Identities: `tunnel`, `admin`, `material`, `super`; ASCII order is the tie-break order everywhere.
2. Store roots at `/stores/<identity>/`; membership declared by `-members`, never discovered from the directory listing.
3. Heartbeat file name: ten zero-padded decimal digits plus `.hb`; sequence starts at 1; maximum `9999999999`.
4. Staging name: final name plus `.tmp`, in the same directory; a writer reuses its own stale staging file.
5. Encoding: one JSON object per file, UTF-8, no BOM, trailing line feed written and tolerated.
6. Marker: the file begins with the exact bytes `{"kind":"<kind>",`; classification by prefix before parsing.
7. Strict key sets; unknown keys, missing keys, wrong types, `version ≠ 1` are all malformed (`S5`).
8. Timestamps: `YYYY-MM-DDTHH:MM:SSZ`, UTC, whole seconds.
9. Hash: SHA-256, lower-case hex, over the whole file's bytes as published, re-read after rename.
10. Heartbeat keys: `kind, version, observer, sequence, timestamp, cadence_seconds, checks, check_count, observed, previous, boot, stop`.
11. `observed` keys are exactly the other declared members; `null` for a member with no hashable current heartbeat.
12. `previous` is `null` on sequence 1 only.
13. Boot record: `{"started", "resumed_from"}` on the first heartbeat of every process start; `resumed_from` is the highest sequence found or `null`.
14. Durable sequence with a continued chain across restarts; a restart never resets numbering or breaks a link.
15. Clean stop: `stop: true` on a final heartbeat; the next entry after a stop must carry a boot record.
16. Fault keys: `kind, version, observer, failing[{check, subject}]`, the failing set sorted; written on change of the failing set, not every cycle.
17. Halt keys: `kind, version, observer, reason, subject, sequence, when, detail`; names one reason, the first in evaluation order.
18. Presence is the signal for both `fault` and `halt`; a file that does not parse is still in force and is additionally `S5`.
19. `halts/` entries named by writer identity; a writer's slot holds its own halt or the first halt it found; never overwritten.
20. Relay copies the found halt's bytes verbatim, preserving the finder's name.
21. The folder may hold `WINDOW + 1` entries (publish, copy, then prune); every entry present is part of the chain.
22. Copy directory shape: exactly `heartbeat/`, `fault`, `fault.tmp`; `heartbeat/` inside a copy is the one permitted subdirectory.
23. Copies are read before their originals; an entry ahead of the original is `I7` after one fresh listing of the original.
24. Fault copy comparison: wrong author is `I7`; any other disagreement is `copy-current`.
25. Verdict priority: absent, retired, stale, faulted, unknown, alive; procedure V fixes the order.
26. Staleness is a duration on the reader's own clock, accumulated in process; `STALE_AFTER(A) = A.cadence_seconds * (1 + STALE_SLACK)`.
27. A restarted reader has no basis: first-cycle verdicts are `unknown`/`absent`; `I1` and `I4` are not evaluated on that cycle.
28. Memory is rebuilt from the own store on start (trust on boot).
29. `I1(b)` is evaluated only over accounts from members whose verdict is `alive` or `faulted`.
30. A retired member, whichever it is, fails `member-fresh`.
31. Shape rules identified `S1` to `S5`; a file is classified by its prefix before it is parsed, so `I6` takes precedence over `S1` and `S5` for heartbeat-marked strays.
32. Staging-file age is judged by modification time against the reader's clock (same host).
33. Cycle order fixed as section 13; the halt names the first failing assertion in that order.
34. Overrun (`cycle-within-cadence`) is judged over the cycle's work, before publication, in the cycle that overran.
35. Clear-condition for members: no `fault` at any store root, the coordinator's `halt` absent, own assertions pass; for the coordinator: the first and third.
36. Removal order on clearing is the reverse of the raising order.
37. Schedule trace format: JSON Lines at `<traces root>/<schedule>/<run>.trace`, appended, not staged; unterminated last line ignored.
38. Schedule trace task identifiers in fixtures: one name per task, with `:<argument>` where a task runs more than once.
39. Structural check identifiers and their subjects as section 15; per-subject listing as `<id>:<subject>` in `checks`.
40. Fixture manifest format, as `testdata/FIXTURES.md` describes.
41. `since`: one timestamp and one line feed, written once on the first start against a store without one, re-read before every cycle.

---

## 18. Values to be set

Everything this document did not decide. Each is set by the deployment, with the constraint on it and the flag that carries it.

| Value | Flag | Where used | Constraint |
|---|---|---|---|
| `cadence_seconds`, per observer | `-cadence` (seconds, at least 1) | 3.2, 13 | the whole cycle's work must fit inside it, including every read and comparison; the coordinator does the most work; all four must be close enough that no member falls more than `WINDOW − 1` peer cycles behind, because the window binds the cadences together |
| `STALE_SLACK` | `-stale-slack` | 8 | ≥ 0 |
| `STAGING_STALE_AFTER_SECONDS` | `-staging-stale-after` | C3, K2, H4 | must exceed the writer's cadence, since no honest writer holds a staging file across a cycle |
| `MAX_HEARTBEAT_BYTES`, `MAX_FAULT_BYTES`, `MAX_HALT_BYTES` | `-max-heartbeat-bytes`, `-max-fault-bytes`, `-max-halt-bytes` | 3.1, C4, K2, H5 | each must exceed the largest file an honest implementation writes |
| `HEARTBEAT_MAX_AGE_SECONDS` | `-heartbeat-max-age` | V4b | no default; refused unless it exceeds the member's own cadence; must exceed every member's cadence with margin (`deploy/README.md`, "The cadence contract") |
| `WINDOW` | `-window` | 6 | 4 |
| `MIN_CYCLE` | `-min-cycle` | 13 step 12 | the floor under a cycle; the same on every member |
| the account each member runs as, by member | `-slot-owners` | 10.2 H7 | the deployment's own account names, the same mapping on every member, every declared member named; the accounts must exist on the host, since a name that does not resolve fails the clause |
| the deployment's tree | `-tree` | 13 step 3 | the same file `setup-tree.sh` built the tree from |
| the tick tolerance | `-tick-max-age` | 14.3 | one value on all four members; above the proxy's `--ring-tick` with margin |
| the tunnel surface's margins | `-lifetime-margin`, `-acl-grace` on the tunnel member; `-tunnel-lifetime-margin`, `-tunnel-acl-grace` on the other three | 14.3 | the same values on all four |
| the policy query | `-policy-query` | 14.3 | the proxy's `--allow-query`, one value on all four; empty means a policy rule cannot be re-judged |
| the expectations of the tunnel member | `-expect-listen`, `-expect-target`, `-expect-acl`, `-expect-proxy-protocol` | 14.3, 15 | from a record of what the deployment is meant to be, never from the proxy's own configuration (`deploy/README.md`, "Two files, two sources") |
| the gate's window | `--ring-heartbeat-max-age` on ghostunnel | 19 | no default; must exceed the coordinator's cadence |
| `TRACE_MARGIN(s)`, `TRACE_DEADLINE(s)`, `DECLARED(s)`, per schedule; the post-condition answers | `Config.Traces`, `Config.DB` (no flag; the fixture harness) | 14.2 | the margin small against the period; the deadline above the job's honest running time and below the period |

---

## 19. The gate: what the proxy reads before it serves

Everything above describes observers reading each other. This section describes the one other reader of the store tree: the proxy. Its reader (`ringtrace/gate.go`, `ringtrace/gatestate.go`, and `ring.go` in the proxy) is a second, independent implementation of a reading this document specifies, written without sharing a line of the members' code, and the two have to agree about bytes. `ringtrace/README.md` section 3 gives the same rules from the proxy's side.

### 19.1 The rule

**The proxy reads the whole store tree before it serves a connection: every member's store for a halt, a fault or a delivered halt, and the coordinator's heartbeat for liveness. If any read fails, anything has halted, or the coordinator's heartbeat is not current, the connection is refused.**

It is continuous, not a check at start. The gate is consulted on every accept, and its standing decision is re-evaluated on every change the operating system reports on the tree and, regardless of events, by a full scan every second (`ringWatchInterval`), which also closes every connection in flight when the answer is a refusal. A decision is reused by the accepts that follow it only while no change has been reported since the scan that made it, it is younger than the watch interval (or than 10 ms when no change notification is running), and, for a serve decision, the heartbeat it rests on is still within the window by the gate's clock. The proxy also refuses, before the gate is asked, on its own sticky conditions: a trace that can no longer be written, a reload that failed, a status listener that died (`ringtrace/README.md`, `reload`, `refusal`).

### 19.2 What it reads

In this order, refusing on the first failure:

1. **Its configuration.** A window that is not set, a size bound that is not set, no clock, no members, or a coordinator that is not a member: refused.
2. **The root** (`--ring-stores`). Cannot be stat'ed, or is not a directory: refused.
3. **Has anything halted?** For every declared member in identity order: the store directory missing or not a directory; a regular file `halt` at its root; a regular file `fault` at its root; anything else at either name; `halts/` unlistable; any entry in `halts/` other than a regular file whose name ends in `.tmp`. A regular non-`.tmp` file in `halts/` is a delivered halt in force whatever its content or size. Presence is the answer; no content is read.

   The fault is read as well as the halt, which section 12 does not require of a member. It is strictly earlier (a member writes its own fault in the cycle one of its own assertions fails, and the halt that follows takes another member a cycle to find and write), and it cannot make a halt unrecoverable, because the clear-condition is already *no store holds a fault*, so whatever lifts the halt has lifted this first.
4. **Is the coordinator alive?** Its newest heartbeat by name, read within the size bound, parsed strictly under 3.2, and its `timestamp` judged against the window (`--ring-heartbeat-max-age`) in both directions. Section 19.3 lists what fails.

Only when every read above succeeded and found nothing does it serve. The gate has one window and one clock: its own host's, which is the coordinator's host too.

### 19.3 What is not a heartbeat

**Everything that is not a well-formed, current heartbeat of the coordinator's own is a stop.** The list is exhaustive rather than illustrative:

- the heartbeat folder cannot be listed, or holds no `<seq>.hb`
- a staging name (`<seq>.hb.tmp`) is present and no published heartbeat is: a publication that has not finished is not a heartbeat
- the folder holds any entry that is not a regular `<seq>.hb` or `<seq>.hb.tmp`
- the file is larger than the size bound, checked before it is read (3.1)
- the first bytes are not the heartbeat marker (3.1)
- it does not parse, or `version` is not `1`
- `observer` is not the coordinator
- `sequence` is not the number in the file's name
- `timestamp` is not of the form 3.1 fixes
- `check_count` is not the length of `checks`; `observed` does not hold exactly the other members with hash-or-null values; `previous` is not a hash (null only on sequence 1); `boot` is neither null nor `{started, resumed_from}`; `stop` is not a boolean
- the timestamp is older than the window, **or newer than the window**: a clock that disagrees disagrees whichever way it runs, and a future timestamp that held the gate open indefinitely would be the same hole
- `stop` is `true`: a deliberate retirement is still nothing watching this host
- any member's store root is missing, or its `halts/` cannot be listed

### 19.4 What the gate is not

**It writes nothing and it repairs nothing.** The tree is read-only in the proxy's namespace and its sandbox (`deploy/README.md`, "Landlock and the ring").

**It loads nothing.** Not the proxy's configuration, not any observer's code. A proxy whose backend is unreachable must still be able to find out that it has been told to stop.

**It binds honest code only.** The proxy checks because it is written to check; a proxy that has been rewritten not to look carries on, and nothing inside the process can prevent that. What the ring holds against such a proxy is the trace: a proxy that serves while the gate refuses serves connections whose lines every member re-verifies (14.3), and a proxy whose trace stops is one every member reports (`tick-fresh`).

### 19.5 Nothing is prevented from starting; everything is prevented from serving

An observer asserts that the proxy on its host is running: the process is there (`proxy-process-alive`), the trace is ticking (`tick-fresh`), the accept loop is accepting (`accept-loop`). Those are the owner's own assertions, so a failure is a fault, and a fault stops the serving. If the coupling also stopped the proxy from *starting*, the two would lock:

```
the proxy is prevented from starting, because something has halted
something has halted, because the proxy is not running
```

Both statements true, no sequence of events clears it, and a transient condition becomes permanent. The rule that resolves it is not an exemption and not a softened check. **The proxy starts, and refuses visibly.**

- A halted status surface still answers; every request is answered `503` with the reason.
- A halted proxy still binds its listener and still accepts; every connection is refused unserved, its `accept` and its `close` with reason `halt` recorded together.
- The trace keeps ticking, so `tick-fresh` holds, and the process stays alive, so `proxy-process-alive` holds.

Every *is the proxy there* assertion is therefore satisfied by a refusing proxy, every *is the proxy serving* assertion is answered honestly, and no assertion depends on a condition the coupling itself prevents. The proxy's watchdog health (`deploy/README.md`, "Health and the watchdog") is judged on the same principle: a gate refusal is not unhealthy, because restarting into a halt changes nothing.

### 19.6 Reserved

This section is intentionally empty; the number is kept so that later sections keep theirs.

### 19.7 Reserved

This section is intentionally empty; the number is kept so that later sections keep theirs.

### 19.8 What the gate rests on

A file is evidence only if the thing being judged cannot write it. The deployment runs the proxy and each observer as different users, and the store tree is read-only to the proxy by mode and by its unit's namespace (`deploy/README.md`), so the proxy can write none of what the gate reads.

Of the gate's reads, two turn a no into a yes, and between them they cover both directions:

| | |
|---|---|
| `<member>/halts/`, for every member | where every *other* member relays what it found. It is the **positive signal**, and it arrives for anything any member detects, including a member dying, which its peers report. |
| `super/heartbeat/` | writable by the coordinator alone, so its staleness cannot be concealed. It is the **absence**: an observer that dies stops writing, and what the proxy needs expires on its own without anybody having to notice or deliver anything. |

**Permission requires both of these to have been read and found clean.** A path that is missing, unreadable or stale is a stop rather than a question skipped, or deleting the evidence would be as good as satisfying it.

The gate reads the rest of the tree as well (`halt`, `fault`), and that is deliberate. The question it answers is *may I serve*, so a read the proxy could tamper with could only ever turn a yes into a no. What turns a no into a yes is the table above.

### 19.9 Reserved

This section is intentionally empty; the number is kept so that later sections keep theirs.

---

## 20. What the ring cannot establish

Every mechanism in this specification is a deployment checking itself, and that has an edge: a fact that needs an authority outside the deployment is out of reach. Four things sit outside it. Which build was the intended build: a member compares what the proxy loaded against what is on disk, which cannot tell a tampered build from an intended one; that needs provenance from the build. The host: every member runs on one host under one kernel and one service manager, and whoever holds the host holds every member at once. That a member is legitimate: membership is a declared constant, which stops a missing member reading as a healthy ring, but nothing enrols a member or establishes that a store bearing a member's name was meant to be that member. Its own code: every check binds code that is written to check, and a process rewritten not to check carries on; the trace and the members' re-verification bound what such a process can do unseen, and nothing removes the rest from inside the thing being judged.
