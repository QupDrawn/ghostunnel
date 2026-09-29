# ringtrace: ghostunnel's half of the observer ring

Three things, one package, stdlib only, nothing shared with `observers/`:

- **Emitter** appends the trace ghostunnel leaves under `gt/`.
- **Read** is the reference reader of that trace. The observers' localchecks
  mirror it from this document, never by importing it.
- **Gate** is what ghostunnel calls on every accept before serving (SPEC §19).

Everything below is exact. A reader that tolerates something this document
does not will disagree with one that does not, and in this ring a
disagreement is a halt.

## 1. The trace

### 1.1 Lines

The trace is JSON Lines: one JSON object per line, each line ending in exactly
one line feed (`0x0A`), no carriage return, UTF-8, no byte-order mark. A line
including its line feed is at most **65536 bytes** (`MaxLineBytes`); the
emitter refuses to write a longer one and a reader treats a longer complete
line as malformed.

**The marker is the first key.** Every line begins with exactly

```
{"kind":"<kind>","version":1,"sequence":
```

with no whitespace before or within that prefix. A reader classifies a line
by its prefix before parsing it (`ClassifyLine`); a line that does not begin
with `{"kind":"<kind>",` for one of the ten kinds is malformed. The
remainder of the line is any valid JSON. The marker includes the closing
quote and comma, so `accept` never matches an `accept-error` line.

**Strict keys.** Every kind has an exact key set, in the order written below.
A key missing, a key added, a key of the wrong type, a `null` where the type
is not nullable, a duplicate key, or bytes after the object make the line
malformed. Nested objects (`config`, `material[]`, `peer`) are strict the
same way. Readers do not tolerate unknown keys.

**Header.** Every kind carries these four keys first:

| Key | Type | Meaning |
|---|---|---|
| `kind` | one of `start`, `accept`, `handshake`, `acl`, `close`, `reload`, `shutdown`, `tick`, `accept-error`, `refusal` | the marker |
| `version` | integer `1` | any other value is malformed |
| `sequence` | integer ≥ 1 | per-process, starting at 1 on the `start` line, increasing by exactly 1 per line, never reused |
| `at` | string `YYYY-MM-DDTHH:MM:SSZ` | UTC, whole seconds, exactly this form (a valid RFC 3339 timestamp). Never earlier than the previous line's `at` |

**Enumerations are closed.** A value outside the set listed for a field is
malformed. Integers are JSON integers (`3`, never `3.0` or `"3"`). Hashes are
SHA-256, 64 lower-case hexadecimal characters.

**No secrets.** No line ever carries key material, a `--storepass` or
`--pkcs11-pin` value, or the process command line. The `key` material entry
never carries a hash. Any string field containing `-----BEGIN` (a PEM header)
is refused by the emitter and malformed to the reader.

### 1.2 The kinds

**`start`**: the first line of every boot, `sequence` 1. What this process
serves.

| Key | Type | Meaning |
|---|---|---|
| `boot` | integer ≥ 1 | the boot number; must equal the number of the directory the line is in |
| `pid` | integer ≥ 1 | the process id |
| `config` | object | exactly the keys below |

`config`:

| Key | Type | Meaning |
|---|---|---|
| `mode` | `"server"` or `"client"` | ghostunnel's mode |
| `listen` | non-empty string | the tunnel listener address |
| `target` | non-empty string | the backend dial target |
| `proxy_protocol` | `"off"`, `"conn"`, `"tls"` or `"tls-full"` | the PROXY protocol v2 header the backend receives ahead of each connection's bytes (below) |
| `status_listen` | string or `null` | the status/admin listener address, `null` when none |
| `status_client_cert` | boolean | the status listener requires a client certificate |
| `pprof_cmdline_redacted` | boolean | `/debug/pprof/cmdline`, when served, redacts every argument value |
| `shutdown_requires_client_cert` | boolean | `/_shutdown`, when served, acts only for a caller with a verified client certificate |
| `session_tickets` | boolean | TLS session resumption (tickets) is enabled |
| `verify_on_resume` | boolean | client-certificate verification is re-run on a resumed session |
| `acl` | non-empty array of strings | the rule in force: exactly what the verifier applies, in the closed vocabulary below, sorted (byte order), no duplicates |
| `lifetime_cap_seconds` | integer ≥ 0 | the per-connection lifetime cap; `0` means none |
| `sandbox_state` | `"applied"`, `"unsupported"`, `"disabled"`, `"failed"` or `"skipped"` | the outcome of the process sandbox attempt at startup (below) |
| `sandbox_accepted` | non-empty string or `null` | the OS an operator named with `--accept-no-sandbox`, else `null` |
| `material` | array (may be empty, never `null`) of material objects | the trust material as loaded |
| `binary` | object: `path`, non-empty string; `sha256`, hash | the executable this process started from (below) |

`proxy_protocol` is what the backend is handed ahead of every connection's
bytes, and so, with `target`, what the backend receives: `off`, nothing
(no `--proxy-protocol` and no `--proxy-protocol-mode`); `conn`, a PROXY
protocol v2 header carrying the connection's addresses (`--proxy-protocol`,
or `--proxy-protocol-mode=conn`); `tls`, that header with the TLS version,
ALPN and SNI (`--proxy-protocol-mode=tls`); `tls-full`, all of that and the
client's certificate, its common name and its whole DER encoding
(`--proxy-protocol-mode=tls-full`). Client mode dials the backend with no
header and always writes `off`. The set is closed (`ProxyProtocols`); a
reader that finds a start line without the key, or with a value outside
the set, has a malformed line, not a mode of `off`.

`sandbox_state` is what became of ghostunnel's attempt to apply the
platform's process sandbox at startup; the attempt is made on every
platform, and landlock is the facility on Linux. `applied`: the sandbox was
applied and the kernel enforces it. `unsupported`: this build has no sandbox
facility at all (every non-Linux build), so there was nothing to
attempt. `disabled`: the operator turned it off (`--disable-landlock`).
`failed`: the facility exists but the attempt errored, or the kernel does
not enforce it, so nothing was restricted; the process runs and the line
says so. `skipped`: PKCS#11 is in use, and landlock is not applied
alongside it.

`sandbox_accepted` is the operator's explicit statement that the platform
has no sandbox, given as `--accept-no-sandbox=<os>` where `<os>` must equal
the OS the build runs on as Go names it (`windows`, `darwin`, ...).
ghostunnel refuses to start on a build whose state is `unsupported` without
it, refuses a value that is not its own OS, and refuses the flag outright on
any build whose state is anything other than `unsupported`, because there
the facility exists and there is nothing outside the process to accept; so
in a trace ghostunnel wrote, `sandbox_accepted` is non-null only with
`sandbox_state: "unsupported"`. The format itself constrains only the two
fields' shapes; a reader that wants the cross-field rule checks it.

`acl` is the rule the verifier applies, as non-secret strings. The
vocabulary is closed (`ACLTokens`, `ACLPrefixes`): a reader classifies an
entry by exact match on a bare token or by prefix, and anything else is
malformed. Bare tokens: `allow-all`, `verify-hostname`,
`disable-authentication`. Prefixed entries, whose remainder is the rule's
value and is never empty: `allow-cn:<value>`, `allow-ou:<value>`,
`allow-dns:<value>`, `allow-ip:<value>`, `allow-uri:<pattern>`,
`allow-spki-pin:<algo>:<hex-digest>`, and their client-mode forms
`verify-cn:`, `verify-ou:`, `verify-dns:`, `verify-ip:`, `verify-uri:`,
`verify-spki-pin:`; and `policy:<hash>`, where the value is the SHA-256 of
the policy file (the same hash as the `policy` material). The array is sorted
in byte order and holds no duplicates; an unsorted or repeated entry is
malformed. It is never empty, because ghostunnel never serves under no rule.

What ghostunnel writes. Server mode: `disable-authentication` alone when no
client certificate is requested; otherwise every `--allow-spki-pin` in pin
mode (nothing else applies there); otherwise `allow-all`, or one entry per
`--allow-cn` / `--allow-ou` / `--allow-dns` / `--allow-ip` / `--allow-uri`
value plus `policy:<hash>` when an OPA policy is evaluated. Client mode:
every `--verify-spki-pin` in pin mode (crypto/tls then verifies neither the
chain nor the hostname); otherwise `verify-hostname`, because crypto/tls
verifies the server name on every dial, plus one entry per `--verify-*`
value and `policy:<hash>` when an OPA policy is evaluated; a client that
verifies by hostname alone must be started with `--verify-hostname-only`
and its `acl` is exactly `["verify-hostname"]`. In client mode
`disable-authentication` is added when no client certificate is presented.
An `--allow-uri` / `--verify-uri` entry carries the pattern as given on the
command line, not its compiled form.

A material object, used here and in `reload`:

| Key | Type | Meaning |
|---|---|---|
| `material` | `"cert"`, `"key"`, `"ca"` or `"policy"` | |
| `path` | string | the path on disk; may be empty when the material has no file |
| `sha256` | hash or `null` | SHA-256 of the file as loaded; **always `null` for `key`** |

ghostunnel lists `cert`, `key` and `ca` always and `policy` when an OPA
policy is configured. A `--keystore` holds the key, so it appears as both
`cert` and `key`, both without a hash; a `--cacert` of `""` is the system
trust store, listed with an empty path; a keychain, PKCS#11, SPIFFE or ACME
source has no file and is listed with an empty path.

`binary` names the file this process was executed from and its hash.
`path` is `os.Executable()` with every symbolic link resolved. `sha256` is
the SHA-256 of the executed file's bytes, read once at startup, before the
process sandbox applies; on Linux the bytes are read through
`/proc/self/exe`, so a path replaced after the exec does not change them.
ghostunnel refuses to start when it cannot resolve or read its own
executable. The key is required: a `start` line without it, or with an
empty `path` or a `sha256` that is not a hash, is malformed.

**`accept`**: a connection was accepted on the tunnel listener.

| Key | Type | Meaning |
|---|---|---|
| `conn` | integer ≥ 1 | the connection id, unique within the boot |
| `listener` | non-empty string | the listener address |
| `remote` | non-empty string | the peer address |

What ghostunnel writes. The `accept` line is written in the same batch as
the connection's `handshake` and `acl` lines, first, once the handshake has
finished and before the proxy dials the backend: one write under one
`fsync` (§2), so the file reads `accept`, `handshake`, `acl` consecutively
and all three are durable before any byte is forwarded, and the connection
pays one `fsync` on its critical path. A handshake that
fails gets its `accept` and its `handshake` (`refused`) together, then its
`close`. An `accept` the gate refuses (§3) writes `accept` and `close` with
reason `halt` together, no `handshake`. A connection nothing else was
recorded about (in client mode, a dial that never reached TLS) writes its
`accept` with its `close`. So every connection's lines begin with its
`accept`, in the order `accept`, `handshake`, `acl`, `close`. **The bound
this accepts:** a crash during a handshake leaves no `accept` line for that
connection; no plaintext flowed, and the process's death is seen by every
member within a cadence (the ticks stop). A batch that cannot be
written is the emitter's sticky failure: serving is refused from then on
and the connection whose batch failed is closed by ghostunnel at once.

**`handshake`**: the TLS handshake on a connection finished.

| Key | Type | Meaning |
|---|---|---|
| `conn` | integer ≥ 1 | the connection |
| `outcome` | `"ok"` or `"refused"` | |
| `resumed` | boolean | the session was resumed |
| `verified` | boolean | client-certificate chain verification **completed on this handshake** (not carried over from the session it resumed) |
| `protocol` | string | the negotiated protocol version as Go names it, e.g. `TLS 1.3`; empty when none was negotiated |
| `peer` | object or `null` | the client's identity when a certificate was presented, else `null` |
| `error` | string or `null` | the error on a refused handshake, else `null` |
| `chain` | hash; **optional** | the chain the peer presented, by name in the chain store (§1.5): the SHA-256 of the presented certificates' DER concatenated in presented order, which is the file `gt/chains/<chain>.der`. Present when at least one certificate was presented; **absent** otherwise (never `null`, never empty) |

`chain` is the one optional key of the format (`OptionalKeys`): a
`handshake` line without it is well-formed and means no chain was presented;
one with it must carry a hash. A `chain` on any other kind is an unknown
key. ghostunnel writes `chain` exactly when it writes a non-null `peer`, on
a full or a resumed handshake alike (on a resumed handshake the presented
chain is the stored session's, `PeerCertificates`, which is what the ACL
re-verified) and on a refused handshake whose peer presented a chain before
the refusal. The format itself constrains only the field's shape; a reader
that wants the cross-field rule (`chain` present exactly when `peer` is
non-null) checks it. The chain file is durable before the line that names it
is written (§1.5), so a durable `handshake` line never names an absent chain.

`peer`:

| Key | Type | Meaning |
|---|---|---|
| `subject` | string | the leaf subject, RFC 2253 form |
| `issuer` | string | the leaf issuer |
| `serial` | string | the leaf serial, hexadecimal |
| `sans` | array of strings (may be empty, never `null`) | each `dns:`, `uri:`, `ip:` or `email:` followed by the value |
| `fingerprint` | hash | SHA-256 of the leaf certificate DER |

The tunnel observer's reading: every `accept` on the tunnel listener is
followed by a `handshake` for the same `conn`; a served connection (one with
an `acl` `allow`) has `outcome` `ok` and `verified` `true`; a `handshake`
with `resumed` `true` and `verified` `false` is a violation unless the boot's
`config.session_tickets` is `false`.

What ghostunnel writes. In server mode the line is the tunnel listener's
handshake; `verified` is `true` exactly when a peer certificate verifier is
installed and the handshake completed, since Go runs the verifier on a full
handshake and the resumption hook runs it again on a resumed one. With
`--disable-authentication` no verifier is installed and `verified` is
`false` on every line. A TLS-ALPN-01 challenge probe completes its handshake
with no certificate asked for: `verified` `false`, then an `acl` `deny`
under rule `acme-tls/1`. In client mode the listener is plaintext and the
line describes the TLS handshake to the target, made by the dialer: `peer`
is the server's certificate and `verified` is `true` when that handshake
completed (crypto/tls, the pin or the `--verify-*` rules verified it); a
dial that never reached TLS writes no `handshake` line, only a `close` with
reason `error`. On a refused handshake `peer` is filled when a certificate
was presented before the refusal.

**`acl`**: an access-control decision on a connection.

| Key | Type | Meaning |
|---|---|---|
| `conn` | integer ≥ 1 | the connection |
| `decision` | `"allow"` or `"deny"` | |
| `rule` | non-empty string | the rule that decided: a flag name such as `allow-all`, `allow-cn`, `allow-ou`, `allow-dns`, `allow-uri`, `policy` (OPA), or `none` when no rule matched |
| `reason` | string | free text for people |

What ghostunnel writes. The verifier is what decides on the server, inside
the handshake, so the `acl` line follows the `handshake` line: `allow` when
the handshake completed, `deny` under `none` with the error as `reason` when
it was refused over the peer's certificate (the verifier's `unauthorized`
error, a chain that did not verify, a certificate required and not
presented). A handshake that failed before any certificate was judged (a
timeout, a protocol error, a peer that hung up) has no `acl` line. On
`allow`, `rule` is the flag the verifier stopped at, found by
`auth.ACL.ServerRule` (or `ClientRule` in client mode), which walks the
same checks in the same order without evaluating the policy again: it names
`policy` when no other rule matched a handshake the verifier let through,
`allow-spki-pin` / `verify-spki-pin` in pin mode, `hostname` in client mode
when no `--verify-*` rule is configured, and `disable-authentication` when
no client certificate is requested at all. `ServerRule` is given the leaf
the handshake parsed, as a chain of one: the rule of an allow is a function
of that leaf and of configuration that lives for the process, so the line
records the verifier's own decision whatever a reload did to the verify
cache between the handshake and the line. An `allow` is never written under
`none`: a completed handshake no rule names (one with no certificate, which
the verifier never judged) is recorded `deny` under `none`, `verified`
false, and refused before anything is forwarded.

**`close`**: a connection ended.

| Key | Type | Meaning |
|---|---|---|
| `conn` | integer ≥ 1 | the connection |
| `reason` | `"eof"`, `"error"`, `"lifetime"`, `"shutdown"`, `"halt"` or `"refused"` | why: peer or backend finished; an error; the lifetime cap; process shutdown; the ring's gate refused after accept; the handshake or ACL refused it |
| `duration_ms` | integer ≥ 0 | from accept to close, by the monotonic clock |

The lifetime reading: for every `close`, `duration_ms` ≤ `lifetime_cap_seconds
× 1000` plus the observer's margin; and every `accept` without a `close`
whose `at` is older than the cap plus margin is a connection that has
outlived it.

**`reload`**: a reload of trust material finished.

| Key | Type | Meaning |
|---|---|---|
| `outcome` | `"ok"` or `"failed"` | |
| `error` | string or `null` | the error on failure |
| `serving` | boolean | whether the process is still serving after this reload |
| `material` | array (may be empty, never `null`) of material objects | what was reloaded, with the hashes now loaded |

The material observer's reading: a `reload` with `outcome` `failed` and
`serving` `true` is a failed reload that kept serving, which is a violation.
The reader does not enforce this; it records what happened.

What ghostunnel writes. Each hash is of the material in use: the bytes the
certificate loader and the policy loader read and parsed or compiled on
their last successful load, never a second read of the path, so after a
failed reload the entries name the material the process still serves
with. A TLS source that hands back no files (PKCS#11, a keychain, SPIFFE)
has its configured files read when the line is written. `outcome` is
`failed` when the reload itself failed, **or** when a certificate, CA
bundle or policy file could not be hashed (its loader handed back nothing
for the configured path, or, for a source that hands back no files, the
read failed; that entry then has `sha256` `null` and `error` names it),
**or** when the CA bundle could not be stored (§1.6); a failed reload is
sticky: ghostunnel refuses to serve (503, accepts refused, connections in
flight closed with reason `halt`) until a later reload succeeds with every
hash and the bundle stored, and does not tell the service manager it is
ready again until then.
`serving` is whether serving is allowed once this reload is accounted for,
so it is `false` on every failed reload and also `false` on a successful
one while a gate refusal is in force.

**`shutdown`**: a request to stop the process was received.

| Key | Type | Meaning |
|---|---|---|
| `source` | `"signal"`, `"status-endpoint"`, `"service-control"`, `"ring-halt"` or `"internal"` | where it came from |
| `authorized` | boolean | the request passed the gate that guards its source (for `status-endpoint`, the `/_shutdown` authorization) |
| `peer` | string or `null` | the identity that asked, when it came over a connection |
| `detail` | string | free text for people |

**`tick`**: the trace's own heartbeat. The header and nothing else:

```
{"kind":"tick","version":1,"sequence":N,"at":"YYYY-MM-DDTHH:MM:SSZ"}
```

ghostunnel writes one every `--ring-tick` (default 5 s; must be above zero,
below `--ring-heartbeat-max-age` and below the observers' cadence) from a
goroutine, through the same path as every other line, so a tick takes a
sequence like any line and a sticky emitter failure stops the ticks. The
ticks stop when the trace is closed. An observer's reading: a boot whose
latest line, tick or otherwise, is older than the tick interval plus its
margin has a trace that has stopped, whether the process died, hung or lost
its emitter; without ticks a quiet proxy and a dead one would leave the same
trace.

**`accept-error`**: an Accept on the tunnel listener failed.

| Key | Type | Meaning |
|---|---|---|
| `error` | non-empty string | the error as the listener reported it (an operating-system error such as `too many open files`; never a secret) |
| `backoff_ms` | integer ≥ 0 | how long the accept loop sleeps before its next attempt, in milliseconds |

ghostunnel writes one line per failed Accept, which is one per backoff
step: the backoff starts at 5 ms on the first error, doubles up to 1 s, and
resets on the next successful accept. The accept loop's own deadline (it
wakes every second to record that it is alive) is not an error and writes
nothing. Without this line a listener that has stopped accepting, out of
file descriptors say, backs off silently and leaves no trace.

**`refusal`**: the process refuses to serve until restart, for a reason no
other line records.

| Key | Type | Meaning |
|---|---|---|
| `source` | `"status-listener"` | what failed |
| `error` | non-empty string | the error as it was reported (never a secret) |

ghostunnel writes one line, once, when the status listener's `Serve`
returns an error other than a clean close: the status surface is part of
what the ring observes and of what the start line describes, so the proxy
refuses every accept from then on until restart (`ring.stickyRefusal`);
without this line nothing in the trace would say why. Every
member reads it as the admin surface's `status-listener-up`, failing for
the rest of the boot (SPEC 14.3). The other sticky refusals need no line of
their own: a failed reload writes `reload` with `outcome` `failed` and
`serving` false, and a trace that can no longer be written cannot write one
by definition, which is what `tick-fresh` is for. `source` is a closed set
of one so that a later refusal with a source of its own extends the set
rather than the format.

`Keys(kind)` in `format.go` returns each kind's exact key list and is pinned
to the struct tags by a test.

### 1.3 Files under `gt/`

```
gt/                          the trace root, written only by ghostunnel; gt:gtring-trace 2750 (deploy)
  lock                       the emitter's exclusive lock, the only file here          0640
  chains/                    the chain store (§1.5), one of the two directories that are not a boot  0750
    <sha256>.der             a presented chain, named by the SHA-256 of its content   0640
  material/                  the material store (§1.6), the other                    0750
    <sha256>                 a CA bundle a start or reload line hashed, named by the SHA-256 of its content  0640
  0000000001/                one directory per process start ("boot")                 0750
    0000000001.trace         segment whose first line has sequence 1                  0640
    0000004097.trace         segment whose first line has sequence 4097               0640
  0000000002/
    0000000001.trace
```

- **Modes: the owner and the group read, nobody else.** The trace names
  every peer that presented a certificate (the handshake line's `peer`, and
  the chain itself in §1.5), so the emitter and the chain store request
  `0750` on every directory they create and `0640` on every file
  (`DirMode`, `FileMode`); the process umask can narrow that and never
  widen it, and the deployment runs the proxy under `UMask=0027` so exactly
  those land. The readers are the group of the root, which the deployment
  makes the four observers (`gt:gtring-trace 2750`, deploy/README.md "The
  trace root is group-readable"); an account outside it cannot list `gt/`
  or reach a file inside it by name.

- **Boot numbers are durable.** On start the emitter lists `gt/`, takes the
  highest directory number plus one (or 1), and creates that directory. A
  number is never reused, so a restart never looks like a rewrite.
- **Sequences restart at 1 per boot.** They are per-process; the boot number
  says which process.
- **Segments are named by the sequence of their first line.** The first
  segment of a boot is always `0000000001.trace`. When a segment has reached
  `MaxSegmentBytes` (default 64 MiB) the next line opens a new segment named
  by that line's sequence. Lines are never split across segments.
- **Segments are pre-extended, and the segment rule.** The emitter extends
  every segment to `MaxSegmentBytes` when it opens it and writes at a
  tracked offset inside it, so the live segment's size on disk is
  `MaxSegmentBytes` from the start and only its content grows; it truncates
  a segment to its written length when it closes it (rotation, `Close`,
  and best effort on the failure path), so a closed segment holds exactly
  its lines. The last segment of a boot that ended in a crash keeps its
  zero tail forever. Readers apply this rule: A segment's content is its
  bytes before the first NUL byte (0x00), or all of its bytes when it has
  none. Bytes from the first NUL onward are unwritten space of a
  pre-extended segment and are not part of the trace. A reader reads a
  segment in bounded chunks from its start and stops at the first chunk
  holding a NUL or at end of file; it never reads a whole pre-extended
  segment. The complete-line prefix and the torn tail are then taken of
  the content, as before. Lines are JSON objects, which never carry a raw
  NUL (`encoding/json` escapes it), so the rule is exact.
  `ReadSegmentContent(path)` is the reference implementation, in chunks of
  `ContentChunkBytes` (1 MiB).
- **The latest line** is the last complete line of the highest-named segment
  of the highest-numbered boot that holds one. Rotation cannot hide it: the
  highest name is the newest segment, and every segment but the last ends in
  a complete line.
- **One emitter per root.** `gt/lock` is a regular file the emitter creates
  and holds an exclusive advisory lock on (`flock` on unix, `LockFileEx` on
  Windows) for the process lifetime; the operating system releases it when
  the process dies, so no stale lock survives a crash. A second `Open` under
  the same root fails before creating a boot, and ghostunnel refuses to
  start on it: two processes never write, and the readers never judge, a
  second boot of a root already in use. The file's content is nothing.
- **The tree is exactly this and nothing else.** Any entry under `gt/` that is
  not a directory named by ten digits, the regular file `lock` or the
  directories `chains` (§1.5) and `material` (§1.6), or any entry in a boot
  directory that is not a regular file named `<ten digits>.trace`, makes the
  tree malformed. A regular file named `chains` or `material` is malformed
  too, and the emitter refuses to open on it.
- **Retention is not the emitter's job.** It never deletes, and neither
  does any member: the trace is the record that survives recovery
  (observers/SPEC.md 12.4). An operator may remove whole boot directories
  that are not the current boot, and a chain file only when no retained
  boot names it. Removing a segment from a boot makes that boot malformed
  (a gap), and removing its first segment leaves a boot with no start line,
  which `boot-ambiguous` cannot show dead. The rule, the `systemd-tmpfiles`
  form and its limit are in deploy/README.md "Trace retention".

### 1.4 The reader's rules

`Read(root)` applies all of these and returns `*MalformedError` (with path
and 1-based line) on the first violation; a trace that cannot be read has not
been read, so nothing is returned with the error. Every segment is first
reduced to its content by the segment rule (§1.3: the bytes before its
first NUL, read in bounded chunks); rules 5 to 10 are applied to that
content, so a pre-extended segment reads exactly as the same bytes ending
at the content did.

1. Every entry under `gt/` is a directory named by ten digits, the regular
   file `lock` (anything else at that name is malformed), or one of the
   directories `chains` and `material` (anything else at either name is
   malformed). `Read` walks neither; a chain or a bundle is judged when it
   is read by name (§1.5, §1.6).
2. Every entry in a boot directory is a regular file named
   `<ten digits>.trace`.
3. A boot directory with **no segments** is benign: a process that died
   between creating its directory and writing its first line. It reads as a
   boot with no records.
4. Segments sorted by name are consecutive: the first is named `0000000001`
   and each is named by the sequence the previous one left off at.
5. A **torn final line** (no trailing line feed) is ignored, and only in the
   last segment of a boot; the boot reads as ending at the last complete line
   and reports `Torn`. A torn line in any other segment is malformed.
6. An **empty last segment** is benign when its name is the next sequence
   (a crash between rotation and the first write); an empty segment anywhere
   else is malformed.
7. Every complete line parses strictly under §1.1–1.2 (`DecodeLine`).
8. Sequences run 1, 2, 3, … across segments with no gap and no repeat.
9. Line 1 of a boot is a `start` whose `boot` equals the directory number;
   no other line is a `start`.
10. `at` never decreases within a boot.

### 1.5 The chain store `gt/chains/`

**What it is.** The certificate chain a peer presented on a handshake, kept
whole so that a member can judge the substance of what the proxy recorded,
not only its word: re-verify the presented chain against the CA on disk and
re-run the recorded rule set (`config.acl`) on its leaf. The trace carries
the chain by reference (`handshake.chain`), so a repeat client costs nothing
more than a stat and the line stays small (75 bytes for the key); the chain
itself is written once per distinct chain, into a content-addressed store
that only grows. `gt/chains/` is written by ghostunnel alone, like the
segments, and read by every member.

**The content.** A chain file holds the concatenation, in presented order,
of the DER of every certificate the peer presented: exactly the bytes
`tls.ConnectionState.PeerCertificates[i].Raw` concatenated for `i` from 0
(leaf first), which `x509.ParseCertificates` parses back into the same
certificates in the same order. In server mode that is the client's chain;
in client mode (`config.mode` `client`) the line describes the dial and the
chain is the server's. Presented order is part of the identity: the same
certificates in another order are another chain with another name.

**The naming.** A file is named `<sha256>.der`, where `<sha256>` is the
lower-case hexadecimal SHA-256 of the file's content, 64 characters, the
value the `handshake` line carries as `chain`. `ChainPath(root, hash)` is
`<root>/chains/<hash>.der`.

**The write protocol** (`WriteChain(root, der)`, which returns the hash).
The store is a set that only grows; a file is written once and never
modified:

1. `chains/` is created (`DirMode`, `0750`) the first time and the root
   synced so the entry is durable.
2. If `<sha256>.der` exists, nothing is written.
3. Otherwise the content is written to `<sha256>.tmp` (created or truncated,
   `FileMode`, `0640`), that file is `fsync`ed and closed, it is renamed to
   `<sha256>.der`, and `chains/` is `fsync`ed, so the name is as durable as
   the content (as for segments, the directory sync is a no-op on Windows).
4. A write that fails at any step leaves at most a `<sha256>.tmp` behind,
   which is never read and is truncated and reused by the next write of that
   chain. A `<sha256>.der` is therefore always complete: it appears only by
   rename after its content was synced.

Writes of one chain are serialised inside the process, so two connections
presenting the same first-seen chain at once write it once, and the second
returns only after the first's directory sync; writes of different chains
wait for each other only while the store's directory is checked (and, the
first time, created and the root synced). A directory sync that fails (of
`chains/` after a rename, or of the root after creating `chains/`) fails
that write, every writer of the same chain waiting on it, and every later
write into the store for the life of the process. An empty chain (no
certificate presented) is refused and never stored; a chain above
`MaxChainBytes` (1 MiB; `crypto/tls` refuses a handshake message above
64 KiB, so none approaches it) is refused too, and the reader treats a file
above it as malformed, so a reader never hashes an unbounded file.

**The durability order.** The chain file is durable, renamed and its
directory synced, **before** the `handshake` line naming it is written: in
ghostunnel the write of a new chain happens in `recordHandshake` before the
batch that holds the line is written (§2, `EmitAll`), so a durable
`handshake` line never names an absent chain. The chain's own syncs are a
one-time cost per distinct chain. A
chain that cannot be stored is a record that cannot be written: the ring's
sticky failure, logged as `a handshake event could not be recorded`, the
connection closed with nothing written for it, and every later line
refused (as after a failed emitter write).

**The reader's rules** (`ReadChain(root, hash)`, the proxy's own reader;
the members' is their own, written to this section). It returns the
certificates in presented order and the bytes read, or an error and
nothing, on the first of:

1. `hash` is not 64 lower-case hexadecimal characters (so a name is never
   a path).
2. `<root>/chains/<hash>.der` does not exist, or is not a regular file (a
   symbolic link is judged as the link and refused; a directory is refused),
   or, opened as the gate opens a heartbeat (§3, without following a link
   and without waiting), is not the regular file the `Lstat` found.
   A `<hash>.tmp` is never read, whatever it holds: a chain that only has
   its `.tmp` is absent.
3. The file is larger than `MaxChainBytes` (checked by size before any
   content is read).
4. The content's SHA-256 is not `hash`: the reader verifies that the
   content hashes to the name and fails closed otherwise. A tampered byte,
   or the right content under another name, is refused.
5. The content is not a concatenation of at least one DER certificate
   (`x509.ParseCertificates`).

`Read` (§1.4) accepts `chains/` beside the boots and does not walk it; a
chain is judged when read by name. What the members do with a chain they
have read (verification against the CA material, the rule set on the leaf)
is theirs; this section fixes only what is on disk and how it is read.

**Retention.** As for boots: the emitter never deletes. An operator may
remove chain files that no line of any kept boot names; a chain named by a
kept line and missing reads as malformed to the member that follows the
reference, which is what a missing segment is.

### 1.6 The material store `gt/material/`

**What it is.** The CA bundle ghostunnel verified client chains against,
kept as the bytes it hashed for the `start` line's `material` entry of kind
`ca`, and for every successful `reload` line's, so that a member judging a
handshake against the bundle in force at the line (SPEC 14.3) reads those
bytes by the recorded hash and never the file at the entry's `path`, which
may since have been rewritten. A rotation in place (the operator writes a
new bundle over the old path and reloads) leaves the old bundle on record
under its old hash for the handshakes before the `reload` line and the new
one under the new hash for those after; nothing at the path has to survive
for either to be judged. Like `gt/chains/`, it is written by ghostunnel
alone and read by every member.

**The content.** A material file holds the bundle's bytes exactly as they
were read when they were hashed for the line (PEM, as `--cacert` is),
whatever their format: the store does not parse them, and what they parse
as is the reader's to judge (a bundle with no certificate in it is one the
member cannot verify against).

**The naming.** A file is named `<sha256>`, no suffix: the lower-case
hexadecimal SHA-256 of its content, 64 characters, the value the line's
`material` entry carries as `sha256`. `MaterialPath(root, hash)` is
`<root>/material/<hash>`; the temporary file of a write in progress is
`<sha256>.tmp`.

**The write protocol** (`WriteMaterial(root, data)`, which returns the
hash; `StoreMaterial(root, material, ca)`, which writes `ca` for the hashed
`ca` entry of a material list after holding the bytes to the entry's hash)
is the chain store's (§1.5), the same code (`store.go`): `material/` is
created (`0750`, `DirMode`) the first time and the root synced; nothing is written when
`<sha256>` exists; otherwise the content goes to `<sha256>.tmp`, that file
is `fsync`ed and closed, renamed to `<sha256>`, and `material/` is
`fsync`ed. Empty content is refused; content above `MaxMaterialBytes`
(16 MiB) is refused and the reader treats a longer file as malformed.
`StoreMaterial` refuses, with nothing written, a hashed `ca` entry given no
bytes and bytes that do not hash to the entry; a list with no hashed `ca`
entry (the system trust store, or a bundle the proxy could not read, which
is listed without a hash) stores nothing.

**The durability order.** The bundle is durable under its name before the
line that names its hash is written. `Open` stores `Options.CABundle` after
taking the lock and before the boot directory is created, so a store that
refuses is an `Open` that fails with no boot; ghostunnel's reload stores the
reloaded bundle before its `reload` line, so a store that refuses is a
failed reload (the line says `failed` with `serving` `false`, and nothing is
served until a reload succeeds). A durable line therefore never names a
bundle the store lacks.

**The reader's rules** (`ReadMaterial(root, hash)`, the proxy's own reader;
the members' is their own, written to this section) are the chain store's
rules 1 to 4 (§1.5) on `<root>/material/<hash>` with the bound
`MaxMaterialBytes`: a name that is not 64 lower-case hexadecimal
characters; a file absent or not regular as `Lstat` sees it (a symbolic
link, a directory; a `<hash>.tmp` is never read, so a bundle that only has
its `.tmp` is absent), or not that regular file once opened; a file over
the bound, checked by size before any content is read; content whose
SHA-256 is not the name. Each returns an
error and nothing. There is no rule 5: the bytes are returned as stored.
`Read` (§1.4) accepts `material/` beside the boots and does not walk it.
What the members do with a bundle they have read (the pool a presented
chain is verified against) is theirs; a hash the store lacks fails their
check closed, as a chain the chain store lacks does.

**Retention.** As for chains: the emitter never deletes. An operator may
remove material files that no `start` or `reload` line of any kept boot
names; one named by a kept line and missing fails, on the member that
follows the reference, every verified handshake judged under it.

## 2. The emitter

- **Single writer, one process.** `Open(root, Options)` takes the lock,
  stores the CA bundle the configuration hashed (`Options.CABundle`, §1.6),
  creates the boot directory and first segment and writes the `start` line
  before returning.
  `Emit(body)` appends one line and returns its sequence. `EmitAll(bodies...)`
  appends two or more lines as one write with consecutive sequences, in the
  order given, and returns the first (ghostunnel uses it for a connection's
  `accept`, `handshake` and `acl` lines, and for `accept` with `close` when
  nothing else is recorded). Writes are serialised; lines land whole and
  in sequence order.
- **Every line is one write** of the whole line including its line feed,
  landed with `WriteAt` at the tracked offset inside the pre-extended
  segment (never `O_APPEND`, which would land after the pre-extension); an
  `EmitAll` is one write of its whole lines. A crash mid-write can leave at
  most one torn final line, which readers ignore (§1.4 rule 5). A crash
  inside an `EmitAll` leaves exactly what a crash between the same lines'
  separate `Emit`s would: the earlier lines whole, the one being written
  torn or absent.
- **Pre-extension, and which sync covers what.** Every segment is
  extended to `MaxSegmentBytes` when it is opened and that size is
  `fsync`ed before any line is written (one `fsync` per segment opened,
  counted in `SyncCount`; the directory is synced after it), so the sync
  after each write commits data alone and never a size change. The sync
  of a size change costs a journal commit on ext4 that a data-only sync
  does not, and a write into a file whose size does not change still
  dirties the inode's timestamp, which `fsync` journals and `fdatasync`
  does not. So the group commit's sync is `fdatasync` on Linux
  (`syncdata_linux.go`) and `Sync` elsewhere; the syncs of a size change,
  the pre-extension at open and the truncation at close, are `fsync`. The
  seams cover both kinds: `failSync` fails both, `syncHook` replaces both,
  `SyncCount` counts both. Nothing in the ring reads a segment's
  timestamp: `trace-consistent` and the readers take content, and the
  members' staging-file age is of heartbeat files, never of a segment.
  What `fdatasync` omits is exactly what no reader needs, and what it
  keeps (the data, the size, the block mapping) is what a reader needs to
  read the line back, so a line is durable before `Emit` returns. Crash
  cases: a torn group leaves a partial line followed by NULs, which reads
  as the torn tail; pages of one unacknowledged group may persist out of
  order, leaving zeros before data inside that group, and the segment rule
  cuts the content at the first zero, dropping only bytes whose sync never
  returned, so no served connection loses its record; a crash between the
  truncation at close and its `fsync` leaves a closed segment with a zero
  tail, which reads as the same content. What a reader observes: the live
  segment's size on disk is `MaxSegmentBytes` from the start and its
  content length is what grows; a closed segment is exactly its content.
  A first group larger than `MaxSegmentBytes` on an empty segment is
  written past the pre-extension and is still readable.
- **fsync policy.** `SyncEveryLine` (the default): every `Emit` and `EmitAll`
  returns only once an `fsync` that began after its bytes were written has
  completed, so a sequence the caller has been handed is on disk. The
  `fsync` is a **group commit**: the write happens under the emitter's
  mutex, the `fsync` outside it; the first caller whose line was written
  since the previous `fsync` began leads the next one, waits for the one in
  flight to end, then `fsync`s once for every line written meanwhile and
  releases all their callers with that one outcome. N concurrent callers
  therefore pay at most one `fsync` each and usually far fewer; one caller
  at a time pays one. Rotation and `Close` wait for
  an `fsync` in flight and then `fsync` the segment they close, so nothing
  written before them is left uncovered and no segment is closed under a
  running `fsync`. `SyncOnRotateAndClose`: `fsync` only when a segment is
  closed. Directories are `fsync`ed after a boot directory or segment is
  created so the entry is as durable as its content (no-op on Windows,
  which has no directory sync).
- **`EmitAllAsync`: the same commit, waited for later.**
  `EmitAllAsync(bodies...)` is `EmitAll` up to and including the write: when
  it returns with a nil error the lines are written and sequenced, in one
  write, in the order given, and it returns a `wait` function alongside the
  first sequence. The only difference is who waits for the group commit:
  when the caller leads its batch the commit runs on a goroutine of its own
  instead of the caller's, and the caller does what it has to do meanwhile
  before calling `wait`, which blocks on that batch's commit and returns its
  outcome. Every line written before `wait` returns is covered by the commit
  `wait` waits on, exactly as with `EmitAll`; callers that `Emit` while an
  async commit is in flight join the batch behind it and are released by
  it; a failure is reported by `wait`, fails the emitter for good
  and is reported by every later call; rotation and `Close` behave as with
  `EmitAll` (neither closes a segment under a running commit, whichever goroutine
  runs it; `Close` waits for an async commit in flight); `SyncCount` counts
  the same one sync per commit. Under `SyncOnRotateAndClose` `wait` returns
  nil at once. An error from `EmitAllAsync` itself (an invalid body, a
  failed write) comes with a nil `wait`. `EmitAll` is `EmitAllAsync` with
  the commit run on the caller's goroutine and waited for before it
  returns; the two share one body. ghostunnel uses `EmitAllAsync` in one
  place: in server mode, for the `accept` + `handshake` + `acl` batch of a
  connection the ACL allowed, the batch that precedes the backend dial; the
  proxy dials while the commit runs and the observer waits for it in
  `Dialed`, before the PROXY protocol header and before any byte is copied,
  so the record is durable before any byte is forwarded, and
  the sync's latency is hidden up to the dial's length. Every other batch,
  and client mode entirely, uses `EmitAll`. `SetSyncHook` installs a sync
  hook from outside the package, for the proxy's tests of that placement.
- **What a power loss can lose.** Under `SyncEveryLine`, only lines whose
  callers had not yet been told they were durable: with group commit that is
  every line of the `fsync` in flight and of the batch behind it, none of
  whose callers had proceeded. That end of the boot is never judged again
  (a restart opens a new boot).
- **Fails closed, for the caller.** A body that does not validate is refused
  without consuming a sequence (in an `EmitAll`, one invalid body refuses
  them all). A write that errors or lands short, an fsync that fails, a
  rotation that fails, or a clock that goes backwards fails the emitter
  **for good**: every later `Emit` returns the same error (`Err()`), because
  the emitter cannot know what reached the disk. An `fsync` that fails fails
  **every** caller whose line it was to cover, and every caller queued
  behind it; none is told its line is durable. The caller refuses to serve
  and the process restarts into a new boot. Nothing is ever dropped
  silently.
- **Never writes a secret.** The bodies have no field for one, and §1.1's PEM
  rule refuses a field that carries one anyway.

## 3. The gate (SPEC §19)

`Gate.Check()` returns `Decision{Serve, Reason}`. ghostunnel calls it on
every accept and rejects the connection, logging `Reason`, when `Serve` is
false. The gate writes nothing, repairs nothing and loads nothing.

Configuration: `Root` (default `/var/lib/ghostunnel-ring/stores`), `Members`
(default `admin`, `material`, `super`, `tunnel`, walked in ASCII identity
order), `Coordinator` (default `super`), `MaxHeartbeatAge` (**must be set**;
zero refuses everything), `MaxHeartbeatBytes` (default 64 KiB), `Now`.

It reads, in this order, and **refuses on the first of**:

1. **Configuration**: `MaxHeartbeatAge` ≤ 0, `MaxHeartbeatBytes` ≤ 0, no
   clock, no members, no `Root`, or a coordinator that is not a member.
2. **For each member in identity order**:
   - `<member>/halt` exists (a regular file is "in force"; anything else at
     that name is also a refusal), or its `Lstat` fails for any reason but
     absence;
   - `<member>/fault` exists, the same way;
   - `<member>/halts/` cannot be listed;
   - `<member>/halts/` holds any entry other than a regular file whose name
     ends in `.tmp`. A regular non-`.tmp` file is a delivered halt in force,
     **regardless of its content or size**; a subdirectory or other entry is a
     refusal in its own right.

   The root and the stores are not read on their own: a root or a store
   that is missing, not a directory or a link to nothing fails the `Lstat`s
   (`ENOTDIR`) or leaves `halts/` unlistable, and is refused there.
3. **The coordinator's heartbeat**:
   - `<coordinator>/heartbeat/` cannot be listed;
   - it holds any entry other than a regular `NNNNNNNNNN.hb` or
     `NNNNNNNNNN.hb.tmp`;
   - it holds no `.hb` file (a `.hb.tmp` alone is not a heartbeat);
   - the newest `.hb` (highest name, which is highest sequence) is larger than
     `MaxHeartbeatBytes`, checked before it is read;
   - opened without following a link and without waiting (`O_NOFOLLOW` and
     `O_NONBLOCK` on unix, the reparse point itself on Windows), the open
     file is not a regular file within the bound, or not the file the
     `Lstat` found: a pipe or anything else swapped in after the `Lstat` is
     refused, never waited on;
   - it does not begin with `{"kind":"heartbeat",`;
   - it does not parse strictly under SPEC §3.2: exact keys, `version` 1,
     `observer` equal to the coordinator, `sequence` equal to the name,
     `timestamp` of the form `YYYY-MM-DDTHH:MM:SSZ`, `cadence_seconds` ≥ 1,
     `check_count` equal to the length of `checks`, `observed` holding exactly
     the other members with hash-or-null values, `previous` a hash (null only
     on sequence 1), `boot` null or `{started, resumed_from}`, `stop` boolean;
   - `stop` is `true`;
   - `timestamp` is more than `MaxHeartbeatAge` before **or after** now.

Only when every read above succeeded and found nothing does it serve, and
the serve reason names the heartbeat it rests on.

Every one of those reads happens on every `Check`; the heartbeat's bytes
are read within the size bound each time. The one thing reused between
calls is the strict parse: when the bytes read hash (SHA-256) the same as
the last ones parsed, under the same coordinator, sequence and member list,
the parse's result, error included, is taken as it stands, since it is a
function of exactly those. Different bytes are parsed again. The
timestamp's age is judged against the clock afresh on every call. Nothing
is ever keyed on a size or a modification time.

Of these reads, the two that turn a no into a yes are `super/heartbeat` (an
observer that dies stops writing, and nothing has to deliver its absence) and
each member's `halts/` (where every other member relays what it found). The
rest can only turn a yes into a no.

### 3.1 The gate as a trivial call (`GateState`)

ghostunnel does not call `Gate.Check` on every accept. It keeps a
`GateState` over the gate: the decision of the last full scan, when it was
made, and a generation counter that the operating system's change
notification on the store tree bumps on every event. On an accept the
state first drains what the kernel has ready (a non-blocking read of the
notification, never a wait), then either **reuses the standing decision**
or **runs one full scan** (`Gate.Check`, every read above), shared with the
accepts that arrive while it runs: the first arrival runs the scan, the
others wait for that read and take its decision; nobody waits for anything
but the one read it started or joined, and there is no queue.

A decision stands while **all** of these hold:

1. no event has been reported since the scan that made it (an event, a
   queue overflow, or a failure of the watcher itself each bump the
   generation, so nothing lost goes unnoticed);
2. it is younger than the **window**, 10 ms (`ringGateWindow`, pinned by a
   test to stay below a tenth of the watch interval), **or** the watcher is
   running without error and it is younger than the **watch interval**, 1 s
   (`ringWatchInterval`), at which ghostunnel's watch calls `Scan` (a full
   scan, never a reuse) and refreshes the state regardless of events,
   closing every in-flight connection when the answer is a refusal;
3. when it is a serve decision, the heartbeat it rests on is still within
   `MaxHeartbeatAge` by the gate's clock, in both directions, judged afresh
   on every reuse; the heartbeat's age is never cached.

The watcher, per operating system: on Linux, one inotify descriptor with a
watch on the root, on every member's store and `halts/`, and on the
coordinator's `heartbeat/`, for `IN_CREATE | IN_DELETE | IN_MOVED_TO |
IN_MOVED_FROM | IN_CLOSE_WRITE | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF`;
`IN_Q_OVERFLOW` marks the decision stale (the scan that follows sees what
was missed), and a watched directory removed, moved or unmounted fails the
watcher. On Windows, one `ReadDirectoryChangesW` on the tree root with the
subtree flag, for name, directory-name, attribute, size, last-write,
creation and security changes; a completion with no bytes is the kernel's
buffer overflowing, marked stale the same way. A notification marks the
decision stale unless its path is one the gate never reads: under `gt\`,
under a store's `copy*\`, or under the `heartbeat\` of a store that is not
the coordinator's, matched without regard to case. An 8.3 short name or
any other name the watcher does not recognise marks it stale. Since the
kernel reports a change where it happened and the gate reads through
links, that holds only while every store, its `halts\` and the
coordinator's `heartbeat\` is a plain directory and not a reparse point,
which the watcher checks at start, whenever a notification names one of
them or a name it cannot match, and after an overflow or a cancelled
read; once one is not, every notification marks the decision stale.
Elsewhere, no watcher.
**Without a watcher, or once it has failed**, only the window stands: every
accept more than 10 ms after the last scan is a full scan, a scan per
accept, and concurrent accepts share one.

**The bound.** The same files decide, read by the same `Gate.Check`, on
the same schedule at worst: the watch's full scan every second is what
closes a served connection when a halt lands. So the bound on a halt
reaching a served connection is ≤ 1 s, and a change the kernel reports is
seen by the next accept, since every accept drains the notification before
deciding. **The residual, stated exactly:** a change the kernel does
not report is seen at the next scheduled scan, within 1 s. Four cases
go unreported: a write through a shared mapping without `msync`, a
mount placed over a watched directory, any change while the watcher is
not running, and, on Windows, a change to a file's *content* only (the
last-write and size notifications are delivered when the cache flushes,
while name changes are delivered at once; the gate decides halts, faults
and delivered halts by name, and the heartbeat is judged by name and by its
age on every reuse). Nothing is keyed on a size or a modification time.

## 4. Tests

`go test ./ringtrace/` covers: format round-trip and every rejection
(the `acl` vocabulary, the `tick`, `accept-error` and `refusal` kinds included, the
`chain` key accepted as a hash, refused as anything else and absent by
default), the chain store (a chain is written once through a synced `.tmp`,
a rename and a directory sync, its content hashes to its name, a second
write of the same bytes syncs nothing and touches nothing, sixteen
concurrent first writes leave one file; `ReadChain` returns the
certificates in presented order and fails closed on a tampered byte, a
wrong name, a missing file, a `.tmp` left behind, a symbolic link where
the platform allows one, a name that is not a hash, content that is not
DER, a directory at the name, a file over the bound and a root with no
store; `chains/` and `material/` are the two directories beside the boots
and the lock, and a regular file at either name or any other stray entry
is malformed), the material store (`WriteMaterial` writes once through a
synced `.tmp`, a rename and a directory sync, under the hash and no
suffix, and a second write of the same bytes touches nothing;
`ReadMaterial` fails closed on the chain store's cases and on the same
bytes stored under `chains/` only; `StoreMaterial` stores nothing for a
list with no hashed `ca` entry and refuses, with nothing written, a hashed
entry given no bytes or bytes of another hash; `Open` with a
configuration that hashes a bundle stores it before any boot exists, and a
refused store, bytes of the wrong hash or a regular file at `material`,
is an `Open` that fails with no boot),
emitter boot numbering, rotation, sticky failure, the exclusive lock,
concurrency and the no-secret invariant, the group commit (every `Emit`
returns after a covering `fsync`, an `fsync` failure reaches every caller
in its batch and sticks, rotation and `Close` cover what precedes them,
`EmitAll` is consecutive, one write, one `fsync`, and tears as two `Emit`s
would), `EmitAllAsync` (it returns while its sync is held with the lines
written and sequenced and `wait` blocks until the sync completes; a failed
sync is returned by `wait` and sticks; `Emit`s from other goroutines while
an async commit is held return after a completed sync covering their line,
in order, sharing commits; `Close` waits for an async commit in flight and
leaves an exact segment), the pre-extension (the live segment is `MaxSegmentBytes` on disk
from the start and its content ends with the line `Emit` returned;
rotation and `Close` leave exact-size segments with no NUL whose contents
are the lines emitted; `SyncCount` is one per segment opened, one per
commit and one per segment closed), reader torn-line tolerance, the
segment rule (a partial line then NULs is torn, complete lines then NULs
are not, zeros inside the last line cut it there, a NUL tail in an
earlier segment and an all-NUL last segment are benign, and the content
read is exact at the chunk boundary), the `lock` file and every malformation,
gate serve and every refusal, the heartbeat parse reuse (a rewrite in
place of the same size is judged anew; identical bytes are not re-parsed
but their age is), and the gate state (§3.1: sixteen concurrent checks
share one scan; a check inside the window reuses and one outside it scans;
an event, an overflow or a watcher failure makes the next check scan; a
silent watcher leaves a decision reused for the watch interval at most and
never later; a reused serve decision still refuses on a heartbeat that has
aged out; `Scan` never reuses; and the real watcher on this OS reports a
halt placed and cleared). ghostunnel's own tests (`ring_test.go`)
add the accept path: concurrent accepts share one scan, the window, the
halt seen by the next accept under the real watcher, one `fsync` for
`accept` + `handshake` + `acl`, the refused-handshake batch, `accept` + `close` on a gate
refusal and on a dial that never reached TLS, and the chain store in the
served path (§1.5): a served connection's `handshake` names the chain the
client presented, the file is under `gt/chains/` and `ReadChain` returns
the client's certificates, a second connection from the same client adds
no file, a resumed handshake names the same chain, a refused handshake
whose peer presented a chain names it too; with a hook recording every
sync, the chain file's and its directory's precede the handshake batch's,
and the same chain again syncs nothing for it; and a chain that cannot be
stored is a record that cannot be written (the connection closed unrecorded,
the failure sticky, nothing more written).
