# ringstatus

What the observer ring looks like right now, in a terminal.

An operator's view, not a member. It reads the store tree and prints it. It
joins no ring, publishes nothing, holds no credential and writes no file: every
path it touches is opened for reading, and `TestRenderingWritesNothing`
snapshots a synthetic tree (every name, size, mtime and mode) before and after
a render and requires them identical.

**It is not a check, and its opinion is not a verdict.** The members' own
`fault` and `halt` files are the truth: they are what stopped the work, and
anything printed here that disagrees with them is this tool being wrong. Where
it cannot tell two things apart it says so rather than guessing.

**Why a terminal tool and not a page.** Every way into the deployment is gated,
and a gate answers 503 during a halt, which is exactly when somebody wants to
look. The thing that watches a deployment has to work when the deployment does
not, so this runs beside the tree and needs no listener.

## Running it

```
go run ./observers/ringstatus                  # watch, if stdout is a terminal
go run ./observers/ringstatus --once           # one frame, then stop
go run ./observers/ringstatus --interval=5     # watch, redrawing every 5s
go run ./observers/ringstatus -stores /path/to/copied/tree --once --no-color
```

| | |
|---|---|
| `-stores DIR` | the tree to read. Default `/var/lib/ghostunnel-ring/stores`, or `$GHOSTUNNEL_RING_STORES` when set; the flag beats the variable |
| `--watch` | redraw in place, in the alternate screen buffer, restored on exit (including ctrl-c and SIGTERM) |
| `--once` | print one frame and stop. Wins over `--watch` and `--interval` wherever it appears, so a launcher can pass `--watch` as its default and still be overridden |
| `--interval=N` | seconds between frames, at least 1. Implies `--watch` |
| `--no-color` | no colour escapes. `$NO_COLOR` (set to anything, even empty) does the same |

With no argument it watches when stdout is a terminal and prints once when it is
not. Piped into a file or a pager, watch mode prints frames one after another
with no cursor movement.

`--once` pauses for one second between two readings of the sequence numbers,
because the cycle column is measured rather than assumed and there is no rate
without two readings.

### What the operator's account needs

`ringstatus` reads the four member stores, which are world-readable, and
nothing under `gt/`, so any account runs it. The trace root `gt/` itself is
`gt:gtring-trace 0750` with `0640` files: it names every peer that presented
a certificate, and only the four observers read it, through the group
`gtring-trace`. An operator who needs the trace (`gt/<boot>/*.trace`,
`gt/chains/`) must be in `gtring-trace` or be root, and so must the account
that copies the whole tree below; without the group `cp -r` copies the four
stores and fails on `gt/`, which `ringstatus` does not need. Joining the
group means reading every client's certificate: keep it to the accounts that
must (deploy/README.md, "The trace root is group-readable").

### Pointing it at a copied tree

Copy the whole tree (`cp -r /var/lib/ghostunnel-ring/stores /tmp/ring-snapshot`)
and pass `-stores /tmp/ring-snapshot` or set `GHOSTUNNEL_RING_STORES`. This is
how to look at a deployment that has since been restarted, or to see what a
halt renders like without causing one. Ages are measured against the clock now,
so on a copy every LAST BEAT will be old; that is the copy, not the ring.

## Reading a frame

### The verdict banner

Taken from the files, not computed: a halt in force is a halt in force whatever
this tool thinks of anybody's freshness.

- **RING HALTED**: some member holds a `halt` file, or has a slot delivered
  into its `halts/`. The reason, subject, finder and age come from whichever
  halt file or slot carries them (a slot is the raiser's own bytes, so it
  answers when the raiser's file is gone). `N of 4 members stopped` counts every
  member whose gate is refusing, which is every member with a halt file *or* a
  slot: only the raiser writes a halt file of its own, everybody else is stopped
  by the slot. When no halt file or slot can be parsed the line reads
  `unknown, found by a member`, with `(halt file unreadable)` appended: a
  halt that will not parse is still a halt here.
- **RING INCOMPLETE**: some member has no readable heartbeat. The newest entry in
  its folder is missing, will not open, or does not parse.
- **RING CLEAR**: neither of the above.

### The members table

Display order is `super` first, then `tunnel`, `admin`, `material`. The
coordinator leads because it holds the whole view and its absence alone stops
everything. The ring's own order is identity order; nothing here changes it.

| column | what it is |
|---|---|
| **STATE** | `fault` (red): this member found something wrong; the `failing:` line beneath lists it as `check:subject` (no line when the list is empty; `failing: (fault file unreadable)` when the file will not parse). `halt` (red): stopped on something another member found (a halt file *or* a delivered slot, because that is what the gate reads). `stopped` (amber): its own heartbeat says `stop`. `clear` (green): nothing wrong here. `· booted` (amber) is appended when the heartbeat carries a boot record. Fault is checked before halt, because the raiser has both. The column is 16 wide, and `stopped · booted` fills it, so that label runs into SEQUENCE. |
| **SEQUENCE** | the newest heartbeat's sequence number |
| **LAST BEAT** | the newest heartbeat's age. Green inside two cadences, amber past two, red past six. `bad time` when the timestamp will not parse. The gates' own windows decide what counts; these colours are for reading. |
| **CYCLE** | seconds per cycle, measured between two samplings of the sequence number a known interval apart, against the cadence ceiling: `0.3s/5s`. Green under 70% of the ceiling, amber above, red at or over. `--` when there is no rate yet, or the sequence did not move. The cadence is a ceiling, not a pace, so a number creeping up on it is the warning that arrives before the halt does. |
| **OBSERVING** | wall-clock since the member's `since` file, which it writes once and never rewrites. `--` in red when the file is absent or not exactly `YYYY-MM-DDTHH:MM:SSZ` plus one line feed, round-tripped. It is the one durable record of how long a store has been observed; a count of cycles is not a unit of time. |
| **CHECKS** | `check_count` from the heartbeat |

A member with no readable heartbeat shows `no heartbeat` and nothing else.

### EDGES

`who has read whose heartbeat, and how recently. The row is the one doing the
reading.` Each member records, in its own heartbeat, the hash of the heartbeat
it read from every other member: bytes it could not produce without having
looked. The row is the reader, the column is the subject, and the recorded hash
is searched for among the files of the subject's folder that can be read, as it
stands now.

The legend, verbatim:

| cell | meaning |
|---|---|
| `ok` | read the newest one |
| `-1` | read the one before that. Normal: they do not run in step |
| `-2` | two behind, and so on |
| `past` | read something so old it has been deleted since |
| `none` | has not read it at all. Not normal |

`past` is also what a disagreement looks like, and what an entry this tool
could not open looks like: a hash that is not among the readable files is
`past`, whatever the reason. **This tool cannot tell those apart**; the member's
own chain check can, and its fault file above is the answer.

The diagonal `·` cell is padded one column short of the others: padding counts
bytes, and the middle dot is two.

### COPIES

`each member writes its heartbeat a second time into another member's folder,
and that member checks the copy against the original.` Every structural member
writes into one peer's `copy/` (`material` writes into `tunnel/copy`, `tunnel`
into `admin/copy`, `admin` into `material/copy`) and into `super/copy-<self>/`;
`super` writes `copy-super/` into all three. The holder checks the copy against
the author's own store, so an author publishing one thing at home and another
to its peer is caught by the peer.

| cell | meaning |
|---|---|
| `ok` | the newest copy's bytes are in the author's own folder |
| `past` | they are not: pruned since, or never the same |
| `empty` | nothing copied, or no folder |
| `unreadable` | the newest copy could not be opened |

The header counts `all 9 match` or `k of 9 match`; each row reads `from
<author>`.

### HALT SLOTS

`delivered into a store by members that cannot be overwritten by its holder.`
Shown only when a slot is in force somewhere. A slot is a halt delivered into a
member's `halts/` by another member, at a path the holder cannot write, so a
compromised member cannot delete the news about itself. Each row reads `from
<deliverer>` or `none`.

## What it never does

- Opens nothing for writing, creates nothing, deletes nothing, anywhere.
- Joins no ring, publishes no heartbeat, delivers no halt, clears nothing.
- Imports nothing from the member packages: the little parsing it needs is its
  own, deliberately loose, because the members validate their files strictly
  and this tool only displays what they wrote. It does require each file's kind
  marker, since a file in a heartbeat folder that does not begin with the
  heartbeat marker is not a heartbeat.
- Talks to no network and needs no container.
