# bench: base ghostunnel against the fork

A standard-library Go tool that checks out two refs of this repository,
builds each into a real `ghostunnel server`, drives both with the same
client, and prints the numbers side by side. It also runs the trees' own Go
benchmarks unless told `-skip-gobench`. It is its own Go module, nested
here so its build stays out of the main module and `vendor/`.

Nothing leaves the machine unless you point it at a remote echo. It writes
only under its work directory.

## Run

From the repository root:

    go -C bench run . -quick -skip-gobench   a first look: count 2, 100 connections, 16 MiB
    go -C bench run .                        the full run: count 5, 300 connections, 64 MiB, Go benchmarks

The report goes to stdout and to `bench/work/results/<stamp>.txt`, with
`<stamp>` the start time as `YYYYMMDD-HHMMSS`. Raw `go test -bench` output,
when taken, lands beside it as `<stamp>-base-gobench.txt` and
`<stamp>-fork-gobench.txt`.

## What it measures

Both trees are started first and stay up for the whole run. Each `-count`
run then takes, through one tree's proxy:

- churn: `-conns` sequential connections, each a TLS handshake, 64 bytes
  written, 64 bytes read back, close. Reported as connections per second
  and the p50, p95, p99 and max wall time per connection in milliseconds.
- bulk: `-bulk` MiB streamed through one connection and read back, in
  MiB/s.
- concurrent x16: `-conns` connections split across sixteen workers,
  reported as connections per second with p99 and max.

The report shows the median of the runs per row, the delta of fork against
base in percent, and the count of connections that failed and were retried
(up to four attempts each), so a pressured host is visible in the table.

After the fork's runs the tool sizes the trace the fork left under `gt/`:
bytes and lines, and both per connection served. A segment counts only its
content, the bytes before the first NUL, because the fork pre-extends
segments.

Unless `-skip-gobench`, the tool also finds every package in each tree with
a `func Benchmark` outside `vendor/`, runs `go test -run '^$' -bench .
-benchmem -count N` there, and tabulates the median ns/op, B/op and
allocs/op per benchmark. Benchmarks present in one tree only are marked.
The end-to-end measurement runs first: the trees' own connection-churn
benchmarks leave thousands of sockets in TIME_WAIT, which would poison
whichever tree was measured next. The Go benchmarks add many minutes;
`-skip-e2e` is the other way round and skips the end-to-end measurement.

## How the trees are built

1. `git worktree add --detach <work>/base <base-ref>` and the same for
   `<work>/fork <fork-ref>`, from `-repo`. A stale worktree at either path
   is removed first, so the checkout is always fresh. The report prints
   both commits: hash, date, subject.
2. `go build` of each tree's main package into `<work>/<tree>/`.
3. A throwaway PKI in `<work>/pki/`: a CA, a server leaf for `localhost`,
   a client leaf.
4. A TCP echo in the tool's own process on a kernel-assigned loopback port,
   unless `-backend` names one elsewhere.
5. Each proxy on kernel-assigned loopback ports (`--listen`, `--status`)
   with `--allow-all` and the PKI. The fork also gets a store tree under
   `<work>/fork/tree/` (four member stores and the `gt/` trace root) and
   `--ring-traces`, `--ring-stores`, `--ring-heartbeat-max-age 30s`. The
   tool publishes the coordinator's heartbeat every 2 s in the format the
   fork's gate parses, so the fork serves. Off Linux the fork also gets
   `--accept-no-sandbox=<GOOS>`; on Linux it gets no acceptance flag, and
   landlock must be enforced.

A tree that does not build or does not serve is reported as not measured,
with the gate's last refusal line when the fork logged one. The tool exits
non-zero only on its own failures: git, the PKI, the echo, writing results.

## Options

| flag | default | meaning |
|---|---|---|
| `-repo PATH` | the repository this tool lives in | holds both refs |
| `-base REF` | `git merge-base <fork> origin/master` | the base tree |
| `-fork REF` | `portal` | the fork tree |
| `-work DIR` | `bench/work/` | everything the run writes |
| `-count N` | 5 | runs per measurement and per benchmark; medians reported |
| `-conns N` | 300 | connections per churn and per concurrent run; at least 16 |
| `-bulk MiB` | 64 | bytes streamed in the bulk run |
| `-quick` | off | count 2, conns 100, bulk 16 |
| `-order abba\|sequential` | `abba` | run order, below |
| `-skip-gobench` | off | skip the trees' own Go benchmarks |
| `-skip-e2e` | off | skip the end-to-end measurement |
| `-fork-args "FLAGS"` | none | extra flags for the fork proxy only |
| `-backend HOST:PORT` | none | a remote echo instead of the loopback one |
| `-serve-echo ADDR` | none | be that echo on `ADDR` (`:9000`) and never return |

`-order abba` interleaves the runs: base, fork, fork, base, and so on.
What drifts over a run, above all the port pool filling with TIME_WAIT
sockets, then lands on both trees alike. `sequential` takes every base run
and then every fork run, kept so the two orders can be compared.

`-fork-args` passes flags to the fork alone, for example
`"--warm-backend-connections 16"`. The report then says it compares the
fork as configured against the base as it is. The fork chooses its warm
backend pool itself and logs the choice; the report's `fork-pool` line
repeats it.

`-backend` makes both proxies dial an echo on another host, so the dial
crosses the network the way a real backend's does. Both trees refuse a
plaintext target off loopback unless told `--unsafe-target`; the tool
passes it to both. Start the echo on the other host with
`go -C bench run . -serve-echo :9000` and give this host its address as
`-backend <private address>:9000`. The tool never checks the echo answers;
a tree that cannot reach it is reported as not measured.

## The report

The header names the run: start and end time, the host's OS, architecture,
CPU count and Go version, the repository, both commits, the flags, the run
order, `fork-args` and `fork-pool` when set, the backend (loopback or
remote), the work directory with its filesystem where that is cheap to
know (the `/proc/mounts` entry on Linux, the volume on Windows), and the
`fsync` line described below. Then the two tables, the trace line, and the
caveats: a loaded machine inflates both columns, a small `-count` still
moves between runs, and the end-to-end rows include what the fork does per
connection that the base does not.

## Host requirements

Go and git on the host. The module declares Go 1.27.

**A disk with fast fsync under `-work`.** The fork syncs its trace once per
connection, on the critical path. Before the run the tool appends 200 lines
of 80 bytes to a file in the work directory, syncing after each, and prints
the median on the report's `fsync` line. Above 1 ms it prints a warning and
the fork's end-to-end rows measure the disk, not the fork. A cloud root
volume typically syncs in 1 to 3 ms; a local NVMe device in under 0.2 ms.
Put `-work` on the fast disk. The default, `bench/work/`, is wherever the
clone is.

**Room in the ephemeral port pool.** Every connection leaves two sockets in
TIME_WAIT for 60 s: the client's and the proxy's to the backend. One run
at the default `-conns 300` makes about 600 connections, so about 1,200
sockets, and the default range holds about 28,000, so a long run slows
both trees' connects.
The tool interleaves the trees and, on Linux, waits before each run until
the count in `/proc/net/sockstat` is below 40% of `ip_local_port_range`
(up to 90 s; a run taken above the limit says so on its progress line). It
also waits until a burst of raw connects to the echo succeeds. The fix is
on the host:

    net.ipv4.ip_local_port_range = 10240 65535
    net.ipv4.tcp_tw_reuse = 1

Both apply to base and fork alike. Put them in a file under
`/etc/sysctl.d/` and load it with `sysctl --system`.

**Landlock enforced, on Linux.** The fork starts on Linux without an
acceptance flag only when the kernel enforces landlock:
`cat /sys/kernel/security/lsm` must list `landlock`. Otherwise the fork
refuses to start and the report carries the gate's reason. Off Linux the
tool passes `--accept-no-sandbox=<GOOS>` itself.

**A second host for the echo, when the dial should cross the network.**
Build the tool there, run `go -C bench run . -serve-echo :9000` (or build
a binary and start it under `nohup`), allow inbound TCP 9000 from the first
host, and pass `-backend <private address>:9000` on the first. The second
host needs neither a fast disk nor landlock. Check it listens before the
run: `ss -ltn | grep 9000`.

## The `box` subcommand: run on a remote host

`box` runs the tool on a remote host over ssh, fetches the report into
`bench/work/results/box-<stamp>.txt` beside this machine's own, and prints
it the way `ringstatus` prints the ring: one verdict badge, then the tables.
`-host` is required.

    go -C bench run ./box -host <address>                run end to end there, fetch, print
    go -C bench run ./box -host <address> -quick         the -quick run
    go -C bench run ./box -host <address> -gobench       include the Go benchmarks (adds minutes)
    go -C bench run ./box -host <address> -latest        fetch and print the newest report, no run
    go -C bench run ./box -host <address> -fetch STAMP   one report by its stamp
    go -C bench run ./box -render FILE                   print a report already here, no ssh

The verdict comes from the two rows that decide it: churn p50, what one
connection pays for the ring, and concurrent x16 connections per second,
what the host does under load. Green is the fork better by more than the
3% noise band, red worse, grey inside it. A report carrying the fsync
warning is marked disk bound instead.

| flag | default | meaning |
|---|---|---|
| `-host` | none, required | the remote host: an address or an ssh alias |
| `-user` | `ubuntu` | the ssh user |
| `-key FILE` | none | ssh private key; empty leaves the choice to ssh |
| `-remote-repo` | `~/ghostunnel` | the clone on the remote host |
| `-remote-bench` | `<remote-repo>/bench` | this tool on the remote host |
| `-remote-work` | the tool's own default | the run's `-work` there; put it on the fast disk |
| `-base`, `-fork` | the tool's defaults | the refs |
| `-quick`, `-count`, `-order`, `-fork-args`, `-backend` | | passed through |
| `-gobench` | off | the Go benchmarks are opt-in over ssh |
| `-latest`, `-fetch STAMP`, `-render FILE` | | fetch or print without running |
| `-no-color` | off | plain text; `NO_COLOR` in the environment does the same |

The remote command is `cd <remote-bench> && go run . <flags>` with
`/usr/local/go/bin` appended to the PATH, so a Go installed there or already
on the PATH both work. Every flag value is quoted as one word for the remote
shell, spaces and quotes included, and a bare `~` or a leading `~/` still
expands there. A remote path must be absolute, `~`, or start with `~/`;
anything else is refused before ssh or scp runs. On Windows, Git Bash
rewrites an argument such as `/var/lib/x` into a Windows path before the
tool sees it, which that check catches; set `MSYS_NO_PATHCONV=1` for the
command. The run stays in the foreground of the ssh session: closing the
session kills it. A run that must outlive this machine is started on the
remote host with `nohup` and collected afterwards with `-latest`.

## Preparing a remote host

1. Install git and Go. Confirm `go version`.
2. Give the work directory a fast disk: format the local device, mount it
   with `noatime`, and create a directory there owned by the ssh user. Pass
   it as `-remote-work`. A local instance disk is usually wiped when the
   machine is stopped; that is fine for a benchmark host.
3. Confirm `cat /sys/kernel/security/lsm` lists `landlock`.
4. Set the two sysctls above.
5. Clone the repository to `~/ghostunnel` (or another path, given as
   `-remote-repo`) with both refs present. Where the clone has no
   `origin/master`, pass `-base` explicitly.
6. Check the tree builds there: `go build ./...` in the clone.
7. For a network backend, prepare a second host with the same clone, start
   the echo there, and open its port to the first host.

Then, from this machine, `go -C bench run ./box -host <address> -quick`
for a first look.
