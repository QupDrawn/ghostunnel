package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	churnPayload = 64
	concWorkers  = 16
	bulkChunk    = 64 << 10
)

// latencyStat is one churn-style measurement's summary.
type latencyStat struct {
	connsPerSec, p50, p95, p99, max float64 // ms except the rate
}

// e2eResult holds the medians across runs for one tree.
type e2eResult struct {
	churn      latencyStat
	bulkMiBps  float64
	conc       latencyStat
	totalConns int   // connections made against this tree, all runs
	retries    int64 // connections retried after a failure, all runs
}

// echoServer is the plain TCP backend both proxies forward to.
type echoServer struct {
	ln   net.Listener
	addr string
	wg   sync.WaitGroup
}

// loopbackAny is the loopback interface with a kernel-assigned port.
var loopbackAny = net.JoinHostPort(net.IPv4(127, 0, 0, 1).String(), "0")

func startEcho() (*echoServer, error) { return startEchoOn(loopbackAny) }

// startEchoOn serves the echo on addr; ":9000" makes this process the
// backend of a run on another host (-serve-echo).
func startEchoOn(addr string) (*echoServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	e := &echoServer{ln: ln, addr: ln.Addr().String()}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.wg.Add(1)
			go func() {
				defer e.wg.Done()
				defer c.Close()
				buf := make([]byte, bulkChunk)
				_, _ = io.CopyBuffer(c, c, buf)
			}()
		}
	}()
	return e, nil
}

func (e *echoServer) Close() {
	if e.ln != nil {
		e.ln.Close()
	}
}

// freePorts asks the kernel for n distinct free loopback ports, holding
// all of them open until every one is chosen (a port released and asked
// for again comes back the same on Windows), then releases them. The
// proxy binds them moments later; a collision would show as a start
// failure, which is reported.
func freePorts(n int) ([]string, error) {
	var lns []net.Listener
	defer func() {
		for _, ln := range lns {
			ln.Close()
		}
	}()
	addrs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", loopbackAny)
		if err != nil {
			return nil, err
		}
		lns = append(lns, ln)
		addrs = append(addrs, ln.Addr().String())
	}
	return addrs, nil
}

func binaryName() string {
	if runtime.GOOS == "windows" {
		return "ghostunnel.exe"
	}
	return "ghostunnel"
}

// buildBinary builds the tree's main package into work/<tree>/.
func buildBinary(tree, outDir string) (string, error) {
	out := filepath.Join(outDir, binaryName())
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = tree
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go build: %v\n%s", err, strings.TrimSpace(buf.String()))
	}
	return out, nil
}

// proxyProc is a running ghostunnel server.
type proxyProc struct {
	cmd     *exec.Cmd
	listen  string
	status  string
	logPath string
	logFile *os.File
	exited  chan error
	once    sync.Once
}

func startProxy(binary, logPath string, args []string, listen, status string) (*proxyProc, error) {
	lf, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(binary, args...)
	cmd.Stdout, cmd.Stderr = lf, lf
	dieWithTool(cmd)
	p := &proxyProc{cmd: cmd, listen: listen, status: status, logPath: logPath, logFile: lf, exited: make(chan error, 1)}
	if err := startChild(cmd, p); err != nil {
		lf.Close()
		return nil, err
	}
	go func() { p.exited <- cmd.Wait() }()
	return p, nil
}

// waitListening dials the listener until it accepts, the process exits, or
// the deadline passes.
func (p *proxyProc) waitListening(deadline time.Duration) error {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		select {
		case err := <-p.exited:
			p.exited <- err
			return fmt.Errorf("the process exited before listening: %v\n%s", err, p.tail(20))
		default:
		}
		c, err := net.DialTimeout("tcp", p.listen, 500*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("the listener at %s did not accept within %s\n%s", p.listen, deadline, p.tail(20))
}

// stop kills the process (if it is still running) and waits for it; safe
// to call more than once.
func (p *proxyProc) stop() {
	p.once.Do(func() {
		select {
		case err := <-p.exited:
			p.exited <- err
		default:
			_ = p.cmd.Process.Kill()
			err := <-p.exited
			p.exited <- err
		}
		p.logFile.Close()
		releaseChild(p)
	})
}

// tail returns the last n lines of the process log.
func (p *proxyProc) tail(n int) string {
	data, err := os.ReadFile(p.logPath)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\r\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// warmPoolLine is what the fork logged about its warm backend pool at
// startup ("warm backend pool: ..."), or "" for a tree that logs none.
func (p *proxyProc) warmPoolLine() string {
	data, err := os.ReadFile(p.logPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "warm backend pool: "); i >= 0 {
			return strings.TrimSpace(line[i+len("warm backend pool: "):])
		}
	}
	return ""
}

// gateReasons returns the ring's refusal lines from the process log.
func (p *proxyProc) gateReasons() []string {
	data, err := os.ReadFile(p.logPath)
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if strings.Contains(sc.Text(), "refusing connection") {
			out = append(out, strings.TrimSpace(sc.Text()))
		}
	}
	return out
}

// client is the measuring side, shared by both trees.
type client struct {
	cfg  *tls.Config
	addr string
	// retries counts connections that failed and were retried: a loopback
	// hiccup (ephemeral-port exhaustion after thousands of short-lived
	// connections is the usual one) reaches the client as an EOF or a
	// refused dial, from either tree alike.
	retries atomic.Int64
}

const connAttempts = 4

// connRetry runs oneConn up to connAttempts times, counting retries.
func (c *client) connRetry(payload []byte) (time.Duration, error) {
	var err error
	for attempt := 1; attempt <= connAttempts; attempt++ {
		var d time.Duration
		d, err = c.oneConn(payload)
		if err == nil {
			return d, nil
		}
		if attempt < connAttempts {
			c.retries.Add(1)
			time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
		}
	}
	return 0, fmt.Errorf("after %d attempts: %w", connAttempts, err)
}

func newClient(p *pki, addr string) *client {
	return &client{addr: addr, cfg: &tls.Config{
		RootCAs:      p.caPool,
		Certificates: []tls.Certificate{p.clientCert},
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}}
}

// oneConn dials, handshakes, sends 64 bytes, reads the echo and closes,
// returning the wall time of the whole exchange.
func (c *client) oneConn(payload []byte) (time.Duration, error) {
	start := time.Now()
	d := &net.Dialer{Timeout: 30 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", c.addr, c.cfg)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return 0, err
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, fmt.Errorf("reading the echo: %w", err)
	}
	if !bytes.Equal(buf, payload) {
		return 0, errors.New("echo mismatch")
	}
	return time.Since(start), nil
}

func summarize(durs []time.Duration, wall time.Duration) latencyStat {
	s := append([]time.Duration(nil), durs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	pct := func(p float64) float64 {
		if len(s) == 0 {
			return 0
		}
		i := int(float64(len(s))*p+0.999999) - 1
		if i < 0 {
			i = 0
		}
		if i >= len(s) {
			i = len(s) - 1
		}
		return float64(s[i]) / float64(time.Millisecond)
	}
	st := latencyStat{p50: pct(0.50), p95: pct(0.95), p99: pct(0.99)}
	if len(s) > 0 {
		st.max = float64(s[len(s)-1]) / float64(time.Millisecond)
	}
	if wall > 0 {
		st.connsPerSec = float64(len(s)) / wall.Seconds()
	}
	return st
}

// churn: n sequential connections.
func (c *client) churn(n int) (latencyStat, error) {
	payload := bytes.Repeat([]byte("x"), churnPayload)
	durs := make([]time.Duration, 0, n)
	start := time.Now()
	for i := 0; i < n; i++ {
		d, err := c.connRetry(payload)
		if err != nil {
			return latencyStat{}, fmt.Errorf("connection %d: %w", i+1, err)
		}
		durs = append(durs, d)
	}
	return summarize(durs, time.Since(start)), nil
}

// concurrent: workers goroutines, each doing n/workers sequential connections.
func (c *client) concurrent(n, workers int) (latencyStat, error) {
	payload := bytes.Repeat([]byte("y"), churnPayload)
	per := n / workers
	var mu sync.Mutex
	var durs []time.Duration
	var firstErr error
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]time.Duration, 0, per)
			for i := 0; i < per; i++ {
				d, err := c.connRetry(payload)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}
				local = append(local, d)
			}
			mu.Lock()
			durs = append(durs, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return latencyStat{}, firstErr
	}
	return summarize(durs, time.Since(start)), nil
}

// bulk streams mib MiB through one connection and reads it all back.
func (c *client) bulk(mib int) (float64, error) {
	total := int64(mib) << 20
	d := &net.Dialer{Timeout: 30 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", c.addr, c.cfg)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	chunk := make([]byte, bulkChunk)
	for i := range chunk {
		chunk[i] = byte(i*7 + 3)
	}
	start := time.Now()
	werr := make(chan error, 1)
	go func() {
		var sent int64
		for sent < total {
			n := int64(len(chunk))
			if total-sent < n {
				n = total - sent
			}
			if _, err := conn.Write(chunk[:n]); err != nil {
				werr <- err
				return
			}
			sent += n
		}
		werr <- nil
	}()
	buf := make([]byte, bulkChunk)
	var got int64
	for got < total {
		n, err := conn.Read(buf)
		got += int64(n)
		if err != nil {
			if got >= total {
				break
			}
			return 0, fmt.Errorf("reading the echo after %d bytes: %w", got, err)
		}
	}
	if err := <-werr; err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	return float64(mib) / elapsed.Seconds(), nil
}

// runE2E builds both binaries, generates the PKI, starts the echo and
// measures each tree through its own proxy. A tree that cannot be built
// or does not serve is recorded on the tree and skipped.
func runE2E(o *options, trees []*treeResult) error {
	work := o.work
	p, err := generatePKI(filepath.Join(work, "pki"))
	if err != nil {
		return fmt.Errorf("pki: %w", err)
	}
	var echo *echoServer
	if o.backend != "" {
		// A remote echo, started on another host with -serve-echo: the
		// proxies' dial then crosses the network, which is what a real
		// backend costs. Nothing here checks it answers; a tree that
		// cannot reach it is reported as not measured.
		echo = &echoServer{addr: o.backend}
		progress("echo backend is remote at %s", echo.addr)
	} else {
		e, err := startEcho()
		if err != nil {
			return fmt.Errorf("echo backend: %w", err)
		}
		echo = e
		progress("echo backend on %s", echo.addr)
	}
	defer echo.Close()

	// Both proxies are started first and stay up, idle, while the other is
	// measured; the runs are then taken in the order -order says. The
	// default interleaves them, base-fork-fork-base-..., so that anything
	// drifting over the minutes of a run (the ephemeral port pool filling
	// with TIME_WAIT sockets, the CPU's clock and thermal state, the page
	// cache) lands on both trees alike instead of on whichever ran second.
	// "sequential" is the older order, every run of one tree and then every
	// run of the other, kept so the two can be compared.
	var running []*runningTree
	for _, t := range trees {
		if err := waitLoopbackSettled(echo.addr, 4*time.Minute); err != nil {
			return err
		}
		rt, err := startTree(o, t, p, echo)
		if err != nil {
			t.e2eErr = err
			progress("%s: end to end not possible on this host: %v", t.name, err)
			continue
		}
		running = append(running, rt)
	}
	defer func() {
		for _, rt := range running {
			rt.stop()
		}
	}()
	take := func(rt *runningTree, i int) error {
		if rt.t.e2eErr != nil {
			return nil
		}
		if err := waitLoopbackSettled(echo.addr, 4*time.Minute); err != nil {
			return err
		}
		waitTimeWaitDrained(rt.t.name)
		if err := rt.runOnce(i); err != nil {
			rt.t.e2eErr = err
			progress("%s: end to end not possible on this host: %v", rt.t.name, err)
		}
		return nil
	}
	if o.order == "sequential" {
		for _, rt := range running {
			for i := 1; i <= o.count; i++ {
				if err := take(rt, i); err != nil {
					return err
				}
			}
		}
	} else {
		for i := 1; i <= o.count; i++ {
			order := running
			if i%2 == 0 {
				order = reversed(running)
			}
			for _, rt := range order {
				if err := take(rt, i); err != nil {
					return err
				}
			}
		}
	}
	for _, rt := range running {
		if rt.t.e2eErr != nil {
			continue
		}
		if err := rt.finish(); err != nil {
			rt.t.e2eErr = err
			progress("%s: %v", rt.t.name, err)
		}
	}
	return nil
}

// A run is not started while too many sockets are in TIME_WAIT: every connection the bench makes leaves one behind for 60 s
// (the client's, on loopback, and the proxy's to the backend), and once
// enough of the ephemeral port range is held that way, connects slow down
// for both trees alike, and the tree measured later pays it. A run waits,
// up to timeWaitPatience, for the count to fall below the limit.
const (
	timeWaitFraction = 0.4 // of the ephemeral port range
	timeWaitFallback = 10000
	timeWaitPatience = 90 * time.Second
)

// timeWaitLimit is the count a run waits below: a fraction of the host's
// ephemeral port range (/proc/sys/net/ipv4/ip_local_port_range on Linux;
// connects slow down for both trees once the range is nearly all held), or
// a fallback where the range cannot be read.
func timeWaitLimit() int {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return timeWaitFallback
	}
	f := strings.Fields(string(data))
	if len(f) != 2 {
		return timeWaitFallback
	}
	lo, err1 := strconv.Atoi(f[0])
	hi, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || hi <= lo {
		return timeWaitFallback
	}
	return int(float64(hi-lo) * timeWaitFraction)
}

// timeWaitCount is the host's count of sockets in TIME_WAIT, from
// /proc/net/sockstat on Linux ("TCP: inuse N orphan N tw N ..."); -1 where
// it cannot be read (other platforms), which disables the wait.
func timeWaitCount() int {
	data, err := os.ReadFile("/proc/net/sockstat")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "TCP:") {
			continue
		}
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "tw" {
				n, err := strconv.Atoi(f[i+1])
				if err != nil {
					return -1
				}
				return n
			}
		}
	}
	return -1
}

// waitTimeWaitDrained holds the next run of tree until the host's TIME_WAIT
// count is below timeWaitLimit, or timeWaitPatience has passed, and says
// what it found; the count is printed on the run's line either way.
func waitTimeWaitDrained(tree string) {
	n := timeWaitCount()
	limit := timeWaitLimit()
	if n < 0 || n < limit {
		return
	}
	progress("%s: %d sockets in TIME_WAIT, above %d (%.0f%% of the ephemeral port range); waiting for the pool to drain", tree, n, limit, timeWaitFraction*100)
	deadline := time.Now().Add(timeWaitPatience)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		if n = timeWaitCount(); n < limit {
			progress("%s: %d in TIME_WAIT; going on", tree, n)
			return
		}
	}
	progress("%s: still %d in TIME_WAIT after %s; measuring anyway, this run is suspect", tree, n, timeWaitPatience)
}

func reversed(in []*runningTree) []*runningTree {
	out := make([]*runningTree, len(in))
	for i, rt := range in {
		out[len(in)-1-i] = rt
	}
	return out
}

// runningTree is one tree's proxy, started and probed, with the runs taken
// so far.
type runningTree struct {
	o      *options
	t      *treeResult
	proc   *proxyProc
	hb     *heartbeatPublisher
	tree   *storeTree
	client *client
	listen string
	res    *e2eResult
	churns []latencyStat
	concs  []latencyStat
	bulks  []float64
}

// startTree builds the tree's binary, starts its proxy against the echo
// and probes it once; the fork serves only once its gate accepts the tree.
func startTree(o *options, t *treeResult, p *pki, echo *echoServer) (*runningTree, error) {
	progress("%s: go build", t.name)
	bin, err := buildBinary(t.dir, filepath.Join(o.work, t.name))
	if err != nil {
		return nil, err
	}
	ports, err := freePorts(2)
	if err != nil {
		return nil, err
	}
	listen, status := ports[0], ports[1]
	args := []string{"server",
		"--listen", listen,
		"--target", echo.addr,
	}
	if o.backend != "" {
		// A plaintext target off loopback is refused by both trees unless
		// the operator says so; the remote echo is exactly that.
		args = append(args, "--unsafe-target")
	}
	args = append(args,
		"--cert", p.serverPEM,
		"--key", p.serverKeyPEM,
		"--cacert", p.caPEM,
		"--allow-all",
		"--status", status,
	)
	var hb *heartbeatPublisher
	var tree *storeTree
	if t.name == "fork" {
		tree, err = buildStoreTree(filepath.Join(o.work, "fork", "tree"))
		if err != nil {
			return nil, err
		}
		hb, err = startHeartbeats(tree)
		if err != nil {
			return nil, fmt.Errorf("heartbeat publisher: %w", err)
		}
		args = append(args,
			"--ring-traces", tree.gt,
			"--ring-stores", tree.root,
			"--ring-heartbeat-max-age", "30s",
		)
		if runtime.GOOS != "linux" {
			args = append(args, "--accept-no-sandbox="+runtime.GOOS)
		}
		if o.forkArgs != "" {
			args = append(args, strings.Fields(o.forkArgs)...)
		}
	}
	progress("%s: starting %s %s", t.name, filepath.Base(bin), strings.Join(args, " "))
	proc, err := startProxy(bin, filepath.Join(o.work, t.name, "proxy.log"), args, listen, status)
	if err != nil {
		if hb != nil {
			hb.Stop()
		}
		return nil, err
	}
	rt := &runningTree{o: o, t: t, proc: proc, hb: hb, tree: tree, listen: listen, res: &e2eResult{totalConns: 1}}
	if err := proc.waitListening(30 * time.Second); err != nil {
		rt.stop()
		return nil, err
	}

	c := newClient(p, listen)
	rt.client = c
	// First probe: the fork serves only once its gate accepts the tree.
	var probeErr error
	for attempt := 1; attempt <= 10; attempt++ {
		_, probeErr = c.oneConn(bytes.Repeat([]byte("p"), churnPayload))
		if probeErr == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if probeErr != nil {
		reasons := proc.gateReasons()
		msg := fmt.Sprintf("the first probe connection failed: %v", probeErr)
		if len(reasons) > 0 {
			msg += "\n  gate: " + reasons[len(reasons)-1]
		} else {
			msg += "\n  log tail:\n" + proc.tail(10)
		}
		rt.stop()
		return nil, errors.New(msg)
	}
	progress("%s: serving on %s; %d run(s) to take", t.name, listen, o.count)
	return rt, nil
}

// runOnce takes run i: one churn, one bulk stream, one concurrent burst.
func (rt *runningTree) runOnce(i int) error {
	o, c, proc, res := rt.o, rt.client, rt.proc, rt.res
	ch, err := c.churn(o.conns)
	if err != nil {
		return fmt.Errorf("churn run %d: %w (gate: %s)", i, err, lastOr(proc.gateReasons(), "none logged"))
	}
	res.totalConns += o.conns
	bk, err := c.bulk(o.bulkMiB)
	if err != nil {
		return fmt.Errorf("bulk run %d: %w", i, err)
	}
	res.totalConns++
	cc, err := c.concurrent(o.conns, concWorkers)
	if err != nil {
		return fmt.Errorf("concurrent run %d: %w (gate: %s)", i, err, lastOr(proc.gateReasons(), "none logged"))
	}
	res.totalConns += (o.conns / concWorkers) * concWorkers
	rt.churns, rt.bulks, rt.concs = append(rt.churns, ch), append(rt.bulks, bk), append(rt.concs, cc)
	tw := ""
	if n := timeWaitCount(); n >= 0 {
		tw = fmt.Sprintf("; %d in TIME_WAIT after", n)
	}
	progress("%s: run %d/%d: churn %.1f conns/s p99 %.2f ms; bulk %.1f MiB/s; concurrent %.1f conns/s p99 %.2f ms%s",
		rt.t.name, i, o.count, ch.connsPerSec, ch.p99, bk, cc.connsPerSec, cc.p99, tw)
	return nil
}

// finish takes the medians, stops the proxy and, for the fork, sizes the
// trace it left.
func (rt *runningTree) finish() error {
	res, t := rt.res, rt.t
	res.churn = medianLatency(rt.churns)
	res.conc = medianLatency(rt.concs)
	res.bulkMiBps = median(rt.bulks)
	res.retries = rt.client.retries.Load()
	if res.retries > 0 {
		progress("%s: %d connection(s) were retried after a failure", t.name, res.retries)
	}
	t.e2e = res

	if t.name == "fork" {
		t.pool = rt.proc.warmPoolLine()
	}
	rt.stop()
	if rt.hb != nil {
		if err := rt.hb.err(); err != nil {
			progress("fork: heartbeat publisher reported: %v", err)
		}
		st, err := measureTraceContent(rt.tree.gt)
		if err != nil {
			return fmt.Errorf("measuring the trace: %w", err)
		}
		t.trace = st
		progress("fork: trace %s bytes, %s lines in %d file(s)", commas(st.bytes), commas(st.lines), st.files)
	}
	return nil
}

// stop ends the proxy and the heartbeat publisher; safe to call twice.
func (rt *runningTree) stop() {
	if rt.proc != nil {
		rt.proc.stop()
	}
	if rt.hb != nil {
		rt.hb.Stop()
	}
}

// traceContentChunk is the bounded read measureTraceContent makes of each
// segment: it reads at most this much past a segment's content.
const traceContentChunk = 1 << 20

// measureTraceContent sizes the fork's trace after a run by the segment
// rule of the fork's ringtrace (README.md section 1.3): a segment's
// content is its bytes before the first NUL byte, or all of its bytes when
// it has none; bytes from the first NUL onward are unwritten space of a
// pre-extended segment and are not part of the trace. Each segment is read
// in bounded chunks from its start, stopping at the first chunk holding a
// NUL or at end of file, so a live segment pre-extended to 64 MiB is
// neither read whole nor counted whole. The bench cannot import the fork
// (a separate module, checked out at run time), so the rule is repeated
// here.
func measureTraceContent(gt string) (*traceStat, error) {
	st := &traceStat{}
	buf := make([]byte, traceContentChunk)
	err := filepath.WalkDir(gt, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		st.files++
		for {
			n, err := io.ReadFull(f, buf)
			chunk := buf[:n]
			if i := bytes.IndexByte(chunk, 0); i >= 0 {
				chunk = chunk[:i]
			}
			st.bytes += int64(len(chunk))
			st.lines += int64(bytes.Count(chunk, []byte("\n")))
			if len(chunk) < n || err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			if err != nil {
				return err
			}
		}
	})
	return st, err
}

// waitLoopbackSettled makes a burst of short loopback connections to addr
// and waits, up to max, until a whole burst succeeds. After a run that
// churned thousands of connections the ephemeral port pool is exhausted
// by sockets in TIME_WAIT, connects fail for a minute or more, and a
// measurement taken then would blame the tree for the host.
func waitLoopbackSettled(addr string, max time.Duration) error {
	const burst = 32
	end := time.Now().Add(max)
	warned := false
	for {
		failed := 0
		var lastErr error
		for i := 0; i < burst; i++ {
			c, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				failed++
				lastErr = err
				continue
			}
			c.Close()
		}
		if failed == 0 {
			if warned {
				progress("loopback settled")
			}
			return nil
		}
		if time.Now().After(end) {
			return fmt.Errorf("loopback did not settle within %s: %d of %d connects still fail: %v", max, failed, burst, lastErr)
		}
		if !warned {
			progress("loopback under pressure (%d of %d connects failed: %v); waiting for it to settle", failed, burst, lastErr)
			warned = true
		}
		time.Sleep(5 * time.Second)
	}
}

func lastOr(s []string, def string) string {
	if len(s) == 0 {
		return def
	}
	return s[len(s)-1]
}

func medianLatency(v []latencyStat) latencyStat {
	pick := func(f func(latencyStat) float64) float64 {
		vals := make([]float64, len(v))
		for i, s := range v {
			vals[i] = f(s)
		}
		return median(vals)
	}
	return latencyStat{
		connsPerSec: pick(func(s latencyStat) float64 { return s.connsPerSec }),
		p50:         pick(func(s latencyStat) float64 { return s.p50 }),
		p95:         pick(func(s latencyStat) float64 { return s.p95 }),
		p99:         pick(func(s latencyStat) float64 { return s.p99 }),
		max:         pick(func(s latencyStat) float64 { return s.max }),
	}
}
