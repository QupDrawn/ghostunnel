/*-
 * Copyright 2015 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ghostunnel/ghostunnel/auth"
	"github.com/ghostunnel/ghostunnel/certloader"
	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/ghostunnel/ghostunnel/proxy"
	"github.com/ghostunnel/ghostunnel/ringtrace"
	"github.com/ghostunnel/ghostunnel/socket"
	"github.com/ghostunnel/ghostunnel/wildcard"

	kingpin "github.com/alecthomas/kingpin/v2"
	graphite "github.com/cyberdelia/go-metrics-graphite"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	metrics "github.com/rcrowley/go-metrics"
	sqmetrics "github.com/square/go-sq-metrics"
	connectproxy "github.com/wrouesnel/go.connect-proxy-scheme"
	netproxy "golang.org/x/net/proxy"

	prometheusmetrics "github.com/deathowl/go-metrics-prometheus"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	version              = "master"
	defaultMetricsPrefix = "ghostunnel"
)

// Optional flags (enabled conditionally based on build)
var (
	keychainIdentity     *string //nolint:unused
	keychainIssuer       *string //nolint:unused
	keychainRequireToken *bool   //nolint:unused
	pkcs11Module         *string //nolint:unused
	pkcs11TokenLabel     *string //nolint:unused
	pkcs11PIN            *string //nolint:unused
	disableLandlock      *bool   //nolint:unused
)

// Main flags (always supported)
var (
	app = kingpin.New("ghostunnel", "A simple TLS proxy with mutual authentication for securing non-TLS services.")

	// Server flags
	serverCommand             = app.Command("server", "Server mode (TLS listener -> plain TCP/UNIX target).")
	serverListenAddress       = serverCommand.Flag("listen", "Address and port to listen on (can be HOST:PORT, unix:PATH, systemd:NAME or launchd:NAME).").PlaceHolder("ADDR").Required().String()
	serverForwardAddress      = serverCommand.Flag("target", "Address to forward connections to (can be HOST:PORT or unix:PATH).").PlaceHolder("ADDR").Required().String()
	serverStatusTargetAddress = serverCommand.Flag("target-status", "Address to target for status checking downstream healthchecks. Defaults to a TCP healthcheck if this flag is not passed.").Default("").String()
	serverProxyProtocol       = serverCommand.Flag("proxy-protocol", "Enable PROXY protocol v2 (connection info only, equivalent to --proxy-protocol-mode=conn).").Bool()
	serverProxyProtocolMode   = serverCommand.Flag("proxy-protocol-mode", "PROXY protocol v2 mode: conn (connection info only), tls (add TLS version/ALPN/SNI metadata), tls-full (add TLS metadata and client certificate). Mutually exclusive with --proxy-protocol.").Enum("conn", "tls", "tls-full")
	serverUnsafeTarget        = serverCommand.Flag("unsafe-target", "If set, does not limit target to localhost, 127.0.0.1, [::1], or UNIX sockets.").Bool()
	serverAllowAll            = serverCommand.Flag("allow-all", "Allow all clients, do not check client cert subject.").Bool()
	serverAllowedCNs          = serverCommand.Flag("allow-cn", "Allow clients with given common name (can be repeated).").PlaceHolder("CN").Strings()
	serverAllowedOUs          = serverCommand.Flag("allow-ou", "Allow clients with given organizational unit name (can be repeated).").PlaceHolder("OU").Strings()
	serverAllowedDNSs         = serverCommand.Flag("allow-dns", "Allow clients with given DNS subject alternative name (can be repeated).").PlaceHolder("DNS").Strings()
	serverAllowedIPs          = serverCommand.Flag("allow-ip", "").Hidden().PlaceHolder("SAN").IPList()
	serverAllowedURIs         = serverCommand.Flag("allow-uri", "Allow clients with given URI subject alternative name (can be repeated).").PlaceHolder("URI").Strings()
	serverAllowSpkiPin        = serverCommand.Flag("allow-spki-pin", "Allow clients matching the given SPKI pin of the form <algo>:<base64-digest> (repeatable, e.g. sha256:...). This is out-of-band key pinning: the client is authenticated by the pin alone. Its certificate chain, validity period, and hostname are not verified. Mutually exclusive with other access control flags.").PlaceHolder("PIN").Strings()
	serverAllowPolicy         = serverCommand.Flag("allow-policy", "Allow passing the location of an OPA bundle.").PlaceHolder("BUNDLE").String()
	serverAllowQuery          = serverCommand.Flag("allow-query", "Allow defining a query to validate against the client certificate and the Rego policy.").PlaceHolder("QUERY").String()
	serverDisableAuth         = serverCommand.Flag("disable-authentication", "Disable client authentication, no client certificate will be required.").Default("false").Bool()
	serverAutoACMEFQDN        = serverCommand.Flag("auto-acme-cert", "Automatically obtain a certificate via ACME for the specified FQDN").PlaceHolder("FQDN").String()
	serverAutoACMEEmail       = serverCommand.Flag("auto-acme-email", "Email address associated with all ACME requests").PlaceHolder("EMAIL").String()
	serverAutoACMEAgreedTOS   = serverCommand.Flag("auto-acme-agree-to-tos", "Agree to the Terms of Service of the ACME CA").Default("false").Bool()
	serverAutoACMEProdCA      = serverCommand.Flag("auto-acme-ca", "Specify the URL to the ACME CA. Defaults to Let's Encrypt if not specified.").PlaceHolder("https://some-acme-ca.example.com/").String()
	serverAutoACMETestCA      = serverCommand.Flag("auto-acme-testca", "Specify the URL to the ACME CA's Test/Staging environment. If set, all requests will go to this CA and --auto-acme-ca will be ignored.").PlaceHolder("https://testing.some-acme-ca.example.com/").String()
	// Hidden: override certmagic's background renewal-check interval. Only
	// used by the ACME integration test to observe renewal within seconds.
	serverAutoACMERenewCheckInterval = serverCommand.Flag("auto-acme-renew-check-interval", "").Hidden().Duration()
	// Hidden: override the port certmagic binds for TLS-ALPN-01 during
	// initial issuance. Production should use 443 so the public ACME CA can
	// reach it; the integration test sets this so it can run without root.
	serverAutoACMEAltTLSALPNPort = serverCommand.Flag("auto-acme-alt-tls-alpn-port", "").Hidden().Int()

	// Client flags
	clientCommand       = app.Command("client", "Client mode (plain TCP/UNIX listener -> TLS target).")
	clientListenAddress = clientCommand.Flag("listen", "Address and port to listen on (can be HOST:PORT, unix:PATH, systemd:NAME or launchd:NAME).").PlaceHolder("ADDR").Required().String()
	// Note: can't use .TCP() for clientForwardAddress because we need to set the original string in tls.Config.ServerName.
	clientForwardAddress = clientCommand.Flag("target", "Address to forward connections to (can be HOST:PORT or unix:PATH).").PlaceHolder("ADDR").Required().String()
	clientUnsafeListen   = clientCommand.Flag("unsafe-listen", "If set, does not limit listen to localhost, 127.0.0.1, [::1], or UNIX sockets.").Bool()
	clientServerName     = clientCommand.Flag("override-server-name", "If set, overrides the server name used for hostname verification.").PlaceHolder("NAME").String()
	clientProxy          = clientCommand.Flag("proxy", "If set, connect to target over given proxy (HTTP CONNECT or SOCKS5). Must be a proxy URL.").PlaceHolder("URL").URL()
	clientAllowedCNs     = clientCommand.Flag("verify-cn", "Allow servers with given common name (can be repeated).").PlaceHolder("CN").Strings()
	clientAllowedOUs     = clientCommand.Flag("verify-ou", "Allow servers with given organizational unit name (can be repeated).").PlaceHolder("OU").Strings()
	clientAllowedDNSs    = clientCommand.Flag("verify-dns", "Allow servers with given DNS subject alternative name (can be repeated).").PlaceHolder("DNS").Strings()
	clientAllowedIPs     = clientCommand.Flag("verify-ip", "").Hidden().PlaceHolder("SAN").IPList()
	clientAllowedURIs    = clientCommand.Flag("verify-uri", "Allow servers with given URI subject alternative name (can be repeated).").PlaceHolder("URI").Strings()
	clientVerifySpkiPin  = clientCommand.Flag("verify-spki-pin", "Verify the server matches the given SPKI pin of the form <algo>:<base64-digest> (repeatable, e.g. sha256:...). This is out-of-band key pinning: the server is authenticated by the pin alone. Its certificate chain, validity period, and hostname are not verified. Mutually exclusive with other verification flags.").PlaceHolder("PIN").Strings()
	clientAllowPolicy    = clientCommand.Flag("verify-policy", "Allow passing the location of an OPA bundle.").PlaceHolder("BUNDLE").String()
	clientAllowQuery     = clientCommand.Flag("verify-query", "Rego query to evaluate against the server certificate and the policy.").PlaceHolder("QUERY").String()
	clientDisableAuth    = clientCommand.Flag("disable-authentication", "Disable client authentication, no certificate will be provided to the server.").Default("false").Bool()
	// clientVerifyHostnameOnly is the operator's explicit statement that the
	// server is verified by its hostname alone (crypto/tls) and no --verify-*
	// rule is wanted; without it, client mode does not start without a rule.
	clientVerifyHostnameOnly = clientCommand.Flag("verify-hostname-only", "Verify the server by its hostname alone (the trust store and the server name), with no --verify-* rule. Client mode refuses to start without either this flag or at least one --verify-* rule; the flag is refused beside any --verify-* rule.").Default("false").Bool()

	// TLS options
	keystorePath          = app.Flag("keystore", "Path to keystore (combined PEM with cert/key, or PKCS12 keystore).").PlaceHolder("PATH").Envar("KEYSTORE_PATH").String()
	certPath              = app.Flag("cert", "Path to certificate (PEM with certificate chain).").PlaceHolder("PATH").Envar("CERT_PATH").String()
	keyPath               = app.Flag("key", "Path to certificate private key (PEM with private key).").PlaceHolder("PATH").Envar("KEY_PATH").String()
	keystorePass          = app.Flag("storepass", "Password for keystore (PKCS#12 or JCEKS; optional for PKCS#12).").PlaceHolder("PASS").Envar("KEYSTORE_PASS").String()
	caBundlePath          = app.Flag("cacert", "Path to CA bundle file (PEM/X509). Uses system trust store by default.").Envar("CACERT_PATH").String()
	useWorkloadAPI        = app.Flag("use-workload-api", "If true, certificate and root CAs are retrieved via the SPIFFE Workload API").Bool()
	useWorkloadAPIAddr    = app.Flag("use-workload-api-addr", "If set, certificates and root CAs are retrieved via the SPIFFE Workload API at the specified address (implies --use-workload-api)").Envar("SPIFFE_ENDPOINT_SOCKET").PlaceHolder("ADDR").String()
	useWorkloadAPITimeout = app.Flag("use-workload-api-timeout", "Timeout for the initial certificate fetch from the SPIFFE Workload API at startup (set to 0 to wait indefinitely)").Default("10m").Duration()
	alpn                  = app.Flag("alpn", "Set of protocols to negotiate via ALPN, comma-separated, in order of preference (e.g. h2,http/1.1).").PlaceHolder("PROTOS").String()

	// Deprecated cipher suite flags
	enabledCipherSuites     = app.Flag("cipher-suites", "Set of cipher suites to enable, comma-separated, in order of preference (AES, CHACHA).").Hidden().Default("AES,CHACHA").String()
	allowUnsafeCipherSuites = app.Flag("allow-unsafe-cipher-suites", "Allow cipher suites deemed to be unsafe to be enabled via the cipher-suites flag.").Hidden().Default("false").Bool()
	maxTLSVersion           = app.Flag("max-tls-version", "Maximum SSL/TLS version to use (TLS1.2, TLS1.3). If unset, uses the Go default.").Default("").Hidden().String()

	// Reloading and timeouts
	timedReload            = app.Flag("timed-reload", "Reload keystores every given interval (e.g. 300s), refresh listener/client on changes.").PlaceHolder("DURATION").Duration()
	processShutdownTimeout = app.Flag("shutdown-timeout", "Process shutdown timeout. Terminates after timeout even if connections still open.").Default("5m").Duration()
	connectTimeout         = app.Flag("connect-timeout", "Timeout for establishing connections, handshakes.").Default("10s").Duration()
	closeTimeout           = app.Flag("close-timeout", "Timeout for closing connections when one side terminates. Zero means immediate closure.").Default("60s").Duration()
	maxConnLifetime        = app.Flag("max-conn-lifetime", "Maximum lifetime for connections post handshake, no matter what. Zero means infinite.").Default("0s").Duration()
	maxConcurrentConns     = app.Flag("max-concurrent-conns", "Maximum number of concurrent connections to handle in the proxy. Zero means infinite.").Default("0").Uint32()
	copyBufferSize         = app.Flag("copy-buffer-size", "Size of each buffer the proxy forwards data with, one per direction per connection; memory for speed. Zero means the built-in default (64KiB).").Default("0").Bytes()
	socketBufferSize       = app.Flag("socket-buffer-size", "Kernel send and receive buffer size (SO_SNDBUF/SO_RCVBUF) for client and backend sockets. Zero (the default) leaves the OS default; Linux autotunes and an explicit size disables that.").Default("0").Bytes()
	warmBackendConnections = app.Flag("warm-backend-connections", "Keep this many pre-dialed connections to the backend open and idle, taken instead of dialing per connection and refilled in the background. Zero dials per connection. The default, -1, chooses: 64 for a server-mode target that is not loopback or a UNIX socket (where the dial is a network round trip), none otherwise.").Default("-1").Int()
	warmBackendIdle        = app.Flag("warm-backend-idle", "Close and replace a pre-dialed backend connection idle for longer than this.").Default("30s").Duration()

	// Metrics options
	metricsGraphite = app.Flag("metrics-graphite", "Collect metrics and report them to the given graphite instance (raw TCP).").PlaceHolder("ADDR").TCP()
	metricsURL      = app.Flag("metrics-url", "Collect metrics and POST them periodically to the given URL (via HTTP/JSON).").PlaceHolder("URL").String()
	metricsPrefix   = app.Flag("metrics-prefix", fmt.Sprintf("Set prefix string for all reported metrics (default: %s).", defaultMetricsPrefix)).PlaceHolder("PREFIX").Default(defaultMetricsPrefix).String()
	metricsInterval = app.Flag("metrics-interval", "Collect (and post/send) metrics every specified interval.").Default("30s").Duration()

	// Status, logging & other
	statusAddress  = app.Flag("status", "Enable serving /_status and /_metrics on given [http(s)://]HOST:PORT, unix:PATH, systemd:NAME or launchd:NAME.").PlaceHolder("ADDR").String()
	enableProf     = app.Flag("enable-pprof", "Enable serving /debug/pprof endpoints alongside /_status (for profiling).").Bool()
	enableShutdown = app.Flag("enable-shutdown", "Enable serving a /_shutdown endpoint alongside /_status to allow terminating via HTTP POST request. Requires a TLS status listener; the request must present a client certificate that verifies against the trust store.").Default("false").Bool()
	quiet          = app.Flag("quiet", "Silence log messages (can be all, conns, conn-errs, handshake-errs; repeat flag for more than one)").Default("").Enums("", "all", "conns", "handshake-errs", "conn-errs")
	skipResolve    = app.Flag("skip-resolve", "Skip resolving target host on startup (useful to start Ghostunnel before network is up).").Default("false").Bool()

	// Observer ring (see ringtrace/README.md). Ghostunnel does not run
	// without it: the trace is always written and the gate always consulted.
	ringTraces          = app.Flag("ring-traces", "Directory the trace of every accept, handshake, access decision, reload and shutdown request is appended under (the observer ring's gt/ root). Ghostunnel refuses to start if it cannot be opened.").PlaceHolder("DIR").Default(ringtrace.DefaultRoot + "/gt").String()
	ringStores          = app.Flag("ring-stores", "Root of the observer ring's store tree, consulted on every accept: a connection is served only if no observer holds a halt or fault and the coordinator's heartbeat is current; otherwise it is refused.").PlaceHolder("DIR").Default(ringtrace.DefaultRoot).String()
	ringHeartbeatMaxAge = app.Flag("ring-heartbeat-max-age", "How old the observer ring coordinator's newest heartbeat may be before connections are refused. Required, no default; must exceed the coordinator's cadence.").PlaceHolder("DURATION").Duration()
	ringTick            = app.Flag("ring-tick", "How often a tick line, the trace's own heartbeat, is written so the observers can tell a dead trace from a quiet one. Must be above zero, below the observers' cadence and below --ring-heartbeat-max-age.").PlaceHolder("DURATION").Default("5s").Duration()
	acceptNoSandbox     = app.Flag("accept-no-sandbox", "Run on a build that has no process sandbox facility, naming this OS (as Go names it: windows, darwin, ...) as the one whose lack of a sandbox is accepted. Required on every such build and refused on any build that has a sandbox facility (Linux, whatever the sandbox's state) or when the value is not this OS. Recorded as sandbox_accepted in the observer ring's start line.").PlaceHolder("OS").String()

	// Man page /help
	_ = app.Flag("help-custom-man", "Generate a man page.").Hidden().PreAction(generateManPage).Bool()
)

func init() {
	// Optional keychain identity flag, if compiled for a supported platform
	if certloader.SupportsKeychain() {
		keychainIdentity = app.Flag("keychain-identity", "Use local keychain identity with given serial/common name (instead of keystore file).").PlaceHolder("CN").String()
		keychainIssuer = app.Flag("keychain-issuer", "Use local keychain identity with given issuer name (instead of keystore file).").PlaceHolder("CN").String()
		if runtime.GOOS == "darwin" {
			keychainRequireToken = app.Flag("keychain-require-token", "Require keychain identity to be from a physical token (sets 'access group' to 'token', macOS only).").Bool()
		} else {
			// The "require token" flag doesn't do anything on Windows/Linux, so we hide it.
			isFalse := false
			keychainRequireToken = &isFalse
		}
	}

	// Optional PKCS#11 flags, if compiled with CGO enabled
	if certloader.SupportsPKCS11() {
		pkcs11Module = app.Flag("pkcs11-module", "Path to PKCS11 module (SO) file (optional).").Envar("PKCS11_MODULE").PlaceHolder("PATH").ExistingFile()
		pkcs11TokenLabel = app.Flag("pkcs11-token-label", "Token label for slot/key in PKCS11 module (optional).").Envar("PKCS11_TOKEN_LABEL").PlaceHolder("LABEL").String()
		pkcs11PIN = app.Flag("pkcs11-pin", "PIN code for slot/key in PKCS11 module (optional).").Envar("PKCS11_PIN").PlaceHolder("PIN").String()
	}

	if runtime.GOOS == "linux" {
		// Deprecated flag: Landlock is now enabled by default.
		app.Flag("use-landlock", "").Hidden().Bool()

		// Flag to disable use of landlock if necessary. Note that landlock is automatically disabled when PKCS#11 is used.
		disableLandlock = app.Flag("disable-landlock", "Disable the best-effort landlock sandboxing.").Bool()
	}

	// Aliases for flags that were renamed to be backwards-compatible
	serverCommand.Flag("allow-dns-san", "").Hidden().StringsVar(serverAllowedDNSs)
	serverCommand.Flag("allow-ip-san", "").Hidden().IPListVar(serverAllowedIPs)
	serverCommand.Flag("allow-uri-san", "").Hidden().StringsVar(serverAllowedURIs)
	clientCommand.Flag("verify-dns-san", "").Hidden().StringsVar(clientAllowedDNSs)
	clientCommand.Flag("verify-ip-san", "").Hidden().IPListVar(clientAllowedIPs)
	clientCommand.Flag("verify-uri-san", "").Hidden().StringsVar(clientAllowedURIs)
	clientCommand.Flag("connect-proxy", "").Hidden().URLVar(clientProxy)

	// Register HTTP CONNECT proxy scheme for golang.org/x/net/proxy
	netproxy.RegisterDialerType("http", connectproxy.ConnectProxy)
}

// exitFunc is the single sanctioned reference to os.Exit; all process exits go
// through it so exit hooks can wrap it to flush coverage counters and so exits
// stay testable.
var exitFunc = os.Exit //nolint:forbidigo // the one allowed os.Exit indirection

// extraRWPaths collects additional filesystem paths that should be
// read-writable under landlock. Populated by init() hooks (e.g. the
// coverage build tag registers GOCOVERDIR here) and consumed by the
// linux landlock setup. Read/written only behind build tags, hence the
// nolint directive.
var extraRWPaths []string //nolint:unused

// sandboxOutcome is the process sandbox's state as setupSandbox decided it
// (one of ringtrace.SandboxStates), set once by run before any validation
// and any listener; "" until then. sandboxState reads it: the start line is
// filled from it and validateSandboxAcceptance is judged against it, so
// the platform file that makes the attempt is the only place the state
// comes from.
var sandboxOutcome string

// sandboxState is the process sandbox's state as decided at startup, or ""
// while it is undecided, which every consumer refuses.
func sandboxState() string {
	return sandboxOutcome
}

// decideSandbox is the sandbox attempt run makes (a seam for tests, which
// must not confine the test process to run the rest of the suite).
var decideSandbox = setupSandbox

// Environment groups listening context data together.
type Environment struct {
	status          *statusHandler
	statusHTTP      *http.Server
	shutdownChannel chan bool
	shutdownTimeout time.Duration
	dial            proxy.DialFunc
	metrics         *sqmetrics.SquareMetrics
	proxyMetrics    *proxy.Metrics
	tlsConfigSource certloader.TLSConfigSource
	regoPolicy      policy.Policy
	// verifyCache remembers the tunnel ACL's peer verifications; reload()
	// invalidates it after every reload of trust material and policy.
	verifyCache *auth.VerifyCache
	// ring is the observer ring's emitter and gate, set before the tunnel
	// listener binds.
	ring *ring
	// proxy is the tunnel proxy, set by attachRing; statusListener is the
	// status port's listener, set by serveStatus. The watchdog's health
	// check reads the first; the second is what a failed Serve is about.
	proxy          *proxy.Proxy
	statusListener net.Listener
}

// acceptHealthWindow is how recently the accept loop must have come round
// for the process to be healthy; the loop bounds every wait to one second,
// so a healthy loop is never this far behind.
var acceptHealthWindow = 5 * time.Second

// healthy is the watchdog's health check: true only if the accept loop
// came round within acceptHealthWindow, the proxy is not shutting down and
// its listener is open, and the ring holds no sticky refusal (an emitter
// that failed, a reload that failed, a status listener that died). A gate
// refusal in force is not unhealthy: restarting into a halt changes
// nothing. The service manager restarts the process when this is false for
// its watchdog interval.
func (env *Environment) healthy() bool {
	p := env.proxy
	if p == nil || p.ShuttingDown() || p.ListenerClosed() {
		return false
	}
	last := p.LastIteration()
	if last.IsZero() || time.Since(last) > acceptHealthWindow {
		return false
	}
	return env.ring.stickyRefusal() == ""
}

// Global logger instance
var logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

func initLogger(systemLog bool, flags []string) (err error) {
	// If user has indicated request for system log (syslog on Unix, event
	// log on Windows), override default stdout logger with the platform
	// system logger instead. This can fail, e.g. in containers that don't
	// have syslog available.
	if slices.Contains(flags, "all") {
		// If --quiet=all if passed, disable all logging
		logger = log.New(io.Discard, "", 0)
		return
	}
	if systemLog {
		err = initSystemLogger()
	}
	return
}

// panicOnError panics if err is not nil
func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

// Validate flags for both, server and client mode
func validateFlags(app *kingpin.Application) error {
	if *statusAddress == "" {
		if *enableProf {
			return fmt.Errorf("--enable-pprof requires --status to be set")
		}
		if *enableShutdown {
			return fmt.Errorf("--enable-shutdown requires --status to be set")
		}
	}
	if *metricsURL != "" && !strings.HasPrefix(*metricsURL, "http://") && !strings.HasPrefix(*metricsURL, "https://") {
		return fmt.Errorf("--metrics-url should start with http:// or https://")
	}
	if *serverStatusTargetAddress != "" && !strings.HasPrefix(*serverStatusTargetAddress, "http://") && !strings.HasPrefix(*serverStatusTargetAddress, "https://") {
		return fmt.Errorf("--target-status should start with http:// or https://")
	}
	if err := validateStatusAddress(); err != nil {
		return err
	}
	if *connectTimeout == 0 {
		return fmt.Errorf("--connect-timeout duration must not be zero")
	}
	if *useWorkloadAPITimeout < 0 {
		return fmt.Errorf("--use-workload-api-timeout duration must not be negative (use 0 to wait indefinitely)")
	}
	if err := validateALPN(); err != nil {
		return err
	}
	return nil
}

// validateStatusAddress enforces the supported shapes of --status: TLS may
// only be served on TCP, so the http:// and https:// scheme prefixes are
// rejected for unix/systemd/launchd listeners (which always serve plain HTTP).
func validateStatusAddress() error {
	if *statusAddress == "" {
		return nil
	}
	_, addr := socket.ParseHTTPAddress(*statusAddress)
	network, _, _, err := socket.ParseAddress(addr, true)
	if err != nil {
		return fmt.Errorf("invalid --status address: %w", err)
	}
	hasScheme := strings.HasPrefix(*statusAddress, "http://") || strings.HasPrefix(*statusAddress, "https://")
	if hasScheme && network != "tcp" {
		return fmt.Errorf("invalid --status network %q: http(s):// scheme requires a HOST:PORT target", network)
	}
	return nil
}

// defaultWarmBackendConnections is the pool a server-mode proxy keeps to a
// backend that is not loopback or a UNIX socket when --warm-backend-connections
// is left at its default. Against a remote backend the pool takes the dial
// off every connection's path; 64 rather than 16 keeps the tail latency
// down under concurrent load. The cost is that many idle connections held
// open on the backend per proxy.
const defaultWarmBackendConnections = 64

// warmPoolSize resolves --warm-backend-connections: an explicit value (0 or
// more) is taken as given; the default, -1, is defaultWarmBackendConnections
// for a server-mode target the proxy considers remote (not loopback, not a
// UNIX socket: consideredSafe), and none otherwise. On loopback the dial is
// pure CPU and the pool adds bookkeeping under saturation; in client mode a
// pooled connection's TLS handshake would be recorded at draw time rather
// than when it happened, so the pool there is an explicit choice.
func warmPoolSize(flag int, mode, target string) int {
	if flag >= 0 {
		return flag
	}
	if mode == "server" && !consideredSafe(target) {
		return defaultWarmBackendConnections
	}
	return 0
}

// logWarmPool says what warmPoolSize decided and why, once at startup, so
// the log shows the resolved value and not the flag's -1.
func logWarmPool(n, flag int, mode, target string) {
	switch {
	case n == 0 && flag >= 0:
		logger.Printf("warm backend pool: none (--warm-backend-connections 0)")
	case n == 0:
		logger.Printf("warm backend pool: none (automatic: %s mode, target %s is local or a UNIX socket, or client mode)", mode, target)
	case flag >= 0:
		logger.Printf("warm backend pool: %d connections (--warm-backend-connections %d)", n, flag)
	default:
		logger.Printf("warm backend pool: %d connections (automatic: %s mode, remote target %s)", n, mode, target)
	}
}

// Validates that addr is "safe" and does not need --unsafe-listen (or --unsafe-target).
func consideredSafe(addr string) bool {
	safePrefixes := []string{
		"unix:",
		"systemd:",
		"launchd:",
		"127.0.0.1:",
		"[::1]:",
		"localhost:",
	}
	for _, prefix := range safePrefixes {
		if strings.HasPrefix(addr, prefix) {
			return true
		}
	}
	return false
}

func validateCredentials(creds []bool) int {
	count := 0
	for _, cred := range creds {
		if cred {
			count++
		}
	}
	return count
}

func validateCipherSuites() error {
	if _, err := resolveCipherSuites(*enabledCipherSuites, *allowUnsafeCipherSuites); err != nil {
		return err
	}
	return nil
}

// validateALPN rejects a malformed --alpn list at flag-parse time, so a typo
// such as "h2, ,http/1.1" surfaces as a startup error rather than as handshake
// failures (client mode) or protocols that silently never negotiate (server
// mode). See parseALPN for details.
func validateALPN() error {
	if _, err := parseALPN(*alpn); err != nil {
		return err
	}
	return nil
}

func validateCertKeyPair() error {
	if (*keyPath != "" && *certPath == "") || (*certPath != "" && *keyPath == "" && !hasPKCS11()) {
		return errors.New("--cert/--key must be set together, unless using PKCS11 for private key")
	}
	return nil
}

func validateServerCredentials() error {
	count := validateCredentials([]bool{
		*keystorePath != "",
		hasKeychainIdentity(),
		(*certPath != "" && *keyPath != ""),
		(*certPath != "" && hasPKCS11()),
		*useWorkloadAPI,
		*serverAutoACMEFQDN != "",
	})
	if count == 0 {
		return errors.New("at least one of --keystore, --cert/--key, --auto-acme-cert, or --keychain-identity/issuer (if supported) flags is required")
	}
	if count > 1 {
		return errors.New("--keystore, --cert/--key, --auto-acme-cert, and --keychain-identity/issuer flags are mutually exclusive")
	}
	return validateCertKeyPair()
}

func validateServerAccessControl(hasAccessFlags, hasPinFlag, hasOPAFlags bool) error {
	if !(*serverDisableAuth) && !(*serverAllowAll) && !hasAccessFlags && !hasPinFlag && !hasOPAFlags {
		return errors.New("at least one access control flag (--allow-{all,cn,ou,dns,uri,spki-pin}, or OPA flags, or --disable-authentication) is required")
	}
	if !(*serverDisableAuth) && *serverAllowAll && (hasAccessFlags || hasPinFlag || hasOPAFlags) {
		return errors.New("--allow-all is mutually exclusive with other access control flags")
	}
	if *serverDisableAuth && (*serverAllowAll || hasAccessFlags || hasPinFlag || hasOPAFlags) {
		return errors.New("--disable-authentication is mutually exclusive with other access control flags")
	}
	if hasPinFlag && (hasAccessFlags || *serverAllowAll || hasOPAFlags) {
		return errors.New("--allow-spki-pin is mutually exclusive with other access control flags")
	}
	// The SPIFFE Workload API source independently disables normal verification
	// and wraps VerifyPeerCertificate, which would conflict with pin-only auth.
	if hasPinFlag && *useWorkloadAPI {
		return errors.New("--allow-spki-pin is mutually exclusive with --use-workload-api")
	}
	return nil
}

func validateServerTarget() error {
	if !*serverUnsafeTarget && !consideredSafe(*serverForwardAddress) {
		return errors.New("--target must be unix:PATH or localhost:PORT (unless --unsafe-target is set)")
	}
	network, _, _, err := socket.ParseAddress(*serverForwardAddress, true)
	if err != nil {
		return fmt.Errorf("invalid --target address: %w", err)
	}
	if !socket.IsDialableNetwork(network) {
		return fmt.Errorf("invalid --target network %q: only tcp and unix targets are supported (systemd:/launchd: cannot be dialed)", network)
	}
	return nil
}

func validateServerACME() error {
	if *serverAutoACMEFQDN == "" {
		return nil
	}
	if *serverAutoACMEEmail == "" {
		return errors.New("--auto-acme-cert was specified but no email address was provided with --auto-acme-email")
	}
	if !*serverAutoACMEAgreedTOS {
		return errors.New("--auto-acme-agree-to-tos was not specified and is required if --auto-acme-cert is specified")
	}
	return nil
}

func validateServerOPA(hasOPAFlags bool) error {
	if !hasOPAFlags {
		return nil
	}
	if *serverAllowPolicy == "" || *serverAllowQuery == "" {
		return errors.New("--allow-policy and --allow-query have to be used together")
	}
	return nil
}

// Decoded SPKI pins, populated by decodeSPKIPins during flag validation from
// --allow-spki-pin / --verify-spki-pin so that malformed pins are rejected at
// startup rather than at listen/dial time.
var (
	decodedServerPins []auth.SPKIPin
	decodedClientPins []auth.SPKIPin
)

// decodeSPKIPins parses SPKI pin flag values, tagging any parse error with the
// flag name so the message is actionable. Used by both the server
// (--allow-spki-pin) and client (--verify-spki-pin) validators.
func decodeSPKIPins(values []string, flag string) ([]auth.SPKIPin, error) {
	pins, err := auth.ParseSPKIPins(values)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flag, err)
	}
	return pins, nil
}

// Validate flags for server mode
func serverValidateFlags() error {
	if err := validateServerCredentials(); err != nil {
		return err
	}

	hasAccessFlags := len(*serverAllowedCNs) > 0 ||
		len(*serverAllowedOUs) > 0 ||
		len(*serverAllowedDNSs) > 0 ||
		len(*serverAllowedIPs) > 0 ||
		len(*serverAllowedURIs) > 0
	hasPinFlag := len(*serverAllowSpkiPin) > 0
	hasOPAFlags := len(*serverAllowPolicy) > 0 || len(*serverAllowQuery) > 0

	if err := validateServerAccessControl(hasAccessFlags, hasPinFlag, hasOPAFlags); err != nil {
		return err
	}
	if err := validateServerPin(); err != nil {
		return err
	}
	if err := validateServerTarget(); err != nil {
		return err
	}
	if err := validateServerACME(); err != nil {
		return err
	}
	if err := validateServerOPA(hasOPAFlags); err != nil {
		return err
	}
	if err := validateServerProxyProtocol(); err != nil {
		return err
	}
	if err := validateRingFlags(); err != nil {
		return err
	}
	if err := validateSandboxAcceptance(*acceptNoSandbox, runtime.GOOS, sandboxState()); err != nil {
		return err
	}
	return validateCipherSuites()
}

// validateServerPin decodes --allow-spki-pin into decodedServerPins.
func validateServerPin() error {
	// Reset decodedServerPins first so repeated in-process validation (as unit
	// tests do) can't leak a previous run's decoded pins into a later run that
	// omits the flag or fails parsing.
	decodedServerPins = nil
	if len(*serverAllowSpkiPin) == 0 {
		return nil
	}
	pins, err := decodeSPKIPins(*serverAllowSpkiPin, "--allow-spki-pin")
	if err != nil {
		return err
	}
	decodedServerPins = pins
	return nil
}

func validateServerProxyProtocol() error {
	if *serverProxyProtocol && *serverProxyProtocolMode != "" {
		return errors.New("--proxy-protocol and --proxy-protocol-mode are mutually exclusive")
	}
	return nil
}

func validateClientCredentials() error {
	// --disable-authentication is mutex with file-based identity flags, but
	// may be combined with --use-workload-api for server verification only.
	disableAuthCounts := *clientDisableAuth && !*useWorkloadAPI
	count := validateCredentials([]bool{
		*keystorePath != "",
		hasKeychainIdentity(),
		(*certPath != "" && *keyPath != ""),
		(*certPath != "" && hasPKCS11()),
		*useWorkloadAPI,
		disableAuthCounts,
	})
	if count == 0 {
		return errors.New("at least one of --keystore, --cert/--key, --keychain-identity/issuer (if supported), --use-workload-api or --disable-authentication flags is required")
	}
	if count > 1 {
		return errors.New("--keystore, --cert/--key, --keychain-identity/issuer, --use-workload-api and --disable-authentication flags are mutually exclusive")
	}
	return validateCertKeyPair()
}

func validateClientListen() error {
	if !*clientUnsafeListen && !consideredSafe(*clientListenAddress) {
		return fmt.Errorf("--listen must be unix:PATH, localhost:PORT, systemd:NAME or launchd:NAME (unless --unsafe-listen is set)")
	}
	return nil
}

func validateClientTarget() error {
	network, _, _, err := socket.ParseAddress(*clientForwardAddress, true)
	if err != nil {
		return fmt.Errorf("invalid --target address: %w", err)
	}
	if !socket.IsDialableNetwork(network) {
		return fmt.Errorf("invalid --target network %q: only tcp and unix targets are supported (systemd:/launchd: cannot be dialed)", network)
	}
	return nil
}

func validateClientOPA() error {
	hasOPAFlags := len(*clientAllowPolicy) > 0 || len(*clientAllowQuery) > 0
	if !hasOPAFlags {
		return nil
	}
	if *clientAllowPolicy == "" || *clientAllowQuery == "" {
		return errors.New("--verify-policy and --verify-query have to be used together")
	}
	return nil
}

// validateClientPin decodes --verify-spki-pin into decodedClientPins.
func validateClientPin() error {
	// Reset decodedClientPins first so repeated in-process validation (as
	// unit tests do) can't leak a previous run's decoded pins into a later run
	// that omits the flag or fails parsing.
	decodedClientPins = nil
	if len(*clientVerifySpkiPin) == 0 {
		return nil
	}
	// The SPIFFE Workload API source independently disables normal verification
	// and wraps VerifyPeerCertificate, which would conflict with pin-only auth.
	if *useWorkloadAPI {
		return errors.New("--verify-spki-pin is mutually exclusive with --use-workload-api")
	}
	hasVerifyFlags := len(*clientAllowedCNs) > 0 ||
		len(*clientAllowedOUs) > 0 ||
		len(*clientAllowedDNSs) > 0 ||
		len(*clientAllowedIPs) > 0 ||
		len(*clientAllowedURIs) > 0
	hasOPAFlags := len(*clientAllowPolicy) > 0 || len(*clientAllowQuery) > 0
	// --disable-authentication is deliberately NOT a conflict here: on the client
	// it only governs whether we present our own certificate to the server, not
	// how we verify the server.
	if hasVerifyFlags || hasOPAFlags {
		return errors.New("--verify-spki-pin is mutually exclusive with other verification flags")
	}
	pins, err := decodeSPKIPins(*clientVerifySpkiPin, "--verify-spki-pin")
	if err != nil {
		return err
	}
	decodedClientPins = pins
	return nil
}

// Validate flags for client mode
func clientValidateFlags() error {
	if err := validateClientCredentials(); err != nil {
		return err
	}
	if err := validateClientListen(); err != nil {
		return err
	}
	if err := validateClientTarget(); err != nil {
		return err
	}
	if err := validateClientOPA(); err != nil {
		return err
	}
	if err := validateClientPin(); err != nil {
		return err
	}
	if err := validateClientVerification(); err != nil {
		return err
	}
	if err := validateRingFlags(); err != nil {
		return err
	}
	if err := validateSandboxAcceptance(*acceptNoSandbox, runtime.GOOS, sandboxState()); err != nil {
		return err
	}
	return validateCipherSuites()
}

// validateClientVerification refuses a client that would verify the server
// by its hostname alone without the operator saying so: at least one
// --verify-* rule (subject, SAN, pin or OPA) is required, or
// --verify-hostname-only, which states that no rule beyond the hostname is
// wanted and is refused beside any rule. The start line's acl then says
// exactly which it is.
func validateClientVerification() error {
	hasRule := len(*clientAllowedCNs) > 0 ||
		len(*clientAllowedOUs) > 0 ||
		len(*clientAllowedDNSs) > 0 ||
		len(*clientAllowedIPs) > 0 ||
		len(*clientAllowedURIs) > 0 ||
		len(*clientVerifySpkiPin) > 0 ||
		*clientAllowPolicy != "" || *clientAllowQuery != ""
	if *clientVerifyHostnameOnly && hasRule {
		return errors.New("--verify-hostname-only is mutually exclusive with the --verify-* rules: it states that no rule beyond the hostname is wanted")
	}
	if !*clientVerifyHostnameOnly && !hasRule {
		return errors.New("client mode verifies the server by its hostname alone unless a --verify-* rule is given: pass at least one of --verify-{cn,ou,dns,uri,spki-pin} or the OPA flags, or --verify-hostname-only to accept hostname-only verification explicitly")
	}
	return nil
}

// serverProxyProtoMode computes the ProxyProtocolMode from the
// --proxy-protocol and --proxy-protocol-mode flags.
func serverProxyProtoMode() proxy.ProxyProtocolMode {
	if *serverProxyProtocolMode != "" {
		switch *serverProxyProtocolMode {
		case "tls":
			return proxy.ProxyProtocolTLS
		case "tls-full":
			return proxy.ProxyProtocolTLSFull
		default:
			return proxy.ProxyProtocolConn
		}
	}
	if *serverProxyProtocol {
		return proxy.ProxyProtocolConn
	}
	return proxy.ProxyProtocolOff
}

func main() {
	if isRunningAsService() {
		runAsService()
		return
	}
	err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		exitFunc(1)
	}
	exitFunc(0)
}

// applyFlagImplications applies implicit flag relationships after parsing.
// Setting --use-workload-api-addr implies --use-workload-api.
func applyFlagImplications() {
	if *useWorkloadAPIAddr != "" {
		*useWorkloadAPI = true
	}
}

func run(args []string) error {
	app.Version(fmt.Sprintf("rev %s built with %s (pkcs11: %v, keychain: %v)", version, runtime.Version(), certloader.SupportsPKCS11(), certloader.SupportsKeychain()))
	app.Validate(validateFlags)
	app.UsageTemplate(kingpin.LongHelpTemplate)

	command, parseErr := app.Parse(args)
	command = kingpin.MustParse(command, parseErr)

	if handled, err := runServiceCommand(command); handled {
		return err
	}

	applyFlagImplications()

	// Logger
	err := initLogger(useSystemLog(), *quiet)
	if err != nil {
		return fmt.Errorf("unable to set up logger: %w", err)
	}

	logger.SetPrefix(fmt.Sprintf("[%d] ", os.Getpid()))
	logger.Printf("starting ghostunnel in %s mode", command)

	// The process sandbox. It is attempted on every platform (setupSandbox
	// in landlock_<platform>.go) and the outcome is what the start line
	// reports. Only an applied sandbox serves; a build with no sandbox
	// facility runs only under an explicit --accept-no-sandbox naming this
	// OS. Both are checked by serverValidateFlags and clientValidateFlags
	// below and again by openRing before any listener binds.
	pkcs11Enabled := pkcs11Module != nil && *pkcs11Module != ""
	// The start line's record of the executable is taken here, before the
	// sandbox: landlock grants no read of the executable. A failure is
	// kept and refuses the start at ringConfig.
	_, _ = recordRingBinary()
	sandboxOutcome = decideSandbox(pkcs11Enabled)
	logger.Printf("process sandbox: %s", sandboxOutcome)

	// Metrics
	//
	// Metrics leave the process through exactly three sinks: the pull surface
	// (/_metrics*, served only when --status is set) and the two push reporters
	// (--metrics-graphite, --metrics-url). When none is configured, nothing can
	// observe the registry, so we skip metrics collection entirely: the proxy
	// gets no-op handles (see proxy.NilMetrics) and neither metrics background
	// goroutine is started.
	//
	// NOTE: these flags are start-time-only; nothing reconfigures them at
	// runtime (cert hot-reload does not touch them), so this predicate is
	// decided once here and stays valid for the process lifetime. If that ever
	// changes, this gate must be re-evaluated.
	metricsConsumed := *statusAddress != "" || *metricsGraphite != nil || *metricsURL != ""

	// proxyMetrics drives the connection hot path: live handles on the default
	// registry when metrics are consumed, no-op handles otherwise.
	var proxyMetrics *proxy.Metrics
	if metricsConsumed {
		proxyMetrics = proxy.LiveMetrics(metrics.DefaultRegistry)
	} else {
		proxyMetrics = proxy.NilMetrics()
	}

	// metricsSink is the sq-metrics collector; left nil when metrics are not
	// consumed (its only readers live in serveStatus, which is not registered
	// unless --status is set, in which case metrics are consumed).
	var metricsSink *sqmetrics.SquareMetrics
	if metricsConsumed {
		if *metricsGraphite != nil {
			logger.Printf("metrics enabled; reporting metrics via TCP to %s", *metricsGraphite)
			go graphite.Graphite(metrics.DefaultRegistry, 1*time.Second, *metricsPrefix, *metricsGraphite)
		}
		if *metricsURL != "" {
			logger.Printf("metrics enabled; reporting metrics via POST to %s", *metricsURL)
		}

		// Bridge go-metrics into the prometheus registry for /_metrics/prometheus.
		// The overhead is minimal (an in-mem map is updated with the values).
		pClient := prometheusmetrics.NewPrometheusProvider(metrics.DefaultRegistry, *metricsPrefix, "", prometheus.DefaultRegisterer, 1*time.Second)
		go pClient.UpdatePrometheusMetrics()

		// Read CA bundle for passing to metrics library
		ca, err := certloader.LoadTrustStore(*caBundlePath)
		if err != nil {
			logger.Printf("error: unable to build TLS config: %s\n", err)
			return err
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    ca,
				},
			},
		}
		metricsSink = sqmetrics.NewMetrics(*metricsURL, *metricsPrefix, client, *metricsInterval, metrics.DefaultRegistry, logger)
	}

	switch command {
	case serverCommand.FullCommand():
		if err := serverValidateFlags(); err != nil {
			logger.Printf("error: %s\n", err)
			return err
		}

		// Duplicating this call to getTLSConfigSource() in all switch cases
		// because we need to complete the validation of the command flags first.
		tlsConfigSource, err := getTLSConfigSource(*serverDisableAuth)
		if err != nil {
			return err
		}

		dial, err := serverBackendDialer()
		if err != nil {
			logger.Printf("error: invalid target address: %s\n", err)
			return err
		}
		logger.Printf("using target address %s", *serverForwardAddress)

		// Compile the rego policy before constructing the Environment so the
		// reload goroutine (started below) does not race with a later
		// assignment to env.regoPolicy.
		regoPolicy, err := loadOPAPolicy(*serverAllowPolicy, *serverAllowQuery)
		if err != nil {
			return err
		}

		status := newStatusHandler(dial, command, *serverListenAddress, *serverForwardAddress, *serverStatusTargetAddress)
		env := &Environment{
			status:          status,
			shutdownChannel: make(chan bool, 1),
			shutdownTimeout: *processShutdownTimeout,
			dial:            dial,
			metrics:         metricsSink,
			proxyMetrics:    proxyMetrics,
			tlsConfigSource: tlsConfigSource,
			regoPolicy:      regoPolicy,
		}
		go env.reloadHandler(*timedReload)

		// Start listening
		err = serverListen(env, regoPolicy)
		if err != nil {
			logger.Printf("error from server listen: %s\n", err)
		}
		return err

	case clientCommand.FullCommand():
		if err := clientValidateFlags(); err != nil {
			logger.Printf("error: %s\n", err)
			return err
		}

		// Duplicating this call to getTLSConfigSource() in all switch cases
		// because we need to complete the validation of the command flags first.
		tlsConfigSource, err := getTLSConfigSource(*clientDisableAuth)
		if err != nil {
			return err
		}

		// Note: A target address given on the command line may not be resolvable
		// on our side if the connection is forwarded through a CONNECT proxy. Hence,
		// we ignore "no such host" errors when a proxy is set and trust that the
		// proxy will be able to find the target for us.
		skipRes := *skipResolve || *clientProxy != nil
		network, address, host, err := socket.ParseAddress(*clientForwardAddress, skipRes)
		if err != nil {
			logger.Printf("error: invalid target address: %s\n", err)
			return err
		}
		logger.Printf("using target address %s", *clientForwardAddress)

		dial, policy, err := clientBackendDialer(tlsConfigSource, network, address, host)
		if err != nil {
			logger.Printf("error: unable to build dialer: %s\n", err)
			return err
		}

		// NOTE: We don't provide a target status address here because this handler
		// is for the client /_status endpoint, its target will be a Ghostunnel in
		// server mode, and thus this should be a (default) connect check via the
		// backend dialer (which handles both tcp and unix targets).
		status := newStatusHandler(dial, command, *clientListenAddress, *clientForwardAddress, "")
		env := &Environment{
			status:          status,
			shutdownChannel: make(chan bool, 1),
			shutdownTimeout: *processShutdownTimeout,
			dial:            dial,
			metrics:         metricsSink,
			proxyMetrics:    proxyMetrics,
			tlsConfigSource: tlsConfigSource,
			regoPolicy:      policy,
		}
		go env.reloadHandler(*timedReload)

		// Start listening
		err = clientListen(env)
		if err != nil {
			logger.Printf("error from client listen: %s\n", err)
		}
		return err
	}

	return errors.New("unknown command")
}

// loadOPAPolicy compiles a rego policy from the given path+query. Returns
// (nil, nil) when either flag is empty (OPA disabled); otherwise loads the
// policy and returns it, or an error if compilation fails.
func loadOPAPolicy(allowPolicy, allowQuery string) (policy.Policy, error) {
	if len(allowPolicy) == 0 || len(allowQuery) == 0 {
		return nil, nil
	}
	p, err := policy.LoadFromPath(allowPolicy, allowQuery)
	if err != nil {
		logger.Printf("Invalid rego policy or query: %s", err)
		return nil, err
	}
	return p, nil
}

// Open listening socket in server mode. Take note that we create a
// "reusable port listener", meaning we pass SO_REUSEPORT to the kernel. This
// allows us to have multiple sockets listening on the same port and accept
// connections. This is useful for the purpose of replacing certificates
// in-place without having to take downtime, e.g. if a certificate is expiring.
func serverListen(env *Environment, regoPolicy policy.Policy) error {
	config, err := buildServerConfig(*enabledCipherSuites, *maxTLSVersion, *allowUnsafeCipherSuites, *alpn)
	if err != nil {
		logger.Printf("error trying to read CA bundle: %s", err)
		return err
	}

	allowedURIs, err := wildcard.CompileList(*serverAllowedURIs)
	if err != nil {
		logger.Printf("invalid URI pattern in --allow-uri flag (%s)", err)
		return err
	}

	serverACL := auth.ACL{
		AllowAll:        *serverAllowAll,
		AllowedCNs:      *serverAllowedCNs,
		AllowedOUs:      *serverAllowedOUs,
		AllowedDNSs:     *serverAllowedDNSs,
		AllowedIPs:      *serverAllowedIPs,
		AllowOPAQuery:   regoPolicy,
		AllowedURIs:     allowedURIs,
		OPAQueryTimeout: *connectTimeout,
		AllowedPins:     decodedServerPins,
	}

	// One cache shared by every copy of the ACL (the tunnel's callback, the
	// resumption hook, the ring's checks); the reload path bumps its
	// generation (Environment.reload).
	env.verifyCache = auth.NewVerifyCache(auth.DefaultVerifyCacheSize)
	serverACL = serverACL.WithVerifyCache(env.verifyCache)
	var serverConfig certloader.TLSServerConfig
	if *serverDisableAuth {
		config.ClientAuth = tls.NoClientCert
		serverConfig, err = getServerConfig(env.tlsConfigSource, config)
	} else {
		// The ACL is the tunnel's client verifier: on the certificate and
		// ACME sources it verifies the client's chain itself, with the
		// options crypto/tls would use, so a repeat client's verification
		// can be remembered; in pin mode it checks the pin; the
		// Workload API source verifies through go-spiffe and gets the plain
		// callback (certloader.GetServerConfigVerifying).
		serverConfig, err = certloader.GetServerConfigVerifying(env.tlsConfigSource, config, serverACL)
	}
	if err != nil {
		logger.Printf("error: unable to get server TLS config: %s", err)
		return err
	}

	// The observer ring's start line describes the configuration as it is
	// about to be served, so it is written before the listener binds.
	ringCfg, ringCA, err := ringConfig("server", *serverListenAddress, *serverForwardAddress, serverProxyProtoMode(), serverConfig.GetServerConfig(), sandboxState(), *serverAllowPolicy,
		ringRules{acl: serverACL, uris: *serverAllowedURIs, disableAuth: *serverDisableAuth})
	if err != nil {
		logger.Printf("error: unable to record the configuration for the ring trace: %s", err)
		return err
	}
	env.ring, err = openRing(ringCfg, ringCA, serverACL, !*serverDisableAuth, *serverAllowPolicy)
	if err != nil {
		return err
	}

	listener, err := socket.ParseAndOpen(*serverListenAddress)
	if err != nil {
		env.ring.close()
		logger.Printf("error trying to listen: %s", err)
		return err
	}

	p := proxy.New(
		certloader.NewListener(listener, serverConfig),
		*connectTimeout,
		*closeTimeout,
		*maxConnLifetime,
		int64(*maxConcurrentConns),
		env.dial,
		logger,
		proxyLoggerFlags(*quiet),
		serverProxyProtoMode(),
		env.proxyMetrics,
	)
	p.CopyBufferSize = int(*copyBufferSize)
	p.SocketBufferSize = int(*socketBufferSize)
	p.WarmBackendConnections = warmPoolSize(*warmBackendConnections, "server", *serverForwardAddress)
	logWarmPool(p.WarmBackendConnections, *warmBackendConnections, "server", *serverForwardAddress)
	p.WarmBackendIdle = *warmBackendIdle
	env.attachRing(p)

	if *statusAddress != "" {
		err := env.serveStatus()
		if err != nil {
			listener.Close()
			env.ring.close()
			logger.Printf("error serving /_status: %s", err)
			return err
		}
	}

	logger.Printf("listening for connections on %s", *serverListenAddress)

	go p.Accept()

	env.status.Listening()
	env.status.HandleWatchdog(env.healthy)
	env.signalHandler(p)
	p.Wait()
	env.ring.close()

	return nil
}

// Open listening socket in client mode.
func clientListen(env *Environment) error {
	// The listener is plaintext: no session tickets and no resumption on
	// it. The TLS handshake of each connection is the dial to the target.
	// The ring's start line is written before the listener binds.
	acl, err := clientACL(env.regoPolicy)
	if err != nil {
		return err
	}
	// A client dials its backend with no PROXY protocol header: the mode is
	// a server flag, and the client's start line records off.
	ringCfg, ringCA, err := ringConfig("client", *clientListenAddress, *clientForwardAddress, proxy.ProxyProtocolOff, nil, sandboxState(), *clientAllowPolicy,
		ringRules{acl: acl, uris: *clientAllowedURIs, disableAuth: *clientDisableAuth})
	if err != nil {
		logger.Printf("error: unable to record the configuration for the ring trace: %s", err)
		return err
	}
	env.ring, err = openRing(ringCfg, ringCA, acl, true, *clientAllowPolicy)
	if err != nil {
		return err
	}

	listener, err := socket.ParseAndOpen(*clientListenAddress)
	if err != nil {
		env.ring.close()
		logger.Printf("error opening socket: %s", err)
		return err
	}

	p := proxy.New(
		listener,
		*connectTimeout,
		*closeTimeout,
		*maxConnLifetime,
		int64(*maxConcurrentConns),
		env.dial,
		logger,
		proxyLoggerFlags(*quiet),
		proxy.ProxyProtocolOff,
		env.proxyMetrics,
	)
	p.CopyBufferSize = int(*copyBufferSize)
	p.SocketBufferSize = int(*socketBufferSize)
	p.WarmBackendConnections = warmPoolSize(*warmBackendConnections, "client", *clientForwardAddress)
	logWarmPool(p.WarmBackendConnections, *warmBackendConnections, "client", *clientForwardAddress)
	p.WarmBackendIdle = *warmBackendIdle
	env.attachRing(p)

	if *statusAddress != "" {
		err := env.serveStatus()
		if err != nil {
			listener.Close()
			env.ring.close()
			logger.Printf("error serving /_status: %s", err)
			return err
		}
	}

	logger.Printf("listening for connections on %s", *clientListenAddress)

	go p.Accept()

	env.status.Listening()
	env.status.HandleWatchdog(env.healthy)
	env.signalHandler(p)
	p.Wait()
	env.ring.close()

	return nil
}

// attachRing makes the observer ring the proxy's observer (consulted on
// every accept), the status handler's refusal source (so /_status answers
// 503 while serving is refused), and starts the watch that closes the
// connections in flight when serving becomes refused.
func (env *Environment) attachRing(p *proxy.Proxy) {
	env.proxy = p
	p.Observer = env.ring
	env.status.refusal = env.ring.refusal
	go env.ring.watch(p)
}

// verifiedClientCert reports whether the request arrived over TLS with a
// client certificate that the listener verified against its trust store.
// Only a chain the TLS layer built counts; a certificate that was merely
// presented, or a plaintext request, does not.
func verifiedClientCert(r *http.Request) bool {
	return r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.VerifiedChains) > 0
}

// shutdownHandler serves POST /_shutdown by signalling the shutdown channel.
// The send is non-blocking so repeated requests after shutdown has already
// been requested do not block the handler goroutine (which would stall
// graceful shutdown of the status HTTP server and leak goroutines until the
// shutdown timeout fires).
func (env *Environment) shutdownHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Stopping the proxy is reserved for callers the status listener has
	// authenticated: a client certificate that verified against the trust
	// store. Anything else, including a plaintext request, is refused.
	if !verifiedClientCert(r) {
		logger.Printf("shutdown request refused: no verified client certificate")
		env.ring.shutdownRequested("status-endpoint", false, nil, "POST /_shutdown refused: no verified client certificate")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// A verified certificate says the caller is someone the trust store
	// knows; the tunnel's own rule says who is allowed. The same rule the
	// verifier applies to tunnel clients applies here.
	peer := r.TLS.PeerCertificates[0].Subject.String()
	if err := env.ring.shutdownAllowed(r.TLS); err != nil {
		logger.Printf("shutdown request refused for %s: %s", peer, err)
		env.ring.shutdownRequested("status-endpoint", false, &peer, "POST /_shutdown refused: not allowed by the tunnel ACL: "+err.Error())
		w.WriteHeader(http.StatusForbidden)
		return
	}

	logger.Printf("shutdown was requested via status endpoint by %s", peer)
	env.ring.shutdownRequested("status-endpoint", true, &peer, "POST /_shutdown")
	w.WriteHeader(http.StatusOK)

	// Non-blocking send: if a shutdown has already been requested (the
	// buffer is full or no reader is left), we drop this request rather
	// than block forever.
	select {
	case env.shutdownChannel <- true:
	default:
	}
}

// cmdlineHandler serves /debug/pprof/cmdline. The stock net/http/pprof
// handler writes os.Args verbatim, which would hand any secret passed on the
// command line (--storepass, --pkcs11-pin, a proxy URL with credentials) to
// whoever can reach the status port. This handler keeps the output shape
// (arguments separated by NUL) but serves only the program path and flag
// names; every value is replaced by a placeholder.
func cmdlineHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, strings.Join(redactCmdline(os.Args, knownFlagNames(app.Model())), "\x00"))
}

// knownFlagNames collects every flag name kingpin knows for the application
// and its commands, in the spellings the command line accepts (--name,
// --no-name for booleans, and -s for a short form).
func knownFlagNames(model *kingpin.ApplicationModel) map[string]bool {
	names := make(map[string]bool)
	addFlags := func(group *kingpin.FlagGroupModel) {
		for _, flag := range group.Flags {
			names["--"+flag.Name] = true
			if flag.IsBoolFlag() {
				names["--no-"+flag.Name] = true
			}
			if flag.Short != 0 {
				names["-"+string(flag.Short)] = true
			}
		}
	}
	var addCommands func(*kingpin.CmdGroupModel)
	addCommands = func(group *kingpin.CmdGroupModel) {
		for _, cmd := range group.Commands {
			addFlags(cmd.FlagGroupModel)
			addCommands(cmd.CmdGroupModel)
		}
	}
	addFlags(model.FlagGroupModel)
	addCommands(model.CmdGroupModel)
	return names
}

// redactCmdline keeps args[0] and every argument that is a known flag name,
// with the value of a --name=value form replaced. Everything else, including
// the subcommand and space-separated values, becomes "<redacted>". The
// output is built from an allowlist, so an argument that is not a flag name
// is never served, whichever flag it belongs to.
func redactCmdline(args []string, known map[string]bool) []string {
	out := make([]string, 0, len(args))
	for i, arg := range args {
		switch name, _, hasValue := strings.Cut(arg, "="); {
		case i == 0:
			out = append(out, arg)
		case known[name] && hasValue:
			out = append(out, name+"=<redacted>")
		case known[arg]:
			out = append(out, arg)
		default:
			out = append(out, "<redacted>")
		}
	}
	return out
}

// statusMux builds the handler tree served on the status port.
func (env *Environment) statusMux() *http.ServeMux {
	promHandler := promhttp.Handler()

	mux := http.NewServeMux()
	mux.Handle("/_status", env.status)
	mux.HandleFunc("/_metrics/json", func(w http.ResponseWriter, r *http.Request) {
		env.metrics.ServeHTTP(w, r)
	})
	mux.HandleFunc("/_metrics/prometheus", func(w http.ResponseWriter, r *http.Request) {
		promHandler.ServeHTTP(w, r)
	})
	mux.HandleFunc("/_metrics", func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		format, ok := params["format"]
		if !ok || format[0] != "prometheus" {
			env.metrics.ServeHTTP(w, r)
			return
		}
		promHandler.ServeHTTP(w, r)
	})

	if *enableShutdown {
		mux.HandleFunc("/_shutdown", env.shutdownHandler)
	}

	if *enableProf {
		// Every profiling endpoint, the index with the named profiles it
		// serves included, acts only for a caller the status listener
		// authenticated, as /_shutdown does: a CPU profile, a runtime trace
		// or a goroutine dump is not for whoever can reach the port.
		mux.Handle("/debug/pprof/", requireVerifiedClientCert(http.HandlerFunc(pprof.Index)))
		mux.Handle("/debug/pprof/cmdline", requireVerifiedClientCert(http.HandlerFunc(cmdlineHandler)))
		mux.Handle("/debug/pprof/profile", requireVerifiedClientCert(http.HandlerFunc(pprof.Profile)))
		mux.Handle("/debug/pprof/symbol", requireVerifiedClientCert(http.HandlerFunc(pprof.Symbol)))
		mux.Handle("/debug/pprof/trace", requireVerifiedClientCert(http.HandlerFunc(pprof.Trace)))
	}

	return mux
}

// requireVerifiedClientCert serves h only to a request that arrived over
// TLS with a client certificate the listener verified (verifiedClientCert);
// anything else is refused with 403 before h runs.
func requireVerifiedClientCert(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !verifiedClientCert(r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Serve /_status (if configured)
func (env *Environment) serveStatus() error {
	mux := env.statusMux()

	https, addr := socket.ParseHTTPAddress(*statusAddress)

	network, address, _, err := socket.ParseAddress(addr, true)
	if err != nil {
		return err
	}

	// TLS is only served on TCP with a certificate source that can act as a
	// server; unix/systemd/launchd listeners and http:// addresses serve
	// plain HTTP, on which no caller can be authenticated.
	serveTLS := network == "tcp" && https && env.tlsConfigSource.CanServe()
	if *enableShutdown && !serveTLS {
		return fmt.Errorf("--enable-shutdown requires a TLS status listener: /_shutdown only acts for a caller with a verified client certificate")
	}
	if *enableProf && !serveTLS {
		return fmt.Errorf("--enable-pprof requires a TLS status listener: /debug/pprof only acts for a caller with a verified client certificate")
	}

	listener, err := socket.Open(network, address)
	if err != nil {
		logger.Printf("error: unable to bind on status port: %s\n", err)
		return err
	}

	if serveTLS {
		// The status endpoint deliberately doesn't apply --alpn: it always
		// serves HTTPS, so a tunnel configured for some other protocol (e.g.
		// --alpn=postgresql) would otherwise lock out monitoring clients.
		config, err := buildServerConfig(*enabledCipherSuites, *maxTLSVersion, *allowUnsafeCipherSuites, "")
		if err != nil {
			return err
		}
		// Monitoring clients need no certificate and get the health summary.
		// The deployment details in /_status and the shutdown endpoint are
		// reserved for a caller whose certificate verified against the trust
		// store, so ask for one and verify it if given.
		config.ClientAuth = tls.VerifyClientCertIfGiven

		serverConfig, err := getServerConfig(env.tlsConfigSource, config)
		if err != nil {
			return err
		}
		if *serverAutoACMEFQDN != "" {
			// The ACME source appends acme-tls/1 to every listener it serves,
			// which would leave this listener advertising only acme-tls/1 and
			// rejecting monitoring clients that offer ALPN (as browsers and
			// curl do by default). The TLS-ALPN-01 challenge only ever arrives
			// on the tunnel listener, so strip the challenge plumbing here.
			serverConfig = certloader.WithoutACMEChallenge(serverConfig)
		}
		listener = certloader.NewListener(listener, serverConfig)
	}

	env.statusHTTP = &http.Server{
		Handler:           mux,
		ErrorLog:          logger,
		ReadHeaderTimeout: *connectTimeout,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	env.statusListener = listener
	go func() {
		err := env.statusHTTP.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			// The status surface is part of what the ring observes; without
			// it the process is not the deployment the start line describes.
			// A Serve error is a sticky refusal, logged once here.
			logger.Printf("ring: status listener failed, refusing to serve until restart: %s", err)
			env.ring.statusServeFailed(err)
		}
	}()

	return nil
}

// Get backend dialer function in server mode (connecting to a unix socket or tcp port)
func serverBackendDialer() (proxy.DialFunc, error) {
	backendNet, backendAddr, _, err := socket.ParseAddress(*serverForwardAddress, *skipResolve)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{Timeout: *connectTimeout}
		return d.DialContext(ctx, backendNet, backendAddr)
	}, nil
}

// Get backend dialer function in client mode (connecting to a TLS port)
func clientBackendDialer(
	tlsConfigSource certloader.TLSConfigSource,
	network, address, host string,
) (proxy.DialFunc, policy.Policy, error) {

	config, err := buildClientConfig(*enabledCipherSuites, *maxTLSVersion, *allowUnsafeCipherSuites, *alpn)
	if err != nil {
		return nil, nil, err
	}

	if *clientServerName == "" {
		config.ServerName = host
	} else {
		config.ServerName = *clientServerName
	}

	regoPolicy, err := loadOPAPolicy(*clientAllowPolicy, *clientAllowQuery)
	if err != nil {
		return nil, nil, err
	}

	clientACL, err := clientACL(regoPolicy)
	if err != nil {
		return nil, nil, err
	}

	if clientACL.PinningEnabled() {
		// SPKIPin-based verification: skip chain and hostname validation.
		// The ACL callback will verify the SPKI hash.
		config.InsecureSkipVerify = true
	}

	config.VerifyPeerCertificate = clientACL.VerifyPeerCertificateClient

	var dialer netproxy.ContextDialer = &net.Dialer{Timeout: *connectTimeout}

	if *clientProxy != nil {
		logger.Printf("using proxy %s", (*clientProxy).String())
		proxyDialer, err := netproxy.FromURL(*clientProxy, &net.Dialer{Timeout: *connectTimeout})
		if err != nil {
			logger.Printf("error: error configuring proxy: %s\n", err)
			return nil, nil, err
		}

		var ok bool
		dialer, ok = proxyDialer.(netproxy.ContextDialer)
		if !ok {
			logger.Printf("unexpected: proxy dialer scheme did not implement context dialing, aborting")
			return nil, nil, errors.New("unexpected: proxy dialer scheme did not implement context dialing, aborting")
		}
	}

	clientConfig, err := getClientConfig(tlsConfigSource, config)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get client TLS config: %w", err)
	}
	d := certloader.DialerWithCertificate(clientConfig, *connectTimeout, dialer)
	return func(ctx context.Context) (net.Conn, error) {
			return d.DialContext(ctx, network, address)
		},
		regoPolicy, nil
}

// clientACL builds the server-verification ACL from the --verify-* flags.
func clientACL(regoPolicy policy.Policy) (auth.ACL, error) {
	allowedURIs, err := wildcard.CompileList(*clientAllowedURIs)
	if err != nil {
		logger.Printf("invalid URI pattern in --verify-uri flag (%s)", err)
		return auth.ACL{}, err
	}
	return auth.ACL{
		AllowedCNs:      *clientAllowedCNs,
		AllowedOUs:      *clientAllowedOUs,
		AllowedDNSs:     *clientAllowedDNSs,
		AllowedIPs:      *clientAllowedIPs,
		AllowedURIs:     allowedURIs,
		AllowOPAQuery:   regoPolicy,
		OPAQueryTimeout: *connectTimeout,
		AllowedPins:     decodedClientPins,
	}, nil
}

func proxyLoggerFlags(flags []string) int {
	out := proxy.LogEverything
	for _, flag := range flags {
		switch flag {
		case "all":
			// Disable all proxy logs
			out = 0
		case "conns":
			// Disable connection logs
			out = out & ^proxy.LogConnections
		case "conn-errs":
			// Disable connection errors logs
			out = out & ^proxy.LogConnectionErrors
		case "handshake-errs":
			// Disable handshake error logs
			out = out & ^proxy.LogHandshakeErrors
		}
	}
	return out
}

func getTLSConfigSource(disableAuth bool) (certloader.TLSConfigSource, error) {
	if *useWorkloadAPI {
		logger.Printf("using SPIFFE Workload API as certificate source")
		source, err := certloader.TLSConfigSourceFromWorkloadAPI(*useWorkloadAPIAddr, disableAuth, *useWorkloadAPITimeout, logger)
		if err != nil {
			logger.Printf("error: unable to create workload API TLS source: %s\n", err)
			return nil, err
		}
		return source, nil
	}

	if *serverAutoACMEFQDN != "" {
		logger.Printf("using ACME server as certificate source")
		acmeConfig := certloader.ACMEConfig{
			FQDN:               *serverAutoACMEFQDN,
			Email:              *serverAutoACMEEmail,
			TOSAgreed:          *serverAutoACMEAgreedTOS,
			ProdCAURL:          *serverAutoACMEProdCA,
			TestCAURL:          *serverAutoACMETestCA,
			CABundlePath:       *caBundlePath,
			RenewCheckInterval: *serverAutoACMERenewCheckInterval,
			AltTLSALPNPort:     *serverAutoACMEAltTLSALPNPort,
		}
		source, err := certloader.TLSConfigSourceFromACME(&acmeConfig)
		if err != nil {
			logger.Printf("error: Unable to load or obtain ACME cert: %s\n", err)
			return nil, err
		}
		return source, nil
	}

	cert, err := buildCertificate(*keystorePath, *certPath, *keyPath, *keystorePass, *caBundlePath, logger)
	if err != nil {
		logger.Printf("error: unable to load certificates: %s\n", err)
		return nil, err
	}
	return certloader.TLSConfigSourceFromCertificate(cert, logger), nil
}

func getServerConfig(source certloader.TLSConfigSource, config *tls.Config) (certloader.TLSServerConfig, error) {
	return source.GetServerConfig(config)
}

func getClientConfig(source certloader.TLSConfigSource, config *tls.Config) (certloader.TLSClientConfig, error) {
	return source.GetClientConfig(config)
}
