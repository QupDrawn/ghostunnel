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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/ghostunnel/ghostunnel/proxy"
)

type statusDialer struct {
	dial proxy.DialFunc
}

func (sd statusDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return sd.dial(ctx)
}

type statusHandler struct {
	// Mutex for locking
	mu *sync.Mutex
	// Backend dialer and HTTP client to check if target is up and running
	// - dialer is used for raw TCP status checks
	// - client is used for HTTP status checks if a statusTargetAddress is supplied
	dial                proxy.DialFunc
	client              *http.Client
	command             string
	listenAddress       string
	forwardAddress      string
	statusTargetAddress string
	// Current status
	listening bool
	reloading bool
	stopping  bool
	// Last time we reloaded
	lastReload time.Time
	// Outcome and time of the last backend probe, shared by callers without
	// a verified client certificate (see checkBackendStatusCached).
	backendMu      sync.Mutex
	backendChecked time.Time
	backendErr     error
	// refusal, when set, reports why serving is refused right now (the
	// observer ring's gate, or its trace having failed), or "" when it is
	// not. While it reports a reason the status is critical.
	refusal func() string
}

// readyNotifier sends the service manager's readiness notification (a seam
// for tests, which count it).
var readyNotifier = notifyServiceReady

// statusBackendCheckInterval bounds how often callers without a verified
// client certificate can make ghostunnel probe its backend. In client mode
// the probe is a full TLS handshake with ghostunnel's own certificate, so an
// unauthenticated GET must not be able to drive it at will.
const statusBackendCheckInterval = 5 * time.Second

// statusResponse is the /_status body. The health summary (ok, status,
// message, backend_ok, backend_status, time) is served to every caller; the
// remaining fields describe the deployment and are only filled in for a
// caller whose client certificate the status listener verified.
type statusResponse struct {
	Ok             bool      `json:"ok"`
	Status         string    `json:"status"`
	ListenAddress  string    `json:"listen_address,omitempty"`
	ForwardAddress string    `json:"forward_address,omitempty"`
	BackendOk      bool      `json:"backend_ok"`
	BackendStatus  string    `json:"backend_status"`
	BackendError   string    `json:"backend_error,omitempty"`
	Time           time.Time `json:"time"`
	LastReload     time.Time `json:"last_reload,omitzero"`
	Hostname       string    `json:"hostname,omitempty"`
	HaltReason     string    `json:"halt_reason,omitempty"`
	Message        string    `json:"message"`
	Revision       string    `json:"revision,omitempty"`
	Compiler       string    `json:"compiler,omitempty"`
}

func newStatusHandler(dial proxy.DialFunc, command, listenAddress, forwardAddress, statusTargetAddress string) *statusHandler {
	client := http.Client{
		Transport: &http.Transport{
			DialContext: statusDialer{dial}.DialContext,
		},
	}
	status := &statusHandler{
		mu:                  &sync.Mutex{},
		dial:                dial,
		client:              &client,
		command:             command,
		listenAddress:       listenAddress,
		forwardAddress:      forwardAddress,
		statusTargetAddress: statusTargetAddress,
		listening:           false,
		reloading:           false,
		stopping:            false,
		lastReload:          time.Time{},
	}
	return status
}

func (s *statusHandler) Listening() {
	// Hold the lock across the notify calls so the stopping check and the
	// readiness notification are atomic with respect to Stopping(); otherwise
	// a timed reload racing shutdown could emit READY=1 after STOPPING=1.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		// Once we're shutting down, don't resurrect healthy state or
		// re-notify readiness (e.g. a timed reload firing mid-drain).
		return
	}
	s.listening = true
	s.reloading = false

	readyNotifier()
	notifyServiceStatus(fmt.Sprintf("listening | %s proxying %s => %s", s.command, s.listenAddress, s.forwardAddress))
}

func (s *statusHandler) Reloading() {
	// Hold the lock across the notify calls so the stopping check and the
	// reload notification are atomic with respect to Stopping(); otherwise a
	// timed reload racing shutdown could emit RELOADING=1 after STOPPING=1.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		// Once we're shutting down, a timed reload firing mid-drain must not
		// flip us back to reloading or re-emit RELOADING=1.
		return
	}
	s.reloading = true
	s.lastReload = time.Now()

	notifyServiceReloading()
	notifyServiceStatus(fmt.Sprintf("reloading | %s proxying %s => %s", s.command, s.listenAddress, s.forwardAddress))
}

// ReloadFailed ends a reload that did not succeed. The process is not
// listening again in any useful sense (the ring refuses to serve until a
// reload succeeds), so no readiness notification is sent; the status
// message says what happened.
func (s *statusHandler) ReloadFailed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return
	}
	s.reloading = false

	notifyServiceStatus(fmt.Sprintf("reload failed, refusing to serve | %s proxying %s => %s", s.command, s.listenAddress, s.forwardAddress))
}

func (s *statusHandler) Stopping() {
	// Set stopping and send the stop notification while holding the lock, so a
	// concurrent Listening()/Reloading() either runs fully before us or observes
	// stopping and skips its notify — no READY/RELOADING can follow STOPPING.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listening = false
	s.reloading = false
	s.stopping = true

	notifyServiceStopping()
	notifyServiceStatus(fmt.Sprintf("stopping | %s proxying %s => %s", s.command, s.listenAddress, s.forwardAddress))
}

// HandleWatchdog feeds the service manager's watchdog, at half the interval
// it gave (WATCHDOG_USEC), only while isHealthy says so: the accept loop is
// alive, the listener open and the ring holds no sticky refusal
// (Environment.healthy). The backend is deliberately not part of it;
// restarting ghostunnel when the backend is down helps nothing.
func (s *statusHandler) HandleWatchdog(isHealthy func() bool) {
	//nolint:errcheck
	go handleServiceWatchdog(isHealthy, nil)
}

// status builds the response. With detailed set the caller was authenticated
// and gets the deployment details and a fresh backend probe; otherwise only
// the health summary is filled in and the probe result is shared across
// callers, so an anonymous request neither learns where ghostunnel listens
// and forwards nor gets to trigger a probe of its own.
func (s *statusHandler) status(ctx context.Context, detailed bool) statusResponse {
	resp := statusResponse{
		Time: time.Now(),

		// Defaults. Will be overridden if checks fail.
		BackendOk:     true,
		BackendStatus: "ok",
	}

	var backendErr error
	if detailed {
		resp.Revision = version
		resp.Compiler = runtime.Version()
		resp.ListenAddress = s.listenAddress
		resp.ForwardAddress = s.forwardAddress
		backendErr = s.checkBackendStatus(ctx)
	} else {
		backendErr = s.checkBackendStatusCached(ctx)
	}
	if backendErr != nil {
		resp.BackendOk = false
		if detailed {
			resp.BackendError = backendErr.Error()
		}
		resp.BackendStatus = "critical"
	}

	halted := ""
	if s.refusal != nil {
		halted = s.refusal()
	}
	if detailed {
		resp.HaltReason = halted
	}

	s.mu.Lock()
	if detailed {
		resp.LastReload = s.lastReload
	}
	resp.Ok = s.listening && resp.BackendOk && halted == ""
	if s.stopping {
		resp.Message = "stopping"
	} else if halted != "" {
		resp.Message = "halted"
	} else if s.reloading {
		resp.Message = "reloading"
	} else if s.listening {
		resp.Message = "listening"
	} else {
		resp.Message = "initializing"
	}
	s.mu.Unlock()

	if resp.Ok && resp.BackendOk {
		resp.Status = "ok"
	} else {
		resp.Status = "critical"
	}

	if detailed {
		hostname, err := os.Hostname()
		if err == nil {
			resp.Hostname = hostname
		}
	}

	return resp
}

func (s *statusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp := s.status(r.Context(), verifiedClientCert(r))
	out, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !resp.Ok {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	_, _ = w.Write(out)
}

// checkBackendStatusCached returns the outcome of the last backend probe,
// running a new one only when the last is older than
// statusBackendCheckInterval. Concurrent callers wait for the probe in
// flight rather than starting their own. The probe runs detached from the
// caller's cancellation so a caller that disconnects mid-probe cannot leave
// a cancellation error cached for everyone else; the backend dialers carry
// their own timeouts.
func (s *statusHandler) checkBackendStatusCached(ctx context.Context) error {
	s.backendMu.Lock()
	defer s.backendMu.Unlock()
	if !s.backendChecked.IsZero() && time.Since(s.backendChecked) < statusBackendCheckInterval {
		return s.backendErr
	}
	s.backendErr = s.checkBackendStatus(context.WithoutCancel(ctx))
	s.backendChecked = time.Now()
	return s.backendErr
}

func (s *statusHandler) checkBackendStatus(ctx context.Context) error {
	// If a statusTargetAddress was supplied attempt a HTTP status check.
	// Otherwise, fallback to a raw TCP status check.
	if s.statusTargetAddress != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.statusTargetAddress, nil)
		if err != nil {
			return err
		}
		resp, err := s.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("target returned status: %d", resp.StatusCode)
		}
	} else {
		conn, err := s.dial(ctx)
		if err != nil {
			return err
		}
		conn.Close()
	}

	return nil
}
