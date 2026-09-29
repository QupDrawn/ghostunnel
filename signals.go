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
	"errors"
	"os"
	"os/signal"
	"slices"
	"time"

	"github.com/ghostunnel/ghostunnel/proxy"
)

// isShutdownSignal checks if the received signal is a shutdown signal
// and returns true if that's the case. Returns false if the signal is
// a refresh signal.
func isShutdownSignal(sig os.Signal) bool {
	return slices.Contains(shutdownSignals, sig)
}

// signalHandler listens for incoming shutdown or refresh signals. If we get
// a shutdown signal, we stop listening for new connections and gracefully
// terminate the process. If we get a refresh signal, reload certificates.
func (env *Environment) signalHandler(p *proxy.Proxy) {
	signals := make(chan os.Signal, 3)
	signal.Notify(signals, append(shutdownSignals, refreshSignals...)...)

	shutdownFunc := func() {
		// Stop delivering signals to our channel and make sure refresh signals
		// (SIGHUP/SIGUSR1) don't revert to their default disposition (terminate)
		// while we drain in-flight connections in p.Wait(). Ignore them instead.
		signal.Stop(signals)
		if len(refreshSignals) > 0 {
			signal.Ignore(refreshSignals...)
		}

		env.status.Stopping()

		// Best-effort graceful shutdown of status listener; closeRing waits
		// for it.
		go env.stopStatus()

		// Force-exit after timeout
		time.AfterFunc(env.shutdownTimeout, func() {
			// Graceful shutdown timeout reached. If we can't drain connections
			// to exit gracefully after this timeout, let's just exit.
			logger.Printf("graceful shutdown timeout: forcing exit")
			exitFunc(1)
		})

		p.Shutdown()
		logger.Printf("shutdown proxy, waiting for drain")
	}

	for {
		// Wait for a signal
		select {
		case <-env.shutdownChannel:
			logger.Printf("shutdown request processing")

			shutdownFunc()

			return
		case <-serviceShutdownChan(): // nil on non-Windows; nil channel blocks forever, disabling this case
			logger.Printf("Windows service stop requested, shutting down")
			env.ring.shutdownRequested("service-control", true, nil, "Windows service stop")

			shutdownFunc()

			return
		case sig := <-signals:
			if isShutdownSignal(sig) {
				logger.Printf("received %s, shutting down", sig.String())
				env.ring.shutdownRequested("signal", true, nil, sig.String())

				shutdownFunc()

				return
			}

			logger.Printf("received %s, reloading TLS configuration", sig.String())
			env.reload()
		}
	}
}

// statusShutdownGrace bounds the status listener's graceful shutdown.
const statusShutdownGrace = 5 * time.Second

// stopStatus shuts the status listener down gracefully, waiting at most
// statusShutdownGrace for its handlers, once; a later call waits for the
// first to return.
func (env *Environment) stopStatus() {
	env.statusStopOnce.Do(func() {
		if env.statusHTTP == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), statusShutdownGrace)
		defer cancel()
		//nolint:errcheck
		env.statusHTTP.Shutdown(ctx)
	})
}

// startReloads starts the timed reload loop, every interval, unless the
// interval is not positive.
func (env *Environment) startReloads(interval time.Duration) {
	if interval <= 0 {
		return
	}
	env.reloadStop = make(chan struct{})
	env.reloads.Add(1)
	go func() {
		defer env.reloads.Done()
		env.reloadHandler(interval, env.reloadStop)
	}()
}

// stopReloads ends the timed reload loop and waits for it to return, a
// reload in progress included.
func (env *Environment) stopReloads() {
	env.reloadStopOnce.Do(func() {
		if env.reloadStop != nil {
			close(env.reloadStop)
		}
	})
	env.reloads.Wait()
}

// closeRing closes the observer ring once nothing else can record: the
// timed reloads have stopped and the status listener's handlers have
// returned, or its graceful shutdown ran out.
func (env *Environment) closeRing() {
	env.stopReloads()
	env.stopStatus()
	env.ring.close()
}

func (env *Environment) reloadHandler(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		env.reload()
	}
}

func (env *Environment) reload() {
	env.status.Reloading()
	var reloadErr error
	if err := env.tlsConfigSource.Reload(); err != nil {
		logger.Printf("error reloading TLS configuration: %s", err)
		reloadErr = err
	}
	if env.regoPolicy != nil {
		if err := env.regoPolicy.Reload(); err != nil {
			logger.Printf("error reloading OPA policy: %s", err)
			reloadErr = errors.Join(reloadErr, err)
		}
	}
	// Whether or not the reload succeeded, some input may have changed.
	env.verifyCache.Invalidate()
	if !env.ring.reloaded(reloadErr) {
		// A failed reload does not put the process back into service: the
		// ring refuses every accept until a reload succeeds, and the
		// service manager is not told READY again.
		logger.Printf("reloading configuration failed")
		env.status.ReloadFailed()
		return
	}
	logger.Printf("reloading configuration complete")
	env.status.Listening()
}
