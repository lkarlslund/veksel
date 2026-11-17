package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/log"
)

// shutdownDrainTimeout bounds how long shutdown waits for protocol sessions
// and HTTP requests to finish before closing their connections.
const shutdownDrainTimeout = 20 * time.Second

// drainTarget is one component that stops accepting work and waits for its
// active sessions or requests until the shutdown context ends.
type drainTarget struct {
	name     string
	shutdown func(context.Context) error
}

// drain shuts every target down concurrently under one shared deadline.
func drain(ctx context.Context, targets []drainTarget) {
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := target.shutdown(ctx); err != nil {
				log.Warn("shutdown: drain incomplete", "component", target.name, "error", err)
			}
		}()
	}
	wg.Wait()
}

// waitForStop blocks until SIGINT, SIGTERM, or an API shutdown or restart
// request, and returns errRestartRequested for a restart.
func (s *server) waitForStop() error {
	var exitErr error
	select {
	case <-s.signalCtx.Done():
		log.Info("shutting down...")
	case <-s.shutdownCh:
		log.Info("shutting down (api request)...")
	case <-s.restartCh:
		log.Info("restarting (api request)...")
		exitErr = errRestartRequested
	}
	s.stopSignals()
	return exitErr
}

// shutdown stops accepting new work, then drains protocol sessions and HTTP
// requests under one deadline so nothing submits into the queue or writes to
// the stores after they close. Background workers stop, and are waited for,
// before the queue they feed; the stores close last through the cleanup stack
// as run returns.
func (s *server) shutdown() {
	if s.stopLongPolls != nil {
		s.stopLongPolls()
	}
	targets := s.protocolControl.controllers.beginShutdown()
	for _, server := range s.httpListeners.Servers() {
		targets = append(targets, drainTarget{name: "http " + server.Addr, shutdown: shutdownHTTP(server)})
	}
	for _, server := range s.pprofListener.Servers() {
		targets = append(targets, drainTarget{name: "pprof", shutdown: shutdownHTTP(server)})
	}
	if s.dnsServer != nil {
		s.dnsServer.Close()
	}
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), shutdownDrainTimeout)
	drain(drainCtx, targets)
	cancelDrain()

	s.webhooks.Stop()
	s.stopScheduledMail()
	s.background.Stop()
	if s.sendGuard != nil {
		s.sendGuard.Wait()
	}
	if s.mailQueue != nil {
		s.mailQueue.Close()
	}
	s.drained = true

	fmt.Fprintln(os.Stderr, "bye")
}

// shutdownHTTP gracefully shuts server down and forcibly closes remaining
// connections, such as long polls and event streams, when ctx ends first.
func shutdownHTTP(server *http.Server) func(context.Context) error {
	return func(ctx context.Context) error {
		err := server.Shutdown(ctx)
		if err != nil {
			_ = server.Close()
		}
		return err
	}
}
