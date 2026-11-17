package main

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/dane"
	"github.com/lkarlslund/veksel/pkg/log"
)

// daneProbeInterval bounds how stale the validating-resolver verdict shown to
// operators, and used to deactivate DANE, may become.
const daneProbeInterval = 6 * time.Hour

// daneRuntime owns outbound DANE and its validating-resolver probe.
type daneRuntime struct {
	service *dane.Service
	probing atomic.Bool
}

// openDANE configures outbound DANE from cfg. The first validation probe
// runs a minute after startup, then periodically and on demand from the
// Outbound TLS administration page.
func (s *server) openDANE(cfg *config.Config) error {
	s.dane.service = dane.New(dane.Options{})
	if err := s.applyDANE(cfg); err != nil {
		return startupError("configure DANE", err)
	}
	s.background.Go(func(ctx context.Context) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
		s.background.Every(daneProbeInterval, true, s.probeDANE)
	})
	return nil
}

// applyDANE installs the dane_* settings for the next delivery.
func (s *server) applyDANE(cfg *config.Config) error {
	resolvers, err := config.ParseResolverAddresses("dane_resolvers", cfg.DaneResolvers)
	if err != nil {
		return err
	}
	s.dane.service.Configure(dane.Config{Enabled: cfg.DaneEnabled, Resolvers: resolvers})
	return nil
}

// probeDANE checks that the trusted resolver validates DNSSEC. Concurrent
// requests share one probe.
func (s *server) probeDANE() {
	if !s.dane.probing.CompareAndSwap(false, true) {
		return
	}
	defer s.dane.probing.Store(false)
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	status := s.dane.service.Probe(ctx)
	if status.Enabled && !status.Active {
		log.Warn("DANE: outbound DANE is inactive", "detail", status.Detail)
	}
}

// daneStatus reports the DANE state for administration and starts a fresh
// probe in the background when the verdict is unknown or stale.
func (s *server) daneStatus() dane.Status {
	status := s.dane.service.Status()
	if status.Active && (status.CheckedAt.IsZero() || time.Since(status.CheckedAt) > daneProbeInterval) {
		s.spawn(s.probeDANE)
	}
	return status
}
