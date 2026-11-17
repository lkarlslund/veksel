package contentscan

import (
	"context"
	"errors"
	"sync/atomic"
)

// ErrNoTrainer reports that no scanner currently accepts spam/ham training.
var ErrNoTrainer = errors.New("no content scanner accepts training")

// Switch is a stable scanning and training boundary whose pipeline can be
// replaced while messages are scanned. Each scan runs to completion on the
// pipeline that was installed when it started. The zero value has no
// pipeline and scans nothing.
type Switch struct {
	current atomic.Pointer[switchState]
}

type switchState struct {
	pipeline *Pipeline
	trainer  Trainer
}

// Set installs pipeline and trainer for subsequent scans and training; nil
// removes them.
func (s *Switch) Set(pipeline *Pipeline, trainer Trainer) {
	s.current.Store(&switchState{pipeline: pipeline, trainer: trainer})
}

func (s *Switch) state() switchState {
	if state := s.current.Load(); state != nil {
		return *state
	}
	return switchState{}
}

// Scan runs the current pipeline. Without one it returns an empty report.
func (s *Switch) Scan(ctx context.Context, message Message) Report {
	pipeline := s.state().pipeline
	if pipeline == nil {
		return Report{}
	}
	return pipeline.Scan(ctx, message)
}

// Status projects the current pipeline's engines; it is empty without one.
func (s *Switch) Status() []EngineStatus {
	pipeline := s.state().pipeline
	if pipeline == nil {
		return nil
	}
	return pipeline.Status()
}

// Learn forwards explicit training to the current trainer.
func (s *Switch) Learn(ctx context.Context, message []byte, spam bool) error {
	trainer := s.state().trainer
	if trainer == nil {
		return ErrNoTrainer
	}
	return trainer.Learn(ctx, message, spam)
}

// TrainingAvailable reports whether a trainer is currently installed.
func (s *Switch) TrainingAvailable() bool { return s.state().trainer != nil }
