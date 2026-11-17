// Package contentscan defines the protocol-neutral message scanning boundary.
package contentscan

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

const (
	maxEngineNameBytes = 64
	maxSymbols         = 64
	maxSymbolNameBytes = 128
	maxMalwareNames    = 16
	maxEvidenceBytes   = 512
)

//go:generate go tool enumer -type=Verdict,FailurePolicy,Decision -linecomment -json -text -output=enums_generated.go

// Verdict is an engine's content classification.
type Verdict uint8

const (
	VerdictUnknown Verdict = iota // unknown
	VerdictClean                  // clean
	VerdictSpam                   // spam
	VerdictMalware                // malware
)

// FailurePolicy controls admission when an engine cannot produce a verdict.
type FailurePolicy uint8

const (
	FailurePolicyOpen       FailurePolicy = iota // fail-open
	FailurePolicyDefer                           // fail-closed
	FailurePolicyQuarantine                      // quarantine
)

// Decision is the pipeline's strongest requested admission action. The SMTP
// boundary can strengthen a quarantine to rejection based on connection type.
type Decision uint8

const (
	DecisionAllow      Decision = iota // allow
	DecisionQuarantine                 // quarantine
	DecisionDefer                      // defer
)

// Message is a read-only view of the content and routing metadata supplied to
// every scanner. Content is never copied by Pipeline; implementations must not
// retain or mutate it after Scan returns.
type Message struct {
	Content      []byte
	Headers      map[string]string
	EnvelopeFrom string
	Recipient    string
	RemoteIP     string
}

// Symbol is bounded, engine-specific evidence contributing to a result.
type Symbol struct {
	Name        string  `json:"name"`
	Score       float64 `json:"score,omitempty"`
	Description string  `json:"description,omitempty"`
}

// Result is one scanner's structured result. Pipeline owns Engine, Duration,
// ErrorCode and Error and normalizes all externally supplied evidence.
type Result struct {
	Engine        string        `json:"engine"`
	Verdict       Verdict       `json:"verdict"`
	Score         float64       `json:"score,omitempty"`
	RequiredScore float64       `json:"required_score,omitempty"`
	Symbols       []Symbol      `json:"symbols,omitempty"`
	MalwareNames  []string      `json:"malware_names,omitempty"`
	Duration      time.Duration `json:"duration"`
	InputBytes    int64         `json:"input_bytes"`
	ErrorCode     string        `json:"error_code,omitempty"`
	Error         string        `json:"error,omitempty"`
}

// Scanner is implemented by content engines such as the built-in baseline,
// ClamAV and Rspamd. Implementations must honor context cancellation.
type Scanner interface {
	Name() string
	Scan(context.Context, Message) (Result, error)
}

// Trainer accepts an explicit operator or mailbox-owner classification. It is
// deliberately separate from Scanner so inspection and release never imply
// learning, and engines without a learning endpoint need not implement it.
type Trainer interface {
	Learn(context.Context, []byte, bool) error
}

// Engine applies resource and outage policy to one scanner.
type Engine struct {
	Scanner       Scanner
	Timeout       time.Duration
	MaxInputBytes int64
	FailurePolicy FailurePolicy
}

// Report contains bounded per-engine evidence and the strongest admission
// action requested by the configured outage policies or malware verdicts.
type Report struct {
	Results  []Result      `json:"results"`
	Decision Decision      `json:"decision"`
	Duration time.Duration `json:"duration"`
}

// Observer receives the final normalized report for each pipeline execution.
// Implementations must return quickly and must not retain mutable report data.
// It is intended for bounded operational projections such as metrics, not for
// admission decisions or scanner evidence persistence.
type Observer interface {
	ObserveContentScan(Report)
}

// Pipeline runs a validated, immutable engine sequence.
type Pipeline struct {
	engines  []configuredEngine
	observer Observer
}

type configuredEngine struct {
	Engine
	name  string
	state *engineState
}

type engineState struct {
	mu             sync.RWMutex
	scans          uint64
	errors         uint64
	lastVerdict    Verdict
	lastErrorCode  string
	lastDuration   time.Duration
	lastObservedAt time.Time
}

// EngineStatus is the race-safe desired/observed projection used by health
// and administration surfaces.
type EngineStatus struct {
	Name           string        `json:"name"`
	Timeout        time.Duration `json:"timeout"`
	MaxInputBytes  int64         `json:"max_input_bytes"`
	FailurePolicy  FailurePolicy `json:"failure_policy"`
	Scans          uint64        `json:"scans"`
	Errors         uint64        `json:"errors"`
	LastVerdict    Verdict       `json:"last_verdict"`
	LastErrorCode  string        `json:"last_error_code,omitempty"`
	LastDuration   time.Duration `json:"last_duration"`
	LastObservedAt time.Time     `json:"last_observed_at,omitzero"`
}

// New validates and snapshots an engine sequence.
func New(engines ...Engine) (*Pipeline, error) {
	return NewObserved(nil, engines...)
}

// NewObserved validates and snapshots an engine sequence and installs one
// observer for normalized final reports. A nil observer disables observation.
func NewObserved(observer Observer, engines ...Engine) (*Pipeline, error) {
	if len(engines) == 0 {
		return nil, errors.New("at least one content scanner is required")
	}
	seen := make(map[string]struct{}, len(engines))
	configured := make([]configuredEngine, len(engines))
	for index, engine := range engines {
		if engine.Scanner == nil {
			return nil, fmt.Errorf("engine %d has no scanner", index)
		}
		name := strings.ToLower(strings.TrimSpace(engine.Scanner.Name()))
		if !validEngineName(name) {
			return nil, fmt.Errorf("engine %d has invalid name %q", index, name)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("duplicate content scanner %q", name)
		}
		seen[name] = struct{}{}
		if engine.Timeout <= 0 || engine.Timeout > 10*time.Minute {
			return nil, fmt.Errorf("content scanner %q timeout must be between 1ns and 10m", name)
		}
		if engine.MaxInputBytes < 1 {
			return nil, fmt.Errorf("content scanner %q maximum input must be positive", name)
		}
		if !engine.FailurePolicy.IsAFailurePolicy() {
			return nil, fmt.Errorf("content scanner %q has invalid failure policy", name)
		}
		configured[index] = configuredEngine{Engine: engine, name: name, state: &engineState{}}
	}
	return &Pipeline{engines: configured, observer: observer}, nil
}

// Scan runs every engine in stable order. Scanner failures are recorded as
// evidence and projected through their configured policy instead of being
// discarded or returned as an ambiguous generic error.
func (p *Pipeline) Scan(ctx context.Context, message Message) Report {
	started := time.Now()
	report := Report{Results: make([]Result, 0, len(p.engines))}
	for _, engine := range p.engines {
		result := p.scanEngine(ctx, engine, message)
		engine.observe(result)
		report.Results = append(report.Results, result)
		switch {
		case result.ErrorCode != "":
			report.Decision = strongerDecision(report.Decision, failureDecision(engine.FailurePolicy))
		case result.Verdict == VerdictMalware:
			report.Decision = strongerDecision(report.Decision, DecisionQuarantine)
		}
	}
	report.Duration = time.Since(started)
	if p.observer != nil {
		p.observer.ObserveContentScan(report)
	}
	return report
}

// Status returns a stable snapshot in configured engine order.
func (p *Pipeline) Status() []EngineStatus {
	status := make([]EngineStatus, len(p.engines))
	for index, engine := range p.engines {
		engine.state.mu.RLock()
		status[index] = EngineStatus{
			Name: engine.name, Timeout: engine.Timeout, MaxInputBytes: engine.MaxInputBytes, FailurePolicy: engine.FailurePolicy,
			Scans: engine.state.scans, Errors: engine.state.errors, LastVerdict: engine.state.lastVerdict,
			LastErrorCode: engine.state.lastErrorCode, LastDuration: engine.state.lastDuration, LastObservedAt: engine.state.lastObservedAt,
		}
		engine.state.mu.RUnlock()
	}
	return status
}

func (engine configuredEngine) observe(result Result) {
	engine.state.mu.Lock()
	defer engine.state.mu.Unlock()
	engine.state.scans++
	if result.ErrorCode != "" {
		engine.state.errors++
	}
	engine.state.lastVerdict = result.Verdict
	engine.state.lastErrorCode = result.ErrorCode
	engine.state.lastDuration = result.Duration
	engine.state.lastObservedAt = time.Now().UTC()
}

func (p *Pipeline) scanEngine(parent context.Context, engine configuredEngine, message Message) Result {
	name := engine.name
	started := time.Now()
	base := Result{Engine: name, InputBytes: int64(len(message.Content))}
	if int64(len(message.Content)) > engine.MaxInputBytes {
		base.Duration = time.Since(started)
		base.ErrorCode = "input_too_large"
		base.Error = fmt.Sprintf("message has %d bytes; engine limit is %d", len(message.Content), engine.MaxInputBytes)
		return base
	}
	ctx, cancel := context.WithTimeout(parent, engine.Timeout)
	defer cancel()
	request := message
	request.Headers = cloneHeaders(message.Headers)
	result, err := engine.Scanner.Scan(ctx, request)
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	result.Engine = name
	result.InputBytes = int64(len(message.Content))
	result.Duration = time.Since(started)
	if err != nil {
		result.Verdict = VerdictUnknown
		result.ErrorCode = scannerErrorCode(ctx, err)
		result.Error = boundedText(err.Error(), maxEvidenceBytes)
		return normalizeResult(result)
	}
	if !result.Verdict.IsAVerdict() || result.Verdict == VerdictUnknown {
		result.Verdict = VerdictUnknown
		result.ErrorCode = "invalid_result"
		result.Error = "scanner returned an invalid verdict"
	}
	return normalizeResult(result)
}

func normalizeResult(result Result) Result {
	if math.IsNaN(result.Score) || math.IsInf(result.Score, 0) {
		result.Score = 0
	}
	if math.IsNaN(result.RequiredScore) || math.IsInf(result.RequiredScore, 0) {
		result.RequiredScore = 0
	}
	if len(result.Symbols) > maxSymbols {
		result.Symbols = result.Symbols[:maxSymbols]
	}
	for index := range result.Symbols {
		result.Symbols[index].Name = boundedText(result.Symbols[index].Name, maxSymbolNameBytes)
		result.Symbols[index].Description = boundedText(result.Symbols[index].Description, maxEvidenceBytes)
		if math.IsNaN(result.Symbols[index].Score) || math.IsInf(result.Symbols[index].Score, 0) {
			result.Symbols[index].Score = 0
		}
	}
	if len(result.MalwareNames) > maxMalwareNames {
		result.MalwareNames = result.MalwareNames[:maxMalwareNames]
	}
	for index := range result.MalwareNames {
		result.MalwareNames[index] = boundedText(result.MalwareNames[index], maxEvidenceBytes)
	}
	result.ErrorCode = boundedToken(result.ErrorCode, maxEngineNameBytes)
	result.Error = boundedText(result.Error, maxEvidenceBytes)
	return result
}

func scannerErrorCode(ctx context.Context, err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		return "canceled"
	default:
		return "scanner_error"
	}
}

func failureDecision(policy FailurePolicy) Decision {
	switch policy {
	case FailurePolicyDefer:
		return DecisionDefer
	case FailurePolicyQuarantine:
		return DecisionQuarantine
	default:
		return DecisionAllow
	}
}

func strongerDecision(current, candidate Decision) Decision {
	if candidate > current {
		return candidate
	}
	return current
}

func cloneHeaders(headers map[string]string) map[string]string {
	cloned := make(map[string]string, len(headers))
	for name, value := range headers {
		cloned[name] = value
	}
	return cloned
}

func validEngineName(value string) bool {
	if value == "" || len(value) > maxEngineNameBytes {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func boundedToken(value string, limit int) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var result strings.Builder
	for _, character := range value {
		if result.Len() >= limit {
			break
		}
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_' {
			result.WriteRune(character)
		}
	}
	return result.String()
}

func boundedText(value string, limit int) string {
	value = strings.ToValidUTF8(value, "�")
	value = strings.TrimSpace(strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, value))
	if len(value) <= limit {
		return value
	}
	end := 0
	for index := range value {
		if index > limit {
			break
		}
		end = index
	}
	if end == 0 {
		return ""
	}
	return strings.TrimSpace(value[:end])
}
