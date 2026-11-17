// Package virus provides virus scanning for incoming mail.
//
// It supports multiple scanner backends (built-in signature detection,
// ClamAV) and integrates with the SMTP delivery pipeline.
package virus

import (
	"fmt"
	"sync"
	"time"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
)

var log = logpkg.For(logpkg.ModuleVirus)

// Scanner defines the interface for virus detection implementations.
type Scanner interface {
	// Scan checks data for viruses. Returns the virus name (if infected),
	// whether the data is infected, and any error encountered.
	Scan(data []byte) (name string, infected bool, err error)

	// Name returns the scanner identifier, e.g. "clamav", "builtin".
	Name() string
}

// Manager coordinates multiple scanners and provides a unified scan interface.
type Manager struct {
	scanners []Scanner
	mu       sync.RWMutex
}

// NewManager creates a Manager with the given scanners.
// Scanners are run in order; the first detection stops the chain.
func NewManager(scanners ...Scanner) *Manager {
	return &Manager{scanners: scanners}
}

// Scan runs the data through all configured scanners.
// Returns the first virus name found, or empty if clean.
func (m *Manager) Scan(data []byte) (virusName string, infected bool, err error) {
	m.mu.RLock()
	scanners := make([]Scanner, len(m.scanners))
	copy(scanners, m.scanners)
	m.mu.RUnlock()

	for _, s := range scanners {
		name, infected, err := s.Scan(data)
		if err != nil {
			log.Warn("scanner error", "scanner", s.Name(), "error", err)
			// Continue with next scanner on error
			continue
		}
		if infected {
			log.Info("virus detected", "scanner", s.Name(), "virus", name)
			return name, true, nil
		}
	}
	return "", false, nil
}

// GetScanners returns the list of configured scanner names.
func (m *Manager) GetScanners() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, len(m.scanners))
	for i, s := range m.scanners {
		names[i] = s.Name()
	}
	return names
}

// QuarantineEntry represents a message stored in the virus quarantine.
type QuarantineEntry struct {
	ID                    string            `json:"id"`
	OwnerID               string            `json:"owner_id,omitempty"`
	Sender                string            `json:"sender"`
	Recipient             string            `json:"recipient"`
	Subject               string            `json:"subject"`
	Date                  string            `json:"date"`
	VirusName             string            `json:"virus_name"`
	Scanner               string            `json:"scanner"`
	MessageSize           int64             `json:"message_size"`
	MessageData           []byte            `json:"message_data"`
	Headers               map[string]string `json:"headers,omitempty"`
	ReasonType            string            `json:"reason_type,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	AuthenticationResults string            `json:"authentication_results,omitempty"`
	ScanTranscript        string            `json:"scan_transcript,omitempty"`
	CreatedAt             time.Time         `json:"created_at,omitzero"`
	ExpiresAt             time.Time         `json:"expires_at,omitzero"`
}

// ScanResult holds the result of a virus scan.
type ScanResult struct {
	Infected  bool   `json:"infected"`
	VirusName string `json:"virus_name,omitempty"`
	Scanner   string `json:"scanner,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ErrVirusDetected is returned when a virus is found during scanning.
type ErrVirusDetected struct {
	VirusName string
	Scanner   string
}

func (e *ErrVirusDetected) Error() string {
	return fmt.Sprintf("virus detected: %s (scanner: %s)", e.VirusName, e.Scanner)
}
