// Package attachment inspects the MIME parts of a message for risky
// attachments: dangerous or disguised file types, Office macros,
// password-protected archives, spoofed file names, and phishing HTML.
//
// Inspection is bounded in parts, nesting depth, decoded bytes, and archive
// entries, never executes or fully expands content, and reports named
// findings. The spam engine scores the findings as symbols and the SMTP
// boundary applies the hard policy to the executable-class ones.
package attachment

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
)

// Symbol names reported in findings. The spam engine owns their scores.
const (
	SymbolDangerousExt     = "ATTACH_DANGEROUS_EXT"
	SymbolDoubleExt        = "ATTACH_DOUBLE_EXT"
	SymbolTypeMismatch     = "ATTACH_TYPE_MISMATCH"
	SymbolMacro            = "ATTACH_MACRO"
	SymbolEncryptedArchive = "ATTACH_ENCRYPTED_ARCHIVE"
	SymbolArchiveBomb      = "ATTACH_ARCHIVE_BOMB"
	SymbolRTLO             = "ATTACH_RTLO"
	SymbolHTMLForm         = "ATTACH_HTML_FORM"
)

// Mode is the hard policy applied to dangerous executable attachments.
type Mode string

const (
	// ModeOff disables inspection entirely.
	ModeOff Mode = "off"
	// ModeScore reports findings as spam symbols only.
	ModeScore Mode = "score"
	// ModeQuarantine quarantines messages with dangerous executables.
	ModeQuarantine Mode = "quarantine"
	// ModeReject rejects messages with dangerous executables at DATA.
	ModeReject Mode = "reject"
)

const maxBlockedExtensions = 256

// DefaultBlockedExtensions returns the built-in dangerous extension list.
func DefaultBlockedExtensions() []string {
	return []string{
		"exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "wsc", "hta",
		"msi", "msp", "mst", "lnk", "cpl", "jar", "ps1", "psm1", "reg", "iso", "img", "vhd", "vhdx",
		"apk", "appx", "msix", "dll", "sys", "gadget", "inf", "scf", "chm", "ocx", "application",
	}
}

// Settings is the managed-configuration form of a policy.
type Settings struct {
	Mode              string
	BlockedExtensions []string
	// CheckSubmissions applies the policy to authenticated submissions too.
	CheckSubmissions bool
}

// Policy is one immutable attachment policy; replace it rather than
// mutating it.
type Policy struct {
	mode             Mode
	blocked          map[string]struct{}
	checkSubmissions bool
}

// NewPolicy validates settings. Extensions are lower-cased and a leading dot
// is ignored; each must be 1-16 letters or digits.
func NewPolicy(settings Settings) (*Policy, error) {
	mode := Mode(settings.Mode)
	if !slices.Contains([]Mode{ModeOff, ModeScore, ModeQuarantine, ModeReject}, mode) {
		return nil, errors.New("attachment_policy must be off, score, quarantine, or reject")
	}
	if len(settings.BlockedExtensions) > maxBlockedExtensions {
		return nil, fmt.Errorf("at most %d blocked attachment extensions are allowed", maxBlockedExtensions)
	}
	blocked := make(map[string]struct{}, len(settings.BlockedExtensions))
	for _, entry := range settings.BlockedExtensions {
		extension := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(entry), "."))
		if !validExtension(extension) {
			return nil, fmt.Errorf("blocked attachment extension %q must be 1-16 letters or digits", entry)
		}
		blocked[extension] = struct{}{}
	}
	return &Policy{mode: mode, blocked: blocked, checkSubmissions: settings.CheckSubmissions}, nil
}

func validExtension(extension string) bool {
	if extension == "" || len(extension) > 16 {
		return false
	}
	for _, character := range extension {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

// Mode returns the hard policy mode.
func (p *Policy) Mode() Mode { return p.mode }

// Applies reports whether a message is inspected: never when the policy is
// off, and for authenticated submissions only when they are opted in.
func (p *Policy) Applies(authenticated bool) bool {
	return p != nil && p.mode != ModeOff && (!authenticated || p.checkSubmissions)
}

// Switch is a stable inspection boundary whose policy is replaced live. The
// zero value inspects nothing.
type Switch struct {
	policy atomic.Pointer[Policy]
}

// Set installs policy for subsequent messages; nil disables inspection.
func (s *Switch) Set(policy *Policy) { s.policy.Store(policy) }

// Load returns the current policy, or nil.
func (s *Switch) Load() *Policy { return s.policy.Load() }

// Finding is one named piece of attachment evidence.
type Finding struct {
	Symbol string `json:"symbol"`
	// Detail names what matched, such as the file name.
	Detail string `json:"detail,omitempty"`
	// Hard marks a dangerous executable the hard policy acts on.
	Hard bool `json:"hard,omitempty"`
}

// Report is the outcome of inspecting one message.
type Report struct {
	Findings []Finding `json:"findings,omitempty"`
}

// Hard returns the findings the hard policy acts on.
func (r Report) Hard() []Finding {
	var hard []Finding
	for _, finding := range r.Findings {
		if finding.Hard {
			hard = append(hard, finding)
		}
	}
	return hard
}

// Reason is a bounded, reportable summary of the hard findings.
func (r Report) Reason() string {
	parts := make([]string, 0, 4)
	for _, finding := range r.Hard() {
		if len(parts) == 4 {
			break
		}
		parts = append(parts, finding.Symbol+" ("+finding.Detail+")")
	}
	return "Attachment policy: " + strings.Join(parts, ", ")
}
