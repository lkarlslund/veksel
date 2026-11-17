// Package dane implements outbound SMTP DANE (RFC 7672): DNSSEC-validated
// TLSA discovery through a trusted validating resolver and certificate
// matching per RFC 6698 and RFC 7671.
package dane

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TLSA certificate usages (RFC 6698 section 2.1.1).
const (
	UsagePKIXTA uint8 = 0
	UsagePKIXEE uint8 = 1
	UsageDANETA uint8 = 2
	UsageDANEEE uint8 = 3
)

// TLSA selectors (RFC 6698 section 2.1.2).
const (
	SelectorCert uint8 = 0
	SelectorSPKI uint8 = 1
)

// TLSA matching types (RFC 6698 section 2.1.3).
const (
	MatchFull   uint8 = 0
	MatchSHA256 uint8 = 1
	MatchSHA512 uint8 = 2
)

// Record is one TLSA resource record.
type Record struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Data         []byte
}

// Usable reports whether SMTP may use the record (RFC 7672 section 3.1):
// only DANE-TA(2) and DANE-EE(3) with a known selector and matching type
// and association data of the right size. PKIX-TA(0) and PKIX-EE(1) are
// unusable for SMTP.
func (r Record) Usable() bool {
	if r.Usage != UsageDANETA && r.Usage != UsageDANEEE {
		return false
	}
	if r.Selector != SelectorCert && r.Selector != SelectorSPKI {
		return false
	}
	switch r.MatchingType {
	case MatchFull:
		return len(r.Data) > 0
	case MatchSHA256:
		return len(r.Data) == sha256.Size
	case MatchSHA512:
		return len(r.Data) == sha512.Size
	}
	return false
}

// String returns the record's presentation form, as used in TLS reports.
func (r Record) String() string {
	return fmt.Sprintf("%d %d %d %s", r.Usage, r.Selector, r.MatchingType, strings.ToUpper(hex.EncodeToString(r.Data)))
}

// Matches reports whether cert carries the record's association data.
func (r Record) Matches(cert *x509.Certificate) bool {
	var selected []byte
	switch r.Selector {
	case SelectorCert:
		selected = cert.Raw
	case SelectorSPKI:
		selected = cert.RawSubjectPublicKeyInfo
	default:
		return false
	}
	switch r.MatchingType {
	case MatchFull:
		return bytes.Equal(selected, r.Data)
	case MatchSHA256:
		sum := sha256.Sum256(selected)
		return bytes.Equal(sum[:], r.Data)
	case MatchSHA512:
		sum := sha512.Sum512(selected)
		return bytes.Equal(sum[:], r.Data)
	}
	return false
}

// Verification failure kinds, used as TLS report failure reason codes.
const (
	FailureNoCertificate = "dane-no-certificate"
	FailureNoMatch       = "dane-no-tlsa-match"
	FailureNameMismatch  = "dane-ta-name-mismatch"
	FailureChainInvalid  = "dane-ta-chain-invalid"
)

// VerifyError reports why a server certificate does not satisfy a TLSA
// RRset.
type VerifyError struct {
	Kind   string
	Detail string
}

func (e *VerifyError) Error() string {
	if e.Detail == "" {
		return "DANE: " + e.Kind
	}
	return "DANE: " + e.Kind + ": " + e.Detail
}

// Verify checks the presented chain (leaf first) against the usable records
// per RFC 7672 section 3.1. DANE-EE(3) matches the leaf and ignores names
// and validity dates. DANE-TA(2) requires a trust anchor in or named by the
// RRset, a valid chain from the leaf to it, and a leaf name matching one of
// names (the MX host and TLSA base domain). It succeeds when any record does.
func Verify(chain []*x509.Certificate, records []Record, names []string, now time.Time) error {
	if len(chain) == 0 {
		return &VerifyError{Kind: FailureNoCertificate}
	}
	leaf := chain[0]
	var taErr error
	for _, record := range records {
		if !record.Usable() {
			continue
		}
		switch record.Usage {
		case UsageDANEEE:
			if record.Matches(leaf) {
				return nil
			}
		case UsageDANETA:
			anchors := trustAnchors(chain, record)
			if len(anchors) == 0 {
				continue
			}
			if err := verifyTrustAnchor(chain, anchors, names, now); err == nil {
				return nil
			} else if taErr == nil {
				taErr = err
			}
		}
	}
	if taErr != nil {
		return taErr
	}
	return &VerifyError{Kind: FailureNoMatch, Detail: "server certificate matches no usable TLSA record"}
}

// trustAnchors returns the certificates that record designates: presented
// certificates that match it, or the record's own certificate when it
// publishes one in full (the server may then omit it from the chain).
func trustAnchors(chain []*x509.Certificate, record Record) []*x509.Certificate {
	var anchors []*x509.Certificate
	for _, cert := range chain {
		if record.Matches(cert) {
			anchors = append(anchors, cert)
		}
	}
	if len(anchors) == 0 && record.Selector == SelectorCert && record.MatchingType == MatchFull {
		if cert, err := x509.ParseCertificate(record.Data); err == nil {
			anchors = append(anchors, cert)
		}
	}
	return anchors
}

func verifyTrustAnchor(chain []*x509.Certificate, anchors []*x509.Certificate, names []string, now time.Time) error {
	roots := x509.NewCertPool()
	for _, anchor := range anchors {
		roots.AddCert(anchor)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	options := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	if _, err := chain[0].Verify(options); err != nil {
		return &VerifyError{Kind: FailureChainInvalid, Detail: err.Error()}
	}
	for _, name := range names {
		if name != "" && chain[0].VerifyHostname(strings.TrimSuffix(name, ".")) == nil {
			return nil
		}
	}
	return &VerifyError{Kind: FailureNameMismatch, Detail: "certificate does not name " + strings.Join(names, " or ")}
}

// IsVerifyError reports whether err carries a DANE verification failure and
// returns it.
func IsVerifyError(err error) (*VerifyError, bool) {
	var verifyErr *VerifyError
	ok := errors.As(err, &verifyErr)
	return verifyErr, ok
}
