// Package dmarc parses DMARC aggregate reports (RFC 7489).
//
// DMARC aggregate reports are XML documents sent by receiving mail
// systems to domain owners, summarizing email sending activity.
package dmarc

import (
	"encoding/xml"
	"fmt"
	"time"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
)

var log = logpkg.For(logpkg.ModuleDMARC)

// AggregateReport is the top-level XML element of a DMARC aggregate report.
type AggregateReport struct {
	XMLName    xml.Name        `xml:"http://schema.dmarc.org/2008 report"`
	Version    string          `xml:"version,attr"`
	OrgName    string          `xml:"org_name"`
	ReportID   string          `xml:"report_id"`
	ReportMeta ReportMeta      `xml:"report_metadata"`
	PolicyPub  PolicyPublished `xml:"policy_published"`
	Records    []Record        `xml:"record"`
	Additional AdditionalInfo  `xml:"additional_info,omitempty"`
}

// ReportMeta contains metadata about the report.
type ReportMeta struct {
	OrgName          string    `xml:"org_name"`
	Email            string    `xml:"email"`
	ExtraContactInfo string    `xml:"extra_contact_info,omitempty"`
	DateRange        DateRange `xml:"date_range"`
	Error            []string  `xml:"error,omitempty"`
}

// DateRange specifies the begin and end of the report period.
type DateRange struct {
	Begin int `xml:"begin"`
	End   int `xml:"end"`
}

// BeginTime returns the begin time as time.Time.
func (d DateRange) BeginTime() time.Time {
	return time.Unix(int64(d.Begin), 0).UTC()
}

// EndTime returns the end time as time.Time.
func (d DateRange) EndTime() time.Time {
	return time.Unix(int64(d.End), 0).UTC()
}

// PolicyPublished contains the DMARC policy published by the domain.
type PolicyPublished struct {
	Domain   string `xml:"domain"`
	Adkim    string `xml:"adkim"`
	Aspf     string `xml:"aspf"`
	Policy   string `xml:"p"`
	SpPolicy string `xml:"sp"`
	Pct      int    `xml:"pct"`
}

// Record represents one row in the DMARC report.
type Record struct {
	Row         Row         `xml:"row"`
	Ident       Identifiers `xml:"identifiers"`
	AuthResults AuthResults `xml:"auth_results"`
}

// Row contains summary data for a source IP.
type Row struct {
	SourceIP    string `xml:"source_ip"`
	RecordCount int    `xml:"count"`
	SpfPass     int    `xml:"spf_pass"`
	DkimPass    int    `xml:"dkim_pass"`
	DmarcPass   int    `xml:"dmarc_pass"`
}

// Identifiers contains the header and envelope from domains.
type Identifiers struct {
	HeaderFrom   string `xml:"header_from"`
	EnvelopeFrom string `xml:"envelope_from"`
}

// AuthResults contains SPF and DKIM authentication results.
type AuthResults struct {
	Spf  AuthResult   `xml:"spf,omitempty"`
	Dkim []AuthResult `xml:"dkim,omitempty"`
}

// AuthResult represents a single authentication mechanism result.
type AuthResult struct {
	Domain string `xml:"domain,attr"`
	Result string `xml:"result,attr"`
}

// AdditionalInfo contains optional extra information.
type AdditionalInfo struct {
}

// ParsedReport is a simplified, user-friendly representation of a DMARC report.
type ParsedReport struct {
	OrgName    string
	ReportID   string
	Email      string
	BeginTime  time.Time
	EndTime    time.Time
	Domain     string
	SpfPolicy  string
	DkimPolicy string
	Policy     string
	Records    []ParsedRecord
}

// ParsedRecord is a simplified representation of a report record.
type ParsedRecord struct {
	SourceIP     string
	RecordCount  int
	HeaderFrom   string
	EnvelopeFrom string
	SpfResult    string
	SpfDomain    string
	DkimResults  []DkimResult
}

// DkimResult represents a single DKIM authentication result.
type DkimResult struct {
	Domain string
	Result string
}

// Parse parses a DMARC aggregate report from XML bytes.
func Parse(data []byte) (*ParsedReport, error) {
	log.Debug("dmarc: parsing report")
	var report AggregateReport
	if err := xml.Unmarshal(data, &report); err != nil {
		log.Error("dmarc: failed to parse report", "error", err)
		return nil, fmt.Errorf("unmarshal DMARC report: %w", err)
	}

	parsed := &ParsedReport{
		OrgName:    report.OrgName,
		ReportID:   report.ReportID,
		Email:      report.ReportMeta.Email,
		BeginTime:  report.ReportMeta.DateRange.BeginTime(),
		EndTime:    report.ReportMeta.DateRange.EndTime(),
		Domain:     report.PolicyPub.Domain,
		SpfPolicy:  report.PolicyPub.Aspf,
		DkimPolicy: report.PolicyPub.Adkim,
		Policy:     report.PolicyPub.Policy,
	}

	for _, rec := range report.Records {
		pr := ParsedRecord{
			SourceIP:     rec.Row.SourceIP,
			RecordCount:  rec.Row.RecordCount,
			HeaderFrom:   rec.Ident.HeaderFrom,
			EnvelopeFrom: rec.Ident.EnvelopeFrom,
			SpfResult:    rec.AuthResults.Spf.Result,
			SpfDomain:    rec.AuthResults.Spf.Domain,
		}
		for _, dkim := range rec.AuthResults.Dkim {
			pr.DkimResults = append(pr.DkimResults, DkimResult{
				Domain: dkim.Domain,
				Result: dkim.Result,
			})
		}
		parsed.Records = append(parsed.Records, pr)
	}

	return parsed, nil
}

// Validate checks if the parsed report has valid data.
func (p *ParsedReport) Validate() error {
	if p.OrgName == "" {
		return fmt.Errorf("missing org_name")
	}
	if p.Domain == "" {
		return fmt.Errorf("missing domain")
	}
	if p.BeginTime.IsZero() || p.EndTime.IsZero() {
		return fmt.Errorf("missing or invalid date range")
	}
	return nil
}
