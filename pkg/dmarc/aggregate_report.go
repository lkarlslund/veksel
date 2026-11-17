package dmarc

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"time"
)

const aggregateReportNamespace = "urn:ietf:params:xml:ns:dmarc-2.0"

type AggregateReportIdentity struct {
	Organization string
	Email        string
	ExtraContact string
}

type GeneratedAggregateReport struct {
	ID       string
	Filename string
	XML      []byte
	GZIP     []byte
}

type reportXML struct {
	XMLName  xml.Name          `xml:"urn:ietf:params:xml:ns:dmarc-2.0 feedback"`
	Version  string            `xml:"version,omitempty"`
	Metadata reportMetadataXML `xml:"report_metadata"`
	Policy   reportPolicyXML   `xml:"policy_published"`
	Records  []reportRecordXML `xml:"record"`
}

type reportMetadataXML struct {
	Organization string       `xml:"org_name"`
	Email        string       `xml:"email"`
	ExtraContact string       `xml:"extra_contact_info,omitempty"`
	ReportID     string       `xml:"report_id"`
	DateRange    dateRangeXML `xml:"date_range"`
}
type dateRangeXML struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}
type reportPolicyXML struct {
	Domain    string `xml:"domain"`
	Discovery string `xml:"discovery_method"`
	ADKIM     string `xml:"adkim"`
	ASPF      string `xml:"aspf"`
	Policy    string `xml:"p"`
	Subdomain string `xml:"sp"`
}
type reportRecordXML struct {
	Row            reportRowXML         `xml:"row"`
	Identifiers    reportIdentifiersXML `xml:"identifiers"`
	Authentication reportAuthResultsXML `xml:"auth_results"`
}
type reportRowXML struct {
	SourceIP  string                   `xml:"source_ip"`
	Count     int64                    `xml:"count"`
	Evaluated reportPolicyEvaluatedXML `xml:"policy_evaluated"`
}
type reportPolicyEvaluatedXML struct {
	Disposition string `xml:"disposition"`
	DKIM        string `xml:"dkim"`
	SPF         string `xml:"spf"`
}
type reportIdentifiersXML struct {
	EnvelopeFrom string `xml:"envelope_from,omitempty"`
	HeaderFrom   string `xml:"header_from"`
}
type reportAuthResultsXML struct {
	DKIM []reportDKIMXML `xml:"dkim,omitempty"`
	SPF  *reportSPFXML   `xml:"spf,omitempty"`
}
type reportDKIMXML struct {
	Domain   string `xml:"domain"`
	Selector string `xml:"selector"`
	Result   string `xml:"result"`
}
type reportSPFXML struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

// GenerateAggregateReport renders deterministic RFC 9990 XML and gzip bytes.
// A bounded-overflow aggregate is refused rather than silently represented as
// complete.
func GenerateAggregateReport(aggregate RecordedAggregate, identity AggregateReportIdentity) (GeneratedAggregateReport, error) {
	if aggregate.OverflowCount != 0 {
		return GeneratedAggregateReport{}, errors.New("DMARC aggregate is incomplete because its row limit was reached")
	}
	day, err := time.Parse(time.DateOnly, aggregate.Day)
	if err != nil {
		return GeneratedAggregateReport{}, errors.New("DMARC aggregate day is invalid")
	}
	if strings.TrimSpace(identity.Organization) == "" {
		return GeneratedAggregateReport{}, errors.New("DMARC report organization is required")
	}
	address, err := mail.ParseAddress(identity.Email)
	if err != nil || address.Address != identity.Email {
		return GeneratedAggregateReport{}, errors.New("DMARC report email is invalid")
	}
	if len(aggregate.Rows) == 0 {
		return GeneratedAggregateReport{}, errors.New("DMARC aggregate has no rows")
	}
	begin, end := day.UTC().Unix(), day.Add(24*time.Hour).UTC().Unix()-1
	reportID := digestStrings(identity.Organization, aggregate.Policy.Domain, aggregate.Day, aggregate.ID)
	document := reportXML{Version: "1.0", Metadata: reportMetadataXML{Organization: identity.Organization,
		Email: identity.Email, ExtraContact: identity.ExtraContact, ReportID: reportID, DateRange: dateRangeXML{Begin: begin, End: end}},
		Policy: reportPolicyXML{Domain: aggregate.Policy.Domain, Discovery: aggregate.Policy.DiscoveryMethod,
			ADKIM: aggregate.Policy.ADKIM, ASPF: aggregate.Policy.ASPF, Policy: aggregate.Policy.Policy, Subdomain: aggregate.Policy.SubdomainPolicy}}
	for _, row := range aggregate.Rows {
		if row.Count <= 0 {
			return GeneratedAggregateReport{}, errors.New("DMARC report row count must be positive")
		}
		record := reportRecordXML{Row: reportRowXML{SourceIP: row.SourceIP, Count: row.Count,
			Evaluated: reportPolicyEvaluatedXML{Disposition: row.Disposition, DKIM: passFail(row.DKIMAligned), SPF: passFail(row.SPFAligned)}},
			Identifiers: reportIdentifiersXML{EnvelopeFrom: row.EnvelopeFrom, HeaderFrom: row.HeaderFrom}}
		for _, result := range row.DKIM {
			if outcome, ok := reportResult(result.Result, dkimReportResults); ok && result.Domain != "" && result.Selector != "" {
				record.Authentication.DKIM = append(record.Authentication.DKIM, reportDKIMXML{Domain: result.Domain, Selector: result.Selector, Result: outcome})
			}
		}
		// The schema requires exactly one spf element. A row without an SPF
		// check (SPF disabled or skipped) reports none for the envelope
		// domain, falling back to the header domain for a null sender.
		spf := reportSPFXML{Domain: cmp.Or(row.SPF.Domain, row.EnvelopeFrom, row.HeaderFrom), Result: "none"}
		if outcome, ok := reportResult(row.SPF.Result, spfReportResults); ok {
			spf.Result = outcome
		}
		record.Authentication.SPF = &spf
		document.Records = append(document.Records, record)
	}
	data, err := xml.MarshalIndent(document, "", "  ")
	if err != nil {
		return GeneratedAggregateReport{}, err
	}
	data = append([]byte(xml.Header), data...)
	if err := validateGeneratedAggregateXML(data, len(document.Records)); err != nil {
		return GeneratedAggregateReport{}, err
	}
	var compressed bytes.Buffer
	writer, _ := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	writer.Header.ModTime = time.Unix(0, 0).UTC()
	writer.Header.OS = 255
	if _, err := writer.Write(data); err != nil {
		return GeneratedAggregateReport{}, err
	}
	if err := writer.Close(); err != nil {
		return GeneratedAggregateReport{}, err
	}
	filename := "veksel!" + aggregate.Policy.Domain + "!" + strconv.FormatInt(begin, 10) + "!" + strconv.FormatInt(end, 10) + "!" + reportID[:16] + ".xml.gz"
	return GeneratedAggregateReport{ID: reportID, Filename: filename, XML: data, GZIP: compressed.Bytes()}, nil
}

func validateGeneratedAggregateXML(data []byte, expectedRecords int) error {
	var decoded reportXML
	if err := xml.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("validate generated DMARC XML: %w", err)
	}
	if decoded.XMLName.Space != aggregateReportNamespace || decoded.Version != "1.0" || decoded.Metadata.ReportID == "" ||
		decoded.Metadata.Organization == "" || decoded.Metadata.Email == "" || decoded.Policy.Domain == "" || len(decoded.Records) != expectedRecords {
		return errors.New("generated DMARC XML failed structural validation")
	}
	return nil
}

// The result vocabularies of the aggregate report schema's DKIMResultType
// and SPFResultType.
var (
	dkimReportResults = []string{"none", "pass", "fail", "policy", "neutral", "temperror", "permerror"}
	spfReportResults  = []string{"none", "neutral", "pass", "fail", "softfail", "temperror", "permerror"}
)

// reportResult returns result when the schema vocabulary allows it. An
// internal value such as "skip" (no check ran) is not reportable.
func reportResult(result string, allowed []string) (string, bool) {
	result = strings.ToLower(strings.TrimSpace(result))
	return result, slices.Contains(allowed, result)
}

func passFail(value bool) string {
	if value {
		return "pass"
	}
	return "fail"
}
