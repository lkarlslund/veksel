package dmarc

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
)

func TestGenerateAggregateReportIsDeterministicAndStructurallyValid(t *testing.T) {
	recorder, closeRecorder := newTestAggregateRecorder(t, AggregateRecorderOptions{})
	defer closeRecorder()
	if err := recorder.Record(t.Context(), aggregateObservation("one")); err != nil {
		t.Fatal(err)
	}
	aggregates, err := recorder.Aggregates(t.Context(), "2026-08-27", "")
	if err != nil || len(aggregates) != 1 {
		t.Fatalf("Aggregates() = %#v, %v", aggregates, err)
	}
	identity := AggregateReportIdentity{Organization: "Veksel Test", Email: "dmarc@receiver.example"}
	first, err := GenerateAggregateReport(aggregates[0], identity)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateAggregateReport(aggregates[0], identity)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.Filename != second.Filename || !bytes.Equal(first.GZIP, second.GZIP) {
		t.Fatal("report output is not deterministic")
	}
	if !strings.Contains(string(first.XML), `xmlns="urn:ietf:params:xml:ns:dmarc-2.0"`) || !strings.Contains(string(first.XML), "<selector>mail</selector>") {
		t.Fatalf("XML = %s", first.XML)
	}
	reader, err := gzip.NewReader(bytes.NewReader(first.GZIP))
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decompressed, first.XML) {
		t.Fatal("gzip payload differs from XML")
	}
}

func TestGenerateAggregateReportRefusesIncompleteAggregate(t *testing.T) {
	_, err := GenerateAggregateReport(RecordedAggregate{Day: "2026-08-27", OverflowCount: 1}, AggregateReportIdentity{Organization: "Veksel", Email: "dmarc@example.test"})
	if err == nil {
		t.Fatal("incomplete aggregate was rendered as complete")
	}
}

// TestGenerateAggregateReportAlwaysCarriesSPF: the schema requires one spf
// element per record and fixed result vocabularies, so a row recorded with
// SPF disabled ("skip", no domain) or an internal DKIM value must still
// render valid XML.
func TestGenerateAggregateReportAlwaysCarriesSPF(t *testing.T) {
	aggregate := RecordedAggregate{ID: "a", Day: "2026-08-27", Policy: ReportingPolicy{Domain: "sender.example", Policy: "reject", SubdomainPolicy: "reject", ADKIM: "r", ASPF: "r"},
		Rows: []AggregateRow{{SourceIP: "192.0.2.1", Count: 1, Disposition: "reject", HeaderFrom: "sender.example",
			DKIM: []AggregateAuthResult{{Domain: "sender.example", Selector: "s1", Result: "skip"}, {Domain: "list.example", Selector: "l", Result: "policy"}},
			SPF:  AggregateAuthResult{Result: "skip"}}}}
	report, err := GenerateAggregateReport(aggregate, AggregateReportIdentity{Organization: "Veksel", Email: "dmarc@receiver.example"})
	if err != nil {
		t.Fatal(err)
	}
	xml := strings.Join(strings.Fields(string(report.XML)), "")
	for _, want := range []string{"<spf><domain>sender.example</domain><result>none</result></spf>", "<domain>list.example</domain>", "<result>policy</result>"} {
		if !strings.Contains(xml, want) {
			t.Errorf("XML lacks %q:\n%s", want, xml)
		}
	}
	if strings.Contains(xml, "skip") {
		t.Errorf("XML carries an internal result:\n%s", xml)
	}
}
