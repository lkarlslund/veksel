package dmarc

import (
	"testing"
)

const sampleReport = `<?xml version="1.0" encoding="UTF-8"?>
<report version="1.0" xmlns="http://schema.dmarc.org/2008">
 <org_name>Example ISP</org_name>
 <report_id>1234567890</report_id>
 <report_metadata>
   <org_name>Example ISP</org_name>
   <email>dmarc@example-isp.com</email>
   <extra_contact_info>https://example-isp.com/dmarc</extra_contact_info>
   <date_range>
     <begin>1704067200</begin>
     <end>1704153600</end>
   </date_range>
 </report_metadata>
 <policy_published>
   <domain>example.com</domain>
   <adkim>s</adkim>
   <aspf>r</aspf>
   <p>reject</p>
   <sp>quarantine</sp>
   <pct>100</pct>
 </policy_published>
 <record>
   <row>
     <source_ip>192.0.2.1</source_ip>
     <count>10</count>
     <spf_pass>10</spf_pass>
     <dkim_pass>10</dkim_pass>
     <dmarc_pass>10</dmarc_pass>
   </row>
   <identifiers>
     <header_from>example.com</header_from>
     <envelope_from>example.com</envelope_from>
   </identifiers>
   <auth_results>
     <spf domain="example.com" result="pass"/>
     <dkim domain="example.com" result="pass"/>
   </auth_results>
 </record>
 <record>
   <row>
     <source_ip>198.51.100.5</source_ip>
     <count>5</count>
     <spf_pass>0</spf_pass>
     <dkim_pass>0</dkim_pass>
     <dmarc_pass>0</dmarc_pass>
   </row>
   <identifiers>
     <header_from>example.com</header_from>
     <envelope_from>evil.com</envelope_from>
   </identifiers>
   <auth_results>
     <spf domain="example.com" result="fail"/>
     <dkim domain="example.com" result="fail"/>
   </auth_results>
 </record>
</report>`

func TestParse(t *testing.T) {
	report, err := Parse([]byte(sampleReport))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if report.OrgName != "Example ISP" {
		t.Errorf("OrgName = %q, want %q", report.OrgName, "Example ISP")
	}

	if report.ReportID != "1234567890" {
		t.Errorf("ReportID = %q, want %q", report.ReportID, "1234567890")
	}

	if report.Email != "dmarc@example-isp.com" {
		t.Errorf("Email = %q, want %q", report.Email, "dmarc@example-isp.com")
	}

	if report.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", report.Domain, "example.com")
	}

	if report.Policy != "reject" {
		t.Errorf("Policy = %q, want %q", report.Policy, "reject")
	}

	if len(report.Records) != 2 {
		t.Fatalf("Records length = %d, want 2", len(report.Records))
	}

	// Check first record (passing)
	rec0 := report.Records[0]
	if rec0.SourceIP != "192.0.2.1" {
		t.Errorf("Records[0].SourceIP = %q, want %q", rec0.SourceIP, "192.0.2.1")
	}
	if rec0.RecordCount != 10 {
		t.Errorf("Records[0].RecordCount = %d, want 10", rec0.RecordCount)
	}
	if rec0.SpfResult != "pass" {
		t.Errorf("Records[0].SpfResult = %q, want %q", rec0.SpfResult, "pass")
	}
	if len(rec0.DkimResults) != 1 || rec0.DkimResults[0].Result != "pass" {
		t.Errorf("Records[0].DkimResults = %+v, want pass", rec0.DkimResults)
	}

	// Check second record (failing)
	rec1 := report.Records[1]
	if rec1.SourceIP != "198.51.100.5" {
		t.Errorf("Records[1].SourceIP = %q, want %q", rec1.SourceIP, "198.51.100.5")
	}
	if rec1.SpfResult != "fail" {
		t.Errorf("Records[1].SpfResult = %q, want %q", rec1.SpfResult, "fail")
	}
}

func TestParseInvalidXML(t *testing.T) {
	_, err := Parse([]byte("not xml"))
	if err == nil {
		t.Error("expected error for invalid XML, got nil")
	}
}

func TestValidate(t *testing.T) {
	report, err := Parse([]byte(sampleReport))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if err := report.Validate(); err != nil {
		t.Errorf("Validate() error: %v", err)
	}

	// Test with missing org_name
	report.OrgName = ""
	if err := report.Validate(); err == nil {
		t.Error("expected validation error for missing org_name, got nil")
	}

	// Test with missing domain
	report.OrgName = "Test"
	report.Domain = ""
	if err := report.Validate(); err == nil {
		t.Error("expected validation error for missing domain, got nil")
	}
}

func TestDateRange(t *testing.T) {
	report, err := Parse([]byte(sampleReport))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if report.BeginTime.IsZero() {
		t.Error("BeginTime is zero")
	}
	if report.EndTime.IsZero() {
		t.Error("EndTime is zero")
	}
	if !report.EndTime.After(report.BeginTime) {
		t.Error("EndTime should be after BeginTime")
	}
}

func TestEmptyReport(t *testing.T) {
	emptyReport := `<?xml version="1.0" encoding="UTF-8"?>
<report version="1.0" xmlns="http://schema.dmarc.org/2008">
 <org_name>Test Org</org_name>
 <report_id>test-1</report_id>
 <report_metadata>
   <org_name>Test Org</org_name>
   <email>test@test.com</email>
   <date_range>
     <begin>1704067200</begin>
     <end>1704153600</end>
   </date_range>
 </report_metadata>
 <policy_published>
   <domain>test.com</domain>
   <adkim>r</adkim>
   <aspf>r</aspf>
   <p>none</p>
   <sp>none</sp>
   <pct>100</pct>
 </policy_published>
</report>`

	report, err := Parse([]byte(emptyReport))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(report.Records) != 0 {
		t.Errorf("Records length = %d, want 0", len(report.Records))
	}
}

func TestReportWithMultipleDKIM(t *testing.T) {
	multiDkim := `<?xml version="1.0" encoding="UTF-8"?>
<report version="1.0" xmlns="http://schema.dmarc.org/2008">
 <org_name>Test Org</org_name>
 <report_id>multi-dkim</report_id>
 <report_metadata>
   <org_name>Test Org</org_name>
   <email>test@test.com</email>
   <date_range>
     <begin>1704067200</begin>
     <end>1704153600</end>
   </date_range>
 </report_metadata>
 <policy_published>
   <domain>test.com</domain>
   <adkim>r</adkim>
   <aspf>r</aspf>
   <p>none</p>
   <sp>none</sp>
   <pct>100</pct>
 </policy_published>
 <record>
   <row>
     <source_ip>10.0.0.1</source_ip>
     <count>1</count>
     <spf_pass>1</spf_pass>
     <dkim_pass>1</dkim_pass>
     <dmarc_pass>1</dmarc_pass>
   </row>
   <identifiers>
     <header_from>test.com</header_from>
     <envelope_from>test.com</envelope_from>
   </identifiers>
   <auth_results>
     <spf domain="test.com" result="pass"/>
     <dkim domain="test.com" result="pass"/>
     <dkim domain="mail.test.com" result="pass"/>
   </auth_results>
 </record>
</report>`

	report, err := Parse([]byte(multiDkim))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(report.Records) != 1 {
		t.Fatalf("Records length = %d, want 1", len(report.Records))
	}

	dkimResults := report.Records[0].DkimResults
	if len(dkimResults) != 2 {
		t.Fatalf("DkimResults length = %d, want 2", len(dkimResults))
	}

	if dkimResults[0].Domain != "test.com" || dkimResults[0].Result != "pass" {
		t.Errorf("DkimResults[0] = %+v, want domain=test.com result=pass", dkimResults[0])
	}
	if dkimResults[1].Domain != "mail.test.com" || dkimResults[1].Result != "pass" {
		t.Errorf("DkimResults[1] = %+v, want domain=mail.test.com result=pass", dkimResults[1])
	}
}
