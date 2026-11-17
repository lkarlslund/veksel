package dmarc

import "testing"

// FuzzDMARCRecord feeds DNS TXT answers into the DMARC record parser and
// report-address parser. An accepted record must carry valid policy values.
func FuzzDMARCRecord(f *testing.F) {
	for _, seed := range []string{
		"v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:dmarc@example.com,mailto:x@y.org!10m; ruf=mailto:f@example.com; adkim=s; aspf=r; fo=1",
		"v=DMARC1; p=none",
		"v=DMARC1;p=none;p=reject",
		"v=DMARC1; p=none; rua=\"mailto:a;b@example.com\"",
		"v=DMARC1; p=none; pct=101",
		"v=DMARC2; p=none",
		"p=none; v=DMARC1",
		"", ";;;", "=", "\"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_ = isDMARCRecord(input)
		record, err := parseDmarcRecord(input)
		if err == nil {
			valid := map[string]bool{"none": true, "quarantine": true, "reject": true}
			if record.Version != "DMARC1" || !valid[record.Policy] || !valid[record.SpPolicy] ||
				record.Pct < 0 || record.Pct > 100 || (record.Adkim != "r" && record.Adkim != "s") ||
				(record.Aspf != "r" && record.Aspf != "s") {
				t.Fatalf("accepted invalid record %+v from %q", record, input)
			}
			for _, uri := range append(record.RUA, record.RUF...) {
				_, _, _ = parseAggregateDestination(uri)
			}
		}
		_, _, _ = parseAggregateDestination(input)
		_ = organizationalDomain(input)
	})
}

// FuzzAggregateReport feeds received aggregate report XML into the parser.
func FuzzAggregateReport(f *testing.F) {
	for _, seed := range []string{
		`<?xml version="1.0"?><feedback><report_metadata><org_name>google.com</org_name><email>noreply@google.com</email><report_id>1</report_id><date_range><begin>1704067200</begin><end>1704153600</end></date_range></report_metadata><policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf><p>none</p></policy_published><record><row><source_ip>192.0.2.1</source_ip><count>2</count></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><dkim><domain>example.com</domain><result>pass</result></dkim><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record></feedback>`,
		`<feedback><report_metadata><date_range><begin>-1</begin><end>99999999999999999999</end></date_range></report_metadata></feedback>`,
		"", "<", "<feedback>",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if report, err := Parse([]byte(input)); err == nil {
			_ = report.Validate()
		}
	})
}
