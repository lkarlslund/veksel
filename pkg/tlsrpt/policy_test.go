package tlsrpt

import "testing"

func TestParseReportingPolicy(t *testing.T) {
	tests := []struct {
		name      string
		records   []string
		available bool
		wantURIs  int
		wantErr   bool
	}{
		{name: "mailto", records: []string{"v=TLSRPTv1; rua=mailto:reports@example.test"}, available: true, wantURIs: 1},
		{name: "https and whitespace", records: []string{"v=TLSRPTv1; rua=https://reports.example.test/v1 , mailto:reports@example.test; future=value"}, available: true, wantURIs: 2},
		{name: "unrelated record ignored", records: []string{"google-site-verification=x"}},
		{name: "version must lead", records: []string{"rua=mailto:r@example.test; v=TLSRPTv1"}},
		{name: "multiple usable", records: []string{"v=TLSRPTv1; rua=mailto:a@example.test", "v=TLSRPTv1; rua=mailto:b@example.test"}, wantErr: true},
		{name: "missing rua", records: []string{"v=TLSRPTv1; future=value"}, wantErr: true},
		{name: "unsupported scheme", records: []string{"v=TLSRPTv1; rua=http://reports.example.test"}, wantErr: true},
		{name: "mailto headers rejected", records: []string{"v=TLSRPTv1; rua=mailto:r@example.test?subject=unsafe"}, wantErr: true},
		{name: "https credentials rejected", records: []string{"v=TLSRPTv1; rua=https://user:pass@reports.example.test"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, available, err := ParseReportingPolicy("example.test", test.records)
			if (err != nil) != test.wantErr || available != test.available || len(policy.URIs) != test.wantURIs {
				t.Fatalf("ParseReportingPolicy() = %#v, %t, %v", policy, available, err)
			}
		})
	}
}
