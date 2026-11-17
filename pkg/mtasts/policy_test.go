package mtasts

import (
	"strings"
	"testing"
)

func TestParsePolicy(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    Policy
		wantErr bool
	}{
		{name: "enforce", body: "version: STSv1\r\nmode: enforce\r\nmx: mail.example.test\r\nmx: *.backup.example.test\r\nmax_age: 604800\r\n", want: Policy{Version: "STSv1", Mode: ModeEnforce, MX: []string{"mail.example.test", "*.backup.example.test"}, MaxAge: 604800}},
		{name: "none without mx", body: "version: STSv1\nmode: none\nmax_age: 0", want: Policy{Version: "STSv1", Mode: ModeNone, MaxAge: 0}},
		{name: "first duplicate wins", body: "version: STSv1\nversion: invalid\nmode: testing\nmode: enforce\nmx: MAIL.EXAMPLE.TEST\nmax_age: 60\nmax_age: 999", want: Policy{Version: "STSv1", Mode: ModeTesting, MX: []string{"mail.example.test"}, MaxAge: 60}},
		{name: "unknown extension", body: "version: STSv1\nmode: enforce\nmx: mail.example.test\nmax_age: 60\nfuture-field: valid UTF-8 ✓", want: Policy{Version: "STSv1", Mode: ModeEnforce, MX: []string{"mail.example.test"}, MaxAge: 60}},
		{name: "missing required", body: "version: STSv1\nmode: enforce\nmx: mail.example.test", wantErr: true},
		{name: "missing mx", body: "version: STSv1\nmode: testing\nmax_age: 60", wantErr: true},
		{name: "excessive age", body: "version: STSv1\nmode: none\nmax_age: 31557601", wantErr: true},
		{name: "unicode mx u-label", body: "version: STSv1\nmode: enforce\nmx: bücher.example\nmax_age: 60", wantErr: true},
		{name: "invalid wildcard", body: "version: STSv1\nmode: enforce\nmx: mail.*.example\nmax_age: 60", wantErr: true},
		{name: "bare carriage return", body: "version: STSv1\rmode: none\nmax_age: 0", wantErr: true},
		{name: "blank interior line", body: "version: STSv1\n\nmode: none\nmax_age: 0", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParsePolicy([]byte(test.body))
			if (err != nil) != test.wantErr {
				t.Fatalf("ParsePolicy() error = %v, wantErr %t", err, test.wantErr)
			}
			if !test.wantErr && (got.Version != test.want.Version || got.Mode != test.want.Mode || got.MaxAge != test.want.MaxAge || strings.Join(got.MX, ",") != strings.Join(test.want.MX, ",")) {
				t.Fatalf("ParsePolicy() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestParsePolicyBoundsBody(t *testing.T) {
	body := make([]byte, maxPolicyBytes+1)
	if _, err := ParsePolicy(body); err == nil {
		t.Fatal("oversized policy was accepted")
	}
	if _, err := ParsePolicy([]byte{0xff}); err == nil {
		t.Fatal("invalid UTF-8 policy was accepted")
	}
}

func TestPolicyID(t *testing.T) {
	tests := []struct {
		name      string
		records   []string
		wantID    string
		available bool
		wantErr   bool
	}{
		{name: "valid", records: []string{"v=STSv1; id=20260818; future=value;"}, wantID: "20260818", available: true},
		{name: "case insensitive", records: []string{"V=STSv1; ID=AbC123"}, wantID: "AbC123", available: true},
		{name: "unrelated ignored", records: []string{"google-site-verification=x"}},
		{name: "multiple usable", records: []string{"v=STSv1; id=a", "v=STSv1; id=b"}, wantErr: true},
		{name: "missing id", records: []string{"v=STSv1; future=value"}, wantErr: true},
		{name: "invalid id", records: []string{"v=STSv1; id=not_valid"}, wantErr: true},
		{name: "version must lead", records: []string{"id=x; v=STSv1;"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, available, err := PolicyID(test.records)
			if (err != nil) != test.wantErr || id != test.wantID || available != test.available {
				t.Fatalf("PolicyID() = %q, %t, %v", id, available, err)
			}
		})
	}
}

func TestPolicyMatchesMX(t *testing.T) {
	policy := Policy{MX: []string{"mail.example.test", "*.backup.example.test", "xn--bcher-kva.example"}}
	for _, test := range []struct {
		host string
		want bool
	}{
		{"mail.example.test", true},
		{"MAIL.EXAMPLE.TEST.", true},
		{"mx.backup.example.test", true},
		{"backup.example.test", false},
		{"a.b.backup.example.test", false},
		{"bücher.example", true},
		{"other.example.test", false},
	} {
		if got := policy.MatchesMX(test.host); got != test.want {
			t.Errorf("MatchesMX(%q) = %t, want %t", test.host, got, test.want)
		}
	}
}
