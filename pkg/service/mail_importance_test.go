package service

import "testing"

func TestNormalizeMailImportance(t *testing.T) {
	for _, test := range []struct {
		input MailImportance
		want  MailImportance
		valid bool
	}{
		{"", MailImportanceNormal, true},
		{" NORMAL ", MailImportanceNormal, true},
		{"high", MailImportanceHigh, true},
		{"LOW", MailImportanceLow, true},
		{"urgent", "", false},
	} {
		got, err := NormalizeMailImportance(test.input)
		if (err == nil) != test.valid || got != test.want {
			t.Errorf("NormalizeMailImportance(%q) = %q, %v; want %q, valid=%v", test.input, got, err, test.want, test.valid)
		}
	}
}

func TestMessageImportanceHeaderPrecedence(t *testing.T) {
	for _, test := range []struct {
		name    string
		headers map[string]string
		want    MailImportance
	}{
		{name: "default", headers: nil, want: MailImportanceNormal},
		{name: "importance high", headers: map[string]string{"importance": "High"}, want: MailImportanceHigh},
		{name: "x priority high", headers: map[string]string{"X-Priority": "2 (High)"}, want: MailImportanceHigh},
		{name: "x priority normal", headers: map[string]string{"X-Priority": "3"}, want: MailImportanceNormal},
		{name: "x priority low", headers: map[string]string{"x-priority": "5 (Lowest)"}, want: MailImportanceLow},
		{name: "priority urgent", headers: map[string]string{"Priority": "urgent"}, want: MailImportanceHigh},
		{name: "priority non urgent", headers: map[string]string{"Priority": "non-urgent"}, want: MailImportanceLow},
		{name: "explicit wins", headers: map[string]string{"Importance": "low", "X-Priority": "1", "Priority": "urgent"}, want: MailImportanceLow},
		{name: "malformed falls through", headers: map[string]string{"Importance": "maybe", "X-Priority": "no", "Priority": "urgent"}, want: MailImportanceHigh},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := MessageImportance(test.headers); got != test.want {
				t.Fatalf("MessageImportance(%v) = %q, want %q", test.headers, got, test.want)
			}
		})
	}
}

func TestSetMailImportanceHeadersReplacesConventionalHeaders(t *testing.T) {
	headers := map[string]string{"Subject": "Hello", "importance": "low", "X-Priority": "5", "Priority": "non-urgent"}
	SetMailImportanceHeaders(headers, MailImportanceHigh)
	if MessageImportance(headers) != MailImportanceHigh || headers["Importance"] != "high" || headers["X-Priority"] != "1" || headers["Priority"] != "urgent" {
		t.Fatalf("high headers = %#v", headers)
	}
	SetMailImportanceHeaders(headers, MailImportanceNormal)
	if len(headers) != 1 || headers["Subject"] != "Hello" || MessageImportance(headers) != MailImportanceNormal {
		t.Fatalf("normal headers = %#v", headers)
	}
}
