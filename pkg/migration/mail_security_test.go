package migration

import "testing"

func TestNormalizeMailSecurityMode(t *testing.T) {
	for input, want := range map[string]MailSecurityMode{
		"": MailSecurityImplicit, "implicit": MailSecurityImplicit, "tls": MailSecurityImplicit,
		"starttls": MailSecurityStartTLS, "STLS": MailSecurityStartTLS,
		"plain": MailSecurityPlain, "none": MailSecurityPlain,
	} {
		if got, err := NormalizeMailSecurityMode(input); err != nil || got != want {
			t.Errorf("NormalizeMailSecurityMode(%q)=%q,%v want %q", input, got, err, want)
		}
	}
	if _, err := NormalizeMailSecurityMode("opportunistic"); err == nil {
		t.Fatal("unsupported security mode was accepted")
	}
}
