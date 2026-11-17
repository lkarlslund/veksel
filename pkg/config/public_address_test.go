package config

import "testing"

func TestPatchSMTPPublicAddressValidates(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := service.Current().Config.SmtpPublicAddress; got != "" {
		t.Fatalf("default = %q", got)
	}
	for _, bad := range []string{"mail.example.com", "0.0.0.0", "127.0.0.1", "999.1.1.1"} {
		if _, err := service.Patch(service.Current().Revision, map[string]any{"smtp_public_address": bad}); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	updated, err := service.Patch(service.Current().Revision, map[string]any{"smtp_public_address": "203.0.113.9"})
	if err != nil || updated.Config.SmtpPublicAddress != "203.0.113.9" {
		t.Fatalf("patch: %v %q", err, updated.Config.SmtpPublicAddress)
	}
	if _, err := service.Patch(updated.Revision, map[string]any{"smtp_public_address": ""}); err != nil {
		t.Fatalf("clearing rejected: %v", err)
	}
}
