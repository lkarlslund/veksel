package main

import (
	"testing"

	imapmigration "github.com/lkarlslund/veksel/pkg/migration/imap"
)

func TestIMAPMigrationAcceptsSyncWizardSecurityVocabulary(t *testing.T) {
	for input, want := range map[string]imapmigration.TLSMode{
		"implicit": imapmigration.TLSImplicit,
		"starttls": imapmigration.TLSStartTLS,
		"plain":    imapmigration.TLSNone,
		"tls":      imapmigration.TLSImplicit,
		"none":     imapmigration.TLSNone,
	} {
		if got, err := imapMigrationTLSMode(input); err != nil || got != want {
			t.Errorf("imapMigrationTLSMode(%q)=%q,%v want %q", input, got, err, want)
		}
	}
}
