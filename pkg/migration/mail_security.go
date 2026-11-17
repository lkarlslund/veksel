package migration

import (
	"fmt"
	"strings"
)

type MailSecurityMode string

const (
	MailSecurityImplicit MailSecurityMode = "implicit"
	MailSecurityStartTLS MailSecurityMode = "starttls"
	MailSecurityPlain    MailSecurityMode = "plain"
)

// NormalizeMailSecurityMode keeps the REST/UI vocabulary stable while
// accepting profiles written with the older IMAP-client spellings.
func NormalizeMailSecurityMode(value string) (MailSecurityMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "implicit", "tls":
		return MailSecurityImplicit, nil
	case "starttls", "stls":
		return MailSecurityStartTLS, nil
	case "plain", "none":
		return MailSecurityPlain, nil
	default:
		return "", fmt.Errorf("unsupported mail connection security %q", value)
	}
}
