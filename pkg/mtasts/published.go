package mtasts

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// PublishedOff disables the policy this server publishes for its domains.
const PublishedOff = "off"

// ValidPublishedMode reports whether mode is a published-policy mode: off,
// or an RFC 8461 policy mode.
func ValidPublishedMode(mode string) bool {
	switch mode {
	case PublishedOff, ModeNone, ModeTesting, ModeEnforce:
		return true
	}
	return false
}

// PublishedPolicy returns the RFC 8461 section 3.2 policy a hosted domain
// publishes at https://mta-sts.<domain>/.well-known/mta-sts.txt, naming the
// MX hosts senders must reach over validated TLS, and the id its
// _mta-sts.<domain> TXT record carries. The id follows the policy text, so a
// changed policy gets a new id. Testing policies are cached for a day and
// enforced ones for two weeks.
func PublishedPolicy(mode string, mx []string) (text, id string) {
	maxAge := 86400
	if mode == ModeEnforce {
		maxAge = 1209600
	}
	var policy strings.Builder
	policy.WriteString("version: STSv1\r\nmode: " + mode + "\r\n")
	if mode != ModeNone {
		for _, host := range mx {
			if host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), "."); host != "" {
				policy.WriteString("mx: " + host + "\r\n")
			}
		}
	}
	policy.WriteString("max_age: " + strconv.Itoa(maxAge) + "\r\n")
	sum := sha256.Sum256([]byte(policy.String()))
	return policy.String(), hex.EncodeToString(sum[:])[:20]
}

// PublishedRecord is the _mta-sts TXT record value for a policy id.
func PublishedRecord(id string) string { return "v=STSv1; id=" + id }
