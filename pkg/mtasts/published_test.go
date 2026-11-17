package mtasts

import (
	"strings"
	"testing"
)

// The published policy parses as a valid policy, and its id changes with it.
func TestPublishedPolicyParsesAndVersions(t *testing.T) {
	text, id := PublishedPolicy(ModeTesting, []string{"Mail.Example.Test."})
	policy, err := ParsePolicy([]byte(text))
	if err != nil {
		t.Fatalf("published policy does not parse: %v\n%s", err, text)
	}
	if policy.Mode != ModeTesting || !policy.MatchesMX("mail.example.test") || policy.MaxAge != 86400 {
		t.Fatalf("policy = %+v", policy)
	}
	if got, ok, err := PolicyID([]string{PublishedRecord(id)}); err != nil || !ok || got != id {
		t.Fatalf("TXT record %q: id=%q ok=%v err=%v", PublishedRecord(id), got, ok, err)
	}
	enforced, enforcedID := PublishedPolicy(ModeEnforce, []string{"mail.example.test"})
	if enforcedID == id || !strings.Contains(enforced, "max_age: 1209600") {
		t.Fatalf("enforce policy %q id %q", enforced, enforcedID)
	}
	if !ValidPublishedMode("off") || ValidPublishedMode("strict") {
		t.Fatal("published mode validation")
	}
}
