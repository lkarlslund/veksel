package model

import "testing"

func TestPersonalWebhookMatchesOnlyItsOwner(t *testing.T) {
	all := Webhook{OwnerID: "bob", Events: []string{"message.received"}}
	narrow := Webhook{OwnerID: "bob", Addresses: []string{"signup@example.test"}}
	for name, test := range map[string]struct {
		webhook Webhook
		scope   WebhookScope
		want    bool
	}{
		"own mail":           {all, WebhookScope{Account: "bob", Recipients: []string{"bob@example.test"}}, true},
		"another account":    {all, WebhookScope{Account: "alice", Recipients: []string{"bob@example.test"}}, false},
		"server-wide event":  {all, WebhookScope{}, false},
		"narrowed, matching": {narrow, WebhookScope{Account: "bob", Recipients: []string{"Signup@example.test"}}, true},
		"narrowed, other":    {narrow, WebhookScope{Account: "bob", Recipients: []string{"bob@example.test"}}, false},
		"alias, other owner": {narrow, WebhookScope{Account: "alice", Recipients: []string{"signup@example.test"}}, false},
	} {
		if got := test.webhook.Matches(test.scope); got != test.want {
			t.Errorf("%s: Matches = %v, want %v", name, got, test.want)
		}
	}
}
