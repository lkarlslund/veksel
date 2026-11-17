package jmap

import (
	"testing"

	"github.com/lkarlslund/veksel/pkg/service"
)

// TestEmailDestroyUnderLegalHoldPreservesMessage proves Email/set destroy
// reaches the FolderSpace hold check and that the client's change feed sees
// only a destroy.
func TestEmailDestroyUnderLegalHoldPreservesMessage(t *testing.T) {
	f := newFixture(t)
	compliance, err := service.NewCompliance(t.Context(), f.ts)
	if err != nil {
		t.Fatal(err)
	}
	service.ConfigureLegalHolds(f.space, compliance)
	access := accountAccess("alice", "alice")
	inbox, err := f.space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	created, err := f.space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: held\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	state, err := f.handler.journalState(t.Context(), access, service.ChangeObjectItem)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compliance.PlaceHold(t.Context(), service.LegalHold{Scope: service.HoldScopeAccount, Target: "alice", Reason: "case"}); err != nil {
		t.Fatal(err)
	}
	body := `{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"alice","destroy":["` + created.ID + `"]},"d"],["Email/changes",{"accountId":"alice","sinceState":"` + state + `"},"c"]]}`
	response := decodeResponse(t, f.request(t, "POST", "/jmap/api", body, "alice", "password"))
	calls := response["methodResponses"].([]any)
	set := calls[0].([]any)[1].(map[string]any)
	if destroyed, _ := set["destroyed"].([]any); len(destroyed) != 1 || destroyed[0] != created.ID {
		t.Fatalf("Email/set = %#v", calls[0])
	}
	changes := calls[1].([]any)[1].(map[string]any)
	if destroyed, _ := changes["destroyed"].([]any); len(destroyed) != 1 || len(changes["created"].([]any)) != 0 {
		t.Fatalf("Email/changes = %#v", calls[1])
	}
	if _, err := f.space.GetItem(t.Context(), access, created.ID); err == nil {
		t.Fatal("client still reads the destroyed message")
	}
	if preserved, err := f.space.GetItem(t.Context(), service.ComplianceAccess("alice"), created.ID); err != nil || preserved.HeldDeletedAt.IsZero() {
		t.Fatalf("compliance read = %+v err=%v", preserved, err)
	}
}
