package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/imip"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestMailInvitationCardAndAcceptSendsReply(t *testing.T) {
	handler, ts := testHandler(t)
	for _, namespace := range []string{model.NSIMIPState} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	var sent []imip.Outgoing
	scheduling, err := imip.New(t.Context(), imip.Config{
		Space: handler.folderSpace, Store: ts.Store(), Identity: ts.UserStore().GetEmailAddress,
		Resolve: func(ctx context.Context, address string) (model.RecipientRoute, error) {
			return ts.ResolveRecipient(ctx, address, "+")
		},
		Send: func(_ context.Context, message imip.Outgoing) error { sent = append(sent, message); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureCalendarScheduling(scheduling)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	if err := ts.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().AddEmailAddress(t.Context(), "alice@example.test", "alice", "example.test", true); err != nil {
		t.Fatal(err)
	}
	ics := strings.Join([]string{"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Remote//EN", "METHOD:REQUEST", "BEGIN:VEVENT",
		"UID:quarterly-1", "DTSTAMP:20261005T080000Z", "DTSTART:20261110T130000Z", "DTEND:20261110T140000Z",
		"SUMMARY:Quarterly review", "LOCATION:Room 4", "ORGANIZER;CN=Zed:mailto:zed@remote.test",
		"ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:alice@example.test", "END:VEVENT", "END:VCALENDAR"}, "\r\n")
	raw := strings.Join([]string{"From: zed@remote.test", "To: alice@example.test", "Subject: Invitation", "MIME-Version: 1.0",
		"Content-Type: multipart/alternative; boundary=b", "", "--b", "Content-Type: text/plain", "", "Join us",
		"--b", "Content-Type: text/calendar; method=REQUEST; charset=utf-8", "", ics, "--b--", ""}, "\r\n")
	itemID, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}

	response, err := client.Get(server.URL + "/api/v1/workspace/mail/messages/" + url.PathEscape(itemID))
	if err != nil {
		t.Fatal(err)
	}
	var message struct {
		Text       string           `json:"text"`
		Invitation *imip.Invitation `json:"invitation"`
	}
	if err := json.NewDecoder(response.Body).Decode(&message); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if message.Invitation == nil || !message.Invitation.CanRespond || message.Invitation.Method != "REQUEST" || message.Invitation.Event.Summary != "Quarterly review" || message.Invitation.Response != "NEEDS-ACTION" {
		t.Fatalf("invitation card = %+v", message.Invitation)
	}

	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/workspace/mail/messages/"+url.PathEscape(itemID)+"/invitation", strings.NewReader(`{"response":"ACCEPTED"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var answered imip.Invitation
	if err := json.NewDecoder(response.Body).Decode(&answered); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || answered.Response != "ACCEPTED" {
		t.Fatalf("accept status = %d invitation = %+v", response.StatusCode, answered)
	}
	if len(sent) != 1 || sent[0].From != "alice@example.test" || sent[0].To[0] != "zed@remote.test" || !strings.Contains(string(sent[0].Raw), "method=REPLY") {
		t.Fatalf("accept sent %+v", sent)
	}

	request, _ = http.NewRequest(http.MethodPost, server.URL+"/api/v1/workspace/mail/messages/"+url.PathEscape(itemID)+"/invitation", strings.NewReader(`{"response":"MAYBE"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid response status = %d", response.StatusCode)
	}
}
