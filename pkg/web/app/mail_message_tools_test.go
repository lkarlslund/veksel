package app

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// richMailFixture serves an app with a recording queue, an owner "alice" with
// alice@example.test, and a second user "bob".
func richMailFixture(t *testing.T) (*acceptingSubmissionQueue, *model.TypedStore, string, *http.Client, string) {
	t.Helper()
	handler, ts := testHandler(t)
	mailQueue := &acceptingSubmissionQueue{}
	handler.SetMailQueue(mailQueue)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	if err := ts.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	users := ts.UserStore()
	if err := users.AddEmailAddress(t.Context(), "alice@example.test", "alice", "example.test", true); err != nil {
		t.Fatal(err)
	}
	if err := users.Create(t.Context(), "bob", "bob", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := model.NewFolderStore(ts).EnsureForUser(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	return mailQueue, ts, server.URL, client, csrf
}

func readJSONResponse(t *testing.T, response *http.Response, value any) {
	t.Helper()
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if value != nil {
		if err := json.Unmarshal(data, value); err != nil {
			t.Fatalf("decode %s: %v", data, err)
		}
	}
}

func TestMailSourceAndEMLDownloadAuthorization(t *testing.T) {
	_, ts, serverURL, client, _ := richMailFixture(t)
	raw := "From: sender@example.net\r\nTo: alice@example.test\r\nSubject: =?UTF-8?Q?Budget_/_plan?=\r\nMessage-ID: <budget@example.net>\r\n\r\nSecret body\r\n"
	itemID, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	base := serverURL + "/api/v1/workspace/mail/messages/" + url.PathEscape(itemID)
	response, err := client.Get(base + "/source")
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		Size      int    `json:"size"`
		Truncated bool   `json:"truncated"`
		Headers   string `json:"headers"`
		Source    string `json:"source"`
	}
	readJSONResponse(t, response, &source)
	if response.StatusCode != http.StatusOK || source.Source != raw || source.Size != len(raw) || source.Truncated || !strings.HasSuffix(source.Headers, "Message-ID: <budget@example.net>") || strings.Contains(source.Headers, "Secret body") {
		t.Fatalf("source status=%d payload=%+v", response.StatusCode, source)
	}
	response, err = client.Get(base + "/eml")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	_, params, _ := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	if response.StatusCode != http.StatusOK || string(data) != raw || response.Header.Get("Content-Type") != "message/rfc822" || params["filename"] != "Budget plan.eml" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("eml status=%d headers=%v body=%q", response.StatusCode, response.Header, data)
	}

	bobClient := testClient(t)
	loginExistingUser(t, bobClient, serverURL, "bob")
	for _, path := range []string{"/source", "/eml"} {
		response, err := bobClient.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode == http.StatusOK || strings.Contains(string(data), "Secret body") {
			t.Fatalf("bob read alice's message %s: status=%d body=%s", path, response.StatusCode, data)
		}
	}
}

func TestMailReceiptRequestIsAnsweredOnceAndNeverAutomatically(t *testing.T) {
	mailQueue, ts, serverURL, client, csrf := richMailFixture(t)
	raw := "From: Sender <sender@example.net>\r\nTo: alice@example.test\r\nSubject: Please confirm\r\nMessage-ID: <confirm@example.net>\r\nDisposition-Notification-To: Sender <sender@example.net>\r\n\r\nBody\r\n"
	itemID, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	base := serverURL + "/api/v1/workspace/mail/messages/" + url.PathEscape(itemID)
	response, err := client.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	var projection service.MessageProjection
	readJSONResponse(t, response, &projection)
	if projection.Headers["Disposition-Notification-To"] != "Sender <sender@example.net>" || len(mailQueue.queued) != 0 {
		t.Fatalf("opening the message: headers=%v queued=%d", projection.Headers, len(mailQueue.queued))
	}
	response = authenticatedJSON(t, client, http.MethodPost, base+"/receipt", csrf, `{"action":"send"}`)
	var result struct {
		Flags     []string `json:"flags"`
		Recipient string   `json:"recipient"`
	}
	readJSONResponse(t, response, &result)
	if response.StatusCode != http.StatusOK || result.Recipient != "sender@example.net" || !slices.Contains(result.Flags, model.KeywordMDNSent) || len(mailQueue.queued) != 1 {
		t.Fatalf("send receipt status=%d result=%+v queued=%d", response.StatusCode, result, len(mailQueue.queued))
	}
	queued := mailQueue.queued[0]
	mediaType, params, _ := mime.ParseMediaType(queued.Headers["Content-Type"])
	if queued.Recipient != "sender@example.net" || queued.EnvelopeSender != "alice@example.test" || mediaType != "multipart/report" || params["report-type"] != "disposition-notification" || !strings.Contains(string(queued.Body), "Disposition: manual-action/MDN-sent-manually; displayed") {
		t.Fatalf("queued MDN = %+v body=%s", queued, queued.Body)
	}
	response = authenticatedJSON(t, client, http.MethodPost, base+"/receipt", csrf, `{"action":"send"}`)
	readJSONResponse(t, response, nil)
	if response.StatusCode != http.StatusConflict || len(mailQueue.queued) != 1 {
		t.Fatalf("second receipt status=%d queued=%d", response.StatusCode, len(mailQueue.queued))
	}

	plain, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte("From: other@example.net\r\nSubject: No request\r\n\r\nBody\r\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	plainBase := serverURL + "/api/v1/workspace/mail/messages/" + url.PathEscape(plain)
	response = authenticatedJSON(t, client, http.MethodPost, plainBase+"/receipt", csrf, `{"action":"send"}`)
	readJSONResponse(t, response, nil)
	if response.StatusCode != http.StatusBadRequest || len(mailQueue.queued) != 1 {
		t.Fatalf("receipt without a request status=%d queued=%d", response.StatusCode, len(mailQueue.queued))
	}
	response = authenticatedJSON(t, client, http.MethodPost, plainBase+"/receipt", csrf, `{"action":"dismiss"}`)
	readJSONResponse(t, response, &result)
	if response.StatusCode != http.StatusOK || !slices.Contains(result.Flags, model.KeywordMDNSent) || len(mailQueue.queued) != 1 {
		t.Fatalf("dismiss status=%d result=%+v queued=%d", response.StatusCode, result, len(mailQueue.queued))
	}

	bobClient := testClient(t)
	bobCSRF := loginExistingUser(t, bobClient, serverURL, "bob")
	other, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	response = authenticatedJSON(t, bobClient, http.MethodPost, serverURL+"/api/v1/workspace/mail/messages/"+url.PathEscape(other)+"/receipt", bobCSRF, `{"action":"send"}`)
	readJSONResponse(t, response, nil)
	if response.StatusCode == http.StatusOK || len(mailQueue.queued) != 1 {
		t.Fatalf("bob answered alice's receipt request: status=%d queued=%d", response.StatusCode, len(mailQueue.queued))
	}
	// Reading alice's Inbox through a share does not let bob answer for her,
	// once or repeatedly.
	if err := ts.UserStore().AddEmailAddress(t.Context(), "bob@example.test", "bob", "example.test", true); err != nil {
		t.Fatal(err)
	}
	grant := authenticatedJSON(t, client, http.MethodPost, serverURL+"/api/v1/folders/"+url.PathEscape(model.InboxFolderID("alice"))+"/grants", csrf, `{"principal":{"kind":"user","id":"bob"},"effect":"allow","role_id":"folder.viewer","inheritance":"self"}`)
	readJSONResponse(t, grant, nil)
	if grant.StatusCode != http.StatusCreated {
		t.Fatalf("grant status = %d", grant.StatusCode)
	}
	if response, err := bobClient.Get(serverURL + "/api/v1/workspace/mail/messages/" + url.PathEscape(other) + "/source"); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("viewer cannot read the shared message: %v %v", response.StatusCode, err)
	}
	for range 2 {
		response = authenticatedJSON(t, bobClient, http.MethodPost, serverURL+"/api/v1/workspace/mail/messages/"+url.PathEscape(other)+"/receipt", bobCSRF, `{"action":"send"}`)
		readJSONResponse(t, response, nil)
		if response.StatusCode != http.StatusForbidden || len(mailQueue.queued) != 1 {
			t.Fatalf("viewer answered alice's receipt request: status=%d queued=%d", response.StatusCode, len(mailQueue.queued))
		}
	}
}

func TestRemoteImageSenderAllowlist(t *testing.T) {
	_, ts, serverURL, client, csrf := richMailFixture(t)
	raw := "From: News <News@Example.net>\r\nTo: alice@example.test\r\nSubject: Offers\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hi</p><img src=\"https://cdn.example.net/banner.png\">"
	itemID, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	message := func() (bool, string) {
		response, err := client.Get(serverURL + "/api/v1/workspace/mail/messages/" + url.PathEscape(itemID))
		if err != nil {
			t.Fatal(err)
		}
		var projection struct {
			HTML                 string `json:"html"`
			RemoteContentBlocked bool   `json:"remote_content_blocked"`
			RemoteImagesAllowed  bool   `json:"remote_images_allowed"`
		}
		readJSONResponse(t, response, &projection)
		if !projection.RemoteContentBlocked || strings.Contains(projection.HTML, ` src="https://`) {
			t.Fatalf("remote image was not blocked by the sanitizer: %+v", projection)
		}
		return projection.RemoteImagesAllowed, projection.HTML
	}
	if allowed, html := message(); allowed || !strings.Contains(html, `data-remote-src="https://cdn.example.net/banner.png"`) {
		t.Fatalf("before allowing: allowed=%v html=%s", allowed, html)
	}
	var list struct {
		Senders []string `json:"senders"`
	}
	response := authenticatedJSON(t, client, http.MethodPut, serverURL+"/api/v1/user/remote-image-senders/"+url.PathEscape("NEWS@example.net"), csrf, "")
	readJSONResponse(t, response, &list)
	if response.StatusCode != http.StatusOK || !slices.Equal(list.Senders, []string{"news@example.net"}) {
		t.Fatalf("allow sender status=%d list=%v", response.StatusCode, list.Senders)
	}
	if allowed, _ := message(); !allowed {
		t.Fatal("allowed sender's images were not marked as allowed")
	}
	stored, err := ts.UserStore().Get(t.Context(), "alice")
	if err != nil || !slices.Equal(stored.RemoteImageSenders, []string{"news@example.net"}) {
		t.Fatalf("persisted senders=%v err=%v", stored.RemoteImageSenders, err)
	}
	response = authenticatedJSON(t, client, http.MethodDelete, serverURL+"/api/v1/user/remote-image-senders/news@example.net", csrf, "")
	readJSONResponse(t, response, &list)
	if response.StatusCode != http.StatusOK || len(list.Senders) != 0 {
		t.Fatalf("remove sender status=%d list=%v", response.StatusCode, list.Senders)
	}
	if allowed, _ := message(); allowed {
		t.Fatal("removed sender's images were still allowed")
	}
	response = authenticatedJSON(t, client, http.MethodPut, serverURL+"/api/v1/user/remote-image-senders/not-an-address", csrf, "")
	readJSONResponse(t, response, nil)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid sender status=%d", response.StatusCode)
	}

	bobClient := testClient(t)
	loginExistingUser(t, bobClient, serverURL, "bob")
	response, err = bobClient.Get(serverURL + "/api/v1/user/remote-image-senders")
	if err != nil {
		t.Fatal(err)
	}
	readJSONResponse(t, response, &list)
	if response.StatusCode != http.StatusOK || len(list.Senders) != 0 {
		t.Fatalf("bob sees alice's allowlist: %v", list.Senders)
	}
}

func TestHTMLDraftAndSubmissionThroughREST(t *testing.T) {
	mailQueue, _, serverURL, client, csrf := richMailFixture(t)
	draftBody := `{"from":"alice@example.test","to":["recipient@example.net"],"subject":"Rich","read_receipt":true,` +
		`"html":"<p onclick=\"x()\">Hello <b>there</b></p><script>steal()</script><p><img src=\"cid:pic1@veksel\" alt=\"pic\"></p>",` +
		`"attachments":[{"name":"pic.png","content_type":"image/png","content_id":"pic1@veksel","data":"cGljdHVyZQ=="}]}`
	response := authenticatedJSON(t, client, http.MethodPost, serverURL+"/api/v1/workspace/mail/drafts", csrf, draftBody)
	var draft service.ItemSummary
	readJSONResponse(t, response, &draft)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create HTML draft status=%d", response.StatusCode)
	}
	response, err := client.Get(serverURL + "/api/v1/workspace/mail/drafts/" + url.PathEscape(draft.ID))
	if err != nil {
		t.Fatal(err)
	}
	var saved service.Submission
	readJSONResponse(t, response, &saved)
	if saved.HTML != `<p>Hello <b>there</b></p><p><img src="cid:pic1@veksel" alt="pic"/></p>` || !saved.ReadReceipt || saved.Body != "Hello there\n\n[pic]" {
		t.Fatalf("restored draft html=%q body=%q receipt=%v", saved.HTML, saved.Body, saved.ReadReceipt)
	}
	if len(saved.Attachments) != 1 || saved.Attachments[0].ContentID != "pic1@veksel" || string(saved.Attachments[0].Data) != "picture" {
		t.Fatalf("restored draft attachments = %+v", saved.Attachments)
	}

	response = authenticatedJSON(t, client, http.MethodPost, serverURL+"/api/v1/mail/submissions", csrf,
		`{"draft_id":"`+draft.ID+`","from":"alice@example.test","to":["recipient@example.net"],"subject":"Rich","read_receipt":true,"html":`+jsonString(saved.HTML)+`}`)
	readJSONResponse(t, response, nil)
	if response.StatusCode != http.StatusAccepted || len(mailQueue.queued) != 1 {
		t.Fatalf("HTML submission status=%d queued=%d", response.StatusCode, len(mailQueue.queued))
	}
	queued := mailQueue.queued[0]
	mediaType, _, _ := mime.ParseMediaType(queued.Headers["Content-Type"])
	body := string(queued.Body)
	if mediaType != "multipart/alternative" || queued.Headers["Disposition-Notification-To"] != queued.Headers["From"] || !strings.HasSuffix(queued.Headers["From"], "<alice@example.test>") || !strings.Contains(body, "multipart/related") || !strings.Contains(body, "Content-Id: <pic1@veksel>") || strings.Contains(body, "steal") || strings.Contains(body, "onclick") {
		t.Fatalf("queued HTML message headers=%v body=%s", queued.Headers, body)
	}
}

func TestRichSignatureIsSanitizedWithPlainTextForm(t *testing.T) {
	_, _, serverURL, client, csrf := richMailFixture(t)
	response := authenticatedJSON(t, client, http.MethodPut, serverURL+"/api/v1/user/signatures/alice@example.test", csrf,
		`{"text":"","html":"<p><b>Alice</b> <img src=x onerror=alert(1)></p><script>bad()</script><p><a href=\"https://example.test\">Site</a></p>","new_messages":true}`)
	var signature model.MailSignature
	readJSONResponse(t, response, &signature)
	if response.StatusCode != http.StatusOK || strings.Contains(signature.HTML, "onerror") || strings.Contains(signature.HTML, "script") || !strings.Contains(signature.HTML, "<b>Alice</b>") || signature.Text != "Alice\n\nSite <https://example.test>" || !signature.NewMessages {
		t.Fatalf("signature status=%d saved=%+v", response.StatusCode, signature)
	}
}

func jsonString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
