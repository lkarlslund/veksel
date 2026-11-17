package ews

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

var (
	subscriptionIDPattern = regexp.MustCompile(`<m:SubscriptionId>([^<]+)</m:SubscriptionId>`)
	watermarkPattern      = regexp.MustCompile(`<m:Watermark>([^<]+)</m:Watermark>`)
)

// outlookPullSubscribe is the pull Subscribe Outlook for Mac sends for the
// folders it shows.
func outlookPullSubscribe(folders, watermark string) string {
	request := `<m:Subscribe><m:PullSubscriptionRequest><t:FolderIds>` + folders + `</t:FolderIds><t:EventTypes>` +
		`<t:EventType>NewMailEvent</t:EventType><t:EventType>CreatedEvent</t:EventType><t:EventType>DeletedEvent</t:EventType>` +
		`<t:EventType>ModifiedEvent</t:EventType><t:EventType>MovedEvent</t:EventType><t:EventType>CopiedEvent</t:EventType></t:EventTypes>`
	if watermark != "" {
		request += `<t:Watermark>` + watermark + `</t:Watermark>`
	}
	return request + `<t:Timeout>10</t:Timeout></m:PullSubscriptionRequest></m:Subscribe>`
}

func subscribeAs(t *testing.T, handler http.Handler, request, user string) (string, string) {
	t.Helper()
	body := ewsRequestAs(t, handler, request, user, "secret").Body.String()
	id := subscriptionIDPattern.FindStringSubmatch(body)
	if id == nil {
		t.Fatalf("Subscribe = %s", body)
	}
	watermark := ""
	if match := watermarkPattern.FindStringSubmatch(body); match != nil {
		watermark = match[1]
	}
	return id[1], watermark
}

func getEvents(t *testing.T, handler http.Handler, id, user string) string {
	t.Helper()
	return ewsRequestAs(t, handler, `<m:GetEvents><m:SubscriptionId>`+id+`</m:SubscriptionId><m:Watermark>ignored</m:Watermark></m:GetEvents>`, user, "secret").Body.String()
}

// TestPullSubscriptionReportsMailboxChanges replays Outlook for Mac's pull
// notification loop: Subscribe on the Inbox, new mail arrives, GetEvents
// reports NewMailEvent and CreatedEvent naming the item and folder, then a
// flag change, a move out, and an idle poll's StatusEvent.
func TestPullSubscriptionReportsMailboxChanges(t *testing.T) {
	handler, space := testHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	archive, err := space.CreateFolder(t.Context(), access, "Filed", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	id, watermark := subscribeAs(t, handler, outlookPullSubscribe(`<t:DistinguishedFolderId Id="inbox"/>`, ""), "alice")
	if watermark == "" {
		t.Fatal("pull Subscribe returned no watermark")
	}
	if body := getEvents(t, handler, id, "alice"); !strings.Contains(body, "<t:StatusEvent>") || !strings.Contains(body, "<t:MoreEvents>false</t:MoreEvents>") {
		t.Fatalf("idle GetEvents = %s", body)
	}
	item, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("From: bob@example.test\r\nSubject: hi\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	body := getEvents(t, handler, id, "alice")
	itemRef := `<t:ItemId Id="` + encodeID("i:", item.ID) + `"`
	parentRef := `<t:ParentFolderId Id="` + encodeID("f:", inbox.ID) + `"/>`
	for _, want := range []string{"<t:NewMailEvent>", "<t:CreatedEvent>", itemRef, parentRef, "<t:PreviousWatermark>"} {
		if !strings.Contains(body, want) {
			t.Fatalf("GetEvents after new mail lacks %q: %s", want, body)
		}
	}
	if strings.Contains(body, "<t:StatusEvent>") {
		t.Fatalf("GetEvents with changes carried a StatusEvent: %s", body)
	}
	if _, err := space.SetFlags(t.Context(), access, item.ID, []string{`\Seen`}); err != nil {
		t.Fatal(err)
	}
	if body := getEvents(t, handler, id, "alice"); !strings.Contains(body, "<t:ModifiedEvent>") || !strings.Contains(body, itemRef) {
		t.Fatalf("GetEvents after flag change = %s", body)
	}
	if _, err := space.MoveItem(t.Context(), access, item.ID, archive.ID, ""); err != nil {
		t.Fatal(err)
	}
	body = getEvents(t, handler, id, "alice")
	if !strings.Contains(body, "<t:MovedEvent>") || !strings.Contains(body, `<t:OldParentFolderId Id="`+encodeID("f:", inbox.ID)+`"/>`) || !strings.Contains(body, `<t:ParentFolderId Id="`+encodeID("f:", archive.ID)+`"/>`) {
		t.Fatalf("GetEvents after move = %s", body)
	}

	// Resubscribing from the first watermark replays everything since.
	resumed, _ := subscribeAs(t, handler, outlookPullSubscribe(`<t:DistinguishedFolderId Id="inbox"/>`, watermark), "alice")
	if body := getEvents(t, handler, resumed, "alice"); !strings.Contains(body, "<t:NewMailEvent>") || !strings.Contains(body, "<t:MovedEvent>") {
		t.Fatalf("GetEvents from a resumed watermark = %s", body)
	}

	if body := ewsRequest(t, handler, `<m:Unsubscribe><m:SubscriptionId>`+id+`</m:SubscriptionId></m:Unsubscribe>`).Body.String(); !strings.Contains(body, `<m:UnsubscribeResponseMessage ResponseClass="Success">`) {
		t.Fatalf("Unsubscribe = %s", body)
	}
	if body := getEvents(t, handler, id, "alice"); !strings.Contains(body, "ErrorSubscriptionNotFound") {
		t.Fatalf("GetEvents after Unsubscribe = %s", body)
	}
}

// TestSubscriptionErrors covers the per-message errors clients resubscribe
// on: unknown and expired subscriptions, another user's subscription, a
// streaming subscription polled with GetEvents, and bad requests.
func TestSubscriptionErrors(t *testing.T) {
	handler, _ := testHandler(t)
	if body := getEvents(t, handler, "bm9wZQ==", "alice"); !strings.Contains(body, `ResponseClass="Error"`) || !strings.Contains(body, "ErrorSubscriptionNotFound") {
		t.Fatalf("GetEvents on unknown subscription = %s", body)
	}
	id, _ := subscribeAs(t, handler, outlookPullSubscribe(`<t:DistinguishedFolderId Id="inbox"/>`, ""), "alice")
	if body := getEvents(t, handler, id, "bob"); !strings.Contains(body, "ErrorSubscriptionAccessDenied") {
		t.Fatalf("GetEvents on another user's subscription = %s", body)
	}
	streaming, _ := subscribeAs(t, handler, `<m:Subscribe><m:StreamingSubscriptionRequest SubscribeToAllFolders="true"><t:EventTypes><t:EventType>NewMailEvent</t:EventType></t:EventTypes></m:StreamingSubscriptionRequest></m:Subscribe>`, "alice")
	if body := getEvents(t, handler, streaming, "alice"); !strings.Contains(body, "ErrorInvalidSubscription") {
		t.Fatalf("GetEvents on a streaming subscription = %s", body)
	}
	for name, request := range map[string]string{
		"push":           `<m:Subscribe><m:PushSubscriptionRequest><t:FolderIds><t:DistinguishedFolderId Id="inbox"/></t:FolderIds><t:EventTypes><t:EventType>NewMailEvent</t:EventType></t:EventTypes><t:URL>http://example.test/</t:URL></m:PushSubscriptionRequest></m:Subscribe>`,
		"timeout":        `<m:Subscribe><m:PullSubscriptionRequest><t:FolderIds><t:DistinguishedFolderId Id="inbox"/></t:FolderIds><t:EventTypes><t:EventType>NewMailEvent</t:EventType></t:EventTypes><t:Timeout>0</t:Timeout></m:PullSubscriptionRequest></m:Subscribe>`,
		"event type":     `<m:Subscribe><m:PullSubscriptionRequest><t:FolderIds><t:DistinguishedFolderId Id="inbox"/></t:FolderIds><t:EventTypes><t:EventType>Bogus</t:EventType></t:EventTypes><t:Timeout>5</t:Timeout></m:PullSubscriptionRequest></m:Subscribe>`,
		"watermark":      outlookPullSubscribe(`<t:DistinguishedFolderId Id="inbox"/>`, "!!"),
		"missing folder": outlookPullSubscribe(`<t:FolderId Id="`+encodeID("f:", "gone")+`"/>`, ""),
	} {
		body := ewsRequest(t, handler, request).Body.String()
		if !strings.Contains(body, `<m:SubscribeResponseMessage ResponseClass="Error">`) {
			t.Errorf("%s: Subscribe = %s", name, body)
		}
	}

	// A pull subscription lapses after its Timeout without GetEvents.
	handler.subscriptions.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if body := getEvents(t, handler, id, "alice"); !strings.Contains(body, "ErrorSubscriptionNotFound") {
		t.Fatalf("GetEvents on an expired subscription = %s", body)
	}
	handler.subscriptions.now = time.Now
	if got := handler.subscriptions.count(); got != 1 {
		t.Fatalf("subscriptions after expiry = %d, want only the streaming one", got)
	}
	for range maxSubscriptionsPerUser - 1 {
		subscribeAs(t, handler, outlookPullSubscribe(`<t:DistinguishedFolderId Id="inbox"/>`, ""), "alice")
	}
	if body := ewsRequest(t, handler, outlookPullSubscribe(`<t:DistinguishedFolderId Id="inbox"/>`, "")).Body.String(); !strings.Contains(body, "ErrorExceededSubscriptionCount") {
		t.Fatalf("Subscribe beyond the per-user limit = %s", body)
	}
}

// notifyingSpace reports commits like the production account space does.
type notifyingSpace struct {
	*service.FolderSpaceService
	mu        sync.Mutex
	listeners []func(string, []string)
}

func (s *notifyingSpace) OnChangesCommitted(listener func(string, []string)) func() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listeners = append(s.listeners, listener)
	return func() {}
}

func (s *notifyingSpace) CreateItem(ctx context.Context, access service.AccessContext, folderID string, input service.ItemInput) (model.Item, error) {
	item, err := s.FolderSpaceService.CreateItem(ctx, access, folderID, input)
	if err == nil {
		s.mu.Lock()
		listeners := append([]func(string, []string){}, s.listeners...)
		s.mu.Unlock()
		for _, listener := range listeners {
			listener(access.Subject.ID, []string{folderID})
		}
	}
	return item, err
}

// TestStreamingSubscriptionDeliversOnCommit replays Outlook for Mac's
// streaming notifications: a StreamingSubscriptionRequest, then
// GetStreamingEvents held open. A commit reaches the open response within
// 200 ms as a chunked SOAP envelope, and the response ends with
// ConnectionStatus Closed at ConnectionTimeout.
func TestStreamingSubscriptionDeliversOnCommit(t *testing.T) {
	base, folderSpace := testHandler(t)
	space := &notifyingSpace{FolderSpaceService: folderSpace}
	handler, err := New(Config{Space: space, Authenticate: base.authenticate})
	if err != nil {
		t.Fatal(err)
	}
	handler.streamingMinute = 600 * time.Millisecond
	server := httptest.NewServer(handler)
	defer server.Close()
	access := service.UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	id, watermark := subscribeAs(t, handler, `<m:Subscribe><m:StreamingSubscriptionRequest><t:FolderIds><t:DistinguishedFolderId Id="inbox"/></t:FolderIds><t:EventTypes>`+
		`<t:EventType>NewMailEvent</t:EventType><t:EventType>CreatedEvent</t:EventType><t:EventType>ModifiedEvent</t:EventType></t:EventTypes></m:StreamingSubscriptionRequest></m:Subscribe>`, "alice")
	if watermark != "" {
		t.Fatalf("streaming Subscribe returned a watermark")
	}
	envelopeBody := `<s:Envelope xmlns:s="` + soapNS + `" xmlns:m="` + msgNS + `" xmlns:t="` + typeNS + `"><s:Body><m:GetStreamingEvents><m:SubscriptionIds><t:SubscriptionId>` + id +
		`</t:SubscriptionId></m:SubscriptionIds><m:ConnectionTimeout>1</m:ConnectionTimeout></m:GetStreamingEvents></s:Body></s:Envelope>`
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, strings.NewReader(envelopeBody))
	request.SetBasicAuth("alice", "secret")
	started := time.Now()
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	envelopes := make(chan string, 16)
	go func() {
		defer close(envelopes)
		reader := bufio.NewReader(response.Body)
		var current strings.Builder
		for {
			chunk, err := reader.ReadString('>')
			current.WriteString(chunk)
			if strings.HasSuffix(current.String(), "</s:Envelope>") {
				envelopes <- current.String()
				current.Reset()
			}
			if err != nil {
				return
			}
		}
	}()
	next := func(within time.Duration) string {
		select {
		case envelope, ok := <-envelopes:
			if !ok {
				t.Fatal("stream ended early")
			}
			return envelope
		case <-time.After(within):
			t.Fatal("no envelope in time")
		}
		return ""
	}
	if first := next(time.Second); !strings.Contains(first, "<m:ConnectionStatus>OK</m:ConnectionStatus>") {
		t.Fatalf("first envelope = %s", first)
	}
	committed := time.Now()
	item, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: streamed\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	event := next(200 * time.Millisecond)
	if delay := time.Since(committed); delay > 200*time.Millisecond {
		t.Fatalf("event arrived after %v", delay)
	}
	for _, want := range []string{"<m:Notifications>", "<t:SubscriptionId>" + id + "</t:SubscriptionId>", "<t:NewMailEvent>", "<t:CreatedEvent>", encodeID("i:", item.ID)} {
		if !strings.Contains(event, want) {
			t.Fatalf("streamed envelope lacks %q: %s", want, event)
		}
	}
	last := next(2 * time.Second)
	if !strings.Contains(last, "<m:ConnectionStatus>Closed</m:ConnectionStatus>") {
		t.Fatalf("last envelope = %s", last)
	}
	if elapsed := time.Since(started); elapsed < 500*time.Millisecond {
		t.Fatalf("stream closed after %v, before ConnectionTimeout", elapsed)
	}
	if _, ok := <-envelopes; ok {
		t.Fatal("stream continued after Closed")
	}
	// The subscription outlives the connection, ready for the next one.
	if _, err := handler.subscriptions.lookup(access, id, true); err != nil {
		t.Fatalf("subscription after connection close: %v", err)
	}
	if body := ewsRequest(t, handler, `<m:GetStreamingEvents><m:SubscriptionIds><t:SubscriptionId>missing</t:SubscriptionId></m:SubscriptionIds><m:ConnectionTimeout>1</m:ConnectionTimeout></m:GetStreamingEvents>`).Body.String(); !strings.Contains(body, "ErrorSubscriptionNotFound") {
		t.Fatalf("GetStreamingEvents on unknown subscription = %s", body)
	}
}
