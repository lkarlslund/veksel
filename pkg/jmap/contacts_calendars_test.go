package jmap

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/imip"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// call runs one JMAP request and returns the method responses keyed by tag.
func (f *fixture) call(t *testing.T, user string, calls ...[]any) map[string][]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{"using": []string{CoreCapability, MailCapability, SubmissionCapability, VacationCapability, ContactsCapability, CalendarsCapability}, "methodCalls": calls})
	if err != nil {
		t.Fatal(err)
	}
	response := decodeResponse(t, f.request(t, "POST", "/jmap/api", string(body), user, "password"))
	out := map[string][]any{}
	for _, raw := range response["methodResponses"].([]any) {
		invocation := raw.([]any)
		out[invocation[2].(string)] = invocation
	}
	return out
}

// result returns the arguments of a successful method response.
func result(t *testing.T, responses map[string][]any, tag, name string) map[string]any {
	t.Helper()
	invocation, ok := responses[tag]
	if !ok || invocation[0] != name {
		t.Fatalf("%s: expected %s, got %#v", tag, name, invocation)
	}
	return invocation[1].(map[string]any)
}

func folderByPath(t *testing.T, f *fixture, user, path string) model.Folder {
	t.Helper()
	folder, err := f.space.GetFolderByPath(t.Context(), service.UserAccess(user, "test"), path)
	if err != nil {
		t.Fatal(err)
	}
	return folder
}

func share(t *testing.T, f *fixture, folder model.Folder, grantee, role string) {
	t.Helper()
	_, err := model.NewPolicyStore(f.ts).Create(t.Context(), model.PolicyBinding{Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: grantee},
		Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folder.ID}, Effect: model.EffectAllow, RoleID: role, Inheritance: model.InheritanceSelf, GrantedBy: folder.UserID})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSessionAdvertisesContactsAndCalendars(t *testing.T) {
	f := newFixture(t)
	session := decodeResponse(t, f.request(t, "GET", "/.well-known/jmap", "", "alice", "password"))
	caps := session["capabilities"].(map[string]any)
	for _, capability := range []string{ContactsCapability, CalendarsCapability} {
		if caps[capability] == nil {
			t.Errorf("missing session capability %s", capability)
		}
		if session["primaryAccounts"].(map[string]any)[capability] != "alice" {
			t.Errorf("missing primary account for %s", capability)
		}
	}
	account := session["accounts"].(map[string]any)["alice"].(map[string]any)["accountCapabilities"].(map[string]any)
	if account[ContactsCapability].(map[string]any)["mayCreateAddressBook"] != true || account[CalendarsCapability].(map[string]any)["mayCreateCalendar"] != true {
		t.Fatalf("account capabilities = %#v", account)
	}
}

func TestContactCardLifecycleThroughJMAP(t *testing.T) {
	f := newFixture(t)
	book := folderByPath(t, f, "alice", "Contacts")
	responses := f.call(t, "alice", []any{"AddressBook/get", map[string]any{"accountId": "alice"}, "books"}, []any{"ContactCard/get", map[string]any{"accountId": "alice", "ids": []string{}}, "cards"})
	books := result(t, responses, "books", "AddressBook/get")["list"].([]any)
	foundDefault := false
	for _, raw := range books {
		b := raw.(map[string]any)
		if b["id"] == book.ID && b["isDefault"] == true && b["myRights"].(map[string]any)["mayWrite"] == true {
			foundDefault = true
		}
	}
	if !foundDefault {
		t.Fatalf("default address book missing: %#v", books)
	}
	initial := result(t, responses, "cards", "ContactCard/get")["state"].(string)

	responses = f.call(t, "alice",
		[]any{"ContactCard/set", map[string]any{"accountId": "alice", "create": map[string]any{"ada": map[string]any{
			"addressBookIds": map[string]any{book.ID: true}, "kind": "individual",
			"name":   map[string]any{"components": []any{map[string]any{"kind": "given", "value": "Ada"}, map[string]any{"kind": "surname", "value": "Lovelace"}}},
			"emails": map[string]any{"e1": map[string]any{"address": "ada@example.test", "contexts": map[string]any{"work": true}}},
		}}}, "create"},
		[]any{"ContactCard/query", map[string]any{"accountId": "alice", "filter": map[string]any{"email": "ada@"}, "sort": []any{map[string]any{"property": "name/surname", "isAscending": true}}, "calculateTotal": true}, "query"},
		[]any{"ContactCard/get", map[string]any{"accountId": "alice", "#ids": map[string]any{"resultOf": "query", "name": "ContactCard/query", "path": "/ids"}}, "get"},
	)
	created := result(t, responses, "create", "ContactCard/set")["created"].(map[string]any)["ada"].(map[string]any)
	id := created["id"].(string)
	if !strings.HasPrefix(created["uid"].(string), "urn:uuid:") {
		t.Fatalf("server uid = %#v", created)
	}
	query := result(t, responses, "query", "ContactCard/query")
	if ids := query["ids"].([]any); len(ids) != 1 || ids[0] != id || query["total"] != float64(1) || query["canCalculateChanges"] != true {
		t.Fatalf("query = %#v", query)
	}
	card := result(t, responses, "get", "ContactCard/get")["list"].([]any)[0].(map[string]any)
	if card["name"].(map[string]any)["full"] != "Ada Lovelace" || card["addressBookIds"].(map[string]any)[book.ID] != true {
		t.Fatalf("card = %#v", card)
	}
	stored, err := f.space.GetItem(t.Context(), service.UserAccess("alice", "test"), id)
	if err != nil {
		t.Fatal(err)
	}
	if parsed := model.ParseVCard(stored.Data); parsed.FN != "Ada Lovelace" || len(parsed.Emails) != 1 {
		t.Fatalf("CardDAV view of the card = %#v", parsed)
	}
	// A CardDAV client adds a vendor property; a JMAP patch keeps it.
	withVendor := strings.Replace(string(stored.Data), "END:VCARD", "X-VENDOR-FLAG;X-P=1:keep me\r\nEND:VCARD", 1)
	if _, err := f.space.UpdateItem(t.Context(), service.UserAccess("alice", "test"), id, []byte(withVendor), stored.Headers); err != nil {
		t.Fatal(err)
	}
	afterCreate := result(t, f.call(t, "alice", []any{"ContactCard/get", map[string]any{"accountId": "alice", "ids": []string{}}, "s"}), "s", "ContactCard/get")["state"].(string)
	responses = f.call(t, "alice",
		[]any{"ContactCard/set", map[string]any{"accountId": "alice", "ifInState": afterCreate, "update": map[string]any{id: map[string]any{"emails/e1/address": "ada@new.test", "notes": map[string]any{"n1": map[string]any{"note": "Analyst"}}}}}, "update"},
		[]any{"ContactCard/changes", map[string]any{"accountId": "alice", "sinceState": initial}, "fromStart"},
		[]any{"ContactCard/changes", map[string]any{"accountId": "alice", "sinceState": afterCreate}, "sinceCreate"},
		[]any{"ContactCard/queryChanges", map[string]any{"accountId": "alice", "filter": map[string]any{"email": "ada@"}, "sinceQueryState": query["queryState"]}, "qc"},
		[]any{"ContactCard/set", map[string]any{"accountId": "alice", "ifInState": "stale", "destroy": []string{id}}, "stale"},
	)
	if updated := result(t, responses, "update", "ContactCard/set")["updated"].(map[string]any); len(updated) != 1 {
		t.Fatalf("update = %#v", responses["update"])
	}
	if c := result(t, responses, "fromStart", "ContactCard/changes"); len(c["created"].([]any)) != 1 || len(c["updated"].([]any)) != 0 {
		t.Fatalf("changes from start = %#v", c)
	}
	if c := result(t, responses, "sinceCreate", "ContactCard/changes"); len(c["updated"].([]any)) != 1 || c["updated"].([]any)[0] != id {
		t.Fatalf("changes since create = %#v", c)
	}
	qc := result(t, responses, "qc", "ContactCard/queryChanges")
	if added := qc["added"].([]any); len(added) != 1 || added[0].(map[string]any)["id"] != id {
		t.Fatalf("queryChanges = %#v", qc)
	}
	if responses["stale"][0] != "error" || responses["stale"][1].(map[string]any)["type"] != "stateMismatch" {
		t.Fatalf("stale ifInState = %#v", responses["stale"])
	}
	stored, _ = f.space.GetItem(t.Context(), service.UserAccess("alice", "test"), id)
	for _, want := range []string{"X-VENDOR-FLAG;X-P=1:keep me", "ada@new.test", "NOTE:Analyst"} {
		if !strings.Contains(string(stored.Data), want) {
			t.Fatalf("stored card lacks %q:\n%s", want, stored.Data)
		}
	}
	beforeDestroy := result(t, f.call(t, "alice", []any{"ContactCard/get", map[string]any{"accountId": "alice", "ids": []string{}}, "s"}), "s", "ContactCard/get")["state"].(string)
	responses = f.call(t, "alice", []any{"ContactCard/set", map[string]any{"accountId": "alice", "destroy": []string{id}}, "destroy"},
		[]any{"ContactCard/changes", map[string]any{"accountId": "alice", "sinceState": beforeDestroy}, "changes"})
	if destroyed := result(t, responses, "changes", "ContactCard/changes")["destroyed"].([]any); len(destroyed) != 1 || destroyed[0] != id {
		t.Fatalf("destroy changes = %#v", responses["changes"])
	}
}

func TestAddressBookSetRequiresRemovingContents(t *testing.T) {
	f := newFixture(t)
	responses := f.call(t, "alice",
		[]any{"AddressBook/set", map[string]any{"accountId": "alice", "create": map[string]any{"b": map[string]any{"name": "Clients", "description": "ignored"}}}, "book"},
		[]any{"ContactCard/set", map[string]any{"accountId": "alice", "create": map[string]any{"c": map[string]any{"addressBookIds": map[string]any{"#b": true}, "name": map[string]any{"full": "Client"}}}}, "card"},
		[]any{"AddressBook/set", map[string]any{"accountId": "alice", "update": map[string]any{"#b": map[string]any{"name": "Customers"}}, "destroy": []string{"#b"}}, "keep"},
		[]any{"AddressBook/set", map[string]any{"accountId": "alice", "destroy": []string{"#b"}, "onDestroyRemoveContents": true}, "remove"},
	)
	created := result(t, responses, "book", "AddressBook/set")["created"].(map[string]any)["b"].(map[string]any)
	if created["description"] != nil {
		t.Fatalf("unsupported description reported as stored: %#v", created)
	}
	if len(result(t, responses, "card", "ContactCard/set")["created"].(map[string]any)) != 1 {
		t.Fatalf("card = %#v", responses["card"])
	}
	keep := result(t, responses, "keep", "AddressBook/set")
	if keep["notDestroyed"].(map[string]any)[created["id"].(string)].(map[string]any)["type"] != "addressBookHasContents" || len(keep["updated"].(map[string]any)) != 1 {
		t.Fatalf("destroy without removal = %#v", keep)
	}
	if destroyed := result(t, responses, "remove", "AddressBook/set")["destroyed"].([]any); len(destroyed) != 1 {
		t.Fatalf("destroy with removal = %#v", responses["remove"])
	}
	if _, err := f.space.GetFolder(t.Context(), service.UserAccess("alice", "test"), created["id"].(string)); err == nil {
		t.Fatal("address book still exists")
	}
}

func meetingEvent(calendarID string) map[string]any {
	return map[string]any{
		"calendarIds": map[string]any{calendarID: true}, "@type": "Event", "title": "Standup", "start": "2026-11-02T09:00:00",
		"timeZone": "Europe/Copenhagen", "duration": "PT15M",
		"recurrenceRules":     []any{map[string]any{"@type": "RecurrenceRule", "frequency": "daily", "count": 5}},
		"recurrenceOverrides": map[string]any{"2026-11-03T09:00:00": map[string]any{"excluded": true}, "2026-11-04T09:00:00": map[string]any{"title": "Standup (long)", "duration": "PT45M"}},
		"alerts":              map[string]any{"a1": map[string]any{"@type": "Alert", "trigger": map[string]any{"@type": "OffsetTrigger", "offset": "-PT5M"}}},
	}
}

func TestCalendarEventLifecycleWithRecurrenceOverrides(t *testing.T) {
	f := newFixture(t)
	cal := folderByPath(t, f, "alice", "Calendar")
	responses := f.call(t, "alice",
		[]any{"Calendar/get", map[string]any{"accountId": "alice", "ids": []string{cal.ID}}, "cal"},
		[]any{"CalendarEvent/set", map[string]any{"accountId": "alice", "create": map[string]any{"e": meetingEvent(cal.ID)}}, "create"},
		[]any{"CalendarEvent/get", map[string]any{"accountId": "alice", "ids": []string{"#e"}}, "badref"},
	)
	if c := result(t, responses, "cal", "Calendar/get")["list"].([]any)[0].(map[string]any); c["isDefault"] != true || c["myRights"].(map[string]any)["mayWriteAll"] != true {
		t.Fatalf("calendar = %#v", c)
	}
	id := result(t, responses, "create", "CalendarEvent/set")["created"].(map[string]any)["e"].(map[string]any)["id"].(string)
	stored, err := f.space.GetItem(t.Context(), service.UserAccess("alice", "test"), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"RRULE:FREQ=DAILY;COUNT=5", "EXDATE;TZID=Europe/Copenhagen:20261103T090000", "RECURRENCE-ID;TZID=Europe/Copenhagen:20261104T090000", "BEGIN:VALARM"} {
		if !strings.Contains(string(stored.Data), want) {
			t.Fatalf("stored event lacks %q:\n%s", want, stored.Data)
		}
	}
	responses = f.call(t, "alice",
		[]any{"CalendarEvent/set", map[string]any{"accountId": "alice", "update": map[string]any{id: map[string]any{"recurrenceOverrides/2026-11-04T09:00:00/title": "Retro"}}}, "update"},
		[]any{"CalendarEvent/get", map[string]any{"accountId": "alice", "ids": []string{id}, "properties": []string{"title", "recurrenceOverrides"}}, "get"},
		[]any{"CalendarEvent/query", map[string]any{"accountId": "alice", "filter": map[string]any{"after": "2026-11-05T00:00:00Z", "before": "2026-11-06T00:00:00Z"}}, "inside"},
		[]any{"CalendarEvent/query", map[string]any{"accountId": "alice", "filter": map[string]any{"after": "2026-12-01T00:00:00Z"}}, "outside"},
		[]any{"CalendarEvent/query", map[string]any{"accountId": "alice", "filter": map[string]any{"title": "stand"}, "sort": []any{map[string]any{"property": "start", "isAscending": true}}}, "title"},
	)
	if len(result(t, responses, "update", "CalendarEvent/set")["updated"].(map[string]any)) != 1 {
		t.Fatalf("update = %#v", responses["update"])
	}
	event := result(t, responses, "get", "CalendarEvent/get")["list"].([]any)[0].(map[string]any)
	override := event["recurrenceOverrides"].(map[string]any)["2026-11-04T09:00:00"].(map[string]any)
	if override["title"] != "Retro" || override["duration"] != "PT45M" || event["title"] != "Standup" || event["start"] != nil {
		t.Fatalf("event = %#v", event)
	}
	if ids := result(t, responses, "inside", "CalendarEvent/query")["ids"].([]any); len(ids) != 1 {
		t.Fatalf("window query = %#v", ids)
	}
	if ids := result(t, responses, "outside", "CalendarEvent/query")["ids"].([]any); len(ids) != 0 {
		t.Fatalf("outside query = %#v", ids)
	}
	if ids := result(t, responses, "title", "CalendarEvent/query")["ids"].([]any); len(ids) != 1 {
		t.Fatalf("title query = %#v", ids)
	}
}

func TestCalendarSetCreatesRenamesAndDestroys(t *testing.T) {
	f := newFixture(t)
	state := result(t, f.call(t, "alice", []any{"Calendar/get", map[string]any{"accountId": "alice", "ids": []string{}}, "s"}), "s", "Calendar/get")["state"].(string)
	responses := f.call(t, "alice",
		[]any{"Calendar/set", map[string]any{"accountId": "alice", "create": map[string]any{"c": map[string]any{"name": "Travel", "color": "#ff0000"}}, "onSuccessSetIsDefault": "#c"}, "create"},
		[]any{"CalendarEvent/set", map[string]any{"accountId": "alice", "create": map[string]any{"e": map[string]any{"calendarIds": map[string]any{"#c": true}, "title": "Flight", "start": "2026-12-01T08:00:00", "timeZone": "Etc/UTC"}}}, "event"},
		[]any{"Calendar/changes", map[string]any{"accountId": "alice", "sinceState": state}, "changes"},
		[]any{"Calendar/set", map[string]any{"accountId": "alice", "update": map[string]any{"#c": map[string]any{"name": "Trips"}}}, "rename"},
		[]any{"Calendar/get", map[string]any{"accountId": "alice", "ids": []string{"#c"}}, "get"},
	)
	id := result(t, responses, "create", "Calendar/set")["created"].(map[string]any)["c"].(map[string]any)["id"].(string)
	if created := result(t, responses, "changes", "Calendar/changes")["created"].([]any); len(created) != 1 || created[0] != id {
		t.Fatalf("calendar changes = %#v", responses["changes"])
	}
	_ = result(t, responses, "event", "CalendarEvent/set")
	if got := result(t, responses, "get", "Calendar/get")["list"].([]any)[0].(map[string]any); got["name"] != "Trips" || got["isDefault"] != true || got["color"] != nil {
		t.Fatalf("calendar = %#v", got)
	}
	folder, err := f.space.GetFolder(t.Context(), service.UserAccess("alice", "test"), id)
	if err != nil || folder.Name != "Trips" || folder.SpecialUse != model.SpecialUseCalendar {
		t.Fatalf("folder = %#v err=%v", folder, err)
	}
	responses = f.call(t, "alice", []any{"Calendar/set", map[string]any{"accountId": "alice", "destroy": []string{id}}, "keep"})
	if result(t, responses, "keep", "Calendar/set")["notDestroyed"].(map[string]any)[id].(map[string]any)["type"] != "calendarHasEvent" {
		t.Fatalf("destroy = %#v", responses["keep"])
	}
}

func TestSharedCollectionsFollowFolderACL(t *testing.T) {
	f := newFixture(t)
	cal := folderByPath(t, f, "alice", "Calendar")
	book := folderByPath(t, f, "alice", "Contacts")
	share(t, f, cal, "bob", authz.RoleFolderViewer)
	share(t, f, book, "bob", authz.RoleFolderEditor)
	responses := f.call(t, "alice", []any{"CalendarEvent/set", map[string]any{"accountId": "alice", "create": map[string]any{"e": map[string]any{"calendarIds": map[string]any{cal.ID: true}, "title": "Shared", "start": "2026-11-10T10:00:00"}}}, "e"})
	eventID := result(t, responses, "e", "CalendarEvent/set")["created"].(map[string]any)["e"].(map[string]any)["id"].(string)

	session := decodeResponse(t, f.request(t, "GET", "/.well-known/jmap", "", "bob", "password"))
	account := session["accounts"].(map[string]any)["alice"].(map[string]any)
	capabilities := account["accountCapabilities"].(map[string]any)
	if account["isReadOnly"] != true || capabilities[CalendarsCapability] == nil || capabilities[ContactsCapability] == nil || capabilities[MailCapability] != nil {
		t.Fatalf("shared account = %#v", account)
	}
	state := result(t, f.call(t, "bob", []any{"CalendarEvent/get", map[string]any{"accountId": "alice", "ids": []string{}}, "s"}), "s", "CalendarEvent/get")["state"].(string)
	responses = f.call(t, "bob",
		[]any{"Calendar/get", map[string]any{"accountId": "alice"}, "cals"},
		[]any{"CalendarEvent/get", map[string]any{"accountId": "alice"}, "events"},
		[]any{"CalendarEvent/set", map[string]any{"accountId": "alice", "create": map[string]any{"x": map[string]any{"calendarIds": map[string]any{cal.ID: true}, "title": "Nope", "start": "2026-11-11T10:00:00"}}}, "write"},
		[]any{"AddressBook/get", map[string]any{"accountId": "alice"}, "books"},
		[]any{"ContactCard/set", map[string]any{"accountId": "alice", "create": map[string]any{"c": map[string]any{"addressBookIds": map[string]any{book.ID: true}, "name": map[string]any{"full": "From Bob"}}}}, "card"},
	)
	cals := result(t, responses, "cals", "Calendar/get")["list"].([]any)
	if len(cals) != 1 || cals[0].(map[string]any)["myRights"].(map[string]any)["mayWriteAll"] != false || cals[0].(map[string]any)["myRights"].(map[string]any)["mayReadItems"] != true {
		t.Fatalf("shared calendars = %#v", cals)
	}
	if events := result(t, responses, "events", "CalendarEvent/get")["list"].([]any); len(events) != 1 || events[0].(map[string]any)["id"] != eventID {
		t.Fatalf("shared events = %#v", events)
	}
	if notCreated := result(t, responses, "write", "CalendarEvent/set")["notCreated"].(map[string]any); notCreated["x"] == nil {
		t.Fatalf("viewer wrote an event: %#v", responses["write"])
	}
	books := result(t, responses, "books", "AddressBook/get")["list"].([]any)
	if len(books) != 1 || books[0].(map[string]any)["myRights"].(map[string]any)["mayWrite"] != true {
		t.Fatalf("shared books = %#v", books)
	}
	if created := result(t, responses, "card", "ContactCard/set")["created"].(map[string]any); created["c"] == nil {
		t.Fatalf("editor could not create: %#v", responses["card"])
	}
	// Alice's later change reaches bob through the owner's journal.
	f.call(t, "alice", []any{"CalendarEvent/set", map[string]any{"accountId": "alice", "update": map[string]any{eventID: map[string]any{"title": "Shared v2"}}}, "u"})
	changes := result(t, f.call(t, "bob", []any{"CalendarEvent/changes", map[string]any{"accountId": "alice", "sinceState": state}, "c"}), "c", "CalendarEvent/changes")
	if updated := changes["updated"].([]any); len(updated) != 1 || updated[0] != eventID {
		t.Fatalf("shared changes = %#v", changes)
	}
	unshared := f.call(t, "bob", []any{"CalendarEvent/get", map[string]any{"accountId": "nobody"}, "x"})
	if unshared["x"][0] != "error" {
		t.Fatalf("unknown account = %#v", unshared["x"])
	}
}

type sentIMIP struct {
	mu   sync.Mutex
	sent []imip.Outgoing
}

// method reports the iTIP method of a sent scheduling message.
func method(message imip.Outgoing) string {
	raw := string(message.Raw)
	if i := strings.Index(raw, "method="); i >= 0 {
		return strings.Fields(raw[i+len("method="):])[0]
	}
	return ""
}

func summarize(sent []imip.Outgoing) []string {
	var out []string
	for _, message := range sent {
		out = append(out, method(message)+" "+strings.Join(message.To, ","))
	}
	return out
}

func (s *sentIMIP) take() []imip.Outgoing {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.sent
	s.sent = nil
	return out
}

func TestOrganizerEventSavesScheduleAttendeesThroughIMIP(t *testing.T) {
	outbox := &sentIMIP{}
	f := buildFixture(t, func(ts *model.TypedStore, backend store.Store, base service.FolderSpace) service.FolderSpace {
		engine, err := rules.NewEngine(t.Context(), backend, base)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(engine.Close)
		space, err := rules.NewFolderSpace(base, engine)
		if err != nil {
			t.Fatal(err)
		}
		scheduler, err := imip.New(t.Context(), imip.Config{Space: space, Store: backend, Identity: ts.UserStore().GetEmailAddress,
			Resolve: func(ctx context.Context, address string) (model.RecipientRoute, error) {
				return ts.ResolveRecipient(ctx, address, "+")
			},
			Send: func(_ context.Context, message imip.Outgoing) error {
				outbox.mu.Lock()
				defer outbox.mu.Unlock()
				outbox.sent = append(outbox.sent, message)
				return nil
			}})
		if err != nil {
			t.Fatal(err)
		}
		space.SetItemObserver(scheduler)
		return space
	})
	cal := folderByPath(t, f, "alice", "Calendar")
	organizer := participantID("alice@example.test")
	event := map[string]any{"calendarIds": map[string]any{cal.ID: true}, "title": "Review", "start": "2026-11-20T13:00:00", "timeZone": "Europe/Copenhagen", "duration": "PT1H",
		"participants": map[string]any{
			organizer: map[string]any{"name": "Alice", "sendTo": map[string]any{"imip": "mailto:alice@example.test"}, "roles": map[string]any{"owner": true, "attendee": true}, "participationStatus": "accepted"},
			"carol":   map[string]any{"name": "Carol", "email": "carol@remote.test", "roles": map[string]any{"attendee": true}, "expectReply": true},
		}}
	responses := f.call(t, "alice", []any{"CalendarEvent/set", map[string]any{"accountId": "alice", "create": map[string]any{"e": event}}, "create"})
	id := result(t, responses, "create", "CalendarEvent/set")["created"].(map[string]any)["e"].(map[string]any)["id"].(string)
	sent := outbox.take()
	if got := summarize(sent); len(got) != 1 || got[0] != "REQUEST carol@remote.test" {
		t.Fatalf("invitation = %v", got)
	}
	f.call(t, "alice", []any{"CalendarEvent/set", map[string]any{"accountId": "alice", "update": map[string]any{id: map[string]any{
		"participants/dave": map[string]any{"email": "dave@remote.test", "roles": map[string]any{"attendee": true}}}}}, "add"})
	sent = outbox.take()
	if got := summarize(sent); len(got) != 1 || got[0] != "REQUEST dave@remote.test" {
		t.Fatalf("added attendee invitation = %v", got)
	}
	f.call(t, "alice", []any{"CalendarEvent/set", map[string]any{"accountId": "alice", "update": map[string]any{id: map[string]any{"start": "2026-11-20T15:00:00"}}}, "move"})
	sent = outbox.take()
	if got := summarize(sent); len(got) != 1 || len(sent[0].To) != 2 || method(sent[0]) != "REQUEST" {
		t.Fatalf("reschedule = %v", got)
	}
	stored, _ := f.space.GetItem(t.Context(), service.UserAccess("alice", "test"), id)
	if !strings.Contains(string(stored.Data), "SEQUENCE:1") {
		t.Fatalf("reschedule did not raise SEQUENCE:\n%s", stored.Data)
	}
	f.call(t, "alice", []any{"CalendarEvent/set", map[string]any{"accountId": "alice", "destroy": []string{id}}, "cancel"})
	if got := summarize(outbox.take()); len(got) != 1 || !strings.HasPrefix(got[0], "CANCEL ") {
		t.Fatalf("cancellation = %v", got)
	}
}

func TestEventSourcePushesTypeStateChanges(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", f.server.URL+"/jmap/eventsource?types=*&closeafter=no&ping=0", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("alice", "password")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	next := func() map[string]string {
		t.Helper()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if data, ok := strings.CutPrefix(strings.TrimSpace(line), "data: "); ok {
				var change stateChange
				if err := json.Unmarshal([]byte(data), &change); err != nil {
					t.Fatal(err)
				}
				return change.Changed["alice"]
			}
		}
	}
	initial := next()
	for _, name := range []string{"Mailbox", "Email", "ContactCard", "CalendarEvent", "AddressBook", "Calendar"} {
		if initial[name] == "" {
			t.Fatalf("initial state lacks %s: %#v", name, initial)
		}
	}
	book := folderByPath(t, f, "alice", "Contacts")
	responses := f.call(t, "alice", []any{"ContactCard/set", map[string]any{"accountId": "alice", "create": map[string]any{"c": map[string]any{"addressBookIds": map[string]any{book.ID: true}, "name": map[string]any{"full": "Pushed"}}}}, "c"})
	newState := result(t, responses, "c", "ContactCard/set")["newState"]
	changed := next()
	if changed["ContactCard"] != newState || changed["Email"] != "" || changed["CalendarEvent"] != "" {
		t.Fatalf("push = %#v (want ContactCard %v only)", changed, newState)
	}
}
