package jmap

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// Regression tests from the RFC 8620/8621 conformance audit.

// jmap runs one request and returns its method responses in order.
func (f *fixture) jmap(t *testing.T, user string, calls ...[]any) [][]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{"using": []string{CoreCapability, MailCapability, SubmissionCapability, VacationCapability}, "methodCalls": calls})
	if err != nil {
		t.Fatal(err)
	}
	response := decodeResponse(t, f.request(t, "POST", "/jmap/api", string(body), user, "password"))
	var out [][]any
	for _, raw := range response["methodResponses"].([]any) {
		out = append(out, raw.([]any))
	}
	return out
}

// one runs a single method call as alice and returns its response.
func (f *fixture) one(t *testing.T, name string, args map[string]any) []any {
	t.Helper()
	return f.jmap(t, "alice", []any{name, args, "0"})[0]
}

func args(t *testing.T, invocation []any, name string) map[string]any {
	t.Helper()
	if invocation[0] != name {
		t.Fatalf("expected %s, got %#v", name, invocation)
	}
	return invocation[1].(map[string]any)
}

func errorType(invocation []any) string {
	if invocation[0] != "error" {
		return ""
	}
	return invocation[1].(map[string]any)["type"].(string)
}

func (f *fixture) storeMail(t *testing.T, folder, raw string, received time.Time, flags ...string) string {
	t.Helper()
	item, err := f.space.CreateItem(t.Context(), service.UserAccess("alice", "test"), folderByPath(t, f, "alice", folder).ID,
		service.ItemInput{Data: []byte(raw), Flags: flags, InternalDate: received})
	if err != nil {
		t.Fatal(err)
	}
	return item.ID
}

func TestSessionPlacesMailLimitsInAccountCapabilities(t *testing.T) {
	f := newFixture(t)
	session := decodeResponse(t, f.request(t, "GET", "/.well-known/jmap", "", "alice", "password"))
	caps := session["capabilities"].(map[string]any)
	if len(caps[MailCapability].(map[string]any)) != 0 || len(caps[SubmissionCapability].(map[string]any)) != 0 {
		t.Fatalf("session-level mail capabilities must be empty: %#v", caps)
	}
	account := session["accounts"].(map[string]any)["alice"].(map[string]any)["accountCapabilities"].(map[string]any)
	mail := account[MailCapability].(map[string]any)
	if mail["maxMailboxesPerEmail"] != float64(1) || mail["emailQuerySortOptions"] == nil {
		t.Fatalf("account mail capability = %#v", mail)
	}
	if _, ok := account[SubmissionCapability].(map[string]any)["maxDelayedSend"]; !ok {
		t.Fatalf("account submission capability = %#v", account[SubmissionCapability])
	}
	for _, variable := range []string{"{accountId}", "{blobId}", "{type}", "{name}"} {
		if !strings.Contains(session["downloadUrl"].(string), variable) {
			t.Fatalf("downloadUrl %q lacks %s", session["downloadUrl"], variable)
		}
	}
}

func TestRequestLevelErrors(t *testing.T) {
	f := newFixture(t)
	problem := func(body string) map[string]any {
		t.Helper()
		response := f.request(t, "POST", "/jmap/api", body, "alice", "password")
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: status %d", body, response.StatusCode)
		}
		return decodeResponse(t, response)
	}
	if got := problem(`{nope`)["type"]; got != "urn:ietf:params:jmap:error:notJSON" {
		t.Fatalf("invalid JSON = %v", got)
	}
	for _, body := range []string{`{"foo":1}`, `[]`, `{"using":"x","methodCalls":[]}`, `{"using":[],"methodCalls":[["Core/echo",{}]]}`} {
		if got := problem(body)["type"]; got != "urn:ietf:params:jmap:error:notRequest" {
			t.Fatalf("%s = %v", body, got)
		}
	}
	calls := make([]string, 65)
	for i := range calls {
		calls[i] = `["Core/echo",{},"c"]`
	}
	limit := problem(`{"using":[],"methodCalls":[` + strings.Join(calls, ",") + `]}`)
	if limit["type"] != "urn:ietf:params:jmap:error:limit" || limit["limit"] != "maxCallsInRequest" {
		t.Fatalf("call limit = %#v", limit)
	}
	big := problem(`{"using":[],"methodCalls":[["Core/echo",{"x":"` + strings.Repeat("a", maxRequestSize) + `"},"c"]]}`)
	if big["type"] != "urn:ietf:params:jmap:error:limit" || big["limit"] != "maxSizeRequest" {
		t.Fatalf("size limit = %#v", big)
	}
	// A method whose capability is missing from using is unknown.
	v := decodeResponse(t, f.request(t, "POST", "/jmap/api", `{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Mailbox/get",{"accountId":"alice"},"m"]]}`, "alice", "password"))
	if got := errorType(v["methodResponses"].([]any)[0].([]any)); got != "unknownMethod" {
		t.Fatalf("Mailbox/get without mail capability = %q", got)
	}
}

func TestResultReferenceWildcardFlattensAndCreationIDs(t *testing.T) {
	f := newFixture(t)
	root := f.storeMail(t, "INBOX", "Subject: one\r\nMessage-ID: <r@x>\r\n\r\nbody", time.Unix(1000, 0))
	reply := f.storeMail(t, "INBOX", "Subject: Re: one\r\nMessage-ID: <s@x>\r\nIn-Reply-To: <r@x>\r\nReferences: <r@x>\r\n\r\nbody", time.Unix(2000, 0))
	responses := f.jmap(t, "alice",
		[]any{"Email/get", map[string]any{"accountId": "alice", "ids": []string{reply}, "properties": []string{"threadId"}}, "g"},
		[]any{"Thread/get", map[string]any{"accountId": "alice", "#ids": map[string]any{"resultOf": "g", "name": "Email/get", "path": "/list/*/threadId"}}, "t"},
		[]any{"Email/get", map[string]any{"accountId": "alice", "#ids": map[string]any{"resultOf": "t", "name": "Thread/get", "path": "/list/*/emailIds"}, "properties": []string{"subject"}}, "e"},
		[]any{"Email/get", map[string]any{"accountId": "alice", "ids": []string{}, "#ids": map[string]any{"resultOf": "t", "name": "Thread/get", "path": "/list/*/emailIds"}}, "x"},
	)
	thread := args(t, responses[1], "Thread/get")["list"].([]any)
	if len(thread) != 1 || len(thread[0].(map[string]any)["emailIds"].([]any)) != 2 || thread[0].(map[string]any)["emailIds"].([]any)[0] != root {
		t.Fatalf("thread = %#v", thread)
	}
	if got := args(t, responses[2], "Email/get")["list"].([]any); len(got) != 2 {
		t.Fatalf("flattened emailIds fetched %d emails", len(got))
	}
	if errorType(responses[3]) != "invalidArguments" {
		t.Fatalf("ids and #ids together = %#v", responses[3])
	}
	inbox := folderByPath(t, f, "alice", "INBOX").ID
	// jmapc and Fastmail clients nest references inside the filter.
	nested := f.jmap(t, "alice",
		[]any{"Mailbox/query", map[string]any{"accountId": "alice", "filter": map[string]any{"role": "inbox"}}, "m"},
		[]any{"Email/query", map[string]any{"accountId": "alice", "filter": map[string]any{"#inMailbox": map[string]any{"resultOf": "m", "name": "Mailbox/query", "path": "/ids/0"}}}, "q"},
	)
	if got := args(t, nested[1], "Email/query")["ids"].([]any); len(got) != 2 {
		t.Fatalf("nested filter reference = %#v", nested[1])
	}
	created := f.jmap(t, "alice",
		[]any{"Email/set", map[string]any{"accountId": "alice", "create": map[string]any{"n": map[string]any{"mailboxIds": map[string]bool{inbox: true}, "subject": "new"}}}, "s"},
		[]any{"Email/get", map[string]any{"accountId": "alice", "ids": []string{"#n"}, "properties": []string{"subject"}}, "g"},
	)
	if list := args(t, created[1], "Email/get")["list"].([]any); len(list) != 1 || list[0].(map[string]any)["subject"] != "new" {
		t.Fatalf("#creation id in ids = %#v", created[1])
	}
}

const alternativeMessage = "From: =?utf-8?q?J=C3=B8rgen?= <jorgen@example.org>\r\n" +
	"To: Alice <alice@example.test>, Team: bob@example.test, carol@example.test;\r\n" +
	"Subject: =?iso-8859-1?q?R=E6kke?=\r\n" +
	"Date: Tue, 15 Aug 2023 14:12:00 +0200\r\n" +
	"List-Post: <mailto:list@example.org>\r\n" +
	"X-Folded: first\r\n second\r\n" +
	"Content-Type: multipart/mixed; boundary=outer\r\n\r\n" +
	"--outer\r\nContent-Type: multipart/alternative; boundary=alt\r\n\r\n" +
	"--alt\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nHej R=E6kke\r\n" +
	"--alt\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nPHA+SGVqIDxiPlLDpmtrZTwvYj48L3A+\r\n" +
	"--alt--\r\n" +
	"--outer\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"doc.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n" +
	"--outer--\r\n"

func TestEmailGetPropertiesHeaderFormsAndBodyStructure(t *testing.T) {
	f := newFixture(t)
	id := f.storeMail(t, "INBOX", alternativeMessage, time.Date(2023, 8, 15, 12, 13, 0, 0, time.UTC))
	email := args(t, f.one(t, "Email/get", map[string]any{"accountId": "alice", "ids": []string{id, "missing"}, "fetchTextBodyValues": true, "fetchHTMLBodyValues": true}), "Email/get")
	if notFound := email["notFound"].([]any); len(notFound) != 1 || notFound[0] != "missing" {
		t.Fatalf("notFound = %#v", email["notFound"])
	}
	e := email["list"].([]any)[0].(map[string]any)
	if _, ok := e["headers"]; ok {
		t.Fatal("headers is not a default property")
	}
	if e["subject"] != "Række" || e["sentAt"] != "2023-08-15T14:12:00+02:00" || e["receivedAt"] != "2023-08-15T12:13:00Z" || e["sender"] != nil {
		t.Fatalf("convenience headers = %v %v %v %v", e["subject"], e["sentAt"], e["receivedAt"], e["sender"])
	}
	if from := e["from"].([]any)[0].(map[string]any); from["name"] != "Jørgen" {
		t.Fatalf("from = %#v", from)
	}
	if to := e["to"].([]any); len(to) != 3 {
		t.Fatalf("to must flatten the group: %#v", to)
	}
	text, html := e["textBody"].([]any)[0].(map[string]any), e["htmlBody"].([]any)[0].(map[string]any)
	if text["type"] != "text/plain" || html["type"] != "text/html" || len(e["attachments"].([]any)) != 1 || e["hasAttachment"] != true {
		t.Fatalf("body lists text=%v html=%v attachments=%v", text, html, e["attachments"])
	}
	values := e["bodyValues"].(map[string]any)
	if values[text["partId"].(string)].(map[string]any)["value"] != "Hej Række" || values[html["partId"].(string)].(map[string]any)["value"] != "<p>Hej <b>Række</b></p>" {
		t.Fatalf("decoded body values = %#v", values)
	}
	if attachment := e["attachments"].([]any)[0].(map[string]any); attachment["size"] != float64(9) || attachment["name"] != "doc.pdf" {
		t.Fatalf("attachment = %#v", attachment)
	}

	props := []string{"header:Subject", "header:Subject:asText", "header:To:asGroupedAddresses", "header:List-Post:asURLs", "header:X-Folded",
		"header:X-Folded:asText", "header:X-Missing", "header:X-Missing:all", "bodyStructure"}
	e = args(t, f.one(t, "Email/get", map[string]any{"accountId": "alice", "ids": []string{id}, "properties": props, "bodyProperties": []string{"type", "partId"}}), "Email/get")["list"].([]any)[0].(map[string]any)
	if len(e) != len(props)+1 {
		t.Fatalf("properties not filtered: %#v", e)
	}
	if e["header:Subject"] != " =?iso-8859-1?q?R=E6kke?=" || e["header:Subject:asText"] != "Række" || e["header:X-Folded"] != " first\r\n second" || e["header:X-Folded:asText"] != "first second" {
		t.Fatalf("raw/text forms = %#v", e)
	}
	groups := e["header:To:asGroupedAddresses"].([]any)
	if len(groups) != 2 || groups[0].(map[string]any)["name"] != nil || groups[1].(map[string]any)["name"] != "Team" || len(groups[1].(map[string]any)["addresses"].([]any)) != 2 {
		t.Fatalf("grouped addresses = %#v", groups)
	}
	if urls := e["header:List-Post:asURLs"].([]any); len(urls) != 1 || urls[0] != "mailto:list@example.org" {
		t.Fatalf("urls = %#v", urls)
	}
	if e["header:X-Missing"] != nil || len(e["header:X-Missing:all"].([]any)) != 0 {
		t.Fatalf("missing header forms = %#v %#v", e["header:X-Missing"], e["header:X-Missing:all"])
	}
	structure := e["bodyStructure"].(map[string]any)
	if structure["type"] != "multipart/mixed" || structure["partId"] != nil || len(structure["subParts"].([]any)) != 2 {
		t.Fatalf("bodyStructure = %#v", structure)
	}
	for _, bad := range []string{"header:From:asDate", "nope"} {
		if got := errorType(f.one(t, "Email/get", map[string]any{"accountId": "alice", "ids": []string{id}, "properties": []string{bad}})); got != "invalidArguments" {
			t.Fatalf("property %s = %q", bad, got)
		}
	}
}

func TestBodyListsFollowRFC8621Algorithm(t *testing.T) {
	htmlOnly := "Content-Type: text/html\r\n\r\n<p>only <i>html</i></p>"
	v := newEmailView(model.Item{ID: "i"}, "i", []byte(htmlOnly))
	if len(v.text) != 1 || v.text[0].mediaType != "text/html" || len(v.html) != 1 || v.preview() != "only html" {
		t.Fatalf("html-only text=%v html=%v preview=%q", v.text, v.html, v.preview())
	}
	related := "Content-Type: multipart/related; boundary=r\r\n\r\n--r\r\nContent-Type: text/html\r\n\r\n<img src=cid:a>\r\n--r\r\nContent-Type: image/png\r\nContent-ID: <a>\r\nContent-Disposition: inline\r\n\r\nPNG\r\n--r--\r\n"
	v = newEmailView(model.Item{ID: "i"}, "i", []byte(related))
	if len(v.html) != 1 || len(v.attachments) != 1 || v.hasAttachment() {
		t.Fatalf("related html=%v attachments=%v hasAttachment=%v", v.html, v.attachments, v.hasAttachment())
	}
	textOnlyAlternative := "Content-Type: multipart/alternative; boundary=a\r\n\r\n--a\r\nContent-Type: text/plain\r\n\r\nplain\r\n--a--\r\n"
	v = newEmailView(model.Item{ID: "i"}, "i", []byte(textOnlyAlternative))
	if len(v.html) != 1 || v.html[0].mediaType != "text/plain" {
		t.Fatalf("alternative without html must reuse the text part: %v", v.html)
	}
}

func TestEmailSetCreatesMIMEAndAppliesPatchPaths(t *testing.T) {
	f := newFixture(t)
	f.storeMail(t, "INBOX", "Subject: parent\r\nMessage-ID: <p@x>\r\n\r\nbody", time.Unix(1000, 0))
	upload := f.request(t, "POST", "/jmap/upload/alice", "attached bytes", "alice", "password")
	if upload.StatusCode != http.StatusCreated {
		t.Fatalf("upload status = %d", upload.StatusCode)
	}
	blob := decodeResponse(t, upload)["blobId"].(string)
	drafts, trash, inbox := folderByPath(t, f, "alice", "Drafts").ID, folderByPath(t, f, "alice", "Trash").ID, folderByPath(t, f, "alice", "INBOX").ID
	set := args(t, f.one(t, "Email/set", map[string]any{"accountId": "alice", "create": map[string]any{"d": map[string]any{
		"mailboxIds": map[string]bool{drafts: true}, "keywords": map[string]bool{"$draft": true, "$seen": true},
		"from": []any{map[string]any{"name": "Alice Å", "email": "alice@example.test"}}, "to": []any{map[string]any{"email": "bob@example.test"}},
		"subject": "Draft ✓", "inReplyTo": []string{"p@x"}, "references": []string{"p@x"}, "sentAt": "2024-01-02T03:04:05+01:00",
		"header:X-Client:asText": "tests", "bodyValues": map[string]any{"t": map[string]any{"value": "plain ✓"}, "h": map[string]any{"value": "<p>html</p>"}},
		"textBody": []any{map[string]any{"partId": "t"}}, "htmlBody": []any{map[string]any{"partId": "h", "type": "text/html"}},
		"attachments": []any{map[string]any{"blobId": blob, "type": "text/x-notes", "name": "notes ✓.txt"}},
	}}}), "Email/set")
	created := set["created"].(map[string]any)["d"].(map[string]any)
	id := created["id"].(string)
	got := args(t, f.one(t, "Email/get", map[string]any{"accountId": "alice", "ids": []string{id}, "fetchAllBodyValues": true,
		"properties": []string{"subject", "from", "sentAt", "threadId", "messageId", "keywords", "attachments", "textBody", "htmlBody", "header:X-Client:asText", "header:Date", "bodyValues"}}), "Email/get")["list"].([]any)[0].(map[string]any)
	if got["subject"] != "Draft ✓" || got["sentAt"] != "2024-01-02T03:04:05+01:00" || got["header:X-Client:asText"] != "tests" || got["messageId"] == nil {
		t.Fatalf("created headers = %#v", got)
	}
	if got["header:Date"] != " Tue, 02 Jan 2024 03:04:05 +0100" {
		t.Fatalf("Date must be RFC 5322: %q", got["header:Date"])
	}
	if got["threadId"] != created["threadId"] || got["from"].([]any)[0].(map[string]any)["name"] != "Alice Å" {
		t.Fatalf("threadId/from = %#v", got)
	}
	attachment := got["attachments"].([]any)[0].(map[string]any)
	if attachment["name"] != "notes ✓.txt" || attachment["type"] != "text/x-notes" || attachment["size"] != float64(len("attached bytes")) {
		t.Fatalf("attachment = %#v", attachment)
	}
	if len(got["textBody"].([]any)) != 1 || len(got["htmlBody"].([]any)) != 1 {
		t.Fatalf("bodies = %#v %#v", got["textBody"], got["htmlBody"])
	}

	update := func(patch map[string]any) map[string]any {
		return args(t, f.one(t, "Email/set", map[string]any{"accountId": "alice", "update": map[string]any{id: patch}}), "Email/set")
	}
	if r := update(map[string]any{"keywords/$flagged": true, "keywords/$seen": nil}); r["updated"].(map[string]any)[id] != nil || len(r["notUpdated"].(map[string]any)) != 0 {
		t.Fatalf("keyword patch = %#v", r)
	}
	if r := update(map[string]any{"mailboxIds/" + drafts: nil, "mailboxIds/" + trash: true}); len(r["notUpdated"].(map[string]any)) != 0 {
		t.Fatalf("mailbox patch = %#v", r)
	}
	after := args(t, f.one(t, "Email/get", map[string]any{"accountId": "alice", "ids": []string{id}, "properties": []string{"keywords", "mailboxIds"}}), "Email/get")["list"].([]any)[0].(map[string]any)
	if len(after["keywords"].(map[string]any)) != 2 || after["keywords"].(map[string]any)["$flagged"] != true || after["mailboxIds"].(map[string]any)[trash] != true {
		t.Fatalf("after patches = %#v", after)
	}
	for _, patch := range []map[string]any{{"mailboxIds/" + inbox: true}, {"subject": "x"}, {"keywords/bad word": true}} {
		if r := update(patch); r["notUpdated"].(map[string]any)[id].(map[string]any)["type"] != "invalidProperties" {
			t.Fatalf("patch %v = %#v", patch, r)
		}
	}
	bad := args(t, f.one(t, "Email/set", map[string]any{"accountId": "alice", "create": map[string]any{
		"a": map[string]any{"mailboxIds": map[string]bool{inbox: true}, "attachments": []any{map[string]any{"blobId": "nope"}}},
		"b": map[string]any{"mailboxIds": map[string]bool{inbox: true}, "id": "forced"},
		"c": map[string]any{"mailboxIds": map[string]bool{inbox: true, drafts: true}},
	}, "destroy": []string{"nope"}}), "Email/set")
	notCreated := bad["notCreated"].(map[string]any)
	if notCreated["a"].(map[string]any)["type"] != "blobNotFound" || notCreated["b"].(map[string]any)["type"] != "invalidProperties" || notCreated["c"].(map[string]any)["type"] != "invalidProperties" {
		t.Fatalf("notCreated = %#v", notCreated)
	}
	if bad["notDestroyed"].(map[string]any)["nope"].(map[string]any)["type"] != "notFound" {
		t.Fatalf("notDestroyed = %#v", bad["notDestroyed"])
	}
}

func TestEmailQueryPagingSortingAndThreads(t *testing.T) {
	f := newFixture(t)
	a := f.storeMail(t, "INBOX", "Subject: alpha\r\nMessage-ID: <a@x>\r\n\r\nshort", time.Unix(1000, 0), model.FlagSeen)
	b := f.storeMail(t, "INBOX", "Subject: Re: alpha\r\nMessage-ID: <b@x>\r\nIn-Reply-To: <a@x>\r\n\r\nlonger body text", time.Unix(2000, 0))
	c := f.storeMail(t, "INBOX", "Subject: gamma\r\nMessage-ID: <c@x>\r\n\r\nbody", time.Unix(3000, 0))
	ids := func(r []any) []any { return args(t, r, "Email/query")["ids"].([]any) }
	same := func(got []any, want ...string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range want {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}
	if got := ids(f.one(t, "Email/query", map[string]any{"accountId": "alice", "sort": []any{map[string]any{"property": "receivedAt"}}})); !same(got, a, b, c) {
		t.Fatalf("isAscending must default to true: %v", got)
	}
	if got := ids(f.one(t, "Email/query", map[string]any{"accountId": "alice", "collapseThreads": true, "sort": []any{map[string]any{"property": "receivedAt", "isAscending": false}}})); !same(got, c, b) {
		t.Fatalf("collapseThreads = %v", got)
	}
	r := args(t, f.one(t, "Email/query", map[string]any{"accountId": "alice", "sort": []any{map[string]any{"property": "receivedAt"}}, "anchor": c, "anchorOffset": -1, "limit": 1}), "Email/query")
	if !same(r["ids"].([]any), b) || r["position"] != float64(1) {
		t.Fatalf("anchor = %#v", r)
	}
	r = args(t, f.one(t, "Email/query", map[string]any{"accountId": "alice", "sort": []any{map[string]any{"property": "receivedAt"}}, "position": -1}), "Email/query")
	if !same(r["ids"].([]any), c) || r["position"] != float64(2) {
		t.Fatalf("negative position = %#v", r)
	}
	if got := ids(f.one(t, "Email/query", map[string]any{"accountId": "alice", "filter": map[string]any{"operator": "NOT", "conditions": []any{map[string]any{"subject": "gamma"}, map[string]any{"hasKeyword": "$seen"}}}})); !same(got, b) {
		t.Fatalf("NOT over two conditions = %v", got)
	}
	if got := ids(f.one(t, "Email/query", map[string]any{"accountId": "alice", "filter": map[string]any{"someInThreadHaveKeyword": "$seen"}, "sort": []any{map[string]any{"property": "receivedAt"}}})); !same(got, a, b) {
		t.Fatalf("someInThreadHaveKeyword = %v", got)
	}
	if got := ids(f.one(t, "Email/query", map[string]any{"accountId": "alice", "filter": map[string]any{"after": "1970-01-01T00:30:00Z"}, "sort": []any{map[string]any{"property": "size", "isAscending": false}}})); !same(got, b, c) {
		t.Fatalf("after + size sort = %v", got)
	}
	if got := errorType(f.one(t, "Email/query", map[string]any{"accountId": "alice", "anchor": "nope"})); got != "anchorNotFound" {
		t.Fatalf("anchor not found = %q", got)
	}
	if got := errorType(f.one(t, "Email/query", map[string]any{"accountId": "alice", "filter": map[string]any{"bogus": true}})); got != "unsupportedFilter" {
		t.Fatalf("unknown filter = %q", got)
	}
	if got := errorType(f.one(t, "Email/query", map[string]any{"accountId": "alice", "sort": []any{map[string]any{"property": "bogus"}}})); got != "unsupportedSort" {
		t.Fatalf("unknown sort = %q", got)
	}

	before := args(t, f.one(t, "Email/query", map[string]any{"accountId": "alice", "filter": map[string]any{"inMailbox": folderByPath(t, f, "alice", "INBOX").ID}}), "Email/query")
	if before["canCalculateChanges"] != true {
		t.Fatalf("canCalculateChanges = %v", before["canCalculateChanges"])
	}
	d := f.storeMail(t, "INBOX", "Subject: delta\r\n\r\nbody", time.Unix(4000, 0))
	changes := args(t, f.one(t, "Email/queryChanges", map[string]any{"accountId": "alice", "filter": map[string]any{"inMailbox": folderByPath(t, f, "alice", "INBOX").ID}, "sinceQueryState": before["queryState"]}), "Email/queryChanges")
	added := changes["added"].([]any)
	if len(added) != 1 || added[0].(map[string]any)["id"] != d || added[0].(map[string]any)["index"] != float64(0) {
		t.Fatalf("queryChanges = %#v", changes)
	}
}

type recordingSubmitter struct {
	mu      sync.Mutex
	options []service.RawSubmissionOptions
}

func (r *recordingSubmitter) SubmitRawWithOptions(_ context.Context, _ model.PrincipalRef, _ []byte, options service.RawSubmissionOptions) (service.SubmissionResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.options = append(r.options, options)
	return service.SubmissionResult{ID: "sub-1", AcceptedAt: time.Unix(5000, 0)}, nil
}

func TestEmailSubmissionOnSuccessUpdateEmailIsImplicitEmailSet(t *testing.T) {
	f := newFixture(t)
	submitter := &recordingSubmitter{}
	f.handler.cfg.Submitter = submitter
	drafts, sent := folderByPath(t, f, "alice", "Drafts").ID, folderByPath(t, f, "alice", "Sent").ID
	responses := f.jmap(t, "alice",
		[]any{"Email/set", map[string]any{"accountId": "alice", "create": map[string]any{"m": map[string]any{"mailboxIds": map[string]bool{drafts: true}, "keywords": map[string]bool{"$draft": true},
			"from": []any{map[string]any{"email": "alice@example.test"}}, "to": []any{map[string]any{"email": "bob@example.test"}}, "subject": "hi"}}}, "a"},
		[]any{"EmailSubmission/set", map[string]any{"accountId": "alice", "create": map[string]any{"s": map[string]any{"identityId": "alice@example.test", "emailId": "#m"}},
			"onSuccessUpdateEmail": map[string]any{"#s": map[string]any{"mailboxIds/" + drafts: nil, "mailboxIds/" + sent: true, "keywords/$draft": nil}}}, "b"},
	)
	if len(responses) != 3 || responses[2][0] != "Email/set" || responses[2][2] != "b" {
		t.Fatalf("responses = %#v", responses)
	}
	submission := args(t, responses[1], "EmailSubmission/set")["created"].(map[string]any)["s"].(map[string]any)
	if submission["id"] != "sub-1" || submission["undoStatus"] != "final" {
		t.Fatalf("submission = %#v", submission)
	}
	emailID := args(t, responses[0], "Email/set")["created"].(map[string]any)["m"].(map[string]any)["id"].(string)
	if _, ok := args(t, responses[2], "Email/set")["updated"].(map[string]any)[emailID]; !ok {
		t.Fatalf("implicit Email/set = %#v", responses[2])
	}
	moved := args(t, f.one(t, "Email/get", map[string]any{"accountId": "alice", "ids": []string{emailID}, "properties": []string{"mailboxIds", "keywords"}}), "Email/get")["list"].([]any)[0].(map[string]any)
	if moved["mailboxIds"].(map[string]any)[sent] != true || len(moved["keywords"].(map[string]any)) != 0 {
		t.Fatalf("draft after send = %#v", moved)
	}
	if len(submitter.options) != 1 || !submitter.options[0].SkipSentCopy {
		t.Fatalf("a client-filed send must skip the automatic Sent copy: %#v", submitter.options)
	}
	if got := args(t, f.one(t, "EmailSubmission/get", map[string]any{"accountId": "alice", "ids": []string{"sub-1"}}), "EmailSubmission/get")["list"].([]any); len(got) != 1 {
		t.Fatalf("EmailSubmission/get = %#v", got)
	}
	wrongFrom := f.storeMail(t, "Drafts", "From: someone@else.test\r\nTo: bob@example.test\r\nSubject: x\r\n\r\nbody", time.Now())
	r := args(t, f.one(t, "EmailSubmission/set", map[string]any{"accountId": "alice", "create": map[string]any{"x": map[string]any{"identityId": "alice@example.test", "emailId": wrongFrom}}}), "EmailSubmission/set")
	if r["notCreated"].(map[string]any)["x"].(map[string]any)["type"] != "forbiddenFrom" {
		t.Fatalf("wrong From = %#v", r)
	}
}

func TestMailboxQueryFiltersAndSetOrdersParents(t *testing.T) {
	f := newFixture(t)
	inbox := folderByPath(t, f, "alice", "INBOX").ID
	query := args(t, f.one(t, "Mailbox/query", map[string]any{"accountId": "alice", "filter": map[string]any{"role": "inbox"}}), "Mailbox/query")
	if ids := query["ids"].([]any); len(ids) != 1 || ids[0] != inbox {
		t.Fatalf("role filter = %#v", query)
	}
	got := args(t, f.one(t, "Mailbox/get", map[string]any{"accountId": "alice", "ids": []string{inbox}, "properties": []string{"name"}}), "Mailbox/get")["list"].([]any)[0].(map[string]any)
	if len(got) != 2 {
		t.Fatalf("Mailbox/get properties = %#v", got)
	}
	// The child sorts before its parent; the parent must still be made first.
	set := args(t, f.one(t, "Mailbox/set", map[string]any{"accountId": "alice", "create": map[string]any{
		"a-child": map[string]any{"name": "Child", "parentId": "#z-parent"}, "z-parent": map[string]any{"name": "Parent"},
		"dup": map[string]any{"name": "INBOX"},
	}}), "Mailbox/set")
	created := set["created"].(map[string]any)
	if len(created) != 2 || created["a-child"].(map[string]any)["myRights"] == nil {
		t.Fatalf("created = %#v notCreated = %#v", created, set["notCreated"])
	}
	if set["notCreated"].(map[string]any)["dup"].(map[string]any)["type"] != "invalidProperties" {
		t.Fatalf("duplicate sibling name = %#v", set["notCreated"])
	}
	parent := created["z-parent"].(map[string]any)["id"].(string)
	f.storeMail(t, "INBOX", "Subject: keep\r\n\r\nbody", time.Now())
	destroy := args(t, f.one(t, "Mailbox/set", map[string]any{"accountId": "alice", "destroy": []string{parent}}), "Mailbox/set")
	if destroy["notDestroyed"].(map[string]any)[parent].(map[string]any)["type"] != "mailboxHasChild" {
		t.Fatalf("destroy parent = %#v", destroy)
	}
	custom, err := f.space.CreateFolder(t.Context(), service.UserAccess("alice", "test"), "Full", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	f.storeMail(t, "Full", "Subject: x\r\n\r\nbody", time.Now())
	destroy = args(t, f.one(t, "Mailbox/set", map[string]any{"accountId": "alice", "destroy": []string{custom.ID}}), "Mailbox/set")
	if destroy["notDestroyed"].(map[string]any)[custom.ID].(map[string]any)["type"] != "mailboxHasEmail" {
		t.Fatalf("destroy non-empty = %#v", destroy)
	}
}

func TestDownloadDecodesPartsAndHonoursType(t *testing.T) {
	f := newFixture(t)
	id := f.storeMail(t, "INBOX", alternativeMessage, time.Now())
	attachment := args(t, f.one(t, "Email/get", map[string]any{"accountId": "alice", "ids": []string{id}, "properties": []string{"attachments"}}), "Email/get")["list"].([]any)[0].(map[string]any)["attachments"].([]any)[0].(map[string]any)
	response := f.request(t, "GET", "/jmap/download/alice/"+attachment["blobId"].(string)+"/doc.pdf?accept=application/pdf", "", "alice", "password")
	data, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(data) != "%PDF-1.4\n" || response.Header.Get("Content-Type") != "application/pdf" {
		t.Fatalf("download %q type %q", data, response.Header.Get("Content-Type"))
	}
}

func TestIdentityGetWithoutAddressesIsEmpty(t *testing.T) {
	f := newFixture(t)
	r := f.jmap(t, "bob", []any{"Identity/get", map[string]any{"accountId": "bob"}, "i"})[0]
	if list := args(t, r, "Identity/get")["list"].([]any); len(list) != 0 {
		t.Fatalf("identities = %#v", list)
	}
}

func TestPushSubscriptionVerifiesAndSendsEncryptedStateChanges(t *testing.T) {
	f := newFixture(t)
	received := make(chan []byte, 8)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("TTL") == "" || r.Header.Get("Content-Encoding") != "aes128gcm" {
			t.Errorf("push headers = %v", r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		received <- body
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	f.handler.pushClient = server.Client()
	uaPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	_, _ = rand.Read(auth)
	keys := map[string]string{"p256dh": base64.RawURLEncoding.EncodeToString(uaPrivate.PublicKey().Bytes()), "auth": base64.RawURLEncoding.EncodeToString(auth)}
	set := args(t, f.one(t, "PushSubscription/set", map[string]any{"create": map[string]any{"p": map[string]any{"deviceClientId": "dev", "url": server.URL, "keys": keys, "types": []string{"Email"}}}}), "PushSubscription/set")
	id := set["created"].(map[string]any)["p"].(map[string]any)["id"].(string)
	next := func() map[string]any {
		t.Helper()
		select {
		case body := <-received:
			var message map[string]any
			if err := json.Unmarshal(decryptPush(t, uaPrivate, auth, body), &message); err != nil {
				t.Fatal(err)
			}
			return message
		case <-time.After(5 * time.Second):
			t.Fatal("no push delivered")
			return nil
		}
	}
	verification := next()
	if verification["@type"] != "PushVerification" || verification["pushSubscriptionId"] != id {
		t.Fatalf("verification = %#v", verification)
	}
	listed := args(t, f.one(t, "PushSubscription/get", map[string]any{"ids": nil}), "PushSubscription/get")["list"].([]any)[0].(map[string]any)
	if _, leaked := listed["url"]; leaked || listed["verificationCode"] != nil {
		t.Fatalf("PushSubscription/get must hide url and the unconfirmed code: %#v", listed)
	}
	f.one(t, "PushSubscription/set", map[string]any{"update": map[string]any{id: map[string]any{"verificationCode": verification["verificationCode"]}}})
	time.Sleep(100 * time.Millisecond)
	f.storeMail(t, "INBOX", "Subject: pushed\r\n\r\nbody", time.Now())
	change := next()
	if change["@type"] != "StateChange" || change["changed"].(map[string]any)["alice"].(map[string]any)["Email"] == nil {
		t.Fatalf("state change = %#v", change)
	}
	if r := args(t, f.one(t, "PushSubscription/set", map[string]any{"create": map[string]any{"bad": map[string]any{"deviceClientId": "d", "url": "http://insecure.test/"}}}), "PushSubscription/set"); r["notCreated"].(map[string]any)["bad"] == nil {
		t.Fatalf("plain http push url accepted: %#v", r)
	}
	f.one(t, "PushSubscription/set", map[string]any{"destroy": []string{id}})
}

// decryptPush reverses RFC 8291 encryption as a user agent would.
func decryptPush(t *testing.T, uaPrivate *ecdh.PrivateKey, auth, body []byte) []byte {
	t.Helper()
	salt, keyLength := body[:16], int(body[20])
	asPublicBytes := body[21 : 21+keyLength]
	asPublic, err := ecdh.P256().NewPublicKey(asPublicBytes)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := uaPrivate.ECDH(asPublic)
	if err != nil {
		t.Fatal(err)
	}
	info := append(append([]byte("WebPush: info\x00"), uaPrivate.PublicKey().Bytes()...), asPublicBytes...)
	ikm, _ := hkdf.Key(sha256.New, shared, auth, string(info), 32)
	cek, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, nonce, body[21+keyLength:], nil)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(plain, []byte{0x02})
}
