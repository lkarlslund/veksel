package jmap

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
)

// FuzzRequest decodes JMAP API request bodies the way the API endpoint does
// and runs each invocation through decoding, back-reference resolution and
// filter decoding.
func FuzzRequest(f *testing.F) {
	for _, seed := range []string{
		`{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/query",{"accountId":"a","filter":{"operator":"AND","conditions":[{"from":"x"},{"hasKeyword":"$seen"}]}},"0"],["Email/get",{"accountId":"a","#ids":{"resultOf":"0","name":"Email/query","path":"/ids/*"}},"1"]]}`,
		`{"using":[],"methodCalls":[["Mailbox/get",{},"t"]],"createdIds":{"k":"v"}}`,
		`{"methodCalls":[[1,2,3]]}`,
		`{"methodCalls":[["x",{"#a":{"resultOf":"t","name":"x","path":"/~0~1"}},"t"]]}`,
		`{"unknown":1}`,
		`[`, ``, `null`,
	} {
		f.Add(seed)
	}
	prior := map[string][]methodResult{
		"0": {{name: "Email/query", value: map[string]any{"ids": []string{"a", "b"}, "nested": map[string]any{"list": []any{1, "x"}}}}},
	}
	f.Fuzz(func(t *testing.T, input string) {
		request, err := decodeRequest([]byte(input))
		if err != nil {
			return
		}
		for _, call := range request.MethodCalls {
			_, args, _, ok := decodeInvocation(call)
			if !ok {
				continue
			}
			resolved, refErr := resolveReferences(args, prior)
			if refErr != nil {
				continue
			}
			var arguments map[string]json.RawMessage
			if json.Unmarshal(resolved, &arguments) == nil {
				if filter, ok := arguments["filter"]; ok {
					_, _ = decodeFilter(filter)
				}
			}
		}
	})
}

// FuzzObjectConversion converts arbitrary stored messages, vCards and
// iCalendar events into their JMAP objects, and converts decoded contacts
// back to vCard.
func FuzzObjectConversion(f *testing.F) {
	for _, seed := range []string{
		"BEGIN:VCARD\r\nVERSION:4.0\r\nUID:urn:uuid:1\r\nFN:Jane\r\nN:Doe;Jane;;;\r\nEMAIL;TYPE=work;PREF=1:jane@example.com\r\nTEL;VALUE=uri:tel:+1-555\r\nBDAY:--0415\r\nPHOTO:data:image/png;base64,iVBORw0KGgo=\r\nADR;LABEL=\"1 Main\\nTown\":;;1 Main;Town;;;\r\nEND:VCARD\r\n",
		"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:e\r\nDTSTART;TZID=Europe/Copenhagen:20240101T090000\r\nDURATION:P1DT2H\r\nRRULE:FREQ=MONTHLY;BYDAY=-1FR;UNTIL=20241231T000000Z\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:a@b\r\nBEGIN:VALARM\r\nTRIGGER;RELATED=END:-PT5M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
		"Subject: hi\r\nFrom: A <a@b>\r\nContent-Type: multipart/alternative; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nplain\r\n--x\r\nContent-Type: text/html\r\n\r\n<p>html</p>\r\n--x--\r\n",
		"", "\x00",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		data := []byte(input)
		item := model.Item{ID: "i", FolderID: "f", Data: data, Size: int64(len(data)), InternalDate: time.Unix(0, 0)}
		view := newEmailView(item, item.ID, data)
		all := append(append([]string{}, defaultEmailProperties...), "headers", "bodyStructure", "header:From:asAddresses:all", "header:To:asGroupedAddresses",
			"header:Date:asDate", "header:Message-ID:asMessageIds", "header:List-Post:asURLs", "header:Subject:asText", "header:X-Any")
		_ = view.object(emailOptions{properties: all, bodyProperties: append(append([]string{}, defaultBodyProperties...), "headers", "header:Content-Type"), fetchAll: true, maxBytes: 256})
		if part := view.root.find("1.1"); part != nil {
			_, _ = part.text()
		}
		if doc, err := parseVCard(data); err == nil {
			card, _ := decodeContact(doc, "i")
			if encoded, err := encodeContact(card, doc, "i", func(string) ([]byte, string, error) { return nil, "", errors.New("no blobs") }); err == nil {
				if _, err := parseVCard(encoded.encode()); err != nil && !bytes.Contains(data, []byte("\x00")) {
					t.Logf("re-encoded card does not parse: %v", err)
				}
			}
		}
		if cal, err := calendar.Decode(data); err == nil {
			_, _ = decodeCalendarEvent(cal)
		}
		_, _ = parseDuration(input)
		_, _ = parseVCardDate(input)
	})
}
