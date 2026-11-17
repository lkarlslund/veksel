package dnsprovider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeCloudflare implements the subset of the Cloudflare v4 API the
// connector uses.
type fakeCloudflare struct {
	mu      sync.Mutex
	records map[string]cloudflareRecord
	next    int
	methods []string
}

func (f *fakeCloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(status int, result any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": status < 300, "errors": []any{}, "result": result})
	}
	if r.Header.Get("Authorization") != "Bearer cf-token" {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
		return
	}
	f.methods = append(f.methods, r.Method)
	switch {
	case r.URL.Path == "/zones":
		reply(200, []map[string]string{{"id": "zone-1", "name": r.URL.Query().Get("name")}})
	case r.URL.Path == "/zones/zone-1/dns_records" && r.Method == http.MethodGet:
		var out []cloudflareRecord
		for _, rec := range f.records {
			if rec.Name == r.URL.Query().Get("name") && rec.Type == r.URL.Query().Get("type") {
				out = append(out, rec)
			}
		}
		reply(200, out)
	case r.URL.Path == "/zones/zone-1/dns_records" && r.Method == http.MethodPost:
		var rec cloudflareRecord
		_ = json.NewDecoder(r.Body).Decode(&rec)
		f.next++
		rec.ID = fmt.Sprintf("rec-%d", f.next)
		f.records[rec.ID] = rec
		reply(200, rec)
	case strings.HasPrefix(r.URL.Path, "/zones/zone-1/dns_records/"):
		id := strings.TrimPrefix(r.URL.Path, "/zones/zone-1/dns_records/")
		if _, ok := f.records[id]; !ok {
			reply(404, nil)
			return
		}
		if r.Method == http.MethodDelete {
			delete(f.records, id)
			reply(200, map[string]string{"id": id})
			return
		}
		var rec cloudflareRecord
		_ = json.NewDecoder(r.Body).Decode(&rec)
		rec.ID = id
		f.records[id] = rec
		reply(200, rec)
	default:
		reply(404, nil)
	}
}

func TestCloudflareClientAgainstFakeAPI(t *testing.T) {
	fake := &fakeCloudflare{records: map[string]cloudflareRecord{
		"pre": {ID: "pre", Type: "TXT", Name: "example.test", Content: `"v=spf1 mx" " -all"`, TTL: 1},
	}}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	provider := &Cloudflare{Zone: "example.test", Token: "cf-token", BaseURL: server.URL, Client: server.Client()}
	ctx := t.Context()

	txt, err := provider.ListRecords(ctx, "example.test", "TXT")
	if err != nil || len(txt) != 1 || txt[0].Value != "v=spf1 mx -all" || txt[0].ID != "pre" {
		t.Fatalf("quoted TXT content: %+v %v", txt, err)
	}
	if err := provider.UpsertRecord(ctx, Record{Type: "MX", Name: "example.test", Value: "10 mail.example.test."}); err != nil {
		t.Fatal(err)
	}
	var created cloudflareRecord
	for _, rec := range fake.records {
		if rec.Type == "MX" {
			created = rec
		}
	}
	if created.Content != "mail.example.test" || created.Priority == nil || *created.Priority != 10 || created.TTL != DefaultTTL {
		t.Fatalf("MX body must split priority from content: %+v", created)
	}
	mx, err := provider.ListRecords(ctx, "example.test", "MX")
	if err != nil || len(mx) != 1 || mx[0].Value != "10 mail.example.test." {
		t.Fatalf("listed MX: %+v %v", mx, err)
	}
	txt[0].Value = "v=spf1 mx ~all"
	if err := provider.UpsertRecord(ctx, txt[0]); err != nil {
		t.Fatal(err)
	}
	if fake.records["pre"].Content != "v=spf1 mx ~all" || fake.methods[len(fake.methods)-1] != http.MethodPut {
		t.Fatalf("update must PUT the listed record: %+v %v", fake.records["pre"], fake.methods)
	}
	if err := provider.DeleteRecord(ctx, Record{Type: "MX", Name: "example.test", Value: "10 mail.example.test"}); err != nil {
		t.Fatal(err)
	}
	if mx, _ := provider.ListRecords(ctx, "example.test", "MX"); len(mx) != 0 {
		t.Fatalf("delete by value left %v", mx)
	}

	bad := &Cloudflare{Zone: "example.test", ZoneID: "zone-1", Token: "wrong-secret-token", BaseURL: server.URL, Client: server.Client()}
	_, err = bad.ListRecords(ctx, "example.test", "TXT")
	if err == nil || !strings.Contains(err.Error(), "Authentication error") || strings.Contains(err.Error(), "wrong-secret-token") {
		t.Fatalf("auth failure must surface the API error without the token: %v", err)
	}
}

func TestWebhookConnectorContract(t *testing.T) {
	var calls []webhookRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer hook-token" {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet {
			if r.URL.Query().Get("zone") != "example.test" || r.URL.Query().Get("type") != "TXT" {
				http.Error(w, "bad query", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"records":[{"id":"7","type":"txt","name":"Example.Test.","value":"v=spf1 -all"}]}`))
			return
		}
		var request webhookRequest
		_ = json.NewDecoder(r.Body).Decode(&request)
		calls = append(calls, request)
	}))
	t.Cleanup(server.Close)
	provider := &Webhook{Zone: "example.test", URL: server.URL, Token: "hook-token", Client: server.Client()}
	records, err := provider.ListRecords(t.Context(), "example.test", "TXT")
	if err != nil || len(records) != 1 || records[0].Name != "example.test" || records[0].Type != "TXT" {
		t.Fatalf("listing: %+v %v", records, err)
	}
	records[0].Value = "v=spf1 mx -all"
	if err := provider.UpsertRecord(t.Context(), records[0]); err != nil {
		t.Fatal(err)
	}
	if err := provider.DeleteRecord(t.Context(), records[0]); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0].Action != "upsert" || calls[0].Record.ID != "7" || calls[0].Record.TTL != DefaultTTL || calls[1].Action != "delete" {
		t.Fatalf("calls: %+v", calls)
	}
	if err := (&Webhook{Zone: "example.test", URL: server.URL, Client: server.Client()}).UpsertRecord(t.Context(), records[0]); err == nil {
		t.Fatal("unauthorized call succeeded")
	}
}
