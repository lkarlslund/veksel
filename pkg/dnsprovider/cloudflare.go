package dnsprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// CloudflareAPI is the Cloudflare v4 API base URL.
const CloudflareAPI = "https://api.cloudflare.com/client/v4"

// Cloudflare manages records through the Cloudflare v4 API with a scoped API
// token (Zone:DNS:Edit). ZoneID is looked up from Zone when empty.
type Cloudflare struct {
	Zone    string
	ZoneID  string
	Token   string
	BaseURL string
	Client  *http.Client

	mu sync.Mutex
}

type cloudflareRecord struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl,omitempty"`
	Priority *int   `json:"priority,omitempty"`
}

type cloudflareEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (p *Cloudflare) call(ctx context.Context, method, path string, body, out any) error {
	base := strings.TrimRight(p.BaseURL, "/")
	if base == "" {
		base = CloudflareAPI
	}
	var envelope cloudflareEnvelope
	err := doJSON(ctx, p.Client, method, base+path, p.Token, body, &envelope)
	var status *httpStatusError
	if errors.As(err, &status) && json.Unmarshal([]byte(status.Body), &envelope) == nil && len(envelope.Errors) > 0 {
		err = nil
	}
	if err != nil {
		return err
	}
	if !envelope.Success {
		messages := make([]string, 0, len(envelope.Errors))
		for _, e := range envelope.Errors {
			messages = append(messages, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		return fmt.Errorf("cloudflare: %s", strings.Join(messages, "; "))
	}
	if out != nil && len(envelope.Result) > 0 {
		return json.Unmarshal(envelope.Result, out)
	}
	return nil
}

func (p *Cloudflare) zoneID(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ZoneID != "" {
		return p.ZoneID, nil
	}
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := p.call(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(NormalizeName(p.Zone)), nil, &zones); err != nil {
		return "", err
	}
	for _, zone := range zones {
		if NormalizeName(zone.Name) == NormalizeName(p.Zone) {
			p.ZoneID = zone.ID
			return zone.ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare: zone %s is not visible to this token", p.Zone)
}

func (p *Cloudflare) ListRecords(ctx context.Context, name, rtype string) ([]Record, error) {
	zone, err := p.zoneID(ctx)
	if err != nil {
		return nil, err
	}
	query := url.Values{"name": {NormalizeName(name)}, "type": {strings.ToUpper(rtype)}, "per_page": {"100"}}
	var listed []cloudflareRecord
	if err := p.call(ctx, http.MethodGet, "/zones/"+url.PathEscape(zone)+"/dns_records?"+query.Encode(), nil, &listed); err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(listed))
	for _, rec := range listed {
		value := rec.Content
		switch strings.ToUpper(rec.Type) {
		case "MX":
			if rec.Priority != nil {
				value = fmt.Sprintf("%d %s.", *rec.Priority, NormalizeName(rec.Content))
			}
		case "TXT":
			value = unquoteTXT(value)
		}
		out = append(out, Record{ID: rec.ID, Type: strings.ToUpper(rec.Type), Name: NormalizeName(rec.Name), Value: value, TTL: rec.TTL})
	}
	return out, nil
}

func (p *Cloudflare) UpsertRecord(ctx context.Context, rec Record) error {
	if err := validateRecord(p.Zone, rec); err != nil {
		return err
	}
	zone, err := p.zoneID(ctx)
	if err != nil {
		return err
	}
	body := cloudflareRecord{Type: strings.ToUpper(rec.Type), Name: NormalizeName(rec.Name), Content: rec.Value, TTL: ttlOrDefault(rec.TTL)}
	if body.Type == "MX" {
		preference, host, err := splitMX(rec.Value)
		if err != nil {
			return err
		}
		body.Content, body.Priority = host, &preference
	}
	path := "/zones/" + url.PathEscape(zone) + "/dns_records"
	if rec.ID != "" {
		return p.call(ctx, http.MethodPut, path+"/"+url.PathEscape(rec.ID), body, nil)
	}
	return p.call(ctx, http.MethodPost, path, body, nil)
}

func (p *Cloudflare) DeleteRecord(ctx context.Context, rec Record) error {
	zone, err := p.zoneID(ctx)
	if err != nil {
		return err
	}
	if rec.ID == "" {
		listed, err := p.ListRecords(ctx, rec.Name, rec.Type)
		if err != nil {
			return err
		}
		for _, candidate := range listed {
			if SameValue(rec.Type, candidate.Value, rec.Value) {
				rec.ID = candidate.ID
				break
			}
		}
		if rec.ID == "" {
			return nil
		}
	}
	return p.call(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zone)+"/dns_records/"+url.PathEscape(rec.ID), nil, nil)
}

// unquoteTXT joins quoted character strings ("a" "b") into one value and
// leaves unquoted content unchanged.
func unquoteTXT(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, `"`) {
		return value
	}
	var out strings.Builder
	inside, escaped := false, false
	for _, r := range value {
		switch {
		case escaped:
			out.WriteRune(r)
			escaped = false
		case inside && r == '\\':
			escaped = true
		case r == '"':
			inside = !inside
		case inside:
			out.WriteRune(r)
		}
	}
	return out.String()
}
