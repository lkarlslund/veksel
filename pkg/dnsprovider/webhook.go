package dnsprovider

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// Webhook is the generic connector: any DNS service can be bridged by a
// small HTTP endpoint implementing three JSON calls, authorized with an
// optional bearer token.
//
//	GET  URL?zone=Z&name=N&type=T        -> {"records": [Record, ...]}
//	POST URL {"action":"upsert","zone":Z,"record":Record}
//	POST URL {"action":"delete","zone":Z,"record":Record}
//
// Record IDs returned by the listing are passed back unchanged.
type Webhook struct {
	Zone   string
	URL    string
	Token  string
	Client *http.Client
}

type webhookRequest struct {
	Action string `json:"action"`
	Zone   string `json:"zone"`
	Record Record `json:"record"`
}

func (p *Webhook) ListRecords(ctx context.Context, name, rtype string) ([]Record, error) {
	query := url.Values{"zone": {NormalizeName(p.Zone)}, "name": {NormalizeName(name)}, "type": {strings.ToUpper(rtype)}}
	separator := "?"
	if strings.Contains(p.URL, "?") {
		separator = "&"
	}
	var reply struct {
		Records []Record `json:"records"`
	}
	if err := doJSON(ctx, p.Client, http.MethodGet, p.URL+separator+query.Encode(), p.Token, nil, &reply); err != nil {
		return nil, err
	}
	for i := range reply.Records {
		reply.Records[i].Name = NormalizeName(reply.Records[i].Name)
		reply.Records[i].Type = strings.ToUpper(reply.Records[i].Type)
	}
	return reply.Records, nil
}

func (p *Webhook) UpsertRecord(ctx context.Context, rec Record) error {
	if err := validateRecord(p.Zone, rec); err != nil {
		return err
	}
	rec.TTL = ttlOrDefault(rec.TTL)
	return doJSON(ctx, p.Client, http.MethodPost, p.URL, p.Token, webhookRequest{Action: "upsert", Zone: NormalizeName(p.Zone), Record: rec}, nil)
}

func (p *Webhook) DeleteRecord(ctx context.Context, rec Record) error {
	return doJSON(ctx, p.Client, http.MethodPost, p.URL, p.Token, webhookRequest{Action: "delete", Zone: NormalizeName(p.Zone), Record: rec}, nil)
}
