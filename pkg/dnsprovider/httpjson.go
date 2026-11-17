package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lkarlslund/veksel/pkg/netguard"
)

// providerTimeout bounds every provider API call.
const providerTimeout = 30 * time.Second

// defaultHTTPClient serves providers built without a client; it never
// reaches private networks.
var defaultHTTPClient = (&netguard.Dialer{}).Client(providerTimeout)

// doJSON sends an optional JSON body with a bearer token and decodes a JSON
// reply into out. Non-2xx statuses become errors carrying a bounded excerpt
// of the reply, never the request or its credential.
func doJSON(ctx context.Context, client *http.Client, method, url, token string, body, out any) error {
	if client == nil {
		client = defaultHTTPClient
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		excerpt := string(payload)
		if len(excerpt) > 300 {
			excerpt = excerpt[:300]
		}
		return &httpStatusError{Status: response.StatusCode, Body: excerpt}
	}
	if out == nil || len(bytes.TrimSpace(payload)) == 0 {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("decode %s %s reply: %w", method, request.URL.Path, err)
	}
	return nil
}

type httpStatusError struct {
	Status int
	Body   string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("provider API answered HTTP %d: %s", e.Status, e.Body)
}
