package contentscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const rspamdMaxResponseBytes = 1 << 20

// RspamdScanner implements Rspamd's HTTP /checkv2 protocol and controller
// learning endpoints without allowing redirects to forward its password.
type RspamdScanner struct {
	endpoint *url.URL
	password string
	client   *http.Client
}

var _ Trainer = (*RspamdScanner)(nil)

// NewRspamdScanner validates the endpoint once. A bare worker/controller URL
// receives the canonical /checkv2 path.
func NewRspamdScanner(endpoint, password string, client *http.Client) (*RspamdScanner, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return nil, errors.New("Rspamd endpoint must be an http(s) URL without user information")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Rspamd endpoint cannot contain a query or fragment")
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/checkv2"
	}
	if strings.ContainsAny(password, "\r\n\x00") || len(password) > 1024 {
		return nil, errors.New("invalid Rspamd password")
	}
	if client == nil {
		client = &http.Client{}
	}
	isolated := *client
	isolated.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &RspamdScanner{endpoint: parsed, password: password, client: &isolated}, nil
}

func (s *RspamdScanner) Name() string { return "rspamd" }

func (s *RspamdScanner) Scan(ctx context.Context, message Message) (Result, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), bytes.NewReader(message.Content))
	if err != nil {
		return Result{}, err
	}
	request.Header.Set("Content-Type", "message/rfc822")
	setSafeHeader(request.Header, "From", message.EnvelopeFrom)
	setSafeHeader(request.Header, "Deliver-To", message.Recipient)
	setSafeHeader(request.Header, "IP", message.RemoteIP)
	if s.password != "" {
		request.Header.Set("Password", s.password)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return Result{}, fmt.Errorf("Rspamd request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return Result{}, fmt.Errorf("Rspamd returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, rspamdMaxResponseBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("read Rspamd response: %w", err)
	}
	if len(body) > rspamdMaxResponseBytes {
		return Result{}, errors.New("Rspamd response exceeds limit")
	}
	var output rspamdResponse
	if err := json.Unmarshal(body, &output); err != nil {
		return Result{}, fmt.Errorf("decode Rspamd response: %w", err)
	}
	return output.result(), nil
}

// Learn sends a message to the controller's bounded learnspam/learnham
// endpoint. It is used by explicit quarantine training actions.
func (s *RspamdScanner) Learn(ctx context.Context, content []byte, spam bool) error {
	target := *s.endpoint
	if spam {
		target.Path = "/learnspam"
	} else {
		target.Path = "/learnham"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(content))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "message/rfc822")
	if s.password != "" {
		request.Header.Set("Password", s.password)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("Rspamd learning request: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Rspamd learning returned HTTP %d", response.StatusCode)
	}
	return nil
}

type rspamdResponse struct {
	Skipped       bool                    `json:"is_skipped"`
	Score         float64                 `json:"score"`
	RequiredScore float64                 `json:"required_score"`
	Action        string                  `json:"action"`
	Symbols       map[string]rspamdSymbol `json:"symbols"`
}

type rspamdSymbol struct {
	Name        string   `json:"name"`
	Score       float64  `json:"score"`
	Description string   `json:"description"`
	Options     []string `json:"options"`
}

func (r rspamdResponse) result() Result {
	result := Result{Verdict: VerdictClean, Score: r.Score, RequiredScore: r.RequiredScore}
	names := make([]string, 0, len(r.Symbols))
	for name := range r.Symbols {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, key := range names {
		symbol := r.Symbols[key]
		name := symbol.Name
		if name == "" {
			name = key
		}
		result.Symbols = append(result.Symbols, Symbol{Name: name, Score: symbol.Score, Description: symbol.Description})
		upper := strings.ToUpper(name)
		if strings.Contains(upper, "VIRUS") || strings.Contains(upper, "MALWARE") {
			result.Verdict = VerdictMalware
			if len(symbol.Options) == 0 {
				result.MalwareNames = append(result.MalwareNames, name)
			} else {
				result.MalwareNames = append(result.MalwareNames, symbol.Options...)
			}
		}
	}
	if result.Verdict != VerdictMalware && rspamdSpamAction(r.Action, r.Score, r.RequiredScore) {
		result.Verdict = VerdictSpam
	}
	return result
}

func rspamdSpamAction(action string, score, required float64) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "greylist", "add header", "rewrite subject", "soft reject", "reject":
		return true
	case "no action":
		return false
	default:
		return required > 0 && score >= required
	}
}

func setSafeHeader(headers http.Header, name, value string) {
	value = boundedText(value, maxEvidenceBytes)
	if value != "" {
		headers.Set(name, value)
	}
}
