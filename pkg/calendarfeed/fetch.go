package calendarfeed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/lkarlslund/veksel/pkg/netguard"
)

const maxRedirects = 5

// ErrForbiddenAddress means a feed resolves only to addresses that
// subscriptions may not reach.
var ErrForbiddenAddress = netguard.ErrForbiddenAddress

// FetchResult is one completed feed request.
type FetchResult struct {
	Body         []byte
	NotModified  bool
	ETag         string
	LastModified string
}

// Fetcher downloads feeds with bounded size and time. Each connection goes
// to an address checked when the host was resolved, so later DNS answers
// cannot redirect the request, and every redirect is checked again.
type Fetcher struct {
	// AllowPrivate reports whether private and loopback addresses are
	// permitted; nil refuses them.
	AllowPrivate func() bool
	MaxBytes     int64
	Timeout      time.Duration
	// Resolver looks hosts up; nil uses net.DefaultResolver.
	Resolver netguard.Resolver
}

// Fetch requests rawURL, conditionally on etag and lastModified.
func (f *Fetcher) Fetch(ctx context.Context, rawURL, etag, lastModified string) (FetchResult, error) {
	ctx, cancel := context.WithTimeout(ctx, f.Timeout)
	defer cancel()
	target, err := url.Parse(rawURL)
	if err != nil {
		return FetchResult{}, fmt.Errorf("invalid feed URL: %w", err)
	}
	for redirect := 0; ; redirect++ {
		response, err := f.request(ctx, target, etag, lastModified)
		if err != nil {
			return FetchResult{}, err
		}
		switch {
		case response.StatusCode >= 300 && response.StatusCode < 400 && response.StatusCode != http.StatusNotModified:
			location := response.Header.Get("Location")
			_ = response.Body.Close()
			if location == "" || redirect >= maxRedirects {
				return FetchResult{}, fmt.Errorf("the feed redirects too often or without a location (HTTP %d)", response.StatusCode)
			}
			next, err := target.Parse(location)
			if err != nil || (next.Scheme != "https" && next.Scheme != "http") {
				return FetchResult{}, errors.New("the feed redirects to an unsupported location")
			}
			target = next
			continue
		case response.StatusCode == http.StatusNotModified:
			_ = response.Body.Close()
			return FetchResult{NotModified: true}, nil
		case response.StatusCode != http.StatusOK:
			_ = response.Body.Close()
			return FetchResult{}, fmt.Errorf("the feed server answered HTTP %d", response.StatusCode)
		}
		defer func() { _ = response.Body.Close() }()
		if response.ContentLength > f.MaxBytes {
			return FetchResult{}, fmt.Errorf("the feed is larger than %d MiB", f.MaxBytes>>20)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, f.MaxBytes+1))
		if err != nil {
			return FetchResult{}, fmt.Errorf("download the feed: %w", err)
		}
		if int64(len(body)) > f.MaxBytes {
			return FetchResult{}, fmt.Errorf("the feed is larger than %d MiB", f.MaxBytes>>20)
		}
		return FetchResult{Body: body, ETag: response.Header.Get("ETag"), LastModified: response.Header.Get("Last-Modified")}, nil
	}
}

func (f *Fetcher) request(ctx context.Context, target *url.URL, etag, lastModified string) (*http.Response, error) {
	transport := (&netguard.Dialer{AllowPrivate: f.AllowPrivate, Resolver: f.Resolver}).Transport()
	transport.ResponseHeaderTimeout = 20 * time.Second
	transport.DisableKeepAlives = true
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "text/calendar, application/calendar+json;q=0.1, */*;q=0.1")
	request.Header.Set("User-Agent", "Veksel calendar subscription")
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		request.Header.Set("If-Modified-Since", lastModified)
	}
	response, err := client.Do(request)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("fetch the feed: %w", err)
	}
	return response, nil
}
