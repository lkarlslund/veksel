package mtasts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"golang.org/x/sync/singleflight"
)

const (
	SourceNone  = "none"
	SourceLive  = "live"
	SourceCache = "cache"

	FailureDNS        = "dns"
	FailureTXTInvalid = "txt-invalid"
	FailureHTTPS      = "https"
	FailurePolicy     = "policy-invalid"
)

// TXTResolver is the DNS capability needed for MTA-STS discovery.
type TXTResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

// Options controls bounded discovery. Zero values select conservative RFC
// 8461 defaults suitable for production use.
type Options struct {
	Resolver        TXTResolver
	HTTPClient      *http.Client
	Now             func() time.Time
	FetchTimeout    time.Duration
	RefreshInterval time.Duration
	FailureRetry    time.Duration
}

// Failure describes a discovery problem without making delivery fail when no
// valid cached policy exists. It is also the input for TLS-RPT aggregation.
type Failure struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Result is the policy decision for one delivery attempt.
type Result struct {
	Policy  *Policy  `json:"policy,omitempty"`
	Source  string   `json:"source"`
	Failure *Failure `json:"failure,omitempty"`
}

// CacheEntry is durable policy and refresh state for one policy domain.
type CacheEntry struct {
	Domain         string    `json:"domain"`
	Policy         *Policy   `json:"policy,omitempty"`
	PolicyID       string    `json:"policy_id,omitempty"`
	FetchedAt      time.Time `json:"fetched_at,omitzero"`
	ExpiresAt      time.Time `json:"expires_at,omitzero"`
	LastCheckedAt  time.Time `json:"last_checked_at,omitzero"`
	LastFailure    *Failure  `json:"last_failure,omitempty"`
	FailedPolicyID string    `json:"failed_policy_id,omitempty"`
	RetryAfter     time.Time `json:"retry_after,omitzero"`
}

// Service owns policy discovery and the durable system cache.
type Service struct {
	store           store.Store
	resolver        TXTResolver
	client          *http.Client
	now             func() time.Time
	fetchTimeout    time.Duration
	refreshInterval time.Duration
	failureRetry    time.Duration
	group           singleflight.Group
}

// New creates an MTA-STS service and ensures its system namespace exists.
func New(ctx context.Context, backend store.Store, options Options) (*Service, error) {
	if backend == nil {
		return nil, errors.New("MTA-STS store is required")
	}
	exists, err := backend.NamespaceExists(ctx, model.NSMTASTSPolicies)
	if err != nil {
		return nil, fmt.Errorf("inspect MTA-STS namespace: %w", err)
	}
	if !exists {
		if err := backend.CreateNamespace(ctx, model.NSMTASTSPolicies); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, fmt.Errorf("create MTA-STS namespace: %w", err)
		}
	}
	resolver := options.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	client := &http.Client{}
	if options.HTTPClient != nil {
		clone := *options.HTTPClient
		client = &clone
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	if options.FetchTimeout <= 0 {
		options.FetchTimeout = time.Minute
	}
	if options.RefreshInterval <= 0 {
		options.RefreshInterval = 24 * time.Hour
	}
	if options.FailureRetry <= 0 {
		options.FailureRetry = 5 * time.Minute
	}
	return &Service{store: backend, resolver: resolver, client: client, now: now,
		fetchTimeout: options.FetchTimeout, refreshInterval: options.RefreshInterval, failureRetry: options.FailureRetry}, nil
}

// Resolve returns the currently applicable policy. Valid cached policies are
// retained across DNS and HTTPS failures; an unavailable first policy does not
// block ordinary opportunistic delivery.
func (s *Service) Resolve(ctx context.Context, domain string) (Result, error) {
	domain, err := CanonicalDomain(domain)
	if err != nil {
		return Result{Source: SourceNone}, nil
	}
	value, err, _ := s.group.Do(domain, func() (any, error) {
		return s.resolve(ctx, domain, false)
	})
	if err != nil {
		return Result{}, err
	}
	return value.(Result), nil
}

// Refresh performs an unconditional DNS policy-id check. It is intended for
// administration and the pre-expiry maintenance loop.
func (s *Service) Refresh(ctx context.Context, domain string) (Result, error) {
	domain, err := CanonicalDomain(domain)
	if err != nil {
		return Result{}, err
	}
	return s.resolve(ctx, domain, true)
}

// List returns durable policy-cache status without network access.
func (s *Service) List(ctx context.Context) ([]CacheEntry, error) {
	entries := make([]CacheEntry, 0)
	err := s.store.Iterate(ctx, model.NSMTASTSPolicies, "", func(_ string, value []byte) (bool, error) {
		var entry CacheEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			return false, fmt.Errorf("decode MTA-STS cache entry: %w", err)
		}
		entries = append(entries, entry)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Domain < entries[j].Domain })
	return entries, nil
}

// Prune deletes status entries whose policies and failure retry windows have
// both expired before the supplied cutoff.
func (s *Service) Prune(ctx context.Context, before time.Time) (int, error) {
	entries, err := s.List(ctx)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		if entry.ExpiresAt.After(before) || entry.RetryAfter.After(before) || entry.LastCheckedAt.After(before) {
			continue
		}
		if err := s.store.Delete(ctx, model.NSMTASTSPolicies, entry.Domain); err != nil && !errors.Is(err, store.ErrNotFound) {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func (s *Service) resolve(ctx context.Context, domain string, force bool) (Result, error) {
	now := s.now().UTC()
	entry, found, err := s.load(ctx, domain)
	if err != nil {
		return Result{}, fmt.Errorf("read MTA-STS cache for %s: %w", domain, err)
	}
	validCache := found && entry.Policy != nil && !entry.ExpiresAt.Before(now)
	if validCache && !force && !entry.LastCheckedAt.IsZero() && now.Sub(entry.LastCheckedAt) < s.refreshInterval {
		return cachedResult(entry, nil), nil
	}

	records, lookupErr := s.resolver.LookupTXT(ctx, "_mta-sts."+domain)
	if lookupErr != nil {
		var dnsError *net.DNSError
		if errors.As(lookupErr, &dnsError) && dnsError.IsNotFound {
			records = nil
		} else {
			return s.recordFailure(ctx, entry, domain, validCache, FailureDNS, lookupErr.Error(), "", now)
		}
	}
	policyID, available, policyIDErr := PolicyID(records)
	if policyIDErr != nil {
		return s.recordFailure(ctx, entry, domain, validCache, FailureTXTInvalid, policyIDErr.Error(), "", now)
	}
	if !available {
		entry.Domain = domain
		entry.LastCheckedAt = now
		entry.LastFailure = nil
		entry.FailedPolicyID = ""
		entry.RetryAfter = time.Time{}
		if err := s.save(ctx, entry); err != nil {
			return Result{}, err
		}
		if validCache {
			return cachedResult(entry, nil), nil
		}
		return Result{Source: SourceNone}, nil
	}
	if validCache && entry.PolicyID == policyID {
		entry.LastCheckedAt = now
		entry.LastFailure = nil
		entry.FailedPolicyID = ""
		entry.RetryAfter = time.Time{}
		if err := s.save(ctx, entry); err != nil {
			return Result{}, err
		}
		return cachedResult(entry, nil), nil
	}
	if entry.FailedPolicyID == policyID && now.Before(entry.RetryAfter) {
		if validCache {
			return cachedResult(entry, entry.LastFailure), nil
		}
		return Result{Source: SourceNone, Failure: entry.LastFailure}, nil
	}

	policy, fetchErr := s.fetch(ctx, domain)
	if fetchErr != nil {
		failureType := FailureHTTPS
		var invalidPolicy *invalidPolicyError
		if errors.As(fetchErr, &invalidPolicy) {
			failureType = FailurePolicy
		}
		return s.recordFailure(ctx, entry, domain, validCache, failureType, fetchErr.Error(), policyID, now)
	}
	policy.PolicyDomain = domain
	policy.PolicyID = policyID
	entry = CacheEntry{Domain: domain, Policy: &policy, PolicyID: policyID, FetchedAt: now,
		ExpiresAt: now.Add(time.Duration(policy.MaxAge) * time.Second), LastCheckedAt: now}
	if err := s.save(ctx, entry); err != nil {
		return Result{}, err
	}
	return Result{Policy: &policy, Source: SourceLive}, nil
}

func (s *Service) fetch(ctx context.Context, domain string) (Policy, error) {
	requestCtx, cancel := context.WithTimeout(ctx, s.fetchTimeout)
	defer cancel()
	url := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, url, nil)
	if err != nil {
		return Policy{}, err
	}
	request.Header.Set("Accept", "text/plain")
	response, err := s.client.Do(request)
	if err != nil {
		return Policy{}, fmt.Errorf("fetch MTA-STS policy: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Policy{}, fmt.Errorf("fetch MTA-STS policy: HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "text/plain") {
		return Policy{}, errors.New("fetch MTA-STS policy: response is not text/plain")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPolicyBytes+1))
	if err != nil {
		return Policy{}, fmt.Errorf("read MTA-STS policy: %w", err)
	}
	if len(body) > maxPolicyBytes {
		return Policy{}, fmt.Errorf("fetch MTA-STS policy: response exceeds %d bytes", maxPolicyBytes)
	}
	policy, err := ParsePolicy(body)
	if err != nil {
		return Policy{}, &invalidPolicyError{err: err}
	}
	return policy, nil
}

func (s *Service) load(ctx context.Context, domain string) (CacheEntry, bool, error) {
	data, err := s.store.Get(ctx, model.NSMTASTSPolicies, domain)
	if errors.Is(err, store.ErrNotFound) {
		return CacheEntry{Domain: domain}, false, nil
	}
	if err != nil {
		return CacheEntry{}, false, err
	}
	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return CacheEntry{}, false, err
	}
	if entry.Domain != domain {
		return CacheEntry{}, false, errors.New("cache key does not match policy domain")
	}
	return entry, true, nil
}

func (s *Service) save(ctx context.Context, entry CacheEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err := s.store.Set(ctx, model.NSMTASTSPolicies, entry.Domain, data); err != nil {
		return fmt.Errorf("store MTA-STS cache for %s: %w", entry.Domain, err)
	}
	return nil
}

func (s *Service) recordFailure(ctx context.Context, entry CacheEntry, domain string, validCache bool, failureType, message, policyID string, now time.Time) (Result, error) {
	failure := &Failure{Type: failureType, Message: boundedMessage(message)}
	entry.Domain = domain
	entry.LastCheckedAt = now
	entry.LastFailure = failure
	entry.FailedPolicyID = policyID
	entry.RetryAfter = now.Add(s.failureRetry)
	if err := s.save(ctx, entry); err != nil {
		return Result{}, err
	}
	if validCache {
		return cachedResult(entry, failure), nil
	}
	return Result{Source: SourceNone, Failure: failure}, nil
}

func cachedResult(entry CacheEntry, failure *Failure) Result {
	policy := *entry.Policy
	return Result{Policy: &policy, Source: SourceCache, Failure: failure}
}

func boundedMessage(message string) string {
	message = strings.TrimSpace(message)
	const maximum = 512
	if len(message) > maximum {
		return message[:maximum]
	}
	return message
}

type invalidPolicyError struct{ err error }

func (e *invalidPolicyError) Error() string { return "invalid MTA-STS policy: " + e.err.Error() }
func (e *invalidPolicyError) Unwrap() error { return e.err }
