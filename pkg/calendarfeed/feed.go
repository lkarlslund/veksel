// Package calendarfeed keeps per-user calendar subscriptions: external
// webcal/https iCalendar feeds fetched on a schedule and shown as read-only
// calendars, and the per-user calendar settings (the Birthdays calendar
// toggle). Fetches are bounded in size and time, use conditional requests,
// and refuse private network destinations unless an administrator allows
// them; the resolved address is pinned for the connection so a DNS answer
// cannot change between the check and the request.
package calendarfeed

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/calendarport"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

var logger = log.For(log.ModuleCalDAV)

const (
	// MaxSubscriptionsPerUser bounds one account's subscriptions.
	MaxSubscriptionsPerUser = 25
	// MaxFeedBytes bounds one downloaded feed.
	MaxFeedBytes = 8 << 20
	// FetchTimeout bounds one download, redirects included.
	FetchTimeout = 30 * time.Second
	// errorRetry is how soon a failed feed is tried again (at most its
	// own interval).
	errorRetry = 30 * time.Minute

	maxNameLength = 120
	maxURLLength  = 2048
)

// Interval is a subscription's refresh schedule.
type Interval string

const (
	Hourly Interval = "hourly"
	Daily  Interval = "daily"
)

func (i Interval) duration() time.Duration {
	if i == Hourly {
		return time.Hour
	}
	return 24 * time.Hour
}

// Subscription is one external calendar feed.
type Subscription struct {
	ID       string   `json:"id"`
	UserID   string   `json:"user_id"`
	Name     string   `json:"name"`
	URL      string   `json:"url"`
	Color    string   `json:"color,omitempty"`
	Interval Interval `json:"interval"`
	// Refresh state. LastError is shown on the calendar until a refresh
	// succeeds.
	LastAttempt  time.Time `json:"last_attempt,omitzero"`
	LastSuccess  time.Time `json:"last_success,omitzero"`
	NextRefresh  time.Time `json:"next_refresh,omitzero"`
	LastError    string    `json:"last_error,omitempty"`
	ETag         string    `json:"-"`
	LastModified string    `json:"-"`
	Events       int       `json:"events"`
	Bytes        int       `json:"bytes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// stored keeps the conditional-request validators that the API omits.
type stored struct {
	Subscription
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// Settings are a user's calendar preferences kept on the server.
type Settings struct {
	Birthdays bool `json:"birthdays"`
}

// Input creates or changes a subscription.
type Input struct {
	Name     *string   `json:"name,omitempty"`
	URL      *string   `json:"url,omitempty"`
	Color    *string   `json:"color,omitempty"`
	Interval *Interval `json:"interval,omitempty"`
}

// ErrInvalid wraps rejected input.
var ErrInvalid = errors.New("invalid calendar subscription")

// ErrLimit means the account already has the maximum subscriptions.
var ErrLimit = fmt.Errorf("%w: at most %d subscriptions per account", ErrInvalid, MaxSubscriptionsPerUser)

// Service owns subscription records, cached feed contents, refresh, and
// settings.
type Service struct {
	store        store.Store
	fetcher      *Fetcher
	now          func() time.Time
	allowPrivate atomic.Bool
	refreshing   sync.Map // subscription ID -> struct{}

	mu    sync.Mutex
	cache map[string]cachedFeed
}

type cachedFeed struct {
	version time.Time
	objects [][]byte
}

// New opens the service on the system store.
func New(ctx context.Context, backend store.Store) (*Service, error) {
	if backend == nil {
		return nil, errors.New("calendar feeds require a store")
	}
	if err := backend.CreateNamespace(ctx, model.NSCalendarFeeds); err != nil && !errors.Is(err, store.ErrExists) {
		return nil, fmt.Errorf("initialize calendar feeds: %w", err)
	}
	s := &Service{store: backend, now: time.Now, cache: map[string]cachedFeed{}}
	s.fetcher = &Fetcher{AllowPrivate: s.allowPrivate.Load, MaxBytes: MaxFeedBytes, Timeout: FetchTimeout}
	return s, nil
}

// SetAllowPrivateNetworks lets feeds on loopback, private, and link-local
// addresses be fetched (calendar_subscription_allow_private_networks).
func (s *Service) SetAllowPrivateNetworks(allow bool) { s.allowPrivate.Store(allow) }

func subscriptionKey(userID, id string) string { return "sub/" + userID + "/" + id }
func dataKey(id string) string                 { return "data/" + id }
func settingsKey(userID string) string         { return "settings/" + userID }

// List returns userID's subscriptions by name.
func (s *Service) List(ctx context.Context, userID string) ([]Subscription, error) {
	records, err := s.scan(ctx, "sub/"+userID+"/")
	if err != nil {
		return nil, err
	}
	result := make([]Subscription, 0, len(records))
	for _, record := range records {
		result = append(result, record.Subscription)
	}
	sort.Slice(result, func(i, j int) bool { return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name) })
	return result, nil
}

func (s *Service) scan(ctx context.Context, prefix string) ([]stored, error) {
	var records []stored
	err := s.store.Iterate(ctx, model.NSCalendarFeeds, prefix, func(_ string, value []byte) (bool, error) {
		var record stored
		if err := json.Unmarshal(value, &record); err != nil {
			return false, fmt.Errorf("decode calendar subscription: %w", err)
		}
		records = append(records, record)
		return true, nil
	})
	return records, err
}

// Get returns one of userID's subscriptions.
func (s *Service) Get(ctx context.Context, userID, id string) (Subscription, error) {
	record, err := s.load(ctx, userID, id)
	return record.Subscription, err
}

func (s *Service) load(ctx context.Context, userID, id string) (stored, error) {
	if userID == "" || id == "" || strings.Contains(id, "/") {
		return stored{}, store.ErrNotFound
	}
	raw, err := s.store.Get(ctx, model.NSCalendarFeeds, subscriptionKey(userID, id))
	if err != nil {
		return stored{}, err
	}
	var record stored
	if err := json.Unmarshal(raw, &record); err != nil {
		return stored{}, fmt.Errorf("decode calendar subscription: %w", err)
	}
	record.Subscription.ETag, record.Subscription.LastModified = record.ETag, record.LastModified
	return record, nil
}

func (s *Service) save(ctx context.Context, record stored) error {
	record.ETag, record.LastModified = record.Subscription.ETag, record.Subscription.LastModified
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.store.Set(ctx, model.NSCalendarFeeds, subscriptionKey(record.UserID, record.ID), raw)
}

// NormalizeURL accepts webcal, webcals, https, and http feed URLs and
// returns the URL to fetch.
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxURLLength {
		return "", fmt.Errorf("%w: a feed URL of at most %d characters is required", ErrInvalid, maxURLLength)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("%w: the feed URL is not valid", ErrInvalid)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "webcal", "webcals", "https":
		parsed.Scheme = "https"
	case "http":
		parsed.Scheme = "http"
	default:
		return "", fmt.Errorf("%w: the feed URL must use webcal, https, or http", ErrInvalid)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("%w: credentials in the feed URL are not supported", ErrInvalid)
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}

func validColor(color string) bool {
	if color == "" {
		return true
	}
	if len(color) != 7 || color[0] != '#' {
		return false
	}
	_, err := hex.DecodeString(color[1:])
	return err == nil
}

// Create adds a subscription and fetches it once; a failed first fetch is
// kept and reported on the subscription like any later failure.
func (s *Service) Create(ctx context.Context, userID string, input Input) (Subscription, error) {
	existing, err := s.List(ctx, userID)
	if err != nil {
		return Subscription{}, err
	}
	if len(existing) >= MaxSubscriptionsPerUser {
		return Subscription{}, ErrLimit
	}
	if input.URL == nil {
		return Subscription{}, fmt.Errorf("%w: url is required", ErrInvalid)
	}
	id, err := randomID()
	if err != nil {
		return Subscription{}, err
	}
	now := s.now().UTC()
	record := stored{Subscription: Subscription{ID: id, UserID: userID, Interval: Daily, CreatedAt: now, UpdatedAt: now}}
	if err := apply(&record.Subscription, input); err != nil {
		return Subscription{}, err
	}
	if err := s.save(ctx, record); err != nil {
		return Subscription{}, err
	}
	// An unnamed subscription takes the feed's X-WR-CALNAME, or its host.
	created, err := s.Refresh(ctx, userID, id)
	if err != nil || created.Name != "" {
		return created, err
	}
	name := defaultName(created.URL)
	return s.Update(ctx, userID, id, Input{Name: &name})
}

func defaultName(feedURL string) string {
	if parsed, err := url.Parse(feedURL); err == nil {
		return parsed.Hostname()
	}
	return "Subscribed calendar"
}

func apply(sub *Subscription, input Input) error {
	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		if len(name) > maxNameLength {
			return fmt.Errorf("%w: the name is longer than %d characters", ErrInvalid, maxNameLength)
		}
		sub.Name = name
	}
	if input.URL != nil {
		normalized, err := NormalizeURL(*input.URL)
		if err != nil {
			return err
		}
		if normalized != sub.URL {
			sub.URL, sub.ETag, sub.LastModified = normalized, "", ""
			sub.NextRefresh = time.Time{}
		}
	}
	if input.Color != nil {
		color := strings.ToLower(strings.TrimSpace(*input.Color))
		if !validColor(color) {
			return fmt.Errorf("%w: color must be #rrggbb", ErrInvalid)
		}
		sub.Color = color
	}
	if input.Interval != nil {
		if *input.Interval != Hourly && *input.Interval != Daily {
			return fmt.Errorf("%w: interval must be hourly or daily", ErrInvalid)
		}
		if *input.Interval != sub.Interval && !sub.LastAttempt.IsZero() {
			sub.NextRefresh = sub.LastAttempt.Add(input.Interval.duration())
		}
		sub.Interval = *input.Interval
	}
	return nil
}

// Update changes a subscription's name, URL, color, or interval.
func (s *Service) Update(ctx context.Context, userID, id string, input Input) (Subscription, error) {
	record, err := s.load(ctx, userID, id)
	if err != nil {
		return Subscription{}, err
	}
	previousURL := record.URL
	if err := apply(&record.Subscription, input); err != nil {
		return Subscription{}, err
	}
	record.UpdatedAt = s.now().UTC()
	if err := s.save(ctx, record); err != nil {
		return Subscription{}, err
	}
	if record.URL != previousURL {
		return s.Refresh(ctx, userID, id)
	}
	return record.Subscription, nil
}

// Delete removes a subscription and its cached contents.
func (s *Service) Delete(ctx context.Context, userID, id string) error {
	if _, err := s.load(ctx, userID, id); err != nil {
		return err
	}
	if err := s.store.Delete(ctx, model.NSCalendarFeeds, dataKey(id)); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	s.mu.Lock()
	delete(s.cache, id)
	s.mu.Unlock()
	return s.store.Delete(ctx, model.NSCalendarFeeds, subscriptionKey(userID, id))
}

// Refresh fetches a subscription now. Fetch failures are recorded on the
// subscription and do not return an error.
func (s *Service) Refresh(ctx context.Context, userID, id string) (Subscription, error) {
	if _, busy := s.refreshing.LoadOrStore(id, struct{}{}); busy {
		return s.Get(ctx, userID, id)
	}
	defer s.refreshing.Delete(id)
	record, err := s.load(ctx, userID, id)
	if err != nil {
		return Subscription{}, err
	}
	now := s.now().UTC()
	record.LastAttempt = now
	result, fetchErr := s.fetcher.Fetch(ctx, record.URL, record.Subscription.ETag, record.Subscription.LastModified)
	if fetchErr == nil && !result.NotModified {
		fetchErr = s.storeFeed(ctx, &record, result)
	}
	interval := record.Interval.duration()
	if fetchErr != nil {
		record.LastError = fetchErr.Error()
		record.NextRefresh = now.Add(min(interval, errorRetry))
		logger.Warn("calendar subscription refresh failed", "subscription", id, "user", userID, "error", fetchErr)
	} else {
		record.LastError, record.LastSuccess, record.NextRefresh = "", now, now.Add(interval)
		if !result.NotModified {
			record.Subscription.ETag, record.Subscription.LastModified = result.ETag, result.LastModified
		}
	}
	// The record may have been deleted or edited while fetching.
	current, err := s.load(ctx, userID, id)
	if err != nil {
		return Subscription{}, err
	}
	if current.URL != record.URL {
		return current.Subscription, nil
	}
	if current.Name != "" {
		record.Name = current.Name
	}
	record.Color, record.Interval = current.Color, current.Interval
	if err := s.save(ctx, record); err != nil {
		return Subscription{}, err
	}
	return record.Subscription, nil
}

func (s *Service) storeFeed(ctx context.Context, record *stored, result FetchResult) error {
	document := calendarport.Parse(result.Body)
	if len(document.Objects) == 0 {
		if len(document.Problems) > 0 {
			return fmt.Errorf("the feed is not a usable calendar: %s", document.Problems[0].Message)
		}
		if document.Skipped == 0 && !strings.Contains(string(result.Body[:min(len(result.Body), 512)]), "BEGIN:VCALENDAR") {
			return errors.New("the feed is not an iCalendar document")
		}
	}
	objects := make([][]byte, 0, len(document.Objects))
	for _, object := range document.Objects {
		objects = append(objects, object.Data)
	}
	raw, err := json.Marshal(objects)
	if err != nil {
		return err
	}
	if err := s.store.Set(ctx, model.NSCalendarFeeds, dataKey(record.ID), raw); err != nil {
		return fmt.Errorf("store feed: %w", err)
	}
	record.Events, record.Bytes = len(objects), len(result.Body)
	if record.Name == "" && document.Name != "" {
		record.Name = document.Name
	}
	s.mu.Lock()
	delete(s.cache, record.ID)
	s.mu.Unlock()
	return nil
}

// Occurrences expands a subscription's events over [start, end).
func (s *Service) Occurrences(ctx context.Context, userID, id string, start, end time.Time) ([]calendar.Occurrence, error) {
	record, err := s.load(ctx, userID, id)
	if err != nil {
		return nil, err
	}
	objects, err := s.objects(ctx, record)
	if err != nil {
		return nil, err
	}
	var result []calendar.Occurrence
	for _, data := range objects {
		occurrences, _, err := calendar.Occurrences(data, start, end)
		if err != nil {
			continue
		}
		result = append(result, occurrences...)
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Start < result[j].Start })
	return result, nil
}

// Objects returns a subscription's cached calendar objects.
func (s *Service) Objects(ctx context.Context, userID, id string) ([][]byte, error) {
	record, err := s.load(ctx, userID, id)
	if err != nil {
		return nil, err
	}
	return s.objects(ctx, record)
}

func (s *Service) objects(ctx context.Context, record stored) ([][]byte, error) {
	s.mu.Lock()
	cached, ok := s.cache[record.ID]
	s.mu.Unlock()
	if ok && cached.version.Equal(record.LastSuccess) {
		return cached.objects, nil
	}
	raw, err := s.store.Get(ctx, model.NSCalendarFeeds, dataKey(record.ID))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var objects [][]byte
	if err := json.Unmarshal(raw, &objects); err != nil {
		return nil, fmt.Errorf("decode feed: %w", err)
	}
	s.mu.Lock()
	s.cache[record.ID] = cachedFeed{version: record.LastSuccess, objects: objects}
	s.mu.Unlock()
	return objects, nil
}

// Settings returns userID's calendar settings.
func (s *Service) Settings(ctx context.Context, userID string) (Settings, error) {
	var settings Settings
	raw, err := s.store.Get(ctx, model.NSCalendarFeeds, settingsKey(userID))
	if errors.Is(err, store.ErrNotFound) {
		return settings, nil
	}
	if err != nil {
		return settings, err
	}
	return settings, json.Unmarshal(raw, &settings)
}

// SetSettings replaces userID's calendar settings.
func (s *Service) SetSettings(ctx context.Context, userID string, settings Settings) error {
	raw, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	return s.store.Set(ctx, model.NSCalendarFeeds, settingsKey(userID), raw)
}

// RefreshDue refreshes every subscription whose next refresh has passed.
func (s *Service) RefreshDue(ctx context.Context) {
	records, err := s.scan(ctx, "sub/")
	if err != nil {
		logger.Warn("list calendar subscriptions", "error", err)
		return
	}
	now := s.now().UTC()
	for _, record := range records {
		if ctx.Err() != nil {
			return
		}
		if record.NextRefresh.After(now) {
			continue
		}
		if _, err := s.Refresh(ctx, record.UserID, record.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			logger.Warn("refresh calendar subscription", "subscription", record.ID, "error", err)
		}
	}
}

// Run refreshes due subscriptions every interval until ctx ends.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		s.RefreshDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func randomID() (string, error) {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
