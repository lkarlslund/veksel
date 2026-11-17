package app

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	adminWebhookMaxRetries = 20
	adminWebhookPageSize   = 25
)

var webhookEventPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type adminWebhookView struct {
	ID                         string    `json:"id"`
	URL                        string    `json:"url"`
	Events                     []string  `json:"events"`
	Accounts                   []string  `json:"accounts"`
	Domains                    []string  `json:"domains"`
	Addresses                  []string  `json:"addresses"`
	Include                    []string  `json:"include"`
	Active                     bool      `json:"active"`
	HasSecret                  bool      `json:"has_secret"`
	MaxRetries                 int       `json:"max_retries"`
	EffectiveMaxRetries        int       `json:"effective_max_retries"`
	BackoffMultiplier          float64   `json:"backoff_multiplier"`
	EffectiveBackoffMultiplier float64   `json:"effective_backoff_multiplier"`
	CreatedAt                  time.Time `json:"created_at"`
	UpdatedAt                  time.Time `json:"updated_at"`
	SecretRotatedAt            string    `json:"secret_rotated_at,omitempty"`
	SecretRotationCount        int       `json:"secret_rotation_count,omitempty"`
}

type adminWebhookRequest struct {
	URL               *string    `json:"url"`
	Events            *[]string  `json:"events"`
	Accounts          *[]string  `json:"accounts"`
	Domains           *[]string  `json:"domains"`
	Addresses         *[]string  `json:"addresses"`
	Include           *[]string  `json:"include"`
	Active            *bool      `json:"active"`
	Secret            *string    `json:"secret"`
	MaxRetries        *int       `json:"max_retries"`
	BackoffMultiplier *float64   `json:"backoff_multiplier"`
	UpdatedAt         *time.Time `json:"updated_at"`
}

type adminWebhookRotationRequest struct {
	UpdatedAt time.Time `json:"updated_at"`
}

type adminWebhookRotationView struct {
	adminWebhookView
	Secret string `json:"secret"`
}

type adminWebhookDeliveryView struct {
	ID           string                      `json:"id"`
	Event        string                      `json:"event"`
	URL          string                      `json:"url"`
	Status       model.WebhookDeliveryStatus `json:"status"`
	StatusCode   int                         `json:"status_code"`
	ResponseBody string                      `json:"response_body,omitempty"`
	ErrorMessage string                      `json:"error_message,omitempty"`
	Attempt      int                         `json:"attempt"`
	MaxAttempts  int                         `json:"max_attempts"`
	DurationMs   int                         `json:"duration_ms"`
	CreatedAt    time.Time                   `json:"created_at"`
	UpdatedAt    time.Time                   `json:"updated_at"`
	CompletedAt  time.Time                   `json:"completed_at,omitzero"`
}

type adminWebhookDeliveryPage struct {
	Items      []adminWebhookDeliveryView `json:"items"`
	Total      int                        `json:"total"`
	NextCursor string                     `json:"next_cursor,omitempty"`
}

type webhookDeliveryCursor struct {
	At time.Time `json:"at"`
	ID string    `json:"id"`
}

func webhookView(webhook model.Webhook) adminWebhookView {
	view := adminWebhookView{
		ID: webhook.ID, URL: webhook.URL, Events: slices.Clone(webhook.Events), Accounts: slices.Clone(webhook.Accounts), Domains: slices.Clone(webhook.Domains), Addresses: slices.Clone(webhook.Addresses), Include: slices.Clone(webhook.Include), Active: webhook.Active,
		HasSecret: webhook.Secret != "", MaxRetries: webhook.MaxRetries, EffectiveMaxRetries: webhook.EffectiveMaxRetries(),
		BackoffMultiplier: webhook.BackoffMultiplier, EffectiveBackoffMultiplier: webhook.EffectiveBackoffMultiplier(),
		CreatedAt: webhook.CreatedAt, UpdatedAt: webhook.UpdatedAt,
	}
	if !webhook.SecretRotatedAt.IsZero() {
		view.SecretRotatedAt = webhook.SecretRotatedAt.UTC().Format(time.RFC3339Nano)
	}
	view.SecretRotationCount = webhook.SecretRotationCount
	return view
}

func webhookDeliveryView(delivery model.WebhookDelivery) adminWebhookDeliveryView {
	return adminWebhookDeliveryView{
		ID: delivery.ID, Event: delivery.Event, URL: delivery.URL, Status: delivery.Status,
		StatusCode: delivery.StatusCode, ResponseBody: delivery.ResponseBody, ErrorMessage: delivery.ErrorMessage,
		Attempt: delivery.Attempt, MaxAttempts: delivery.MaxAttempts, DurationMs: delivery.DurationMs,
		CreatedAt: delivery.CreatedAt, UpdatedAt: delivery.UpdatedAt, CompletedAt: delivery.CompletedAt,
	}
}

func (h *Handler) listWebhooks(w http.ResponseWriter, r *http.Request, personal bool) {
	owner, ok := h.webhookOwner(w, r, personal)
	if !ok {
		return
	}
	webhooks, err := h.webhooks.List(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	result := make([]adminWebhookView, 0, len(webhooks))
	for _, webhook := range webhooks {
		if webhook.OwnerID == owner {
			result = append(result, webhookView(webhook))
		}
	}
	jsonResponse(w, http.StatusOK, result)
}

func (h *Handler) createWebhook(w http.ResponseWriter, r *http.Request, personal bool) {
	owner, ok := h.webhookOwner(w, r, personal)
	if !ok {
		return
	}
	var request adminWebhookRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.URL == nil || request.Events == nil {
		jsonError(w, http.StatusBadRequest, "url and events are required")
		return
	}
	if personal {
		existing, err := h.webhooks.List(r.Context())
		if err != nil {
			apiError(w, err)
			return
		}
		count := 0
		for _, webhook := range existing {
			if webhook.OwnerID == owner {
				count++
			}
		}
		if count >= maxPersonalWebhooks {
			jsonError(w, http.StatusConflict, fmt.Sprintf("at most %d personal webhooks", maxPersonalWebhooks))
			return
		}
	}
	webhook := model.Webhook{ID: model.GenerateWebhookID(), OwnerID: owner, Active: true, CreatedAt: time.Now().UTC()}
	if err := applyWebhookRequest(&webhook, request, true); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	webhook.UpdatedAt = webhook.CreatedAt
	if err := h.webhooks.Create(r.Context(), webhook); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "webhook.create", webhook.ID, webhookAuditDetails(webhook))
	jsonResponse(w, http.StatusCreated, webhookView(webhook))
}

func (h *Handler) updateWebhook(w http.ResponseWriter, r *http.Request, personal bool) {
	owner, ok := h.webhookOwner(w, r, personal)
	if !ok {
		return
	}
	webhook, err := h.ownedWebhook(r, owner)
	if err != nil {
		apiError(w, err)
		return
	}
	var request adminWebhookRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.UpdatedAt == nil {
		jsonError(w, http.StatusBadRequest, "updated_at is required")
		return
	}
	if err := applyWebhookRequest(webhook, request, false); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	webhook, err = h.webhooks.UpdateIfUpdatedAt(r.Context(), *webhook, *request.UpdatedAt)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "webhook.update", webhook.ID, webhookAuditDetails(*webhook))
	jsonResponse(w, http.StatusOK, webhookView(*webhook))
}

func (h *Handler) rotateWebhookSecret(w http.ResponseWriter, r *http.Request, personal bool) {
	owner, ok := h.webhookOwner(w, r, personal)
	if !ok {
		return
	}
	var request adminWebhookRotationRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.UpdatedAt.IsZero() {
		jsonError(w, http.StatusBadRequest, "updated_at is required")
		return
	}
	if _, err := h.ownedWebhook(r, owner); err != nil {
		apiError(w, err)
		return
	}
	webhook, secret, err := h.webhooks.RotateSecret(r.Context(), r.PathValue("id"), request.UpdatedAt)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "webhook.secret.rotate", webhook.ID, map[string]string{
		"rotation_count": strconv.Itoa(webhook.SecretRotationCount), "url": webhook.URL,
	})
	jsonResponse(w, http.StatusOK, adminWebhookRotationView{adminWebhookView: webhookView(*webhook), Secret: secret})
}

func (h *Handler) deleteWebhook(w http.ResponseWriter, r *http.Request, personal bool) {
	owner, ok := h.webhookOwner(w, r, personal)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if _, err := h.ownedWebhook(r, owner); err != nil {
		apiError(w, err)
		return
	}
	if err := h.webhooks.Delete(r.Context(), id); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "webhook.delete", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) testWebhook(w http.ResponseWriter, r *http.Request, personal bool) {
	owner, ok := h.webhookOwner(w, r, personal)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if _, err := h.ownedWebhook(r, owner); err != nil {
		apiError(w, err)
		return
	}
	if h.webhookTester == nil {
		jsonError(w, http.StatusServiceUnavailable, "webhook dispatcher is unavailable")
		return
	}
	delivery, err := h.webhookTester.Test(r.Context(), id)
	h.audit.Log(currentActor(r).ID, "webhook.test", id, map[string]string{"success": strconv.FormatBool(err == nil)})
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	if delivery == nil {
		jsonError(w, http.StatusServiceUnavailable, "webhook test returned no delivery evidence")
		return
	}
	jsonResponse(w, http.StatusOK, webhookDeliveryView(*delivery))
}

func (h *Handler) listWebhookDeliveries(w http.ResponseWriter, r *http.Request, personal bool) {
	owner, ok := h.webhookOwner(w, r, personal)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if _, err := h.ownedWebhook(r, owner); err != nil {
		apiError(w, err)
		return
	}
	limit := adminWebhookPageSize
	if raw := strings.TrimSpace(r.URL.Query().Get("page_size")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			jsonError(w, http.StatusBadRequest, "page_size must be between 1 and 100")
			return
		}
		limit = parsed
	}
	cursor, err := decodeWebhookDeliveryCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	deliveries, total, more, err := h.webhookDeliveries.ListPageByWebhook(r.Context(), id, cursor.At, cursor.ID, limit)
	if err != nil {
		apiError(w, err)
		return
	}
	page := adminWebhookDeliveryPage{Items: make([]adminWebhookDeliveryView, 0, len(deliveries)), Total: total}
	for _, delivery := range deliveries {
		page.Items = append(page.Items, webhookDeliveryView(delivery))
	}
	if more && len(deliveries) > 0 {
		last := deliveries[len(deliveries)-1]
		page.NextCursor = encodeWebhookDeliveryCursor(webhookDeliveryCursor{At: deliveryTimestamp(last), ID: last.ID})
	}
	jsonResponse(w, http.StatusOK, page)
}

const maxPersonalWebhooks = 10

// webhookOwner resolves whose webhooks a request manages: an administrator
// manages server webhooks (owner ""), anyone manages their own personal
// ones (the account they are working as).
func (h *Handler) webhookOwner(w http.ResponseWriter, r *http.Request, personal bool) (string, bool) {
	if !personal {
		return "", h.requireAdminAPI(w, r)
	}
	subject := currentSubject(r).ID
	if subject == "" {
		jsonError(w, http.StatusUnauthorized, "sign-in required")
		return "", false
	}
	return subject, true
}

// ownedWebhook returns the {id} webhook when it belongs to owner; another
// owner's webhook is reported as not found.
func (h *Handler) ownedWebhook(r *http.Request, owner string) (*model.Webhook, error) {
	webhook, err := h.webhooks.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	if webhook.OwnerID != owner {
		return nil, store.ErrNotFound
	}
	return webhook, nil
}

func applyWebhookRequest(webhook *model.Webhook, request adminWebhookRequest, creating bool) error {
	if request.URL != nil {
		destination := strings.TrimSpace(*request.URL)
		if len(destination) > 2048 {
			return errors.New("webhook URL cannot exceed 2048 characters")
		}
		parsed, err := url.Parse(destination)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
			return errors.New("webhook URL must be an HTTP or HTTPS URL without embedded credentials")
		}
		webhook.URL = destination
	}
	if request.Events != nil {
		events := make([]string, 0, len(*request.Events))
		seen := make(map[string]struct{}, len(*request.Events))
		for _, value := range *request.Events {
			event := strings.ToLower(strings.TrimSpace(value))
			if !webhookEventPattern.MatchString(event) {
				return fmt.Errorf("invalid webhook event %q", value)
			}
			if _, duplicate := seen[event]; duplicate {
				continue
			}
			seen[event] = struct{}{}
			events = append(events, event)
		}
		if len(events) == 0 || len(events) > 32 {
			return errors.New("between 1 and 32 webhook events are required")
		}
		slices.Sort(events)
		webhook.Events = events
	}
	if request.Accounts != nil {
		accounts, err := webhookFilterValues(*request.Accounts, webhookAccountPattern, "account")
		if err != nil {
			return err
		}
		webhook.Accounts = accounts
	}
	if request.Domains != nil {
		domains, err := webhookFilterValues(*request.Domains, webhookDomainPattern, "domain")
		if err != nil {
			return err
		}
		webhook.Domains = domains
	}
	if request.Addresses != nil {
		addresses, err := webhookFilterValues(*request.Addresses, webhookAddressPattern, "address")
		if err != nil {
			return err
		}
		webhook.Addresses = addresses
	}
	if request.Include != nil {
		include := make([]string, 0, len(*request.Include))
		for _, value := range *request.Include {
			part := strings.ToLower(strings.TrimSpace(value))
			if !model.IsWebhookIncludeOption(part) {
				return fmt.Errorf("unknown webhook payload part %q (use %s)", value, strings.Join(model.WebhookIncludeOptions, ", "))
			}
			if !slices.Contains(include, part) {
				include = append(include, part)
			}
		}
		slices.Sort(include)
		webhook.Include = include
	}
	if request.Active != nil {
		webhook.Active = *request.Active
	}
	if request.Secret != nil {
		if len(*request.Secret) > 4096 {
			return errors.New("webhook secret cannot exceed 4096 characters")
		}
		webhook.Secret = *request.Secret
	}
	if request.MaxRetries != nil {
		if *request.MaxRetries < 0 || *request.MaxRetries > adminWebhookMaxRetries {
			return fmt.Errorf("max_retries must be between 0 and %d", adminWebhookMaxRetries)
		}
		webhook.MaxRetries = *request.MaxRetries
	}
	if request.BackoffMultiplier != nil {
		if *request.BackoffMultiplier != 0 && (*request.BackoffMultiplier < 1 || *request.BackoffMultiplier > 10) {
			return errors.New("backoff_multiplier must be zero or between 1 and 10")
		}
		webhook.BackoffMultiplier = *request.BackoffMultiplier
	}
	if creating && request.Active == nil {
		webhook.Active = true
	}
	if webhook.URL == "" || len(webhook.Events) == 0 {
		return errors.New("url and at least one event are required")
	}
	if webhook.OwnerID != "" {
		if len(webhook.Accounts) > 0 || len(webhook.Domains) > 0 {
			return errors.New("personal webhooks cover your own mail; use addresses to narrow them")
		}
		for _, event := range webhook.Events {
			if !accountEvent(event) {
				return fmt.Errorf("personal webhooks receive message events only, not %q", event)
			}
		}
		return nil
	}
	if slices.ContainsFunc(webhook.Events, accountEvent) && len(webhook.Accounts) == 0 && len(webhook.Domains) == 0 && len(webhook.Addresses) == 0 {
		return errors.New("message events need an account, domain or address filter, so the webhook does not receive every mailbox's mail")
	}
	return nil
}

var (
	webhookAddressPattern = regexp.MustCompile(`^[a-z0-9._%+=-]{1,64}@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	webhookAccountPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{0,127}$`)
	webhookDomainPattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// accountEvent reports whether event is about one account's data.
func accountEvent(event string) bool { return strings.HasPrefix(event, "message.") }

func webhookFilterValues(values []string, pattern *regexp.Regexp, kind string) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || slices.Contains(result, value) {
			continue
		}
		if !pattern.MatchString(value) {
			return nil, fmt.Errorf("invalid webhook %s filter %q", kind, value)
		}
		result = append(result, value)
	}
	if len(result) > 100 {
		return nil, fmt.Errorf("at most 100 %s filters", kind)
	}
	slices.Sort(result)
	return result, nil
}

func webhookAuditDetails(webhook model.Webhook) map[string]string {
	parsed, _ := url.Parse(webhook.URL)
	return map[string]string{"host": parsed.Host, "active": strconv.FormatBool(webhook.Active), "events": strconv.Itoa(len(webhook.Events)), "has_secret": strconv.FormatBool(webhook.Secret != "")}
}

func encodeWebhookDeliveryCursor(cursor webhookDeliveryCursor) string {
	encoded, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func decodeWebhookDeliveryCursor(raw string) (webhookDeliveryCursor, error) {
	if strings.TrimSpace(raw) == "" {
		return webhookDeliveryCursor{}, nil
	}
	encoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return webhookDeliveryCursor{}, errors.New("invalid delivery cursor")
	}
	var cursor webhookDeliveryCursor
	if err := json.Unmarshal(encoded, &cursor); err != nil || cursor.At.IsZero() || strings.TrimSpace(cursor.ID) == "" {
		return webhookDeliveryCursor{}, errors.New("invalid delivery cursor")
	}
	return cursor, nil
}

func deliveryTimestamp(delivery model.WebhookDelivery) time.Time {
	if !delivery.UpdatedAt.IsZero() {
		return delivery.UpdatedAt
	}
	return delivery.CreatedAt
}

func (h *Handler) apiAdminWebhooks(w http.ResponseWriter, r *http.Request) {
	h.listWebhooks(w, r, false)
}
func (h *Handler) apiAdminCreateWebhook(w http.ResponseWriter, r *http.Request) {
	h.createWebhook(w, r, false)
}
func (h *Handler) apiAdminUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	h.updateWebhook(w, r, false)
}
func (h *Handler) apiAdminRotateWebhookSecret(w http.ResponseWriter, r *http.Request) {
	h.rotateWebhookSecret(w, r, false)
}
func (h *Handler) apiAdminDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	h.deleteWebhook(w, r, false)
}
func (h *Handler) apiAdminTestWebhook(w http.ResponseWriter, r *http.Request) {
	h.testWebhook(w, r, false)
}
func (h *Handler) apiAdminWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	h.listWebhookDeliveries(w, r, false)
}

func (h *Handler) apiUserWebhooks(w http.ResponseWriter, r *http.Request) { h.listWebhooks(w, r, true) }
func (h *Handler) apiUserCreateWebhook(w http.ResponseWriter, r *http.Request) {
	h.createWebhook(w, r, true)
}
func (h *Handler) apiUserUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	h.updateWebhook(w, r, true)
}
func (h *Handler) apiUserRotateWebhookSecret(w http.ResponseWriter, r *http.Request) {
	h.rotateWebhookSecret(w, r, true)
}
func (h *Handler) apiUserDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	h.deleteWebhook(w, r, true)
}
func (h *Handler) apiUserTestWebhook(w http.ResponseWriter, r *http.Request) {
	h.testWebhook(w, r, true)
}
func (h *Handler) apiUserWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	h.listWebhookDeliveries(w, r, true)
}
