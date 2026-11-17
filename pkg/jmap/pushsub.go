package jmap

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// PushSubscription (RFC 8620 §7.2): the server verifies the push URL with a
// PushVerification, and once the client echoes the verification code it
// posts StateChange objects there, encrypted per RFC 8291 when the client
// supplied keys. Subscriptions persist in the subscriber's account store, so
// they survive a restart: the background sweep resumes delivery for verified
// ones and deletes expired ones.

const (
	maxPushLifetime     = 7 * 24 * time.Hour
	defaultPushLifetime = 48 * time.Hour
	maxPushPerUser      = 16
)

type pushKeys struct {
	P256DH string `json:"p256dh"`
	Auth   string `json:"auth"`
}

// pushSubscription is the durable record. The verification code is kept so
// a restart neither forgets a pending verification nor a confirmed one.
type pushSubscription struct {
	ID               string    `json:"id"`
	DeviceClientID   string    `json:"device_client_id"`
	URL              string    `json:"url"`
	Keys             *pushKeys `json:"keys,omitempty"`
	VerificationCode string    `json:"verification_code"`
	Verified         bool      `json:"verified,omitempty"`
	Expires          time.Time `json:"expires"`
	// Types is nil for every type; an empty list is kept as given.
	Types []string `json:"types"`
}

// pushLoop is one running delivery loop.
type pushLoop struct {
	cancel context.CancelFunc
}

// object is the PushSubscription as /get returns it; url and keys are
// write-only (RFC 8620 §7.2).
func (s *pushSubscription) object() map[string]any {
	var types any
	if s.Types != nil {
		types = s.Types
	}
	var code any
	if s.Verified {
		code = s.VerificationCode
	}
	return map[string]any{"id": s.ID, "deviceClientId": s.DeviceClientID, "verificationCode": code, "expires": formatUTCDate(s.Expires), "types": types}
}

func (h *Handler) pushGet(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a struct {
		IDs        []string `json:"ids"`
		Properties []string `json:"properties"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	subscriptions, err := h.loadPushLocked(ctx, actor.ID)
	if err != nil {
		return nil, serverError(err)
	}
	wanted := idSet(a.IDs)
	list := []any{}
	found := map[string]bool{}
	for _, id := range sortedKeys(subscriptions) {
		if wanted == nil || wanted[id] {
			list = append(list, selectProperties(subscriptions[id].object(), a.Properties))
			found[id] = true
		}
	}
	// PushSubscription has no accountId and no state (RFC 8620 §7.2.1).
	return map[string]any{"list": list, "notFound": missing(a.IDs, found)}, nil
}

// loadPushLocked reads the user's subscriptions, deleting expired ones and
// stopping their delivery.
func (h *Handler) loadPushLocked(ctx context.Context, userID string) (map[string]*pushSubscription, error) {
	subscriptions := map[string]*pushSubscription{}
	now := time.Now()
	err := h.withState(ctx, userID, false, func(ctx context.Context, index store.Store) error {
		var expired []string
		err := index.Iterate(ctx, stateNamespace, pushPrefix, func(key string, value []byte) (bool, error) {
			var s pushSubscription
			if err := json.Unmarshal(value, &s); err != nil {
				return false, fmt.Errorf("decode jmap push subscription %s: %w", key, err)
			}
			if now.After(s.Expires) {
				expired = append(expired, key)
			} else {
				subscriptions[s.ID] = &s
			}
			return true, nil
		})
		if err != nil {
			return err
		}
		for _, key := range expired {
			h.stopPushLocked(userID, strings.TrimPrefix(key, pushPrefix))
			if err := deleteKey(ctx, index, stateNamespace, key); err != nil {
				return err
			}
		}
		return nil
	})
	return subscriptions, err
}

// savePushLocked persists changed and destroyed subscriptions and keeps the
// user's entry in the state index in step.
func (h *Handler) savePushLocked(ctx context.Context, userID string, subscriptions map[string]*pushSubscription, changed map[string]bool, destroyed []string) error {
	if len(changed) == 0 && len(destroyed) == 0 {
		return nil
	}
	if len(subscriptions) > 0 {
		if err := h.markIndexed(ctx, indexPushPrefix, userID); err != nil {
			return err
		}
	}
	err := h.withState(ctx, userID, len(changed) > 0, func(ctx context.Context, index store.Store) error {
		return store.Batch(ctx, index, func(ctx context.Context) error {
			for _, id := range sortedKeys(changed) {
				if err := setJSON(ctx, index, pushPrefix+id, subscriptions[id]); err != nil {
					return err
				}
			}
			for _, id := range destroyed {
				if err := deleteKey(ctx, index, stateNamespace, pushPrefix+id); err != nil {
					return err
				}
			}
			return nil
		})
	})
	if err != nil || len(subscriptions) > 0 {
		return err
	}
	return h.unmarkIndexed(ctx, indexPushPrefix, userID)
}

// stopPushLocked cancels a subscription's delivery loop.
func (h *Handler) stopPushLocked(userID, id string) {
	if loop := h.pushLoops[userID][id]; loop != nil {
		loop.cancel()
		delete(h.pushLoops[userID], id)
	}
	if len(h.pushLoops[userID]) == 0 {
		delete(h.pushLoops, userID)
	}
}

// sweepPush expires one user's subscriptions, resumes delivery for the
// verified ones, and forgets users that were deleted or purged.
func (h *Handler) sweepPush(ctx context.Context, userID string) error {
	user, userErr := h.cfg.Directory.GetAccount(ctx, userID)
	if userErr != nil && !errors.Is(userErr, store.ErrNotFound) {
		return userErr
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	subscriptions, err := h.loadPushLocked(ctx, userID)
	if err != nil {
		return err
	}
	if errors.Is(userErr, store.ErrNotFound) && len(subscriptions) > 0 {
		// The user is gone; so is every reason to keep pushing to them.
		destroyed := sortedKeys(subscriptions)
		subscriptions = map[string]*pushSubscription{}
		if err := h.savePushLocked(ctx, userID, subscriptions, nil, destroyed); err != nil {
			return err
		}
	}
	for id := range h.pushLoops[userID] {
		if s, ok := subscriptions[id]; !ok || !s.Verified {
			h.stopPushLocked(userID, id)
		}
	}
	if len(subscriptions) == 0 {
		return h.unmarkIndexed(ctx, indexPushPrefix, userID)
	}
	for _, id := range sortedKeys(subscriptions) {
		if s := subscriptions[id]; s.Verified && user.Enabled && h.pushLoops[userID][id] == nil {
			h.startPushLocked(user, s)
		}
	}
	return nil
}

func (h *Handler) pushSet(ctx context.Context, actor model.User, raw json.RawMessage, created map[string]string) (any, *MethodError) {
	var a struct {
		IfInState string                     `json:"ifInState"`
		Create    map[string]json.RawMessage `json:"create"`
		Update    map[string]json.RawMessage `json:"update"`
		Destroy   []string                   `json:"destroy"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	if a.IfInState != "" {
		return nil, &MethodError{Type: "invalidArguments", Description: "PushSubscription has no state", Properties: []string{"ifInState"}}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	subscriptions, err := h.loadPushLocked(ctx, actor.ID)
	if err != nil {
		return nil, serverError(err)
	}
	changed := map[string]bool{}
	var verifications []pushSubscription
	made, notMade := map[string]any{}, map[string]any{}
	for _, cid := range sortedKeys(a.Create) {
		var v struct {
			DeviceClientID   string    `json:"deviceClientId"`
			URL              string    `json:"url"`
			Keys             *pushKeys `json:"keys"`
			VerificationCode *string   `json:"verificationCode"`
			Expires          *string   `json:"expires"`
			Types            []string  `json:"types"`
		}
		if err := json.Unmarshal(a.Create[cid], &v); err != nil {
			notMade[cid] = *invalidProperties("a PushSubscription must be a JSON object")
			continue
		}
		if len(subscriptions) >= maxPushPerUser {
			notMade[cid] = MethodError{Type: "overQuota", Description: "too many push subscriptions"}
			continue
		}
		if v.DeviceClientID == "" {
			notMade[cid] = *invalidProperties("deviceClientId is required", "deviceClientId")
			continue
		}
		if v.VerificationCode != nil {
			notMade[cid] = *invalidProperties("verificationCode is set by the server", "verificationCode")
			continue
		}
		if parsed, err := url.Parse(v.URL); err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			notMade[cid] = *invalidProperties("url must be an https URL", "url")
			continue
		}
		if v.Keys != nil {
			if _, _, err := decodePushKeys(*v.Keys); err != nil {
				notMade[cid] = *invalidProperties(err.Error(), "keys")
				continue
			}
		}
		expires, e := pushExpiry(v.Expires)
		if e != nil {
			notMade[cid] = *e
			continue
		}
		s := &pushSubscription{ID: randomID("push-"), DeviceClientID: v.DeviceClientID, URL: v.URL, Keys: v.Keys,
			VerificationCode: randomID(""), Expires: expires, Types: v.Types}
		subscriptions[s.ID] = s
		changed[s.ID] = true
		created[cid] = s.ID
		made[cid] = map[string]any{"id": s.ID, "expires": formatUTCDate(expires)}
		verifications = append(verifications, *s)
	}
	updated, notUpdated := map[string]any{}, map[string]any{}
	restart := map[string]bool{}
	for _, key := range sortedKeys(a.Update) {
		id := resolveCreated(key, created)
		s, ok := subscriptions[id]
		if !ok {
			notUpdated[key] = MethodError{Type: "notFound"}
			continue
		}
		var patch map[string]json.RawMessage
		if json.Unmarshal(a.Update[key], &patch) != nil {
			notUpdated[key] = *invalidProperties("patch must be a JSON object")
			continue
		}
		var e *MethodError
		next := *s
		for property, value := range patch {
			switch property {
			case "verificationCode":
				var code string
				if json.Unmarshal(value, &code) != nil || code != s.VerificationCode {
					e = invalidProperties("verificationCode does not match", property)
				} else {
					next.Verified = true
				}
			case "expires":
				var raw *string
				if json.Unmarshal(value, &raw) != nil {
					e = invalidProperties("expires must be a UTCDate", property)
				} else if next.Expires, e = pushExpiry(raw); e == nil {
					updated[key] = map[string]any{"expires": formatUTCDate(next.Expires)}
				}
			case "types":
				if json.Unmarshal(value, &next.Types) != nil {
					e = invalidProperties("types must be an array of type names", property)
				}
			default:
				e = invalidProperties(property+" cannot be changed", property)
			}
		}
		if e != nil {
			notUpdated[key] = *e
			continue
		}
		if _, ok := updated[key]; !ok {
			updated[key] = nil
		}
		*s = next
		changed[id] = true
		restart[id] = true
	}
	destroyed, notDestroyed := []string{}, map[string]any{}
	var removed []string
	for _, key := range a.Destroy {
		id := resolveCreated(key, created)
		if _, ok := subscriptions[id]; !ok {
			notDestroyed[key] = MethodError{Type: "notFound"}
			continue
		}
		delete(subscriptions, id)
		delete(changed, id)
		removed = append(removed, id)
		destroyed = append(destroyed, key)
	}
	// Persist before any side effect, so a failed write leaves nothing
	// running that a restart would not know about.
	if err := h.savePushLocked(ctx, actor.ID, subscriptions, changed, removed); err != nil {
		return nil, serverError(err)
	}
	for _, id := range removed {
		h.stopPushLocked(actor.ID, id)
	}
	for _, id := range sortedKeys(restart) {
		h.stopPushLocked(actor.ID, id)
		if s, ok := subscriptions[id]; ok && s.Verified {
			h.startPushLocked(actor, s)
		}
	}
	for _, s := range verifications {
		if _, ok := subscriptions[s.ID]; !ok {
			continue
		}
		verification, _ := json.Marshal(map[string]any{"@type": "PushVerification", "pushSubscriptionId": s.ID, "verificationCode": s.VerificationCode})
		h.goBackground(func(ctx context.Context) { h.deliverPush(ctx, s, verification) })
	}
	return map[string]any{"created": made, "notCreated": notMade, "updated": updated, "notUpdated": notUpdated, "destroyed": destroyed, "notDestroyed": notDestroyed}, nil
}

func pushExpiry(value *string) (time.Time, *MethodError) {
	now := time.Now()
	if value == nil {
		return now.Add(defaultPushLifetime), nil
	}
	expires, err := parseUTCDate(*value)
	if err != nil || !expires.After(now) {
		return time.Time{}, invalidProperties("expires must be a future UTCDate", "expires")
	}
	if limit := now.Add(maxPushLifetime); expires.After(limit) {
		expires = limit
	}
	return expires.Truncate(time.Second), nil
}

// startPushLocked starts the loop that posts the subscriber's state
// changes until the subscription is destroyed, replaced or expires.
func (h *Handler) startPushLocked(actor model.User, s *pushSubscription) {
	subscription := *s
	ctx, cancel := context.WithDeadline(context.Background(), subscription.Expires)
	loop := &pushLoop{cancel: cancel}
	h.stopPushLocked(actor.ID, subscription.ID)
	if h.pushLoops[actor.ID] == nil {
		h.pushLoops[actor.ID] = map[string]*pushLoop{}
	}
	h.pushLoops[actor.ID][subscription.ID] = loop
	started := h.goBackground(func(background context.Context) {
		stop := context.AfterFunc(background, cancel)
		defer stop()
		defer h.forgetPushLoop(actor.ID, subscription.ID, loop)
		h.runPush(ctx, actor, subscription, loop)
	})
	if !started {
		// The server is shutting down; nothing will deliver.
		h.stopPushLocked(actor.ID, subscription.ID)
	}
}

// forgetPushLoop drops a finished loop unless a newer one replaced it.
func (h *Handler) forgetPushLoop(userID, id string, loop *pushLoop) {
	loop.cancel()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pushLoops[userID][id] == loop {
		h.stopPushLocked(userID, id)
	}
}

// runPush posts the subscriber's state changes until ctx ends or the push
// service reports the subscription gone, which destroys it.
func (h *Handler) runPush(ctx context.Context, actor model.User, subscription pushSubscription, loop *pushLoop) {
	tracker := &pushTracker{last: map[string]string{}}
	if len(subscription.Types) > 0 {
		tracker.wanted = idSet(subscription.Types)
	}
	watcher := h.newPushWatcher()
	defer watcher.close()
	h.pushStates(ctx, actor, tracker, true)
	watcher.follow(tracker)
	ticker := time.NewTicker(h.cfg.PushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-watcher.wake:
			if !watcher.settle(ctx) {
				return
			}
		case <-ticker.C:
		}
		changed := h.pushStates(ctx, actor, tracker, false)
		watcher.follow(tracker)
		if len(changed) == 0 {
			continue
		}
		body, _ := json.Marshal(stateChange{Type: "StateChange", Changed: changed})
		if gone := h.deliverPush(ctx, subscription, body); gone {
			h.dropGonePush(ctx, actor.ID, subscription.ID, loop)
			return
		}
	}
}

// dropGonePush destroys a subscription the push service no longer knows,
// unless the loop was replaced in the meantime.
func (h *Handler) dropGonePush(ctx context.Context, userID, id string, loop *pushLoop) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pushLoops[userID][id] != loop {
		return
	}
	// Stopping the loop cancels ctx; the store writes must still happen.
	h.stopPushLocked(userID, id)
	ctx = context.WithoutCancel(ctx)
	subscriptions, err := h.loadPushLocked(ctx, userID)
	if err == nil {
		delete(subscriptions, id)
		err = h.savePushLocked(ctx, userID, subscriptions, nil, []string{id})
	}
	if err != nil && !errors.Is(err, store.ErrClosed) {
		logger.Warn("jmap: drop gone push subscription", "user", userID, "subscription", id, "error", err)
	}
}

// deliverPush posts body to the subscription URL. It reports whether the
// push service says the subscription no longer exists.
func (h *Handler) deliverPush(ctx context.Context, s pushSubscription, body []byte) (gone bool) {
	headers := http.Header{"Content-Type": {"application/json; charset=utf-8"}, "TTL": {"86400"}, "Urgency": {"normal"}}
	if s.Keys != nil {
		encrypted, err := encryptPush(*s.Keys, body)
		if err != nil {
			return false
		}
		body = encrypted
		headers.Set("Content-Type", "application/octet-stream")
		headers.Set("Content-Encoding", "aes128gcm")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header = headers
	resp, err := h.pushClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone
}

func decodePushKeys(keys pushKeys) (*ecdh.PublicKey, []byte, error) {
	decode := func(value string) ([]byte, error) {
		return base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "="))
	}
	public, err := decode(keys.P256DH)
	if err != nil {
		return nil, nil, errors.New("keys.p256dh must be base64url")
	}
	key, err := ecdh.P256().NewPublicKey(public)
	if err != nil {
		return nil, nil, errors.New("keys.p256dh must be an uncompressed P-256 point")
	}
	auth, err := decode(keys.Auth)
	if err != nil || len(auth) < 16 {
		return nil, nil, errors.New("keys.auth must be a 16-octet base64url secret")
	}
	return key, auth, nil
}

// encryptPush encrypts a push message body for the user agent (RFC 8291,
// aes128gcm content coding from RFC 8188).
func encryptPush(keys pushKeys, plaintext []byte) ([]byte, error) {
	uaPublic, authSecret, err := decodePushKeys(keys)
	if err != nil {
		return nil, err
	}
	asPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := asPrivate.ECDH(uaPublic)
	if err != nil {
		return nil, err
	}
	asPublic := asPrivate.PublicKey().Bytes()
	keyInfo := append(append([]byte("WebPush: info\x00"), uaPublic.Bytes()...), asPublic...)
	ikm, err := hkdf.Key(sha256.New, shared, authSecret, string(keyInfo), 32)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	cek, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 0, 86)
	header = append(header, salt...)
	header = binary.BigEndian.AppendUint32(header, 4096)
	header = append(header, byte(len(asPublic)))
	header = append(header, asPublic...)
	// A single record: the plaintext followed by the last-record delimiter.
	return gcm.Seal(header, nonce, append(append([]byte{}, plaintext...), 0x02), nil), nil
}
