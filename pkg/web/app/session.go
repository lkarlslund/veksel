package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	sessionLifetime         = 7 * 24 * time.Hour
	sessionActivityInterval = time.Minute
	maxBrowserSessions      = 100
	// pendingSignInLifetime bounds how long a password-verified sign-in may
	// wait for its second factor or required enrolment.
	pendingSignInLifetime = 5 * time.Minute
	// maxSecondFactorFailures ends a pending sign-in, forcing a new password
	// check, independently of the shared failed-login throttle.
	maxSecondFactorFailures = 5
)

// Pending sign-in states; see model.Session.SecondFactor.
const (
	secondFactorVerify = "verify"
	secondFactorEnrol  = "enrol"
)

var errCurrentSession = errors.New("current browser session cannot be revoked here")

type sessionStore struct {
	ts *model.TypedStore
	mu sync.Mutex
}

func newSessionStore(ts *model.TypedStore) *sessionStore { return &sessionStore{ts: ts} }

func (s *sessionStore) Create(ctx context.Context, userID, csrfToken, ip, userAgent string) (string, error) {
	return s.create(ctx, userID, csrfToken, ip, userAgent, "")
}

// CreatePending records a sign-in in a second-factor state. Get and
// ActiveByID never return it; only GetPending does.
func (s *sessionStore) CreatePending(ctx context.Context, userID, csrfToken, ip, userAgent, state string) (string, error) {
	return s.create(ctx, userID, csrfToken, ip, userAgent, state)
}

func (s *sessionStore) create(ctx context.Context, userID, csrfToken, ip, userAgent, state string) (string, error) {
	if _, err := s.ts.UserStore().RequireInteractive(ctx, userID); errors.Is(err, model.ErrResourceAccount) {
		return "", err
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	lifetime := sessionLifetime
	if state != "" {
		lifetime = pendingSignInLifetime
	}
	session := model.Session{
		ID: tokenHash(token), User: userID, ActorID: userID, SubjectID: userID,
		CSRFTokenHash: tokenHash(csrfToken), IP: sessionIP(ip), UserAgent: boundedString(userAgent, 1024),
		CreatedAt: now, LastActivity: now, ExpiresAt: now.Add(lifetime), SecondFactor: state,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err = store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		existing, listErr := s.listByActorLocked(batchCtx, userID, now)
		if listErr != nil {
			return listErr
		}
		if remove := len(existing) - maxBrowserSessions + 1; remove > 0 {
			slices.SortFunc(existing, compareSessionOldest)
			for _, candidate := range existing[:remove] {
				if deleteErr := s.ts.Delete(batchCtx, model.NSSessions, candidate.ID); deleteErr != nil {
					return deleteErr
				}
			}
		}
		return s.ts.Put(batchCtx, model.NSSessions, session.ID, session)
	})
	if err != nil {
		return "", fmt.Errorf("store session: %w", err)
	}
	return token, nil
}

func (s *sessionStore) Get(ctx context.Context, token string) (model.Session, error) {
	if token == "" {
		return model.Session{}, store.ErrNotFound
	}
	return s.getFull(ctx, tokenHash(token))
}

// GetPending returns a sign-in still awaiting its second factor.
func (s *sessionStore) GetPending(ctx context.Context, token string) (model.Session, error) {
	if token == "" {
		return model.Session{}, store.ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, err := s.getByIDLocked(ctx, tokenHash(token), time.Now().UTC(), false)
	if err == nil && session.SecondFactor == "" {
		return model.Session{}, store.ErrNotFound
	}
	return session, err
}

// RecordSecondFactorFailure counts a failed second-factor attempt and ends
// the pending sign-in once maxSecondFactorFailures is reached. It reports
// whether the sign-in remains usable.
func (s *sessionStore) RecordSecondFactorFailure(ctx context.Context, token string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, err := s.getByIDLocked(ctx, tokenHash(token), time.Now().UTC(), false)
	if err != nil || session.SecondFactor == "" {
		return false, err
	}
	session.SecondFactorFailures++
	if session.SecondFactorFailures >= maxSecondFactorFailures {
		return false, s.ts.Delete(ctx, model.NSSessions, session.ID)
	}
	return true, s.ts.Set(ctx, model.NSSessions, session.ID, session)
}

// getFull returns a completed session; pending sign-ins are not sessions.
func (s *sessionStore) getFull(ctx context.Context, id string) (model.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, err := s.getByIDLocked(ctx, id, time.Now().UTC(), true)
	if err == nil && session.SecondFactor != "" {
		return model.Session{}, store.ErrNotFound
	}
	return session, err
}

func (s *sessionStore) Delete(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.ts.Delete(ctx, model.NSSessions, tokenHash(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

func (s *sessionStore) SetActing(ctx context.Context, token, subjectID, mode, reason string, expiresAt time.Time) (model.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, err := s.getByIDLocked(ctx, tokenHash(token), time.Now().UTC(), true)
	if err == nil && session.SecondFactor != "" {
		err = store.ErrNotFound
	}
	if err != nil {
		return model.Session{}, err
	}
	if subjectID == "" || subjectID == session.ActorID {
		subjectID = session.ActorID
		mode = ""
		reason = ""
		expiresAt = time.Time{}
	}
	session.SubjectID = subjectID
	session.ActingMode = mode
	session.ActingReason = reason
	session.ActingExpiresAt = expiresAt
	if err := s.ts.Set(ctx, model.NSSessions, session.ID, session); err != nil {
		return model.Session{}, fmt.Errorf("update session acting state: %w", err)
	}
	return session, nil
}

// ActiveByID validates and lightly touches an already hashed session ID. It is
// used by upgraded connections that no longer carry ordinary HTTP middleware.
func (s *sessionStore) ActiveByID(ctx context.Context, id string) (model.Session, error) {
	return s.getFull(ctx, id)
}

func (s *sessionStore) ListByActor(ctx context.Context, actorID string) ([]model.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sessions []model.Session
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		var err error
		sessions, err = s.listByActorLocked(batchCtx, actorID, time.Now().UTC())
		return err
	})
	sessions = slices.DeleteFunc(sessions, func(session model.Session) bool { return session.SecondFactor != "" })
	slices.SortFunc(sessions, func(left, right model.Session) int { return -compareSessionOldest(left, right) })
	return sessions, err
}

func (s *sessionStore) DeleteOwned(ctx context.Context, actorID, id, currentID string) (model.Session, error) {
	if !validSessionID(id) {
		return model.Session{}, store.ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, err := s.getByIDLocked(ctx, id, time.Now().UTC(), false)
	if err != nil || !strings.EqualFold(session.ActorID, actorID) {
		return model.Session{}, store.ErrNotFound
	}
	if session.ID == currentID {
		return model.Session{}, errCurrentSession
	}
	if err := s.ts.Delete(ctx, model.NSSessions, session.ID); err != nil {
		return model.Session{}, err
	}
	return session, nil
}

func (s *sessionStore) DeleteOthers(ctx context.Context, actorID, currentID string) ([]model.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var deleted []model.Session
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		var err error
		deleted, err = s.deleteOthersLocked(batchCtx, actorID, currentID, time.Now().UTC())
		return err
	})
	return deleted, err
}

// UpdateActorAndDeleteOthers commits an account-security update and its
// browser-session invalidation in the same backend transaction. The callback
// must only mutate the same TypedStore and must honor the supplied context.
func (s *sessionStore) UpdateActorAndDeleteOthers(ctx context.Context, actorID, currentID string, update func(context.Context) error) ([]model.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var deleted []model.Session
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		if err := update(batchCtx); err != nil {
			return err
		}
		var err error
		deleted, err = s.deleteOthersLocked(batchCtx, actorID, currentID, time.Now().UTC())
		return err
	})
	return deleted, err
}

func (s *sessionStore) deleteOthersLocked(ctx context.Context, actorID, currentID string, now time.Time) ([]model.Session, error) {
	sessions, err := s.listByActorLocked(ctx, actorID, now)
	if err != nil {
		return nil, err
	}
	deleted := make([]model.Session, 0, len(sessions))
	for _, session := range sessions {
		if session.ID == currentID {
			continue
		}
		if err := s.ts.Delete(ctx, model.NSSessions, session.ID); err != nil {
			return nil, err
		}
		deleted = append(deleted, session)
	}
	return deleted, nil
}

func (s *sessionStore) getByIDLocked(ctx context.Context, id string, now time.Time, touch bool) (model.Session, error) {
	if !validSessionID(id) {
		return model.Session{}, store.ErrNotFound
	}
	var session model.Session
	if err := s.ts.Get(ctx, model.NSSessions, id, &session); err != nil {
		return model.Session{}, err
	}
	changed := normalizeBrowserSession(&session)
	if session.ID != id {
		session.ID = id
		changed = true
	}
	if session.ActorID == "" || !session.ExpiresAt.After(now) {
		_ = s.ts.Delete(ctx, model.NSSessions, id)
		return model.Session{}, store.ErrNotFound
	}
	if touch && now.Sub(session.LastActivity) >= sessionActivityInterval {
		session.LastActivity = now
		changed = true
	}
	if changed {
		if err := s.ts.Set(ctx, model.NSSessions, session.ID, session); err != nil {
			return model.Session{}, fmt.Errorf("update session: %w", err)
		}
	}
	return session, nil
}

func (s *sessionStore) listByActorLocked(ctx context.Context, actorID string, now time.Time) ([]model.Session, error) {
	keys, err := s.ts.List(ctx, model.NSSessions)
	if errors.Is(err, store.ErrNotFound) {
		return []model.Session{}, nil
	}
	if err != nil {
		return nil, err
	}
	actorID = strings.ToLower(strings.TrimSpace(actorID))
	result := make([]model.Session, 0)
	for _, key := range keys {
		if !validSessionID(key) {
			continue
		}
		var session model.Session
		if err := s.ts.Get(ctx, model.NSSessions, key, &session); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return nil, err
		}
		changed := normalizeBrowserSession(&session)
		if session.ID != key {
			session.ID = key
			changed = true
		}
		if session.ActorID == "" || !session.ExpiresAt.After(now) {
			if err := s.ts.Delete(ctx, model.NSSessions, key); err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
			continue
		}
		if changed {
			if err := s.ts.Set(ctx, model.NSSessions, session.ID, session); err != nil {
				return nil, err
			}
		}
		if strings.EqualFold(session.ActorID, actorID) {
			result = append(result, session)
		}
	}
	return result, nil
}

// RecentSubjects returns the mailboxes of full browser sessions active since
// since, most recently active first and at most limit. It only reads; expired
// sessions are pruned elsewhere.
func (s *sessionStore) RecentSubjects(ctx context.Context, since time.Time, limit int) ([]string, error) {
	keys, err := s.ts.List(ctx, model.NSSessions)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	latest := make(map[string]time.Time)
	for _, key := range keys {
		var session model.Session
		if !validSessionID(key) || s.ts.Get(ctx, model.NSSessions, key, &session) != nil {
			continue
		}
		normalizeBrowserSession(&session)
		if session.SecondFactor != "" || session.SubjectID == "" || session.LastActivity.Before(since) || !session.ExpiresAt.After(time.Now()) {
			continue
		}
		subject := strings.ToLower(session.SubjectID)
		if session.LastActivity.After(latest[subject]) {
			latest[subject] = session.LastActivity
		}
	}
	subjects := make([]string, 0, len(latest))
	for subject := range latest {
		subjects = append(subjects, subject)
	}
	slices.SortFunc(subjects, func(left, right string) int { return latest[right].Compare(latest[left]) })
	return subjects[:min(len(subjects), limit)], nil
}

func normalizeBrowserSession(session *model.Session) bool {
	changed := false
	if session.ActorID == "" && session.User != "" {
		session.ActorID = strings.ToLower(strings.TrimSpace(session.User))
		changed = true
	}
	if session.User == "" && session.ActorID != "" {
		session.User = session.ActorID
		changed = true
	}
	if session.SubjectID == "" && session.ActorID != "" {
		session.SubjectID = session.ActorID
		changed = true
	}
	if session.ExpiresAt.IsZero() && !session.CreatedAt.IsZero() {
		session.ExpiresAt = session.CreatedAt.Add(sessionLifetime)
		changed = true
	}
	return changed
}

func compareSessionOldest(left, right model.Session) int {
	leftActivity, rightActivity := left.LastActivity, right.LastActivity
	if leftActivity.IsZero() {
		leftActivity = left.CreatedAt
	}
	if rightActivity.IsZero() {
		rightActivity = right.CreatedAt
	}
	if compared := leftActivity.Compare(rightActivity); compared != 0 {
		return compared
	}
	return strings.Compare(left.ID, right.ID)
}

func validSessionID(id string) bool {
	if len(id) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func sessionIP(remote string) string {
	remote = strings.TrimSpace(remote)
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	return boundedString(remote, 200)
}

func boundedString(value string, limit int) string {
	value = strings.ToValidUTF8(strings.TrimSpace(value), "�")
	if len(value) > limit {
		value = value[:limit]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value
}

func (s *sessionStore) ValidCSRF(session model.Session, token string) bool {
	want := []byte(session.CSRFTokenHash)
	got := []byte(tokenHash(token))
	return len(want) == len(got) && subtle.ConstantTimeCompare(want, got) == 1
}

func randomToken() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
