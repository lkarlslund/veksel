package jmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/sendguard"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// EmailSubmission (RFC 8621 §7). Messages are queued immediately, so every
// submission is final. Submissions persist in the account's store with a
// change history, so get, query and changes stay consistent across restarts;
// history past the retention period, or beyond maxRetainedSubmissions, is
// pruned and reported destroyed.

const maxRetainedSubmissions = 200

type envelopeAddress struct {
	Email      string          `json:"email"`
	Parameters json.RawMessage `json:"parameters,omitempty"`
}

type submissionEnvelope struct {
	MailFrom envelopeAddress   `json:"mailFrom"`
	RcptTo   []envelopeAddress `json:"rcptTo"`
}

// submissionLog is the account's EmailSubmission state counter. Floor is
// the oldest state /changes can follow from; older change entries are gone.
type submissionLog struct {
	State uint64 `json:"state"`
	Floor uint64 `json:"floor"`
}

type storedSubmission struct {
	Object     map[string]any `json:"object"`
	RecordedAt time.Time      `json:"recorded_at"`
}

func (s storedSubmission) id() string {
	id, _ := s.Object["id"].(string)
	return id
}

const (
	changeCreated   = "created"
	changeDestroyed = "destroyed"
)

type submissionChange struct {
	ID   string    `json:"id"`
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
}

func submissionChangeKey(state uint64) string {
	return fmt.Sprintf("%s%020d", submissionChangePrefix, state)
}

func formatSubmissionState(state uint64) string { return fmt.Sprintf("s%d", state) }

func parseSubmissionState(state string) (uint64, bool) {
	if !strings.HasPrefix(state, "s") {
		return 0, false
	}
	value, err := strconv.ParseUint(state[1:], 10, 64)
	return value, err == nil
}

// loadSubmissions reads the account's submissions in send order.
func loadSubmissions(ctx context.Context, index store.Store) (submissionLog, []storedSubmission, error) {
	var state submissionLog
	if _, err := getJSON(ctx, index, submissionStateKey, &state); err != nil {
		return state, nil, err
	}
	var list []storedSubmission
	err := index.Iterate(ctx, stateNamespace, submissionPrefix, func(key string, value []byte) (bool, error) {
		var record storedSubmission
		if err := json.Unmarshal(value, &record); err != nil {
			return false, fmt.Errorf("decode jmap submission %s: %w", key, err)
		}
		list = append(list, record)
		return true, nil
	})
	sort.SliceStable(list, func(i, j int) bool {
		if !list[i].RecordedAt.Equal(list[j].RecordedAt) {
			return list[i].RecordedAt.Before(list[j].RecordedAt)
		}
		return list[i].id() < list[j].id()
	})
	return state, list, err
}

func (h *Handler) readSubmissions(ctx context.Context, accountID string) (submissionLog, []storedSubmission, error) {
	var state submissionLog
	var list []storedSubmission
	err := h.withState(ctx, accountID, false, func(ctx context.Context, index store.Store) error {
		var err error
		state, list, err = loadSubmissions(ctx, index)
		return err
	})
	return state, list, err
}

func appendSubmissionChange(ctx context.Context, index store.Store, state *submissionLog, id, kind string, now time.Time) error {
	state.State++
	return setJSON(ctx, index, submissionChangeKey(state.State), submissionChange{ID: id, Kind: kind, At: now})
}

// pruneSubmissions destroys submissions sent before cutoff and the oldest
// beyond maxRetainedSubmissions, logging each as destroyed.
func pruneSubmissions(ctx context.Context, index store.Store, state *submissionLog, list []storedSubmission, cutoff, now time.Time) ([]storedSubmission, error) {
	excess := len(list) - maxRetainedSubmissions
	var kept []storedSubmission
	for i, record := range list {
		if i >= excess && !record.RecordedAt.Before(cutoff) {
			kept = append(kept, record)
			continue
		}
		if err := deleteKey(ctx, index, stateNamespace, submissionPrefix+record.id()); err != nil {
			return nil, err
		}
		if err := appendSubmissionChange(ctx, index, state, record.id(), changeDestroyed, now); err != nil {
			return nil, err
		}
	}
	return kept, nil
}

// pruneSubmissionChanges drops change entries logged before cutoff or
// beyond maxSubmissionChanges and raises the floor past them. It reports
// how many entries remain.
func pruneSubmissionChanges(ctx context.Context, index store.Store, state *submissionLog, cutoff time.Time) (int, error) {
	type entry struct {
		key string
		at  time.Time
	}
	var entries []entry
	err := index.Iterate(ctx, stateNamespace, submissionChangePrefix, func(key string, value []byte) (bool, error) {
		var change submissionChange
		if err := json.Unmarshal(value, &change); err != nil {
			return false, fmt.Errorf("decode jmap submission change %s: %w", key, err)
		}
		entries = append(entries, entry{key: key, at: change.At})
		return true, nil
	})
	if err != nil {
		return 0, err
	}
	drop := 0
	for drop < len(entries) && (len(entries)-drop > maxSubmissionChanges || entries[drop].at.Before(cutoff)) {
		drop++
	}
	for _, e := range entries[:drop] {
		if err := deleteKey(ctx, index, stateNamespace, e.key); err != nil {
			return 0, err
		}
		if seq, err := strconv.ParseUint(strings.TrimPrefix(e.key, submissionChangePrefix), 10, 64); err == nil && seq > state.Floor {
			state.Floor = seq
		}
	}
	return len(entries) - drop, nil
}

// sweepSubmissions prunes one account's EmailSubmission history and drops
// the account from the index once nothing is left to prune.
func (h *Handler) sweepSubmissions(ctx context.Context, accountID string) error {
	h.submissionMu.Lock()
	defer h.submissionMu.Unlock()
	now := time.Now().UTC()
	cutoff := now.Add(-h.submissionRetention())
	empty := true
	err := h.withState(ctx, accountID, false, func(ctx context.Context, index store.Store) error {
		return store.Batch(ctx, index, func(ctx context.Context) error {
			state, list, err := loadSubmissions(ctx, index)
			if err != nil {
				return err
			}
			before := state
			if list, err = pruneSubmissions(ctx, index, &state, list, cutoff, now); err != nil {
				return err
			}
			changes, err := pruneSubmissionChanges(ctx, index, &state, cutoff)
			if err != nil {
				return err
			}
			empty = len(list) == 0 && changes == 0
			if state == before {
				return nil
			}
			return setJSON(ctx, index, submissionStateKey, state)
		})
	})
	// A purged account reads as empty: its records went with its storage.
	if err != nil || !empty {
		return err
	}
	return h.unmarkIndexed(ctx, indexSubmissionPrefix, accountID)
}

// recordSubmission persists a sent submission and its change entry.
func (h *Handler) recordSubmission(ctx context.Context, accountID string, submission map[string]any) error {
	h.submissionMu.Lock()
	defer h.submissionMu.Unlock()
	if err := h.markIndexed(ctx, indexSubmissionPrefix, accountID); err != nil {
		return err
	}
	now := time.Now().UTC()
	return h.withState(ctx, accountID, true, func(ctx context.Context, index store.Store) error {
		return store.Batch(ctx, index, func(ctx context.Context) error {
			state, list, err := loadSubmissions(ctx, index)
			if err != nil {
				return err
			}
			record := storedSubmission{Object: submission, RecordedAt: now}
			if err := setJSON(ctx, index, submissionPrefix+record.id(), record); err != nil {
				return err
			}
			if err := appendSubmissionChange(ctx, index, &state, record.id(), changeCreated, now); err != nil {
				return err
			}
			if _, err := pruneSubmissions(ctx, index, &state, append(list, record), now.Add(-h.submissionRetention()), now); err != nil {
				return err
			}
			return setJSON(ctx, index, submissionStateKey, state)
		})
	})
}

// destroySubmission deletes a submission record, reporting whether it
// existed.
func (h *Handler) destroySubmission(ctx context.Context, accountID, id string) (bool, error) {
	h.submissionMu.Lock()
	defer h.submissionMu.Unlock()
	removed := false
	err := h.withState(ctx, accountID, false, func(ctx context.Context, index store.Store) error {
		return store.Batch(ctx, index, func(ctx context.Context) error {
			if _, err := index.Get(ctx, stateNamespace, submissionPrefix+id); errors.Is(err, store.ErrNotFound) {
				return nil
			} else if err != nil {
				return err
			}
			var state submissionLog
			if _, err := getJSON(ctx, index, submissionStateKey, &state); err != nil {
				return err
			}
			if err := index.Delete(ctx, stateNamespace, submissionPrefix+id); err != nil {
				return err
			}
			if err := appendSubmissionChange(ctx, index, &state, id, changeDestroyed, time.Now().UTC()); err != nil {
				return err
			}
			removed = true
			return setJSON(ctx, index, submissionStateKey, state)
		})
	})
	return removed, err
}

func (h *Handler) readSubmissionLog(ctx context.Context, accountID string) (submissionLog, error) {
	var state submissionLog
	err := h.withState(ctx, accountID, false, func(ctx context.Context, index store.Store) error {
		_, err := getJSON(ctx, index, submissionStateKey, &state)
		return err
	})
	return state, err
}

func (h *Handler) submissionState(ctx context.Context, accountID string) (string, error) {
	state, err := h.readSubmissionLog(ctx, accountID)
	return formatSubmissionState(state.State), err
}

func (h *Handler) submissionGet(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a getArgs
	if e := decodeGetArgs(raw, &a, func() []string { return a.IDs }); e != nil {
		return nil, e
	}
	if _, e := h.validateAccount(ctx, actor, a.AccountID); e != nil {
		return nil, e
	}
	state, submissions, err := h.readSubmissions(ctx, a.AccountID)
	if err != nil {
		return nil, serverError(err)
	}
	wanted := idSet(a.IDs)
	found := map[string]bool{}
	list := []any{}
	for _, submission := range submissions {
		id := submission.id()
		if wanted == nil || wanted[id] {
			found[id] = true
			list = append(list, selectProperties(submission.Object, a.Properties))
		}
	}
	return map[string]any{"accountId": a.AccountID, "state": formatSubmissionState(state.State), "list": list, "notFound": missing(a.IDs, found)}, nil
}

func (h *Handler) submissionQuery(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a queryArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	if _, e := h.validateAccount(ctx, actor, a.AccountID); e != nil {
		return nil, e
	}
	filter, e := decodeFilter(a.Filter)
	if e != nil {
		return nil, e
	}
	for _, comparator := range a.Sort {
		if comparator.Property != "emailId" && comparator.Property != "threadId" && comparator.Property != "sentAt" {
			return nil, &MethodError{Type: "unsupportedSort", Description: comparator.Property}
		}
	}
	history, submissions, err := h.readSubmissions(ctx, a.AccountID)
	if err != nil {
		return nil, serverError(err)
	}
	state := formatSubmissionState(history.State)
	var filterErr error
	var ids []string
	for _, submission := range submissions {
		row := submission.Object
		matched := evalFilter(filter, func(condition map[string]any) bool {
			for key, value := range condition {
				switch key {
				case "identityIds", "emailIds", "threadIds":
					list, _ := value.([]any)
					property := strings.TrimSuffix(key, "s")
					if !slices.Contains(list, any(row[property])) {
						return false
					}
				case "undoStatus":
					if value != row["undoStatus"] {
						return false
					}
				case "before", "after":
					limit, _ := value.(string)
					sendAt, _ := row["sendAt"].(string)
					if (key == "before") != (sendAt < limit) {
						return false
					}
				default:
					filterErr = fmt.Errorf("unsupported filter condition %q", key)
					return false
				}
			}
			return true
		})
		if matched {
			ids = append(ids, row["id"].(string))
		}
	}
	if filterErr != nil {
		return nil, &MethodError{Type: "unsupportedFilter", Description: filterErr.Error()}
	}
	if ids == nil {
		ids = []string{}
	}
	position, e := queryPosition(ids, len(ids), a)
	if e != nil {
		return nil, e
	}
	return map[string]any{"accountId": a.AccountID, "queryState": state, "canCalculateChanges": false, "position": position, "ids": window(ids, position, a.Limit), "total": len(ids)}, nil
}

// statefulChanges answers /changes for types whose history is not kept:
// an unchanged state has no changes, any other state cannot be followed.
func statefulChanges(raw json.RawMessage, current func(string) (string, *MethodError)) (any, *MethodError) {
	var a changesArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	state, e := current(a.AccountID)
	if e != nil {
		return nil, e
	}
	if a.SinceState == state {
		return emptyChanges(a.AccountID, state), nil
	}
	return nil, &MethodError{Type: "cannotCalculateChanges", Description: "change history is not retained for this type"}
}

// submissionChanges follows the account's EmailSubmission change history from
// any state at or after its floor.
func (h *Handler) submissionChanges(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a changesArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	if _, e := h.validateAccount(ctx, actor, a.AccountID); e != nil {
		return nil, e
	}
	since, ok := parseSubmissionState(a.SinceState)
	limit := 0
	if a.MaxChanges != nil && *a.MaxChanges > 0 {
		limit = *a.MaxChanges
	}
	var history submissionLog
	var changes []submissionChange
	var last uint64
	err := h.withState(ctx, a.AccountID, false, func(ctx context.Context, index store.Store) error {
		if _, err := getJSON(ctx, index, submissionStateKey, &history); err != nil {
			return err
		}
		if !ok || since < history.Floor || since >= history.State {
			return nil
		}
		last = since
		return index.Iterate(ctx, stateNamespace, submissionChangePrefix, func(key string, value []byte) (bool, error) {
			seq, err := strconv.ParseUint(strings.TrimPrefix(key, submissionChangePrefix), 10, 64)
			if err != nil || seq <= since {
				return true, nil
			}
			if limit > 0 && len(changes) >= limit {
				return false, nil
			}
			var change submissionChange
			if err := json.Unmarshal(value, &change); err != nil {
				return false, fmt.Errorf("decode jmap submission change %s: %w", key, err)
			}
			changes = append(changes, change)
			last = seq
			return true, nil
		})
	})
	if err != nil {
		return nil, serverError(err)
	}
	current := formatSubmissionState(history.State)
	switch {
	case ok && since == history.State:
		return emptyChanges(a.AccountID, current), nil
	case !ok || since < history.Floor || since > history.State:
		return nil, &MethodError{Type: "cannotCalculateChanges", Description: "the state is unknown or older than the retained change history"}
	}
	// Fold the window: a submission made and destroyed inside it is omitted.
	first, final := map[string]string{}, map[string]string{}
	var order []string
	for _, change := range changes {
		if _, seen := first[change.ID]; !seen {
			first[change.ID] = change.Kind
			order = append(order, change.ID)
		}
		final[change.ID] = change.Kind
	}
	created, updated, destroyed := []string{}, []string{}, []string{}
	for _, id := range order {
		switch {
		case first[id] == changeCreated && final[id] == changeDestroyed:
		case first[id] == changeCreated:
			created = append(created, id)
		case final[id] == changeDestroyed:
			destroyed = append(destroyed, id)
		default:
			updated = append(updated, id)
		}
	}
	return map[string]any{"accountId": a.AccountID, "oldState": a.SinceState, "newState": formatSubmissionState(last),
		"hasMoreChanges": last < history.State, "created": created, "updated": updated, "destroyed": destroyed}, nil
}

func (h *Handler) identityChanges(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	return statefulChanges(raw, func(accountID string) (string, *MethodError) {
		if _, e := h.validateAccount(ctx, actor, accountID); e != nil {
			return "", e
		}
		identities, err := h.cfg.Directory.ListIdentities(ctx, accountID)
		if err != nil {
			return "", serverError(err)
		}
		return shortState(identityIDs(identities)), nil
	})
}

func (h *Handler) submissionSet(ctx context.Context, actor model.User, raw json.RawMessage, created map[string]string) (any, *MethodError) {
	var a setArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	if h.cfg.Submitter == nil {
		return nil, &MethodError{Type: "serverFail", Description: "submission is unavailable"}
	}
	oldState, err := h.submissionState(ctx, a.AccountID)
	if err != nil {
		return nil, serverError(err)
	}
	if a.IfInState != "" && a.IfInState != oldState {
		return nil, &MethodError{Type: "stateMismatch"}
	}
	identities, err := h.cfg.Directory.ListIdentities(ctx, a.AccountID)
	if err != nil {
		return nil, serverError(err)
	}
	result := newSetResult(a.AccountID, oldState)
	submittedEmail := map[string]string{} // submission id -> email id
	for _, cid := range sortedKeys(a.Create) {
		// A client that files the sent message itself (onSuccessUpdateEmail,
		// typically Drafts to Sent) gets no second, automatic Sent copy.
		// One that destroys its draft, or does nothing, keeps the
		// server's copy.
		_, managed := a.OnSuccessUpdateEmail["#"+cid]
		submission, e := h.createSubmission(ctx, access, actor, a.Create[cid], identities, created, managed)
		if e != nil {
			result.notCreated[cid] = *e
			continue
		}
		id := submission["id"].(string)
		created[cid] = id
		submittedEmail[id] = submission["emailId"].(string)
		result.created[cid] = map[string]any{"id": id, "threadId": submission["threadId"], "sendAt": submission["sendAt"], "undoStatus": "final"}
		// The message is already queued, so a failure to record it must not
		// read as a failed send that the client would retry.
		if err := h.recordSubmission(ctx, a.AccountID, submission); err != nil {
			logger.Error("jmap: record EmailSubmission", "account", a.AccountID, "submission", id, "error", err)
		}
	}
	for _, id := range sortedKeys(a.Update) {
		var patch map[string]any
		if json.Unmarshal(a.Update[id], &patch) != nil {
			result.notUpdated[id] = *invalidProperties("patch must be a JSON object")
			continue
		}
		exists, err := h.hasSubmission(ctx, a.AccountID, resolveCreated(id, created))
		if err != nil {
			result.notUpdated[id] = *serverError(err)
			continue
		}
		if !exists {
			result.notUpdated[id] = MethodError{Type: "notFound"}
			continue
		}
		if status, ok := patch["undoStatus"]; ok && len(patch) == 1 {
			if status == "canceled" {
				result.notUpdated[id] = MethodError{Type: "cannotUnsend", Description: "the message has already been sent"}
			} else if status == "final" {
				result.updated[id] = nil
			} else {
				result.notUpdated[id] = *invalidProperties("undoStatus can only be set to canceled", "undoStatus")
			}
			continue
		}
		result.notUpdated[id] = *invalidProperties("only undoStatus can be changed", "undoStatus")
	}
	for _, id := range a.Destroy {
		removed, err := h.destroySubmission(ctx, a.AccountID, resolveCreated(id, created))
		switch {
		case err != nil:
			result.notDestroyed[id] = *serverError(err)
		case removed:
			result.destroyed = append(result.destroyed, id)
		default:
			result.notDestroyed[id] = MethodError{Type: "notFound"}
		}
	}
	newState, err := h.submissionState(ctx, a.AccountID)
	if err != nil {
		return nil, serverError(err)
	}
	response := result.response(newState)
	implicit := h.onSuccessEmailArgs(a, created, submittedEmail)
	if implicit == nil {
		return response, nil
	}
	// RFC 8621 §7.5: one implicit Email/set follows, under the same call id.
	args, _ := json.Marshal(implicit)
	emailResult, methodErr := h.emailSet(ctx, actor, args, created)
	if methodErr != nil {
		return multiResult{primary: response, extra: []methodResult{{name: "error", value: methodErr}}}, nil
	}
	return multiResult{primary: response, extra: []methodResult{{name: "Email/set", value: emailResult}}}, nil
}

func (h *Handler) hasSubmission(ctx context.Context, accountID, id string) (bool, error) {
	found := false
	err := h.withState(ctx, accountID, false, func(ctx context.Context, index store.Store) error {
		_, err := index.Get(ctx, stateNamespace, submissionPrefix+id)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		found = err == nil
		return err
	})
	return found, err
}

// onSuccessEmailArgs builds the implicit Email/set arguments for the
// submissions that succeeded, or nil when there is nothing to do.
func (h *Handler) onSuccessEmailArgs(a setArgs, created map[string]string, submittedEmail map[string]string) map[string]any {
	emailFor := func(reference string) (string, bool) {
		id := reference
		if strings.HasPrefix(reference, "#") {
			var ok bool
			if id, ok = created[strings.TrimPrefix(reference, "#")]; !ok {
				return "", false
			}
		}
		emailID, ok := submittedEmail[id]
		return emailID, ok
	}
	update := map[string]json.RawMessage{}
	for reference, patch := range a.OnSuccessUpdateEmail {
		if emailID, ok := emailFor(reference); ok {
			update[emailID] = patch
		}
	}
	destroy := []string{}
	for _, reference := range a.OnSuccessDestroyEmail {
		if emailID, ok := emailFor(reference); ok {
			destroy = append(destroy, emailID)
		}
	}
	if len(update) == 0 && len(destroy) == 0 {
		return nil
	}
	return map[string]any{"accountId": a.AccountID, "update": update, "destroy": destroy}
}

func (h *Handler) createSubmission(ctx context.Context, access service.AccessContext, actor model.User, raw json.RawMessage, identities []model.EmailAddress, created map[string]string, managed bool) (map[string]any, *MethodError) {
	var v struct {
		IdentityID string              `json:"identityId"`
		EmailID    string              `json:"emailId"`
		Envelope   *submissionEnvelope `json:"envelope"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, invalidProperties("an EmailSubmission must be a JSON object")
	}
	var identity *model.EmailAddress
	for i := range identities {
		if identities[i].ID == v.IdentityID && identities[i].Enabled {
			identity = &identities[i]
		}
	}
	if identity == nil {
		return nil, invalidProperties("unknown identityId", "identityId")
	}
	items, err := h.mailItemsByID(ctx, access, []string{resolveCreated(v.EmailID, created)})
	if err != nil {
		return nil, serverError(err)
	}
	if len(items) == 0 {
		return nil, invalidProperties("emailId does not name an email", "emailId")
	}
	item := items[0]
	view := newEmailView(item, item.ID, item.Data)
	from, _ := view.property("from", emailOptions{}).([]address)
	if len(from) != 1 || !strings.EqualFold(from[0].Email, identity.ID) {
		return nil, &MethodError{Type: "forbiddenFrom", Description: "the From header must be the identity's address"}
	}
	options := service.RawSubmissionOptions{SkipSentCopy: managed}
	envelope := submissionEnvelope{MailFrom: envelopeAddress{Email: identity.ID}}
	if v.Envelope != nil {
		if !strings.EqualFold(v.Envelope.MailFrom.Email, identity.ID) {
			return nil, &MethodError{Type: "forbiddenMailFrom", Description: "envelope mailFrom must be the identity's address"}
		}
		if len(v.Envelope.RcptTo) == 0 {
			return nil, &MethodError{Type: "noRecipients"}
		}
		for _, recipient := range v.Envelope.RcptTo {
			options.Recipients = append(options.Recipients, recipient.Email)
		}
		envelope = *v.Envelope
	} else {
		for _, property := range []string{"to", "cc", "bcc"} {
			list, _ := view.property(property, emailOptions{}).([]address)
			for _, recipient := range list {
				envelope.RcptTo = append(envelope.RcptTo, envelopeAddress{Email: recipient.Email})
			}
		}
		if len(envelope.RcptTo) == 0 {
			return nil, &MethodError{Type: "noRecipients", Description: "the email has no To, Cc or Bcc recipients"}
		}
	}
	submitted, err := h.cfg.Submitter.SubmitRawWithOptions(ctx, model.PrincipalRef{Kind: model.PrincipalUser, ID: actor.ID}, item.Data, options)
	switch {
	case sendguard.IsQuota(err):
		// RFC 8621 section 7.5: the submission would exceed a sending limit.
		return nil, &MethodError{Type: "rateLimit", Description: err.Error()}
	case err != nil && strings.Contains(err.Error(), "recipient"):
		return nil, &MethodError{Type: "invalidRecipients", Description: err.Error()}
	case err != nil && (strings.Contains(err.Error(), "identity") || strings.Contains(err.Error(), "From") || errors.Is(err, service.ErrForbidden)):
		return nil, &MethodError{Type: "forbiddenFrom", Description: err.Error()}
	case err != nil:
		return nil, serverError(err)
	}
	sendAt := submitted.AcceptedAt
	if sendAt.IsZero() {
		sendAt = time.Now()
	}
	return map[string]any{"id": submitted.ID, "identityId": identity.ID, "emailId": item.ID, "threadId": threadForData(item.Data),
		"envelope": envelope, "sendAt": formatUTCDate(sendAt), "undoStatus": "final", "deliveryStatus": nil,
		"dsnBlobIds": []string{}, "mdnBlobIds": []string{}}, nil
}
