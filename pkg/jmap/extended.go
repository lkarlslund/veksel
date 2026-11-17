package jmap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"mime"
	"net/http"
	"net/mail"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

func (h *Handler) emailCopy(ctx context.Context, actor model.User, raw json.RawMessage, created map[string]string) (any, *MethodError) {
	var a struct {
		FromAccountID            string                     `json:"fromAccountId"`
		AccountID                string                     `json:"accountId"`
		IfFromInState            string                     `json:"ifFromInState"`
		IfInState                string                     `json:"ifInState"`
		Create                   map[string]json.RawMessage `json:"create"`
		OnSuccessDestroyOriginal bool                       `json:"onSuccessDestroyOriginal"`
		DestroyFromIfInState     string                     `json:"destroyFromIfInState"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	if a.FromAccountID == a.AccountID {
		return nil, &MethodError{Type: "invalidArguments", Description: "fromAccountId and accountId must differ", Properties: []string{"fromAccountId"}}
	}
	source, e := h.validateAccount(ctx, actor, a.FromAccountID)
	if e != nil {
		return nil, e
	}
	destination, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	sourceState, stateErr := h.journalState(ctx, source, service.ChangeObjectItem)
	if stateErr != nil {
		return nil, serverError(stateErr)
	}
	destinationState, stateErr := h.journalState(ctx, destination, service.ChangeObjectItem)
	if stateErr != nil {
		return nil, serverError(stateErr)
	}
	if a.IfFromInState != "" && a.IfFromInState != sourceState {
		return nil, &MethodError{Type: "stateMismatch"}
	}
	if a.IfInState != "" && a.IfInState != destinationState {
		return nil, &MethodError{Type: "stateMismatch"}
	}
	made := map[string]any{}
	failed := map[string]any{}
	var copied []string
	for _, cid := range sortedKeys(a.Create) {
		var v struct {
			ID         string          `json:"id"`
			MailboxIDs map[string]bool `json:"mailboxIds"`
			Keywords   map[string]bool `json:"keywords"`
			ReceivedAt *string         `json:"receivedAt"`
		}
		if err := json.Unmarshal(a.Create[cid], &v); err != nil || v.ID == "" {
			failed[cid] = *invalidProperties("a copy needs the source id", "id")
			continue
		}
		folderID, e := singleMailbox(v.MailboxIDs, created)
		if e != nil {
			failed[cid] = *e
			continue
		}
		items, err := h.mailItemsByID(ctx, source, []string{resolveCreated(v.ID, created)})
		if err == nil && len(items) == 0 {
			err = store.ErrNotFound
		}
		if err != nil {
			failed[cid] = *serverError(err)
			continue
		}
		item := items[0]
		date := item.InternalDate
		if v.ReceivedAt != nil {
			if date, err = parseUTCDate(*v.ReceivedAt); err != nil {
				failed[cid] = *invalidProperties("receivedAt must be a UTCDate", "receivedAt")
				continue
			}
		}
		flags := item.Flags
		if v.Keywords != nil {
			flags = keywordFlags(nil, v.Keywords)
		}
		copy, err := h.cfg.Space.CreateItem(ctx, destination, folderID, service.ItemInput{Data: item.Data, Headers: item.Headers, Flags: flags, InternalDate: date})
		if err != nil {
			failed[cid] = *serverError(err)
			continue
		}
		created[cid] = copy.ID
		made[cid] = map[string]any{"id": copy.ID, "blobId": copy.ID, "threadId": threadForData(copy.Data), "size": copy.Size}
		copied = append(copied, item.ID)
	}
	newState, stateErr := h.journalState(ctx, destination, service.ChangeObjectItem)
	if stateErr != nil {
		return nil, serverError(stateErr)
	}
	response := map[string]any{"fromAccountId": a.FromAccountID, "accountId": a.AccountID, "oldState": destinationState, "newState": newState, "created": made, "notCreated": failed}
	if !a.OnSuccessDestroyOriginal || len(copied) == 0 {
		return response, nil
	}
	// RFC 8620 §5.4: the original is destroyed by an implicit Email/set.
	destroy, _ := json.Marshal(map[string]any{"accountId": a.FromAccountID, "ifInState": a.DestroyFromIfInState, "destroy": copied})
	result, methodErr := h.emailSet(ctx, actor, destroy, created)
	if methodErr != nil {
		return multiResult{primary: response, extra: []methodResult{{name: "error", value: methodErr}}}, nil
	}
	return multiResult{primary: response, extra: []methodResult{{name: "Email/set", value: result}}}, nil
}

func threadForData(data []byte) string {
	m, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	return threadID(m.Header)
}

func (h *Handler) emailImport(ctx context.Context, actor model.User, raw json.RawMessage, created map[string]string) (any, *MethodError) {
	var a struct {
		AccountID string `json:"accountId"`
		IfInState string `json:"ifInState"`
		Emails    map[string]struct {
			BlobID     string          `json:"blobId"`
			MailboxIDs map[string]bool `json:"mailboxIds"`
			Keywords   map[string]bool `json:"keywords"`
			ReceivedAt *string         `json:"receivedAt"`
		} `json:"emails"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	if len(a.Emails) > maxObjectsInSet {
		return nil, &MethodError{Type: "requestTooLarge"}
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	oldState, stateErr := h.journalState(ctx, access, service.ChangeObjectItem)
	if stateErr != nil {
		return nil, serverError(stateErr)
	}
	if a.IfInState != "" && a.IfInState != oldState {
		return nil, &MethodError{Type: "stateMismatch"}
	}
	made := map[string]any{}
	failed := map[string]any{}
	for _, cid := range sortedKeys(a.Emails) {
		v := a.Emails[cid]
		folderID, e := singleMailbox(v.MailboxIDs, created)
		if e != nil {
			failed[cid] = *e
			continue
		}
		blobID := resolveCreated(v.BlobID, created)
		data, _, err := h.blobData(ctx, access, blobID)
		if err != nil {
			failed[cid] = MethodError{Type: "blobNotFound", NotFound: []string{v.BlobID}}
			continue
		}
		if fields, _ := parseHeaderBlock(data); len(fields) == 0 {
			failed[cid] = MethodError{Type: "invalidEmail", Description: "blob is not an RFC 5322 message"}
			continue
		}
		var date time.Time
		if v.ReceivedAt != nil {
			if date, err = parseUTCDate(*v.ReceivedAt); err != nil {
				failed[cid] = *invalidProperties("receivedAt must be a UTCDate", "receivedAt")
				continue
			}
		}
		item, err := h.cfg.Space.CreateItem(ctx, access, folderID, service.ItemInput{Data: data, Headers: messageHeaders(data), Flags: keywordFlags(nil, v.Keywords), InternalDate: date})
		if err != nil {
			failed[cid] = *serverError(err)
			continue
		}
		created[cid] = item.ID
		made[cid] = map[string]any{"id": item.ID, "blobId": item.ID, "threadId": threadForData(item.Data), "size": item.Size}
	}
	newState, stateErr := h.journalState(ctx, access, service.ChangeObjectItem)
	if stateErr != nil {
		return nil, serverError(stateErr)
	}
	return map[string]any{"accountId": a.AccountID, "oldState": oldState, "newState": newState, "created": made, "notCreated": failed}, nil
}

func messageHeaders(data []byte) map[string]string {
	m, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for k := range m.Header {
		out[k] = m.Header.Get(k)
	}
	return out
}

func (h *Handler) emailParse(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a struct {
		AccountID  string   `json:"accountId"`
		BlobIDs    []string `json:"blobIds"`
		Properties []string `json:"properties"`
		emailFetchArgs
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	opts, e := a.options(a.Properties, defaultParseProperties)
	if e != nil {
		return nil, e
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	parsed := map[string]any{}
	notParsable := []string{}
	notFound := []string{}
	for _, id := range a.BlobIDs {
		data, _, err := h.blobData(ctx, access, id)
		if err != nil {
			notFound = append(notFound, id)
			continue
		}
		if fields, _ := parseHeaderBlock(data); len(fields) == 0 {
			notParsable = append(notParsable, id)
			continue
		}
		parsed[id] = newEmailView(model.Item{}, id, data).object(opts)
	}
	return map[string]any{"accountId": a.AccountID, "parsed": parsed, "notParsable": notParsable, "notFound": notFound}, nil
}

// searchSnippetGet highlights the filter's text, subject and body terms in
// each email's subject and preview; a field without a match is null.
func (h *Handler) searchSnippetGet(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a struct {
		AccountID string          `json:"accountId"`
		Filter    json.RawMessage `json:"filter"`
		EmailIDs  []string        `json:"emailIds"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	if len(a.EmailIDs) > maxObjectsInGet {
		return nil, &MethodError{Type: "requestTooLarge"}
	}
	filter, e := decodeFilter(a.Filter)
	if e != nil {
		return nil, e
	}
	if err := validateEmailFilter(filter); err != nil {
		return nil, &MethodError{Type: "unsupportedFilter", Description: err.Error()}
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	subjectTerms, bodyTerms := snippetTerms(filter)
	items, err := h.mailItemsByID(ctx, access, a.EmailIDs)
	if err != nil {
		return nil, serverError(err)
	}
	byID := map[string]model.Item{}
	for _, item := range items {
		byID[item.ID] = item
	}
	list := []any{}
	notFound := []string{}
	for _, id := range a.EmailIDs {
		item, ok := byID[id]
		if !ok {
			notFound = append(notFound, id)
			continue
		}
		view := newEmailView(item, item.ID, item.Data)
		subject, _ := view.property("subject", emailOptions{}).(string)
		list = append(list, map[string]any{"emailId": id, "subject": highlightTerms(subject, subjectTerms), "preview": highlightTerms(view.preview(), bodyTerms)})
	}
	return map[string]any{"accountId": a.AccountID, "list": list, "notFound": notFound}, nil
}

// snippetTerms collects the search terms of a filter, skipping NOT.
func snippetTerms(filter map[string]any) (subject, body []string) {
	if filter == nil {
		return nil, nil
	}
	if operator, ok := filter["operator"].(string); ok {
		if operator == "NOT" {
			return nil, nil
		}
		conditions, _ := filter["conditions"].([]any)
		for _, condition := range conditions {
			child, _ := condition.(map[string]any)
			s, b := snippetTerms(child)
			subject, body = append(subject, s...), append(body, b...)
		}
		return subject, body
	}
	if value, _ := filter["text"].(string); value != "" {
		subject, body = append(subject, value), append(body, value)
	}
	if value, _ := filter["subject"].(string); value != "" {
		subject = append(subject, value)
	}
	if value, _ := filter["body"].(string); value != "" {
		body = append(body, value)
	}
	return subject, body
}

// highlightTerms returns value as HTML with the first matching term marked,
// or nil when no term matches.
func highlightTerms(value string, terms []string) any {
	for _, term := range terms {
		if start, _ := model.IndexFold(value, term); start >= 0 {
			return highlight(value, term)
		}
	}
	return nil
}

func highlight(value, needle string) string {
	if needle == "" {
		return html.EscapeString(value)
	}
	// The match range must index value itself, not a lowered copy whose
	// byte offsets drift once lowering changes a rune's length.
	start, end := model.IndexFold(value, needle)
	if start < 0 {
		return html.EscapeString(value)
	}
	return html.EscapeString(value[:start]) + "<mark>" + html.EscapeString(value[start:end]) + "</mark>" + html.EscapeString(value[end:])
}

func (h *Handler) identityGet(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a getArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	if access.Subject.ID != a.AccountID {
		return nil, &MethodError{Type: "forbidden", Description: "identity discovery requires account delegation"}
	}
	identities, err := h.cfg.Directory.ListIdentities(ctx, a.AccountID)
	if err != nil {
		return nil, serverError(err)
	}
	owner, err := h.cfg.Directory.GetAccount(ctx, a.AccountID)
	if err != nil {
		return nil, serverError(err)
	}
	wanted := idSet(a.IDs)
	found := map[string]bool{}
	list := []any{}
	for _, id := range identities {
		if !id.Enabled || (wanted != nil && !wanted[id.ID]) {
			continue
		}
		found[id.ID] = true
		identity := map[string]any{"id": id.ID, "name": owner.DisplayName, "email": id.ID, "replyTo": nil, "bcc": nil, "textSignature": "", "htmlSignature": "", "mayDelete": false}
		list = append(list, selectProperties(identity, a.Properties))
	}
	return map[string]any{"accountId": a.AccountID, "state": shortState(identityIDs(identities)), "list": list, "notFound": missing(a.IDs, found)}, nil
}
func identityIDs(ids []model.EmailAddress) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.ID)
	}
	sort.Strings(out)
	return out
}

func (h *Handler) vacationGet(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a getArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	if access.Subject.ID != a.AccountID {
		return nil, &MethodError{Type: "forbidden"}
	}
	u, err := h.cfg.Directory.GetAccount(ctx, a.AccountID)
	if err != nil {
		return nil, serverError(err)
	}
	list := []any{}
	if a.IDs == nil || idSet(a.IDs)["singleton"] {
		list = append(list, map[string]any{"id": "singleton", "isEnabled": u.VacationEnabled, "fromDate": dateOnly(u.VacationStart), "toDate": dateOnly(u.VacationEnd), "subject": u.VacationSubject, "textBody": u.VacationMessage, "htmlBody": nil})
	}
	notFound := []string{}
	for _, id := range a.IDs {
		if id != "singleton" {
			notFound = append(notFound, id)
		}
	}
	return map[string]any{"accountId": a.AccountID, "state": vacationState(u), "list": list, "notFound": notFound}, nil
}
func (h *Handler) vacationSet(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a setArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	if access.Subject.ID != a.AccountID {
		return nil, &MethodError{Type: "forbidden"}
	}
	before, err := h.cfg.Directory.GetAccount(ctx, a.AccountID)
	if err != nil {
		return nil, serverError(err)
	}
	if a.IfInState != "" && a.IfInState != vacationState(before) {
		return nil, &MethodError{Type: "stateMismatch"}
	}
	updated := map[string]any{}
	notUpdated := map[string]any{}
	if patch, ok := a.Update["singleton"]; ok {
		var v struct {
			IsEnabled *bool   `json:"isEnabled"`
			FromDate  *string `json:"fromDate"`
			ToDate    *string `json:"toDate"`
			Subject   *string `json:"subject"`
			TextBody  *string `json:"textBody"`
			HTMLBody  *string `json:"htmlBody"`
		}
		if json.Unmarshal(patch, &v) != nil {
			notUpdated["singleton"] = MethodError{Type: "invalidProperties"}
		} else {
			enabled := before.VacationEnabled
			if v.IsEnabled != nil {
				enabled = *v.IsEnabled
			}
			start, end := before.VacationStart, before.VacationEnd
			if v.FromDate != nil {
				start, _ = time.Parse("2006-01-02", *v.FromDate)
			}
			if v.ToDate != nil {
				end, _ = time.Parse("2006-01-02", *v.ToDate)
			}
			subject := before.VacationSubject
			if v.Subject != nil {
				subject = *v.Subject
			}
			body := before.VacationMessage
			if v.TextBody != nil {
				body = *v.TextBody
			} else if v.HTMLBody != nil {
				body = *v.HTMLBody
			}
			if err := h.cfg.Directory.SetVacation(ctx, a.AccountID, enabled, start, end, subject, body); err != nil {
				notUpdated["singleton"] = *serverError(err)
			} else {
				updated["singleton"] = nil
			}
		}
	}
	after, _ := h.cfg.Directory.GetAccount(ctx, a.AccountID)
	return map[string]any{"accountId": a.AccountID, "oldState": vacationState(before), "newState": vacationState(after), "created": map[string]any{}, "notCreated": map[string]any{}, "updated": updated, "notUpdated": notUpdated, "destroyed": []string{}, "notDestroyed": map[string]any{}}, nil
}
func vacationState(u model.User) string {
	return shortState([]string{u.ID, fmt.Sprint(u.VacationEnabled), u.VacationStart.String(), u.VacationEnd.String(), u.VacationSubject, u.VacationMessage})
}
func dateOnly(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Format("2006-01-02")
}
func randomID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func (h *Handler) blobCopy(ctx context.Context, actor model.User, raw json.RawMessage, created map[string]string) (any, *MethodError) {
	var a struct {
		FromAccountID string   `json:"fromAccountId"`
		AccountID     string   `json:"accountId"`
		BlobIDs       []string `json:"blobIds"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	source, e := h.validateAccount(ctx, actor, a.FromAccountID)
	if e != nil {
		return nil, e
	}
	dest, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	files, err := h.cfg.Space.GetFolderByPath(ctx, dest, "Files")
	if err != nil {
		return nil, serverError(err)
	}
	copied := map[string]string{}
	notCopied := map[string]any{}
	for _, id := range a.BlobIDs {
		item, err := h.cfg.Space.GetItem(ctx, source, id)
		if err == nil {
			item, err = h.cfg.Space.CreateItem(ctx, dest, files.ID, service.ItemInput{Name: "jmap-" + randomID("blob-"), Data: item.Data, Headers: item.Headers})
		}
		if err != nil {
			notCopied[id] = *serverError(err)
		} else {
			copied[id] = item.ID
		}
	}
	return map[string]any{"fromAccountId": a.FromAccountID, "accountId": a.AccountID, "copied": copied, "notCopied": notCopied}, nil
}

func (h *Handler) upload(w http.ResponseWriter, r *http.Request) {
	who := actor(r)
	access, e := h.validateAccount(r.Context(), who, r.PathValue("accountId"))
	if e != nil {
		requestProblem(w, 404, "urn:ietf:params:jmap:error:accountNotFound", "")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.cfg.MaxSizeUpload)
	data, err := readLimited(r.Body, h.cfg.MaxSizeUpload)
	if err != nil || int64(len(data)) > h.cfg.MaxSizeUpload {
		requestLimit(w, "maxSizeUpload", "upload exceeds maxSizeUpload")
		return
	}
	folder, err := h.cfg.Space.GetFolderByPath(r.Context(), access, "Files")
	if err != nil {
		http.Error(w, "file collection unavailable", 500)
		return
	}
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	item, err := h.cfg.Space.CreateItem(r.Context(), access, folder.ID, service.ItemInput{Name: "jmap-" + randomID("blob-"), Data: data, Headers: map[string]string{"Content-Type": contentType}})
	if err != nil {
		http.Error(w, "upload forbidden", http.StatusForbidden)
		return
	}
	// RFC 8620 §6.1: a successful upload answers 201 Created.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"accountId": r.PathValue("accountId"), "blobId": item.ID, "type": contentType, "size": len(data)})
}

func (h *Handler) download(w http.ResponseWriter, r *http.Request) {
	who := actor(r)
	access, e := h.validateAccount(r.Context(), who, r.PathValue("accountId"))
	if e != nil {
		http.NotFound(w, r)
		return
	}
	data, contentType, err := h.blobData(r.Context(), access, r.PathValue("blobId"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// The client names the type in the downloadUrl {type} variable.
	if accept := r.URL.Query().Get("accept"); accept != "" {
		if mediaType, _, err := mime.ParseMediaType(accept); err == nil && strings.Contains(mediaType, "/") {
			contentType = accept
		}
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": safeFilename(r.PathValue("name"))}))
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	w.Header().Set("Cache-Control", "private, immutable, max-age=31536000")
	_, _ = w.Write(data)
}

func splitBlobID(id string) (string, string) {
	if i := strings.LastIndex(id, "-"); i > 0 && strings.Contains(id[i+1:], ".") {
		return id[:i], id[i+1:]
	}
	return id, ""
}
