package jmap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/httpservice"
	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/netguard"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	maxRequestSize  = 10 << 20
	maxObjectsInGet = 1000
	maxObjectsInSet = 500
)

type Authenticator func(context.Context, string, string) (model.User, error)

type Directory interface {
	ListAccounts(context.Context) ([]model.User, error)
	GetAccount(context.Context, string) (model.User, error)
	ListIdentities(context.Context, string) ([]model.EmailAddress, error)
	SetVacation(context.Context, string, bool, time.Time, time.Time, string, string) error
}

type Submitter interface {
	SubmitRawWithOptions(context.Context, model.PrincipalRef, []byte, service.RawSubmissionOptions) (service.SubmissionResult, error)
}

// Authorizer answers the per-collection rights JMAP reports as myRights.
// Without one, collections shared with the actor are reported read-only;
// FolderSpace enforces the real policy on every operation either way.
type Authorizer interface {
	Check(context.Context, authz.Request) (authz.Decision, error)
}

type Config struct {
	Space      service.FolderSpace
	Authorizer Authorizer
	Search     service.SearchReader
	// MailIndex answers Mailbox unread counts from the mail unseen
	// projection; without it the counts come from listing every mailbox.
	MailIndex           *mailindex.Index
	Directory           Directory
	Authenticate        Authenticator
	Submitter           Submitter
	BaseURL             string
	MaxSizeUpload       int64
	MaxConcurrentUpload int
	MaxCallsInRequest   int
	// PushInterval is how often an EventSource connection or push
	// subscription polls the account journals for state changes. When the
	// folder space notifies commits, they wake push at once and the poll is
	// only a fallback, by default every minute.
	PushInterval time.Duration
	// PushClient posts PushSubscription notifications; nil uses a client
	// that refuses private and loopback addresses.
	PushClient *http.Client
	// Accounts opens each account's own index store, where EmailSubmission
	// and PushSubscription records persist.
	Accounts AccountStores
	// State is the system store that indexes which accounts hold such
	// records, for the background sweep and push resumption.
	State store.Store
	// Go runs push delivery on the server background group so it stops
	// before the stores close; nil starts plain goroutines.
	Go func(func(context.Context)) bool
}

type Handler struct {
	cfg Config
	// mu guards push subscription records and their delivery loops.
	mu         sync.Mutex
	pushLoops  map[string]map[string]*pushLoop
	pushClient *http.Client
	// submissionMu orders EmailSubmission state transitions.
	submissionMu sync.Mutex
	retention    atomic.Int64
	// wakes wakes push loops on commits; nil when the folder space sends
	// no commit notifications.
	wakes *pushWakes
}

func New(cfg Config) (*Handler, error) {
	if cfg.Space == nil || cfg.Directory == nil || cfg.Authenticate == nil {
		return nil, errors.New("jmap requires folder space, directory, and authenticator")
	}
	if cfg.Accounts == nil || cfg.State == nil {
		return nil, errors.New("jmap requires account stores and a system state store")
	}
	ctx := context.Background()
	exists, err := cfg.State.NamespaceExists(ctx, stateIndexNamespace)
	if err != nil {
		return nil, fmt.Errorf("check jmap state index: %w", err)
	}
	if !exists {
		if err := cfg.State.CreateNamespace(ctx, stateIndexNamespace); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, fmt.Errorf("create jmap state index: %w", err)
		}
	}
	if cfg.MaxSizeUpload <= 0 {
		cfg.MaxSizeUpload = 50 << 20
	}
	if cfg.MaxConcurrentUpload <= 0 {
		cfg.MaxConcurrentUpload = 4
	}
	if cfg.MaxCallsInRequest <= 0 {
		cfg.MaxCallsInRequest = 64
	}
	notifier, notified := cfg.Space.(service.FolderChangeNotifier)
	if cfg.PushInterval <= 0 {
		cfg.PushInterval = 5 * time.Second
		if notified {
			cfg.PushInterval = notifiedPushInterval
		}
	}
	pushClient := cfg.PushClient
	if pushClient == nil {
		// Push URLs are client-supplied: never reach private networks.
		pushClient = (&netguard.Dialer{}).Client(time.Minute)
	}
	h := &Handler{cfg: cfg, pushLoops: map[string]map[string]*pushLoop{}, pushClient: pushClient}
	if notified {
		// The handler lives as long as the folder space; the listener is
		// never removed.
		h.wakes = &pushWakes{byAccount: map[string]map[*pushWatcher]struct{}{}}
		notifier.OnChangesCommitted(h.wakes.changesCommitted)
	}
	h.SetSubmissionRetention(DefaultSubmissionRetention)
	return h, nil
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("GET /.well-known/jmap", h.auth(http.HandlerFunc(h.session)))
	mux.Handle("POST /jmap/api", h.auth(http.HandlerFunc(h.api)))
	mux.Handle("POST /jmap/upload/{accountId}", h.auth(http.HandlerFunc(h.upload)))
	mux.Handle("GET /jmap/download/{accountId}/{blobId}/{name}", h.auth(http.HandlerFunc(h.download)))
	mux.Handle("GET /jmap/eventsource", h.auth(http.HandlerFunc(h.eventSource)))
}

type authKey struct{}

func (h *Handler) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="JMAP"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		account, err := h.cfg.Authenticate(r.Context(), user, pass)
		if err != nil || !account.Enabled {
			w.Header().Set("WWW-Authenticate", `Basic realm="JMAP"`)
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authKey{}, account)))
	})
}
func actor(r *http.Request) model.User { return r.Context().Value(authKey{}).(model.User) }

func (h *Handler) base(r *http.Request) string {
	if h.cfg.BaseURL != "" {
		return strings.TrimRight(h.cfg.BaseURL, "/")
	}
	client := httpservice.RequestClient(r)
	return client.Scheme() + "://" + client.Host
}

func (h *Handler) capabilities() map[string]Capability {
	return map[string]Capability{
		CoreCapability:       {"maxSizeUpload": h.cfg.MaxSizeUpload, "maxConcurrentUpload": h.cfg.MaxConcurrentUpload, "maxSizeRequest": maxRequestSize, "maxConcurrentRequests": 8, "maxCallsInRequest": h.cfg.MaxCallsInRequest, "maxObjectsInGet": maxObjectsInGet, "maxObjectsInSet": maxObjectsInSet, "collationAlgorithms": []string{"i;ascii-casemap", "i;unicode-casemap"}},
		MailCapability:       {},
		SubmissionCapability: {},
		VacationCapability:   {},
		ContactsCapability:   {},
		CalendarsCapability:  {},
	}
}

func (h *Handler) accounts(ctx context.Context, who model.User) (map[string]Account, error) {
	users, err := h.cfg.Directory.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	result := map[string]Account{}
	for _, candidate := range users {
		access, methodErr := h.validateAccount(ctx, who, candidate.ID)
		if methodErr != nil {
			continue
		}
		owner := access.Subject.ID == candidate.ID
		types := h.accountFolderTypes(ctx, access, candidate.ID)
		capabilities := map[string]any{}
		if types[model.FolderTypeMail] {
			// RFC 8621 §1.3: the mail and submission limits are per account;
			// the Session-level capability objects stay empty.
			capabilities[MailCapability] = map[string]any{"maxMailboxesPerEmail": 1, "maxMailboxDepth": 100, "maxSizeMailboxName": 255,
				"maxSizeAttachmentsPerEmail": h.cfg.MaxSizeUpload, "emailQuerySortOptions": emailSortOptions, "mayCreateTopLevelMailbox": owner}
			capabilities[SubmissionCapability] = map[string]any{"maxDelayedSend": 0, "submissionExtensions": map[string][]string{}}
			capabilities[VacationCapability] = map[string]any{}
		}
		if types[model.FolderTypeContacts] {
			capabilities[ContactsCapability] = map[string]any{"maxAddressBooksPerCard": 1, "mayCreateAddressBook": owner}
		}
		if types[model.FolderTypeCalendar] {
			capabilities[CalendarsCapability] = map[string]any{"maxCalendarsPerEvent": 1, "minDateTime": "1900-01-01T00:00:00Z", "maxDateTime": "2200-01-01T00:00:00Z",
				"maxExpandedQueryDuration": "P400D", "maxParticipantsPerEvent": 200, "mayCreateCalendar": owner}
		}
		result[candidate.ID] = Account{Name: candidate.DisplayName, IsPersonal: candidate.ID == who.ID, IsReadOnly: !owner, AccountCapabilities: capabilities}
	}
	return result, nil
}

func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	who := actor(r)
	accounts, err := h.accounts(r.Context(), who)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	base := h.base(r)
	primary := map[string]string{}
	if _, ok := accounts[who.ID]; ok {
		primary[MailCapability] = who.ID
		primary[SubmissionCapability] = who.ID
		primary[VacationCapability] = who.ID
		primary[ContactsCapability] = who.ID
		primary[CalendarsCapability] = who.ID
	}
	writeJSON(w, Session{Capabilities: h.capabilities(), Accounts: accounts, PrimaryAccounts: primary, Username: who.ID, APIURL: base + "/jmap/api", DownloadURL: base + "/jmap/download/{accountId}/{blobId}/{name}?accept={type}", UploadURL: base + "/jmap/upload/{accountId}", EventSourceURL: base + "/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}", State: h.sessionState(accounts)})
}

func (h *Handler) sessionState(accounts map[string]Account) string {
	ids := make([]string, 0, len(accounts))
	for id := range accounts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, "\x00")))
	return hex.EncodeToString(sum[:12])
}

func (h *Handler) api(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			requestLimit(w, "maxSizeRequest", "request exceeds maxSizeRequest")
			return
		}
		requestProblem(w, http.StatusBadRequest, "urn:ietf:params:jmap:error:notJSON", err.Error())
		return
	}
	if !json.Valid(body) {
		requestProblem(w, http.StatusBadRequest, "urn:ietf:params:jmap:error:notJSON", "request body is not valid JSON")
		return
	}
	req, err := decodeRequest(body)
	if err != nil {
		requestProblem(w, http.StatusBadRequest, "urn:ietf:params:jmap:error:notRequest", err.Error())
		return
	}
	if len(req.MethodCalls) > h.cfg.MaxCallsInRequest {
		requestLimit(w, "maxCallsInRequest", "too many method calls")
		return
	}
	known := h.capabilities()
	using := map[string]bool{CoreCapability: true}
	for _, capability := range req.Using {
		if _, ok := known[capability]; !ok {
			requestProblem(w, http.StatusBadRequest, "urn:ietf:params:jmap:error:unknownCapability", capability)
			return
		}
		using[capability] = true
	}
	echoCreated := req.CreatedIDs != nil
	if req.CreatedIDs == nil {
		req.CreatedIDs = map[string]string{}
	}
	responses := make([]any, 0, len(req.MethodCalls))
	prior := map[string][]methodResult{}
	for _, call := range req.MethodCalls {
		name, args, tag, ok := decodeInvocation(call)
		if !ok {
			requestProblem(w, http.StatusBadRequest, "urn:ietf:params:jmap:error:notRequest", "invalid invocation")
			return
		}
		if capability := methodCapability(name); capability != "" && !using[capability] {
			responses = append(responses, invocation("error", MethodError{Type: "unknownMethod", Description: name + " requires " + capability + " in using"}, tag))
			continue
		}
		resolved, refErr := resolveReferences(args, prior)
		if refErr != nil {
			responses = append(responses, invocation("error", *refErr, tag))
			continue
		}
		resolved = resolveCreationIDs(resolved, req.CreatedIDs)
		result, methodErr := h.dispatch(r.Context(), actor(r), name, resolved, req.CreatedIDs)
		if methodErr != nil {
			responses = append(responses, invocation("error", methodErr, tag))
			continue
		}
		// A method may answer with further implicit responses (RFC 8621
		// §7.5 onSuccessUpdateEmail); they share the call's tag.
		results := []methodResult{{name: name, value: result}}
		if multi, ok := result.(multiResult); ok {
			results = append([]methodResult{{name: name, value: multi.primary}}, multi.extra...)
		}
		for _, one := range results {
			responses = append(responses, invocation(one.name, one.value, tag))
		}
		prior[tag] = append(prior[tag], results...)
	}
	accounts, _ := h.accounts(r.Context(), actor(r))
	response := Response{MethodResponses: responses, SessionState: h.sessionState(accounts)}
	if echoCreated {
		response.CreatedIDs = req.CreatedIDs
	}
	writeJSON(w, response)
}

// decodeRequest checks the Request object shape (RFC 8620 §3.3): using is
// an array of strings and methodCalls an array of invocations.
func decodeRequest(body []byte) (Request, error) {
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(body, &shape); err != nil {
		return Request{}, errors.New("request must be a JSON object")
	}
	var req Request
	if raw, ok := shape["using"]; !ok || json.Unmarshal(raw, &req.Using) != nil || req.Using == nil {
		return Request{}, errors.New("using must be an array of capability strings")
	}
	if raw, ok := shape["methodCalls"]; !ok || json.Unmarshal(raw, &req.MethodCalls) != nil || req.MethodCalls == nil {
		return Request{}, errors.New("methodCalls must be an array of invocations")
	}
	if raw, ok := shape["createdIds"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &req.CreatedIDs); err != nil {
			return Request{}, errors.New("createdIds must be an object of ids")
		}
		if req.CreatedIDs == nil {
			req.CreatedIDs = map[string]string{}
		}
	}
	return req, nil
}

// creationIDArguments are the id-valued arguments in which a "#creationId"
// names an object created earlier in the request (RFC 8620 §5.3).
var creationIDArguments = []string{"ids", "emailIds", "blobIds", "anchor", "emailId"}

func resolveCreationIDs(raw json.RawMessage, created map[string]string) json.RawMessage {
	if len(created) == 0 || !strings.Contains(string(raw), `"#`) {
		return raw
	}
	var args map[string]any
	if json.Unmarshal(raw, &args) != nil {
		return raw
	}
	resolve := func(value any) any {
		if id, ok := value.(string); ok && strings.HasPrefix(id, "#") {
			if real, found := created[id[1:]]; found {
				return real
			}
		}
		return value
	}
	for _, key := range creationIDArguments {
		switch value := args[key].(type) {
		case []any:
			for i := range value {
				value[i] = resolve(value[i])
			}
		case string:
			args[key] = resolve(value)
		}
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		return raw
	}
	return encoded
}

// multiResult carries a method's own response plus implicit responses that
// follow it under the same method call id.
type multiResult struct {
	primary any
	extra   []methodResult
}

// methodCapability names the capability a method belongs to; the client
// must list it in using (RFC 8620 §3.3). Core methods need none.
func methodCapability(name string) string {
	dataType, _, _ := strings.Cut(name, "/")
	switch dataType {
	case "Mailbox", "Email", "Thread", "SearchSnippet":
		return MailCapability
	case "Identity", "EmailSubmission":
		return SubmissionCapability
	case "VacationResponse":
		return VacationCapability
	case "AddressBook", "ContactCard":
		return ContactsCapability
	case "Calendar", "CalendarEvent", "ParticipantIdentity":
		return CalendarsCapability
	}
	return ""
}

func decodeInvocation(call Invocation) (string, json.RawMessage, string, bool) {
	var n, t string
	if json.Unmarshal(call[0], &n) != nil || json.Unmarshal(call[2], &t) != nil || n == "" || t == "" {
		return "", nil, "", false
	}
	return n, call[1], t, true
}
func invocation(name string, args any, tag string) []any { return []any{name, args, tag} }

type methodResult struct {
	name  string
	value any
}

// resolveReferences replaces "#name" arguments with the values their
// ResultReference selects from earlier responses (RFC 8620 §3.7). Like
// Fastmail, it also resolves references nested in argument objects such as
// a filter's "#inMailbox", which clients like jmapc send.
func resolveReferences(raw json.RawMessage, prior map[string][]methodResult) (json.RawMessage, *MethodError) {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, &MethodError{Type: "invalidArguments", Description: "arguments must be a JSON object"}
	}
	if e := resolveObject(value, prior, true); e != nil {
		return nil, e
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, &MethodError{Type: "invalidArguments", Description: err.Error()}
	}
	return encoded, nil
}

// resolveObject resolves the references among value's keys. At the top
// level every "#" key must be a reference; nested, only objects shaped
// like a ResultReference are, so creation-id keys ("#cid": true) stay.
func resolveObject(value map[string]any, prior map[string][]methodResult, top bool) *MethodError {
	for _, key := range sortedKeys(value) {
		v := value[key]
		if !strings.HasPrefix(key, "#") {
			if e := resolveNested(v, prior); e != nil {
				return e
			}
			continue
		}
		m, isObject := v.(map[string]any)
		_, hasResultOf := m["resultOf"].(string)
		if !top && (!isObject || !hasResultOf) {
			continue
		}
		plain := strings.TrimPrefix(key, "#")
		if _, both := value[plain]; both {
			return &MethodError{Type: "invalidArguments", Description: "both " + plain + " and " + key + " are present"}
		}
		if !isObject {
			return &MethodError{Type: "invalidResultReference", Description: key + " is not a result reference"}
		}
		ref := resultReference{}
		b, _ := json.Marshal(m)
		if json.Unmarshal(b, &ref) != nil || ref.ResultOf == "" || ref.Name == "" {
			return &MethodError{Type: "invalidResultReference", Description: "invalid reference " + key}
		}
		var result *methodResult
		for i := range prior[ref.ResultOf] {
			if prior[ref.ResultOf][i].name == ref.Name {
				result = &prior[ref.ResultOf][i]
				break
			}
		}
		if result == nil {
			return &MethodError{Type: "invalidResultReference", Description: "no " + ref.Name + " response for " + ref.ResultOf}
		}
		selected, err := jsonPointer(result.value, ref.Path)
		if err != nil {
			return &MethodError{Type: "invalidResultReference", Description: err.Error()}
		}
		delete(value, key)
		value[plain] = selected
	}
	return nil
}

func resolveNested(value any, prior map[string][]methodResult) *MethodError {
	switch v := value.(type) {
	case map[string]any:
		return resolveObject(v, prior, false)
	case []any:
		for _, element := range v {
			if e := resolveNested(element, prior); e != nil {
				return e
			}
		}
	}
	return nil
}

// jsonPointer evaluates a JSON Pointer with the JMAP "*" extension: on an
// array, "*" applies the rest of the path to every element and flattens
// results that are themselves arrays (RFC 8620 §3.7).
func jsonPointer(value any, path string) (any, error) {
	b, _ := json.Marshal(value)
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	if path == "" {
		return v, nil
	}
	if !strings.HasPrefix(path, "/") {
		return nil, errors.New("result reference path must be a JSON pointer")
	}
	return evalPointer(v, strings.Split(strings.TrimPrefix(path, "/"), "/"), path)
}

func evalPointer(v any, parts []string, path string) (any, error) {
	for index, part := range parts {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch node := v.(type) {
		case map[string]any:
			var ok bool
			v, ok = node[part]
			if !ok {
				return nil, fmt.Errorf("path %s does not exist", path)
			}
		case []any:
			if part == "*" {
				out := []any{}
				for _, element := range node {
					selected, err := evalPointer(element, parts[index+1:], path)
					if err != nil {
						return nil, err
					}
					if list, ok := selected.([]any); ok {
						out = append(out, list...)
					} else {
						out = append(out, selected)
					}
				}
				return out, nil
			}
			position, err := strconv.Atoi(part)
			if err != nil || position < 0 || position >= len(node) || (len(part) > 1 && part[0] == '0') {
				return nil, fmt.Errorf("path %s does not exist", path)
			}
			v = node[position]
		default:
			return nil, fmt.Errorf("path %s is not traversable", path)
		}
	}
	return v, nil
}

func accountAccess(actorID, accountID string) service.AccessContext {
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: actorID}
	subject := model.PrincipalRef{Kind: model.PrincipalUser, ID: accountID}
	mode := authz.ActingNone
	if actorID != accountID {
		mode = authz.ActingDelegation
	}
	return service.AccessContext{Actor: actor, Subject: subject, Mode: mode, Protocol: "jmap", Correlation: "account:" + accountID}
}

func sharedAccess(actorID, accountID string) service.AccessContext {
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: actorID}
	return service.AccessContext{Actor: actor, Subject: actor, Protocol: "jmap", Correlation: "account:" + accountID}
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// requestLimit reports a request-level limit error naming the exceeded
// limit (RFC 8620 §3.6.1).
func requestLimit(w http.ResponseWriter, limit, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:jmap:error:limit", "status": http.StatusBadRequest, "limit": limit, "detail": detail})
}
func requestProblem(w http.ResponseWriter, status int, kind, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": kind, "status": status, "detail": detail})
}
func safeFilename(name string) string {
	name, _ = url.PathUnescape(name)
	name = strings.ReplaceAll(strings.ReplaceAll(name, "\r", ""), "\n", "")
	if name == "" {
		return "download"
	}
	return name
}
func readLimited(r io.Reader, max int64) ([]byte, error) { return io.ReadAll(io.LimitReader(r, max+1)) }
