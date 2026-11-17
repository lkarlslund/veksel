// Package caldav provides CalDAV (RFC 4791), CardDAV (RFC 6352) and WebDAV (RFC 4918) HTTP handlers.
//
// It is mounted under /dav/* on the main HTTP server and handles:
//
//   - WebDAV base methods: PROPFIND, PROPPATCH, MKCOL, MOVE, COPY, LOCK, UNLOCK
//   - CalDAV extensions: MKCALENDAR, calendar-query, multiget
//   - CardDAV extensions: addressbook MKCOL, addressbook-query, multiget
//   - Calendar object operations: PUT, DELETE, GET for VEVENT items
//   - Contact object operations: PUT, DELETE, GET for vCard items
//
// The handler uses the Veksel model layer (Folders + Items) for persistence.
// Calendar collections map to Folders of type "calendar", addressbooks map to
// Folders of type "contacts", and objects (VEVENTs, vCards) map to Items.
package caldav

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/calendarindex"
	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

var log = logpkg.For(logpkg.ModuleCalDAV)

// TypedStore documents the model capabilities accepted by legacy embedded
// callers. DAV payload operations are adapted to FolderSpace by New.
type TypedStore interface {
	FolderStore() *model.FolderStore
	ItemStore() *model.ItemStore
	UserStore() *model.UserStore
}

// Config holds optional configuration for the CalDAV handler.
type Config struct {
	// ServerName is used in DAV responses (e.g. in hrefs).
	ServerName string

	// Metrics is the optional metrics collector.
	Metrics *metrics.Metrics

	// MaxWebdavFileSize is the maximum allowed file size for WebDAV file uploads (bytes).
	// 0 means no limit. Default is 100 MB.
	MaxWebdavFileSize int64

	// Authorizer enables canonical folder policy for cross-account DAV access.
	Authorizer *authz.Engine

	// CalendarIndex answers free-busy-query from the shared calendar range
	// projection. Production passes the web app's index so the projection
	// is built and sealed once; nil builds an unsealed index over the store.
	CalendarIndex *calendarindex.Index

	// ResolveRecipient routes a schedule-outbox recipient through the
	// unified recipient resolver; store.ErrNotFound means the address is
	// not local. Nil resolves through the store without subaddressing.
	ResolveRecipient func(context.Context, string) (model.RecipientRoute, error)

	// AttendeeReply sends the calendar owner's answer (ACCEPTED, DECLINED,
	// or TENTATIVE) to the organizer of the event stored as itemID and
	// records it in the owner's copy. With implicit scheduling (RFC 6638
	// §3.2.2) the server replies when an attendee changes its PARTSTAT over
	// CalDAV; nil leaves such changes unanswered.
	AttendeeReply func(ctx context.Context, ownerID, itemID, partStat string) error
}

type authenticatedUserKey struct{}

// freeBusyOnlyKey marks a cross-account REPORT the actor may answer only
// as a free-busy-query: it holds free/busy permission but not item read.
type freeBusyOnlyKey struct{}

var errFreeBusyOnly = errors.New("free/busy access only")

type davErrorStateKey struct{}

type davErrorState struct{ special error }

func noteDAVError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if state, _ := ctx.Value(davErrorStateKey{}).(*davErrorState); state != nil &&
		(service.IsTemporarilyUnavailable(err) || errors.Is(err, model.ErrQuotaExceeded)) {
		state.special = err
	}
	return err
}

// WithAuthenticatedUser records the Basic-auth principal for authorization.
func WithAuthenticatedUser(r *http.Request, userID string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), authenticatedUserKey{}, userID))
}

// Handler serves CalDAV and WebDAV requests.
type Handler struct {
	store  *folderSpaceStore
	config *Config
	// calendars and authorizer answer free-busy-query: the range index
	// supplies busy time, the authorizer the read-free-busy privilege.
	calendars  *calendarindex.Index
	authorizer *authz.Engine
	// typed and domains resolve schedule-outbox recipients without a
	// configured resolver and tell hosted domains from remote ones.
	typed   *model.TypedStore
	domains *model.DomainStore
	// maxFileSize is the live WebDAV upload limit (Config.MaxWebdavFileSize
	// until SetMaxWebdavFileSize changes it).
	maxFileSize atomic.Int64
}

// SetMaxWebdavFileSize changes the WebDAV upload limit for later requests;
// 0 means no limit.
func (h *Handler) SetMaxWebdavFileSize(size int64) {
	h.maxFileSize.Store(size)
}

// New creates a new CalDAV handler.
func New(store *model.TypedStore, cfg *Config) *Handler {
	return NewWithFolderSpace(store, service.NewFolderSpace(store, authz.New(store)), cfg)
}

// NewWithFolderSpace creates a DAV handler over the shared protocol-neutral
// folder boundary. Production supplies the durable implementation.
func NewWithFolderSpace(store *model.TypedStore, space service.FolderSpace, cfg *Config) *Handler {
	if cfg == nil {
		cfg = &Config{}
	}
	h := &Handler{
		store:      &folderSpaceStore{users: store.UserStore(), sharing: store.FolderStore(), space: space},
		config:     cfg,
		calendars:  cfg.CalendarIndex,
		authorizer: cfg.Authorizer,
		typed:      store,
		domains:    store.DomainStore(),
	}
	if h.calendars == nil {
		h.calendars = calendarindex.New(store.Store())
	}
	if h.authorizer == nil {
		h.authorizer = authz.New(store)
	}
	h.maxFileSize.Store(cfg.MaxWebdavFileSize)
	return h
}

// ServeHTTP handles all DAV requests. It parses the path to determine
// the user, calendar collection, and optional object, then dispatches
// to the appropriate method handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(context.WithValue(r.Context(), davErrorStateKey{}, &davErrorState{}))
	start := time.Now()
	if h.config.Metrics != nil {
		h.config.Metrics.IncrementCounter("caldav_requests_total", map[string]string{"method": r.Method})
		defer func() {
			h.config.Metrics.ObserveHistogram("caldav_request_duration_seconds", time.Since(start).Seconds(), map[string]string{"method": r.Method})
		}()
	}

	if r.Method == http.MethodOptions {
		// RFC 4791 §5.1 / RFC 6638 §2: clients learn the supported
		// extensions, including implicit scheduling, from OPTIONS.
		w.Header().Set("DAV", davCompliance)
		w.Header().Set("Allow", davAllow)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Path structure: /dav/{username}/{calendar}/{object}
	// Strip the /dav/ prefix and trailing slashes
	path := strings.TrimPrefix(r.URL.Path, "/dav")
	path = strings.Trim(path, "/")

	var parts []string
	if path != "" {
		raw := strings.Split(path, "/")
		for _, p := range raw {
			if p != "" {
				parts = append(parts, p)
			}
		}
	}
	if len(parts) < 1 || parts[0] == "" {
		if r.Method == "PROPFIND" {
			h.propfindServiceRoot(w, r)
			return
		}
		if r.Method == "REPORT" && h.handlePrincipalReport(w, r) {
			return
		}
		h.respondError(w, r, http.StatusNotFound, "dav-root", "no user specified")
		return
	}

	username := parts[0]
	if actorID, _ := r.Context().Value(authenticatedUserKey{}).(string); actorID == "" {
		r = WithAuthenticatedUser(r, username)
	}
	if h.config.Authorizer != nil {
		actorID, _ := r.Context().Value(authenticatedUserKey{}).(string)
		if actorID == "" {
			h.respondError(w, r, http.StatusUnauthorized, "authentication-required", "authenticated principal missing")
			return
		}
		if err := h.authorizeTarget(r.Context(), actorID, username, parts[1:], r.Method); errors.Is(err, errFreeBusyOnly) {
			r = r.WithContext(context.WithValue(r.Context(), freeBusyOnlyKey{}, true))
		} else if err != nil {
			h.respondError(w, r, http.StatusForbidden, "forbidden", "access denied")
			return
		}
	}
	// Look up the user to get the user ID
	user, err := h.store.UserStore().Get(r.Context(), username)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-user", fmt.Sprintf("user %q not found", username))
		return
	}
	if !user.Enabled {
		h.respondError(w, r, http.StatusForbidden, "user-disabled", "user is disabled")
		return
	}

	h.handleUser(w, r, username, parts[1:])
}

func (h *Handler) authorizeTarget(ctx context.Context, actorID, ownerID string, parts []string, method string) error {
	if actorID == ownerID {
		return nil
	}
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: actorID}
	if len(parts) == 0 {
		decision, err := h.config.Authorizer.Check(ctx, authz.Request{Actor: actor, Action: authz.AccountDelegate,
			Resource: model.ResourceRef{Kind: model.ResourceAccount, ID: ownerID}})
		if err == nil && decision.Allowed {
			return nil
		}
		return fmt.Errorf("account access denied")
	}
	folder, err := h.store.FolderStore().GetByPath(ctx, ownerID, parts[0])
	if err != nil {
		return err
	}
	action := authz.FolderItemsRead
	switch method {
	case http.MethodPut, "MKCOL", "MKCALENDAR":
		action = authz.FolderItemsCreate
	case http.MethodPatch, "PROPPATCH", "MOVE", "COPY":
		action = authz.FolderItemsUpdate
	case http.MethodDelete:
		action = authz.FolderItemsDelete
	case "PROPFIND":
		action = authz.FolderDiscover
	}
	decision, err := h.config.Authorizer.Check(ctx, authz.Request{Actor: actor, Action: action,
		Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folder.ID}})
	if err != nil {
		return err
	}
	if !decision.Allowed && method == "REPORT" {
		// RFC 4791 §7.10: free-busy-query needs only read-free-busy.
		decision, err = h.config.Authorizer.Check(ctx, authz.Request{Actor: actor, Action: authz.CalendarFreeBusyRead,
			Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folder.ID}})
		if err == nil && decision.Allowed {
			return errFreeBusyOnly
		}
	}
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return fmt.Errorf("folder access denied")
	}
	return nil
}

// handleUser dispatches requests within a user's DAV space.
func (h *Handler) handleUser(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	log.Debug("caldav: dispatching request", "method", r.Method, "user", username)
	switch r.Method {
	case "PROPFIND":
		h.handlePropfind(w, r, username, parts)
	case "PROPPATCH":
		h.handleProppatch(w, r, username, parts)
	case "MKCOL":
		h.handleMkcol(w, r, username, parts)
	case "MKCALENDAR":
		h.handleMkcalendar(w, r, username, parts)
	case "MOVE":
		h.handleMove(w, r, username, parts)
	case "COPY":
		h.handleCopy(w, r, username, parts)
	case "LOCK":
		h.handleLock(w, r, username, parts)
	case "UNLOCK":
		h.handleUnlock(w, r, username, parts)
	case "GET", "HEAD":
		h.handleGet(w, r, username, parts)
	case "PUT":
		h.handlePut(w, r, username, parts)
	case "DELETE":
		h.handleDelete(w, r, username, parts)
	case http.MethodPost:
		h.handlePost(w, r, username, parts)
	case "REPORT":
		// Detect calendar-multitarget PUT (RFC 6638) disguised as REPORT
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "text/calendar") {
			if freeBusyOnly(r.Context()) {
				h.respondError(w, r, http.StatusForbidden, "need-privileges", "access denied")
				return
			}
			h.handleCalendarMultitargetPut(w, r, username, parts)
			return
		}
		h.handleReport(w, r, username, parts)
	default:
		h.respondError(w, r, http.StatusMethodNotAllowed, "bad-method", fmt.Sprintf("method %q not allowed", r.Method))
	}
}

// propfindServiceRoot answers PROPFIND on /dav/ itself, the target of the
// /.well-known/caldav and /.well-known/carddav redirects. Discovery clients ask
// it for current-user-principal; the account root is the principal.
func (h *Handler) propfindServiceRoot(w http.ResponseWriter, r *http.Request) {
	actorID, _ := r.Context().Value(authenticatedUserKey{}).(string)
	if actorID == "" {
		h.respondError(w, r, http.StatusUnauthorized, "authentication-required", "authenticated principal missing")
		return
	}
	pf, err := parsePropfind(r.Body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid PROPFIND body: %v", err))
		return
	}
	etag := `""`
	lastMod := formatHTTPTime(time.Now())
	principal := buildHref(actorID) + "/"
	responses := []response{{
		Href:   "/dav/",
		Status: "HTTP/1.1 200 OK",
		Prop: &propResp{
			ResourceType:           &resourceType{Collection: &empty{}},
			Getetag:                &etag,
			Getlastmodified:        &lastMod,
			CurrentUserPrincipal:   &davCurrentUserPrincipal{Href: principal},
			PrincipalCollectionSet: &davHomeSet{Href: "/dav/"},
		},
	}}
	requestFor(pf).restrict(responses)
	writeMultistatus(w, responses)
}
