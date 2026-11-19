package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	calendarcore "github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/calendarfeed"
	"github.com/lkarlslund/veksel/pkg/calendarindex"
	"github.com/lkarlslund/veksel/pkg/calendarport"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/sharing"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Virtual calendars are read-only calendars that are not folders: a
// subscribed feed ("subscription:<id>") and the Birthdays calendar built from
// the account's contacts. The calendar events API accepts their IDs next to
// folder IDs.
const (
	subscriptionCalendarPrefix = "subscription:"
	birthdaysCalendarID        = "birthdays"
	// publishedWindowPast and publishedWindowFuture bound the busy times a
	// free/busy-only published calendar reveals.
	publishedWindowPast   = 30 * 24 * time.Hour
	publishedWindowFuture = 365 * 24 * time.Hour
	// maxCalendarImportScan bounds the existing events read to match UIDs.
	maxCalendarImportScan = 20000
)

// calendarShareRoles are the roles the calendar sharing dialog offers, from
// least to most access.
var calendarShareRoles = []string{authz.RoleCalendarFreeBusy, authz.RoleFolderViewer, authz.RoleFolderEditor, authz.RoleCalendarDelegate}

func (h *Handler) registerCalendarSharingRoutes(api apiRouter) {
	api.handleBulk("POST /api/v1/workspace/calendar/import", h.apiWorkspaceCalendarImport)
	api.handle("GET /api/v1/workspace/calendar/export", h.apiWorkspaceCalendarExport)
	api.handle("GET /api/v1/workspace/calendars/{id}/sharing", h.apiWorkspaceCalendarSharing)
	api.handle("POST /api/v1/workspace/calendars/{id}/sharing", h.apiWorkspaceShareCalendar)
	api.handle("DELETE /api/v1/workspace/calendars/{id}/sharing/{grantID}", h.apiWorkspaceUnshareCalendar)
	api.handle("POST /api/v1/workspace/calendars/{id}/publish", h.apiWorkspacePublishCalendar)
	api.handle("GET /api/v1/workspace/calendar/subscriptions", h.apiWorkspaceCalendarSubscriptions)
	api.handle("POST /api/v1/workspace/calendar/subscriptions", h.apiWorkspaceCreateCalendarSubscription)
	api.handle("PATCH /api/v1/workspace/calendar/subscriptions/{id}", h.apiWorkspaceUpdateCalendarSubscription)
	api.handle("DELETE /api/v1/workspace/calendar/subscriptions/{id}", h.apiWorkspaceDeleteCalendarSubscription)
	api.handle("POST /api/v1/workspace/calendar/subscriptions/{id}/refresh", h.apiWorkspaceRefreshCalendarSubscription)
	api.handle("GET /api/v1/workspace/calendar/settings", h.apiWorkspaceCalendarSettings)
	api.handle("PUT /api/v1/workspace/calendar/settings", h.apiWorkspaceUpdateCalendarSettings)
	api.handle("GET /api/v1/workspace/calendar/rooms", h.apiWorkspaceCalendarRooms)
	api.handle("GET /api/v1/admin/resources", h.apiAdminResources)
	api.handle("POST /api/v1/admin/resources", h.apiAdminCreateResource)
	api.handle("PATCH /api/v1/admin/resources/{id}", h.apiAdminUpdateResource)
	api.mux.HandleFunc("GET /share/calendar/{token}", h.publicPublishedCalendar)
}

// CalendarFeeds exposes the subscription service so the process can run its
// refresh schedule.
func (h *Handler) CalendarFeeds() *calendarfeed.Service { return h.calendarFeeds }

// --- Import and export ---

type calendarImportResult struct {
	FolderID string                 `json:"folder_id"`
	Created  int                    `json:"created"`
	Updated  int                    `json:"updated"`
	Failed   int                    `json:"failed"`
	Skipped  int                    `json:"skipped"`
	Events   int                    `json:"events"`
	Problems []calendarport.Problem `json:"problems"`
}

// apiWorkspaceCalendarImport files the events of an uploaded .ics document
// in a calendar. Events whose UID is already in the calendar replace it, so
// importing the same file twice changes nothing.
func (h *Handler) apiWorkspaceCalendarImport(w http.ResponseWriter, r *http.Request) {
	folderID := r.URL.Query().Get("folder_id")
	if _, err := h.workspaceFolder(r, folderID, model.FolderTypeCalendar); err != nil {
		apiError(w, err)
		return
	}
	data, err := readCalendarUpload(w, r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	document := calendarport.Parse(data)
	result := calendarImportResult{FolderID: folderID, Skipped: document.Skipped, Problems: document.Problems, Failed: len(document.Problems)}
	if result.Problems == nil {
		result.Problems = []calendarport.Problem{}
	}
	if len(document.Objects) == 0 {
		if len(result.Problems) == 0 {
			result.Problems = append(result.Problems, calendarport.Problem{Message: "the file holds no events"})
		}
		jsonResponse(w, http.StatusUnprocessableEntity, result)
		return
	}
	access := webAccess(currentActor(r), currentSubject(r), currentActingMode(r))
	existing, err := h.calendarUIDs(r.Context(), access, folderID)
	if err != nil {
		apiError(w, err)
		return
	}
	for _, object := range document.Objects {
		if err := r.Context().Err(); err != nil {
			return
		}
		headers := map[string]string{"UID": object.UID, "SUMMARY": object.Summary}
		if itemID, found := existing[object.UID]; found {
			_, err = h.folderSpace.UpdateItem(r.Context(), access, itemID, object.Data, headers)
			if err == nil {
				result.Updated++
			}
		} else {
			var item model.Item
			item, err = h.folderSpace.CreateItem(r.Context(), access, folderID, service.ItemInput{Name: importedItemName(object.UID), Data: object.Data, Headers: headers, InternalDate: time.Now().UTC()})
			if err == nil {
				existing[object.UID] = item.ID
				result.Created++
			}
		}
		if errors.Is(err, service.ErrForbidden) {
			apiError(w, err)
			return
		}
		if err != nil {
			result.Failed++
			if len(result.Problems) < calendarport.MaxProblems {
				result.Problems = append(result.Problems, calendarport.Problem{UID: object.UID, Message: err.Error()})
			}
			continue
		}
		result.Events += object.Events
	}
	actor, subject := currentActor(r).ID, currentSubject(r).ID
	h.audit.Log(actor, "calendar.import", folderID, map[string]string{"subject_id": subject, "created": strconv.Itoa(result.Created), "updated": strconv.Itoa(result.Updated), "failed": strconv.Itoa(result.Failed)})
	h.workspaceChanged(r, "calendar.imported", folderID, map[string]any{"folder_id": folderID, "created": result.Created, "updated": result.Updated})
	jsonResponse(w, http.StatusOK, result)
}

func importedItemName(uid string) string {
	digest := sha256.Sum256([]byte(uid))
	return "import-" + hex.EncodeToString(digest[:12]) + ".ics"
}

// readCalendarUpload reads a bounded .ics upload: multipart form data with
// a "file" part, or a raw text/calendar body.
func readCalendarUpload(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, calendarport.MaxDocumentBytes+contactImportMultipartOverhead)
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != "multipart/form-data" {
		data, err := io.ReadAll(io.LimitReader(r.Body, calendarport.MaxDocumentBytes+1))
		if err != nil || len(data) > calendarport.MaxDocumentBytes {
			return nil, fmt.Errorf("the calendar file must be at most %d MiB", calendarport.MaxDocumentBytes>>20)
		}
		return data, nil
	}
	if err := r.ParseMultipartForm(calendarport.MaxDocumentBytes + contactImportMultipartOverhead); err != nil {
		return nil, errors.New("calendar upload must be bounded multipart form data")
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		return nil, errors.New("file is required")
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, calendarport.MaxDocumentBytes+1))
	if err != nil || len(data) > calendarport.MaxDocumentBytes {
		return nil, fmt.Errorf("the calendar file must be at most %d MiB", calendarport.MaxDocumentBytes>>20)
	}
	return data, nil
}

// calendarUIDs maps the event UIDs of a calendar to their items.
func (h *Handler) calendarUIDs(ctx context.Context, access service.AccessContext, folderID string) (map[string]string, error) {
	uids := map[string]string{}
	err := h.eachCalendarItem(ctx, access, folderID, false, func(item model.Item) error {
		uid := item.Headers["UID"]
		if uid == "" {
			full, err := h.folderSpace.GetItem(ctx, access, item.ID)
			if err != nil {
				return nil
			}
			if projected, err := calendarcore.Project(full.Data); err == nil {
				uid = projected.UID
			}
		}
		if uid != "" {
			uids[uid] = item.ID
		}
		if len(uids) > maxCalendarImportScan {
			return errors.New("the calendar holds too many events to import into")
		}
		return nil
	})
	return uids, err
}

// eachCalendarItem visits the items of a folder in pages, with their data
// when withData is set.
func (h *Handler) eachCalendarItem(ctx context.Context, access service.AccessContext, folderID string, withData bool, visit func(model.Item) error) error {
	pager, ok := h.folderSpace.(service.FolderItemPager)
	if !ok {
		items, err := h.folderSpace.ListItems(ctx, access, folderID, service.ItemQuery{MetadataOnly: !withData, Limit: maxCalendarImportScan})
		if err != nil {
			return err
		}
		for _, item := range items {
			if err := visit(item); err != nil {
				return err
			}
		}
		return nil
	}
	var beforeUID uint32
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := pager.ListItemPage(ctx, access, folderID, service.ItemPageQuery{BeforeUID: beforeUID, Limit: 200, IncludeData: withData})
		if err != nil {
			return err
		}
		for _, item := range page.Items {
			if !item.TrashedAt.IsZero() {
				continue
			}
			if withData && len(item.Data) == 0 && item.Size > 0 {
				if item, err = h.folderSpace.GetItem(ctx, access, item.ID); err != nil {
					return err
				}
			}
			if err := visit(item); err != nil {
				return err
			}
		}
		if page.NextBeforeUID == 0 || page.NextBeforeUID == beforeUID || len(page.Items) == 0 {
			return nil
		}
		beforeUID = page.NextBeforeUID
	}
}

// apiWorkspaceCalendarExport downloads a calendar, a subscription, or the
// Birthdays calendar as one .ics document, optionally limited to the events
// that occur in [start, end).
func (h *Handler) apiWorkspaceCalendarExport(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	calendarID := query.Get("folder_id")
	var start, end time.Time
	if query.Get("start") != "" || query.Get("end") != "" {
		var startErr, endErr error
		start, startErr = time.Parse(time.RFC3339, query.Get("start"))
		end, endErr = time.Parse(time.RFC3339, query.Get("end"))
		if startErr != nil || endErr != nil || !end.After(start) {
			jsonError(w, http.StatusBadRequest, "start and end must be RFC 3339 timestamps with end after start")
			return
		}
	}
	inRange := func(data []byte) bool { return start.IsZero() || calendarport.Overlaps(data, start, end) }
	var exporter *calendarport.Exporter
	ctx := r.Context()
	subject := currentSubject(r).ID
	switch {
	case strings.HasPrefix(calendarID, subscriptionCalendarPrefix):
		id := strings.TrimPrefix(calendarID, subscriptionCalendarPrefix)
		subscription, err := h.calendarFeeds.Get(ctx, subject, id)
		if err != nil {
			apiError(w, err)
			return
		}
		objects, err := h.calendarFeeds.Objects(ctx, subject, id)
		if err != nil {
			apiError(w, err)
			return
		}
		exporter = calendarport.NewExporter(subscription.Name, 0)
		for _, data := range objects {
			if inRange(data) {
				_ = exporter.Add(data)
			}
		}
	case calendarID == birthdaysCalendarID:
		jsonError(w, http.StatusBadRequest, "the Birthdays calendar is generated from contacts; export the contacts instead")
		return
	default:
		folder, err := h.workspaceFolder(r, calendarID, model.FolderTypeCalendar)
		if err != nil {
			apiError(w, err)
			return
		}
		capabilities, err := h.workspaceFolderCapabilities(ctx, r, folder)
		if err != nil {
			apiError(w, err)
			return
		}
		if !capabilities.ReadItems {
			apiError(w, service.ErrForbidden)
			return
		}
		exporter = calendarport.NewExporter(folder.Name, 0)
		access := webAccess(currentActor(r), currentSubject(r), currentActingMode(r))
		err = h.eachCalendarItem(ctx, access, folder.ID, true, func(item model.Item) error {
			if !inRange(item.Data) {
				return nil
			}
			return exporter.Add(item.Data)
		})
		if err != nil {
			apiError(w, err)
			return
		}
	}
	var buf bytes.Buffer
	if err := exporter.Encode(&buf); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "calendar.export", calendarID, map[string]string{"subject_id": subject, "events": strconv.Itoa(exporter.Events())})
	writeCalendarDocument(w, "calendar.ics", "attachment", buf.Bytes())
}

func writeCalendarDocument(w http.ResponseWriter, filename, disposition string, data []byte) {
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if value := mime.FormatMediaType(disposition, map[string]string{"filename": filename}); value != "" {
		w.Header().Set("Content-Disposition", value)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// --- Sharing with people and publishing ---

type calendarShare struct {
	ID        string             `json:"id"`
	Principal model.PrincipalRef `json:"principal"`
	Name      string             `json:"name"`
	Address   string             `json:"address,omitempty"`
	RoleID    string             `json:"role_id"`
	RoleName  string             `json:"role_name"`
	ExpiresAt time.Time          `json:"expires_at,omitzero"`
}

type calendarPublication struct {
	sharing.Link
	// Path is set only when the link is first issued; tokens are never
	// stored.
	Path string `json:"path,omitempty"`
}

type calendarSharingView struct {
	FolderID string                `json:"folder_id"`
	Roles    []model.Role          `json:"roles"`
	Shares   []calendarShare       `json:"shares"`
	Links    []calendarPublication `json:"links"`
}

// apiWorkspaceCalendarSharing lists who a calendar is shared with and its
// published links.
func (h *Handler) apiWorkspaceCalendarSharing(w http.ResponseWriter, r *http.Request) {
	folder, err := h.workspaceFolder(r, r.PathValue("id"), model.FolderTypeCalendar)
	if err != nil {
		apiError(w, err)
		return
	}
	grants, err := h.authorization.ListFolderGrants(r.Context(), settingsPrincipal(r), folder.ID)
	if err != nil {
		apiError(w, err)
		return
	}
	view := calendarSharingView{FolderID: folder.ID, Roles: []model.Role{}, Shares: []calendarShare{}, Links: []calendarPublication{}}
	for _, id := range calendarShareRoles {
		role, _ := authz.BuiltInRole(id)
		view.Roles = append(view.Roles, role)
	}
	for _, grant := range grants {
		if grant.Effect == model.EffectDeny {
			continue
		}
		view.Shares = append(view.Shares, h.describeCalendarShare(r.Context(), grant))
	}
	links, err := h.shareLinks.List(r.Context(), settingsPrincipal(r))
	if err != nil {
		apiError(w, err)
		return
	}
	for _, link := range links {
		if link.FolderID == folder.ID && link.Publish != "" && link.RevokedAt.IsZero() {
			view.Links = append(view.Links, calendarPublication{Link: link})
		}
	}
	jsonResponse(w, http.StatusOK, view)
}

func (h *Handler) describeCalendarShare(ctx context.Context, grant model.PolicyBinding) calendarShare {
	share := calendarShare{ID: grant.ID, Principal: grant.Principal, Name: grant.Principal.ID, RoleID: grant.RoleID, RoleName: grant.RoleID, ExpiresAt: grant.ExpiresAt}
	if role, ok := authz.BuiltInRole(grant.RoleID); ok {
		share.RoleName = role.Name
	} else if grant.RoleID == "" {
		share.RoleName = "Custom permissions"
	}
	switch grant.Principal.Kind {
	case model.PrincipalUser:
		if user, err := h.users.Get(ctx, grant.Principal.ID); err == nil && user.DisplayName != "" {
			share.Name = user.DisplayName
		}
		share.Address = h.primaryAddress(ctx, grant.Principal.ID)
	case model.PrincipalGroup:
		if group, err := model.NewGroupStore(h.ts).Get(ctx, grant.Principal.ID); err == nil && group.Name != "" {
			share.Name = group.Name
		}
	}
	return share
}

func (h *Handler) primaryAddress(ctx context.Context, userID string) string {
	identities, err := h.users.ListEmailAddressesForUser(ctx, userID)
	if err != nil {
		return ""
	}
	chosen := ""
	for _, identity := range identities {
		if identity.Enabled && (chosen == "" || identity.Primary) {
			chosen = identity.ID
			if identity.Primary {
				break
			}
		}
	}
	return chosen
}

// resolveSharePrincipal turns what the sharing dialog was given (an email
// address, an account ID, or a group ID) into a principal.
func (h *Handler) resolveSharePrincipal(ctx context.Context, recipient string) (model.PrincipalRef, error) {
	recipient = strings.ToLower(strings.TrimSpace(recipient))
	if recipient == "" {
		return model.PrincipalRef{}, errors.New("recipient is required")
	}
	if strings.Contains(recipient, "@") {
		identity, err := h.mailboxForRecipient(ctx, calendarcore.MailAddress(recipient))
		if err != nil || !identity.Enabled {
			return model.PrincipalRef{}, fmt.Errorf("%s is not an account on this server", recipient)
		}
		return model.PrincipalRef{Kind: model.PrincipalUser, ID: identity.UserID}, nil
	}
	if _, err := h.users.Get(ctx, recipient); err == nil {
		return model.PrincipalRef{Kind: model.PrincipalUser, ID: recipient}, nil
	}
	group := strings.TrimPrefix(recipient, "group:")
	if _, err := model.NewGroupStore(h.ts).Get(ctx, group); err == nil {
		return model.PrincipalRef{Kind: model.PrincipalGroup, ID: group}, nil
	}
	return model.PrincipalRef{}, fmt.Errorf("no account or group named %s", recipient)
}

// requireSameMailDomain refuses userID, named as recipient, unless it holds
// an enabled identity in one of subject's mail domains. The refusal reads
// like an unknown name.
func (h *Handler) requireSameMailDomain(ctx context.Context, subject, userID, recipient string) error {
	domains, err := h.mailDomains(ctx, subject)
	if err != nil {
		return err
	}
	theirs, err := h.mailDomains(ctx, userID)
	if err != nil {
		return err
	}
	for domain := range theirs {
		if domains[domain] {
			return nil
		}
	}
	return fmt.Errorf("no account or group named %s", strings.ToLower(strings.TrimSpace(recipient)))
}

// apiWorkspaceShareCalendar shares a calendar with an account or group in
// one of the calendar roles, replacing that recipient's earlier calendar
// role.
func (h *Handler) apiWorkspaceShareCalendar(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Recipient string `json:"recipient"`
		Role      string `json:"role"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !slices.Contains(calendarShareRoles, request.Role) {
		jsonError(w, http.StatusBadRequest, "role must be one of "+strings.Join(calendarShareRoles, ", "))
		return
	}
	folder, err := h.workspaceFolder(r, r.PathValue("id"), model.FolderTypeCalendar)
	if err != nil {
		apiError(w, err)
		return
	}
	principal, err := h.resolveSharePrincipal(r.Context(), request.Recipient)
	if err == nil && principal.Kind == model.PrincipalUser && !strings.Contains(request.Recipient, "@") {
		// A bare account ID resolves only within the subject's own mail
		// domains; otherwise the share response would disclose another
		// tenant's account names and addresses by ID guessing.
		err = h.requireSameMailDomain(r.Context(), currentSubject(r).ID, principal.ID, request.Recipient)
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if principal.Kind == model.PrincipalUser && strings.EqualFold(principal.ID, folder.UserID) {
		jsonError(w, http.StatusBadRequest, "the calendar already belongs to "+request.Recipient)
		return
	}
	actor := settingsPrincipal(r)
	existing, err := h.authorization.ListFolderGrants(r.Context(), actor, folder.ID)
	if err != nil {
		apiError(w, err)
		return
	}
	created, err := h.authorization.CreateFolderGrant(r.Context(), actor, model.PolicyBinding{Principal: principal, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folder.ID}, RoleID: request.Role, Effect: model.EffectAllow, Inheritance: model.InheritanceSelf})
	if err != nil {
		apiError(w, err)
		return
	}
	for _, grant := range existing {
		if grant.Principal == principal && slices.Contains(calendarShareRoles, grant.RoleID) && grant.ID != created.ID {
			if err := h.authorization.DeleteFolderGrant(r.Context(), actor, folder.ID, grant.ID); err != nil {
				apiError(w, err)
				return
			}
		}
	}
	h.workspaceChanged(r, "calendar.shared", folder.ID, map[string]any{"folder_id": folder.ID, "role": request.Role})
	jsonResponse(w, http.StatusCreated, h.describeCalendarShare(r.Context(), created))
}

func (h *Handler) apiWorkspaceUnshareCalendar(w http.ResponseWriter, r *http.Request) {
	folder, err := h.workspaceFolder(r, r.PathValue("id"), model.FolderTypeCalendar)
	if err != nil {
		apiError(w, err)
		return
	}
	if err := h.authorization.DeleteFolderGrant(r.Context(), settingsPrincipal(r), folder.ID, r.PathValue("grantID")); err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "calendar.unshared", folder.ID, map[string]any{"folder_id": folder.ID})
	w.WriteHeader(http.StatusNoContent)
}

// apiWorkspacePublishCalendar issues a public read-only feed URL for a
// calendar: every event, or only busy times. Revoke it like any share link.
func (h *Handler) apiWorkspacePublishCalendar(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Format    sharing.PublishFormat `json:"format"`
		ExpiresAt time.Time             `json:"expires_at,omitzero"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	issued, err := h.shareLinks.Create(r.Context(), settingsPrincipal(r), sharing.CreateRequest{TargetKind: sharing.TargetFolder, FolderID: r.PathValue("id"), Access: sharing.AccessRead, Publish: request.Format, ExpiresAt: request.ExpiresAt})
	if errors.Is(err, sharing.ErrInvalidInput) {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, calendarPublication{Link: issued.Link, Path: "/share/calendar/" + issued.Token + ".ics"})
}

// publicPublishedCalendar serves a published calendar feed to anyone with
// its URL.
func (h *Handler) publicPublishedCalendar(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSuffix(r.PathValue("token"), ".ics")
	link, access, err := h.shareLinks.OpenCalendar(r.Context(), token)
	if err != nil {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "calendar is unavailable", http.StatusNotFound)
		return
	}
	folder, err := h.folderSpace.GetFolder(r.Context(), access, link.FolderID)
	if err != nil {
		http.Error(w, "calendar is unavailable", http.StatusNotFound)
		return
	}
	exporter := calendarport.NewExporter(folder.Name, 0)
	exporter.Public = true
	if link.Publish == sharing.PublishFreeBusy {
		now := time.Now().UTC()
		periods, err := h.BusyPeriods(r.Context(), link.TargetOwnerID, []model.Folder{folder}, now.Add(-publishedWindowPast), now.Add(publishedWindowFuture))
		if err != nil {
			http.Error(w, "calendar is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		for _, period := range calendarindex.MergeBusy(periods) {
			exporter.AddComponent(calendarport.BusyEvent(period.Start, period.End, period.Type == calendarindex.BusyTentativeType, now))
		}
	} else if err := h.eachCalendarItem(r.Context(), access, folder.ID, true, func(item model.Item) error { return exporter.Add(item.Data) }); err != nil {
		http.Error(w, "calendar is temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	var buf bytes.Buffer
	if err := exporter.Encode(&buf); err != nil {
		http.Error(w, "calendar is temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "private, max-age=300")
	writeCalendarDocument(w, folder.Name+".ics", "inline", buf.Bytes())
}

// --- Subscriptions and settings ---

func calendarFeedError(w http.ResponseWriter, err error) {
	if errors.Is(err, calendarfeed.ErrInvalid) {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	apiError(w, err)
}

func (h *Handler) apiWorkspaceCalendarSubscriptions(w http.ResponseWriter, r *http.Request) {
	subscriptions, err := h.calendarFeeds.List(r.Context(), currentSubject(r).ID)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, subscriptions)
}

func (h *Handler) apiWorkspaceCreateCalendarSubscription(w http.ResponseWriter, r *http.Request) {
	var input calendarfeed.Input
	if err := decodeJSON(r, &input); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	subscription, err := h.calendarFeeds.Create(r.Context(), currentSubject(r).ID, input)
	if err != nil {
		calendarFeedError(w, err)
		return
	}
	h.workspaceChanged(r, "calendar.subscription.created", subscription.ID, map[string]any{"id": subscription.ID})
	jsonResponse(w, http.StatusCreated, subscription)
}

func (h *Handler) apiWorkspaceUpdateCalendarSubscription(w http.ResponseWriter, r *http.Request) {
	var input calendarfeed.Input
	if err := decodeJSON(r, &input); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	subscription, err := h.calendarFeeds.Update(r.Context(), currentSubject(r).ID, r.PathValue("id"), input)
	if err != nil {
		calendarFeedError(w, err)
		return
	}
	h.workspaceChanged(r, "calendar.subscription.updated", subscription.ID, map[string]any{"id": subscription.ID})
	jsonResponse(w, http.StatusOK, subscription)
}

func (h *Handler) apiWorkspaceDeleteCalendarSubscription(w http.ResponseWriter, r *http.Request) {
	if err := h.calendarFeeds.Delete(r.Context(), currentSubject(r).ID, r.PathValue("id")); err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "calendar.subscription.deleted", r.PathValue("id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiWorkspaceRefreshCalendarSubscription(w http.ResponseWriter, r *http.Request) {
	subscription, err := h.calendarFeeds.Refresh(r.Context(), currentSubject(r).ID, r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, subscription)
}

func (h *Handler) apiWorkspaceCalendarSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.calendarFeeds.Settings(r.Context(), currentSubject(r).ID)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, settings)
}

func (h *Handler) apiWorkspaceUpdateCalendarSettings(w http.ResponseWriter, r *http.Request) {
	var settings calendarfeed.Settings
	if err := decodeJSON(r, &settings); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.calendarFeeds.SetSettings(r.Context(), currentSubject(r).ID, settings); err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, settings)
}

// virtualCalendarEvents returns the events of a subscription or the
// Birthdays calendar over [start, end); handled is false for folder IDs.
func (h *Handler) virtualCalendarEvents(r *http.Request, calendarID string, start, end time.Time) ([]workspaceCalendarEvent, bool, error) {
	subject := currentSubject(r).ID
	var occurrences []calendarcore.Occurrence
	switch {
	case strings.HasPrefix(calendarID, subscriptionCalendarPrefix):
		var err error
		occurrences, err = h.calendarFeeds.Occurrences(r.Context(), subject, strings.TrimPrefix(calendarID, subscriptionCalendarPrefix), start, end)
		if err != nil {
			return nil, true, err
		}
	case calendarID == birthdaysCalendarID:
		birthdays, err := h.contactBirthdays(r)
		if err != nil {
			return nil, true, err
		}
		occurrences = calendarport.BirthdayEvents(birthdays, start, end)
	default:
		return nil, false, nil
	}
	events := make([]workspaceCalendarEvent, 0, len(occurrences))
	for _, occurrence := range occurrences {
		// The synthetic ID keeps occurrences of different events apart; it
		// names no item.
		event := calendarEventView(calendarID+"/"+occurrence.UID, calendarID, occurrence.Event, occurrence.RecurrenceID)
		event.ReadOnly = true
		events = append(events, event)
	}
	return events, true, nil
}

type cachedBirthdays struct {
	version   string
	birthdays []calendarport.Birthday
}

// contactBirthdays reads BDAY from the subject's own address books. Each
// address book's birthdays are cached until it changes.
func (h *Handler) contactBirthdays(r *http.Request) ([]calendarport.Birthday, error) {
	ctx := r.Context()
	subject := currentSubject(r).ID
	folders, err := h.workspace.ListFolders(ctx, currentActor(r), currentSubject(r), currentActingMode(r))
	if err != nil {
		return nil, err
	}
	access := webAccess(currentActor(r), currentSubject(r), currentActingMode(r))
	var birthdays []calendarport.Birthday
	for _, folder := range folders {
		if folder.Type != model.FolderTypeContacts || !strings.EqualFold(folder.UserID, subject) {
			continue
		}
		version := fmt.Sprintf("%d/%d/%s", folder.HighestModSeq, folder.ItemCount, folder.UpdatedAt.Format(time.RFC3339Nano))
		if cached, ok := h.birthdayCache.Load(folder.ID); ok && cached.(cachedBirthdays).version == version {
			birthdays = append(birthdays, cached.(cachedBirthdays).birthdays...)
			continue
		}
		var found []calendarport.Birthday
		err := h.eachCalendarItem(ctx, access, folder.ID, true, func(item model.Item) error {
			contact := model.ParseVCard(item.Data)
			if contact.Birthday == "" || contact.Kind == "group" {
				return nil
			}
			year, month, day, ok := calendarport.ParseBirthday(contact.Birthday)
			if !ok {
				return nil
			}
			name := strings.TrimSpace(contact.FN)
			if name == "" {
				name = "Contact"
			}
			found = append(found, calendarport.Birthday{ContactID: item.ID, Name: name, Year: year, Month: month, Day: day})
			return nil
		})
		if err != nil {
			return nil, err
		}
		h.birthdayCache.Store(folder.ID, cachedBirthdays{version: version, birthdays: found})
		birthdays = append(birthdays, found...)
	}
	return birthdays, nil
}

// freeBusyEvents returns the busy times of a calendar shared free/busy
// only, as detail-free events.
func (h *Handler) freeBusyEvents(ctx context.Context, folder model.Folder, start, end time.Time) ([]workspaceCalendarEvent, error) {
	periods, err := h.BusyPeriods(ctx, folder.UserID, []model.Folder{folder}, start, end)
	if err != nil {
		return nil, err
	}
	merged := calendarindex.MergeBusy(periods)
	events := make([]workspaceCalendarEvent, 0, len(merged))
	for _, period := range merged {
		summary, status := "Busy", ""
		if period.Type == calendarindex.BusyTentativeType {
			summary, status = "Tentative", "TENTATIVE"
		}
		events = append(events, workspaceCalendarEvent{ID: folder.ID + "/busy/" + strconv.FormatInt(period.Start.Unix(), 10), FolderID: folder.ID, Summary: summary, Status: status, DTStart: period.Start.Format(time.RFC3339), DTEnd: period.End.Format(time.RFC3339), Recurrence: "none", ReadOnly: true, FreeBusyOnly: true})
	}
	return events, nil
}

// --- Rooms and resources ---

type calendarRoom struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Address  string              `json:"address"`
	Kind     model.BookableKind  `json:"kind"`
	Capacity int                 `json:"capacity,omitempty"`
	Location string              `json:"location,omitempty"`
	Policy   model.BookingPolicy `json:"policy"`
	// Status is free or busy for the requested slot.
	Status string `json:"status"`
}

// apiWorkspaceCalendarRooms lists bookable resources and whether each is
// free over [start, end). The event being edited (uid) does not make its own
// resources busy.
func (h *Handler) apiWorkspaceCalendarRooms(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	start, startErr := time.Parse(time.RFC3339, query.Get("start"))
	end, endErr := time.Parse(time.RFC3339, query.Get("end"))
	if startErr != nil || endErr != nil || !end.After(start) || end.Sub(start) > maxFreeBusyRange {
		jsonError(w, http.StatusBadRequest, "start and end must be RFC 3339 timestamps less than 42 days apart")
		return
	}
	ignore := query.Get("uid")
	kind := model.BookableKind(query.Get("kind"))
	// Like free/busy, the room finder covers only the subject's own mail
	// domains, so one tenant cannot see another's resources or bookings.
	domains, err := h.mailDomains(r.Context(), currentSubject(r).ID)
	if err != nil {
		apiError(w, err)
		return
	}
	users, err := h.users.List(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	rooms := []calendarRoom{}
	for _, user := range users {
		if user.Resource == nil || !user.Enabled || (kind != "" && user.Resource.Kind != kind) {
			continue
		}
		address := h.primaryAddress(r.Context(), user.ID)
		if address == "" || !domains[addressDomain(address)] {
			continue
		}
		room := calendarRoom{ID: user.ID, Name: firstNonEmptyString(user.DisplayName, user.ID), Address: address, Kind: user.Resource.Kind, Capacity: user.Resource.Capacity, Location: user.Resource.Location, Policy: user.Resource.Policy, Status: "free"}
		busy, err := h.BusyPeriods(r.Context(), user.ID, nil, start, end)
		if err != nil {
			apiError(w, err)
			return
		}
		for _, period := range busy {
			if period.UID != ignore || ignore == "" {
				room.Status = "busy"
				break
			}
		}
		rooms = append(rooms, room)
	}
	sort.Slice(rooms, func(i, j int) bool {
		if rooms[i].Status != rooms[j].Status {
			return rooms[i].Status == "free"
		}
		return strings.ToLower(rooms[i].Name) < strings.ToLower(rooms[j].Name)
	})
	jsonResponse(w, http.StatusOK, rooms)
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

type adminResource struct {
	ID          string                `json:"id"`
	DisplayName string                `json:"display_name"`
	Address     string                `json:"address"`
	Enabled     bool                  `json:"enabled"`
	CalendarID  string                `json:"calendar_id,omitempty"`
	Delegates   []string              `json:"delegates"`
	Resource    model.ResourceProfile `json:"resource"`
}

type adminResourceRequest struct {
	ID             string               `json:"id"`
	DisplayName    *string              `json:"display_name,omitempty"`
	Address        string               `json:"address"`
	Kind           *model.BookableKind  `json:"kind,omitempty"`
	Capacity       *int                 `json:"capacity,omitempty"`
	Location       *string              `json:"location,omitempty"`
	Policy         *model.BookingPolicy `json:"policy,omitempty"`
	AllowConflicts *bool                `json:"allow_conflicts,omitempty"`
	// Delegates, when present, replaces the accounts that may approve
	// bookings and manage the resource calendar.
	Delegates *[]string `json:"delegates,omitempty"`
}

func (request adminResourceRequest) apply(profile *model.ResourceProfile) error {
	if request.Kind != nil {
		profile.Kind = *request.Kind
	}
	if request.Capacity != nil {
		profile.Capacity = *request.Capacity
	}
	if request.Location != nil {
		profile.Location = strings.TrimSpace(*request.Location)
	}
	if request.Policy != nil {
		profile.Policy = *request.Policy
	}
	if request.AllowConflicts != nil {
		profile.AllowConflicts = *request.AllowConflicts
	}
	switch {
	case profile.Kind != model.BookableRoom && profile.Kind != model.BookableEquipment:
		return errors.New("kind must be room or equipment")
	case profile.Policy != model.BookingAutoAccept && profile.Policy != model.BookingApproval:
		return errors.New("policy must be auto_accept or approval")
	case profile.Capacity < 0 || profile.Capacity > 100000:
		return errors.New("capacity must be between 0 and 100000")
	case len(profile.Location) > 200:
		return errors.New("location must be at most 200 characters")
	}
	return nil
}

func (h *Handler) apiAdminResources(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	users, err := h.users.List(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	result := []adminResource{}
	for _, user := range users {
		if user.Resource != nil {
			result = append(result, h.describeResource(r.Context(), user))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	jsonResponse(w, http.StatusOK, result)
}

func (h *Handler) describeResource(ctx context.Context, user model.User) adminResource {
	resource := adminResource{ID: user.ID, DisplayName: user.DisplayName, Address: h.primaryAddress(ctx, user.ID), Enabled: user.Enabled, Delegates: []string{}, Resource: *user.Resource}
	if calendar, err := h.resourceCalendar(ctx, user.ID); err == nil {
		resource.CalendarID = calendar.ID
		if grants, err := h.authorization.ListFolderGrants(ctx, model.PrincipalRef{Kind: model.PrincipalUser, ID: user.ID}, calendar.ID); err == nil {
			for _, grant := range grants {
				if grant.RoleID == authz.RoleCalendarDelegate && grant.Principal.Kind == model.PrincipalUser {
					resource.Delegates = append(resource.Delegates, grant.Principal.ID)
				}
			}
		}
	}
	sort.Strings(resource.Delegates)
	return resource
}

// resourceCalendar returns the calendar a resource account books into.
func (h *Handler) resourceCalendar(ctx context.Context, userID string) (model.Folder, error) {
	folders, err := h.folderSpace.ListFolders(ctx, service.UserAccess(userID, "resource-admin"), service.FolderQuery{Type: model.FolderTypeCalendar})
	if err != nil {
		return model.Folder{}, err
	}
	var first *model.Folder
	for index, folder := range folders {
		if folder.Type != model.FolderTypeCalendar || !strings.EqualFold(folder.UserID, userID) {
			continue
		}
		if folder.SpecialUse == model.SpecialUseCalendar {
			return folder, nil
		}
		if first == nil {
			first = &folders[index]
		}
	}
	if first == nil {
		return model.Folder{}, store.ErrNotFound
	}
	return *first, nil
}

// apiAdminCreateResource creates a room or equipment account with an email
// address and a booking calendar. The account has an unusable random
// password and cannot sign in.
func (h *Handler) apiAdminCreateResource(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	var request adminResourceRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.ID = strings.ToLower(strings.TrimSpace(request.ID))
	address := strings.ToLower(strings.TrimSpace(request.Address))
	at := strings.LastIndex(address, "@")
	if request.ID == "" || strings.ContainsAny(request.ID, "@:/\\ ") || at < 1 {
		jsonError(w, http.StatusBadRequest, "a valid resource ID and email address are required")
		return
	}
	profile := model.ResourceProfile{Kind: model.BookableRoom, Policy: model.BookingAutoAccept}
	if err := request.apply(&profile); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	if _, err := h.ts.DomainStore().Get(ctx, address[at+1:]); err != nil {
		jsonError(w, http.StatusBadRequest, "the address must be in a domain this server hosts")
		return
	}
	if _, err := h.users.GetEmailAddress(ctx, address); err == nil {
		jsonError(w, http.StatusConflict, "the address is already in use")
		return
	}
	displayName := request.ID
	if request.DisplayName != nil && strings.TrimSpace(*request.DisplayName) != "" {
		displayName = strings.TrimSpace(*request.DisplayName)
	}
	secret := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		apiError(w, err)
		return
	}
	if err := h.createAccount(ctx, request.ID, displayName, hex.EncodeToString(secret)); err != nil {
		apiError(w, err)
		return
	}
	if err := h.users.Update(ctx, request.ID, func(user *model.User) { user.Resource = &profile }); err != nil {
		apiError(w, err)
		return
	}
	if err := h.users.AddEmailAddress(ctx, address, request.ID, address[at+1:], true); err != nil {
		apiError(w, err)
		return
	}
	if err := h.syncAccountManifest(ctx, request.ID); err != nil {
		apiError(w, err)
		return
	}
	if request.Delegates != nil {
		if err := h.setResourceDelegates(ctx, request.ID, *request.Delegates); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	user, err := h.users.Get(ctx, request.ID)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "resource.create", request.ID, map[string]string{"address": address, "kind": string(profile.Kind), "policy": string(profile.Policy)})
	jsonResponse(w, http.StatusCreated, h.describeResource(ctx, user))
}

func (h *Handler) apiAdminUpdateResource(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	var request adminResourceRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	id := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	user, err := h.users.Get(ctx, id)
	if err != nil {
		apiError(w, err)
		return
	}
	if user.Resource == nil {
		jsonError(w, http.StatusNotFound, "not a resource account")
		return
	}
	profile := *user.Resource
	if err := request.apply(&profile); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	err = h.users.Update(ctx, id, func(user *model.User) {
		user.Resource = &profile
		if request.DisplayName != nil && strings.TrimSpace(*request.DisplayName) != "" {
			user.DisplayName = strings.TrimSpace(*request.DisplayName)
		}
	})
	if err != nil {
		apiError(w, err)
		return
	}
	if request.Delegates != nil {
		if err := h.setResourceDelegates(ctx, id, *request.Delegates); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if user, err = h.users.Get(ctx, id); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "resource.update", id, map[string]string{"kind": string(profile.Kind), "policy": string(profile.Policy)})
	jsonResponse(w, http.StatusOK, h.describeResource(ctx, user))
}

// setResourceDelegates makes exactly the given accounts (IDs or addresses)
// delegates of a resource's calendar. Grants are made by the resource
// account, which owns the calendar.
func (h *Handler) setResourceDelegates(ctx context.Context, resourceID string, delegates []string) error {
	calendar, err := h.resourceCalendar(ctx, resourceID)
	if err != nil {
		return fmt.Errorf("the resource has no calendar: %w", err)
	}
	owner := model.PrincipalRef{Kind: model.PrincipalUser, ID: resourceID}
	wanted := map[string]bool{}
	for _, delegate := range delegates {
		principal, err := h.resolveSharePrincipal(ctx, delegate)
		if err != nil {
			return err
		}
		if principal.Kind != model.PrincipalUser {
			return fmt.Errorf("%s is not an account", delegate)
		}
		wanted[principal.ID] = true
	}
	grants, err := h.authorization.ListFolderGrants(ctx, owner, calendar.ID)
	if err != nil {
		return err
	}
	for _, grant := range grants {
		if grant.RoleID != authz.RoleCalendarDelegate || grant.Principal.Kind != model.PrincipalUser {
			continue
		}
		if wanted[grant.Principal.ID] {
			delete(wanted, grant.Principal.ID)
			continue
		}
		if err := h.authorization.DeleteFolderGrant(ctx, owner, calendar.ID, grant.ID); err != nil {
			return err
		}
	}
	for userID := range wanted {
		binding := model.PolicyBinding{Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: userID}, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: calendar.ID}, RoleID: authz.RoleCalendarDelegate, Effect: model.EffectAllow, Inheritance: model.InheritanceSelf}
		if _, err := h.authorization.CreateFolderGrant(ctx, owner, binding); err != nil {
			return err
		}
	}
	return nil
}
