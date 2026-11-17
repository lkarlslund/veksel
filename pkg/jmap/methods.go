package jmap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/lkarlslund/veksel/pkg/folderindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

func (h *Handler) dispatch(ctx context.Context, actor model.User, name string, raw json.RawMessage, created map[string]string) (any, *MethodError) {
	switch name {
	case "Core/echo":
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, invalidArguments(err)
		}
		return v, nil
	case "Mailbox/get":
		return h.mailboxGet(ctx, actor, raw)
	case "Mailbox/query":
		return h.mailboxQuery(ctx, actor, raw)
	case "Mailbox/set":
		return h.mailboxSet(ctx, actor, raw, created)
	case "Mailbox/changes":
		return h.changes(ctx, actor, "Mailbox", raw)
	case "Mailbox/queryChanges":
		return h.queryChanges(ctx, actor, "Mailbox", raw)
	case "Email/get":
		return h.emailGet(ctx, actor, raw)
	case "Email/query":
		return h.emailQuery(ctx, actor, raw)
	case "Email/set":
		return h.emailSet(ctx, actor, raw, created)
	case "Email/copy":
		return h.emailCopy(ctx, actor, raw, created)
	case "Email/import":
		return h.emailImport(ctx, actor, raw, created)
	case "Email/parse":
		return h.emailParse(ctx, actor, raw)
	case "Email/changes":
		return h.changes(ctx, actor, "Email", raw)
	case "Email/queryChanges":
		return h.emailQueryChanges(ctx, actor, raw)
	case "Thread/get":
		return h.threadGet(ctx, actor, raw)
	case "Thread/changes":
		return h.changes(ctx, actor, "Thread", raw)
	case "SearchSnippet/get":
		return h.searchSnippetGet(ctx, actor, raw)
	case "Identity/get":
		return h.identityGet(ctx, actor, raw)
	case "Identity/changes":
		return h.identityChanges(ctx, actor, raw)
	case "Identity/set":
		return nil, &MethodError{Type: "forbidden", Description: "identities are managed by the account service"}
	case "EmailSubmission/get":
		return h.submissionGet(ctx, actor, raw)
	case "EmailSubmission/query":
		return h.submissionQuery(ctx, actor, raw)
	case "EmailSubmission/set":
		return h.submissionSet(ctx, actor, raw, created)
	case "EmailSubmission/changes":
		return h.submissionChanges(ctx, actor, raw)
	case "EmailSubmission/queryChanges":
		return h.queryChanges(ctx, actor, "EmailSubmission", raw)
	case "VacationResponse/get":
		return h.vacationGet(ctx, actor, raw)
	case "VacationResponse/set":
		return h.vacationSet(ctx, actor, raw)
	case "Blob/copy":
		return h.blobCopy(ctx, actor, raw, created)
	case "PushSubscription/get":
		return h.pushGet(ctx, actor, raw)
	case "PushSubscription/set":
		return h.pushSet(ctx, actor, raw, created)
	default:
		if result, err, ok := h.dispatchContacts(ctx, actor, name, raw, created); ok {
			return result, err
		}
		if result, err, ok := h.dispatchCalendars(ctx, actor, name, raw, created); ok {
			return result, err
		}
		return nil, &MethodError{Type: "unknownMethod", Description: name}
	}
}

func invalidArguments(err error) *MethodError {
	return &MethodError{Type: "invalidArguments", Description: err.Error()}
}
func serverError(err error) *MethodError {
	if errors.Is(err, model.ErrQuotaExceeded) {
		return &MethodError{Type: "overQuota", Description: "account quota exceeded"}
	}
	if service.IsTemporarilyUnavailable(err) {
		return &MethodError{Type: "serverFail", Description: "account temporarily unavailable; retry later"}
	}
	if errors.Is(err, service.ErrForbidden) {
		return &MethodError{Type: "forbidden", Description: "access denied"}
	}
	if errors.Is(err, store.ErrNotFound) {
		return &MethodError{Type: "notFound"}
	}
	return &MethodError{Type: "serverFail", Description: err.Error()}
}

func (h *Handler) validateAccount(ctx context.Context, actor model.User, accountID string) (service.AccessContext, *MethodError) {
	if accountID == "" {
		return service.AccessContext{}, &MethodError{Type: "invalidArguments", Properties: []string{"accountId"}}
	}
	access := accountAccess(actor.ID, accountID)
	if accountID == actor.ID {
		return access, nil
	}
	folders, err := h.cfg.Space.ListFolders(ctx, access, service.FolderQuery{})
	if err == nil && hasOwnerFolder(folders, accountID) {
		return access, nil
	}
	access = sharedAccess(actor.ID, accountID)
	folders, err = h.cfg.Space.ListFolders(ctx, access, service.FolderQuery{})
	if err != nil || !hasOwnerFolder(folders, accountID) {
		return service.AccessContext{}, &MethodError{Type: "accountNotFound"}
	}
	return access, nil
}

// hasOwnerFolder reports whether a JMAP-visible folder of the account is in
// the list.
func hasOwnerFolder(folders []model.Folder, accountID string) bool {
	for _, folder := range folders {
		if folder.UserID == accountID && slices.Contains(jmapFolderTypes, folder.Type) {
			return true
		}
	}
	return false
}

func (h *Handler) mailFolders(ctx context.Context, access service.AccessContext) ([]model.Folder, error) {
	return h.typedFolders(ctx, access, model.FolderTypeMail)
}
func (h *Handler) mailItems(ctx context.Context, access service.AccessContext) ([]model.Item, error) {
	return h.listMailItems(ctx, access, service.ItemQuery{})
}

// mailItemMetadata lists the account's readable mail items without their
// content: headers, flags, dates and sizes only.
func (h *Handler) mailItemMetadata(ctx context.Context, access service.AccessContext) ([]model.Item, error) {
	return h.listMailItems(ctx, access, service.ItemQuery{MetadataOnly: true, RequireRead: true})
}

func (h *Handler) listMailItems(ctx context.Context, access service.AccessContext, query service.ItemQuery) ([]model.Item, error) {
	folders, err := h.mailFolders(ctx, access)
	if err != nil {
		return nil, err
	}
	var out []model.Item
	for _, f := range folders {
		items, e := h.cfg.Space.ListItems(ctx, access, f.ID, query)
		if e == nil {
			out = append(out, items...)
		}
	}
	return out, nil
}

// mailItemsByID returns the account's mail items named by ids, with content,
// in request order. A nil ids returns every mail item. IDs that name no
// readable mail item of the account are left out.
func (h *Handler) mailItemsByID(ctx context.Context, access service.AccessContext, ids []string) ([]model.Item, error) {
	if ids == nil {
		return h.mailItems(ctx, access)
	}
	folders, err := h.mailFolders(ctx, access)
	if err != nil {
		return nil, err
	}
	mailFolders := make(map[string]bool, len(folders))
	for _, folder := range folders {
		mailFolders[folder.ID] = true
	}
	out := make([]model.Item, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		item, err := h.cfg.Space.GetItem(ctx, access, id)
		if err != nil || !mailFolders[item.FolderID] {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

func shortState(parts []string) string {
	sum := sha256Bytes(strings.Join(parts, "\x00"))
	return fmt.Sprintf("%x", sum[:12])
}
func sha256Bytes(value string) [32]byte { return sha256.Sum256([]byte(value)) }

// journalState is the change state of the journal behind the account's mail
// folders: the owner's journal for shared accounts, never the viewer's own.
func (h *Handler) journalState(ctx context.Context, access service.AccessContext, _ service.ChangeObject) (string, error) {
	folders, err := h.mailFolders(ctx, access)
	if err != nil {
		return "", err
	}
	return h.collectionState(ctx, access, folders)
}

// mailboxCounts returns a mailbox's total and unread message counts. They
// are zero when the caller cannot read the mailbox's messages.
func (h *Handler) mailboxCounts(ctx context.Context, access service.AccessContext, folder model.Folder) (total, unread int64) {
	if h.cfg.MailIndex != nil && h.folderRights(ctx, access, folder).read {
		if count, err := h.cfg.MailIndex.Unseen(ctx, h.cfg.Space, access, folder, folderindex.PriorityFolder); err == nil {
			return folder.ItemCount, count
		}
	}
	items, _ := h.cfg.Space.ListItems(ctx, access, folder.ID, service.ItemQuery{MetadataOnly: true, RequireRead: true})
	for _, item := range items {
		if !hasFlag(item.Flags, model.FlagSeen) {
			unread++
		}
	}
	return int64(len(items)), unread
}

// mailboxObject renders a Mailbox (RFC 8621 §2).
func (h *Handler) mailboxObject(ctx context.Context, access service.AccessContext, actor model.User, accountID string, f model.Folder) map[string]any {
	total, unread := h.mailboxCounts(ctx, access, f)
	// Owners and account delegates hold every right; shared mailboxes
	// report what the authorizer grants (RFC 8621 §2 myRights).
	granted := h.folderRights(ctx, access, f)
	full := strings.EqualFold(f.UserID, access.Subject.ID)
	rights := map[string]bool{"mayReadItems": granted.read, "mayAddItems": granted.create, "mayRemoveItems": granted.remove,
		"maySetSeen": granted.update, "maySetKeywords": granted.update, "mayCreateChild": full, "mayRename": full && !f.System,
		"mayDelete": full && !f.System, "maySubmit": full}
	return map[string]any{"id": f.ID, "name": f.Name, "parentId": nullable(f.ParentID), "role": nullable(f.SpecialUse), "sortOrder": mailboxSortOrder(f), "totalEmails": total, "unreadEmails": unread, "totalThreads": total, "unreadThreads": unread, "myRights": rights, "isSubscribed": f.Subscribed}
}

// mailboxSortOrder lists role mailboxes first, in the usual client order.
func mailboxSortOrder(f model.Folder) int {
	for index, role := range []string{"inbox", "drafts", "sent", "archive", "junk", "trash"} {
		if f.SpecialUse == role {
			return index + 1
		}
	}
	return 100
}

var mailboxProperties = []string{"id", "name", "parentId", "role", "sortOrder", "totalEmails", "unreadEmails", "totalThreads", "unreadThreads", "myRights", "isSubscribed"}

func (h *Handler) mailboxGet(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a getArgs
	if e := decodeGetArgs(raw, &a, func() []string { return a.IDs }); e != nil {
		return nil, e
	}
	if bad := unknownProperties(a.Properties, mailboxProperties); len(bad) > 0 {
		return nil, &MethodError{Type: "invalidArguments", Description: "unknown Mailbox properties", Properties: bad}
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	folders, err := h.mailFolders(ctx, access)
	if err != nil {
		return nil, serverError(err)
	}
	wanted := idSet(a.IDs)
	list := make([]any, 0, len(folders))
	found := map[string]bool{}
	for _, f := range folders {
		if wanted != nil && !wanted[f.ID] {
			continue
		}
		found[f.ID] = true
		list = append(list, selectProperties(h.mailboxObject(ctx, access, actor, a.AccountID, f), a.Properties))
	}
	state, err := h.journalState(ctx, access, service.ChangeObjectFolder)
	if err != nil {
		return nil, serverError(err)
	}
	return map[string]any{"accountId": a.AccountID, "state": state, "list": list, "notFound": missing(a.IDs, found)}, nil
}

func (h *Handler) mailboxQuery(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a struct {
		queryArgs
		SortAsTree   bool `json:"sortAsTree"`
		FilterAsTree bool `json:"filterAsTree"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	filter, e := decodeFilter(a.Filter)
	if e != nil {
		return nil, e
	}
	for _, comparator := range a.Sort {
		if comparator.Property != "name" && comparator.Property != "sortOrder" && comparator.Property != "parentId" {
			return nil, &MethodError{Type: "unsupportedSort", Description: comparator.Property}
		}
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	folders, err := h.mailFolders(ctx, access)
	if err != nil {
		return nil, serverError(err)
	}
	var filterErr error
	matches := func(f model.Folder) bool {
		return evalFilter(filter, func(condition map[string]any) bool {
			for key, value := range condition {
				switch key {
				case "parentId":
					parent, _ := value.(string)
					if f.ParentID != parent {
						return false
					}
				case "name":
					needle, _ := value.(string)
					if !containsFold(f.Name, needle) {
						return false
					}
				case "role":
					role, _ := value.(string)
					if f.SpecialUse != role {
						return false
					}
				case "hasAnyRole":
					if want, _ := value.(bool); want != (f.SpecialUse != "") {
						return false
					}
				case "isSubscribed":
					if want, _ := value.(bool); want != f.Subscribed {
						return false
					}
				default:
					filterErr = fmt.Errorf("unsupported filter condition %q", key)
					return false
				}
			}
			return true
		})
	}
	byID := folderIndex(folders)
	path := func(f model.Folder) []model.Folder {
		chain := []model.Folder{f}
		for parent, ok := byID[f.ParentID]; ok && len(chain) < 128; parent, ok = byID[parent.ParentID] {
			chain = append([]model.Folder{parent}, chain...)
		}
		return chain
	}
	less := func(x, y model.Folder) int {
		for _, comparator := range a.Sort {
			var c int
			switch comparator.Property {
			case "name":
				c = strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name))
			case "sortOrder":
				c = mailboxSortOrder(x) - mailboxSortOrder(y)
			case "parentId":
				c = strings.Compare(x.ParentID, y.ParentID)
			}
			if !comparator.IsAscending {
				c = -c
			}
			if c != 0 {
				return c
			}
		}
		if len(a.Sort) == 0 {
			if c := mailboxSortOrder(x) - mailboxSortOrder(y); c != 0 {
				return c
			}
			if c := strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name)); c != 0 {
				return c
			}
		}
		return strings.Compare(x.ID, y.ID)
	}
	sort.SliceStable(folders, func(i, j int) bool {
		if a.SortAsTree {
			// Compare the ancestor chains: parents precede their children
			// and siblings follow the sort.
			pi, pj := path(folders[i]), path(folders[j])
			for k := 0; k < len(pi) && k < len(pj); k++ {
				if pi[k].ID != pj[k].ID {
					return less(pi[k], pj[k]) < 0
				}
			}
			return len(pi) < len(pj)
		}
		return less(folders[i], folders[j]) < 0
	})
	ids := []string{}
	for _, f := range folders {
		ok := matches(f)
		if ok && a.FilterAsTree {
			for _, ancestor := range path(f) {
				ok = ok && matches(ancestor)
			}
		}
		if ok {
			ids = append(ids, f.ID)
		}
	}
	if filterErr != nil {
		return nil, &MethodError{Type: "unsupportedFilter", Description: filterErr.Error()}
	}
	position, e := queryPosition(ids, len(ids), a.queryArgs)
	if e != nil {
		return nil, e
	}
	state, err := h.journalState(ctx, access, service.ChangeObjectFolder)
	if err != nil {
		return nil, serverError(err)
	}
	return map[string]any{"accountId": a.AccountID, "queryState": state, "canCalculateChanges": false, "position": position, "ids": window(ids, position, a.Limit), "total": len(ids)}, nil
}

func (h *Handler) mailboxSet(ctx context.Context, actor model.User, raw json.RawMessage, created map[string]string) (any, *MethodError) {
	var a setArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	oldState, stateErr := h.journalState(ctx, access, service.ChangeObjectFolder)
	if stateErr != nil {
		return nil, serverError(stateErr)
	}
	if a.IfInState != "" && a.IfInState != oldState {
		return nil, &MethodError{Type: "stateMismatch"}
	}
	made := map[string]any{}
	notMade := map[string]any{}
	updated := map[string]any{}
	notUpdated := map[string]any{}
	destroyed := []string{}
	notDestroyed := map[string]any{}
	for _, cid := range mailboxCreateOrder(a.Create) {
		input := a.Create[cid]
		var v struct {
			Name         string  `json:"name"`
			ParentID     *string `json:"parentId"`
			IsSubscribed bool    `json:"isSubscribed"`
			Role         *string `json:"role"`
		}
		if json.Unmarshal(input, &v) != nil || strings.TrimSpace(v.Name) == "" {
			notMade[cid] = MethodError{Type: "invalidProperties", Description: "name is required", Properties: []string{"name"}}
			continue
		}
		if v.Role != nil {
			notMade[cid] = MethodError{Type: "invalidProperties", Description: "roles are assigned by the server", Properties: []string{"role"}}
			continue
		}
		parent := ""
		if v.ParentID != nil {
			parent = resolveCreated(*v.ParentID, created)
			if strings.HasPrefix(parent, "#") {
				notMade[cid] = MethodError{Type: "invalidProperties", Description: "parent " + *v.ParentID + " was not created", Properties: []string{"parentId"}}
				continue
			}
		}
		if h.siblingNamed(ctx, access, parent, v.Name) {
			notMade[cid] = MethodError{Type: "invalidProperties", Description: "a sibling mailbox already has this name", Properties: []string{"name"}}
			continue
		}
		f, err := h.cfg.Space.CreateFolder(ctx, access, v.Name, model.FolderTypeMail, parent)
		if err != nil {
			notMade[cid] = *serverError(err)
			continue
		}
		if v.IsSubscribed {
			yes := true
			f, _ = h.cfg.Space.UpdateFolder(ctx, access, f.ID, service.FolderUpdate{Subscribed: &yes})
		}
		created[cid] = f.ID
		object := h.mailboxObject(ctx, access, actor, a.AccountID, f)
		delete(object, "name")
		delete(object, "parentId")
		made[cid] = object
	}
	for key, patch := range a.Update {
		id := resolveCreated(key, created)
		var v struct {
			Name         *string `json:"name"`
			ParentID     *string `json:"parentId"`
			IsSubscribed *bool   `json:"isSubscribed"`
		}
		if err := json.Unmarshal(patch, &v); err != nil {
			notUpdated[key] = MethodError{Type: "invalidProperties"}
			continue
		}
		f, err := h.cfg.Space.GetFolder(ctx, access, id)
		if err == nil && (v.Name != nil || v.ParentID != nil) {
			name := f.Name
			if v.Name != nil {
				name = *v.Name
			}
			parent := f.ParentID
			if v.ParentID != nil {
				parent = resolveCreated(*v.ParentID, created)
			}
			f, err = h.cfg.Space.MoveFolder(ctx, access, id, parent, name)
		}
		if err == nil && v.IsSubscribed != nil {
			_, err = h.cfg.Space.UpdateFolder(ctx, access, id, service.FolderUpdate{Subscribed: v.IsSubscribed})
		}
		if err != nil {
			notUpdated[key] = *serverError(err)
		} else {
			updated[key] = nil
		}
	}
	for _, key := range a.Destroy {
		id := resolveCreated(key, created)
		if e := h.mailboxDestroyable(ctx, access, id, a.OnDestroyRemoveEmails); e != nil {
			notDestroyed[key] = *e
			continue
		}
		if err := h.cfg.Space.DeleteFolder(ctx, access, id); err != nil {
			notDestroyed[key] = *serverError(err)
		} else {
			destroyed = append(destroyed, key)
		}
	}
	newState, stateErr := h.journalState(ctx, access, service.ChangeObjectFolder)
	if stateErr != nil {
		return nil, serverError(stateErr)
	}
	return map[string]any{"accountId": a.AccountID, "oldState": oldState, "newState": newState, "created": made, "notCreated": notMade, "updated": updated, "notUpdated": notUpdated, "destroyed": destroyed, "notDestroyed": notDestroyed}, nil
}

// mailboxCreateOrder orders creations so a parent created in the same call
// ("parentId": "#cid") is made before its children.
func mailboxCreateOrder(create map[string]json.RawMessage) []string {
	parents := map[string]string{}
	for cid, input := range create {
		var v struct {
			ParentID string `json:"parentId"`
		}
		_ = json.Unmarshal(input, &v)
		parents[cid] = strings.TrimPrefix(v.ParentID, "#")
	}
	var order []string
	done := map[string]bool{}
	var visit func(string, int)
	visit = func(cid string, depth int) {
		if done[cid] || depth > len(create) {
			return
		}
		if p := parents[cid]; p != "" && create[p] != nil {
			visit(p, depth+1)
		}
		if !done[cid] {
			done[cid] = true
			order = append(order, cid)
		}
	}
	for _, cid := range sortedKeys(create) {
		visit(cid, 0)
	}
	return order
}

// siblingNamed reports whether parent already has a mail child named name.
func (h *Handler) siblingNamed(ctx context.Context, access service.AccessContext, parent, name string) bool {
	folders, err := h.mailFolders(ctx, access)
	if err != nil {
		return false
	}
	for _, f := range folders {
		if f.ParentID == parent && strings.EqualFold(f.Name, name) {
			return true
		}
	}
	return false
}

// mailboxDestroyable applies RFC 8621 §2.5: a mailbox with children, or
// with emails unless onDestroyRemoveEmails is set, cannot be destroyed.
func (h *Handler) mailboxDestroyable(ctx context.Context, access service.AccessContext, id string, removeEmails bool) *MethodError {
	folders, err := h.mailFolders(ctx, access)
	if err != nil {
		return serverError(err)
	}
	exists := false
	for _, f := range folders {
		if f.ParentID == id {
			return &MethodError{Type: "mailboxHasChild"}
		}
		exists = exists || f.ID == id
	}
	if !exists {
		return &MethodError{Type: "notFound"}
	}
	if !removeEmails {
		items, err := h.cfg.Space.ListItems(ctx, access, id, service.ItemQuery{MetadataOnly: true})
		if err == nil && len(items) > 0 {
			return &MethodError{Type: "mailboxHasEmail"}
		}
	}
	return nil
}

func (h *Handler) changes(ctx context.Context, actor model.User, kind string, raw json.RawMessage) (any, *MethodError) {
	var a changesArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	object := service.ChangeObjectItem
	if kind == "Mailbox" {
		object = service.ChangeObjectFolder
	}
	if kind != "Mailbox" && kind != "Email" {
		current, err := h.journalState(ctx, access, object)
		if err != nil {
			return nil, serverError(err)
		}
		if a.SinceState == current {
			return emptyChanges(a.AccountID, current), nil
		}
		return nil, &MethodError{Type: "cannotCalculateChanges", Description: "thread change projection is not retained"}
	}
	folders, err := h.mailFolders(ctx, access)
	if err != nil {
		return nil, serverError(err)
	}
	limit := 100
	if a.MaxChanges != nil && *a.MaxChanges > 0 {
		limit = *a.MaxChanges
	}
	page, err := h.collectionChanges(ctx, access, folders, object, a.SinceState, limit)
	if errors.Is(err, service.ErrChangeStateExpired) || (err != nil && strings.Contains(err.Error(), "change state")) {
		return nil, &MethodError{Type: "cannotCalculateChanges", Description: err.Error()}
	}
	if err != nil {
		return nil, invalidArguments(err)
	}
	created, updated, destroyed := projectJMAPChanges(page.Records, kind == "Mailbox")
	result := map[string]any{"accountId": a.AccountID, "oldState": page.OldState, "newState": page.NewState, "hasMoreChanges": page.HasMoreChanges, "created": created, "updated": updated, "destroyed": destroyed}
	if kind == "Mailbox" {
		result["updatedProperties"] = nil
	}
	return result, nil
}

func emptyChanges(accountID, state string) map[string]any {
	return map[string]any{"accountId": accountID, "oldState": state, "newState": state, "hasMoreChanges": false, "created": []string{}, "updated": []string{}, "destroyed": []string{}}
}

// projectJMAPChanges folds journal records into JMAP created/updated/destroyed
// lists. With lifecycle set, recoverable deletion and restore count as
// destroy and create, as they do for collections.
func projectJMAPChanges(records []service.ChangeRecord, lifecycle bool) ([]string, []string, []string) {
	created, updated, destroyed := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, record := range records {
		for _, change := range record.Changes {
			op := change.Operation
			if lifecycle && op == service.ChangeTrash {
				op = service.ChangeDestroy
			}
			if lifecycle && op == service.ChangeRestore {
				op = service.ChangeCreate
			}
			switch op {
			case service.ChangeCreate:
				created[change.ID] = true
				delete(updated, change.ID)
				delete(destroyed, change.ID)
			case service.ChangeDestroy:
				if created[change.ID] {
					delete(created, change.ID)
				} else {
					destroyed[change.ID] = true
				}
				delete(updated, change.ID)
			default:
				if !created[change.ID] && !destroyed[change.ID] {
					updated[change.ID] = true
				}
			}
		}
	}
	return sortedSet(created), sortedSet(updated), sortedSet(destroyed)
}

func sortedSet(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (h *Handler) queryChanges(ctx context.Context, actor model.User, kind string, raw json.RawMessage) (any, *MethodError) {
	var a queryChangesArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	return nil, &MethodError{Type: "cannotCalculateChanges", Description: "query change history is not retained"}
}

func idSet(ids []string) map[string]bool {
	if ids == nil {
		return nil
	}
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m
}
func missing(ids []string, found map[string]bool) []string {
	out := []string{}
	for _, id := range ids {
		if !found[id] {
			out = append(out, id)
		}
	}
	return out
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func hasFlag(flags []string, flag string) bool {
	for _, v := range flags {
		if strings.EqualFold(v, flag) {
			return true
		}
	}
	return false
}
func window(ids []string, pos int, limit *int) []string {
	if pos < 0 {
		pos = 0
	}
	if pos > len(ids) {
		pos = len(ids)
	}
	end := len(ids)
	if limit != nil && *limit >= 0 && pos+*limit < end {
		end = pos + *limit
	}
	return ids[pos:end]
}
func resolveCreated(id string, created map[string]string) string {
	if strings.HasPrefix(id, "#") {
		if value, ok := created[strings.TrimPrefix(id, "#")]; ok {
			return value
		}
	}
	return id
}
