package app

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/category"
	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/model"
)

// defaultCategories seed an account that has never saved a list. Their names
// are Thunderbird's default tags, so they meet $label1..$label5 on messages
// that Thunderbird tagged.
var defaultCategories = []model.Category{
	{Name: "Important", Color: "#c0392b"}, {Name: "Work", Color: "#e67e22"}, {Name: "Personal", Color: "#2e8b57"},
	{Name: "To Do", Color: "#2563a8"}, {Name: "Later", Color: "#6d57a8"},
}

type categoriesResponse struct {
	Categories []model.Category `json:"categories"`
	// Defaults is set while the account still uses the seeded list, so a
	// client may merge categories it kept locally before saving.
	Defaults bool `json:"defaults,omitempty"`
}

func (h *Handler) registerCategoryRoutes(api apiRouter) {
	api.handle("GET /api/v1/user/categories", h.apiUserCategories)
	api.handle("PUT /api/v1/user/categories", h.apiUpdateUserCategories)
}

// userCategories returns the signed-in user's master list, or the defaults
// when none was saved.
func (h *Handler) userCategories(ctx context.Context, userID string) ([]model.Category, bool, error) {
	user, err := h.users.Get(ctx, userID)
	if err != nil {
		return nil, false, err
	}
	if user.Categories == nil {
		return append([]model.Category(nil), defaultCategories...), true, nil
	}
	return user.Categories, false, nil
}

func (h *Handler) apiUserCategories(w http.ResponseWriter, r *http.Request) {
	list, defaults, err := h.userCategories(r.Context(), settingsUserID(r))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, categoriesResponse{Categories: list, Defaults: defaults})
}

// apiUpdateUserCategories replaces the master list. Items keep the category
// names they carry; a removed category simply stops having a color.
func (h *Handler) apiUpdateUserCategories(w http.ResponseWriter, r *http.Request) {
	var request categoriesResponse
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	list, err := category.Normalize(request.Categories)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID := settingsUserID(r)
	if err := h.users.UpdateCategories(r.Context(), userID, list); err != nil {
		apiError(w, err)
		return
	}
	h.auditSettings(r, "categories.update", userID, map[string]string{"count": strconv.Itoa(len(list))})
	h.workspaceChanged(r, "categories.updated", userID, nil)
	jsonResponse(w, http.StatusOK, categoriesResponse{Categories: list})
}

// annotateMailCategories resolves each row's keywords to category names.
func (h *Handler) annotateMailCategories(ctx context.Context, userID string, page *mailindex.Page) {
	list, _, err := h.userCategories(ctx, userID)
	if err != nil {
		return
	}
	page.Annotate(func(summary *mailindex.Summary) {
		summary.Categories = category.ItemCategories(model.FolderTypeMail, model.Item{Flags: summary.Flags}, list)
	})
}

// categoryActions applies "categorize" and "uncategorize" item actions,
// resolving each item's folder once per request.
type categoryActions struct {
	h       *Handler
	r       *http.Request
	folders map[string]model.Folder
}

func (c *categoryActions) apply(itemID, name string, add bool) (model.Item, error) {
	if strings.TrimSpace(name) == "" {
		return model.Item{}, errors.New("category is required for categorize and uncategorize")
	}
	actor, subject, mode := currentActor(c.r), currentSubject(c.r), currentActingMode(c.r)
	item, err := c.h.workspace.GetItem(c.r.Context(), actor, subject, mode, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if c.folders == nil {
		folders, err := c.h.workspace.ListFolders(c.r.Context(), actor, subject, mode)
		if err != nil {
			return model.Item{}, err
		}
		c.folders = make(map[string]model.Folder, len(folders))
		for _, folder := range folders {
			c.folders[folder.ID] = folder
		}
	}
	folder, ok := c.folders[item.FolderID]
	if !ok {
		return model.Item{}, category.ErrUnsupportedFolder
	}
	change, err := category.Apply(folder.Type, item, name, add)
	if err != nil || !change.Changed {
		return item, err
	}
	if folder.Type == model.FolderTypeMail {
		return c.h.workspace.SetItemFlags(c.r.Context(), actor, subject, mode, item.ID, change.Flags)
	}
	return c.h.workspace.UpdateItem(c.r.Context(), actor, subject, mode, item.ID, change.Data, item.Headers)
}
