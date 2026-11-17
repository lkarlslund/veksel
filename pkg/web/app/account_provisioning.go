package app

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"sort"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	maxProvisionCSVBytes = 1 << 20
	maxProvisionRows     = 5000
)

type accountProvisionRequest struct {
	Mode string `json:"mode"`
	CSV  string `json:"csv"`
}

type accountProvisionRow struct {
	Row          int    `json:"row"`
	ID           string `json:"id,omitempty"`
	DisplayName  string `json:"display_name,omitempty"`
	Enabled      *bool  `json:"enabled,omitempty"`
	PrimaryEmail string `json:"primary_email,omitempty"`
	Action       string `json:"action"`
	Error        string `json:"error,omitempty"`

	password       string
	displayPresent bool
	enabledPresent bool
	existing       *model.User
}

type accountProvisionResult struct {
	Mode      string                `json:"mode"`
	Valid     bool                  `json:"valid"`
	Rows      []accountProvisionRow `json:"rows"`
	Creates   int                   `json:"creates"`
	Updates   int                   `json:"updates"`
	Unchanged int                   `json:"unchanged"`
	Failed    int                   `json:"failed"`
	Applied   int                   `json:"applied"`
}

func (h *Handler) apiAdminProvisionUsers(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var request accountProvisionRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.Mode = strings.ToLower(strings.TrimSpace(request.Mode))
	if request.Mode != "preview" && request.Mode != "apply" {
		jsonError(w, http.StatusBadRequest, "mode must be preview or apply")
		return
	}
	if len(request.CSV) == 0 || len(request.CSV) > maxProvisionCSVBytes {
		jsonError(w, http.StatusBadRequest, "CSV must contain between 1 byte and 1 MiB")
		return
	}
	result, err := h.prepareAccountProvision(r.Context(), request.CSV)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	result.Mode = request.Mode
	if request.Mode == "apply" {
		if !result.Valid {
			jsonResponse(w, http.StatusUnprocessableEntity, result)
			return
		}
		h.applyAccountProvision(r.Context(), &result, currentActor(r).ID)
		h.audit.Log(currentActor(r).ID, "account.provision", "accounts", map[string]string{
			"applied": strconv.Itoa(result.Applied), "failed": strconv.Itoa(result.Failed),
		})
	}
	jsonResponse(w, http.StatusOK, result)
}

func (h *Handler) prepareAccountProvision(ctx context.Context, source string) (accountProvisionResult, error) {
	result := accountProvisionResult{Rows: []accountProvisionRow{}}
	reader := csv.NewReader(strings.NewReader(strings.TrimPrefix(source, "\ufeff")))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return result, fmt.Errorf("read CSV header: %w", err)
	}
	columns := make(map[string]int, len(header))
	allowed := map[string]bool{"id": true, "display_name": true, "password": true, "enabled": true, "primary_email": true}
	for index, name := range header {
		name = strings.ToLower(strings.TrimSpace(name))
		if !allowed[name] {
			return result, fmt.Errorf("unsupported CSV column %q", name)
		}
		if _, duplicate := columns[name]; duplicate {
			return result, fmt.Errorf("duplicate CSV column %q", name)
		}
		columns[name] = index
	}
	if _, ok := columns["id"]; !ok {
		return result, errors.New("CSV header must contain id")
	}
	users, err := h.users.List(ctx)
	if err != nil {
		return result, err
	}
	byID := make(map[string]model.User, len(users))
	for _, user := range users {
		byID[user.ID] = user
	}
	domains, err := h.ts.DomainStore().List(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return result, err
	}
	domainIDs := make(map[string]bool, len(domains))
	for _, domain := range domains {
		domainIDs[domain.ID] = true
	}
	seenIDs := map[string]int{}
	seenEmails := map[string]int{}
	for rowNumber := 2; ; rowNumber++ {
		record, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return result, fmt.Errorf("read CSV row %d: %w", rowNumber, readErr)
		}
		if len(result.Rows) >= maxProvisionRows {
			return result, fmt.Errorf("CSV exceeds %d account rows", maxProvisionRows)
		}
		blank := true
		for _, value := range record {
			blank = blank && strings.TrimSpace(value) == ""
		}
		if blank {
			continue
		}
		_, displayPresent := columns["display_name"]
		_, enabledPresent := columns["enabled"]
		row := accountProvisionRow{Row: rowNumber, Action: "invalid", displayPresent: displayPresent, enabledPresent: enabledPresent}
		value := func(name string) string {
			index, ok := columns[name]
			if !ok || index >= len(record) {
				return ""
			}
			return strings.TrimSpace(record[index])
		}
		row.ID = strings.ToLower(value("id"))
		row.DisplayName = value("display_name")
		row.password = value("password")
		row.PrimaryEmail = strings.ToLower(value("primary_email"))
		if row.ID == "" || strings.ContainsAny(row.ID, "@:/\\ ") {
			row.Error = "valid account ID required"
		} else if previous, duplicate := seenIDs[row.ID]; duplicate {
			row.Error = fmt.Sprintf("duplicate account ID; first used on row %d", previous)
		} else {
			seenIDs[row.ID] = rowNumber
		}
		if row.Error == "" && row.enabledPresent && value("enabled") != "" {
			enabled, parseErr := strconv.ParseBool(strings.ToLower(value("enabled")))
			if parseErr != nil {
				row.Error = "enabled must be true or false"
			} else {
				row.Enabled = &enabled
			}
		}
		user, exists := byID[row.ID]
		if exists {
			copyUser := user
			row.existing = &copyUser
		} else if row.Error == "" && len(row.password) < 8 {
			row.Error = "new accounts require a password of at least 8 characters"
		}
		if row.Error == "" && row.password != "" && len(row.password) < 8 {
			row.Error = "password must contain at least 8 characters"
		}
		if row.Error == "" && row.PrimaryEmail != "" {
			address, parseErr := mail.ParseAddress(row.PrimaryEmail)
			at := strings.LastIndex(row.PrimaryEmail, "@")
			if parseErr != nil || address.Address != row.PrimaryEmail || at < 1 || !domainIDs[row.PrimaryEmail[at+1:]] {
				row.Error = "primary_email must use a configured local domain"
			} else if previous, duplicate := seenEmails[row.PrimaryEmail]; duplicate {
				row.Error = fmt.Sprintf("duplicate primary email; first used on row %d", previous)
			} else {
				seenEmails[row.PrimaryEmail] = rowNumber
				identity, identityErr := h.users.GetEmailAddress(ctx, row.PrimaryEmail)
				if identityErr == nil && identity.UserID != row.ID {
					row.Error = "primary email belongs to another account"
				} else if identityErr != nil && !errors.Is(identityErr, store.ErrNotFound) {
					return result, identityErr
				}
			}
		}
		if row.Error == "" {
			row.Action = h.accountProvisionAction(ctx, &row)
		}
		result.Rows = append(result.Rows, row)
	}
	if len(result.Rows) == 0 {
		return result, errors.New("CSV contains no account rows")
	}
	for index := range result.Rows {
		switch result.Rows[index].Action {
		case "create":
			result.Creates++
		case "update":
			result.Updates++
		case "unchanged":
			result.Unchanged++
		default:
			result.Failed++
		}
	}
	result.Valid = result.Failed == 0
	return result, nil
}

func (h *Handler) accountProvisionAction(ctx context.Context, row *accountProvisionRow) string {
	if row.existing == nil {
		return "create"
	}
	user := row.existing
	changed := row.displayPresent && user.DisplayName != row.DisplayName || row.Enabled != nil && user.Enabled != *row.Enabled || row.password != "" && !auth.ComparePassword(row.password, user.PasswordHash)
	if row.PrimaryEmail != "" {
		identity, err := h.users.GetEmailAddress(ctx, row.PrimaryEmail)
		changed = changed || errors.Is(err, store.ErrNotFound) || err == nil && (!identity.Primary || !identity.Enabled)
	}
	if changed {
		return "update"
	}
	return "unchanged"
}

func (h *Handler) applyAccountProvision(ctx context.Context, result *accountProvisionResult, actor string) {
	// Re-parse is intentionally unnecessary here: prepare retained the secrets in
	// memory but JSON serialization never exposes them. Every row was validated
	// against current state immediately before this sequential apply.
	for index := range result.Rows {
		row := &result.Rows[index]
		if row.Action == "unchanged" {
			continue
		}
		var err error
		if row.Action == "create" {
			displayName := row.DisplayName
			if displayName == "" {
				displayName = row.ID
			}
			err = h.createAccount(ctx, row.ID, displayName, row.password)
		} else {
			var passwordHash string
			if row.password != "" && !auth.ComparePassword(row.password, row.existing.PasswordHash) {
				passwordHash, err = auth.HashPassword(row.password)
			}
			if err == nil {
				err = h.users.Update(ctx, row.ID, func(user *model.User) {
					if row.displayPresent {
						user.DisplayName = row.DisplayName
					}
					if row.Enabled != nil {
						user.Enabled = *row.Enabled
					}
					if passwordHash != "" {
						user.PasswordHash = passwordHash
					}
				})
			}
		}
		if err == nil && row.PrimaryEmail != "" {
			identity, identityErr := h.users.GetEmailAddress(ctx, row.PrimaryEmail)
			switch {
			case errors.Is(identityErr, store.ErrNotFound):
				at := strings.LastIndex(row.PrimaryEmail, "@")
				err = h.users.AddEmailAddress(ctx, row.PrimaryEmail, row.ID, row.PrimaryEmail[at+1:], true)
			case identityErr != nil:
				err = identityErr
			case !identity.Enabled || !identity.Primary:
				err = h.users.UpdateEmailAddress(ctx, row.PrimaryEmail, true, true)
			}
		}
		if err == nil {
			err = h.syncAccountManifest(ctx, row.ID)
		}
		if err != nil {
			if row.Action == "create" {
				result.Creates--
			} else if row.Action == "update" {
				result.Updates--
			}
			row.Action = "failed"
			row.Error = err.Error()
			result.Failed++
			result.Valid = false
			continue
		}
		result.Applied++
		h.events.Publish(events.Event{Type: "account.provisioned", Resource: row.ID, Recipients: []string{actor}})
	}
	sort.SliceStable(result.Rows, func(i, j int) bool { return result.Rows[i].Row < result.Rows[j].Row })
}
