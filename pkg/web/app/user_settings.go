package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

var userSettingsSections = map[string]struct{}{
	"profile": {}, "two-factor": {}, "sessions": {}, "app-passwords": {}, "api-keys": {}, "webhooks": {}, "devices": {}, "vacation": {}, "display": {}, "mail": {}, "categories": {}, "identities": {}, "aliases": {}, "encryption-keys": {}, "notifications": {}, "storage": {}, "rules": {}, "access": {}, "delegation": {}, "share-links": {}, "sync": {}, "migration": {},
}

func validUserSettingsSection(section string) bool {
	_, ok := userSettingsSections[section]
	return ok
}

func (h *Handler) handleUserSettings(w http.ResponseWriter, r *http.Request) {
	section := r.PathValue("section")
	if section == "migration" {
		http.Redirect(w, r, "/app/settings/sync", http.StatusPermanentRedirect)
		return
	}
	if !validUserSettingsSection(section) {
		http.NotFound(w, r)
		return
	}
	if section == "sync" {
		section = "migration"
	}
	session, _ := sessionFromContext(r.Context())
	scope := h.adminScopeFor(r.Context(), session.ActorID)
	h.render(w, "app.gohtml", map[string]any{
		"Page": "settings", "SettingsSection": section, "Session": session,
		"IsAdmin": scope.system, "DomainAdmin": !scope.system && scope.any(), "CSRF": h.csrfValue(r),
	}, http.StatusOK)
}

type userSettingsResponse struct {
	ID              string                 `json:"id"`
	DisplayName     string                 `json:"display_name"`
	Identities      []userIdentityResponse `json:"identities"`
	VacationEnabled bool                   `json:"vacation_enabled"`
	VacationStart   string                 `json:"vacation_start"`
	VacationEnd     string                 `json:"vacation_end"`
	VacationSubject string                 `json:"vacation_subject"`
	VacationMessage string                 `json:"vacation_message"`
	// Source is "ldap" for a directory account, whose password is changed
	// in the directory rather than here.
	Source          string                  `json:"source,omitempty"`
	MailPreferences mailPreferencesResponse `json:"mail_preferences"`
	// DisplayPreferences and NotificationPreferences are the effective
	// account-wide web app settings; saved=false asks the browser to migrate
	// its older per-browser choices once.
	DisplayPreferences      model.DisplayPreferences      `json:"display_preferences"`
	NotificationPreferences model.NotificationPreferences `json:"notification_preferences"`
}

// mailPreferencesResponse reports the effective webmail behavior settings.
type mailPreferencesResponse struct {
	UndoSendSeconds int    `json:"undo_send_seconds"`
	Shortcuts       string `json:"shortcuts"`
}

func mailPreferencesView(preferences model.MailPreferences) mailPreferencesResponse {
	return mailPreferencesResponse{UndoSendSeconds: preferences.UndoSend(), Shortcuts: preferences.ShortcutSet()}
}

type userIdentityResponse struct {
	Address   string `json:"address"`
	Primary   bool   `json:"primary"`
	Delegated bool   `json:"delegated,omitempty"`
	// Alias marks an active temporary alias usable as a reply identity.
	Alias     bool                 `json:"alias,omitempty"`
	Modes     []string             `json:"modes"`
	Signature *model.MailSignature `json:"signature,omitempty"`
}

func (h *Handler) apiUserSettings(w http.ResponseWriter, r *http.Request) {
	userID := currentActor(r).ID
	user, err := h.users.Get(r.Context(), userID)
	if err != nil {
		apiError(w, err)
		return
	}
	identities, err := h.users.ListEmailAddressesForUser(r.Context(), userID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		apiError(w, err)
		return
	}
	addresses := make([]userIdentityResponse, 0, len(identities))
	for _, identity := range identities {
		if !identity.Enabled {
			continue
		}
		addresses = append(addresses, userIdentityResponse{
			Address: identity.ID, Primary: identity.Primary,
			Modes: []string{"normal", "send_as"}, Signature: signatureFor(user.MailSignatures, identity.ID),
		})
	}
	aliases, err := h.ts.UserAliasStore().ListForUser(r.Context(), userID)
	if err != nil {
		apiError(w, err)
		return
	}
	now := time.Now()
	for _, alias := range aliases {
		if alias.Active(now) {
			addresses = append(addresses, userIdentityResponse{Address: alias.Address, Alias: true, Modes: []string{"normal"}})
		}
	}
	if h.authorization != nil {
		delegated, err := h.authorization.ListDelegatedSendingIdentities(r.Context(), currentActor(r), time.Now().UTC())
		if err != nil {
			apiError(w, err)
			return
		}
		for _, identity := range delegated {
			modes := make([]string, 0, len(identity.Modes))
			for _, mode := range identity.Modes {
				switch mode {
				case authz.IdentitySendAs:
					modes = append(modes, "send_as")
				case authz.IdentitySendOnBehalf:
					modes = append(modes, "send_on_behalf")
				}
			}
			addresses = append(addresses, userIdentityResponse{Address: identity.Address, Delegated: true, Modes: modes})
		}
	}
	formatTime := func(value time.Time) string {
		if value.IsZero() {
			return ""
		}
		return value.UTC().Format(time.RFC3339)
	}
	jsonResponse(w, http.StatusOK, userSettingsResponse{
		ID: user.ID, DisplayName: user.DisplayName, Identities: addresses,
		VacationEnabled: user.VacationEnabled, VacationStart: formatTime(user.VacationStart),
		VacationEnd: formatTime(user.VacationEnd), VacationSubject: user.VacationSubject,
		VacationMessage: user.VacationMessage, Source: user.Source, MailPreferences: mailPreferencesView(user.MailPreferences),
		DisplayPreferences: user.DisplayPreferences.Effective(), NotificationPreferences: user.NotificationPreferences.Effective(),
	})
}

func signatureFor(signatures map[string]model.MailSignature, address string) *model.MailSignature {
	signature, ok := signatures[strings.ToLower(address)]
	if !ok {
		return nil
	}
	copy := signature
	return &copy
}

func (h *Handler) apiUserMailSignature(w http.ResponseWriter, r *http.Request) {
	var request model.MailSignature
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.Text = strings.ReplaceAll(strings.ReplaceAll(request.Text, "\r\n", "\n"), "\r", "\n")
	if len(request.Text) > 10_000 || strings.ContainsRune(request.Text, '\x00') || len(request.HTML) > 50_000 || strings.ContainsRune(request.HTML, '\x00') {
		jsonError(w, http.StatusBadRequest, "signature must be at most 10000 bytes of text and 50000 bytes of HTML and contain no null characters")
		return
	}
	// A rich signature is stored sanitized and always carries a plain-text
	// form, so plain-text composing and older clients keep working.
	if request.HTML = service.SanitizeComposeHTML(request.HTML); request.HTML != "" {
		if text := service.HTMLToText(request.HTML); text != "" {
			request.Text = text
		} else if strings.TrimSpace(request.Text) == "" {
			request.HTML = ""
		}
	}
	if request.Text == "" {
		request.NewMessages, request.RepliesForwards = false, false
	}
	userID := currentActor(r).ID
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	if err := h.users.UpdateMailSignature(r.Context(), userID, address, request); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			jsonError(w, http.StatusNotFound, "owned email identity not found")
			return
		}
		apiError(w, err)
		return
	}
	h.audit.Log(userID, "signature.update", address, map[string]string{
		"configured": strconv.FormatBool(request.Text != ""), "new_messages": strconv.FormatBool(request.NewMessages),
		"replies_forwards": strconv.FormatBool(request.RepliesForwards), "bytes": strconv.Itoa(len(request.Text)), "html": strconv.FormatBool(request.HTML != ""),
	})
	jsonResponse(w, http.StatusOK, request)
}

// apiUserMailPreferences replaces the owner's undo-send hold and keyboard
// shortcut set.
func (h *Handler) apiUserMailPreferences(w http.ResponseWriter, r *http.Request) {
	var request mailPreferencesResponse
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !slices.Contains(model.UndoSendChoices, request.UndoSendSeconds) {
		jsonError(w, http.StatusBadRequest, "undo_send_seconds must be 0, 5, 10, 20, or 30")
		return
	}
	if !slices.Contains(model.ShortcutSets, request.Shortcuts) {
		jsonError(w, http.StatusBadRequest, "shortcuts must be owa, gmail, or off")
		return
	}
	undo := request.UndoSendSeconds
	preferences := model.MailPreferences{UndoSendSeconds: &undo, Shortcuts: request.Shortcuts}
	userID := currentActor(r).ID
	if err := h.users.UpdateMailPreferences(r.Context(), userID, preferences); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(userID, "mail.preferences.update", userID, map[string]string{"undo_send_seconds": strconv.Itoa(undo), "shortcuts": request.Shortcuts})
	jsonResponse(w, http.StatusOK, mailPreferencesView(preferences))
}

// apiUserDisplayPreferences replaces the signed-in person's display
// settings with a complete, validated set.
func (h *Handler) apiUserDisplayPreferences(w http.ResponseWriter, r *http.Request) {
	var request model.DisplayPreferences
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := request.Validate(); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID := currentActor(r).ID
	if err := h.users.UpdateDisplayPreferences(r.Context(), userID, request); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(userID, "user.display_preferences.update", userID, map[string]string{
		"time_zone": request.TimeZone, "time_format": request.TimeFormat, "date_order": request.DateOrder,
		"week_start": strconv.Itoa(request.WeekStart), "density": request.Density, "reading_pane": request.ReadingPane,
	})
	jsonResponse(w, http.StatusOK, request.Effective())
}

// apiUserNotificationPreferences replaces the signed-in person's desktop
// notification settings.
func (h *Handler) apiUserNotificationPreferences(w http.ResponseWriter, r *http.Request) {
	var request model.NotificationPreferences
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := request.Validate(); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID := currentActor(r).ID
	if err := h.users.UpdateNotificationPreferences(r.Context(), userID, request); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(userID, "user.notification_preferences.update", userID, map[string]string{
		"new_mail": strconv.FormatBool(request.NewMail), "favorites": strconv.FormatBool(request.Favorites),
		"meetings": strconv.FormatBool(request.Meetings), "follow_ups": strconv.FormatBool(request.FollowUps),
		"sound": strconv.FormatBool(request.Sound), "quiet_hours": strconv.FormatBool(request.QuietHours),
	})
	jsonResponse(w, http.StatusOK, request.Effective())
}

// clientPreferences is the preference bootstrap embedded in the app shell so
// display settings apply before the first API round trip.
func (h *Handler) clientPreferences(ctx context.Context, userID string) string {
	user, err := h.users.Get(ctx, userID)
	if err != nil {
		return ""
	}
	data, err := json.Marshal(map[string]any{
		"display": user.DisplayPreferences.Effective(), "notifications": user.NotificationPreferences.Effective(),
	})
	if err != nil {
		return ""
	}
	return string(data)
}

func (h *Handler) apiUserProfile(w http.ResponseWriter, r *http.Request) {
	var request struct {
		DisplayName     *string `json:"display_name"`
		CurrentPassword string  `json:"current_password"`
		NewPassword     string  `json:"new_password"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.DisplayName == nil && request.NewPassword == "" {
		jsonError(w, http.StatusBadRequest, "no profile changes supplied")
		return
	}
	if request.DisplayName != nil && len(strings.TrimSpace(*request.DisplayName)) > 200 {
		jsonError(w, http.StatusBadRequest, "display name is too long")
		return
	}
	userID := currentActor(r).ID
	var passwordHash string
	if request.NewPassword != "" {
		if len(request.NewPassword) < 8 {
			jsonError(w, http.StatusBadRequest, "new password must contain at least 8 characters")
			return
		}
		user, err := h.users.Get(r.Context(), userID)
		if err != nil {
			apiError(w, err)
			return
		}
		if user.Directory() {
			apiError(w, model.ErrDirectoryPassword)
			return
		}
		if !auth.ComparePassword(request.CurrentPassword, user.PasswordHash) {
			jsonError(w, http.StatusForbidden, "current password is incorrect")
			return
		}
		passwordHash, err = auth.HashPassword(request.NewPassword)
		if err != nil {
			apiError(w, err)
			return
		}
	}
	update := func(ctx context.Context) error {
		return h.users.Update(ctx, userID, func(user *model.User) {
			if request.DisplayName != nil {
				user.DisplayName = strings.TrimSpace(*request.DisplayName)
			}
			if passwordHash != "" {
				user.PasswordHash = passwordHash
			}
		})
	}
	var (
		revoked   []model.Session
		updateErr error
	)
	if passwordHash != "" {
		current, _ := sessionFromContext(r.Context())
		revoked, updateErr = h.sessions.UpdateActorAndDeleteOthers(r.Context(), userID, current.ID, update)
	} else {
		updateErr = update(r.Context())
	}
	if updateErr != nil {
		apiError(w, updateErr)
		return
	}
	if passwordHash != "" {
		h.recordBrowserSessionRevocations(userID, revoked, "password_changed")
	}
	h.audit.Log(userID, "profile.update", userID, map[string]string{
		"display_name_changed": strconv.FormatBool(request.DisplayName != nil),
		"password_changed":     strconv.FormatBool(passwordHash != ""),
		"sessions_revoked":     strconv.Itoa(len(revoked)),
	})
	jsonResponse(w, http.StatusOK, map[string]string{"id": userID})
}

func (h *Handler) apiUserVacation(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Enabled bool   `json:"enabled"`
		Start   string `json:"start"`
		End     string `json:"end"`
		Subject string `json:"subject"`
		Message string `json:"message"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.Subject = strings.TrimSpace(request.Subject)
	request.Message = strings.TrimSpace(request.Message)
	if request.Enabled && request.Message == "" {
		jsonError(w, http.StatusBadRequest, "an auto-reply message is required when enabled")
		return
	}
	if len(request.Subject) > 200 || len(request.Message) > 10000 {
		jsonError(w, http.StatusBadRequest, "auto-reply content is too long")
		return
	}
	parseTime := func(value string) (time.Time, error) {
		if value == "" {
			return time.Time{}, nil
		}
		return time.Parse(time.RFC3339, value)
	}
	start, err := parseTime(request.Start)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid start time")
		return
	}
	end, err := parseTime(request.End)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid end time")
		return
	}
	if !start.IsZero() && !end.IsZero() && !end.After(start) {
		jsonError(w, http.StatusBadRequest, "end time must be after start time")
		return
	}
	userID := currentActor(r).ID
	if err := h.users.UpdateVacation(r.Context(), userID, request.Enabled, start, end, request.Subject, request.Message); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(userID, "vacation.update", userID, map[string]string{"enabled": strconv.FormatBool(request.Enabled)})
	jsonResponse(w, http.StatusOK, map[string]bool{"enabled": request.Enabled})
}
