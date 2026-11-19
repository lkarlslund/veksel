package app

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

const accountSettingsExportFormat = "veksel-account-settings"

type accountSettingsExport struct {
	Format     string                          `json:"format"`
	Version    int                             `json:"version"`
	ExportedAt time.Time                       `json:"exported_at"`
	Account    accountSettingsExportAccount    `json:"account"`
	Identities []accountSettingsExportIdentity `json:"identities"`
	Mail       accountSettingsExportMail       `json:"mail"`
}

type accountSettingsExportAccount struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type accountSettingsExportIdentity struct {
	Address   string               `json:"address"`
	Domain    string               `json:"domain"`
	Primary   bool                 `json:"primary"`
	Enabled   bool                 `json:"enabled"`
	CreatedAt time.Time            `json:"created_at"`
	Signature *model.MailSignature `json:"signature,omitempty"`
}

type accountSettingsExportMail struct {
	ForwardTo       string     `json:"forward_to,omitempty"`
	SieveActive     bool       `json:"sieve_active"`
	SieveScript     string     `json:"sieve_script,omitempty"`
	SpamEnabled     bool       `json:"spam_enabled"`
	SpamThreshold   float64    `json:"spam_threshold"`
	Vacation        bool       `json:"vacation_enabled"`
	VacationStart   *time.Time `json:"vacation_start,omitzero"`
	VacationEnd     *time.Time `json:"vacation_end,omitzero"`
	VacationSubject string     `json:"vacation_subject,omitempty"`
	VacationMessage string     `json:"vacation_message,omitempty"`
}

func (h *Handler) apiUserAccountExport(w http.ResponseWriter, r *http.Request) {
	userID := settingsUserID(r)
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
	sort.Slice(identities, func(i, j int) bool { return identities[i].ID < identities[j].ID })
	settings := accountSettingsExport{
		Format: accountSettingsExportFormat, Version: 1, ExportedAt: time.Now().UTC(),
		Account:    accountSettingsExportAccount{ID: user.ID, DisplayName: user.DisplayName, Enabled: user.Enabled, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt},
		Identities: make([]accountSettingsExportIdentity, 0, len(identities)),
		Mail: accountSettingsExportMail{
			ForwardTo: user.ForwardTo, SieveActive: user.SieveActive, SieveScript: user.SieveScript,
			SpamEnabled: user.SpamEnabled, SpamThreshold: user.SpamThreshold,
			Vacation: user.VacationEnabled, VacationStart: exportTime(user.VacationStart), VacationEnd: exportTime(user.VacationEnd),
			VacationSubject: user.VacationSubject, VacationMessage: user.VacationMessage,
		},
	}
	for _, identity := range identities {
		projection := accountSettingsExportIdentity{
			Address: identity.ID, Domain: identity.DomainID, Primary: identity.Primary,
			Enabled: identity.Enabled, CreatedAt: identity.CreatedAt,
		}
		if signature, ok := user.MailSignatures[identity.ID]; ok {
			copy := signature
			projection.Signature = &copy
		}
		settings.Identities = append(settings.Identities, projection)
	}
	settingsJSON, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "account settings could not be encoded")
		return
	}

	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if disposition := mime.FormatMediaType("attachment", map[string]string{"filename": user.ID + "-veksel-export.zip"}); disposition != "" {
		w.Header().Set("Content-Disposition", disposition)
	}
	refreshExportWriteDeadline(w)
	counter := &responseByteCounter{ResponseWriter: w}
	report, err := service.ExportAccount(r.Context(), h.folderSpace, service.UserAccess(userID, "web-account-export"), userID, settingsJSON, counter)
	if err != nil {
		h.audit.Log(userID, "account.export", userID, map[string]string{"result": "failed", "error": err.Error()})
		if counter.written == 0 {
			w.Header().Del("Content-Disposition")
			w.Header().Set("Content-Type", "application/json")
			apiError(w, err)
		}
		return
	}
	h.audit.Log(userID, "account.export", userID, map[string]string{
		"result": "succeeded", "folders": strconv.FormatInt(report.Folders, 10),
		"items": strconv.FormatInt(report.Items, 10), "bytes": strconv.FormatInt(report.Bytes, 10),
	})
	if counter.written == 0 {
		w.WriteHeader(http.StatusOK)
	}
}

func exportTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	value = value.UTC()
	return &value
}
