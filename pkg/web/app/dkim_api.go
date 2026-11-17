package app

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

type adminDomainResponse struct {
	ID               string    `json:"id"`
	Enabled          bool      `json:"enabled"`
	CreatedAt        time.Time `json:"created_at"`
	VirusScanEnabled bool      `json:"virus_scan_enabled"`
	CatchAll         string    `json:"catch_all"`
	// UnknownRecipients is the split-delivery policy.
	UnknownRecipients model.UnknownRecipientPolicy `json:"unknown_recipients"`
	DKIMConfigured    bool                         `json:"dkim_configured"`
	DKIMSelector      string                       `json:"dkim_selector,omitempty"`
	DKIMRevision      uint64                       `json:"dkim_revision"`
	// Limits and Usage show the domain's ceilings against what it consumes.
	Limits model.DomainLimits `json:"limits"`
	Usage  *model.DomainUsage `json:"usage,omitempty"`
}

type adminDKIMKeyResponse struct {
	Selector    string             `json:"selector"`
	State       model.DKIMKeyState `json:"state"`
	CreatedAt   time.Time          `json:"created_at"`
	ActivatedAt *time.Time         `json:"activated_at,omitzero"`
	DNSName     string             `json:"dns_name"`
	DNSRecord   string             `json:"dns_record"`
}

type adminDKIMKeysResponse struct {
	Domain   string                 `json:"domain"`
	Revision uint64                 `json:"revision"`
	Keys     []adminDKIMKeyResponse `json:"keys"`
	// DNSPublish reports the automatic DNS provider publication that
	// followed staging or retiring a key, when a provider covers the domain.
	DNSPublish *dnsPublishResponse `json:"dns_publish,omitempty"`
}

func projectAdminDomain(domain model.Domain) adminDomainResponse {
	response := adminDomainResponse{
		ID: domain.ID, Enabled: domain.Enabled, CreatedAt: domain.CreatedAt,
		VirusScanEnabled: domain.VirusScanEnabled, CatchAll: domain.CatchAll, DKIMRevision: domain.DKIMRevision,
		UnknownRecipients: domain.UnknownRecipients,
		Limits:            domain.Limits,
	}
	if active, ok := model.ActiveDKIMKey(domain); ok {
		response.DKIMConfigured = true
		response.DKIMSelector = active.Selector
	}
	return response
}

func projectAdminDKIMKeys(domain model.Domain) adminDKIMKeysResponse {
	response := adminDKIMKeysResponse{Domain: domain.ID, Revision: domain.DKIMRevision, Keys: []adminDKIMKeyResponse{}}
	for _, key := range model.DKIMKeys(domain) {
		projected := adminDKIMKeyResponse{
			Selector: key.Selector, State: key.State, CreatedAt: key.CreatedAt,
			DNSName:   fmt.Sprintf("%s._domainkey.%s", key.Selector, domain.ID),
			DNSRecord: dkim.DKIMDNSRecord([]byte(key.PublicKey)),
		}
		if !key.ActivatedAt.IsZero() {
			activatedAt := key.ActivatedAt
			projected.ActivatedAt = &activatedAt
		}
		response.Keys = append(response.Keys, projected)
	}
	return response
}

func (h *Handler) apiAdminDKIMKeys(w http.ResponseWriter, r *http.Request) {
	if !h.requireDomainAction(w, r, r.PathValue("id"), authz.DomainRead) {
		return
	}
	domain, err := h.ts.DomainStore().Get(r.Context(), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, projectAdminDKIMKeys(domain))
}

func (h *Handler) apiAdminStageDKIMKey(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var request struct {
		Selector string `json:"selector"`
		Revision uint64 `json:"revision"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(request.Selector) == "" {
		request.Selector = "s" + time.Now().UTC().Format("20060102150405")
	}
	selector, err := model.ValidateDKIMSelector(request.Selector)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	privateKey, publicKey, err := dkim.GenerateKeyPair()
	if err != nil {
		apiError(w, err)
		return
	}
	domain, err := h.ts.DomainStore().StageDKIMKey(r.Context(), r.PathValue("id"), request.Revision, model.DKIMKey{
		Selector: selector, PrivateKey: string(privateKey), PublicKey: string(publicKey),
	})
	if err != nil {
		writeDKIMLifecycleError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "domain.dkim.stage", domain.ID, map[string]string{"selector": selector, "revision": fmt.Sprint(domain.DKIMRevision)})
	response := projectAdminDKIMKeys(domain)
	response.DNSPublish = h.syncDKIMRecords(r.Context(), currentActor(r).ID, domain)
	jsonResponse(w, http.StatusCreated, response)
}

func (h *Handler) apiAdminActivateDKIMKey(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	request, ok := decodeDKIMRevision(w, r)
	if !ok {
		return
	}
	domain, err := h.ts.DomainStore().ActivateDKIMKey(r.Context(), r.PathValue("id"), r.PathValue("selector"), request)
	if err != nil {
		writeDKIMLifecycleError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "domain.dkim.activate", domain.ID, map[string]string{"selector": strings.ToLower(r.PathValue("selector")), "revision": fmt.Sprint(domain.DKIMRevision)})
	jsonResponse(w, http.StatusOK, projectAdminDKIMKeys(domain))
}

func (h *Handler) apiAdminDeleteDKIMKey(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	request, ok := decodeDKIMRevision(w, r)
	if !ok {
		return
	}
	selector := r.PathValue("selector")
	domain, err := h.ts.DomainStore().DeleteDKIMKey(r.Context(), r.PathValue("id"), selector, request)
	if err != nil {
		writeDKIMLifecycleError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "domain.dkim.remove", domain.ID, map[string]string{"selector": strings.ToLower(selector), "revision": fmt.Sprint(domain.DKIMRevision)})
	response := projectAdminDKIMKeys(domain)
	response.DNSPublish = h.syncDKIMRecords(r.Context(), currentActor(r).ID, domain)
	jsonResponse(w, http.StatusOK, response)
}

func decodeDKIMRevision(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	var request struct {
		Revision uint64 `json:"revision"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return 0, false
	}
	return request.Revision, true
}

func writeDKIMLifecycleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, model.ErrDKIMRevisionConflict):
		jsonError(w, http.StatusConflict, "DKIM keys changed; reload and try again")
	case errors.Is(err, model.ErrDKIMSelectorExists), errors.Is(err, model.ErrDKIMKeyState), errors.Is(err, model.ErrDKIMKeyLimit):
		jsonError(w, http.StatusConflict, err.Error())
	case errors.Is(err, model.ErrDKIMKeyNotFound), errors.Is(err, store.ErrNotFound):
		jsonError(w, http.StatusNotFound, "DKIM key not found")
	default:
		jsonError(w, http.StatusBadRequest, err.Error())
	}
}
