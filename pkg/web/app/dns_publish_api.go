package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/dnsprovider"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
)

// dnsPublishTimeout bounds one publish, including provider listing.
const dnsPublishTimeout = time.Minute

// dnsPublishResponse is a publish plan, or an applied plan's outcome with a
// summary of failed changes.
type dnsPublishResponse struct {
	dnsprovider.PlanResult
	Error string `json:"error,omitempty"`
}

// DNSZones exposes the DNS provider zones, for ACME DNS-01 and health.
func (h *Handler) DNSZones() *dnsprovider.Zones { return h.dnsZones }

func (h *Handler) apiAdminDNSZones(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	zones, err := h.dnsZones.List(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"zones": zones})
}

func (h *Handler) apiAdminPutDNSZone(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var input dnsprovider.ZoneInput
	if err := decodeJSON(r, &input); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	view, err := h.dnsZones.Put(r.Context(), currentActor(r).ID, r.PathValue("zone"), input)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, view)
}

func (h *Handler) apiAdminDeleteDNSZone(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if err := h.dnsZones.Delete(r.Context(), currentActor(r).ID, r.PathValue("zone")); err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// domainDesired returns the domain's publishable records. The SPF check
// evaluates the live policy, so any SPF record the guidance already accepts
// as authorizing this server is left alone rather than replaced.
func (h *Handler) domainDesired(ctx context.Context, domain model.Domain) []dnsprovider.Desired {
	spfAuthorized := false
	for _, rec := range h.domainDNSGuidance(ctx, domain).Records {
		spfAuthorized = spfAuthorized || (rec.Type == "SPF" && rec.Status == dnsOK)
	}
	var desired []dnsprovider.Desired
	for _, want := range dnsExpectations(domain, h.smtpIdentity(), h.dnsOptions()) {
		if want.Kind == "SPF" && spfAuthorized {
			want.Accept = func(string) bool { return true }
		}
		desired = append(desired, want.Desired)
	}
	return desired
}

func (h *Handler) publishDomain(w http.ResponseWriter, r *http.Request) (model.Domain, bool) {
	if !h.requireAdminAPI(w, r) {
		return model.Domain{}, false
	}
	domain, err := h.ts.DomainStore().Get(r.Context(), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return model.Domain{}, false
	}
	return domain, true
}

func writeDNSPublishError(w http.ResponseWriter, err error) {
	if errors.Is(err, dnsprovider.ErrNoProvider) {
		jsonError(w, http.StatusConflict, "no DNS provider is configured for this domain")
		return
	}
	jsonError(w, http.StatusBadGateway, err.Error())
}

// apiAdminDNSPublishPlan shows the dry-run diff of the domain's records.
func (h *Handler) apiAdminDNSPublishPlan(w http.ResponseWriter, r *http.Request) {
	domain, ok := h.publishDomain(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), dnsPublishTimeout)
	defer cancel()
	plan, err := h.dnsZones.Plan(ctx, domain.ID, h.domainDesired(ctx, domain), dnsprovider.Scope{Purpose: domain.ID})
	if err != nil {
		writeDNSPublishError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, dnsPublishResponse{PlanResult: plan})
}

// apiAdminDNSPublish applies the plan. Records Veksel did not create are
// replaced only with overwrite_conflicts and never deleted.
func (h *Handler) apiAdminDNSPublish(w http.ResponseWriter, r *http.Request) {
	domain, ok := h.publishDomain(w, r)
	if !ok {
		return
	}
	var request struct {
		OverwriteConflicts bool `json:"overwrite_conflicts"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), dnsPublishTimeout)
	defer cancel()
	result, err := h.dnsZones.Apply(ctx, currentActor(r).ID, domain.ID, h.domainDesired(ctx, domain), dnsprovider.Scope{Purpose: domain.ID},
		dnsprovider.ApplyOptions{OverwriteConflicts: request.OverwriteConflicts})
	if result.Zone == "" && err != nil {
		writeDNSPublishError(w, err)
		return
	}
	response := dnsPublishResponse{PlanResult: result}
	if err != nil {
		response.Error = err.Error()
	}
	h.refreshRuntimeHealth(r.Context())
	jsonResponse(w, http.StatusOK, response)
}

// syncDKIMRecords is the DKIM rotation hook: after a key is staged or
// retired it publishes every current selector and deletes the owned records
// of removed selectors, when a provider covers the domain. Failures are
// audited, degrade DNS provider health, and are returned to the caller; the
// key lifecycle change itself has already been committed.
func (h *Handler) syncDKIMRecords(ctx context.Context, actor string, domain model.Domain) *dnsPublishResponse {
	if _, err := h.dnsZones.ForName(ctx, domain.ID); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, dnsPublishTimeout)
	defer cancel()
	var desired []dnsprovider.Desired
	for _, want := range dnsExpectations(domain, h.smtpIdentity(), h.dnsOptions()) {
		if want.Kind == "DKIM" {
			desired = append(desired, want.Desired)
		}
	}
	suffix := "._domainkey." + domain.ID
	scope := dnsprovider.Scope{Purpose: domain.ID, Match: func(rec model.DNSOwnedRecord) bool {
		return strings.EqualFold(rec.Type, "TXT") && strings.HasSuffix(rec.Name, suffix)
	}}
	result, err := h.dnsZones.Apply(ctx, actor, domain.ID, desired, scope, dnsprovider.ApplyOptions{})
	response := &dnsPublishResponse{PlanResult: result}
	if err != nil {
		response.Error = err.Error()
		log.Warn("DKIM DNS publish failed", "domain", domain.ID, "error", err)
	}
	h.refreshRuntimeHealth(ctx)
	return response
}

func (h *Handler) refreshRuntimeHealth(ctx context.Context) {
	if h.refreshHealth != nil {
		h.refreshHealth(ctx)
	}
}
