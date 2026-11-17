package app

import (
	"errors"
	"net/http"
	"strings"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

type recipientAliasMutation struct {
	Address string   `json:"address"`
	Targets []string `json:"targets"`
	Enabled bool     `json:"enabled"`
}

func (h *Handler) apiAdminRecipientAliases(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdminScope(w, r)
	if !ok {
		return
	}
	aliases, err := h.ts.RecipientAliasStore().List(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	visible := aliases[:0]
	for _, alias := range aliases {
		if scope.covers(alias.DomainID) {
			visible = append(visible, alias)
		}
	}
	jsonResponse(w, http.StatusOK, visible)
}

// authorizeRecipientAlias admits a change to the alias address and its
// targets. A domain administrator manages aliases of its domains that
// expand only to identities in domains it administers.
func (h *Handler) authorizeRecipientAlias(w http.ResponseWriter, r *http.Request, address string, targets []string) (accountAccess, bool) {
	domain := addressDomain(address)
	if !h.requireDomainAction(w, r, domain, authz.DomainIdentitiesManage) {
		return accountAccess{}, false
	}
	if h.isAdmin(r.Context(), currentActor(r).ID) {
		return accountAccess{domain: domain}, true
	}
	for _, target := range targets {
		if !h.domainAllowed(r.Context(), currentActor(r).ID, addressDomain(target), authz.DomainIdentitiesManage) {
			jsonError(w, http.StatusForbidden, "alias targets must be identities in domains you administer")
			return accountAccess{}, false
		}
	}
	return accountAccess{domain: domain, delegated: true}, true
}

func (h *Handler) apiAdminCreateRecipientAlias(w http.ResponseWriter, r *http.Request) {
	var request recipientAliasMutation
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	reach, ok := h.authorizeRecipientAlias(w, r, request.Address, request.Targets)
	if !ok {
		return
	}
	h.domainLimitMu.Lock()
	defer h.domainLimitMu.Unlock()
	if err := h.checkAliasCapacity(r.Context(), reach.domain); err != nil && !errors.Is(err, store.ErrNotFound) {
		apiError(w, err)
		return
	}
	alias, err := h.ts.RecipientAliasStore().Create(r.Context(), request.Address, request.Targets, request.Enabled)
	if err != nil {
		recipientAliasError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "recipient_alias.create", alias.Address, reach.auditDetails(map[string]string{"targets": strings.Join(alias.Targets, ",")}))
	h.events.Publish(events.Event{Type: "recipient.alias.created", Resource: alias.Address, Recipients: []string{currentActor(r).ID}})
	jsonResponse(w, http.StatusCreated, alias)
}

func (h *Handler) apiAdminUpdateRecipientAlias(w http.ResponseWriter, r *http.Request) {
	var request recipientAliasMutation
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	reach, ok := h.authorizeRecipientAlias(w, r, r.PathValue("address"), request.Targets)
	if !ok {
		return
	}
	alias, err := h.ts.RecipientAliasStore().Update(r.Context(), r.PathValue("address"), request.Targets, request.Enabled)
	if err != nil {
		recipientAliasError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "recipient_alias.update", alias.Address, reach.auditDetails(map[string]string{"targets": strings.Join(alias.Targets, ",")}))
	jsonResponse(w, http.StatusOK, alias)
}

func (h *Handler) apiAdminDeleteRecipientAlias(w http.ResponseWriter, r *http.Request) {
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	reach, ok := h.authorizeRecipientAlias(w, r, address, nil)
	if !ok {
		return
	}
	if err := h.ts.RecipientAliasStore().Delete(r.Context(), address); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "recipient_alias.delete", address, reach.auditDetails(nil))
	w.WriteHeader(http.StatusNoContent)
}

func recipientAliasError(w http.ResponseWriter, err error) {
	if errors.Is(err, model.ErrRecipientAliasInvalid) {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	apiError(w, err)
}
