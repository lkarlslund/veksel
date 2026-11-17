package app

import (
	"errors"
	"net/http"

	"github.com/lkarlslund/veksel/pkg/dnsprovider"
	"github.com/lkarlslund/veksel/pkg/dnsserver"
)

// ConfigureDNSServer connects the built-in authoritative DNS server, whose
// status the zone records view shows.
func (h *Handler) ConfigureDNSServer(server *dnsserver.Server) { h.dnsServer = server }

// hostedZoneResponse is a built-in zone with the DNS server's state. DS
// records are offered to the registrar only while DNSSEC signing is on.
type hostedZoneResponse struct {
	dnsprovider.HostedZoneView
	Server dnsserver.Status `json:"server"`
}

func writeHostedError(w http.ResponseWriter, err error) {
	if errors.Is(err, dnsprovider.ErrNotHosted) {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	apiError(w, err)
}

func (h *Handler) hostedZoneResponse(r *http.Request) (hostedZoneResponse, error) {
	view, err := h.dnsZones.HostedZone(r.Context(), r.PathValue("zone"))
	if err != nil {
		return hostedZoneResponse{}, err
	}
	response := hostedZoneResponse{HostedZoneView: view, Server: dnsserver.Status{Nameservers: []string{}}}
	if h.dnsServer != nil {
		response.Server = h.dnsServer.Status()
	}
	return response, nil
}

func (h *Handler) apiAdminHostedZone(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	response, err := h.hostedZoneResponse(r)
	if err != nil {
		writeHostedError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) apiAdminAddHostedRecord(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var rec dnsprovider.Record
	if err := decodeJSON(r, &rec); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	stored, err := h.dnsZones.AddHostedRecord(r.Context(), currentActor(r).ID, r.PathValue("zone"), rec)
	if err != nil {
		writeHostedError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, stored)
}

func (h *Handler) apiAdminDeleteHostedRecord(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if err := h.dnsZones.DeleteHostedRecord(r.Context(), currentActor(r).ID, r.PathValue("zone"), r.PathValue("id")); err != nil {
		writeHostedError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apiAdminDNSSECRollover performs one manual DNSSEC key rollover step.
func (h *Handler) apiAdminDNSSECRollover(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	step, err := h.dnsZones.RollDNSSECKey(r.Context(), currentActor(r).ID, r.PathValue("zone"))
	if err != nil {
		writeHostedError(w, err)
		return
	}
	response, err := h.hostedZoneResponse(r)
	if err != nil {
		writeHostedError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"step": step, "zone": response})
}
