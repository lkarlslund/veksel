package app

import (
	"net/http"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

type certificateView struct {
	Name      string    `json:"name"`
	Subject   string    `json:"subject"`
	Signer    string    `json:"signer"`
	SANs      []string  `json:"sans"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Uploaded  time.Time `json:"uploaded"`
	Expired   bool      `json:"expired"`
}

type certificateRequest struct {
	Name    string `json:"name"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

func certificateSummary(cert model.TLSCert) certificateView {
	return certificateView{Name: cert.Domain, Subject: cert.Subject, Signer: cert.Signer, SANs: cert.SANs,
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, Uploaded: cert.Uploaded, Expired: time.Now().UTC().After(cert.NotAfter)}
}

func (h *Handler) apiAdminCertificates(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	certs, err := h.ts.TLSCertStore().List(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	result := make([]certificateView, 0, len(certs))
	for _, cert := range certs {
		result = append(result, certificateSummary(cert))
	}
	jsonResponse(w, http.StatusOK, result)
}

func (h *Handler) apiAdminCreateCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var request certificateRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	cert, err := h.ts.TLSCertStore().Create(r.Context(), request.Name, request.CertPEM, request.KeyPEM)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "certificate.create", cert.Domain, map[string]string{"subject": cert.Subject})
	jsonResponse(w, http.StatusCreated, certificateSummary(*cert))
}

func (h *Handler) apiAdminReplaceCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var request certificateRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	cert, err := h.ts.TLSCertStore().Replace(r.Context(), r.PathValue("name"), request.CertPEM, request.KeyPEM)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "certificate.replace", cert.Domain, map[string]string{"subject": cert.Subject})
	jsonResponse(w, http.StatusOK, certificateSummary(*cert))
}

func (h *Handler) apiAdminDeleteCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	assignment := "stored:" + name
	cfg := h.cfg
	if h.configService != nil {
		cfg = h.configService.Current().Config
	}
	if cfg != nil {
		assigned := cfg.SmtpCertificate == assignment || cfg.ImapCertificate == assignment || cfg.Pop3Certificate == assignment
		for _, listener := range cfg.HTTPListeners {
			assigned = assigned || listener.Certificate == assignment
		}
		if assigned {
			jsonError(w, http.StatusConflict, "certificate is assigned to a listener or protocol; replace it or change the assignment first")
			return
		}
	}
	if err := h.ts.TLSCertStore().Delete(r.Context(), name); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "certificate.delete", name, nil)
	w.WriteHeader(http.StatusNoContent)
}
