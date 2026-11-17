package app

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/autodiscover"
	"github.com/lkarlslund/veksel/pkg/cmssign"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// mobileConfigSource supplies the advertised server settings and, when an
// HTTPS certificate is assigned, the key used to sign profiles.
type mobileConfigSource struct {
	settings func() autodiscover.Config
	signer   func(context.Context) ([]*x509.Certificate, crypto.Signer, error)
}

// ConfigureMobileConfig enables Apple configuration profile downloads. The
// signer may return a nil key, which serves unsigned profiles.
func (h *Handler) ConfigureMobileConfig(settings func() autodiscover.Config, signer func(context.Context) ([]*x509.Certificate, crypto.Signer, error)) {
	h.mobileConfig = &mobileConfigSource{settings: settings, signer: signer}
}

var unsafeFilename = regexp.MustCompile(`[^A-Za-z0-9._@-]+`)

// apiUserMobileConfig downloads an Apple configuration profile for one of
// the caller's own identities. app_password=1 first issues a fresh
// application password scoped to IMAP, SMTP and DAV and embeds it; that
// changes state, so it needs the session CSRF token like any other change.
func (h *Handler) apiUserMobileConfig(w http.ResponseWriter, r *http.Request) {
	if h.mobileConfig == nil {
		jsonError(w, http.StatusServiceUnavailable, "configuration profiles are unavailable")
		return
	}
	actor := currentActor(r)
	user, err := h.users.Get(r.Context(), actor.ID)
	if err != nil {
		apiError(w, err)
		return
	}
	identities, err := h.users.ListEmailAddressesForUser(r.Context(), actor.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		apiError(w, err)
		return
	}
	var identity *model.EmailAddress
	want := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("identity")))
	for i := range identities {
		if !identities[i].Enabled || (want == "" && !identities[i].Primary) || (want != "" && strings.ToLower(identities[i].ID) != want) {
			continue
		}
		identity = &identities[i]
		break
	}
	if identity == nil {
		jsonError(w, http.StatusBadRequest, "identity is not one of your addresses")
		return
	}
	embed := r.URL.Query().Get("app_password") == "1"
	if embed {
		session, ok := sessionFromContext(r.Context())
		if !ok || !h.sessions.ValidCSRF(session, r.Header.Get("X-CSRF-Token")) {
			jsonError(w, http.StatusForbidden, "invalid CSRF token")
			return
		}
	}
	settings := h.mobileConfig.settings()
	params := autodiscover.MobileConfigParams{AccountID: user.ID, Email: identity.ID, DisplayName: user.DisplayName, Username: identity.ID}
	profile, identifier, err := settings.MobileConfig(params)
	if err != nil {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if embed {
		name := "Apple devices " + time.Now().UTC().Format("2006-01-02 15:04")
		protocols := []string{model.AppProtocolIMAP, model.AppProtocolSMTP, model.AppProtocolDAV}
		password, secret, err := h.appPasswords.Create(r.Context(), actor.ID, name, protocols)
		if err != nil {
			apiError(w, err)
			return
		}
		h.audit.Log(actor.ID, "app_password.create", password.ID, map[string]string{"name": password.Name, "protocols": strings.Join(password.Protocols, ","), "via": "mobileconfig"})
		params.Password = secret
		if profile, identifier, err = settings.MobileConfig(params); err != nil {
			apiError(w, err)
			return
		}
	}
	signed := false
	if chain, key, err := h.mobileConfig.signer(r.Context()); err == nil && key != nil && len(chain) > 0 {
		if envelope, err := cmssign.Sign(profile, chain, key); err == nil {
			profile, signed = envelope, true
		}
	}
	h.audit.Log(actor.ID, "mobileconfig.download", identifier, map[string]string{"identity": identity.ID, "app_password": boolString(embed), "signed": boolString(signed)})
	filename := unsafeFilename.ReplaceAllString(identity.ID, "_") + ".mobileconfig"
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Profile-Signed", boolString(signed))
	_, _ = w.Write(profile)
}
