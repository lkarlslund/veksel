package app

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/pgpkey"
	"github.com/lkarlslund/veksel/pkg/store"
)

// pgpKeyView describes one identity's published OpenPGP key. Without a key
// only Address is set.
type pgpKeyView struct {
	Address     string `json:"address"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Created     string `json:"created,omitempty"`
	Expires     string `json:"expires,omitempty"`
	Expired     bool   `json:"expired,omitempty"`
	Autocrypt   bool   `json:"autocrypt"`
	// AutocryptTooLarge marks a key that exceeds the Autocrypt header limit
	// and is therefore never advertised in mail.
	AutocryptTooLarge bool   `json:"autocrypt_too_large,omitempty"`
	UpdatedAt         string `json:"updated_at,omitempty"`
}

func projectPGPKey(address string, key *model.PGPKey, now time.Time) pgpKeyView {
	view := pgpKeyView{Address: address}
	if key == nil {
		return view
	}
	view.Fingerprint, view.Autocrypt, view.Expired = key.Fingerprint, key.Autocrypt, key.Expired(now)
	view.AutocryptTooLarge = len(key.Binary) > pgpkey.MaxAutocryptKeyBytes
	view.Created, view.UpdatedAt = key.Created.UTC().Format(time.RFC3339), key.UpdatedAt.UTC().Format(time.RFC3339)
	if !key.Expires.IsZero() {
		view.Expires = key.Expires.UTC().Format(time.RFC3339)
	}
	return view
}

func (h *Handler) registerPGPKeyRoutes(api apiRouter) {
	api.handle("GET /api/v1/user/pgp-keys", h.apiUserPGPKeys)
	api.handle("PUT /api/v1/user/pgp-keys/{address}", h.apiUserSetPGPKey)
	api.handle("PATCH /api/v1/user/pgp-keys/{address}", h.apiUserUpdatePGPKey)
	api.handle("DELETE /api/v1/user/pgp-keys/{address}", h.apiUserDeletePGPKey)
}

// ownIdentity reports whether address is one of the caller's enabled
// identities; only those can publish a key.
func (h *Handler) ownIdentity(r *http.Request, address string) (bool, error) {
	identities, err := h.users.ListEmailAddressesForUser(r.Context(), currentActor(r).ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	return slices.ContainsFunc(identities, func(identity model.EmailAddress) bool {
		return identity.Enabled && strings.EqualFold(identity.ID, address)
	}), nil
}

func (h *Handler) apiUserPGPKeys(w http.ResponseWriter, r *http.Request) {
	identities, err := h.users.ListEmailAddressesForUser(r.Context(), currentActor(r).ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		apiError(w, err)
		return
	}
	now := time.Now()
	keys := []pgpKeyView{}
	for _, identity := range identities {
		if !identity.Enabled {
			continue
		}
		key, err := h.ts.PGPKeyStore().Get(r.Context(), identity.ID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			keys = append(keys, projectPGPKey(identity.ID, nil, now))
		case err != nil:
			apiError(w, err)
			return
		default:
			keys = append(keys, projectPGPKey(identity.ID, &key, now))
		}
	}
	cfg := h.effectiveConfig()
	jsonResponse(w, http.StatusOK, map[string]any{
		"keys": keys, "wkd_enabled": cfg != nil && cfg.WkdEnabled, "autocrypt_enabled": cfg != nil && cfg.AutocryptEnabled,
	})
}

func (h *Handler) apiUserSetPGPKey(w http.ResponseWriter, r *http.Request) {
	var request struct {
		// Key is an ASCII-armored public key, or the base64 of a binary one.
		Key       string `json:"key"`
		Autocrypt *bool  `json:"autocrypt"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	own, err := h.ownIdentity(r, address)
	if err != nil {
		apiError(w, err)
		return
	}
	if !own {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	parsed, err := pgpkey.Parse([]byte(request.Key), address, time.Now())
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	key := model.PGPKey{Address: address, UserID: currentActor(r).ID, Fingerprint: parsed.Fingerprint, Created: parsed.Created,
		Expires: parsed.Expires, Binary: parsed.Binary}
	if existing, err := h.ts.PGPKeyStore().Get(r.Context(), address); err == nil {
		key.Autocrypt = existing.Autocrypt
	}
	if request.Autocrypt != nil {
		key.Autocrypt = *request.Autocrypt
	}
	if err := h.ts.PGPKeyStore().Set(r.Context(), key); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(key.UserID, "pgp_key.set", address, map[string]string{"fingerprint": key.Fingerprint})
	stored, err := h.ts.PGPKeyStore().Get(r.Context(), address)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, projectPGPKey(address, &stored, time.Now()))
}

func (h *Handler) apiUserUpdatePGPKey(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Autocrypt *bool `json:"autocrypt"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	key, err := h.ts.PGPKeyStore().Get(r.Context(), address)
	if err != nil || key.UserID != currentActor(r).ID {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if request.Autocrypt != nil {
		key.Autocrypt = *request.Autocrypt
	}
	if err := h.ts.PGPKeyStore().Set(r.Context(), key); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(key.UserID, "pgp_key.update", address, nil)
	jsonResponse(w, http.StatusOK, projectPGPKey(address, &key, time.Now()))
}

func (h *Handler) apiUserDeletePGPKey(w http.ResponseWriter, r *http.Request) {
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	key, err := h.ts.PGPKeyStore().Get(r.Context(), address)
	if err != nil || key.UserID != currentActor(r).ID {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if err := h.ts.PGPKeyStore().Delete(r.Context(), address); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(key.UserID, "pgp_key.delete", address, nil)
	w.WriteHeader(http.StatusNoContent)
}
