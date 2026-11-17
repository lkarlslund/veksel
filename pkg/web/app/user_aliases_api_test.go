package app

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type userAliasList struct {
	Aliases    []userAliasView `json:"aliases"`
	Domains    []string        `json:"domains"`
	Enabled    bool            `json:"enabled"`
	MaxPerUser int             `json:"max_per_user"`
	Expiries   []string        `json:"expiries"`
}

// patchConfig changes managed settings as the system owner.
func (f domainAdminFixture) patchConfig(t *testing.T, settings string) {
	t.Helper()
	history := decodeInto[struct {
		Current string `json:"current_revision"`
	}](t, f.expect(t, f.owner, f.ownerTok, http.MethodGet, "/api/v1/admin/config/history?limit=1", "", http.StatusOK))
	f.expect(t, f.owner, f.ownerTok, http.MethodPatch, "/api/v1/admin/config",
		`{"revision":"`+history.Current+`","reason":"test","settings":`+settings+`}`, http.StatusOK)
}

func TestUserAliasesSelfServiceLifecycleAndLimits(t *testing.T) {
	f := newDomainAdminFixture(t)
	alice, aliceTok := loginAs(t, f.server, "alice")
	bob, bobTok := loginAs(t, f.server, "bob")

	list := decodeInto[userAliasList](t, f.expect(t, alice, aliceTok, http.MethodGet, "/api/v1/user/aliases", "", http.StatusOK))
	if !list.Enabled || list.MaxPerUser != 50 || len(list.Domains) != 1 || list.Domains[0] != "a.test" || len(list.Aliases) != 0 {
		t.Fatalf("initial list = %+v", list)
	}

	created := decodeInto[userAliasView](t, f.expect(t, alice, aliceTok, http.MethodPost, "/api/v1/user/aliases",
		`{"prefix":"shop","label":"Webshop","expiry":"week","on_inactive":"discard"}`, http.StatusCreated))
	if !strings.HasPrefix(created.Address, "shop-") || !strings.HasSuffix(created.Address, "@a.test") || created.ExpiresAt == "" || created.OnInactive != "discard" || created.Label != "Webshop" {
		t.Fatalf("created = %+v", created)
	}
	route, err := f.ts.ResolveRecipient(t.Context(), created.Address, "+")
	if err != nil || route.Identity.UserID != "alice" {
		t.Fatalf("route = %+v, %v", route, err)
	}

	// The alias appears as a reply identity only for its owner.
	settings := decodeInto[struct {
		Identities []userIdentityResponse `json:"identities"`
	}](t, f.expect(t, alice, aliceTok, http.MethodGet, "/api/v1/user/settings", "", http.StatusOK))
	found := false
	for _, identity := range settings.Identities {
		found = found || identity.Address == created.Address && identity.Alias
	}
	if !found {
		t.Fatalf("alias missing from identities: %+v", settings.Identities)
	}
	other := decodeInto[struct {
		Identities []userIdentityResponse `json:"identities"`
	}](t, f.expect(t, bob, bobTok, http.MethodGet, "/api/v1/user/settings", "", http.StatusOK))
	for _, identity := range other.Identities {
		if identity.Address == created.Address {
			t.Fatal("another account sees the alias as an identity")
		}
	}

	// Another account cannot read, change, or delete it, and is refused a domain it has no identity in.
	path := "/api/v1/user/aliases/" + url.PathEscape(created.Address)
	f.expect(t, bob, bobTok, http.MethodPatch, path, `{"enabled":false}`, http.StatusNotFound)
	f.expect(t, bob, bobTok, http.MethodDelete, path, "", http.StatusNotFound)
	f.expect(t, bob, bobTok, http.MethodPost, "/api/v1/user/aliases", `{"domain":"a.test"}`, http.StatusBadRequest)
	f.expect(t, alice, aliceTok, http.MethodPost, "/api/v1/user/aliases", `{"expiry":"decade"}`, http.StatusBadRequest)
	f.expect(t, alice, aliceTok, http.MethodPost, "/api/v1/user/aliases", `{"prefix":"bad prefix"}`, http.StatusBadRequest)

	updated := decodeInto[userAliasView](t, f.expect(t, alice, aliceTok, http.MethodPatch, path, `{"enabled":false,"expiry":"never","label":"Off"}`, http.StatusOK))
	if updated.Enabled || updated.ExpiresAt != "" || updated.Label != "Off" {
		t.Fatalf("updated = %+v", updated)
	}
	if route, err := f.ts.ResolveRecipient(t.Context(), created.Address, "+"); err != nil || !route.Discard {
		t.Fatalf("disabled discard route = %+v, %v", route, err)
	}

	// An administrator disables an alias and the owner cannot enable it again.
	f.expect(t, f.dana, f.danaTok, http.MethodPut, "/api/v1/admin/users/alice/aliases/"+url.PathEscape(created.Address)+"/lock", `{"disabled":true}`, http.StatusOK)
	f.expect(t, alice, aliceTok, http.MethodPatch, path, `{"enabled":true}`, http.StatusConflict)
	listed := decodeInto[[]userAliasView](t, f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/users/alice/aliases", "", http.StatusOK))
	if len(listed) != 1 || !listed[0].AdminDisabled || listed[0].UserID != "alice" {
		t.Fatalf("admin view = %+v", listed)
	}
	// A domain administrator cannot reach accounts of other domains, and plain users cannot administer.
	f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/users/bob/aliases", "", http.StatusForbidden)
	f.expect(t, alice, aliceTok, http.MethodGet, "/api/v1/admin/users/alice/aliases", "", http.StatusForbidden)
	f.expect(t, f.dana, f.danaTok, http.MethodPut, "/api/v1/admin/users/alice/aliases/"+url.PathEscape(created.Address)+"/lock", `{"disabled":false}`, http.StatusOK)
	f.expect(t, alice, aliceTok, http.MethodPatch, path, `{"enabled":true}`, http.StatusOK)

	// Deleting leaves a tombstone that still rejects and reserves the address.
	f.expect(t, alice, aliceTok, http.MethodDelete, path, "", http.StatusNoContent)
	if taken, _ := f.ts.UserAliasStore().AddressTaken(t.Context(), created.Address); !taken {
		t.Fatal("deleted alias address was released immediately")
	}
	if route, err := f.ts.ResolveRecipient(t.Context(), created.Address, "+"); err != nil || !route.Disabled {
		t.Fatalf("tombstone route = %+v, %v", route, err)
	}

	// The domain's alias limit counts temporary aliases.
	f.expect(t, f.owner, f.ownerTok, http.MethodPut, "/api/v1/admin/domains/a.test/limits", `{"max_aliases":1}`, http.StatusOK)
	f.expect(t, alice, aliceTok, http.MethodPost, "/api/v1/user/aliases", `{}`, http.StatusCreated)
	body := string(f.expect(t, alice, aliceTok, http.MethodPost, "/api/v1/user/aliases", `{}`, http.StatusConflict))
	if !strings.Contains(body, "at most 1 aliases") {
		t.Fatalf("domain limit error = %s", body)
	}
	f.expect(t, f.owner, f.ownerTok, http.MethodPut, "/api/v1/admin/domains/a.test/limits", `{}`, http.StatusOK)
}

func TestUserAliasSettingsApplyLive(t *testing.T) {
	f := newDomainAdminFixture(t)
	alice, aliceTok := loginAs(t, f.server, "alice")

	f.patchConfig(t, `{"user_aliases_max_per_user":1}`)
	f.expect(t, alice, aliceTok, http.MethodPost, "/api/v1/user/aliases", `{}`, http.StatusCreated)
	body := string(f.expect(t, alice, aliceTok, http.MethodPost, "/api/v1/user/aliases", `{}`, http.StatusConflict))
	if !strings.Contains(body, "at most 1 temporary aliases") {
		t.Fatalf("per-user limit error = %s", body)
	}

	f.patchConfig(t, `{"user_aliases_max_per_user":5,"user_aliases_domains":["b.test"]}`)
	list := decodeInto[userAliasList](t, f.expect(t, alice, aliceTok, http.MethodGet, "/api/v1/user/aliases", "", http.StatusOK))
	if len(list.Domains) != 0 || list.MaxPerUser != 5 {
		t.Fatalf("list after domain restriction = %+v", list)
	}
	f.expect(t, alice, aliceTok, http.MethodPost, "/api/v1/user/aliases", `{"domain":"a.test"}`, http.StatusBadRequest)

	f.patchConfig(t, `{"user_aliases_domains":[],"user_aliases_enabled":false}`)
	f.expect(t, alice, aliceTok, http.MethodPost, "/api/v1/user/aliases", `{}`, http.StatusForbidden)
	// Existing aliases keep delivering while creation is switched off.
	aliases, err := f.ts.UserAliasStore().ListForUser(t.Context(), "alice")
	if err != nil || len(aliases) != 1 {
		t.Fatalf("aliases = %+v, %v", aliases, err)
	}
	if route, err := f.ts.ResolveRecipient(t.Context(), aliases[0].Address, "+"); err != nil || route.Identity.UserID != "alice" {
		t.Fatalf("route = %+v, %v", route, err)
	}
}
