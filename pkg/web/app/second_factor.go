package app

// Two-factor web sign-in. A correct password for an account with second
// factors creates a pending sign-in (sessionStore.CreatePending) carried by
// its own cookie. It grants nothing except the second-factor endpoints in
// this file and is replaced by a fresh full session once a TOTP code, a
// recovery code, or a WebAuthn assertion verifies. Enrolment required by the
// web_two_factor_required policy uses the same pending state. Protocol
// logins, application passwords, API keys and impersonation never consult
// second factors.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/boombuler/barcode/qr"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/httpservice"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	pendingSignInCookie = "veksel_signin"
	totpSecretPurpose   = "totp"
	// pendingTOTPLifetime is how long an unconfirmed authenticator secret is
	// reused, so reloading the setup page does not invalidate a scanned code.
	pendingTOTPLifetime    = 10 * time.Minute
	maxWebAuthnCredentials = 20
	maxFactorNameLength    = 100
	twoFactorIssuer        = "Veksel"
)

var (
	errSecondFactorInvalid  = errors.New("invalid verification code")
	errSecondFactorRequired = errors.New("two-factor sign-in is required for this account; add another factor before removing this one")
	errTOTPSetupExpired     = errors.New("authenticator setup expired; start again")
	errWebAuthnExpired      = errors.New("security key request expired; try again")
	errNoSecondFactor       = errors.New("enable an authenticator app or security key first")
)

// setTwoFactorPolicy installs the live web_two_factor_required value.
func (h *Handler) setTwoFactorPolicy(policy string) { h.twoFactorPolicy.Store(&policy) }

// twoFactorRequired reports whether policy obliges userID to use a second
// factor at web sign-in.
func (h *Handler) twoFactorRequired(ctx context.Context, userID string) bool {
	policy := h.twoFactorPolicy.Load()
	if policy == nil {
		return false
	}
	switch *policy {
	case "all":
		return true
	case "administrators":
		return h.isAdmin(ctx, userID)
	}
	return false
}

// beginSignIn completes a verified password. It starts a full session, or a
// pending sign-in when the account has factors or policy requires enrolment,
// and returns the pending state ("" for a full session).
func (h *Handler) beginSignIn(w http.ResponseWriter, r *http.Request, userID, csrf string) (string, error) {
	factors, err := h.secondFactors.Get(r.Context(), userID)
	if err != nil {
		return "", err
	}
	state := ""
	switch {
	case factors.Enabled():
		state = secondFactorVerify
	case h.twoFactorRequired(r.Context(), userID):
		state = secondFactorEnrol
	default:
		return "", h.startSession(w, r, userID, csrf)
	}
	client := httpservice.RequestClient(r)
	token, err := h.sessions.CreatePending(r.Context(), userID, csrf, client.IP, r.UserAgent(), state)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{Name: pendingSignInCookie, Value: token, Path: "/", HttpOnly: true, Secure: client.HTTPS, SameSite: http.SameSiteStrictMode, MaxAge: int(pendingSignInLifetime.Seconds())})
	return state, nil
}

// pendingSignIn resolves the request's pending sign-in. It must belong to an
// enabled account and to the CSRF cookie it was created with.
func (h *Handler) pendingSignIn(r *http.Request) (model.Session, string, error) {
	cookie, err := r.Cookie(pendingSignInCookie)
	if err != nil {
		return model.Session{}, "", store.ErrNotFound
	}
	session, err := h.sessions.GetPending(r.Context(), cookie.Value)
	if err != nil {
		return model.Session{}, "", err
	}
	csrf, err := r.Cookie(csrfCookie)
	if err != nil || !h.sessions.ValidCSRF(session, csrf.Value) {
		return model.Session{}, "", store.ErrNotFound
	}
	if user, err := h.users.Get(r.Context(), session.ActorID); err != nil || !user.Enabled {
		_ = h.sessions.Delete(r.Context(), cookie.Value)
		return model.Session{}, "", store.ErrNotFound
	}
	return session, cookie.Value, nil
}

// completeSignIn replaces a pending sign-in with a new full session, so the
// pending token never becomes a session credential.
func (h *Handler) completeSignIn(w http.ResponseWriter, r *http.Request, token string, pending model.Session, method string) error {
	if err := h.sessions.Delete(r.Context(), token); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: pendingSignInCookie, Path: "/", HttpOnly: true, Expires: time.Unix(1, 0), MaxAge: -1})
	csrf, err := r.Cookie(csrfCookie)
	if err != nil {
		return err
	}
	if err := h.startSession(w, r, pending.ActorID, csrf.Value); err != nil {
		return err
	}
	h.audit.Log(pending.ActorID, "account.two_factor.sign_in", pending.ActorID, map[string]string{"method": method, "ip": httpservice.RequestClient(r).IP})
	return nil
}

// secondFactorFailed audits a failed attempt and reports whether the pending
// sign-in survives it.
func (h *Handler) secondFactorFailed(r *http.Request, token string, pending model.Session, method string) bool {
	h.audit.Log(pending.ActorID, "account.two_factor.failure", pending.ActorID, map[string]string{"method": method, "ip": httpservice.RequestClient(r).IP})
	usable, err := h.sessions.RecordSecondFactorFailure(r.Context(), token)
	return err == nil && usable
}

// throttledSecondFactor runs verify under the failed-login throttle shared
// with password sign-in. The per-account budget has its own key, so a correct
// password (which clears the password budget) cannot reset code guessing.
func (h *Handler) throttledSecondFactor(r *http.Request, userID string, verify func() error) (err error) {
	ip, account := httpservice.RequestClient(r).IP, ratelimit.SecondFactorAccount(userID)
	if err := h.loginThrottle.Begin(ip, account); err != nil {
		return err
	}
	defer func() { h.loginThrottle.End(ip, account, err == nil) }()
	return verify()
}

// verifySecondFactorCode checks a TOTP or recovery code.
func (h *Handler) verifySecondFactorCode(r *http.Request, userID, method, code string) error {
	return h.throttledSecondFactor(r, userID, func() error {
		switch method {
		case "totp":
			return h.useTOTP(r.Context(), userID, code)
		case "recovery":
			return h.useRecoveryCode(r.Context(), userID, code)
		}
		return errSecondFactorInvalid
	})
}

func (h *Handler) useTOTP(ctx context.Context, userID, code string) error {
	_, err := h.secondFactors.Update(ctx, userID, func(factors *model.SecondFactors) error {
		if factors.TOTP == nil {
			return errSecondFactorInvalid
		}
		secret, err := h.migrationJobs.OpenSecret(totpSecretPurpose, userID, factors.TOTP.SealedSecret)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		step, ok := auth.ValidateTOTP(secret, code, now, factors.TOTP.LastStep)
		if !ok {
			return errSecondFactorInvalid
		}
		factors.TOTP.LastStep, factors.TOTP.LastUsedAt = step, now
		return nil
	})
	return err
}

func (h *Handler) useRecoveryCode(ctx context.Context, userID, code string) error {
	remaining := 0
	_, err := h.secondFactors.Update(ctx, userID, func(factors *model.SecondFactors) error {
		if len(factors.RecoverySalt) == 0 || strings.TrimSpace(code) == "" {
			return errSecondFactorInvalid
		}
		hash := []byte(auth.HashRecoveryCode(factors.RecoverySalt, code))
		for i := range factors.RecoveryCodes {
			candidate := &factors.RecoveryCodes[i]
			if candidate.UsedAt.IsZero() && subtle.ConstantTimeCompare([]byte(candidate.Hash), hash) == 1 {
				candidate.UsedAt = time.Now().UTC()
				remaining = factors.RemainingRecoveryCodes()
				return nil
			}
		}
		return errSecondFactorInvalid
	})
	if err == nil {
		h.audit.Log(userID, "account.two_factor.recovery_code_used", userID, map[string]string{"remaining": fmt.Sprint(remaining)})
	}
	return err
}

// regenerateRecoveryCodes replaces every recovery code and returns the new
// plaintext codes, which are never stored.
func regenerateRecoveryCodes(factors *model.SecondFactors) ([]string, error) {
	codes, err := auth.NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	factors.RecoverySalt, factors.RecoveryCodes, factors.RecoveryGeneratedAt = salt, make([]model.RecoveryCode, len(codes)), time.Now().UTC()
	for i, code := range codes {
		factors.RecoveryCodes[i] = model.RecoveryCode{Hash: auth.HashRecoveryCode(salt, code)}
	}
	return codes, nil
}

// ensureRecoveryCodes issues codes with the first factor, or when none are
// left; otherwise it keeps the existing ones and returns nil.
func ensureRecoveryCodes(factors *model.SecondFactors) ([]string, error) {
	if factors.RemainingRecoveryCodes() > 0 {
		return nil, nil
	}
	return regenerateRecoveryCodes(factors)
}

type totpEnrolment struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	QRCode string `json:"qr_code"`
}

// beginTOTPEnrolment stores an unconfirmed authenticator secret, reusing a
// recent one, and returns what the authenticator application needs.
func (h *Handler) beginTOTPEnrolment(r *http.Request, userID string) (totpEnrolment, error) {
	if _, err := h.users.RequireInteractive(r.Context(), userID); err != nil {
		return totpEnrolment{}, err
	}
	var secret []byte
	_, err := h.secondFactors.Update(r.Context(), userID, func(factors *model.SecondFactors) error {
		now := time.Now().UTC()
		if pending := factors.PendingTOTP; pending != nil && now.Sub(pending.CreatedAt) < pendingTOTPLifetime {
			opened, err := h.migrationJobs.OpenSecret(totpSecretPurpose, userID, pending.SealedSecret)
			if err == nil {
				secret = opened
				return nil
			}
		}
		fresh, err := auth.NewTOTPSecret()
		if err != nil {
			return err
		}
		sealed, err := h.migrationJobs.SealSecret(totpSecretPurpose, userID, fresh)
		if err != nil {
			return err
		}
		secret, factors.PendingTOTP = fresh, &model.PendingTOTP{SealedSecret: sealed, CreatedAt: now}
		return nil
	})
	if err != nil {
		return totpEnrolment{}, err
	}
	uri := auth.TOTPURI(twoFactorIssuer, userID+"@"+requestHostname(r), secret)
	code, err := qrDataURI(uri)
	if err != nil {
		return totpEnrolment{}, err
	}
	return totpEnrolment{Secret: auth.TOTPSecretText(secret), URI: uri, QRCode: code}, nil
}

// confirmTOTPEnrolment activates the pending secret once code proves the
// authenticator holds it. It returns recovery codes when new ones were
// issued.
func (h *Handler) confirmTOTPEnrolment(ctx context.Context, userID, code string) ([]string, error) {
	var codes []string
	_, err := h.secondFactors.Update(ctx, userID, func(factors *model.SecondFactors) error {
		pending := factors.PendingTOTP
		now := time.Now().UTC()
		if pending == nil || now.Sub(pending.CreatedAt) >= pendingTOTPLifetime {
			return errTOTPSetupExpired
		}
		secret, err := h.migrationJobs.OpenSecret(totpSecretPurpose, userID, pending.SealedSecret)
		if err != nil {
			return err
		}
		step, ok := auth.ValidateTOTP(secret, code, now, 0)
		if !ok {
			return errSecondFactorInvalid
		}
		factors.TOTP = &model.TOTPFactor{SealedSecret: pending.SealedSecret, EnabledAt: now, LastStep: step, LastUsedAt: now}
		factors.PendingTOTP = nil
		codes, err = ensureRecoveryCodes(factors)
		return err
	})
	if err == nil {
		h.audit.Log(userID, "account.two_factor.totp_enrolled", userID, nil)
	}
	return codes, err
}

// removeSecondFactor applies remove, refusing to drop the last factor of an
// account that policy obliges to use one. Recovery codes go with the last
// factor.
func (h *Handler) removeSecondFactor(ctx context.Context, userID string, remove func(*model.SecondFactors) bool) error {
	required := h.twoFactorRequired(ctx, userID)
	_, err := h.secondFactors.Update(ctx, userID, func(factors *model.SecondFactors) error {
		if !remove(factors) {
			return store.ErrNotFound
		}
		if !factors.Enabled() {
			if required {
				return errSecondFactorRequired
			}
			factors.RecoverySalt, factors.RecoveryCodes, factors.RecoveryGeneratedAt = nil, nil, time.Time{}
		}
		return nil
	})
	return err
}

// qrDataURI renders content as an SVG QR code data URI.
func qrDataURI(content string) (string, error) {
	code, err := qr.Encode(content, qr.M, qr.Auto)
	if err != nil {
		return "", fmt.Errorf("encode QR code: %w", err)
	}
	const quiet = 4
	bounds := code.Bounds()
	size := bounds.Dx() + 2*quiet
	var path strings.Builder
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if r, _, _, _ := code.At(x, y).RGBA(); r == 0 {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x-bounds.Min.X+quiet, y-bounds.Min.Y+quiet)
			}
		}
	}
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="100%%" height="100%%" fill="#fff"/><path fill="#000" d="%s"/></svg>`, size, size, path.String())
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg)), nil
}

// requestHostname is the host name the client addressed, without port.
func requestHostname(r *http.Request) string {
	host := httpservice.RequestClient(r).Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

// relyingParty describes this server to WebAuthn authenticators. Like the
// session cookie and the events origin check, it follows the host and scheme
// the client addressed (honouring trusted proxies), so a credential is bound
// to the host name it was registered on.
func (h *Handler) relyingParty(r *http.Request) (*webauthn.WebAuthn, error) {
	client := httpservice.RequestClient(r)
	return webauthn.New(&webauthn.Config{
		RPID: requestHostname(r), RPDisplayName: twoFactorIssuer,
		RPOrigins: []string{client.Scheme() + "://" + client.Host},
	})
}

// webAuthnAccount adapts an account's factors to webauthn.User.
type webAuthnAccount struct {
	handle      []byte
	name        string
	credentials []webauthn.Credential
}

func (a webAuthnAccount) WebAuthnID() []byte                         { return a.handle }
func (a webAuthnAccount) WebAuthnName() string                       { return a.name }
func (a webAuthnAccount) WebAuthnDisplayName() string                { return a.name }
func (a webAuthnAccount) WebAuthnCredentials() []webauthn.Credential { return a.credentials }

func newWebAuthnAccount(userID string, factors model.SecondFactors) (webAuthnAccount, error) {
	account := webAuthnAccount{handle: factors.WebAuthnUserHandle, name: userID}
	for _, factor := range factors.WebAuthn {
		var credential webauthn.Credential
		if err := json.Unmarshal(factor.Credential, &credential); err != nil {
			return webAuthnAccount{}, fmt.Errorf("decode security key %s: %w", factor.ID, err)
		}
		account.credentials = append(account.credentials, credential)
	}
	return account, nil
}

// webAuthnCeremonies holds begun WebAuthn ceremonies in memory, keyed by the
// (pending) session that began them. Each is taken at most once and expires
// after webAuthnCeremonyLifetime; a restart simply makes the browser start
// again.
type webAuthnCeremonies struct {
	mu      sync.Mutex
	pending map[string]webAuthnCeremony
}

type webAuthnCeremony struct {
	data    webauthn.SessionData
	expires time.Time
}

const webAuthnCeremonyLifetime = 5 * time.Minute

func (c *webAuthnCeremonies) put(key string, data webauthn.SessionData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for candidate, ceremony := range c.pending {
		if !ceremony.expires.After(now) {
			delete(c.pending, candidate)
		}
	}
	if c.pending == nil {
		c.pending = make(map[string]webAuthnCeremony)
	}
	c.pending[key] = webAuthnCeremony{data: data, expires: now.Add(webAuthnCeremonyLifetime)}
}

func (c *webAuthnCeremonies) take(key string) (webauthn.SessionData, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ceremony, ok := c.pending[key]
	delete(c.pending, key)
	return ceremony.data, ok && ceremony.expires.After(time.Now())
}

// beginWebAuthnRegistration starts adding a security key to userID.
func (h *Handler) beginWebAuthnRegistration(r *http.Request, sessionID, userID string) (*protocol.CredentialCreation, error) {
	if _, err := h.users.RequireInteractive(r.Context(), userID); err != nil {
		return nil, err
	}
	factors, err := h.secondFactors.Get(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	if len(factors.WebAuthn) >= maxWebAuthnCredentials {
		return nil, fmt.Errorf("%w: at most %d security keys can be registered", errBadTwoFactorRequest, maxWebAuthnCredentials)
	}
	if len(factors.WebAuthnUserHandle) == 0 {
		if factors, err = h.secondFactors.Update(r.Context(), userID, func(factors *model.SecondFactors) error {
			if len(factors.WebAuthnUserHandle) == 0 {
				factors.WebAuthnUserHandle = make([]byte, 32)
				_, err := rand.Read(factors.WebAuthnUserHandle)
				return err
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	account, err := newWebAuthnAccount(userID, factors)
	if err != nil {
		return nil, err
	}
	rp, err := h.relyingParty(r)
	if err != nil {
		return nil, err
	}
	creation, data, err := rp.BeginRegistration(account,
		webauthn.WithExclusions(webauthn.Credentials(account.credentials).CredentialDescriptors()),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementDiscouraged))
	if err != nil {
		return nil, err
	}
	h.webAuthn.put(sessionID+":register", *data)
	return creation, nil
}

// finishWebAuthnRegistration verifies the authenticator's attestation and
// stores the credential. It returns recovery codes when new ones were issued.
func (h *Handler) finishWebAuthnRegistration(r *http.Request, sessionID, userID, name string, response json.RawMessage) ([]string, error) {
	data, ok := h.webAuthn.take(sessionID + ":register")
	if !ok {
		return nil, errWebAuthnExpired
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errBadTwoFactorRequest, err)
	}
	factors, err := h.secondFactors.Get(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	account, err := newWebAuthnAccount(userID, factors)
	if err != nil {
		return nil, err
	}
	rp, err := h.relyingParty(r)
	if err != nil {
		return nil, err
	}
	credential, err := rp.CreateCredential(account, data, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: security key registration failed", errBadTwoFactorRequest)
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}
	id := base64.RawURLEncoding.EncodeToString(credential.ID)
	name = factorName(name, "Security key")
	var codes []string
	_, err = h.secondFactors.Update(r.Context(), userID, func(factors *model.SecondFactors) error {
		for _, existing := range factors.WebAuthn {
			if existing.ID == id {
				return fmt.Errorf("%w: this security key is already registered", errBadTwoFactorRequest)
			}
		}
		if len(factors.WebAuthn) >= maxWebAuthnCredentials {
			return fmt.Errorf("%w: at most %d security keys can be registered", errBadTwoFactorRequest, maxWebAuthnCredentials)
		}
		factors.WebAuthn = append(factors.WebAuthn, model.WebAuthnFactor{ID: id, Name: name, Credential: raw, CreatedAt: time.Now().UTC()})
		codes, err = ensureRecoveryCodes(factors)
		return err
	})
	if err == nil {
		h.audit.Log(userID, "account.two_factor.webauthn_enrolled", userID, map[string]string{"credential": id, "name": name})
	}
	return codes, err
}

// beginWebAuthnLogin starts a security key assertion for a pending sign-in.
func (h *Handler) beginWebAuthnLogin(r *http.Request, sessionID, userID string) (*protocol.CredentialAssertion, error) {
	factors, err := h.secondFactors.Get(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	if len(factors.WebAuthn) == 0 {
		return nil, store.ErrNotFound
	}
	account, err := newWebAuthnAccount(userID, factors)
	if err != nil {
		return nil, err
	}
	rp, err := h.relyingParty(r)
	if err != nil {
		return nil, err
	}
	assertion, data, err := rp.BeginLogin(account)
	if err != nil {
		return nil, err
	}
	h.webAuthn.put(sessionID+":login", *data)
	return assertion, nil
}

// finishWebAuthnLogin verifies an assertion and records the authenticator's
// new signature counter. A counter that did not advance suggests a cloned
// authenticator and is refused.
func (h *Handler) finishWebAuthnLogin(r *http.Request, sessionID, userID string, response json.RawMessage) error {
	data, ok := h.webAuthn.take(sessionID + ":login")
	if !ok {
		return errWebAuthnExpired
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return errSecondFactorInvalid
	}
	factors, err := h.secondFactors.Get(r.Context(), userID)
	if err != nil {
		return err
	}
	account, err := newWebAuthnAccount(userID, factors)
	if err != nil {
		return err
	}
	rp, err := h.relyingParty(r)
	if err != nil {
		return err
	}
	credential, err := rp.ValidateLogin(account, data, parsed)
	if err != nil || credential.Authenticator.CloneWarning {
		return errSecondFactorInvalid
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	id := base64.RawURLEncoding.EncodeToString(credential.ID)
	_, err = h.secondFactors.Update(r.Context(), userID, func(factors *model.SecondFactors) error {
		for i := range factors.WebAuthn {
			if factors.WebAuthn[i].ID == id {
				factors.WebAuthn[i].Credential, factors.WebAuthn[i].LastUsedAt = raw, time.Now().UTC()
				return nil
			}
		}
		return errSecondFactorInvalid
	})
	return err
}

func factorName(name, fallback string) string {
	name = boundedString(name, maxFactorNameLength)
	if name == "" {
		return fallback
	}
	return name
}

// errBadTwoFactorRequest marks client mistakes reported with their message.
var errBadTwoFactorRequest = errors.New("invalid request")

// twoFactorAPIError maps second-factor errors onto JSON responses.
func twoFactorAPIError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ratelimit.ErrAuthThrottled):
		ratelimit.WriteRetryAfter(w, err)
		jsonError(w, http.StatusTooManyRequests, "too many failed sign-in attempts; try again later")
	case errors.Is(err, errSecondFactorInvalid), errors.Is(err, errTOTPSetupExpired), errors.Is(err, errWebAuthnExpired):
		jsonError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, errBadTwoFactorRequest):
		jsonError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), errBadTwoFactorRequest.Error()+": "))
	case errors.Is(err, errSecondFactorRequired), errors.Is(err, errNoSecondFactor), errors.Is(err, model.ErrResourceAccount):
		jsonError(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrNotFound):
		jsonError(w, http.StatusNotFound, "not found")
	default:
		apiError(w, err)
	}
}

// Pending sign-in endpoints.

func (h *Handler) registerTwoFactorRoutes(mux *http.ServeMux, api apiRouter) {
	mux.HandleFunc("GET /app/login/second-factor", h.handleSecondFactor)
	mux.HandleFunc("POST /app/login/second-factor", h.handleSecondFactorPost)
	api.public("POST /api/v1/session/second-factor", h.apiSecondFactorVerify)
	api.public("POST /api/v1/session/second-factor/webauthn/options", h.apiSecondFactorWebAuthnOptions)
	api.public("POST /api/v1/session/second-factor/webauthn", h.apiSecondFactorWebAuthn)

	api.browserOnly("GET /api/v1/user/two-factor", h.apiUserTwoFactor)
	api.browserOnly("POST /api/v1/user/two-factor/totp", h.apiBeginUserTOTP)
	api.browserOnly("POST /api/v1/user/two-factor/totp/confirm", h.apiConfirmUserTOTP)
	api.browserOnly("DELETE /api/v1/user/two-factor/totp", h.apiDeleteUserTOTP)
	api.browserOnly("POST /api/v1/user/two-factor/recovery-codes", h.apiRegenerateRecoveryCodes)
	api.browserOnly("POST /api/v1/user/two-factor/webauthn/options", h.apiUserWebAuthnOptions)
	api.browserOnly("POST /api/v1/user/two-factor/webauthn", h.apiRegisterUserWebAuthn)
	api.browserOnly("PATCH /api/v1/user/two-factor/webauthn/{id}", h.apiRenameUserWebAuthn)
	api.browserOnly("DELETE /api/v1/user/two-factor/webauthn/{id}", h.apiDeleteUserWebAuthn)
	api.handle("DELETE /api/v1/admin/users/{id}/two-factor", h.apiAdminResetTwoFactor)
}

const signInExpiredRedirect = "/app/login?error=Sign-in+expired.+Enter+your+password+again."

func (h *Handler) handleSecondFactor(w http.ResponseWriter, r *http.Request) {
	pending, _, err := h.pendingSignIn(r)
	if err != nil {
		http.Redirect(w, r, signInExpiredRedirect, http.StatusFound)
		return
	}
	h.renderSecondFactor(w, r, pending, r.URL.Query().Get("error"), http.StatusOK)
}

func (h *Handler) renderSecondFactor(w http.ResponseWriter, r *http.Request, pending model.Session, message string, status int) {
	data := map[string]any{"CSRF": h.ensureCSRF(w, r), "Step": pending.SecondFactor, "Error": message, "Method": r.URL.Query().Get("method")}
	if pending.SecondFactor == secondFactorEnrol {
		enrolment, err := h.beginTOTPEnrolment(r, pending.ActorID)
		if err != nil {
			http.Error(w, "two-factor enrolment unavailable", http.StatusInternalServerError)
			return
		}
		data["TOTPSecret"], data["QRCode"] = enrolment.Secret, template.URL(enrolment.QRCode)
	} else {
		factors, err := h.secondFactors.Get(r.Context(), pending.ActorID)
		if err != nil {
			http.Error(w, "two-factor state unavailable", http.StatusInternalServerError)
			return
		}
		data["TOTP"], data["WebAuthn"] = factors.TOTP != nil, len(factors.WebAuthn) > 0
	}
	h.render(w, "login.gohtml", data, status)
}

func (h *Handler) handleSecondFactorPost(w http.ResponseWriter, r *http.Request) {
	if !h.validPublicCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	pending, token, err := h.pendingSignIn(r)
	if err != nil {
		http.Redirect(w, r, signInExpiredRedirect, http.StatusFound)
		return
	}
	method, code := r.FormValue("method"), r.FormValue("code")
	if pending.SecondFactor == secondFactorEnrol {
		codes, err := h.confirmTOTPEnrolment(r.Context(), pending.ActorID, code)
		if err != nil {
			if !errors.Is(err, errSecondFactorInvalid) && !errors.Is(err, errTOTPSetupExpired) {
				http.Error(w, "two-factor enrolment failed", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/app/login/second-factor?error=That+code+did+not+match.+Check+the+authenticator+app+and+try+again.", http.StatusFound)
			return
		}
		if err := h.completeSignIn(w, r, token, pending, "totp_enrolment"); err != nil {
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}
		h.render(w, "login.gohtml", map[string]any{"CSRF": h.csrfValue(r), "Step": "recovery", "RecoveryCodes": codes}, http.StatusOK)
		return
	}
	err = h.verifySecondFactorCode(r, pending.ActorID, method, code)
	switch {
	case errors.Is(err, ratelimit.ErrAuthThrottled):
		ratelimit.WriteRetryAfter(w, err)
		h.renderSecondFactor(w, r, pending, "Too many failed attempts. Try again later.", http.StatusTooManyRequests)
	case errors.Is(err, errSecondFactorInvalid):
		if !h.secondFactorFailed(r, token, pending, method) {
			http.Redirect(w, r, "/app/login?error=Too+many+failed+verification+attempts.+Sign+in+again.", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/app/login/second-factor?error=Invalid+verification+code&method="+methodQuery(method), http.StatusFound)
	case err != nil:
		http.Error(w, "two-factor verification failed", http.StatusInternalServerError)
	default:
		if err := h.completeSignIn(w, r, token, pending, method); err != nil {
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/app/", http.StatusFound)
	}
}

func methodQuery(method string) string {
	if method == "recovery" {
		return "recovery"
	}
	return "totp"
}

// apiSecondFactorVerify completes a pending JSON sign-in with a TOTP or
// recovery code.
func (h *Handler) apiSecondFactorVerify(w http.ResponseWriter, r *http.Request) {
	pending, token, ok := h.apiPendingSignIn(w, r)
	if !ok {
		return
	}
	if pending.SecondFactor != secondFactorVerify {
		jsonError(w, http.StatusConflict, "two-factor enrolment is required; finish signing in with a browser")
		return
	}
	var request struct {
		Method string `json:"method"`
		Code   string `json:"code"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.verifySecondFactorCode(r, pending.ActorID, request.Method, request.Code); err != nil {
		h.apiSecondFactorFailure(w, r, token, pending, request.Method, err)
		return
	}
	if err := h.completeSignIn(w, r, token, pending, request.Method); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	csrf, _ := r.Cookie(csrfCookie)
	jsonResponse(w, http.StatusOK, map[string]string{"user_id": pending.ActorID, "csrf": csrf.Value})
}

// apiSecondFactorWebAuthnOptions begins a security key assertion, or a
// registration when the pending sign-in awaits required enrolment.
func (h *Handler) apiSecondFactorWebAuthnOptions(w http.ResponseWriter, r *http.Request) {
	pending, _, ok := h.apiPendingSignIn(w, r)
	if !ok {
		return
	}
	var options any
	var err error
	if pending.SecondFactor == secondFactorEnrol {
		options, err = h.beginWebAuthnRegistration(r, pending.ID, pending.ActorID)
	} else {
		options, err = h.beginWebAuthnLogin(r, pending.ID, pending.ActorID)
	}
	if err != nil {
		twoFactorAPIError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, options)
}

// apiSecondFactorWebAuthn completes a pending sign-in with a security key.
func (h *Handler) apiSecondFactorWebAuthn(w http.ResponseWriter, r *http.Request) {
	pending, token, ok := h.apiPendingSignIn(w, r)
	if !ok {
		return
	}
	var request struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var codes []string
	method := "webauthn"
	if pending.SecondFactor == secondFactorEnrol {
		var err error
		if codes, err = h.finishWebAuthnRegistration(r, pending.ID, pending.ActorID, request.Name, request.Credential); err != nil {
			twoFactorAPIError(w, err)
			return
		}
		method = "webauthn_enrolment"
	} else if err := h.throttledSecondFactor(r, pending.ActorID, func() error {
		return h.finishWebAuthnLogin(r, pending.ID, pending.ActorID, request.Credential)
	}); err != nil {
		h.apiSecondFactorFailure(w, r, token, pending, method, err)
		return
	}
	if err := h.completeSignIn(w, r, token, pending, method); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"redirect": "/app/", "recovery_codes": codes})
}

func (h *Handler) apiPendingSignIn(w http.ResponseWriter, r *http.Request) (model.Session, string, bool) {
	if !h.validPublicCSRF(r) {
		jsonError(w, http.StatusForbidden, "invalid CSRF token")
		return model.Session{}, "", false
	}
	pending, token, err := h.pendingSignIn(r)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "sign-in expired; enter your password again")
		return model.Session{}, "", false
	}
	return pending, token, true
}

func (h *Handler) apiSecondFactorFailure(w http.ResponseWriter, r *http.Request, token string, pending model.Session, method string, err error) {
	if errors.Is(err, errSecondFactorInvalid) && !h.secondFactorFailed(r, token, pending, method) {
		jsonError(w, http.StatusUnauthorized, "too many failed verification attempts; sign in again")
		return
	}
	twoFactorAPIError(w, err)
}

// Account self-service endpoints. They act on the signed-in actor, never on
// an impersonated or delegated subject.

// requireStepUp demands the actor's account password in the request body
// before a self-service action that weakens or reveals second factors, so a
// stolen session alone cannot strip or replace them. The password goes
// through the sign-in verification and its per-account failure throttle.
func (h *Handler) requireStepUp(w http.ResponseWriter, r *http.Request) bool {
	userID := currentActor(r).ID
	var request struct {
		Password string `json:"password"`
	}
	// A missing or malformed body is the same as a missing password.
	_ = decodeJSON(r, &request)
	if request.Password == "" {
		jsonError(w, http.StatusForbidden, "enter your account password to continue")
		return false
	}
	user, err := h.authenticateLogin(r, userID, request.Password)
	if err == nil && user.ID != userID {
		err = errInvalidLogin
	}
	switch {
	case err == nil:
		return true
	case errors.Is(err, errInvalidLogin):
		h.audit.Log(userID, "account.two_factor.failure", userID, map[string]string{"method": "step_up", "ip": httpservice.RequestClient(r).IP})
		jsonError(w, http.StatusForbidden, "the password is incorrect")
	default:
		twoFactorAPIError(w, err)
	}
	return false
}

// requireStepUpIfEnrolled guards enrolling another factor: the first factor
// of an account needs no step-up, since nothing is weakened.
func (h *Handler) requireStepUpIfEnrolled(w http.ResponseWriter, r *http.Request) bool {
	factors, err := h.secondFactors.Get(r.Context(), settingsUserID(r))
	if err != nil {
		apiError(w, err)
		return false
	}
	return !factors.Enabled() || h.requireStepUp(w, r)
}

type twoFactorStatusView struct {
	Enabled                bool              `json:"enabled"`
	Required               bool              `json:"required"`
	TOTP                   *totpStatusView   `json:"totp,omitempty"`
	RecoveryCodesRemaining int               `json:"recovery_codes_remaining"`
	RecoveryGeneratedAt    string            `json:"recovery_generated_at,omitempty"`
	WebAuthn               []webAuthnKeyView `json:"webauthn"`
}

type totpStatusView struct {
	EnabledAt  string `json:"enabled_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
}

type webAuthnKeyView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func (h *Handler) twoFactorStatus(ctx context.Context, userID string) (twoFactorStatusView, error) {
	factors, err := h.secondFactors.Get(ctx, userID)
	if err != nil {
		return twoFactorStatusView{}, err
	}
	view := twoFactorStatusView{
		Enabled: factors.Enabled(), Required: h.twoFactorRequired(ctx, userID),
		RecoveryCodesRemaining: factors.RemainingRecoveryCodes(), RecoveryGeneratedAt: formatOptionalTime(factors.RecoveryGeneratedAt),
		WebAuthn: make([]webAuthnKeyView, 0, len(factors.WebAuthn)),
	}
	if factors.TOTP != nil {
		view.TOTP = &totpStatusView{EnabledAt: formatOptionalTime(factors.TOTP.EnabledAt), LastUsedAt: formatOptionalTime(factors.TOTP.LastUsedAt)}
	}
	for _, key := range factors.WebAuthn {
		view.WebAuthn = append(view.WebAuthn, webAuthnKeyView{ID: key.ID, Name: key.Name, CreatedAt: formatOptionalTime(key.CreatedAt), LastUsedAt: formatOptionalTime(key.LastUsedAt)})
	}
	return view, nil
}

func (h *Handler) apiUserTwoFactor(w http.ResponseWriter, r *http.Request) {
	view, err := h.twoFactorStatus(r.Context(), settingsUserID(r))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, view)
}

func (h *Handler) apiBeginUserTOTP(w http.ResponseWriter, r *http.Request) {
	if !h.requireStepUpIfEnrolled(w, r) {
		return
	}
	enrolment, err := h.beginTOTPEnrolment(r, settingsUserID(r))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, enrolment)
}

func (h *Handler) apiConfirmUserTOTP(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	codes, err := h.confirmTOTPEnrolment(r.Context(), settingsUserID(r), request.Code)
	if err != nil {
		twoFactorAPIError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (h *Handler) apiDeleteUserTOTP(w http.ResponseWriter, r *http.Request) {
	if !h.requireStepUp(w, r) {
		return
	}
	userID := settingsUserID(r)
	if err := h.removeSecondFactor(r.Context(), userID, func(factors *model.SecondFactors) bool {
		removed := factors.TOTP != nil
		factors.TOTP = nil
		return removed
	}); err != nil {
		twoFactorAPIError(w, err)
		return
	}
	h.audit.Log(userID, "account.two_factor.totp_removed", userID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	if !h.requireStepUp(w, r) {
		return
	}
	userID := settingsUserID(r)
	var codes []string
	_, err := h.secondFactors.Update(r.Context(), userID, func(factors *model.SecondFactors) error {
		if !factors.Enabled() {
			return errNoSecondFactor
		}
		var err error
		codes, err = regenerateRecoveryCodes(factors)
		return err
	})
	if err != nil {
		twoFactorAPIError(w, err)
		return
	}
	h.audit.Log(userID, "account.two_factor.recovery_codes_regenerated", userID, nil)
	jsonResponse(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (h *Handler) apiUserWebAuthnOptions(w http.ResponseWriter, r *http.Request) {
	if !h.requireStepUpIfEnrolled(w, r) {
		return
	}
	session, _ := sessionFromContext(r.Context())
	options, err := h.beginWebAuthnRegistration(r, session.ID, settingsUserID(r))
	if err != nil {
		twoFactorAPIError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, options)
}

func (h *Handler) apiRegisterUserWebAuthn(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	session, _ := sessionFromContext(r.Context())
	codes, err := h.finishWebAuthnRegistration(r, session.ID, settingsUserID(r), request.Name, request.Credential)
	if err != nil {
		twoFactorAPIError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, map[string]any{"recovery_codes": codes})
}

func (h *Handler) apiRenameUserWebAuthn(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := boundedString(request.Name, maxFactorNameLength)
	if name == "" {
		jsonError(w, http.StatusBadRequest, "a name is required")
		return
	}
	id := r.PathValue("id")
	_, err := h.secondFactors.Update(r.Context(), settingsUserID(r), func(factors *model.SecondFactors) error {
		for i := range factors.WebAuthn {
			if factors.WebAuthn[i].ID == id {
				factors.WebAuthn[i].Name = name
				return nil
			}
		}
		return store.ErrNotFound
	})
	if err != nil {
		twoFactorAPIError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiDeleteUserWebAuthn(w http.ResponseWriter, r *http.Request) {
	if !h.requireStepUp(w, r) {
		return
	}
	userID, id := settingsUserID(r), r.PathValue("id")
	if err := h.removeSecondFactor(r.Context(), userID, func(factors *model.SecondFactors) bool {
		before := len(factors.WebAuthn)
		factors.WebAuthn = slices.DeleteFunc(factors.WebAuthn, func(key model.WebAuthnFactor) bool { return key.ID == id })
		return len(factors.WebAuthn) != before
	}); err != nil {
		twoFactorAPIError(w, err)
		return
	}
	h.audit.Log(userID, "account.two_factor.webauthn_removed", userID, map[string]string{"credential": id})
	w.WriteHeader(http.StatusNoContent)
}

// apiAdminResetTwoFactor removes every second factor of an account, for a
// user who lost theirs. The account must enrol again if policy requires it.
func (h *Handler) apiAdminResetTwoFactor(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	reach, ok := h.requireAccountAdmin(w, r, id, authz.DomainAccountsManage)
	if !ok {
		return
	}
	if _, err := h.users.Get(r.Context(), id); err != nil {
		apiError(w, err)
		return
	}
	existed, err := h.secondFactors.Delete(r.Context(), id)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "account.two_factor.reset", id, reach.auditDetails(map[string]string{"had_factors": fmt.Sprint(existed)}))
	w.WriteHeader(http.StatusNoContent)
}
