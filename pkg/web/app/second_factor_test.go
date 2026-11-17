package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
)

// twoFactorFixture is an application server with an owner ("owner") signed
// in on ownerClient. Server URLs use localhost so WebAuthn has a valid RP ID.
type twoFactorFixture struct {
	t           *testing.T
	handler     *Handler
	ts          *model.TypedStore
	base        string
	ownerClient *http.Client
	ownerCSRF   string
}

func newTwoFactorFixture(t *testing.T) *twoFactorFixture {
	t.Helper()
	handler, ts := testHandler(t)
	handler.ConfigureLoginThrottle(ratelimit.NewAuthThrottleWithLimits(1000, 1000, time.Minute))
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	f := &twoFactorFixture{t: t, handler: handler, ts: ts, base: strings.Replace(server.URL, "127.0.0.1", "localhost", 1)}
	testHandlers.Store(f.base, handler)
	f.ownerClient = noRedirectClient(t)
	t.Cleanup(func() { testHandlers.Delete(f.base) })
	f.ownerCSRF = setupAndLogin(t, &httptest.Server{URL: f.base}, f.ownerClient, "owner")
	return f
}

func noRedirectClient(t *testing.T) *http.Client {
	client := testClient(t)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

func (f *twoFactorFixture) do(client *http.Client, method, path, csrf, body string) (int, string, http.Header) {
	f.t.Helper()
	request, err := http.NewRequest(method, f.base+path, strings.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := client.Do(request)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(data), response.Header
}

func (f *twoFactorFixture) form(client *http.Client, path string, values url.Values) (int, string, string) {
	f.t.Helper()
	response, err := client.PostForm(f.base+path, values)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, response.Header.Get("Location"), string(data)
}

// passwordSignIn signs in with a password on a new client and returns the
// client, its CSRF token and where the sign-in redirected.
func (f *twoFactorFixture) passwordSignIn(username string) (*http.Client, string, string) {
	f.t.Helper()
	client := noRedirectClient(f.t)
	response, err := client.Get(f.base + "/app/login")
	if err != nil {
		f.t.Fatal(err)
	}
	_ = response.Body.Close()
	csrf := csrfCookieValue(f.t, client, f.base)
	status, location, _ := f.form(client, "/app/login", url.Values{"_csrf": {csrf}, "username": {username}, "password": {"password123"}})
	if status != http.StatusFound {
		f.t.Fatalf("password sign-in status = %d", status)
	}
	return client, csrf, location
}

func (f *twoFactorFixture) auditActions(action string) []audit.Entry {
	f.t.Helper()
	entries, err := audit.New(f.ts).Query(f.t.Context(), time.Time{}, action, "", 1000)
	if err != nil {
		f.t.Fatal(err)
	}
	return entries
}

func decodeTOTPSecret(t *testing.T, text string) []byte {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(text)
	if err != nil {
		t.Fatalf("decode TOTP secret %q: %v", text, err)
	}
	return secret
}

func TestTOTPEnrolmentRecoveryCodesAndSecondFactorSignIn(t *testing.T) {
	f := newTwoFactorFixture(t)
	status, body, _ := f.do(f.ownerClient, http.MethodPost, "/api/v1/user/two-factor/totp", f.ownerCSRF, "{}")
	if status != http.StatusOK {
		t.Fatalf("begin TOTP status=%d body=%s", status, body)
	}
	var enrolment totpEnrolment
	if err := json.Unmarshal([]byte(body), &enrolment); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enrolment.URI, "otpauth://totp/Veksel:owner@localhost?") || !strings.HasPrefix(enrolment.QRCode, "data:image/svg+xml;base64,") {
		t.Fatalf("enrolment URI = %s, QR prefix = %.40s", enrolment.URI, enrolment.QRCode)
	}
	secret := decodeTOTPSecret(t, enrolment.Secret)
	factors, err := f.handler.secondFactors.Get(t.Context(), "owner")
	if err != nil || factors.PendingTOTP == nil || strings.Contains(string(factors.PendingTOTP.SealedSecret), enrolment.Secret) {
		t.Fatalf("pending secret is not sealed: %+v err=%v", factors.PendingTOTP, err)
	}
	if status, body, _ := f.do(f.ownerClient, http.MethodPost, "/api/v1/user/two-factor/totp/confirm", f.ownerCSRF, `{"code":"000000x"}`); status != http.StatusBadRequest {
		t.Fatalf("wrong confirmation status=%d body=%s", status, body)
	}
	step := auth.TOTPStep(time.Now())
	enrolCode := auth.TOTPCode(secret, step)
	status, body, _ = f.do(f.ownerClient, http.MethodPost, "/api/v1/user/two-factor/totp/confirm", f.ownerCSRF, `{"code":"`+enrolCode+`"}`)
	if status != http.StatusOK {
		t.Fatalf("confirm TOTP status=%d body=%s", status, body)
	}
	var confirmed struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal([]byte(body), &confirmed); err != nil || len(confirmed.RecoveryCodes) != auth.RecoveryCodeCount {
		t.Fatalf("recovery codes = %v err=%v", confirmed.RecoveryCodes, err)
	}
	if len(f.auditActions("account.two_factor.totp_enrolled")) != 1 {
		t.Fatal("TOTP enrolment was not audited")
	}

	// A password alone now yields a pending sign-in that grants nothing.
	client, csrf, location := f.passwordSignIn("owner")
	if location != "/app/login/second-factor" {
		t.Fatalf("password sign-in redirected to %q", location)
	}
	for _, path := range []string{"/api/v1/session", "/api/v1/user/settings", "/api/v1/user/two-factor"} {
		if status, _, _ := f.do(client, http.MethodGet, path, "", ""); status != http.StatusUnauthorized {
			t.Fatalf("pending sign-in reached %s with status %d", path, status)
		}
	}
	if status, _, header := f.do(client, http.MethodGet, "/app/", "", ""); status != http.StatusFound || header.Get("Location") != "/app/login" {
		t.Fatalf("pending sign-in opened the app: status=%d location=%q", status, header.Get("Location"))
	}
	if status, body, _ := f.do(client, http.MethodGet, "/app/login/second-factor", "", ""); status != http.StatusOK || !strings.Contains(body, "Authenticator app code") || strings.Contains(body, "data-webauthn-sign-in") {
		t.Fatalf("second-factor page status=%d body=%s", status, body)
	}

	// The code accepted at enrolment cannot be replayed.
	status, location, _ = f.form(client, "/app/login/second-factor", url.Values{"_csrf": {csrf}, "method": {"totp"}, "code": {enrolCode}})
	if status != http.StatusFound || !strings.HasPrefix(location, "/app/login/second-factor?error=") {
		t.Fatalf("replayed code: status=%d location=%q", status, location)
	}
	if len(f.auditActions("account.two_factor.failure")) != 1 {
		t.Fatal("failed second factor was not audited")
	}
	status, location, _ = f.form(client, "/app/login/second-factor", url.Values{"_csrf": {csrf}, "method": {"totp"}, "code": {auth.TOTPCode(secret, step+1)}})
	if status != http.StatusFound || location != "/app/" {
		t.Fatalf("TOTP sign-in: status=%d location=%q", status, location)
	}
	if status, body, _ := f.do(client, http.MethodGet, "/api/v1/user/two-factor", "", ""); status != http.StatusOK || !strings.Contains(body, `"enabled":true`) || !strings.Contains(body, `"recovery_codes_remaining":10`) {
		t.Fatalf("completed session status=%d body=%s", status, body)
	}

	// A recovery code works exactly once, over the JSON sign-in too.
	client, csrf, _ = f.passwordSignIn("owner")
	if status, body, _ := f.do(client, http.MethodPost, "/api/v1/session/second-factor", csrf, `{"method":"recovery","code":"`+strings.ToUpper(confirmed.RecoveryCodes[0])+`"}`); status != http.StatusOK || !strings.Contains(body, `"user_id":"owner"`) {
		t.Fatalf("recovery code sign-in status=%d body=%s", status, body)
	}
	if status, _, _ := f.do(client, http.MethodGet, "/api/v1/session", "", ""); status != http.StatusOK {
		t.Fatalf("session after recovery sign-in status=%d", status)
	}
	client, csrf, _ = f.passwordSignIn("owner")
	if status, _, _ := f.do(client, http.MethodPost, "/api/v1/session/second-factor", csrf, `{"method":"recovery","code":"`+confirmed.RecoveryCodes[0]+`"}`); status != http.StatusBadRequest {
		t.Fatalf("reused recovery code status=%d", status)
	}
	if entries := f.auditActions("account.two_factor.recovery_code_used"); len(entries) != 1 || entries[0].Details["remaining"] != "9" {
		t.Fatalf("recovery code use audit = %+v", entries)
	}

	// Regenerating replaces every code.
	status, body, _ = f.do(f.ownerClient, http.MethodPost, "/api/v1/user/two-factor/recovery-codes", f.ownerCSRF, `{"password":"password123"}`)
	if status != http.StatusOK || strings.Contains(body, confirmed.RecoveryCodes[1]) {
		t.Fatalf("regenerate status=%d body=%s", status, body)
	}
	if status, _, _ := f.do(client, http.MethodPost, "/api/v1/session/second-factor", csrf, `{"method":"recovery","code":"`+confirmed.RecoveryCodes[1]+`"}`); status != http.StatusBadRequest {
		t.Fatalf("replaced recovery code status=%d", status)
	}

	// Removing the only factor turns two-factor sign-in off again.
	if status, body, _ := f.do(f.ownerClient, http.MethodDelete, "/api/v1/user/two-factor/totp", f.ownerCSRF, `{"password":"password123"}`); status != http.StatusNoContent {
		t.Fatalf("remove TOTP status=%d body=%s", status, body)
	}
	if _, _, location := f.passwordSignIn("owner"); location != "/app/" {
		t.Fatalf("sign-in without factors redirected to %q", location)
	}
}

func TestSecondFactorFailuresEndPendingSignIn(t *testing.T) {
	f := newTwoFactorFixture(t)
	f.enrolTOTP("owner", f.ownerClient, f.ownerCSRF)
	client, csrf, _ := f.passwordSignIn("owner")
	for attempt := 1; attempt <= maxSecondFactorFailures; attempt++ {
		status, body, _ := f.do(client, http.MethodPost, "/api/v1/session/second-factor", csrf, `{"method":"totp","code":"000000"}`)
		want := http.StatusBadRequest
		if attempt == maxSecondFactorFailures {
			want = http.StatusUnauthorized
		}
		if status != want {
			t.Fatalf("attempt %d status=%d body=%s", attempt, status, body)
		}
	}
	if status, _, _ := f.do(client, http.MethodPost, "/api/v1/session/second-factor", csrf, `{"method":"totp","code":"000000"}`); status != http.StatusUnauthorized {
		t.Fatalf("ended pending sign-in status=%d", status)
	}
}

func TestSecondFactorAttemptsUseLoginThrottle(t *testing.T) {
	f := newTwoFactorFixture(t)
	f.enrolTOTP("owner", f.ownerClient, f.ownerCSRF)
	f.handler.ConfigureLoginThrottle(ratelimit.NewAuthThrottleWithLimits(100, 2, time.Hour))
	client, csrf, _ := f.passwordSignIn("owner")
	for range 2 {
		if status, _, _ := f.do(client, http.MethodPost, "/api/v1/session/second-factor", csrf, `{"method":"totp","code":"000000"}`); status != http.StatusBadRequest {
			t.Fatalf("wrong code status=%d", status)
		}
	}
	if status, _, header := f.do(client, http.MethodPost, "/api/v1/session/second-factor", csrf, `{"method":"totp","code":"000000"}`); status != http.StatusTooManyRequests || header.Get("Retry-After") == "" {
		t.Fatalf("throttled status=%d", status)
	}
}

// enrolTOTP enables an authenticator for the signed-in client and returns
// its secret.
func (f *twoFactorFixture) enrolTOTP(userID string, client *http.Client, csrf string) []byte {
	f.t.Helper()
	_, body, _ := f.do(client, http.MethodPost, "/api/v1/user/two-factor/totp", csrf, "{}")
	var enrolment totpEnrolment
	if err := json.Unmarshal([]byte(body), &enrolment); err != nil {
		f.t.Fatalf("begin TOTP for %s: %v (%s)", userID, err, body)
	}
	secret := decodeTOTPSecret(f.t, enrolment.Secret)
	if status, body, _ := f.do(client, http.MethodPost, "/api/v1/user/two-factor/totp/confirm", csrf, `{"code":"`+auth.TOTPCode(secret, auth.TOTPStep(time.Now()))+`"}`); status != http.StatusOK {
		f.t.Fatalf("confirm TOTP for %s status=%d body=%s", userID, status, body)
	}
	return secret
}

var enrolmentSecretPattern = regexp.MustCompile(`enter this key manually: <code[^>]*>([A-Z2-7]+)</code>`)

func TestTwoFactorPolicyForcesEnrolmentAndAdminReset(t *testing.T) {
	f := newTwoFactorFixture(t)
	if err := f.ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	f.handler.setTwoFactorPolicy("administrators")
	if _, _, location := f.passwordSignIn("bob"); location != "/app/" {
		t.Fatalf("regular user under administrators policy redirected to %q", location)
	}
	f.handler.setTwoFactorPolicy("all")
	client, csrf, location := f.passwordSignIn("bob")
	if location != "/app/login/second-factor" {
		t.Fatalf("policy sign-in redirected to %q", location)
	}
	if status, _, _ := f.do(client, http.MethodGet, "/api/v1/user/settings", "", ""); status != http.StatusUnauthorized {
		t.Fatalf("enrolment-pending sign-in reached the API with status %d", status)
	}
	if status, body, _ := f.do(client, http.MethodPost, "/api/v1/session/second-factor", csrf, `{"method":"totp","code":"123456"}`); status != http.StatusConflict {
		t.Fatalf("JSON verify during enrolment status=%d body=%s", status, body)
	}
	status, page, _ := f.do(client, http.MethodGet, "/app/login/second-factor", "", "")
	match := enrolmentSecretPattern.FindStringSubmatch(page)
	if status != http.StatusOK || match == nil || !strings.Contains(page, `<img src="data:image/svg`) {
		t.Fatalf("enrolment page status=%d body=%s", status, page)
	}
	secret := decodeTOTPSecret(t, match[1])
	status, _, page = f.form(client, "/app/login/second-factor", url.Values{"_csrf": {csrf}, "method": {"totp"}, "code": {auth.TOTPCode(secret, auth.TOTPStep(time.Now()))}})
	if status != http.StatusOK || strings.Count(page, "<li>") != auth.RecoveryCodeCount {
		t.Fatalf("enrolment confirmation status=%d body=%s", status, page)
	}
	if status, body, _ := f.do(client, http.MethodGet, "/api/v1/user/two-factor", "", ""); status != http.StatusOK || !strings.Contains(body, `"required":true`) {
		t.Fatalf("session after enrolment status=%d body=%s", status, body)
	}
	if status, body, _ := f.do(client, http.MethodDelete, "/api/v1/user/two-factor/totp", csrf, `{"password":"password123"}`); status != http.StatusConflict {
		t.Fatalf("removing the last required factor status=%d body=%s", status, body)
	}

	// Regular users cannot reset factors; administrators can, with an audit
	// record, and the user must enrol again at the next sign-in.
	if status, _, _ := f.do(client, http.MethodDelete, "/api/v1/admin/users/owner/two-factor", csrf, ""); status != http.StatusForbidden {
		t.Fatalf("non-admin reset status=%d", status)
	}
	if status, body, _ := f.do(f.ownerClient, http.MethodDelete, "/api/v1/admin/users/bob/two-factor", f.ownerCSRF, ""); status != http.StatusNoContent {
		t.Fatalf("admin reset status=%d body=%s", status, body)
	}
	if entries := f.auditActions("account.two_factor.reset"); len(entries) != 1 || entries[0].Actor != "owner" || entries[0].Target != "bob" || entries[0].Details["had_factors"] != "true" {
		t.Fatalf("reset audit = %+v", entries)
	}
	if factors, err := f.handler.secondFactors.Get(t.Context(), "bob"); err != nil || factors.Enabled() {
		t.Fatalf("factors after reset = %+v err=%v", factors, err)
	}
	f.handler.setTwoFactorPolicy("off")
	if _, _, location := f.passwordSignIn("bob"); location != "/app/" {
		t.Fatalf("sign-in after reset redirected to %q", location)
	}
}

// softAuthenticator is a minimal software FIDO2 authenticator with "none"
// attestation and an ES256 key.
type softAuthenticator struct {
	t       *testing.T
	key     *ecdsa.PrivateKey
	id      []byte
	counter uint32
	origin  string
}

func newSoftAuthenticator(t *testing.T, origin string) *softAuthenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softAuthenticator{t: t, key: key, id: id, origin: origin}
}

func (a *softAuthenticator) clientData(kind string, challenge []byte) []byte {
	data, _ := json.Marshal(map[string]any{"type": kind, "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": a.origin})
	return data
}

func (a *softAuthenticator) authData(rpID string, flags byte, attested []byte) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	data := append(rpHash[:], flags)
	data = binary.BigEndian.AppendUint32(data, a.counter)
	return append(data, attested...)
}

func (a *softAuthenticator) create(optionsJSON string) string {
	var options protocol.CredentialCreation
	if err := json.Unmarshal([]byte(optionsJSON), &options); err != nil {
		a.t.Fatalf("decode creation options: %v (%s)", err, optionsJSON)
	}
	point, err := a.key.PublicKey.Bytes()
	if err != nil {
		a.t.Fatal(err)
	}
	coseKey, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:65]})
	if err != nil {
		a.t.Fatal(err)
	}
	attested := make([]byte, 16)
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(a.id)))
	attested = append(append(attested, a.id...), coseKey...)
	object, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(options.Response.RelyingParty.ID, 0x45, attested)})
	if err != nil {
		a.t.Fatal(err)
	}
	return a.credentialJSON(map[string]string{
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(a.clientData("webauthn.create", options.Response.Challenge)),
		"attestationObject": base64.RawURLEncoding.EncodeToString(object),
	})
}

func (a *softAuthenticator) get(optionsJSON string) string {
	var options protocol.CredentialAssertion
	if err := json.Unmarshal([]byte(optionsJSON), &options); err != nil {
		a.t.Fatalf("decode assertion options: %v (%s)", err, optionsJSON)
	}
	a.counter++
	authData := a.authData(options.Response.RelyingPartyID, 0x05, nil)
	clientData := a.clientData("webauthn.get", options.Response.Challenge)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte(nil), authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	return a.credentialJSON(map[string]string{
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
		"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
		"signature":         base64.RawURLEncoding.EncodeToString(signature),
	})
}

func (a *softAuthenticator) credentialJSON(response map[string]string) string {
	id := base64.RawURLEncoding.EncodeToString(a.id)
	data, _ := json.Marshal(map[string]any{"id": id, "rawId": id, "type": "public-key", "response": response, "clientExtensionResults": map[string]any{}})
	return string(data)
}

func TestWebAuthnRegistrationSignInAndForcedEnrolment(t *testing.T) {
	f := newTwoFactorFixture(t)
	authenticator := newSoftAuthenticator(t, f.base)
	status, options, _ := f.do(f.ownerClient, http.MethodPost, "/api/v1/user/two-factor/webauthn/options", f.ownerCSRF, "{}")
	if status != http.StatusOK || !strings.Contains(options, `"id":"localhost"`) {
		t.Fatalf("registration options status=%d body=%s", status, options)
	}
	status, body, _ := f.do(f.ownerClient, http.MethodPost, "/api/v1/user/two-factor/webauthn", f.ownerCSRF, `{"name":"Desk key","credential":`+authenticator.create(options)+`}`)
	if status != http.StatusCreated || strings.Count(body, "-") < auth.RecoveryCodeCount {
		t.Fatalf("register status=%d body=%s", status, body)
	}
	// A ceremony is single use.
	if status, _, _ := f.do(f.ownerClient, http.MethodPost, "/api/v1/user/two-factor/webauthn", f.ownerCSRF, `{"name":"Again","credential":`+authenticator.create(options)+`}`); status != http.StatusBadRequest {
		t.Fatalf("replayed registration status=%d", status)
	}
	_, body, _ = f.do(f.ownerClient, http.MethodGet, "/api/v1/user/two-factor", "", "")
	var state twoFactorStatusView
	if err := json.Unmarshal([]byte(body), &state); err != nil || len(state.WebAuthn) != 1 || state.WebAuthn[0].Name != "Desk key" {
		t.Fatalf("status = %s err=%v", body, err)
	}
	keyID := state.WebAuthn[0].ID
	if status, _, _ := f.do(f.ownerClient, http.MethodPatch, "/api/v1/user/two-factor/webauthn/"+keyID, f.ownerCSRF, `{"name":"Keyring"}`); status != http.StatusNoContent {
		t.Fatalf("rename status=%d", status)
	}

	client, csrf, location := f.passwordSignIn("owner")
	if location != "/app/login/second-factor" {
		t.Fatalf("sign-in redirected to %q", location)
	}
	if _, page, _ := f.do(client, http.MethodGet, "/app/login/second-factor", "", ""); !strings.Contains(page, "data-webauthn-sign-in") {
		t.Fatalf("second-factor page lacks the security key option: %s", page)
	}
	status, options, _ = f.do(client, http.MethodPost, "/api/v1/session/second-factor/webauthn/options", csrf, "{}")
	if status != http.StatusOK {
		t.Fatalf("assertion options status=%d body=%s", status, options)
	}
	status, body, _ = f.do(client, http.MethodPost, "/api/v1/session/second-factor/webauthn", csrf, `{"credential":`+authenticator.get(options)+`}`)
	if status != http.StatusOK || !strings.Contains(body, `"redirect":"/app/"`) {
		t.Fatalf("assertion status=%d body=%s", status, body)
	}
	if status, _, _ := f.do(client, http.MethodGet, "/api/v1/session", "", ""); status != http.StatusOK {
		t.Fatalf("session after security key sign-in status=%d", status)
	}

	// A counter that does not advance suggests a cloned authenticator.
	client, csrf, _ = f.passwordSignIn("owner")
	_, options, _ = f.do(client, http.MethodPost, "/api/v1/session/second-factor/webauthn/options", csrf, "{}")
	authenticator.counter--
	if status, _, _ := f.do(client, http.MethodPost, "/api/v1/session/second-factor/webauthn", csrf, `{"credential":`+authenticator.get(options)+`}`); status != http.StatusBadRequest {
		t.Fatalf("cloned counter status=%d", status)
	}
	if status, _, _ := f.do(f.ownerClient, http.MethodDelete, "/api/v1/user/two-factor/webauthn/"+keyID, f.ownerCSRF, `{"password":"password123"}`); status != http.StatusNoContent {
		t.Fatalf("delete key status=%d", status)
	}
	if entries := f.auditActions("account.two_factor.webauthn_removed"); len(entries) != 1 {
		t.Fatalf("removal audit = %+v", entries)
	}

	// Under a requirement, a security key can satisfy forced enrolment.
	if err := f.ts.UserStore().Create(t.Context(), "carol", "Carol", "password123"); err != nil {
		t.Fatal(err)
	}
	f.handler.setTwoFactorPolicy("all")
	client, csrf, _ = f.passwordSignIn("carol")
	status, options, _ = f.do(client, http.MethodPost, "/api/v1/session/second-factor/webauthn/options", csrf, "{}")
	if status != http.StatusOK || !strings.Contains(options, `"user"`) {
		t.Fatalf("enrolment options status=%d body=%s", status, options)
	}
	carolKey := newSoftAuthenticator(t, f.base)
	status, body, _ = f.do(client, http.MethodPost, "/api/v1/session/second-factor/webauthn", csrf, `{"name":"Phone","credential":`+carolKey.create(options)+`}`)
	var enrolled struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &enrolled) != nil || len(enrolled.RecoveryCodes) != auth.RecoveryCodeCount {
		t.Fatalf("forced WebAuthn enrolment status=%d body=%s", status, body)
	}
	if status, _, _ := f.do(client, http.MethodGet, "/api/v1/user/two-factor", "", ""); status != http.StatusOK {
		t.Fatalf("session after forced enrolment status=%d", status)
	}
}

func TestSelfServiceFactorChangesRequirePassword(t *testing.T) {
	f := newTwoFactorFixture(t)
	good, bad := `{"password":"password123"}`, `{"password":"wrong-password"}`
	// The first factor needs no step-up; later enrolment does.
	f.enrolTOTP("owner", f.ownerClient, f.ownerCSRF)
	guarded := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/user/two-factor/totp"},
		{http.MethodPost, "/api/v1/user/two-factor/webauthn/options"},
		{http.MethodPost, "/api/v1/user/two-factor/recovery-codes"},
		{http.MethodDelete, "/api/v1/user/two-factor/totp"},
		{http.MethodDelete, "/api/v1/user/two-factor/webauthn/missing"},
	}
	for _, endpoint := range guarded {
		for _, body := range []string{"", "{}", `{"password":""}`, bad} {
			if status, _, _ := f.do(f.ownerClient, endpoint.method, endpoint.path, f.ownerCSRF, body); status != http.StatusForbidden {
				t.Fatalf("%s %s body %q status=%d, want 403", endpoint.method, endpoint.path, body, status)
			}
		}
	}
	if entries := f.auditActions("account.two_factor.failure"); len(entries) != len(guarded) {
		t.Fatalf("wrong-password audit entries = %d, want %d", len(entries), len(guarded))
	}
	if status, body, _ := f.do(f.ownerClient, http.MethodGet, "/api/v1/user/two-factor", "", ""); status != http.StatusOK || !strings.Contains(body, `"enabled":true`) {
		t.Fatalf("factors changed without a password: %d %s", status, body)
	}
	for _, path := range []string{"/api/v1/user/two-factor/totp", "/api/v1/user/two-factor/webauthn/options", "/api/v1/user/two-factor/recovery-codes"} {
		if status, body, _ := f.do(f.ownerClient, http.MethodPost, path, f.ownerCSRF, good); status != http.StatusOK {
			t.Fatalf("POST %s with password status=%d body=%s", path, status, body)
		}
	}
	if status, body, _ := f.do(f.ownerClient, http.MethodDelete, "/api/v1/user/two-factor/webauthn/missing", f.ownerCSRF, good); status != http.StatusNotFound {
		t.Fatalf("delete missing key with password status=%d body=%s", status, body)
	}
	if status, body, _ := f.do(f.ownerClient, http.MethodDelete, "/api/v1/user/two-factor/totp", f.ownerCSRF, good); status != http.StatusNoContent {
		t.Fatalf("delete TOTP with password status=%d body=%s", status, body)
	}
}

func TestSelfServiceStepUpUsesLoginThrottle(t *testing.T) {
	f := newTwoFactorFixture(t)
	f.enrolTOTP("owner", f.ownerClient, f.ownerCSRF)
	f.handler.ConfigureLoginThrottle(ratelimit.NewAuthThrottleWithLimits(100, 2, time.Hour))
	for range 2 {
		if status, _, _ := f.do(f.ownerClient, http.MethodPost, "/api/v1/user/two-factor/recovery-codes", f.ownerCSRF, `{"password":"nope"}`); status != http.StatusForbidden {
			t.Fatalf("wrong password status=%d", status)
		}
	}
	// Even the right password is refused while the account is throttled.
	if status, _, header := f.do(f.ownerClient, http.MethodDelete, "/api/v1/user/two-factor/totp", f.ownerCSRF, `{"password":"password123"}`); status != http.StatusTooManyRequests || header.Get("Retry-After") == "" {
		t.Fatalf("throttled status=%d", status)
	}
}
