package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/auth"
)

func browserSessions(t *testing.T, client *http.Client, serverURL string) []browserSessionView {
	t.Helper()
	response, err := client.Get(serverURL + "/api/v1/user/browser-sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list sessions status=%d body=%s", response.StatusCode, raw)
	}
	if strings.Contains(string(raw), "csrf_token_hash") || strings.Contains(string(raw), "acting_reason") || strings.Contains(string(raw), "subject_id") {
		t.Fatalf("session projection leaked internal state: %s", raw)
	}
	var payload struct {
		Sessions []browserSessionView `json:"sessions"`
		Maximum  int                  `json:"maximum"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Maximum != maxBrowserSessions {
		t.Fatalf("maximum=%d", payload.Maximum)
	}
	return payload.Sessions
}

func TestBrowserSessionAPIIsOwnerScopedRevocableAndPasswordAware(t *testing.T) {
	server, typed := testApp(t)
	primary := testClient(t)
	primaryCSRF := setupAndLogin(t, server, primary, "alice")
	secondary := testClient(t)
	secondaryCSRF := loginExistingUser(t, secondary, server.URL, "alice")
	if secondaryCSRF == "" {
		t.Fatal("secondary login has no CSRF token")
	}

	listed := browserSessions(t, primary, server.URL)
	if len(listed) != 2 {
		t.Fatalf("sessions=%+v", listed)
	}
	var current, other browserSessionView
	for _, session := range listed {
		if session.Current {
			current = session
		} else {
			other = session
		}
	}
	if current.ID == "" || other.ID == "" || current.CreatedAt == "" || current.ExpiresAt == "" {
		t.Fatalf("current=%+v other=%+v", current, other)
	}
	response := authenticatedJSON(t, primary, http.MethodDelete, server.URL+"/api/v1/user/browser-sessions/"+current.ID, primaryCSRF, "")
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("current delete status=%d", response.StatusCode)
	}
	response = authenticatedJSON(t, primary, http.MethodDelete, server.URL+"/api/v1/user/browser-sessions/"+other.ID, "", "")
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d", response.StatusCode)
	}

	if err := typed.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	bobCSRF := loginExistingUser(t, bob, server.URL, "bob")
	bobSessions := browserSessions(t, bob, server.URL)
	response = authenticatedJSON(t, primary, http.MethodDelete, server.URL+"/api/v1/user/browser-sessions/"+bobSessions[0].ID, primaryCSRF, "")
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-account delete status=%d", response.StatusCode)
	}
	if len(browserSessions(t, bob, server.URL)) != 1 || bobCSRF == "" {
		t.Fatal("Bob session was affected")
	}

	response = authenticatedJSON(t, primary, http.MethodDelete, server.URL+"/api/v1/user/browser-sessions/"+other.ID, primaryCSRF, "")
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("other delete status=%d", response.StatusCode)
	}
	response, err := secondary.Get(server.URL + "/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked session status=%d", response.StatusCode)
	}

	for range 2 {
		client := testClient(t)
		loginExistingUser(t, client, server.URL, "alice")
	}
	if len(browserSessions(t, primary, server.URL)) != 3 {
		t.Fatal("expected current plus two additional sessions")
	}
	response = authenticatedJSON(t, primary, http.MethodDelete, server.URL+"/api/v1/user/browser-sessions", primaryCSRF, "")
	var revoked struct {
		Revoked int `json:"revoked"`
	}
	if err := json.NewDecoder(response.Body).Decode(&revoked); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || revoked.Revoked != 2 || len(browserSessions(t, primary, server.URL)) != 1 {
		t.Fatalf("bulk status=%d result=%+v", response.StatusCode, revoked)
	}

	passwordPeer := testClient(t)
	loginExistingUser(t, passwordPeer, server.URL, "alice")
	response = authenticatedJSON(t, primary, http.MethodPatch, server.URL+"/api/v1/user/profile", primaryCSRF, `{"current_password":"password123","new_password":"replacement123"}`)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("password status=%d", response.StatusCode)
	}
	if len(browserSessions(t, primary, server.URL)) != 1 {
		t.Fatal("password change did not retain exactly the current session")
	}
	response, err = passwordPeer.Get(server.URL + "/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("password-revoked session status=%d", response.StatusCode)
	}
	user, err := typed.UserStore().Get(t.Context(), "alice")
	if err != nil || !auth.ComparePassword("replacement123", user.PasswordHash) || auth.ComparePassword("password123", user.PasswordHash) {
		t.Fatalf("password update user=%+v err=%v", user, err)
	}
	entries, err := audit.New(typed).QueryReverse(t.Context(), time.Time{}, "browser_session.revoke", "alice", 10)
	if err != nil || len(entries) < 3 {
		t.Fatalf("revocation audit=%+v err=%v", entries, err)
	}
}

func TestRevokedBrowserSessionReceivesFinalEventAndWebSocketCloses(t *testing.T) {
	handler, _ := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	primary := testClient(t)
	primaryCSRF := setupAndLogin(t, server, primary, "alice")
	secondary := testClient(t)
	loginExistingUser(t, secondary, server.URL, "alice")

	serverURL, _ := url.Parse(server.URL)
	header := http.Header{"Origin": []string{server.URL}}
	for _, cookie := range secondary.Jar.Cookies(serverURL) {
		header.Add("Cookie", cookie.String())
	}
	connection, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/api/v1/events", header)
	if err != nil {
		if response != nil {
			t.Fatalf("websocket status=%d: %v", response.StatusCode, err)
		}
		t.Fatal(err)
	}
	defer connection.Close()
	var otherID string
	for _, session := range browserSessions(t, primary, server.URL) {
		if !session.Current {
			otherID = session.ID
		}
	}
	response = authenticatedJSON(t, primary, http.MethodDelete, server.URL+"/api/v1/user/browser-sessions/"+otherID, primaryCSRF, "")
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", response.StatusCode)
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	var event struct {
		Type     string `json:"type"`
		Resource string `json:"resource"`
	}
	if err := connection.ReadJSON(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "browser.session.revoked" || event.Resource != otherID {
		t.Fatalf("event=%+v", event)
	}
	if _, _, err := connection.ReadMessage(); err == nil {
		t.Fatal("revoked session WebSocket remained open")
	}
}

func TestBrowserSessionSettingsPageUsesCurrentTabAndWebModals(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	response, err := client.Get(server.URL + "/app/settings/sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	page := string(raw)
	for _, required := range []string{
		`data-settings-section="sessions"`, `aria-current="page" href="/app/settings/sessions"`,
		`<h1 tabindex="-1" autofocus>Web sessions</h1>`, `id="user-browser-session-settings"`,
		`data-session-id="`, `id="confirm-dialog"`,
	} {
		if response.StatusCode != http.StatusOK || !strings.Contains(page, required) {
			t.Fatalf("settings page missing %q (status %d)", required, response.StatusCode)
		}
	}
	if strings.Contains(page, `aria-current="page" href="/app/settings/profile"`) {
		t.Fatal("profile tab remained current on Web sessions")
	}
}
