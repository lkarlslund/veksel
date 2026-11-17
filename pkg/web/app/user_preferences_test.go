package app

import (
	"html"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestDisplayPreferencesDefaultMigrateValidateAndEmbed(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	settings := decodeTestJSON[userSettingsResponse](t, mustGet(t, client, server.URL+"/api/v1/user/settings"))
	display := settings.DisplayPreferences
	// Never saved: defaults, and saved=false tells the browser to migrate its
	// older per-browser layout and calendar choices once.
	if display.Saved || display.Language != "en" || display.WeekStart != 1 || display.Density != "compact" || display.ReadingPane != "right" ||
		!slices.Equal(display.WorkingDays, []int{1, 2, 3, 4, 5}) || display.WorkStart != "08:00" || display.WorkEnd != "17:00" || display.TimeZone != "" {
		t.Fatalf("default display preferences = %+v", display)
	}
	if notifications := settings.NotificationPreferences; notifications.Saved || !notifications.NewMail || notifications.Favorites || !notifications.Meetings || !notifications.FollowUps || notifications.Sound || notifications.QuietHours {
		t.Fatalf("default notification preferences = %+v", notifications)
	}

	valid := `{"language":"en","time_zone":"Europe/Copenhagen","time_format":"24h","date_order":"ymd","week_start":0,"working_days":[5,1,2,2,3,4],"work_start":"07:30","work_end":"16:00","density":"comfortable","reading_pane":"bottom"}`
	for _, invalid := range []string{
		strings.Replace(valid, `"en"`, `"da"`, 1),
		strings.Replace(valid, "Europe/Copenhagen", "Mars/Olympus", 1),
		strings.Replace(valid, "Europe/Copenhagen", "Local", 1),
		strings.Replace(valid, `"24h"`, `"36h"`, 1),
		strings.Replace(valid, `"ymd"`, `"ydm"`, 1),
		strings.Replace(valid, `"week_start":0`, `"week_start":7`, 1),
		strings.Replace(valid, `[5,1,2,2,3,4]`, `[]`, 1),
		strings.Replace(valid, `[5,1,2,2,3,4]`, `[8]`, 1),
		strings.Replace(valid, `"16:00"`, `"07:00"`, 1),
		strings.Replace(valid, `"07:30"`, `"7:30"`, 1),
		strings.Replace(valid, `"comfortable"`, `"spacious"`, 1),
		strings.Replace(valid, `"bottom"`, `"left"`, 1),
	} {
		response := authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/user/display-preferences", csrf, invalid)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s status=%d", invalid, response.StatusCode)
		}
	}
	response := authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/user/display-preferences", csrf, valid)
	if saved := decodeTestJSON[model.DisplayPreferences](t, response); !saved.Saved || saved.TimeZone != "Europe/Copenhagen" {
		t.Fatalf("save response = %+v", saved)
	}
	settings = decodeTestJSON[userSettingsResponse](t, mustGet(t, client, server.URL+"/api/v1/user/settings"))
	display = settings.DisplayPreferences
	if !display.Saved || display.TimeZone != "Europe/Copenhagen" || display.TimeFormat != "24h" || display.DateOrder != "ymd" || display.WeekStart != 0 ||
		!slices.Equal(display.WorkingDays, []int{1, 2, 3, 4, 5}) || display.WorkStart != "07:30" || display.Density != "comfortable" || display.ReadingPane != "bottom" {
		t.Fatalf("saved display preferences = %+v", display)
	}

	// The shell embeds the effective preferences so formatting applies on
	// first paint; the value is attribute-escaped JSON.
	page := mustGet(t, client, server.URL+"/app/mail")
	body, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	match := regexp.MustCompile(`data-preferences="([^"]*)"`).FindStringSubmatch(string(body))
	if match == nil {
		t.Fatal("app shell does not embed account preferences")
	}
	embedded := html.UnescapeString(match[1])
	for _, want := range []string{`"display":{"saved":true`, `"time_zone":"Europe/Copenhagen"`, `"reading_pane":"bottom"`, `"notifications":{"new_mail":true`} {
		if !strings.Contains(embedded, want) {
			t.Errorf("embedded preferences %s lack %s", embedded, want)
		}
	}
	for _, want := range []string{`rel="manifest" href="/app/manifest.webmanifest"`, `data-notification-sound="/static/sounds/notify.wav?v=`, `class="skip-link" href="#main-content"`, `id="main-content"`, `<h1 class="sr-only">Mail</h1>`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("app shell lacks %s", want)
		}
	}
}

func TestNotificationPreferencesValidateAndPersist(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	for _, invalid := range []string{
		`{"new_mail":true,"quiet_hours":true,"quiet_start":"22:00","quiet_end":"22:00"}`,
		`{"new_mail":true,"quiet_start":"25:00","quiet_end":"07:00"}`,
		`{"new_mail":true}`,
	} {
		response := authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/user/notification-preferences", csrf, invalid)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s status=%d", invalid, response.StatusCode)
		}
	}
	response := authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/user/notification-preferences", csrf,
		`{"new_mail":false,"favorites":true,"meetings":true,"follow_ups":false,"sound":true,"quiet_hours":true,"quiet_start":"21:30","quiet_end":"06:45"}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("save status=%d", response.StatusCode)
	}
	settings := decodeTestJSON[userSettingsResponse](t, mustGet(t, client, server.URL+"/api/v1/user/settings"))
	if got := settings.NotificationPreferences; !got.Saved || got.NewMail || !got.Favorites || !got.Meetings || got.FollowUps || !got.Sound || !got.QuietHours || got.QuietStart != "21:30" || got.QuietEnd != "06:45" {
		t.Fatalf("saved notification preferences = %+v", got)
	}
	page := mustGet(t, client, server.URL+"/app/settings/notifications")
	body, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if !strings.Contains(string(body), `id="desktop-notification-settings"`) {
		t.Fatal("notification settings page lacks the desktop notification card")
	}
	display := mustGet(t, client, server.URL+"/app/settings/display")
	body, _ = io.ReadAll(display.Body)
	_ = display.Body.Close()
	if display.StatusCode != http.StatusOK || !strings.Contains(string(body), `id="user-display-settings"`) || !strings.Contains(string(body), `href="/app/settings/display">Display &amp; app</a>`) {
		t.Fatalf("display settings page status=%d", display.StatusCode)
	}
}

func TestInstallableAppFilesArePublic(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	for path, contentType := range map[string]string{
		"/app/manifest.webmanifest": "application/manifest+json",
		"/app/sw.js":                "text/javascript; charset=utf-8",
		"/app/offline":              "text/html; charset=utf-8",
	} {
		response, err := client.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != contentType || response.Header.Get("Cache-Control") != "no-cache" {
			t.Fatalf("%s without a session: status=%d headers=%v", path, response.StatusCode, response.Header)
		}
	}
}
