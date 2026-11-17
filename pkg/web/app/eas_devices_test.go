package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
)

type recordingEASDeviceInventory struct {
	devices      map[string][]EASDevice
	listedUser   string
	removedUser  string
	removedID    string
	removeResult bool
	wipedID      string
}

func (inventory *recordingEASDeviceInventory) ListEASDevices(_ context.Context, userID string) ([]EASDevice, error) {
	inventory.listedUser = userID
	return append([]EASDevice(nil), inventory.devices[userID]...), nil
}

func (inventory *recordingEASDeviceInventory) WipeEASDevice(_ context.Context, userID, deviceID string) (bool, error) {
	for _, device := range inventory.devices[userID] {
		if device.ID == deviceID {
			inventory.wipedID = deviceID
			return true, nil
		}
	}
	return false, nil
}

func (inventory *recordingEASDeviceInventory) RemoveEASDevice(_ context.Context, userID, deviceID string) (bool, error) {
	inventory.removedUser, inventory.removedID = userID, deviceID
	return inventory.removeResult, nil
}

func TestEASDeviceInventoryUnavailableContractAndSettingsPage(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")

	response, err := client.Get(server.URL + "/api/v1/user/eas-devices")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var listing struct {
		Available bool        `json:"available"`
		Devices   []EASDevice `json:"devices"`
	}
	if err := json.NewDecoder(response.Body).Decode(&listing); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || listing.Available || listing.Devices == nil || len(listing.Devices) != 0 {
		t.Fatalf("unavailable listing = %#v, status %d", listing, response.StatusCode)
	}

	page, err := client.Get(server.URL + "/app/settings/devices")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(page.Body)
	page.Body.Close()
	markup := string(body)
	if page.StatusCode != http.StatusOK || !strings.Contains(markup, `id="user-device-settings"`) || !strings.Contains(markup, `aria-current="page" href="/app/settings/devices"`) || !strings.Contains(markup, "Connected devices") {
		t.Fatalf("device settings status=%d body=%s", page.StatusCode, body)
	}
}

func TestEASDeviceInventoryIsAccountScopedCSRFProtectedAndAudited(t *testing.T) {
	handler, typed := testHandler(t)
	now := time.Now().UTC().Truncate(time.Second)
	inventory := &recordingEASDeviceInventory{
		devices: map[string][]EASDevice{
			"alice": {{ID: "PHONE123", FriendlyName: "Alice phone", Protocol: "16.1", LastSeenAt: now}},
			"bob":   {{ID: "SECRET999", FriendlyName: "Bob phone", Protocol: "16.1", LastSeenAt: now}},
		},
		removeResult: true,
	}
	handler.ConfigureEASDeviceInventory(inventory)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	response, err := client.Get(server.URL + "/api/v1/user/eas-devices?user_id=bob")
	if err != nil {
		t.Fatal(err)
	}
	var listing struct {
		Available bool        `json:"available"`
		Devices   []EASDevice `json:"devices"`
	}
	if err := json.NewDecoder(response.Body).Decode(&listing); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if !listing.Available || inventory.listedUser != "alice" || len(listing.Devices) != 1 || listing.Devices[0].ID != "PHONE123" {
		t.Fatalf("scoped listing = %#v, requested user %q", listing, inventory.listedUser)
	}

	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/user/eas-devices/PHONE123", "", "")
	if response.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("delete without CSRF status = %d", response.StatusCode)
	}
	response.Body.Close()
	if inventory.removedID != "" {
		t.Fatalf("inventory mutated without CSRF: %q", inventory.removedID)
	}

	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/user/eas-devices/not-valid!", csrf, "")
	if response.StatusCode != http.StatusBadRequest {
		response.Body.Close()
		t.Fatalf("invalid ID status = %d", response.StatusCode)
	}
	response.Body.Close()

	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/user/eas-devices/phone123", csrf, "")
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("delete status = %d", response.StatusCode)
	}
	response.Body.Close()
	if inventory.removedUser != "alice" || inventory.removedID != "PHONE123" {
		t.Fatalf("removed %q/%q", inventory.removedUser, inventory.removedID)
	}
	entries, err := audit.New(typed).Query(t.Context(), time.Time{}, "eas.device.remove", "alice", 10)
	if err != nil || len(entries) != 1 || entries[0].Target != "PHONE123" || entries[0].Details["removed"] != "true" {
		t.Fatalf("audit entries = %#v, %v", entries, err)
	}
}

func TestEASDeviceWipeIsAccountScopedAndAudited(t *testing.T) {
	handler, typed := testHandler(t)
	inventory := &recordingEASDeviceInventory{devices: map[string][]EASDevice{
		"alice": {{ID: "PHONE123", FriendlyName: "Alice phone"}},
		"bob":   {{ID: "SECRET999", FriendlyName: "Bob phone"}},
	}}
	handler.ConfigureEASDeviceInventory(inventory)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/eas-devices/SECRET999/wipe", csrf, "")
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound || inventory.wipedID != "" {
		t.Fatalf("wipe of another account's device status = %d wiped %q", response.StatusCode, inventory.wipedID)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/eas-devices/PHONE123/wipe", "", "")
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || inventory.wipedID != "" {
		t.Fatalf("wipe without CSRF status = %d", response.StatusCode)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/eas-devices/phone123/wipe", csrf, "")
	response.Body.Close()
	if response.StatusCode != http.StatusOK || inventory.wipedID != "PHONE123" {
		t.Fatalf("wipe status = %d wiped %q", response.StatusCode, inventory.wipedID)
	}
	entries, err := audit.New(typed).Query(t.Context(), time.Time{}, "eas.device.wipe", "alice", 10)
	if err != nil || len(entries) != 1 || entries[0].Target != "PHONE123" {
		t.Fatalf("audit entries = %#v, %v", entries, err)
	}
}
