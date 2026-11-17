package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/netguard"
)

// Any signed-in user can create a sync job, so sources must not reach
// internal addresses unless an administrator listed them.
func TestSyncSourcesRefuseUnlistedPrivateAddresses(t *testing.T) {
	network := &syncNetwork{}
	if err := network.Set(nil); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(server.Close)

	if _, err := network.httpClient(&tls.Config{MinVersion: tls.VersionTLS12}, 0).Get(server.URL); !errors.Is(err, netguard.ErrForbiddenAddress) {
		t.Fatalf("HTTP source reached loopback: %v", err)
	}
	if _, _, err := network.pin(context.Background(), "127.0.0.1:993", &tls.Config{MinVersion: tls.VersionTLS12}); !errors.Is(err, netguard.ErrForbiddenAddress) {
		t.Fatalf("mail source pinned loopback: %v", err)
	}

	if err := network.Set([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	response, err := network.httpClient(&tls.Config{MinVersion: tls.VersionTLS12}, 0).Get(server.URL)
	if err != nil {
		t.Fatalf("allowlisted HTTP source refused: %v", err)
	}
	response.Body.Close()
	address, tlsConfig, err := network.pin(context.Background(), "localhost:993", &tls.Config{MinVersion: tls.VersionTLS12})
	if err != nil || tlsConfig.ServerName != "localhost" || (address != "127.0.0.1:993" && address != "[::1]:993") {
		t.Fatalf("pin = %q, %q, %v; want the loopback IP and the entered name for TLS", address, tlsConfig.ServerName, err)
	}
}

// The factories registered for sync jobs use the guarded network.
func TestSyncSourceFactoriesUseTheGuardedNetwork(t *testing.T) {
	if err := syncSourceNetwork.Set(nil); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"imap", "pop3"} {
		_, err := migrationSourceFactories()[kind](context.Background(), migration.SourceOptions{Endpoint: "127.0.0.1:1", Username: "u", Password: "p", TLSMode: "tls"})
		if !errors.Is(err, netguard.ErrForbiddenAddress) {
			t.Errorf("%s source dialled loopback: %v", kind, err)
		}
	}
}
