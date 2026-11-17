package config

import (
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
)

func TestPatchRefusesSystemEngineSwitch(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	current := service.Current()
	other := store.BackendBadger
	if current.Config.StoreBackend == store.BackendBadger {
		other = store.BackendPebble
	}
	if _, err := service.Patch(current.Revision, map[string]any{"system_engine": string(other)}); err == nil || !strings.Contains(err.Error(), "veksel-store-migrate") {
		t.Fatalf("engine switch error = %v", err)
	}
	if service.Current().Config.StoreBackend != current.Config.StoreBackend || service.Current().Revision != current.Revision {
		t.Fatal("refused switch changed the configuration")
	}
	if _, err := service.Patch(current.Revision, map[string]any{"system_engine": string(current.Config.StoreBackend)}); err != nil {
		t.Fatalf("unchanged engine rejected: %v", err)
	}
}
