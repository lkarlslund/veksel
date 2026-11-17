package main

import (
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
)

func TestDirectorySettingsApplyLiveAndLocalAccountsSurviveOutage(t *testing.T) {
	s := liveAddressingServer(t)
	s.protocolAuth = protocolauth.New(s.ts)
	if err := s.startDirectory(); err != nil {
		t.Fatal(err)
	}
	status, err := s.directory.Status(s.ctx)
	if err != nil || status.Enabled || status.Connected {
		t.Fatalf("default directory status = %+v, %v", status, err)
	}
	// An unreachable directory: nothing listens on port 1.
	patchAndApply(t, s, map[string]any{"ldap_enabled": true, "ldap_urls": []string{"ldap://127.0.0.1:1"}, "ldap_base_dn": "dc=example,dc=test", "ldap_sync_interval_minutes": 0})
	if state := applyState(t, s, "ldap_enabled"); state.State != config.ApplyEffective {
		t.Fatalf("ldap_enabled apply state = %+v", state)
	}
	if status, _ = s.directory.Status(s.ctx); !status.Enabled || !status.Connected || len(status.Servers) != 1 || status.SyncIntervalMinutes != 0 {
		t.Fatalf("enabled directory status = %+v", status)
	}
	if result, err := s.protocolAuth.Authenticate(s.ctx, "alice", "password123", model.AppProtocolIMAP); err != nil || result.User.ID != "alice" {
		t.Fatalf("local account during directory outage = %+v, %v", result, err)
	}
	if _, err := s.protocolAuth.Authenticate(s.ctx, "zed", "password123", model.AppProtocolIMAP); !errors.Is(err, protocolauth.ErrInvalidCredentials) {
		t.Fatalf("unknown login during directory outage = %v", err)
	}
	patchAndApply(t, s, map[string]any{"ldap_enabled": false})
	if status, _ = s.directory.Status(s.ctx); status.Enabled || status.Connected {
		t.Fatalf("disabled directory status = %+v", status)
	}
	if _, err := s.cfgService.Patch(s.cfgService.Current().Revision, map[string]any{"ldap_enabled": true, "ldap_urls": []string{"http://dc.example.test"}}); err == nil {
		t.Fatal("a non-LDAP server URL was accepted")
	}
}
