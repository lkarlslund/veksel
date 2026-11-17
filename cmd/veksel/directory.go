package main

import (
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/directory"
	"github.com/lkarlslund/veksel/pkg/log"
)

// ldapSettingKeys are the settings owned by the directory service.
var ldapSettingKeys = []string{
	"ldap_enabled", "ldap_urls", "ldap_allow_plaintext", "ldap_ca_certificate", "ldap_bind_dn", "ldap_bind_password", "ldap_base_dn",
	"ldap_user_filter", "ldap_id_attributes", "ldap_admin_group_dn", "ldap_admin_role", "ldap_sync_filter", "ldap_sync_interval_minutes", "ldap_timeout_seconds",
}

// startDirectory connects LDAP directory accounts to the shared password
// check, registers their settings as live, and starts scheduled sync. A
// directory that cannot be configured leaves only local accounts working.
func (s *server) startDirectory() error {
	service := directory.New(s.ts, account.Provisioner{TS: s.ts, Manager: s.accountManager}, nil)
	if err := service.Configure(directorySettings(s.cfg)); err != nil {
		log.Error("configure directory accounts", "error", err)
	}
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		return service.Configure(directorySettings(cfg))
	}, ldapSettingKeys...); err != nil {
		return err
	}
	s.protocolAuth.SetDirectory(service)
	s.cleanup.push(service.Close)
	s.cleanup.push(service.Start(s.ctx))
	s.directory = service
	return nil
}

func directorySettings(cfg *config.Config) directory.Settings {
	return directory.Settings{
		Enabled: cfg.LdapEnabled, URLs: cfg.LdapURLs, AllowPlaintext: cfg.LdapAllowPlaintext, CACertificate: cfg.LdapCACertificate,
		BindDN: cfg.LdapBindDN, BindPassword: cfg.LdapBindPassword, BaseDN: cfg.LdapBaseDN,
		UserFilter: cfg.LdapUserFilter, IDAttributes: cfg.LdapIDAttributes, AdminGroupDN: cfg.LdapAdminGroupDN, AdminRole: cfg.LdapAdminRole, SyncFilter: cfg.LdapSyncFilter,
		SyncInterval: time.Duration(cfg.LdapSyncIntervalMinutes) * time.Minute, Timeout: time.Duration(cfg.LdapTimeoutSeconds) * time.Second,
	}
}
