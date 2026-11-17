package config

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// validateLDAP checks directory settings whenever they are set, and requires
// a usable connection description once ldap_enabled is on.
func validateLDAP(cfg *Config) error {
	if cfg.LdapTimeoutSeconds < 1 || cfg.LdapTimeoutSeconds > 300 {
		return errors.New("ldap_timeout_seconds must be between 1 and 300")
	}
	if cfg.LdapSyncIntervalMinutes < 0 || cfg.LdapSyncIntervalMinutes > 10080 {
		return errors.New("ldap_sync_interval_minutes must be between 0 and 10080")
	}
	switch cfg.LdapAdminRole {
	case "", "owner", "admin":
	default:
		return errors.New("ldap_admin_role must be owner or admin")
	}
	for _, raw := range cfg.LdapURLs {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (parsed.Scheme != "ldap" && parsed.Scheme != "ldaps") || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") {
			return fmt.Errorf("ldap_urls entry %q must be ldap://host[:port] or ldaps://host[:port]", raw)
		}
	}
	if pem := strings.TrimSpace(cfg.LdapCACertificate); pem != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(pem)) {
		return errors.New("ldap_ca_certificate must contain at least one PEM certificate")
	}
	for key, dn := range map[string]string{"ldap_bind_dn": cfg.LdapBindDN, "ldap_base_dn": cfg.LdapBaseDN, "ldap_admin_group_dn": cfg.LdapAdminGroupDN} {
		if strings.TrimSpace(dn) == "" {
			continue
		}
		if _, err := ldap.ParseDN(dn); err != nil {
			return fmt.Errorf("%s is not a valid DN: %w", key, err)
		}
	}
	if !strings.Contains(cfg.LdapUserFilter, "{login}") {
		return errors.New("ldap_user_filter must contain the {login} placeholder")
	}
	if _, err := ldap.CompileFilter(strings.ReplaceAll(cfg.LdapUserFilter, "{login}", "x")); err != nil {
		return fmt.Errorf("ldap_user_filter: %w", err)
	}
	if _, err := ldap.CompileFilter(cfg.LdapSyncFilter); err != nil {
		return fmt.Errorf("ldap_sync_filter: %w", err)
	}
	for _, attribute := range cfg.LdapIDAttributes {
		if strings.TrimSpace(attribute) == "" || strings.ContainsAny(attribute, "()=*\\ ") {
			return fmt.Errorf("ldap_id_attributes entry %q is not an attribute name", attribute)
		}
	}
	if !cfg.LdapEnabled {
		return nil
	}
	if len(cfg.LdapURLs) == 0 {
		return errors.New("ldap_urls must name at least one directory server when ldap_enabled is on")
	}
	if strings.TrimSpace(cfg.LdapBaseDN) == "" {
		return errors.New("ldap_base_dn is required when ldap_enabled is on")
	}
	if len(cfg.LdapIDAttributes) == 0 {
		return errors.New("ldap_id_attributes must name at least one attribute when ldap_enabled is on")
	}
	return nil
}
