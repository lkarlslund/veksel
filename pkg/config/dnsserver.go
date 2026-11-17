package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// DNSServerTSIG is a parsed dns_server_axfr_tsig key.
type DNSServerTSIG struct {
	Algorithm string // hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, or hmac-sha512
	Name      string // key name, lower case without the trailing dot
	Secret    string // base64
}

var dnsTSIGAlgorithms = map[string]bool{"hmac-sha1": true, "hmac-sha224": true, "hmac-sha256": true, "hmac-sha384": true, "hmac-sha512": true}

// maxDNSNameservers bounds dns_server_nameservers.
const maxDNSNameservers = 13

// ParseDNSServerTSIG parses the zone transfer key in dig -y form,
// [algorithm:]name:base64-secret, with hmac-sha256 as the default
// algorithm. An empty value disables zone transfers and returns nil.
func ParseDNSServerTSIG(value string) (*DNSServerTSIG, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ":")
	if len(parts) == 2 {
		parts = append([]string{"hmac-sha256"}, parts...)
	}
	if len(parts) != 3 {
		return nil, errors.New("dns_server_axfr_tsig must be [algorithm:]name:base64-secret")
	}
	algorithm := strings.ToLower(strings.TrimSuffix(parts[0], "."))
	if !dnsTSIGAlgorithms[algorithm] {
		return nil, fmt.Errorf("dns_server_axfr_tsig: unsupported algorithm %q", parts[0])
	}
	name := strings.ToLower(strings.TrimSuffix(parts[1], "."))
	if !validDNSName(name) {
		return nil, fmt.Errorf("dns_server_axfr_tsig: invalid key name %q", parts[1])
	}
	if secret, err := base64.StdEncoding.DecodeString(parts[2]); err != nil || len(secret) < 16 {
		return nil, errors.New("dns_server_axfr_tsig: the secret must be base64 of at least 16 bytes")
	}
	return &DNSServerTSIG{Algorithm: algorithm, Name: name, Secret: parts[2]}, nil
}

// validDNSName reports whether name is a host name of letters, digits,
// hyphens, and underscores in labels of at most 63 characters.
func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// validateDNSServer checks the built-in DNS server settings.
func validateDNSServer(cfg *Config) error {
	if err := validateAddress(cfg.DNSServerListen); err != nil {
		return fmt.Errorf("dns_server_listen: %w", err)
	}
	if len(cfg.DNSServerNameservers) > maxDNSNameservers {
		return fmt.Errorf("dns_server_nameservers lists at most %d names", maxDNSNameservers)
	}
	for _, name := range cfg.DNSServerNameservers {
		if name = strings.TrimSuffix(strings.TrimSpace(name), "."); !validDNSName(name) || !strings.Contains(name, ".") {
			return fmt.Errorf("dns_server_nameservers: %q is not a fully qualified host name", name)
		}
	}
	_, err := ParseDNSServerTSIG(cfg.DNSServerAXFRTSIG)
	return err
}
