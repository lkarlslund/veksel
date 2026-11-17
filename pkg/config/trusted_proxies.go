package config

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// MailProxyProtocolTargets are the mail_proxy_protocol entries: a protocol
// name selects all of its listeners, the others select one listener.
var MailProxyProtocolTargets = map[string][]string{
	"smtp":        {"smtp-relay", "submission", "smtps"},
	"imap":        {"imap-starttls", "imaps"},
	"pop3":        {"pop3-starttls", "pop3s"},
	"managesieve": {"managesieve-starttls", "managesieve-tls"},
}

// MailProxyProtocolEnabled reports whether the mail_proxy_protocol entries
// select the listener of protocol, named as in MailProxyProtocolTargets.
func MailProxyProtocolEnabled(entries []string, protocol, listener string) bool {
	return slices.ContainsFunc(entries, func(entry string) bool {
		entry = strings.ToLower(strings.TrimSpace(entry))
		return entry == protocol || entry == listener
	})
}

// validateMailProxyProtocol checks the mail_proxy_protocol entries and that
// a trusted proxy is configured whenever one is enabled.
func validateMailProxyProtocol(cfg *Config) error {
	for _, value := range cfg.MailProxyProtocol {
		entry := strings.ToLower(strings.TrimSpace(value))
		known := false
		for protocol, listeners := range MailProxyProtocolTargets {
			known = known || entry == protocol || slices.Contains(listeners, entry)
		}
		if !known {
			return fmt.Errorf("mail_proxy_protocol: unknown protocol or listener %q", value)
		}
	}
	if _, err := ParseAddressPrefixes("mail_proxy_protocol_trusted", cfg.MailProxyProtocolTrusted); err != nil {
		return err
	}
	if len(cfg.MailProxyProtocol) > 0 && len(cfg.MailProxyProtocolTrusted) == 0 {
		return errors.New("mail_proxy_protocol_trusted must list the proxies that send PROXY headers")
	}
	return nil
}

// Forwarding header families for http_forwarded_header.
const (
	ForwardedHeaderX       = "x-forwarded"
	ForwardedHeaderRFC7239 = "forwarded"
)

// ValidForwardedHeader reports whether value names a forwarding header
// family; empty selects the default, ForwardedHeaderX.
func ValidForwardedHeader(value string) bool {
	switch value {
	case "", ForwardedHeaderX, ForwardedHeaderRFC7239:
		return true
	}
	return false
}

// ParseTrustedProxies parses http_trusted_proxies entries; see
// ParseAddressPrefixes.
func ParseTrustedProxies(values []string) ([]netip.Prefix, error) {
	return ParseAddressPrefixes("http_trusted_proxies", values)
}

// ParseAddressPrefixes parses the entries of the address list setting key.
// Each entry is an IP address, which matches exactly that host, or a CIDR
// prefix. IPv4-mapped IPv6 forms are normalised to IPv4 so they match peers
// either way.
func ParseAddressPrefixes(key string, values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		entry := strings.TrimSpace(value)
		if !strings.Contains(entry, "/") {
			addr, err := netip.ParseAddr(entry)
			if err != nil || addr.Zone() != "" {
				return nil, fmt.Errorf("%s: invalid IP address %q", key, value)
			}
			addr = addr.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid CIDR %q", key, value)
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

// Destination is a permitted network destination: a prefix and, unless
// Port is zero, one port.
type Destination struct {
	Prefix netip.Prefix
	Port   uint16
}

// Allows reports whether address is within the destination.
func (d Destination) Allows(address netip.AddrPort) bool {
	return d.Prefix.Contains(address.Addr().Unmap()) && (d.Port == 0 || d.Port == address.Port())
}

// ParseDestinations parses entries such as "10.0.0.5:7090",
// "[fd00::5]:443", "10.0.0.5", "10.0.0.0/24" or "10.0.0.0/24:443".
func ParseDestinations(key string, values []string) ([]Destination, error) {
	destinations := make([]Destination, 0, len(values))
	for _, value := range values {
		entry := strings.TrimSpace(value)
		var port uint16
		host := entry
		if strings.HasPrefix(entry, "[") {
			end := strings.Index(entry, "]")
			if end < 0 {
				return nil, fmt.Errorf("%s: invalid destination %q", key, value)
			}
			host = entry[1:end]
			if rest := entry[end+1:]; rest != "" {
				parsed, err := strconv.ParseUint(strings.TrimPrefix(rest, ":"), 10, 16)
				if !strings.HasPrefix(rest, ":") || err != nil || parsed == 0 {
					return nil, fmt.Errorf("%s: invalid port in %q", key, value)
				}
				port = uint16(parsed)
			}
		} else if strings.Count(entry, ":") == 1 {
			var portText string
			host, portText, _ = strings.Cut(entry, ":")
			parsed, err := strconv.ParseUint(portText, 10, 16)
			if err != nil || parsed == 0 {
				return nil, fmt.Errorf("%s: invalid port in %q", key, value)
			}
			port = uint16(parsed)
		}
		prefixes, err := ParseAddressPrefixes(key, []string{host})
		if err != nil {
			return nil, err
		}
		destinations = append(destinations, Destination{Prefix: prefixes[0], Port: port})
	}
	return destinations, nil
}
