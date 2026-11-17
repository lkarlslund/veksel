package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ParseResolverAddresses parses the entries of the DNS resolver list setting
// key into host:port form. Each entry is an IP address, optionally with a
// port ("127.0.0.1", "127.0.0.53:53", "[::1]:5353"); the port defaults to
// 53.
func ParseResolverAddresses(key string, values []string) ([]string, error) {
	addresses := make([]string, 0, len(values))
	for _, value := range values {
		entry := strings.TrimSpace(value)
		if addr, err := netip.ParseAddr(entry); err == nil && addr.Zone() == "" {
			addresses = append(addresses, net.JoinHostPort(addr.Unmap().String(), "53"))
			continue
		}
		addrPort, err := netip.ParseAddrPort(entry)
		if err != nil || addrPort.Addr().Zone() != "" || addrPort.Port() == 0 {
			return nil, fmt.Errorf("%s: invalid resolver address %q", key, value)
		}
		addresses = append(addresses, net.JoinHostPort(addrPort.Addr().Unmap().String(), strconv.Itoa(int(addrPort.Port()))))
	}
	return addresses, nil
}
