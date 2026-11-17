package main

import (
	"net"
	"net/url"
	"os"
	"slices"

	"github.com/lkarlslund/veksel/pkg/config"
)

// setupURL returns the first-owner setup link on the first enabled listener
// that serves the web application. A wildcard bind address is replaced by
// the machine host name so the logged link can be opened from elsewhere.
func setupURL(listeners []config.HTTPListener, token string) string {
	path := "/app/setup?token=" + url.QueryEscape(token)
	for _, listener := range listeners {
		if !listener.Enabled || !slices.Contains(listener.Services, "web") {
			continue
		}
		host, port, err := net.SplitHostPort(listener.Address)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); host == "" || ip != nil && ip.IsUnspecified() {
			host = "localhost"
			if name, err := os.Hostname(); err == nil && name != "" {
				host = name
			}
		}
		return listener.Transport + "://" + net.JoinHostPort(host, port) + path
	}
	return path
}
