package migration

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// NormalizeHTTPEndpoint turns a host or URL into an unambiguous HTTP endpoint.
// An explicit URL scheme must agree with transportMode. When no service path is
// supplied, defaultPath is appended.
func NormalizeHTTPEndpoint(endpoint, transportMode, defaultPath string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", errors.New("server endpoint is required")
	}

	mode := strings.ToLower(strings.TrimSpace(transportMode))
	if mode == "" {
		mode = "https"
	}
	if mode != "https" && mode != "http" {
		return "", fmt.Errorf("HTTP transport must be https or http, got %q", transportMode)
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = mode + "://" + endpoint
	}

	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return "", errors.New("server endpoint must contain a valid hostname")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("unsupported endpoint scheme %q", parsed.Scheme)
	}
	if parsed.Scheme != mode {
		return "", fmt.Errorf("endpoint uses %s but HTTP transport is set to %s", parsed.Scheme, mode)
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/" + strings.Trim(strings.TrimSpace(defaultPath), "/")
	}
	return parsed.String(), nil
}
