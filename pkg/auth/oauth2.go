// Package auth provides OAuth 2.0 token validation and XOAUTH2 helpers.
package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrTokenExpired is returned when an OAuth2 access token has expired.
var ErrTokenExpired = errors.New("OAuth2 token expired")

// ValidateOAuth2Token checks whether the token is still valid based on its expiry time.
// Returns ErrTokenExpired if the token has expired.
func ValidateOAuth2Token(expiresAt time.Time) error {
	if time.Now().After(expiresAt) {
		return ErrTokenExpired
	}
	return nil
}

// BuildXOAUTH2Response builds the SASL XOAUTH2 initial response per RFC 7628.
//
// The response is the base64 encoding of:
//
//	user=<email>\x01auth=Bearer <token>\x01\x01
//
// The email is the user's email address and token is the OAuth2 access token.
func BuildXOAUTH2Response(email, token string) string {
	raw := fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", email, token)
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

// ParseXOAUTH2Response parses a base64-encoded XOAUTH2 response and extracts
// the user email and bearer token.
func ParseXOAUTH2Response(response []byte) (email, token string, err error) {
	raw, err := base64.StdEncoding.DecodeString(string(response))
	if err != nil {
		return "", "", fmt.Errorf("invalid base64: %w", err)
	}

	// Parse key=value pairs separated by \x01
	parts := strings.Split(string(raw), "\x01")
	for _, part := range parts {
		if strings.HasPrefix(part, "user=") {
			email = strings.TrimPrefix(part, "user=")
		} else if strings.HasPrefix(part, "auth=Bearer ") {
			token = strings.TrimPrefix(part, "auth=Bearer ")
		}
	}

	if email == "" {
		return "", "", errors.New("missing user field in XOAUTH2 response")
	}
	if token == "" {
		return "", "", errors.New("missing auth field in XOAUTH2 response")
	}

	return email, token, nil
}
