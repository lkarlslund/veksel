package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestValidateOAuth2TokenValid(t *testing.T) {
	t.Parallel()
	expiresAt := time.Now().Add(time.Hour)
	err := ValidateOAuth2Token(expiresAt)
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestValidateOAuth2TokenExpired(t *testing.T) {
	t.Parallel()
	expiresAt := time.Now().Add(-time.Hour)
	err := ValidateOAuth2Token(expiresAt)
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestValidateOAuth2TokenJustExpired(t *testing.T) {
	t.Parallel()
	expiresAt := time.Now().Add(-time.Second)
	err := ValidateOAuth2Token(expiresAt)
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestBuildXOAUTH2Response(t *testing.T) {
	t.Parallel()
	email := "user@example.com"
	token := "ya29.test_token"

	response := BuildXOAUTH2Response(email, token)

	// Decode and verify the structure
	decoded, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		t.Fatalf("failed to decode XOAUTH2 response: %v", err)
	}

	expected := "user=" + email + "\x01auth=Bearer " + token + "\x01\x01"
	if string(decoded) != expected {
		t.Errorf("XOAUTH2 response = %q, want %q", string(decoded), expected)
	}
}

func TestParseXOAUTH2Response(t *testing.T) {
	t.Parallel()
	email := "user@example.com"
	token := "ya29.test_token"

	response := BuildXOAUTH2Response(email, token)
	parsedEmail, parsedToken, err := ParseXOAUTH2Response([]byte(response))
	if err != nil {
		t.Fatalf("ParseXOAUTH2Response returned error: %v", err)
	}
	if parsedEmail != email {
		t.Errorf("email = %q, want %q", parsedEmail, email)
	}
	if parsedToken != token {
		t.Errorf("token = %q, want %q", parsedToken, token)
	}
}

func TestParseXOAUTH2ResponseInvalidBase64(t *testing.T) {
	t.Parallel()
	_, _, err := ParseXOAUTH2Response([]byte("not-valid-base64!!!"))
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

func TestParseXOAUTH2ResponseMissingUser(t *testing.T) {
	t.Parallel()
	// Only auth field, no user
	raw := "auth=Bearer token\x01\x01"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	_, _, err := ParseXOAUTH2Response([]byte(encoded))
	if err == nil {
		t.Error("expected error for missing user field, got nil")
	}
}

func TestParseXOAUTH2ResponseMissingAuth(t *testing.T) {
	t.Parallel()
	// Only user field, no auth
	raw := "user=test@example.com\x01\x01"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	_, _, err := ParseXOAUTH2Response([]byte(encoded))
	if err == nil {
		t.Error("expected error for missing auth field, got nil")
	}
}

func TestAuthenticateXOAUTH2Success(t *testing.T) {
	t.Parallel()
	email := "user@example.com"
	token := "ya29.test_token"
	response := BuildXOAUTH2Response(email, token)

	var validatedEmail, validatedToken string
	validator := func(e, tok string) (string, error) {
		validatedEmail = e
		validatedToken = tok
		return "user123", nil
	}

	userID, err := AuthenticateXOAUTH2([]byte(response), validator)
	if err != nil {
		t.Fatalf("AuthenticateXOAUTH2 returned error: %v", err)
	}
	if userID != "user123" {
		t.Errorf("userID = %q, want %q", userID, "user123")
	}
	if validatedEmail != email {
		t.Errorf("validatedEmail = %q, want %q", validatedEmail, email)
	}
	if validatedToken != token {
		t.Errorf("validatedToken = %q, want %q", validatedToken, token)
	}
}

func TestAuthenticateXOAUTH2ValidatorFailure(t *testing.T) {
	t.Parallel()
	email := "user@example.com"
	token := "ya29.test_token"
	response := BuildXOAUTH2Response(email, token)

	validator := func(e, tok string) (string, error) {
		return "", ErrInvalidPassword
	}

	_, err := AuthenticateXOAUTH2([]byte(response), validator)
	if err == nil {
		t.Error("expected error for failed validation, got nil")
	}
	if !strings.Contains(err.Error(), "XOAUTH2 validation failed") {
		t.Errorf("expected XOAUTH2 validation failed error, got %v", err)
	}
}

func TestAuthenticateXOAUTH2InvalidResponse(t *testing.T) {
	t.Parallel()
	validator := func(e, tok string) (string, error) {
		return "user123", nil
	}

	_, err := AuthenticateXOAUTH2([]byte("invalid"), validator)
	if err == nil {
		t.Error("expected error for invalid response, got nil")
	}
}
