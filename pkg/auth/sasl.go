package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// SASL mechanism names for the password mechanisms PasswordExchange serves.
const (
	// SASLPlain is the SASL PLAIN mechanism (RFC 4616).
	SASLPlain = "PLAIN"
	// SASLLogin is the SASL LOGIN mechanism (draft-murchison-sasl-login).
	SASLLogin = "LOGIN"
)

// Errors reported by PasswordExchange. Protocols map them to their own
// response codes; none of them reveals anything about the account.
var (
	// ErrSASLCanceled reports that the client answered a challenge with "*".
	ErrSASLCanceled = errors.New("SASL exchange canceled by client")
	// ErrSASLEncoding reports a client response that is not valid base64.
	ErrSASLEncoding = errors.New("SASL response is not valid base64")
	// ErrSASLMalformed reports a decoded response that is not a well-formed
	// credential for the mechanism.
	ErrSASLMalformed = errors.New("malformed SASL credentials")
	// ErrSASLAuthzid reports a PLAIN authorization identity that differs from
	// the authentication identity. Veksel does not offer SASL proxy
	// authorization, so RFC 4616 requires the exchange to fail.
	ErrSASLAuthzid = errors.New("SASL authorization identity is not supported")
)

const (
	loginUsernameChallenge = "Username:"
	loginPasswordChallenge = "Password:"
)

// ParsePlain decodes an RFC 4616 PLAIN message:
//
//	message = [authzid] UTF8NUL authcid UTF8NUL passwd
//
// The authentication identity and password must be non-empty and free of NUL.
// A non-empty authorization identity is accepted only when it names the
// authentication identity (compared case-insensitively); anything else is
// ErrSASLAuthzid.
func ParsePlain(message []byte) (username, password string, err error) {
	parts := strings.Split(string(message), "\x00")
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return "", "", ErrSASLMalformed
	}
	if parts[0] != "" && !strings.EqualFold(parts[0], parts[1]) {
		return "", "", ErrSASLAuthzid
	}
	return parts[1], parts[2], nil
}

// PasswordExchange runs the server side of a SASL PLAIN or LOGIN exchange in
// the base64 wire encoding shared by IMAP, SMTP, POP3, and ManageSieve.
// Protocols own the framing (continuation prefixes and response codes); the
// exchange owns decoding, cancellation, and the mechanism state machine.
type PasswordExchange struct {
	mechanism string
	step      int
	username  string
	password  string
}

// NewPasswordExchange starts an exchange for mechanism (case-insensitive).
// It reports false for mechanisms other than PLAIN and LOGIN.
func NewPasswordExchange(mechanism string) (*PasswordExchange, bool) {
	mechanism = strings.ToUpper(mechanism)
	if mechanism != SASLPlain && mechanism != SASLLogin {
		return nil, false
	}
	return &PasswordExchange{mechanism: mechanism}, true
}

// Mechanism returns the upper-case mechanism name.
func (e *PasswordExchange) Mechanism() string { return e.mechanism }

// Start begins the exchange. initial is the client's initial response exactly
// as sent on the wire (RFC 4954, RFC 4959): "" when the client sent none and
// "=" for an empty response. It returns the base64-encoded challenge to send
// next, or done once credentials are available from Credentials.
func (e *PasswordExchange) Start(initial string) (challenge string, done bool, err error) {
	switch initial {
	case "":
		if e.mechanism == SASLLogin {
			return encodeChallenge(loginUsernameChallenge), false, nil
		}
		return "", false, nil
	case "=":
		return e.advance(nil)
	default:
		return e.Next(initial)
	}
}

// Next consumes one base64-encoded client response and returns the next
// challenge, or done once credentials are available from Credentials. A "*"
// response cancels the exchange with ErrSASLCanceled.
func (e *PasswordExchange) Next(response string) (challenge string, done bool, err error) {
	response = strings.TrimSpace(response)
	if response == "*" {
		return "", false, ErrSASLCanceled
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(response)
	if decodeErr != nil {
		return "", false, ErrSASLEncoding
	}
	return e.advance(decoded)
}

func (e *PasswordExchange) advance(decoded []byte) (string, bool, error) {
	switch {
	case e.mechanism == SASLPlain && e.step == 0:
		username, password, err := ParsePlain(decoded)
		if err != nil {
			return "", false, err
		}
		e.username, e.password, e.step = username, password, 2
		return "", true, nil
	case e.mechanism == SASLLogin && e.step < 2:
		if len(decoded) == 0 {
			return "", false, ErrSASLMalformed
		}
		if e.step == 0 {
			e.username, e.step = string(decoded), 1
			return encodeChallenge(loginPasswordChallenge), false, nil
		}
		e.password, e.step = string(decoded), 2
		return "", true, nil
	default:
		return "", false, ErrSASLMalformed
	}
}

// Credentials returns the authentication identity and password once the
// exchange is done.
func (e *PasswordExchange) Credentials() (username, password string) {
	return e.username, e.password
}

// RunPasswordExchange drives a complete PLAIN or LOGIN exchange for protocols
// that read client responses synchronously. prompt sends one base64-encoded
// challenge and returns the client's raw response line; its errors are
// returned unchanged so callers can tell connection failures from SASL
// errors.
func RunPasswordExchange(mechanism, initial string, prompt func(challenge string) (string, error)) (username, password string, err error) {
	exchange, ok := NewPasswordExchange(mechanism)
	if !ok {
		return "", "", fmt.Errorf("SASL mechanism %q is not a password mechanism", mechanism)
	}
	challenge, done, err := exchange.Start(initial)
	for err == nil && !done {
		var response string
		if response, err = prompt(challenge); err != nil {
			return "", "", err
		}
		challenge, done, err = exchange.Next(response)
	}
	if err != nil {
		return "", "", err
	}
	username, password = exchange.Credentials()
	return username, password, nil
}

func encodeChallenge(challenge string) string {
	return base64.StdEncoding.EncodeToString([]byte(challenge))
}

// AuthenticateXOAUTH2 validates a SASL XOAUTH2 response per RFC 7628.
// The response is base64-encoded and contains user=<email>\x01auth=Bearer <token>\x01\x01.
// The validator function receives (email, token) and returns a user ID on success.
func AuthenticateXOAUTH2(response []byte, validator func(email, token string) (string, error)) (string, error) {
	email, token, err := ParseXOAUTH2Response(response)
	if err != nil {
		return "", fmt.Errorf("XOAUTH2 parse error: %w", err)
	}
	userID, err := validator(email, token)
	if err != nil {
		return "", fmt.Errorf("XOAUTH2 validation failed: %w", err)
	}
	return userID, nil
}
