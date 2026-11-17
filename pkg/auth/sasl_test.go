package auth

import (
	"encoding/base64"
	"errors"
	"testing"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParsePlain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, message, user, pass string
		err                       error
	}{
		{name: "empty authzid", message: "\x00alice\x00secret", user: "alice", pass: "secret"},
		{name: "equal authzid", message: "alice\x00alice\x00secret", user: "alice", pass: "secret"},
		{name: "equal authzid case-insensitive", message: "Alice@Example.com\x00alice@example.com\x00secret", user: "alice@example.com", pass: "secret"},
		{name: "different authzid", message: "bob\x00alice\x00secret", err: ErrSASLAuthzid},
		{name: "missing NUL", message: "alice\x00secret", err: ErrSASLMalformed},
		{name: "no NUL", message: "alicesecret", err: ErrSASLMalformed},
		{name: "extra NUL in password", message: "\x00alice\x00sec\x00ret", err: ErrSASLMalformed},
		{name: "empty authcid", message: "\x00\x00secret", err: ErrSASLMalformed},
		{name: "empty password", message: "\x00alice\x00", err: ErrSASLMalformed},
		{name: "empty message", message: "", err: ErrSASLMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			user, pass, err := ParsePlain([]byte(tt.message))
			if !errors.Is(err, tt.err) {
				t.Fatalf("err = %v, want %v", err, tt.err)
			}
			if user != tt.user || pass != tt.pass {
				t.Fatalf("credentials = %q/%q, want %q/%q", user, pass, tt.user, tt.pass)
			}
		})
	}
}

// run feeds responses to a fresh exchange and records the challenges sent.
func run(t *testing.T, mechanism, initial string, responses ...string) (challenges []string, user, pass string, err error) {
	t.Helper()
	user, pass, err = RunPasswordExchange(mechanism, initial, func(challenge string) (string, error) {
		challenges = append(challenges, challenge)
		if len(responses) == 0 {
			t.Fatalf("unexpected challenge %q", challenge)
		}
		response := responses[0]
		responses = responses[1:]
		return response, nil
	})
	return challenges, user, pass, err
}

func TestPasswordExchangePlain(t *testing.T) {
	t.Parallel()
	challenges, user, pass, err := run(t, "plain", "", b64("\x00alice\x00secret"))
	if err != nil || user != "alice" || pass != "secret" {
		t.Fatalf("challenge-response PLAIN = %q/%q, %v", user, pass, err)
	}
	if len(challenges) != 1 || challenges[0] != "" {
		t.Fatalf("PLAIN challenges = %q, want one empty challenge", challenges)
	}

	challenges, user, pass, err = run(t, "PLAIN", b64("alice\x00alice\x00secret"))
	if err != nil || user != "alice" || pass != "secret" || len(challenges) != 0 {
		t.Fatalf("SASL-IR PLAIN = %q/%q, %v, challenges %q", user, pass, err, challenges)
	}
}

func TestPasswordExchangePlainFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, initial, response string
		err                     error
	}{
		{name: "bad base64 initial", initial: "!!!", err: ErrSASLEncoding},
		{name: "bad base64 response", response: "not base64!", err: ErrSASLEncoding},
		{name: "empty initial response", initial: "=", err: ErrSASLMalformed},
		{name: "missing NULs", initial: b64("alice"), err: ErrSASLMalformed},
		{name: "authzid differs", initial: b64("bob\x00alice\x00secret"), err: ErrSASLAuthzid},
		{name: "canceled", response: "*", err: ErrSASLCanceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var responses []string
			if tt.response != "" {
				responses = append(responses, tt.response)
			}
			_, user, _, err := run(t, SASLPlain, tt.initial, responses...)
			if !errors.Is(err, tt.err) || user != "" {
				t.Fatalf("err = %v user = %q, want %v", err, user, tt.err)
			}
		})
	}
}

func TestPasswordExchangeLogin(t *testing.T) {
	t.Parallel()
	challenges, user, pass, err := run(t, SASLLogin, "", b64("alice"), b64("secret")+"\r\n")
	if err != nil || user != "alice" || pass != "secret" {
		t.Fatalf("LOGIN = %q/%q, %v", user, pass, err)
	}
	if len(challenges) != 2 || challenges[0] != b64("Username:") || challenges[1] != b64("Password:") {
		t.Fatalf("LOGIN challenges = %q", challenges)
	}

	challenges, user, pass, err = run(t, SASLLogin, b64("bob"), b64("pw"))
	if err != nil || user != "bob" || pass != "pw" {
		t.Fatalf("LOGIN with initial response = %q/%q, %v", user, pass, err)
	}
	if len(challenges) != 1 || challenges[0] != b64("Password:") {
		t.Fatalf("LOGIN initial-response challenges = %q", challenges)
	}
}

func TestPasswordExchangeLoginFailures(t *testing.T) {
	t.Parallel()
	if _, _, _, err := run(t, SASLLogin, "", ""); !errors.Is(err, ErrSASLMalformed) {
		t.Fatalf("empty username err = %v", err)
	}
	if _, _, _, err := run(t, SASLLogin, "", b64("alice"), ""); !errors.Is(err, ErrSASLMalformed) {
		t.Fatalf("empty password err = %v", err)
	}
	if _, _, _, err := run(t, SASLLogin, "", b64("alice"), "*"); !errors.Is(err, ErrSASLCanceled) {
		t.Fatalf("canceled err = %v", err)
	}
	if _, _, _, err := run(t, SASLLogin, "", "%%%"); !errors.Is(err, ErrSASLEncoding) {
		t.Fatalf("bad base64 err = %v", err)
	}
}

func TestPasswordExchangeStepwise(t *testing.T) {
	t.Parallel()
	exchange, ok := NewPasswordExchange("login")
	if !ok || exchange.Mechanism() != SASLLogin {
		t.Fatalf("NewPasswordExchange(login) = %v, %v", exchange, ok)
	}
	if challenge, done, err := exchange.Start(""); err != nil || done || challenge != b64("Username:") {
		t.Fatalf("Start = %q, %v, %v", challenge, done, err)
	}
	if _, done, err := exchange.Next(b64("alice")); err != nil || done {
		t.Fatalf("Next(username) done=%v err=%v", done, err)
	}
	if _, done, err := exchange.Next(b64("secret")); err != nil || !done {
		t.Fatalf("Next(password) done=%v err=%v", done, err)
	}
	if user, pass := exchange.Credentials(); user != "alice" || pass != "secret" {
		t.Fatalf("Credentials = %q/%q", user, pass)
	}
	if _, _, err := exchange.Next(b64("extra")); !errors.Is(err, ErrSASLMalformed) {
		t.Fatalf("response after completion err = %v", err)
	}
}

func TestPasswordExchangeRejectsOtherMechanisms(t *testing.T) {
	t.Parallel()
	if _, ok := NewPasswordExchange("XOAUTH2"); ok {
		t.Fatal("XOAUTH2 must not be a password exchange")
	}
	promptErr := errors.New("connection closed")
	_, _, err := RunPasswordExchange(SASLPlain, "", func(string) (string, error) { return "", promptErr })
	if !errors.Is(err, promptErr) {
		t.Fatalf("prompt error = %v, want %v", err, promptErr)
	}
}
