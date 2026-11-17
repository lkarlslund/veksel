package srs

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func testCodec(t *testing.T, secrets ...string) *Codec {
	t.Helper()
	if len(secrets) == 0 {
		secrets = []string{"0123456789abcdef-first"}
	}
	keys := make([][]byte, len(secrets))
	for i, secret := range secrets {
		keys[i] = []byte(secret)
	}
	codec, err := New(keys)
	if err != nil {
		t.Fatal(err)
	}
	codec.now = func() time.Time { return time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC) }
	return codec
}

func TestForwardReverseRoundTrip(t *testing.T) {
	codec := testCodec(t)
	rewritten, err := codec.Forward("Alice.Smith@origin.example", "fwd.example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rewritten, "SRS0=") || !strings.HasSuffix(rewritten, "=origin.example=Alice.Smith@fwd.example") {
		t.Fatalf("rewritten = %q", rewritten)
	}
	original, err := codec.Reverse(rewritten)
	if err != nil || original != "Alice.Smith@origin.example" {
		t.Fatalf("reverse = %q, %v", original, err)
	}
	// Local parts containing the separator survive the round trip.
	rewritten, _ = codec.Forward("a=b@origin.example", "fwd.example")
	if original, err := codec.Reverse(rewritten); err != nil || original != "a=b@origin.example" {
		t.Fatalf("reverse with separator = %q, %v", original, err)
	}
}

func TestReverseIsCaseInsensitive(t *testing.T) {
	codec := testCodec(t)
	rewritten, _ := codec.Forward("user@origin.example", "fwd.example")
	for _, variant := range []string{strings.ToLower(rewritten), strings.ToUpper(rewritten)} {
		original, err := codec.Reverse(variant)
		if err != nil || !strings.EqualFold(original, "user@origin.example") {
			t.Fatalf("reverse %q = %q, %v", variant, original, err)
		}
	}
}

func TestReverseRejectsTamperingAndExpiry(t *testing.T) {
	codec := testCodec(t)
	rewritten, _ := codec.Forward("user@origin.example", "fwd.example")
	tampered := strings.Replace(rewritten, "=user@", "=other@", 1)
	if _, err := codec.Reverse(tampered); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered user = %v", err)
	}
	if _, err := testCodec(t, "a-completely-different-secret").Reverse(rewritten); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign secret = %v", err)
	}
	if _, err := codec.Reverse("SRS0=abcd=AA=origin.example=user@fwd.example"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged hash = %v", err)
	}
	if _, err := codec.Reverse("plain@fwd.example"); !errors.Is(err, ErrNotSRS) {
		t.Fatalf("plain address = %v", err)
	}

	issued := codec.now()
	for _, test := range []struct {
		age  time.Duration
		want error
	}{{DefaultMaxAge * timeDay, nil}, {(DefaultMaxAge + 1) * timeDay, ErrExpired}, {-timeDay, ErrExpired}} {
		codec.now = func() time.Time { return issued }
		address, _ := codec.Forward("user@origin.example", "fwd.example")
		codec.now = func() time.Time { return issued.Add(test.age) }
		if _, err := codec.Reverse(address); !errors.Is(err, test.want) && !(test.want == nil && err == nil) {
			t.Fatalf("age %s: reverse error = %v, want %v", test.age, err, test.want)
		}
	}
}

func TestSecretRotationSignsWithFirstAndVerifiesAll(t *testing.T) {
	old := testCodec(t, "0123456789abcdef-old")
	address, _ := old.Forward("user@origin.example", "fwd.example")
	rotated := testCodec(t, "0123456789abcdef-new", "0123456789abcdef-old")
	if original, err := rotated.Reverse(address); err != nil || original != "user@origin.example" {
		t.Fatalf("old address after rotation = %q, %v", original, err)
	}
	fresh, _ := rotated.Forward("user@origin.example", "fwd.example")
	if _, err := old.Reverse(fresh); !errors.Is(err, ErrInvalid) {
		t.Fatalf("new address signed by old secret: %v", err)
	}
}

func TestForwardingAnSRSAddressUsesSRS1(t *testing.T) {
	first, second := testCodec(t, "0123456789abcdef-first"), testCodec(t, "0123456789abcdef-second")
	hop1, _ := first.Forward("user@origin.example", "one.example")
	hop2, err := second.Forward(hop1, "two.example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hop2, "SRS1=") || !strings.Contains(hop2, "=one.example==") {
		t.Fatalf("second hop = %q", hop2)
	}
	hop3, _ := testCodec(t, "0123456789abcdef-third").Forward(hop2, "three.example")
	if !strings.HasPrefix(hop3, "SRS1=") || !strings.Contains(hop3, "=one.example==") || strings.Contains(hop3, "two.example") {
		t.Fatalf("third hop = %q", hop3)
	}
	back, err := second.Reverse(hop2)
	if err != nil || back != hop1 {
		t.Fatalf("SRS1 reverse = %q, %v; want %q", back, err, hop1)
	}
	if original, err := first.Reverse(back); err != nil || original != "user@origin.example" {
		t.Fatalf("SRS0 reverse = %q, %v", original, err)
	}
}

func TestIsSRS(t *testing.T) {
	for local, want := range map[string]bool{"SRS0=a=b=c=d": true, "srs1+x": true, "srs0-x": true, "srs0x": false, "srs": false, "alice": false} {
		if got := IsSRS(local); got != want {
			t.Errorf("IsSRS(%q) = %t", local, got)
		}
	}
}
