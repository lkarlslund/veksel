package dek

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func newTestKey(t testing.TB) *Key {
	t.Helper()
	raw, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	key, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestValueSealBindsAssociatedDataAndKey(t *testing.T) {
	key, other := newTestKey(t), newTestKey(t)
	sealed, err := key.Seal([]byte("ns\x00a"), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != ValueOverhead+5 || bytes.Contains(sealed, []byte("hello")) {
		t.Fatalf("sealed value = %x", sealed)
	}
	if plain, err := key.Open([]byte("ns\x00a"), sealed); err != nil || string(plain) != "hello" {
		t.Fatalf("Open = %q, %v", plain, err)
	}
	if _, err := key.Open([]byte("ns\x00b"), sealed); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Open with other aad = %v", err)
	}
	if _, err := other.Open([]byte("ns\x00a"), sealed); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Open with other key = %v", err)
	}
}

func TestNameSealIsDeterministicAndAuthenticated(t *testing.T) {
	key := newTestKey(t)
	first, second := key.SealName([]byte("aad"), "Quarterly report.pdf"), key.SealName([]byte("aad"), "Quarterly report.pdf")
	if first != second {
		t.Fatalf("names differ: %s %s", first, second)
	}
	if key.SealName([]byte("other"), "Quarterly report.pdf") == first {
		t.Fatal("name encryption ignores associated data")
	}
	if name, err := key.OpenName([]byte("aad"), first); err != nil || name != "Quarterly report.pdf" {
		t.Fatalf("OpenName = %q, %v", name, err)
	}
	if _, err := key.OpenName([]byte("other"), first); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("OpenName with other aad = %v", err)
	}
	if empty, err := key.OpenName(nil, key.SealName(nil, "")); err != nil || empty != "" {
		t.Fatalf("empty name = %q, %v", empty, err)
	}
}

func TestStreamRoundTripsAndDetectsTampering(t *testing.T) {
	key := newTestKey(t)
	for _, size := range []int{0, 1, StreamChunkSize - 1, StreamChunkSize, StreamChunkSize + 1, 3*StreamChunkSize + 17} {
		plaintext := bytes.Repeat([]byte{byte(size)}, size)
		var sealed bytes.Buffer
		writer := key.NewSealingWriter(&sealed, []byte("object"))
		// Uneven writes exercise chunk boundaries.
		for rest := plaintext; len(rest) > 0; {
			n := min(len(rest), 1000)
			if _, err := writer.Write(rest[:n]); err != nil {
				t.Fatal(err)
			}
			rest = rest[n:]
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if int64(sealed.Len()) != SealedStreamSize(int64(size)) {
			t.Fatalf("size %d: sealed %d bytes, predicted %d", size, sealed.Len(), SealedStreamSize(int64(size)))
		}
		got, err := io.ReadAll(key.NewOpeningReader(bytes.NewReader(sealed.Bytes()), []byte("object")))
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("size %d: round trip len=%d err=%v", size, len(got), err)
		}
		if _, err := io.ReadAll(key.NewOpeningReader(bytes.NewReader(sealed.Bytes()), []byte("other"))); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("size %d: other aad = %v", size, err)
		}
		if size > StreamChunkSize {
			truncated := sealed.Bytes()[:streamHeader+StreamChunkSize+16]
			if _, err := io.ReadAll(key.NewOpeningReader(bytes.NewReader(truncated), []byte("object"))); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("size %d: truncation at chunk boundary = %v", size, err)
			}
		}
		extended := append(bytes.Clone(sealed.Bytes()), 0)
		if _, err := io.ReadAll(key.NewOpeningReader(bytes.NewReader(extended), []byte("object"))); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("size %d: extension = %v", size, err)
		}
	}
}
