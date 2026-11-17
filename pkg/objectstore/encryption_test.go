package objectstore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/lkarlslund/veksel/pkg/dek"
)

func testKey(t *testing.T) *dek.Key {
	t.Helper()
	raw, err := dek.Generate()
	if err != nil {
		t.Fatal(err)
	}
	key, err := dek.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func BenchmarkRead(b *testing.B) {
	raw, err := dek.Generate()
	if err != nil {
		b.Fatal(err)
	}
	key, err := dek.New(raw)
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{8 << 10, 1 << 20} {
		payload := bytes.Repeat([]byte("x"), size)
		for _, mode := range []struct {
			name string
			key  *dek.Key
		}{{"plain", nil}, {"encrypted", key}} {
			s, err := Open(b.TempDir(), Options{Key: mode.key})
			if err != nil {
				b.Fatal(err)
			}
			ref, err := s.Put(b.Context(), Header{ItemID: "itm", FolderID: "fld", ContentType: "message/rfc822"}, int64(size), bytes.NewReader(payload))
			if err != nil {
				b.Fatal(err)
			}
			b.Run(fmt.Sprintf("%s/%dKiB", mode.name, size>>10), func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if err := s.Read(b.Context(), ref, io.Discard); err != nil {
						b.Fatal(err)
					}
				}
			})
			_ = s.Close()
		}
	}
}

func TestEncryptedPayloadsRoundTripAndStayConfidential(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	s, err := Open(dir, Options{SyncWrites: true, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte("Subject: board minutes\r\n"), 5000)
	refs := make([]Ref, 0, 2)
	for _, payload := range [][]byte{secret, bytes.Repeat([]byte("Subject: lunch menu!!!!\r\n"), 5000)[:len(secret)]} {
		ref, err := s.Put(t.Context(), testHeader("itm_secret"), int64(len(payload)), bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		if ref.PayloadLength != int64(len(payload)) || ref.StoredLength != dek.SealedStreamSize(int64(len(payload))) || ref.StoredDigest == "" || ref.StoredDigest == ref.Digest {
			t.Fatalf("encrypted ref = %+v", ref)
		}
		refs = append(refs, ref)
	}
	var got bytes.Buffer
	if err := s.Read(t.Context(), refs[0], &got); err != nil || !bytes.Equal(got.Bytes(), secret) {
		t.Fatalf("Read = %d bytes, %v", got.Len(), err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	segment, err := os.ReadFile(segmentPath(dir, refs[0].Segment))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"board minutes", "itm_secret", "fld_inbox", "message/rfc822"} {
		if bytes.Contains(segment, []byte(leak)) {
			t.Fatalf("segment contains plaintext %q", leak)
		}
	}

	// Swapping two equally sized ciphertexts between records fails, even
	// though each is internally consistent.
	firstStart := refs[0].Offset + refs[0].RecordLength - refs[0].StoredLength
	secondStart := refs[1].Offset + refs[1].RecordLength - refs[1].StoredLength
	swapped := bytes.Clone(segment)
	copy(swapped[firstStart:], segment[secondStart:secondStart+refs[1].StoredLength])
	if err := os.WriteFile(segmentPath(dir, refs[0].Segment), swapped, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, Options{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.Read(t.Context(), refs[0], io.Discard); err == nil {
		t.Fatal("ciphertext moved between records was accepted")
	}
	if err := os.WriteFile(segmentPath(dir, refs[0].Segment), segment, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Verify(t.Context(), refs[1]); err != nil {
		t.Fatalf("Verify after restore: %v", err)
	}

	wrongKey, err := Open(dir, Options{Key: testKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrongKey.Close() })
	if err := wrongKey.Read(t.Context(), refs[1], io.Discard); !errors.Is(err, dek.ErrAuthentication) {
		t.Fatalf("wrong key error = %v, want ErrAuthentication", err)
	}
	plain, err := Open(filepath.Clean(dir), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plain.Close() })
	if err := plain.Read(t.Context(), refs[1], io.Discard); !errors.Is(err, ErrKeyRequired) {
		t.Fatalf("keyless read error = %v, want ErrKeyRequired", err)
	}
	unsealed := refs[1]
	unsealed.StoredDigest, unsealed.StoredLength = "", 0
	if err := reopened.Read(t.Context(), unsealed, io.Discard); !errors.Is(err, ErrReference) {
		t.Fatalf("plaintext ref in encrypted store error = %v, want ErrReference", err)
	}
}
