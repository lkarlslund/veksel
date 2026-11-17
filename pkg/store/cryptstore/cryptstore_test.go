package cryptstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/dek"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
	"github.com/lkarlslund/veksel/pkg/store/storetest"
)

var testFamilies = []KeyFamily{
	{Namespace: "items", Prefix: "name:", Segments: 1},
	{Namespace: "acl", Prefix: "", Segments: 1},
	{Namespace: "records", Prefix: "item/", Segments: 0},
}

func newKey(t testing.TB) *dek.Key {
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

func newPebble(t testing.TB) *pebblestore.Store {
	t.Helper()
	inner, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return inner
}

func newEncrypted(t testing.TB, inner store.Store, key *dek.Key) *Store {
	t.Helper()
	encrypted, err := New(inner, key, testFamilies)
	if err != nil {
		t.Fatal(err)
	}
	return encrypted
}

func TestConformance(t *testing.T) {
	t.Run("pebble", func(t *testing.T) {
		storetest.Run(t, func(t *testing.T) store.Store {
			return newEncrypted(t, newPebble(t), newKey(t))
		})
	})
	t.Run("badger", func(t *testing.T) {
		storetest.Run(t, func(t *testing.T) store.Store {
			inner, err := badgerstore.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			return newEncrypted(t, inner, newKey(t))
		})
	})
}

// visitCountingStore counts the entries the engine yields to iteration.
type visitCountingStore struct {
	*pebblestore.Store
	visits int
}

func (s *visitCountingStore) IterateFrom(ctx context.Context, namespace, prefix, start string, fn store.IterCallback) error {
	return s.Store.IterateFrom(ctx, namespace, prefix, start, func(key string, value []byte) (bool, error) {
		s.visits++
		return fn(key, value)
	})
}

func TestIterateFromSeeksEngineOutsideProtectedFamilies(t *testing.T) {
	ctx := t.Context()
	inner := &visitCountingStore{Store: newPebble(t)}
	encrypted := newEncrypted(t, inner, newKey(t))
	t.Cleanup(func() { _ = encrypted.Close() })
	for index := range 100 {
		if err := encrypted.Set(ctx, "changes", fmt.Sprintf("record/%03d", index), []byte("value")); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	err := store.IterateFrom(ctx, encrypted, "changes", "record/", "record/097", func(key string, value []byte) (bool, error) {
		if string(value) != "value" {
			return false, fmt.Errorf("value for %q = %q", key, value)
		}
		got = append(got, key)
		return true, nil
	})
	if err != nil || !reflect.DeepEqual(got, []string{"record/097", "record/098", "record/099"}) {
		t.Fatalf("IterateFrom = %v, %v", got, err)
	}
	if inner.visits != 3 {
		t.Fatalf("engine yielded %d entries, want 3", inner.visits)
	}
}

func TestValuesAndProtectedNamesAreCiphertextAtRest(t *testing.T) {
	ctx := t.Context()
	inner := newPebble(t)
	encrypted := newEncrypted(t, inner, newKey(t))
	t.Cleanup(func() { _ = encrypted.Close() })
	if err := encrypted.Set(ctx, "items", "name:fld_1:Salary review.pdf", []byte("itm_1")); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.Set(ctx, "items", "itm_1", []byte(`{"subject":"confidential"}`)); err != nil {
		t.Fatal(err)
	}
	keys, err := inner.List(ctx, "items")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if strings.Contains(key, "Salary") {
			t.Fatalf("protected name stored in plaintext: %q", key)
		}
		if strings.HasPrefix(key, "name:") && !strings.HasPrefix(key, "name:fld_1:") {
			t.Fatalf("protected key lost its plaintext block: %q", key)
		}
		raw, err := inner.Get(ctx, "items", key)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("confidential")) || bytes.Contains(raw, []byte("itm_1")) {
			t.Fatalf("value stored in plaintext: %q", raw)
		}
	}
	if got, err := encrypted.Get(ctx, "items", "name:fld_1:Salary review.pdf"); err != nil || string(got) != "itm_1" {
		t.Fatalf("Get protected = %q, %v", got, err)
	}
}

func TestSwappedCiphertextAndWrongKeyFailAuthentication(t *testing.T) {
	ctx := t.Context()
	inner := newPebble(t)
	encrypted := newEncrypted(t, inner, newKey(t))
	t.Cleanup(func() { _ = encrypted.Close() })
	for _, key := range []string{"a", "b"} {
		if err := encrypted.Set(ctx, "records", key, []byte("value-"+key)); err != nil {
			t.Fatal(err)
		}
	}
	rawA, err := inner.Get(ctx, "records", "a")
	if err != nil {
		t.Fatal(err)
	}
	if err := inner.Set(ctx, "records", "b", rawA); err != nil {
		t.Fatal(err)
	}
	if _, err := encrypted.Get(ctx, "records", "b"); !errors.Is(err, dek.ErrAuthentication) {
		t.Fatalf("swapped value error = %v, want ErrAuthentication", err)
	}
	if err := encrypted.Iterate(ctx, "records", "", func(string, []byte) (bool, error) { return true, nil }); !errors.Is(err, dek.ErrAuthentication) {
		t.Fatalf("iterate over swapped value error = %v", err)
	}
	wrong := newEncrypted(t, inner, newKey(t))
	if _, err := wrong.Get(ctx, "records", "a"); !errors.Is(err, dek.ErrAuthentication) {
		t.Fatalf("wrong key error = %v, want ErrAuthentication", err)
	}
}

// TestMatchesPlainEngineSemantics applies the same random operations to a
// plain engine and an encrypted one and requires identical observable
// results for every list, scan, and (early-stopping) iteration.
func TestMatchesPlainEngineSemantics(t *testing.T) {
	ctx := t.Context()
	plain := newPebble(t)
	encrypted := newEncrypted(t, newPebble(t), newKey(t))
	t.Cleanup(func() { _ = plain.Close(); _ = encrypted.Close() })
	random := rand.New(rand.NewPCG(1, 2))
	segments := []string{"fld_a", "fld_b", "fld_ab", "x"}
	tails := []string{"", "alpha", "Beta", "zeta.ics", "a:b", "ünïcode", "~", "0"}
	keyFor := func() (string, string) {
		switch random.IntN(5) {
		case 0:
			return "items", "name:" + segments[random.IntN(len(segments))] + ":" + tails[random.IntN(len(tails))]
		case 1:
			return "items", []string{"member:fld_a:itm_1", "name:fld_a", "itm_9", "name", "uid:fld_a:7"}[random.IntN(5)]
		case 2:
			return "acl", segments[random.IntN(len(segments))] + ":" + tails[random.IntN(len(tails))]
		case 3:
			return "acl", segments[random.IntN(len(segments))]
		default:
			return "records", "item/" + tails[random.IntN(len(tails))]
		}
	}
	for step := range 600 {
		namespace, key := keyFor()
		value := []byte(fmt.Sprintf("v%d", step))
		var plainErr, encryptedErr error
		switch random.IntN(4) {
		case 0, 1:
			plainErr, encryptedErr = plain.Set(ctx, namespace, key, value), encrypted.Set(ctx, namespace, key, value)
		case 2:
			plainErr, encryptedErr = plain.Put(ctx, namespace, key, value), encrypted.Put(ctx, namespace, key, value)
		default:
			plainErr, encryptedErr = plain.Delete(ctx, namespace, key), encrypted.Delete(ctx, namespace, key)
		}
		if !errors.Is(encryptedErr, plainErr) && (plainErr == nil) != (encryptedErr == nil) {
			t.Fatalf("step %d %s/%s: plain err %v, encrypted err %v", step, namespace, key, plainErr, encryptedErr)
		}
	}
	prefixes := []string{"", "n", "name:", "name:fld_a", "name:fld_a:", "name:fld_a:a", "name:fld_a:al", "name:x:", "member:", "fld_", "fld_a:", "fld_a:B", "item/", "item/z", "i"}
	for _, namespace := range []string{"items", "acl", "records"} {
		for _, prefix := range prefixes {
			want, wantErr := plain.Scan(ctx, namespace, prefix)
			got, gotErr := encrypted.Scan(ctx, namespace, prefix)
			if wantErr != nil || gotErr != nil || !reflect.DeepEqual(nonNil(got), nonNil(want)) {
				t.Fatalf("Scan(%s, %q) = %q, %v; want %q, %v", namespace, prefix, got, gotErr, want, wantErr)
			}
			for _, limit := range []int{1, 3, 1 << 30} {
				if collect(t, plain, namespace, prefix, limit) != collect(t, encrypted, namespace, prefix, limit) {
					t.Fatalf("Iterate(%s, %q, limit %d) = %s; want %s", namespace, prefix, limit, collect(t, encrypted, namespace, prefix, limit), collect(t, plain, namespace, prefix, limit))
				}
			}
		}
		want, _ := plain.List(ctx, namespace)
		got, err := encrypted.List(ctx, namespace)
		if err != nil || !reflect.DeepEqual(nonNil(got), nonNil(want)) {
			t.Fatalf("List(%s) = %q, %v; want %q", namespace, got, err, want)
		}
	}
}

func nonNil(keys []string) []string {
	if keys == nil {
		return []string{}
	}
	return keys
}

func collect(t *testing.T, s store.Store, namespace, prefix string, limit int) string {
	t.Helper()
	var out strings.Builder
	count := 0
	err := s.Iterate(context.Background(), namespace, prefix, func(key string, value []byte) (bool, error) {
		fmt.Fprintf(&out, "%s=%s;", key, value)
		count++
		return count < limit, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestBatchesHonorRollbackAndSyncMarks(t *testing.T) {
	ctx := store.WithoutSync(t.Context())
	inner := newPebble(t)
	encrypted := newEncrypted(t, inner, newKey(t))
	t.Cleanup(func() { _ = encrypted.Close() })
	err := store.Batch(ctx, encrypted, func(batchCtx context.Context) error {
		if !store.InBatch(batchCtx, encrypted) || !store.SyncDisabled(batchCtx) {
			return errors.New("batch context lost its decorator or sync marks")
		}
		if err := encrypted.Set(batchCtx, "items", "name:fld_a:one", []byte("1")); err != nil {
			return err
		}
		keys, err := encrypted.Scan(batchCtx, "items", "name:fld_a:")
		if err != nil || !reflect.DeepEqual(keys, []string{"name:fld_a:one"}) {
			return fmt.Errorf("read own protected write: %v, %w", keys, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("rollback")
	if err := store.Batch(ctx, encrypted, func(batchCtx context.Context) error {
		if err := encrypted.Set(batchCtx, "items", "name:fld_a:two", []byte("2")); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("rollback error = %v", err)
	}
	if keys, err := encrypted.Scan(ctx, "items", "name:"); err != nil || !reflect.DeepEqual(keys, []string{"name:fld_a:one"}) {
		t.Fatalf("after rollback keys = %v, %v", keys, err)
	}
}

func BenchmarkPebble(b *testing.B) {
	const items = 2000
	value := bytes.Repeat([]byte("x"), 1024)
	for _, mode := range []string{"plain", "encrypted"} {
		var s store.Store = newPebble(b)
		if mode == "encrypted" {
			s = newEncrypted(b, s, newKey(b))
		}
		ctx := context.Background()
		for i := range items {
			if err := s.Set(ctx, "items", fmt.Sprintf("itm_%06d", i), value); err != nil {
				b.Fatal(err)
			}
			if err := s.Set(ctx, "items", fmt.Sprintf("name:fld_a:message-%06d.eml", i), []byte(fmt.Sprintf("itm_%06d", i))); err != nil {
				b.Fatal(err)
			}
		}
		b.Run(mode+"/get", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				if _, err := s.Get(ctx, "items", fmt.Sprintf("itm_%06d", i%items)); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(mode+"/get-protected-name", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				if _, err := s.Get(ctx, "items", fmt.Sprintf("name:fld_a:message-%06d.eml", i%items)); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(mode+"/iterate-values", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := s.Iterate(ctx, "items", "itm_", func(string, []byte) (bool, error) { return true, nil }); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(mode+"/scan-protected-names", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := s.Scan(ctx, "items", "name:fld_a:"); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(mode+"/set", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				if err := s.Set(store.WithoutSync(ctx), "items", fmt.Sprintf("itm_%06d", i%items), value); err != nil {
					b.Fatal(err)
				}
			}
		})
		_ = s.Close()
	}
}
