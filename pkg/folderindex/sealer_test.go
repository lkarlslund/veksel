package folderindex

import (
	"bytes"
	"testing"

	"github.com/lkarlslund/veksel/pkg/dek"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type testSealer struct {
	encrypted bool
	key       *dek.Key
}

func newTestSealer(t *testing.T) *testSealer {
	t.Helper()
	raw, err := dek.Generate()
	if err != nil {
		t.Fatal(err)
	}
	key, err := dek.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &testSealer{encrypted: true, key: key}
}

func (s *testSealer) DerivedEncrypted(string) bool { return s.encrypted }
func (s *testSealer) SealDerived(owner string, aad, plaintext []byte) ([]byte, error) {
	return s.key.Seal(append([]byte(owner), aad...), plaintext)
}
func (s *testSealer) OpenDerived(owner string, aad, sealed []byte) ([]byte, error) {
	return s.key.Open(append([]byte(owner), aad...), sealed)
}

func TestEncryptedOwnersGetSealedProjections(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	space := &testSpace{
		folder: model.Folder{ID: "folder", UserID: "alice", HighestModSeq: 1, ItemCount: 1, Indexes: []model.FolderIndex{{Name: "test-name", Version: 3}}},
		items:  []model.Item{{ID: "item", Name: "secret-subject"}},
	}
	access := service.UserAccess("alice", "test")
	use := func(index *Index) {
		t.Helper()
		if err := index.WithSnapshot(t.Context(), space, access, space.folder, testDefinition{}, func(snapshot *Snapshot) error {
			if len(snapshot.Buckets["all"]) != 1 {
				t.Fatalf("documents = %d", len(snapshot.Buckets["all"]))
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	stored := func() []byte {
		t.Helper()
		raw, err := backend.Get(t.Context(), namespace, indexKey("test-name", "folder"))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	use(New(backend))
	if !bytes.Contains(stored(), []byte("secret-subject")) {
		t.Fatal("control: plaintext projection lacks the item name")
	}

	// Encrypting the owner replaces the plaintext projection on first use.
	sealer := newTestSealer(t)
	sealed := New(backend)
	sealed.SetSealer(sealer)
	space.pages = 0
	use(sealed)
	if space.pages != 1 || bytes.Contains(stored(), []byte("secret-subject")) || !bytes.HasPrefix(stored(), []byte(sealedPrefix)) {
		t.Fatalf("encrypted owner projection rebuilt=%d sealed=%t", space.pages, bytes.HasPrefix(stored(), []byte(sealedPrefix)))
	}
	warm := New(backend)
	warm.SetSealer(sealer)
	use(warm)
	if space.pages != 1 {
		t.Fatalf("sealed projection was not reused (%d pages)", space.pages)
	}
	// A new data key, as after a conversion, makes the old projection stale.
	rotated := New(backend)
	rotated.SetSealer(newTestSealer(t))
	use(rotated)
	if space.pages != 2 {
		t.Fatalf("projection under a replaced key was reused (%d pages)", space.pages)
	}
}
