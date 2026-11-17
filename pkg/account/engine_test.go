package account

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/lkarlslund/veksel/pkg/objectstore"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestGenerationEngines(t *testing.T) {
	for _, engine := range ProductionEngines {
		t.Run(string(engine), func(t *testing.T) {
			accountPath := filepath.Join(t.TempDir(), "acc_00000000000000000000000000000000")
			generationID := "gen_11111111111111111111111111111111"
			generation, err := CreateGeneration(accountPath, generationID, engine)
			if err != nil {
				t.Fatalf("CreateGeneration: %v", err)
			}
			if err := generation.Index.Set(t.Context(), "folders", "inbox", []byte("metadata")); err != nil {
				t.Fatalf("Index.Set: %v", err)
			}
			payload := []byte("From: alice@example.com\r\n\r\nhello")
			ref, err := generation.Objects.Put(t.Context(), objectstore.Header{
				ItemID:      "itm_one",
				FolderID:    "fld_inbox",
				ContentType: "message/rfc822",
			}, int64(len(payload)), bytes.NewReader(payload))
			if err != nil {
				t.Fatalf("Objects.Put: %v", err)
			}
			if err := generation.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			generation, err = OpenGeneration(accountPath, generationID, engine)
			if err != nil {
				t.Fatalf("OpenGeneration: %v", err)
			}
			defer generation.Close()
			got, err := generation.Index.Get(t.Context(), "folders", "inbox")
			if err != nil || string(got) != "metadata" {
				t.Fatalf("Index.Get: got %q, %v", got, err)
			}
			var output bytes.Buffer
			if err := generation.Objects.Read(t.Context(), ref, &output); err != nil {
				t.Fatalf("Objects.Read: %v", err)
			}
			if !bytes.Equal(output.Bytes(), payload) {
				t.Fatalf("payload: got %q, want %q", output.Bytes(), payload)
			}
		})
	}
}

func TestJSONIsNotProductionEngine(t *testing.T) {
	if SupportedEngine(store.BackendJSON) {
		t.Fatal("JSON must not be a production account engine")
	}
}
