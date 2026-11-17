package diagnostics

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSupportBundleManifestAndArchiveAreBoundedAndOrdered(t *testing.T) {
	generated := time.Date(2026, 8, 27, 12, 30, 0, 0, time.UTC)
	sections := []SupportSection{
		{Name: "runtime.json", Description: " Runtime metadata ", Privacy: "No identities", Data: []byte(`{"go":"test"}`)},
		{Name: "configuration.json", Description: "Managed settings", Privacy: "Secrets redacted", Data: []byte(`{"relay_password":"[redacted]"}`)},
	}
	bundle, err := NewSupportBundle(generated, sections)
	if err != nil {
		t.Fatal(err)
	}
	manifest := bundle.Manifest()
	if manifest.SchemaVersion != SupportBundleSchema || manifest.GeneratedAt != generated || len(manifest.Files) != 2 || manifest.Files[0].Name != "configuration.json" || manifest.Files[1].Name != "runtime.json" {
		t.Fatalf("manifest=%+v", manifest)
	}
	for _, file := range manifest.Files {
		var data []byte
		for _, section := range sections {
			if section.Name == file.Name {
				data = section.Data
			}
		}
		digest := sha256.Sum256(data)
		if file.Bytes != int64(len(data)) || file.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("file integrity=%+v", file)
		}
	}

	var output bytes.Buffer
	if err := bundle.WriteArchive(&output); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(reader.File))
	for _, file := range reader.File {
		names = append(names, file.Name)
		if file.Method != zip.Store || !file.Modified.UTC().Equal(generated) {
			t.Fatalf("archive header=%+v", file.FileHeader)
		}
	}
	if !slices.Equal(names, []string{"manifest.json", "configuration.json", "runtime.json"}) {
		t.Fatalf("archive order=%v", names)
	}
	entry, err := reader.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	manifestData, _ := io.ReadAll(entry)
	_ = entry.Close()
	var archived SupportManifest
	if err := json.Unmarshal(manifestData, &archived); err != nil || !slices.Equal(archived.Files, manifest.Files) {
		t.Fatalf("archived manifest=%+v err=%v", archived, err)
	}
}

func TestSupportBundleRejectsUnsafeInvalidAndOversizedSections(t *testing.T) {
	valid := SupportSection{Name: "safe.json", Description: "Safe", Privacy: "Redacted", Data: []byte(`{}`)}
	tests := []struct {
		name     string
		sections []SupportSection
	}{
		{name: "empty"},
		{name: "unsafe path", sections: []SupportSection{{Name: "../safe.json", Description: "Safe", Privacy: "Redacted", Data: []byte(`{}`)}}},
		{name: "wrong extension", sections: []SupportSection{{Name: "safe.txt", Description: "Safe", Privacy: "Redacted", Data: []byte(`{}`)}}},
		{name: "invalid json", sections: []SupportSection{{Name: "safe.json", Description: "Safe", Privacy: "Redacted", Data: []byte(`no`)}}},
		{name: "missing metadata", sections: []SupportSection{{Name: "safe.json", Data: []byte(`{}`)}}},
		{name: "duplicate", sections: []SupportSection{valid, valid}},
		{name: "large", sections: []SupportSection{{Name: "safe.json", Description: "Safe", Privacy: "Redacted", Data: []byte(`{"value":"` + strings.Repeat("x", MaxSupportSection) + `"}`)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSupportBundle(time.Now(), test.sections); !errors.Is(err, ErrInvalidSupportBundle) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestSupportBundleManifestReturnsDetachedSlices(t *testing.T) {
	bundle, err := NewSupportBundle(time.Now(), []SupportSection{{Name: "safe.json", Description: "Safe", Privacy: "Redacted", Data: []byte(`{}`)}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := bundle.Manifest()
	manifest.Files[0].Name = "changed"
	manifest.Excludes[0] = "changed"
	next := bundle.Manifest()
	if next.Files[0].Name != "safe.json" || next.Excludes[0] == "changed" {
		t.Fatalf("manifest mutation leaked: %+v", next)
	}
}
