package diagnostics

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	SupportBundleSchema = 1
	MaxSupportSections  = 16
	MaxSupportSection   = 1 << 20
	MaxSupportBytes     = 4 << 20
)

var (
	ErrInvalidSupportBundle = errors.New("invalid support bundle")
	supportSectionName      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}\.json$`)
)

// SupportSection is one pre-redacted bounded document supplied by a subsystem.
type SupportSection struct {
	Name        string
	Description string
	Privacy     string
	Data        []byte
}

// SupportFile is the preview and integrity record for one archive member.
type SupportFile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Privacy     string `json:"privacy"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
}

// SupportManifest is safe to preview before the archive is downloaded.
type SupportManifest struct {
	SchemaVersion int           `json:"schema_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	Redaction     string        `json:"redaction"`
	TotalBytes    int64         `json:"total_section_bytes"`
	Files         []SupportFile `json:"files"`
	Excludes      []string      `json:"excludes"`
}

// SupportBundle is an immutable validated archive plan.
type SupportBundle struct {
	manifest SupportManifest
	sections []SupportSection
}

func NewSupportBundle(generatedAt time.Time, sections []SupportSection) (SupportBundle, error) {
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	} else {
		generatedAt = generatedAt.UTC()
	}
	if len(sections) == 0 || len(sections) > MaxSupportSections {
		return SupportBundle{}, fmt.Errorf("%w: sections must contain between 1 and %d entries", ErrInvalidSupportBundle, MaxSupportSections)
	}
	sections = slices.Clone(sections)
	slices.SortFunc(sections, func(left, right SupportSection) int { return strings.Compare(left.Name, right.Name) })
	manifest := SupportManifest{
		SchemaVersion: SupportBundleSchema,
		GeneratedAt:   generatedAt,
		Redaction:     "Secrets are replaced with [redacted]. Identities, network locations, and paths are omitted; no message or item payloads are included.",
		Files:         make([]SupportFile, 0, len(sections)),
		Excludes: []string{
			"message, item, attachment, and queue payloads",
			"account and domain identities",
			"passwords, credentials, tokens, cookies, and private keys",
			"raw profiles, database files, filesystem dumps, and filesystem paths",
			"trace, debug, info, and audit records",
		},
	}
	for index, section := range sections {
		if !supportSectionName.MatchString(section.Name) || path.Base(section.Name) != section.Name {
			return SupportBundle{}, fmt.Errorf("%w: unsafe section name %q", ErrInvalidSupportBundle, section.Name)
		}
		if index > 0 && sections[index-1].Name == section.Name {
			return SupportBundle{}, fmt.Errorf("%w: duplicate section name %q", ErrInvalidSupportBundle, section.Name)
		}
		section.Description = boundedSupportText(section.Description, 240)
		section.Privacy = boundedSupportText(section.Privacy, 160)
		if section.Description == "" || section.Privacy == "" || len(section.Data) == 0 || len(section.Data) > MaxSupportSection || !json.Valid(section.Data) {
			return SupportBundle{}, fmt.Errorf("%w: section %q has invalid metadata, JSON, or size", ErrInvalidSupportBundle, section.Name)
		}
		manifest.TotalBytes += int64(len(section.Data))
		if manifest.TotalBytes > MaxSupportBytes {
			return SupportBundle{}, fmt.Errorf("%w: section data exceeds %d bytes", ErrInvalidSupportBundle, MaxSupportBytes)
		}
		digest := sha256.Sum256(section.Data)
		manifest.Files = append(manifest.Files, SupportFile{
			Name: section.Name, Description: section.Description, Privacy: section.Privacy,
			Bytes: int64(len(section.Data)), SHA256: hex.EncodeToString(digest[:]),
		})
		sections[index] = section
	}
	return SupportBundle{manifest: manifest, sections: sections}, nil
}

func (b SupportBundle) Manifest() SupportManifest {
	result := b.manifest
	result.Files = slices.Clone(result.Files)
	result.Excludes = slices.Clone(result.Excludes)
	return result
}

// WriteArchive writes manifest.json first followed by sections in lexical order.
// Stored entries avoid compression-dependent output and keep resource use
// predictable for already-small JSON documents.
func (b SupportBundle) WriteArchive(destination io.Writer) error {
	if len(b.sections) == 0 {
		return fmt.Errorf("%w: empty bundle", ErrInvalidSupportBundle)
	}
	archive := zip.NewWriter(destination)
	write := func(name string, data []byte) error {
		header := &zip.FileHeader{Name: name, Method: zip.Store, Modified: b.manifest.GeneratedAt}
		entry, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = entry.Write(data)
		return err
	}
	manifest, err := json.MarshalIndent(b.manifest, "", "  ")
	if err != nil {
		return err
	}
	manifest = append(manifest, '\n')
	if err := write("manifest.json", manifest); err != nil {
		_ = archive.Close()
		return err
	}
	for _, section := range b.sections {
		if err := write(section.Name, section.Data); err != nil {
			_ = archive.Close()
			return err
		}
	}
	return archive.Close()
}

func boundedSupportText(value string, limit int) string {
	value = strings.Map(func(character rune) rune {
		if character < 32 || character == 127 {
			return ' '
		}
		return character
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) > limit {
		value = string(runes[:limit])
	}
	return value
}
