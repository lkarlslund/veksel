package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Mode determines how restore handles existing data.
type Mode int

const (
	maxLegacyRestoreEntries = 1_000_000
	maxLegacyRestoreBytes   = int64(1 << 30)
)

const (
	// Merge adds imported keys and overwrites matching existing keys.
	Merge Mode = iota
	// Replace clears all current keys before importing.
	Replace
)

// Restore validates and imports a tar.gz backup.
func Restore(s store.Store, r io.Reader, mode Mode) (*Metadata, error) {
	return RestoreContext(context.Background(), s, r, mode)
}

// RestoreContext validates the complete archive before applying every
// namespace and key mutation in one atomic store batch.
func RestoreContext(ctx context.Context, s store.Store, r io.Reader, mode Mode) (*Metadata, error) {
	if s == nil || r == nil {
		return nil, errors.New("restore source and destination are required")
	}
	if mode != Merge && mode != Replace {
		return nil, errors.New("invalid restore mode")
	}
	log.Info("restore: starting restore", "mode", mode)
	started := time.Now()
	gzipReader, err := gzip.NewReader(contextReader{ctx: ctx, r: r})
	if err != nil {
		return nil, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer func() { _ = gzipReader.Close() }()
	tarReader := tar.NewReader(gzipReader)
	var meta *Metadata
	var entries []tarEntry
	seenEntries := make(map[string]struct{})
	observedRecords := make(map[string]ManifestRecord)
	var manifest *Manifest
	var totalBytes int64
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > maxLegacyRestoreBytes || path.Clean(header.Name) != header.Name || strings.HasPrefix(header.Name, "/") {
			return nil, errors.New("unsafe backup archive entry")
		}
		if len(seenEntries) >= maxLegacyRestoreEntries || totalBytes > maxLegacyRestoreBytes-header.Size {
			return nil, errors.New("backup archive exceeds restore limits")
		}
		totalBytes += header.Size
		if _, duplicate := seenEntries[header.Name]; duplicate {
			return nil, fmt.Errorf("duplicate backup archive entry %q", header.Name)
		}
		seenEntries[header.Name] = struct{}{}
		data, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil || int64(len(data)) != header.Size {
			return nil, fmt.Errorf("truncated backup archive entry %q", header.Name)
		}
		if header.Name == metadataFile {
			if meta != nil {
				return nil, errors.New("duplicate backup metadata")
			}
			if err := json.Unmarshal(data, &meta); err != nil {
				return nil, fmt.Errorf("parse metadata: %w", err)
			}
			observedRecords[header.Name] = digestRecord(header.Name, data)
			continue
		}
		if header.Name == manifestFile {
			if manifest != nil {
				return nil, errors.New("duplicate backup manifest")
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				return nil, fmt.Errorf("parse manifest: %w", err)
			}
			continue
		}
		slash := strings.Index(header.Name, "/")
		if slash <= 0 || slash == len(header.Name)-1 {
			return nil, fmt.Errorf("invalid backup archive entry %q", header.Name)
		}
		entries = append(entries, tarEntry{namespace: header.Name[:slash], key: header.Name[slash+1:], value: data})
		observedRecords[header.Name] = digestRecord(header.Name, data)
	}
	if meta == nil {
		return nil, fmt.Errorf("archive missing %s", metadataFile)
	}
	if (meta.Version != "v1" && meta.Version != "v2") || meta.TotalKeys != len(entries) || len(meta.Namespaces) > 4096 {
		return nil, errors.New("invalid backup metadata")
	}
	namespaceSet := make(map[string]bool, len(meta.Namespaces))
	for _, namespace := range meta.Namespaces {
		if namespace == "" || namespaceSet[namespace] {
			return nil, errors.New("invalid backup namespace list")
		}
		namespaceSet[namespace] = true
	}
	for _, entry := range entries {
		if !namespaceSet[entry.namespace] {
			return nil, fmt.Errorf("entry %s/%s belongs to unknown namespace %s", entry.namespace, entry.key, entry.namespace)
		}
	}
	if err := validateManifest(meta, manifest, observedRecords); err != nil {
		return nil, err
	}
	if err := model.CheckSystemSchemaVersion(meta.SchemaVersion); err != nil {
		return nil, err
	}
	if err := store.Batch(ctx, s, func(batchCtx context.Context) error {
		if mode == Replace {
			existing, err := s.ListNamespaces(batchCtx)
			if err != nil {
				return fmt.Errorf("list namespaces for replace: %w", err)
			}
			for _, namespace := range existing {
				keys, err := s.List(batchCtx, namespace)
				if err != nil {
					return fmt.Errorf("list keys for replace in %s: %w", namespace, err)
				}
				for _, key := range keys {
					if err := s.Delete(batchCtx, namespace, key); err != nil {
						return fmt.Errorf("delete %s/%s: %w", namespace, key, err)
					}
				}
			}
		}
		namespaces := slices.Clone(meta.Namespaces)
		slices.Sort(namespaces)
		for _, namespace := range namespaces {
			exists, err := s.NamespaceExists(batchCtx, namespace)
			if err != nil {
				return fmt.Errorf("check namespace %s: %w", namespace, err)
			}
			if !exists {
				if err := s.CreateNamespace(batchCtx, namespace); err != nil {
					return fmt.Errorf("create namespace %s: %w", namespace, err)
				}
			}
		}
		for _, entry := range entries {
			if err := s.Set(batchCtx, entry.namespace, entry.key, entry.value); err != nil {
				return fmt.Errorf("set %s/%s: %w", entry.namespace, entry.key, err)
			}
		}
		return nil
	}); err != nil {
		log.Error("restore: atomic restore failed", "error", err)
		return nil, err
	}
	// An archive from an older release carries data of its own schema, so
	// upgrade it now instead of serving it until the next restart.
	if err := model.UpgradeSystemStore(ctx, s, meta.SchemaVersion); err != nil {
		log.Error("restore: upgrade restored system store failed", "error", err)
		return nil, err
	}
	log.Info("restore: restore completed", "entries", len(entries), "duration", time.Since(started))
	return meta, nil
}

type tarEntry struct {
	namespace string
	key       string
	value     []byte
}

// ValidateBackup reads and validates the metadata from a backup archive.
func ValidateBackup(r io.Reader) (*Metadata, error) {
	verification, err := Verify(r)
	if err != nil {
		return nil, err
	}
	return verification.Metadata, nil
}

func validateManifest(meta *Metadata, manifest *Manifest, observed map[string]ManifestRecord) error {
	if meta.Version == "v1" {
		if manifest != nil {
			return errors.New("legacy backup unexpectedly contains a v2 manifest")
		}
		return nil
	}
	if manifest == nil {
		return errors.New("v2 backup is missing integrity manifest")
	}
	if manifest.Algorithm != "sha256" || len(manifest.Records) != len(observed) {
		return errors.New("invalid backup integrity manifest")
	}
	declared := make(map[string]ManifestRecord, len(manifest.Records))
	var totalBytes int64
	for _, record := range manifest.Records {
		if record.Name == "" || record.Size < 0 || len(record.SHA256) != 64 || record.Name == manifestFile {
			return errors.New("invalid backup integrity record")
		}
		if _, duplicate := declared[record.Name]; duplicate {
			return fmt.Errorf("duplicate backup integrity record %q", record.Name)
		}
		declared[record.Name] = record
		totalBytes += record.Size
	}
	if totalBytes != manifest.TotalBytes {
		return errors.New("backup integrity byte count mismatch")
	}
	for name, actual := range observed {
		expected, ok := declared[name]
		if !ok || expected.Size != actual.Size || expected.SHA256 != actual.SHA256 {
			return fmt.Errorf("backup integrity check failed for %q", name)
		}
	}
	return nil
}

// BackupInfo holds human-readable backup information for the UI.
type BackupInfo struct {
	Version    string
	Timestamp  time.Time
	Backend    string
	Namespaces []string
	TotalKeys  int
	Names      []string
}

// InfoFromMetadata converts Metadata to BackupInfo.
func InfoFromMetadata(meta *Metadata) *BackupInfo {
	return &BackupInfo{Version: meta.Version, Timestamp: meta.Timestamp, Backend: meta.Backend, Namespaces: meta.Namespaces, TotalKeys: meta.TotalKeys, Names: meta.Namespaces}
}
