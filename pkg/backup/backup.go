// Package backup provides export and import for the Veksel KV store.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

var log = logpkg.For(logpkg.ModuleBackup)

// Metadata is embedded in every backup archive.
type Metadata struct {
	Version    string    `json:"version"`
	Timestamp  time.Time `json:"timestamp"`
	Backend    string    `json:"backend"`
	Namespaces []string  `json:"namespaces"`
	TotalKeys  int       `json:"total_keys"`
	// SchemaVersion is the system-store schema recorded in the source store
	// (model.SystemSchemaVersion); zero for stores predating versioning.
	SchemaVersion int `json:"system_schema_version,omitempty"`
}

const metadataFile = "metadata.json"

const manifestFile = "manifest.json"

// ManifestRecord authenticates one regular archive record by logical name.
type ManifestRecord struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest covers metadata and every logical key record. It deliberately does
// not cover itself, avoiding recursive archive digests while still detecting
// missing, extra, duplicate, truncated, or modified logical content.
type Manifest struct {
	Algorithm  string           `json:"algorithm"`
	Records    []ManifestRecord `json:"records"`
	TotalBytes int64            `json:"total_bytes"`
}

// Backup streams all namespaces from s into w as a tar.gz archive.
func Backup(s store.Store, w io.Writer, backend string) error {
	return BackupContext(context.Background(), s, w, backend)
}

// BackupContext writes one snapshot-consistent backup and observes ctx while
// reading the source and writing the archive.
func BackupContext(ctx context.Context, s store.Store, w io.Writer, backend string) error {
	if s == nil || w == nil {
		return errors.New("backup source and destination are required")
	}
	log.Info("backup: starting backup")
	started := time.Now()
	gzipWriter := gzip.NewWriter(w)
	tarWriter := tar.NewWriter(gzipWriter)
	backupErr := store.View(ctx, s, func(viewCtx context.Context) error {
		namespaces, err := s.ListNamespaces(viewCtx)
		if err != nil {
			return fmt.Errorf("list namespaces: %w", err)
		}
		slices.Sort(namespaces)
		keysByNamespace := make(map[string][]string, len(namespaces))
		totalKeys := 0
		for _, namespace := range namespaces {
			keys, err := s.List(viewCtx, namespace)
			if err != nil {
				return fmt.Errorf("list keys in %s: %w", namespace, err)
			}
			slices.Sort(keys)
			keysByNamespace[namespace] = keys
			totalKeys += len(keys)
		}
		schemaVersion, err := model.ReadSystemSchemaVersion(viewCtx, s)
		if err != nil {
			return err
		}
		meta := Metadata{Version: "v2", Timestamp: time.Now().UTC(), Backend: backend, Namespaces: namespaces, TotalKeys: totalKeys, SchemaVersion: schemaVersion}
		metaBytes, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}
		if err := writeRecord(tarWriter, metadataFile, metaBytes, meta.Timestamp); err != nil {
			return fmt.Errorf("write metadata: %w", err)
		}
		manifest := Manifest{Algorithm: "sha256", Records: []ManifestRecord{digestRecord(metadataFile, metaBytes)}, TotalBytes: int64(len(metaBytes))}
		for _, namespace := range namespaces {
			keys := keysByNamespace[namespace]
			log.Debug("backup: backing up namespace", "namespace", namespace, "keys", len(keys))
			for _, key := range keys {
				if err := viewCtx.Err(); err != nil {
					return err
				}
				value, err := s.Get(viewCtx, namespace, key)
				if err != nil {
					return fmt.Errorf("get %s/%s: %w", namespace, key, err)
				}
				if err := writeRecord(tarWriter, namespace+"/"+key, value, meta.Timestamp); err != nil {
					return fmt.Errorf("write %s/%s: %w", namespace, key, err)
				}
				manifest.Records = append(manifest.Records, digestRecord(namespace+"/"+key, value))
				manifest.TotalBytes += int64(len(value))
			}
		}
		manifestBytes, err := json.Marshal(manifest)
		if err != nil {
			return fmt.Errorf("marshal manifest: %w", err)
		}
		if err := writeRecord(tarWriter, manifestFile, manifestBytes, meta.Timestamp); err != nil {
			return fmt.Errorf("write manifest: %w", err)
		}
		log.Info("backup: backup completed", "namespaces", len(namespaces), "total_keys", totalKeys, "duration", time.Since(started))
		return nil
	})
	return errors.Join(backupErr, tarWriter.Close(), gzipWriter.Close())
}

func digestRecord(name string, value []byte) ManifestRecord {
	digest := sha256.Sum256(value)
	return ManifestRecord{Name: name, Size: int64(len(value)), SHA256: fmt.Sprintf("%x", digest[:])}
}

func writeRecord(writer *tar.Writer, name string, value []byte, modified time.Time) error {
	header := &tar.Header{Name: name, Size: int64(len(value)), Mode: 0o600, ModTime: modified, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	_, err := writer.Write(value)
	return err
}

// BackupToBytes creates a backup and returns it as bytes.
func BackupToBytes(s store.Store, backend string) ([]byte, error) {
	var buffer bytes.Buffer
	if err := Backup(s, &buffer, backend); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
