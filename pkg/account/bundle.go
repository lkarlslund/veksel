package account

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/base64"
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

const bundleVersion = 3

type bundleHeader struct {
	Version      int            `json:"version"`
	Manifest     Manifest       `json:"manifest"`
	ExportedAt   time.Time      `json:"exported_at"`
	Namespaces   []string       `json:"namespaces,omitempty"`
	Verification *TransferStats `json:"verification,omitempty"`
}

type bundleMetadata struct {
	Namespace string          `json:"namespace"`
	Key       string          `json:"key"`
	Value     json.RawMessage `json:"value"`
}

// ExportBundle writes a portable logical account image. Backend files and
// stale generations are intentionally excluded. The bundle of an encrypted
// generation is itself encrypted under a fresh key wrapped by the
// installation key ring, so it restores only where that key ring exists.
func ExportBundle(ctx context.Context, entry Entry, generation *Generation, destination io.Writer) error {
	if generation == nil {
		return errors.New("account generation is required")
	}
	var sealer io.WriteCloser
	if generation.Encrypted {
		var err error
		if sealer, err = sealBundle(destination, entry.Manifest.ID, generation.keys); err != nil {
			return err
		}
		destination = sealer
	}
	gzipWriter := gzip.NewWriter(destination)
	tarWriter := tar.NewWriter(gzipWriter)
	exportErr := store.View(ctx, generation.Index, func(viewCtx context.Context) error {
		namespaces, err := generation.Index.ListNamespaces(viewCtx)
		if err != nil {
			return err
		}
		slices.Sort(namespaces)
		verification, err := VerifyTransfer(viewCtx, generation)
		if err != nil {
			return fmt.Errorf("verify account export snapshot: %w", err)
		}
		header, err := json.Marshal(bundleHeader{
			Version: bundleVersion, Manifest: entry.Manifest, ExportedAt: time.Now().UTC(), Namespaces: namespaces, Verification: &verification,
		})
		if err != nil {
			return err
		}
		if err := writeTarRecord(tarWriter, "bundle.json", header); err != nil {
			return err
		}
		for _, namespace := range namespaces {
			if namespace == model.NSItems || namespace == model.NSItemHistory {
				continue
			}
			err := generation.Index.Iterate(viewCtx, namespace, "", func(key string, value []byte) (bool, error) {
				record, marshalErr := json.Marshal(bundleMetadata{Namespace: namespace, Key: key, Value: json.RawMessage(value)})
				if marshalErr != nil {
					return false, marshalErr
				}
				name := "metadata/" + base64.RawURLEncoding.EncodeToString([]byte(namespace+"\x00"+key)) + ".json"
				return true, writeTarRecord(tarWriter, name, record)
			})
			if err != nil {
				return err
			}
		}
		typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
		itemIDs, err := generation.Index.Scan(viewCtx, model.NSItems, "itm_")
		if err != nil {
			return err
		}
		slices.Sort(itemIDs)
		for _, itemID := range itemIDs {
			item, err := typed.ItemStore().Get(viewCtx, itemID)
			if err != nil {
				return err
			}
			data, err := json.Marshal(item)
			if err != nil {
				return err
			}
			if err := writeTarRecord(tarWriter, "items/"+item.ID+".json", data); err != nil {
				return err
			}
		}
		if slices.Contains(namespaces, model.NSItemHistory) {
			versions, err := typed.ItemHistoryStore().ListAll(viewCtx)
			if err != nil {
				return err
			}
			for _, version := range versions {
				data, err := json.Marshal(version)
				if err != nil {
					return err
				}
				if err := writeTarRecord(tarWriter, "item-history/"+version.ID+".json", data); err != nil {
					return err
				}
			}
		}
		return nil
	})
	err := errors.Join(exportErr, tarWriter.Close(), gzipWriter.Close())
	if sealer != nil && err == nil {
		err = sealer.Close()
	}
	return err
}

// ImportBundle restores a portable image into an empty generation and returns
// the source manifest for controlled identity checks by the caller.
func ImportBundle(ctx context.Context, source io.Reader, target *Generation) (Manifest, error) {
	if target == nil {
		return Manifest{}, errors.New("target generation is required")
	}
	source, _, err := openBundle(source, target.keys)
	if err != nil {
		return Manifest{}, err
	}
	gzipReader, err := gzip.NewReader(source)
	if err != nil {
		return Manifest{}, fmt.Errorf("open account bundle: %w", err)
	}
	defer func() { _ = gzipReader.Close() }()
	tarReader := tar.NewReader(gzipReader)
	typed := model.NewTypedStoreWithObjects(target.Index, target.Engine, target.Objects)
	var manifest Manifest
	var expected *TransferStats
	headerSeen := false
	seenEntries := make(map[string]struct{})
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("read account bundle: %w", err)
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > 1<<30 || path.Clean(header.Name) != header.Name || strings.HasPrefix(header.Name, "/") {
			return Manifest{}, errors.New("unsafe account bundle entry")
		}
		if _, duplicate := seenEntries[header.Name]; duplicate {
			return Manifest{}, errors.New("duplicate account bundle entry")
		}
		seenEntries[header.Name] = struct{}{}
		data, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil || int64(len(data)) != header.Size {
			return Manifest{}, errors.New("truncated account bundle entry")
		}
		switch {
		case header.Name == "bundle.json":
			var bundle bundleHeader
			if err := json.Unmarshal(data, &bundle); err != nil || bundle.Version < 1 || bundle.Version > bundleVersion || bundle.Manifest.Validate() != nil || (bundle.Version >= 3 && (bundle.Verification == nil || bundle.Verification.Digest == "" || !validBundleNamespaces(bundle.Namespaces, bundle.Verification.Namespaces))) {
				return Manifest{}, errors.New("invalid account bundle header")
			}
			manifest, expected, headerSeen = bundle.Manifest, bundle.Verification, true
			for _, namespace := range bundle.Namespaces {
				if err := ensureNamespace(ctx, target.Index, namespace); err != nil {
					return Manifest{}, err
				}
			}
		case strings.HasPrefix(header.Name, "metadata/"):
			if !headerSeen {
				return Manifest{}, errors.New("account bundle header must be first")
			}
			var record bundleMetadata
			if err := json.Unmarshal(data, &record); err != nil || record.Namespace == "" || record.Key == "" || record.Namespace == model.NSItems || record.Namespace == model.NSItemHistory || !json.Valid(record.Value) {
				return Manifest{}, errors.New("invalid account metadata record")
			}
			wantName := "metadata/" + base64.RawURLEncoding.EncodeToString([]byte(record.Namespace+"\x00"+record.Key)) + ".json"
			if header.Name != wantName {
				return Manifest{}, errors.New("account metadata filename does not match record identity")
			}
			if err := ensureNamespace(ctx, target.Index, record.Namespace); err != nil {
				return Manifest{}, err
			}
			if err := target.Index.Set(ctx, record.Namespace, record.Key, record.Value); err != nil {
				return Manifest{}, err
			}
		case strings.HasPrefix(header.Name, "items/"):
			if !headerSeen {
				return Manifest{}, errors.New("account bundle header must be first")
			}
			if err := ensureNamespace(ctx, target.Index, model.NSItems); err != nil {
				return Manifest{}, err
			}
			var item model.Item
			if err := json.Unmarshal(data, &item); err != nil || item.ID == "" {
				return Manifest{}, errors.New("invalid account item record")
			}
			if header.Name != "items/"+item.ID+".json" {
				return Manifest{}, errors.New("account item filename does not match record identity")
			}
			if err := typed.ItemStore().RestoreItem(ctx, item); err != nil {
				return Manifest{}, err
			}
		case strings.HasPrefix(header.Name, "item-history/"):
			if !headerSeen {
				return Manifest{}, errors.New("account bundle header must be first")
			}
			var version model.ItemVersion
			if err := json.Unmarshal(data, &version); err != nil || version.ID == "" {
				return Manifest{}, errors.New("invalid account item history record")
			}
			if header.Name != "item-history/"+version.ID+".json" {
				return Manifest{}, errors.New("account item history filename does not match record identity")
			}
			if err := typed.ItemHistoryStore().RestoreSnapshot(ctx, version); err != nil {
				return Manifest{}, err
			}
		default:
			return Manifest{}, fmt.Errorf("unknown account bundle entry %q", header.Name)
		}
	}
	if !headerSeen {
		return Manifest{}, errors.New("account bundle header is missing")
	}
	if expected != nil {
		actual, err := VerifyTransfer(ctx, target)
		if err != nil {
			return Manifest{}, fmt.Errorf("verify restored account bundle: %w", err)
		}
		if !sameTransferImage(*expected, actual) {
			return Manifest{}, fmt.Errorf("account bundle verification mismatch: got digest %s, want %s", actual.Digest, expected.Digest)
		}
	}
	return manifest, nil
}

func sameTransferImage(expected, actual TransferStats) bool {
	return expected.Namespaces == actual.Namespaces &&
		expected.MetadataKeys == actual.MetadataKeys &&
		expected.Items == actual.Items &&
		expected.HistoryVersions == actual.HistoryVersions &&
		expected.PayloadBytes == actual.PayloadBytes &&
		expected.Digest == actual.Digest
}

func validBundleNamespaces(namespaces []string, expected int) bool {
	if len(namespaces) != expected || len(namespaces) > 4096 {
		return false
	}
	for index, namespace := range namespaces {
		if namespace == "" || (index > 0 && namespaces[index-1] >= namespace) {
			return false
		}
	}
	return true
}

func writeTarRecord(writer *tar.Writer, name string, data []byte) error {
	header := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	_, err := writer.Write(data)
	return err
}
