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
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
)

// Verification is the non-mutating result of reading an entire backup. Legacy
// v1 archives can be structurally valid but cannot claim digest verification.
type Verification struct {
	Metadata   *Metadata `json:"metadata"`
	Verified   bool      `json:"verified"`
	Legacy     bool      `json:"legacy"`
	Algorithm  string    `json:"algorithm,omitempty"`
	Records    int       `json:"records"`
	TotalBytes int64     `json:"total_bytes"`
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.r.Read(p)
	if err == nil {
		if contextErr := r.ctx.Err(); contextErr != nil {
			return n, contextErr
		}
	}
	return n, err
}

func Verify(r io.Reader) (*Verification, error) {
	return VerifyContext(context.Background(), r)
}

// VerifyContext validates the complete compressed stream without mutating a
// store. Resource ceilings match restore so a successful verification means
// the same archive is admissible for restore.
func VerifyContext(ctx context.Context, r io.Reader) (*Verification, error) {
	if r == nil {
		return nil, errors.New("backup source is required")
	}
	gzipReader, err := gzip.NewReader(contextReader{ctx: ctx, r: r})
	if err != nil {
		return nil, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer func() { _ = gzipReader.Close() }()
	tarReader := tar.NewReader(gzipReader)
	seen := make(map[string]struct{})
	observed := make(map[string]ManifestRecord)
	namespaceCounts := make(map[string]int)
	var meta *Metadata
	var manifest *Manifest
	var totalArchiveBytes int64
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, fmt.Errorf("read tar entry: %w", nextErr)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > maxLegacyRestoreBytes || path.Clean(header.Name) != header.Name || strings.HasPrefix(header.Name, "/") {
			return nil, errors.New("unsafe backup archive entry")
		}
		if len(seen) >= maxLegacyRestoreEntries || totalArchiveBytes > maxLegacyRestoreBytes-header.Size {
			return nil, errors.New("backup archive exceeds restore limits")
		}
		totalArchiveBytes += header.Size
		if _, duplicate := seen[header.Name]; duplicate {
			return nil, fmt.Errorf("duplicate backup archive entry %q", header.Name)
		}
		seen[header.Name] = struct{}{}
		data, readErr := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if readErr != nil || int64(len(data)) != header.Size {
			return nil, fmt.Errorf("truncated backup archive entry %q", header.Name)
		}
		switch header.Name {
		case metadataFile:
			if meta != nil {
				return nil, errors.New("duplicate backup metadata")
			}
			if err := json.Unmarshal(data, &meta); err != nil {
				return nil, fmt.Errorf("parse metadata: %w", err)
			}
			observed[header.Name] = digestRecord(header.Name, data)
		case manifestFile:
			if manifest != nil {
				return nil, errors.New("duplicate backup manifest")
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				return nil, fmt.Errorf("parse manifest: %w", err)
			}
		default:
			slash := strings.Index(header.Name, "/")
			if slash <= 0 || slash == len(header.Name)-1 {
				return nil, fmt.Errorf("invalid backup archive entry %q", header.Name)
			}
			namespaceCounts[header.Name[:slash]]++
			observed[header.Name] = digestRecord(header.Name, data)
		}
	}
	if meta == nil {
		return nil, fmt.Errorf("archive missing %s", metadataFile)
	}
	if (meta.Version != "v1" && meta.Version != "v2") || meta.TotalKeys != len(observed)-1 || len(meta.Namespaces) > 4096 {
		return nil, errors.New("invalid backup metadata")
	}
	declaredNamespaces := make(map[string]struct{}, len(meta.Namespaces))
	for _, namespace := range meta.Namespaces {
		if namespace == "" {
			return nil, errors.New("invalid backup namespace list")
		}
		if _, duplicate := declaredNamespaces[namespace]; duplicate {
			return nil, errors.New("invalid backup namespace list")
		}
		declaredNamespaces[namespace] = struct{}{}
	}
	for namespace := range namespaceCounts {
		if _, ok := declaredNamespaces[namespace]; !ok {
			return nil, fmt.Errorf("backup record belongs to unknown namespace %s", namespace)
		}
	}
	if err := validateManifest(meta, manifest, observed); err != nil {
		return nil, err
	}
	if err := model.CheckSystemSchemaVersion(meta.SchemaVersion); err != nil {
		return nil, err
	}
	result := &Verification{Metadata: meta, Legacy: meta.Version == "v1", Records: len(observed), TotalBytes: totalArchiveBytes}
	if manifest != nil {
		result.Verified, result.Algorithm, result.TotalBytes = true, manifest.Algorithm, manifest.TotalBytes
	}
	return result, nil
}
