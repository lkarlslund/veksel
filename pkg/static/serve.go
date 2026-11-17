package static

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
)

// asset is one embedded file with its precomputed validators and encodings.
type asset struct {
	data        []byte
	gzipped     []byte // nil when the type is not compressible or gzip does not help
	etag        string
	version     string // short content hash used in ?v= URLs
	contentType string
}

var (
	assetsOnce sync.Once
	assets     map[string]*asset
)

func etagFor(data []byte) string {
	digest := sha256.Sum256(data)
	return `"` + hex.EncodeToString(digest[:16]) + `"`
}

func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == "*" || candidate == etag {
			return true
		}
	}
	return false
}

func contentTypeFor(name string) string {
	switch path.Ext(name) {
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".html":
		return "text/html; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".woff2":
		return "font/woff2"
	case ".png":
		return "image/png"
	case ".wav":
		return "audio/wav"
	}
	if t := mime.TypeByExtension(path.Ext(name)); t != "" {
		return t
	}
	return "application/octet-stream"
}

func compressible(contentType string) bool {
	return strings.HasPrefix(contentType, "text/") || strings.HasPrefix(contentType, "image/svg+xml") ||
		strings.Contains(contentType, "json") || strings.Contains(contentType, "javascript")
}

func loadAssets() map[string]*asset {
	assetsOnce.Do(func() {
		assets = map[string]*asset{}
		_ = fs.WalkDir(Content, ".", func(name string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			data, err := Content.ReadFile(name)
			if err != nil {
				return err
			}
			etag := etagFor(data)
			a := &asset{data: data, etag: etag, version: strings.Trim(etag, `"`)[:16], contentType: contentTypeFor(name)}
			if compressible(a.contentType) {
				var buf bytes.Buffer
				zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
				_, _ = zw.Write(data)
				_ = zw.Close()
				if buf.Len() < len(data) {
					a.gzipped = buf.Bytes()
				}
			}
			assets[name] = a
			return nil
		})
	})
	return assets
}

// AssetURL returns the content-versioned URL for an embedded asset such as
// "js/app.js". The version changes whenever the file content changes, so the
// URL can be cached immutably. Unknown names return an unversioned URL.
func AssetURL(name string) string {
	if a, ok := loadAssets()[name]; ok {
		return "/static/" + name + "?v=" + a.version
	}
	return "/static/" + name
}

func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		if name := strings.ToLower(strings.TrimSpace(fields[0])); name != "gzip" && name != "*" {
			continue
		}
		for _, p := range fields[1:] {
			if p = strings.TrimSpace(p); strings.HasPrefix(p, "q=") {
				if q, err := strconv.ParseFloat(p[2:], 64); err == nil && q == 0 {
					return false
				}
			}
		}
		return true
	}
	return false
}

// Handler serves the embedded assets under a prefix-stripped path (mount it
// with http.StripPrefix("/static", ...)). Every response carries a strong
// content-hash ETag and honours If-None-Match. A request whose ?v= equals the
// file's current content hash is cached immutably for a year; anything else
// must revalidate. Compressible files are gzipped once and served precompressed.
func Handler() http.Handler {
	loadAssets()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a, ok := assets[strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", a.contentType)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("ETag", a.etag)
		if a.gzipped != nil {
			h.Add("Vary", "Accept-Encoding")
		}
		if r.URL.Query().Get("v") == a.version {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "no-cache")
		}
		body := a.data
		gz := a.gzipped != nil && acceptsGzip(r)
		if gz {
			// Distinct representation, distinct strong validator.
			h.Set("ETag", a.etag[:len(a.etag)-1]+`-gzip"`)
		}
		if inm := r.Header.Get("If-None-Match"); etagMatches(inm, a.etag) || (gz && etagMatches(inm, h.Get("ETag"))) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if gz {
			body = a.gzipped
			h.Set("Content-Encoding", "gzip")
		}
		h.Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	})
}
