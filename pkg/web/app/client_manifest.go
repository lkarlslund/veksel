package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"sort"

	staticassets "github.com/lkarlslund/veksel/pkg/static"
)

type clientManifest struct {
	HTML       string `json:"html"`
	JavaScript string `json:"javascript"`
	CSS        string `json:"css"`
	Revision   string `json:"revision"`
}

func buildClientManifest() (clientManifest, error) {
	htmlFiles, err := fs.Glob(templateFS, "templates/*.gohtml")
	if err != nil {
		return clientManifest{}, fmt.Errorf("list client templates: %w", err)
	}
	sort.Strings(htmlFiles)
	htmlHash, err := hashFiles(templateFS, htmlFiles...)
	if err != nil {
		return clientManifest{}, err
	}
	javaScriptHash, err := hashFiles(staticassets.Content, "js/theme.js", "js/app.js", "js/share.js")
	if err != nil {
		return clientManifest{}, err
	}
	cssHash, err := hashFiles(staticassets.Content, "css/admin.css", "css/app.css")
	if err != nil {
		return clientManifest{}, err
	}
	revision := hashBytes([]byte(htmlHash + javaScriptHash + cssHash))
	return clientManifest{HTML: htmlHash, JavaScript: javaScriptHash, CSS: cssHash, Revision: revision}, nil
}

func hashFiles(source fs.FS, names ...string) (string, error) {
	hash := sha256.New()
	for _, name := range names {
		data, err := fs.ReadFile(source, name)
		if err != nil {
			return "", fmt.Errorf("read client asset %q: %w", name, err)
		}
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write(data)
	}
	return hex.EncodeToString(hash.Sum(nil))[:16], nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:16]
}

func (h *Handler) apiClientManifest(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	jsonResponse(w, http.StatusOK, h.clientManifest)
}
