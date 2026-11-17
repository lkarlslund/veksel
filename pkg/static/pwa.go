package static

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// The installable web app: a manifest, a service worker, and an offline page.
// The worker and the offline page are templates filled with the
// content-versioned asset URLs, so every asset change produces a different
// worker script and the browser installs it, precaches the new shell, and
// drops the old one.

//go:embed pwa/*
var pwaFiles embed.FS

// ShellAssets are the embedded files the service worker precaches.
var ShellAssets = []string{
	"css/admin.css", "css/app.css", "js/theme.js", "js/app.js", "js/offline.js",
	"fonts/inter-var.woff2", "images/favicon.svg", "images/icon-192.png", "sounds/notify.wav",
}

const (
	// ServiceWorkerPath is the worker script URL; its directory is the
	// worker scope, so it controls the web app under /app/ and nothing else.
	ServiceWorkerPath = "/app/sw.js"
	// ManifestPath is the web app manifest URL.
	ManifestPath = "/app/manifest.webmanifest"
	// OfflinePath is the page the worker shows when a navigation fails.
	OfflinePath = "/app/offline"
)

type pwaDocument struct {
	body []byte
	etag string
}

var (
	pwaOnce                               sync.Once
	pwaWorker, pwaOffline, pwaManifestDoc pwaDocument
	pwaVersion                            string
)

func newPWADocument(body []byte) pwaDocument {
	return pwaDocument{body: body, etag: etagFor(body)}
}

func loadPWA() {
	pwaOnce.Do(func() {
		all := loadAssets()
		names := make([]string, 0, len(all))
		for name := range all {
			names = append(names, name)
		}
		sort.Strings(names)
		worker, err := pwaFiles.ReadFile("pwa/sw.js")
		if err != nil {
			panic("embedded service worker: " + err.Error())
		}
		offline, err := pwaFiles.ReadFile("pwa/offline.html")
		if err != nil {
			panic("embedded offline page: " + err.Error())
		}
		digest := sha256.New()
		for _, name := range names {
			digest.Write([]byte(name + all[name].etag))
		}
		digest.Write(worker)
		digest.Write(offline)
		pwaVersion = hex.EncodeToString(digest.Sum(nil))[:16]

		shell := make([]string, 0, len(ShellAssets)+1)
		for _, name := range ShellAssets {
			shell = append(shell, AssetURL(name))
		}
		shell = append(shell, OfflinePath+"?v="+pwaVersion)
		shellJSON, _ := json.Marshal(shell)
		pwaWorker = newPWADocument([]byte(strings.NewReplacer(
			"__VEKSEL_SW_VERSION__", pwaVersion,
			"__VEKSEL_SHELL_ASSETS__", string(shellJSON),
			"__VEKSEL_OFFLINE_URL__", OfflinePath+"?v="+pwaVersion,
		).Replace(string(worker))))
		pwaOffline = newPWADocument([]byte(strings.NewReplacer(
			"__ADMIN_CSS__", AssetURL("css/admin.css"),
			"__APP_CSS__", AssetURL("css/app.css"),
			"__THEME_JS__", AssetURL("js/theme.js"),
			"__OFFLINE_JS__", AssetURL("js/offline.js"),
			"__FAVICON__", AssetURL("images/favicon.svg"),
		).Replace(string(offline))))
		manifest, _ := json.MarshalIndent(map[string]any{
			"id": "/app/", "name": "Veksel", "short_name": "Veksel",
			"description":      "Mail, calendar, contacts, and files",
			"start_url":        "/app/",
			"scope":            "/app/",
			"display":          "standalone",
			"background_color": "#edf5f4",
			"theme_color":      "#102f38",
			"icons": []map[string]string{
				{"src": AssetURL("images/icon-192.png"), "sizes": "192x192", "type": "image/png", "purpose": "any"},
				{"src": AssetURL("images/icon-512.png"), "sizes": "512x512", "type": "image/png", "purpose": "any"},
				{"src": AssetURL("images/icon-maskable-512.png"), "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
				{"src": AssetURL("images/favicon.svg"), "sizes": "any", "type": "image/svg+xml", "purpose": "any"},
			},
		}, "", "  ")
		pwaManifestDoc = newPWADocument(manifest)
	})
}

// PWAVersion identifies the current service worker and offline shell.
func PWAVersion() string {
	loadPWA()
	return pwaVersion
}

func servePWA(w http.ResponseWriter, r *http.Request, document pwaDocument, contentType, policy string) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Cache-Control", "no-cache")
	h.Set("ETag", document.etag)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	if policy != "" {
		h.Set("Content-Security-Policy", policy)
	}
	if etagMatches(r.Header.Get("If-None-Match"), document.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(document.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(document.body)
	}
}

// ServeServiceWorker serves the versioned worker. It is public, so browser
// update checks keep working after the session ends, and it never caches API
// responses. The worker's own policy limits it to same-origin requests.
func ServeServiceWorker(w http.ResponseWriter, r *http.Request) {
	loadPWA()
	w.Header().Set("Service-Worker-Allowed", "/app/")
	servePWA(w, r, pwaWorker, "text/javascript; charset=utf-8", "default-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'")
}

// ServeOfflinePage serves the offline fallback precached by the worker. It
// carries no account data; its script reads the bounded offline snapshot the
// signed-in app stored in this browser.
func ServeOfflinePage(w http.ResponseWriter, r *http.Request) {
	loadPWA()
	w.Header().Set("X-Frame-Options", "DENY")
	servePWA(w, r, pwaOffline, "text/html; charset=utf-8", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
}

// ServeManifest serves the web app manifest.
func ServeManifest(w http.ResponseWriter, r *http.Request) {
	loadPWA()
	servePWA(w, r, pwaManifestDoc, "application/manifest+json", "")
}
