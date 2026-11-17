// Package static embeds the web asset files so the binary is self-contained.
package static

import (
	"embed"
	"net/http"
	"strconv"
)

//go:embed css/* js/* fonts/* images/* sounds/*
var Content embed.FS

// FS is the embedded filesystem for static web assets.
// The embed root contains css/, js/, fonts/ directories.
// When served behind /static/, requests like /static/js/app.js
// correctly map to js/app.js inside the embed.
var FS http.FileSystem = http.FS(Content)

var faviconSVG, faviconETag = loadFavicon()

func loadFavicon() ([]byte, string) {
	data, err := Content.ReadFile("images/favicon.svg")
	if err != nil {
		panic("embedded favicon: " + err.Error())
	}
	return data, etagFor(data)
}

// ServeFavicon serves the shared browser identity for every Veksel HTML shell.
func ServeFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=86400, must-revalidate")
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("ETag", faviconETag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if etagMatches(r.Header.Get("If-None-Match"), faviconETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(faviconSVG)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(faviconSVG)
}
