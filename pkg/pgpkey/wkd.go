package pgpkey

import (
	"context"
	"crypto/sha1" //nolint:gosec // WKD (draft-koch-openpgp-webkey-service) mandates SHA-1 for the lookup name
	"net"
	"net/http"
	"strings"
)

const zBase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

// ZBase32 encodes data with the z-base-32 alphabet of RFC 6189 without
// padding.
func ZBase32(data []byte) string {
	var out strings.Builder
	var buffer, bits uint
	for _, b := range data {
		buffer, bits = buffer<<8|uint(b), bits+8
		for bits >= 5 {
			out.WriteByte(zBase32Alphabet[buffer>>(bits-5)&31])
			bits -= 5
		}
	}
	if bits > 0 {
		out.WriteByte(zBase32Alphabet[buffer<<(5-bits)&31])
	}
	return out.String()
}

// WKDHash returns the Web Key Directory lookup name of a local part: the
// z-base-32 encoding of the SHA-1 of its lower-cased UTF-8 form.
func WKDHash(local string) string {
	sum := sha1.Sum([]byte(strings.ToLower(local))) //nolint:gosec // required by the WKD draft
	return ZBase32(sum[:])
}

// wkdHashLength is the length of a z-base-32 SHA-1 (160 bits).
const wkdHashLength = 32

// AdvancedHost is the host name of the WKD advanced method for domain.
func AdvancedHost(domain string) string { return "openpgpkey." + domain }

// Directory serves published public keys over the Web Key Directory:
// the advanced method on openpgpkey.<domain> and the direct method on the
// domain itself, each with its policy file. Keys are looked up by domain and
// hash only for hosted domains while Enabled reports true.
type Directory struct {
	// Enabled reports whether WKD is switched on; it is read per request.
	Enabled func() bool
	// Hosted reports whether domain is a hosted mail domain.
	Hosted func(ctx context.Context, domain string) (bool, error)
	// Key returns the binary key published for the hash of a local part at
	// domain, and whether there is one for an enabled identity.
	Key func(ctx context.Context, domain, hash string) ([]byte, bool, error)
}

const wellKnown = "/.well-known/openpgpkey/"

// ServeHTTP implements http.Handler for paths under /.well-known/openpgpkey/.
func (d *Directory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Keys are public and fetched by browsers' mail clients, so any origin
	// may read them (the draft's CORS requirement).
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if d.Enabled != nil && !d.Enabled() {
		http.NotFound(w, r)
		return
	}
	domain, hash, policy, ok := route(requestHost(r), strings.TrimPrefix(r.URL.Path, wellKnown))
	if !ok {
		http.NotFound(w, r)
		return
	}
	hosted, err := d.Hosted(r.Context(), domain)
	if err != nil {
		http.Error(w, "directory unavailable", http.StatusServiceUnavailable)
		return
	}
	if !hosted {
		http.NotFound(w, r)
		return
	}
	if policy {
		// An empty policy file announces WKD support without flags.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		return
	}
	binary, found, err := d.Key(r.Context(), domain, hash)
	if err != nil {
		http.Error(w, "directory unavailable", http.StatusServiceUnavailable)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(binary)
	}
}

// route classifies the path below /.well-known/openpgpkey/ received for
// host. The advanced method names the domain in the path and must arrive on
// openpgpkey.<domain>; the direct method uses the host as the domain.
func route(host, path string) (domain, hash string, policy, ok bool) {
	parts := strings.Split(path, "/")
	if len(parts) > 1 && parts[0] != "hu" && parts[0] != "policy" {
		domain, parts = strings.ToLower(parts[0]), parts[1:]
		if host != AdvancedHost(domain) {
			return "", "", false, false
		}
	} else {
		domain = host
	}
	switch {
	case len(parts) == 1 && parts[0] == "policy":
		return domain, "", true, domain != ""
	case len(parts) == 2 && parts[0] == "hu" && validHash(parts[1]):
		return domain, parts[1], false, domain != ""
	}
	return "", "", false, false
}

func validHash(hash string) bool {
	if len(hash) != wkdHashLength {
		return false
	}
	for _, c := range hash {
		if !strings.ContainsRune(zBase32Alphabet, c) {
			return false
		}
	}
	return true
}

// requestHost returns the lower-cased host of r without port or trailing dot.
func requestHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
