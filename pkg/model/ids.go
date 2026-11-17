package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// newResourceID returns an opaque, non-guessable storage identity. Resource
// paths and display names are deliberately not encoded in IDs so they can be
// changed without rewriting dependent records.
func newResourceID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate %s id: %w", prefix, err)
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}

func specialFolderID(userID, specialUse string) string {
	sum := sha256.Sum256([]byte("veksel:folder:" + normalizeID(userID) + ":" + specialUse))
	return "fld_" + hex.EncodeToString(sum[:16])
}
