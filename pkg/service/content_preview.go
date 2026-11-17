package service

import (
	"mime"
	"strings"
)

const (
	MaxTextPreviewBytes   = 2 << 20
	MaxBinaryPreviewBytes = 10 << 20
)

// ContentPreviewLimit returns the maximum bytes accepted for an inline
// preview of contentType. Active and sniff-dependent formats are deliberately
// excluded even when their file extension appears familiar.
func ContentPreviewLimit(contentType string) (int64, bool) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return 0, false
	}
	switch strings.ToLower(mediaType) {
	case "text/plain", "text/csv":
		return MaxTextPreviewBytes, true
	case "image/jpeg", "image/png", "image/gif", "image/webp", "application/pdf":
		return MaxBinaryPreviewBytes, true
	default:
		return 0, false
	}
}

// ContentPreviewable classifies content using the same type and size limits
// enforced again at each preview response boundary.
func ContentPreviewable(contentType string, size int64) bool {
	limit, ok := ContentPreviewLimit(contentType)
	return ok && size >= 0 && size <= limit
}
