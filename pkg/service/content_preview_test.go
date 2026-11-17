package service

import "testing"

func TestContentPreviewable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		contentType string
		size        int64
		want        bool
	}{
		{name: "plain text", contentType: "text/plain; charset=utf-8", size: MaxTextPreviewBytes, want: true},
		{name: "CSV mixed case", contentType: "Text/CSV", size: 1, want: true},
		{name: "PNG", contentType: "image/png", size: MaxBinaryPreviewBytes, want: true},
		{name: "PDF", contentType: "application/pdf", size: 0, want: true},
		{name: "oversized text", contentType: "text/plain", size: MaxTextPreviewBytes + 1},
		{name: "oversized PDF", contentType: "application/pdf", size: MaxBinaryPreviewBytes + 1},
		{name: "negative size", contentType: "image/jpeg", size: -1},
		{name: "active HTML", contentType: "text/html", size: 1},
		{name: "active SVG", contentType: "image/svg+xml", size: 1},
		{name: "XML", contentType: "application/xml", size: 1},
		{name: "office document", contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", size: 1},
		{name: "unknown", contentType: "application/octet-stream", size: 1},
		{name: "invalid media type", contentType: "text/plain; broken", size: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := ContentPreviewable(test.contentType, test.size); got != test.want {
				t.Fatalf("ContentPreviewable(%q, %d) = %t, want %t", test.contentType, test.size, got, test.want)
			}
		})
	}
}
