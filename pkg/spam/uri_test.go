package spam

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestExtractURIDomainsMemoMatchesFreshScans(t *testing.T) {
	t.Parallel()
	var body strings.Builder
	body.WriteString("Subject: links\r\nContent-Type: text/plain\r\n\r\n")
	for index := range 12 {
		fmt.Fprintf(&body, "see https://www.site%d.com/page and mail me@host%d.org\r\n", index, index)
	}
	body.WriteString("defanged evil[.]shady-host.net\r\n")
	raw := []byte(body.String())
	parsed := parseContent(raw)
	for _, max := range []int{3, 10, 2, 50, 7, 50} {
		got := extractURIDomains(parsed, max)
		want := scanURIDomains(parseContent(raw), max)
		if !slices.Equal(got, want) {
			t.Fatalf("max %d: memoized %v, fresh %v", max, got, want)
		}
	}
	if got := extractURIDomains(parsed, 50); !slices.Contains(got, "shady-host.net") {
		t.Fatalf("defanged domain missing from %v", got)
	}
}
