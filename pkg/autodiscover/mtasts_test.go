package autodiscover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The MTA-STS policy is served only on a hosted domain's mta-sts host.
func TestMTASTSPolicyServedPerHost(t *testing.T) {
	h := New(nil, Config{MTASTSPolicy: func(_ context.Context, host string) (string, bool) {
		return "version: STSv1\r\n", host == "mta-sts.example.test"
	}})
	for _, test := range []struct {
		host string
		want int
	}{
		{"mta-sts.example.test", http.StatusOK},
		{"MTA-STS.example.test:443", http.StatusOK},
		{"mta-sts.other.test", http.StatusNotFound},
	} {
		request := httptest.NewRequest(http.MethodGet, "https://"+test.host+"/.well-known/mta-sts.txt", nil)
		response := httptest.NewRecorder()
		h.Handle(response, request)
		if response.Code != test.want {
			t.Errorf("%s: status %d, want %d", test.host, response.Code, test.want)
		}
		if test.want == http.StatusOK && response.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Errorf("%s: content type %q", test.host, response.Header().Get("Content-Type"))
		}
	}
}
