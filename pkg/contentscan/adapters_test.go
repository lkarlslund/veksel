package contentscan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/virus"
)

func TestMalwareAdapterProjectsBuiltinEvidence(t *testing.T) {
	adapter := NewMalwareAdapter(virus.NewBuiltinScanner())
	result, err := adapter.Scan(t.Context(), Message{Content: []byte(virus.EICARTestString)})
	if err != nil || result.Verdict != VerdictMalware || len(result.MalwareNames) != 1 || result.MalwareNames[0] != "EICAR-AV-Test" {
		t.Fatalf("result = %+v, error = %v", result, err)
	}
}

func TestRspamdScannerProducesSortedTypedEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/checkv2" || r.Header.Get("Password") != "secret" || r.Header.Get("From") != "sender@example.test" || r.Header.Get("Deliver-To") != "alice@example.test" || r.Header.Get("IP") != "192.0.2.1" {
			t.Errorf("request path=%q headers=%v", r.URL.Path, r.Header)
		}
		content, _ := io.ReadAll(r.Body)
		if string(content) != "message" {
			t.Errorf("content = %q", content)
		}
		_, _ = io.WriteString(w, `{"score":8.5,"required_score":6,"action":"add header","symbols":{"Z_LAST":{"score":1},"A_FIRST":{"score":7.5,"description":"evidence"}}}`)
	}))
	defer server.Close()
	scanner, err := NewRspamdScanner(server.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Scan(t.Context(), Message{Content: []byte("message"), EnvelopeFrom: "sender@example.test", Recipient: "alice@example.test", RemoteIP: "192.0.2.1"})
	if err != nil || result.Verdict != VerdictSpam || result.Score != 8.5 || len(result.Symbols) != 2 || result.Symbols[0].Name != "A_FIRST" {
		t.Fatalf("result = %+v, error = %v", result, err)
	}
}

func TestRspamdScannerDetectsMalwareAndBoundsResponse(t *testing.T) {
	t.Run("malware", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"action":"reject","symbols":{"CLAM_VIRUS":{"score":10,"options":["Eicar-Test-Signature"]}}}`)
		}))
		defer server.Close()
		scanner, _ := NewRspamdScanner(server.URL, "", nil)
		result, err := scanner.Scan(t.Context(), Message{Content: []byte("message")})
		if err != nil || result.Verdict != VerdictMalware || len(result.MalwareNames) != 1 || result.MalwareNames[0] != "Eicar-Test-Signature" {
			t.Fatalf("result = %+v, error = %v", result, err)
		}
	})
	t.Run("response limit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, strings.Repeat("x", rspamdMaxResponseBytes+1))
		}))
		defer server.Close()
		scanner, _ := NewRspamdScanner(server.URL, "", nil)
		if _, err := scanner.Scan(t.Context(), Message{Content: []byte("message")}); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
			t.Fatalf("oversized response error = %v", err)
		}
	})
}

func TestRspamdScannerRefusesRedirectAndSupportsTraining(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("scanner followed a redirect")
	}))
	defer target.Close()
	learned := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/checkv2":
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		case "/learnspam", "/learnham":
			learned <- r.URL.Path
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	scanner, _ := NewRspamdScanner(server.URL, "", nil)
	if _, err := scanner.Scan(t.Context(), Message{Content: []byte("message")}); err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("redirect error = %v", err)
	}
	if err := scanner.Learn(t.Context(), []byte("message"), true); err != nil {
		t.Fatal(err)
	}
	if path := <-learned; path != "/learnspam" {
		t.Fatalf("learn spam path = %q", path)
	}
	if err := scanner.Learn(t.Context(), []byte("message"), false); err != nil {
		t.Fatal(err)
	}
	if path := <-learned; path != "/learnham" {
		t.Fatalf("learn ham path = %q", path)
	}
}

func TestNewRspamdScannerRejectsUnsafeEndpointsAndCredentials(t *testing.T) {
	for _, endpoint := range []string{"", "ftp://example.test", "http://user@example.test", "http://example.test/?query=1"} {
		if _, err := NewRspamdScanner(endpoint, "", nil); err == nil {
			t.Fatalf("endpoint %q was accepted", endpoint)
		}
	}
	if _, err := NewRspamdScanner("http://example.test", "secret\r\nInjected: yes", nil); err == nil {
		t.Fatal("unsafe password was accepted")
	}
}

func TestRspamdCancellationPropagates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	scanner, _ := NewRspamdScanner(server.URL, "", nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := scanner.Scan(ctx, Message{Content: []byte("message")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}
