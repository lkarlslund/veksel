package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/ratelimit"
)

func TestLoginThrottlesRepeatedFailuresPerClient(t *testing.T) {
	handler, ts := testHandler(t)
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	throttle := ratelimit.NewAuthThrottleWithLimits(50, 3, 15*time.Minute)
	throttle.SetClock(func() time.Time { return now })
	handler.ConfigureLoginThrottle(throttle)
	mux := http.NewServeMux()
	handler.Register(mux)

	const csrf = "test-csrf-token"
	formLogin := func(remoteAddr, password string) *httptest.ResponseRecorder {
		form := url.Values{"_csrf": {csrf}, "username": {"alice"}, "password": {password}}
		request := httptest.NewRequest(http.MethodPost, "/app/login", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("X-Forwarded-For", "203.0.113.50")
		request.AddCookie(&http.Cookie{Name: csrfCookie, Value: csrf})
		request.RemoteAddr = remoteAddr
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		return recorder
	}
	jsonLogin := func(remoteAddr, password string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"username": "ALICE", "password": password})
		request := httptest.NewRequest(http.MethodPost, "/api/v1/session/login", strings.NewReader(string(body)))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		request.AddCookie(&http.Cookie{Name: csrfCookie, Value: csrf})
		request.RemoteAddr = remoteAddr
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		return recorder
	}

	if response := formLogin("192.0.2.1:1000", "password123"); response.Code != http.StatusFound || response.Header().Get("Location") != "/app/" {
		t.Fatalf("initial login status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	for range 2 {
		if response := formLogin("192.0.2.1:1001", "wrong"); response.Code != http.StatusFound || !strings.Contains(response.Header().Get("Location"), "error=") {
			t.Fatalf("failed form login status=%d location=%q", response.Code, response.Header().Get("Location"))
		}
	}
	if response := jsonLogin("192.0.2.1:1002", "wrong"); response.Code != http.StatusUnauthorized {
		t.Fatalf("failed JSON login status=%d", response.Code)
	}

	// The correct password is refused: the throttle runs before verification.
	response := formLogin("192.0.2.1:1003", "password123")
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "300" {
		t.Fatalf("throttled form login status=%d retry-after=%q", response.Code, response.Header().Get("Retry-After"))
	}
	response = jsonLogin("192.0.2.1:1004", "password123")
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" || !strings.Contains(response.Body.String(), `"error"`) {
		t.Fatalf("throttled JSON login status=%d retry-after=%q body=%s", response.Code, response.Header().Get("Retry-After"), response.Body.String())
	}
	// Another peer is unaffected; forwarding headers do not select the bucket.
	if response := jsonLogin("192.0.2.2:1000", "password123"); response.Code != http.StatusOK {
		t.Fatalf("different IP login status=%d body=%s", response.Code, response.Body.String())
	}

	now = now.Add(5 * time.Minute)
	if response := formLogin("192.0.2.1:1005", "password123"); response.Code != http.StatusFound || response.Header().Get("Location") != "/app/" {
		t.Fatalf("login after refill status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}
