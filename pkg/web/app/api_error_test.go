package app

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/service"
)

func TestAPIErrorTemporarilyUnavailable(t *testing.T) {
	recorder := httptest.NewRecorder()
	apiError(recorder, account.ErrTemporarilyUnavailable)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if got := recorder.Header().Get("Retry-After"); got != "5" {
		t.Fatalf("Retry-After = %q, want 5", got)
	}
}

func TestAPIErrorItemUpdateConflict(t *testing.T) {
	recorder := httptest.NewRecorder()
	apiError(recorder, errors.Join(service.ErrItemUpdateConflict, errors.New("stale")))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusConflict)
	}
}
