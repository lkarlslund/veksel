package loadtest

import (
	"context"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestLoadIMAP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := &Config{
		Concurrency:        5,
		Duration:           2 * time.Second,
		NumUsers:           3,
		NumMessagesPerUser: 5,
		Scenarios:          ScenarioIMAP,
	}

	results, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Name != "IMAP" {
		t.Fatalf("expected IMAP result, got %s", r.Name)
	}
	if r.TotalReqs == 0 {
		t.Fatal("expected at least 1 request")
	}
	t.Logf("IMAP: %d reqs, %d errors, %.1f req/sec, p50=%s, p95=%s, p99=%s",
		r.TotalReqs, r.Errors, r.ReqPerSec, r.P50, r.P95, r.P99)
}

func TestLoadSMTP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := &Config{
		Concurrency:        5,
		Duration:           2 * time.Second,
		NumUsers:           3,
		NumMessagesPerUser: 5,
		Scenarios:          ScenarioSMTP,
	}

	results, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Name != "SMTP" {
		t.Fatalf("expected SMTP result, got %s", r.Name)
	}
	if r.TotalReqs == 0 {
		t.Fatal("expected at least 1 request")
	}
	t.Logf("SMTP: %d reqs, %d errors, %.1f req/sec, p50=%s, p95=%s, p99=%s",
		r.TotalReqs, r.Errors, r.ReqPerSec, r.P50, r.P95, r.P99)
}

func TestLoadHTTP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := &Config{
		Concurrency:        10,
		Duration:           2 * time.Second,
		NumUsers:           3,
		NumMessagesPerUser: 5,
		Scenarios:          ScenarioHTTP,
	}

	results, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Name != "HTTP" {
		t.Fatalf("expected HTTP result, got %s", r.Name)
	}
	if r.TotalReqs == 0 {
		t.Fatal("expected at least 1 request")
	}
	t.Logf("HTTP: %d reqs, %d errors, %.1f req/sec, p50=%s, p95=%s, p99=%s",
		r.TotalReqs, r.Errors, r.ReqPerSec, r.P50, r.P95, r.P99)
}

func TestLoadCalDAV(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := &Config{
		Concurrency:        5,
		Duration:           2 * time.Second,
		NumUsers:           3,
		NumMessagesPerUser: 5,
		Scenarios:          ScenarioCalDAV,
	}

	results, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Name != "CalDAV" {
		t.Fatalf("expected CalDAV result, got %s", r.Name)
	}
	if r.TotalReqs == 0 {
		t.Fatal("expected at least 1 request")
	}
	t.Logf("CalDAV: %d reqs, %d errors, %.1f req/sec, p50=%s, p95=%s, p99=%s",
		r.TotalReqs, r.Errors, r.ReqPerSec, r.P50, r.P95, r.P99)
}

func TestSeedDataAndCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	tmpDir := t.TempDir()
	s, err := jsonstore.New(tmpDir)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer s.Close()

	ts := model.NewTypedStore(s, store.BackendJSON)
	ctx := context.Background()

	// Ensure namespaces
	for _, ns := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems, model.NSACL, model.NSMetadata} {
		if err := ts.EnsureNamespace(ctx, ns); err != nil {
			t.Fatalf("ensure namespace %s: %v", ns, err)
		}
	}

	seed, err := createSeedData(ctx, ts, 3, 5)
	if err != nil {
		t.Fatalf("seed data: %v", err)
	}

	if len(seed.Users) != 3 {
		t.Fatalf("expected 3 users, got %d", len(seed.Users))
	}

	// Verify users exist
	for _, userID := range seed.Users {
		if _, err := ts.UserStore().Get(ctx, userID); err != nil {
			t.Errorf("user %s not found: %v", userID, err)
		}
	}

	// Cleanup
	if err := CleanupSeedData(ctx, ts, seed); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	// Verify users are gone
	for _, userID := range seed.Users {
		if _, err := ts.UserStore().Get(ctx, userID); err == nil {
			t.Errorf("user %s should have been deleted", userID)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Concurrency != 10 {
		t.Errorf("expected concurrency 10, got %d", cfg.Concurrency)
	}
	if cfg.Duration != 5*time.Second {
		t.Errorf("expected duration 5s, got %v", cfg.Duration)
	}
	if cfg.Scenarios != ScenarioAll {
		t.Errorf("expected ScenarioAll, got %v", cfg.Scenarios)
	}
}

func TestPrintResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	results := []*Result{
		{
			Name:       "Test",
			TotalReqs:  100,
			Errors:     2,
			Duration:   time.Second,
			ReqPerSec:  100,
			P50:        5 * time.Millisecond,
			P95:        20 * time.Millisecond,
			P99:        50 * time.Millisecond,
			ErrorRate:  0.02,
			MemAllocMB: 10.5,
		},
	}

	// Just verify it doesn't panic
	PrintResults(results)
}
