// Package loadtest provides a load testing harness for Veksel IMAP, SMTP, HTTP, and CalDAV endpoints.
//
// It creates a temporary store, seeds test data, starts the protocol servers,
// runs concurrent operations, and reports throughput and latency metrics.
package loadtest

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	imapv2 "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
	"github.com/lkarlslund/veksel/pkg/caldav"
	"github.com/lkarlslund/veksel/pkg/imap"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
	smtp "github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// Config holds load test configuration.
type Config struct {
	// Concurrency is the number of parallel workers per scenario.
	Concurrency int

	// Duration is how long each scenario runs. Zero means run all iterations without a time limit.
	Duration time.Duration

	// NumUsers is the number of seed users to create.
	NumUsers int

	// NumMessagesPerUser is the number of messages to seed per user.
	NumMessagesPerUser int

	// Scenarios is a bitmask of which scenarios to run.
	Scenarios Scenarios

	// ServerAddr is the base hostname used in SMTP/IMAP greetings.
	ServerAddr string
}

// Scenarios is a bitmask of enabled load test scenarios.
type Scenarios uint

const (
	ScenarioIMAP Scenarios = 1 << iota
	ScenarioSMTP
	ScenarioHTTP
	ScenarioCalDAV
	ScenarioAll = ScenarioIMAP | ScenarioSMTP | ScenarioHTTP | ScenarioCalDAV
)

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Concurrency:        10,
		Duration:           5 * time.Second,
		NumUsers:           5,
		NumMessagesPerUser: 10,
		Scenarios:          ScenarioAll,
		ServerAddr:         "127.0.0.1",
	}
}

// Result holds the metrics for a single completed scenario.
type Result struct {
	Name       string
	TotalReqs  int64
	Errors     int64
	Latencies  []time.Duration // per-request latencies
	Duration   time.Duration
	ReqPerSec  float64
	P50        time.Duration
	P95        time.Duration
	P99        time.Duration
	ErrorRate  float64
	MemAllocMB float64 // heap allocation at end of test
}

// Run executes the configured load test scenarios and returns the aggregated results.
func Run(ctx context.Context, cfg *Config) ([]*Result, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Setup temporary store
	tmpDir, err := os.MkdirTemp("", "veksel-loadtest-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	s, err := jsonstore.New(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("create store: %w", err)
	}
	defer s.Close()

	ts := model.NewTypedStore(s, store.BackendJSON)
	met := metrics.New(s)

	// Ensure namespaces
	for _, ns := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems, model.NSACL, model.NSMetadata} {
		if err := ts.EnsureNamespace(ctx, ns); err != nil {
			return nil, fmt.Errorf("ensure namespace %s: %w", ns, err)
		}
	}

	// Seed data
	seed, err := createSeedData(ctx, ts, cfg.NumUsers, cfg.NumMessagesPerUser)
	if err != nil {
		return nil, fmt.Errorf("seed data: %w", err)
	}

	// Start servers
	servers, err := startServers(ctx, ts, met, cfg)
	if err != nil {
		return nil, fmt.Errorf("start servers: %w", err)
	}
	defer servers.close()

	var results []*Result

	if cfg.Scenarios&ScenarioIMAP != 0 {
		r, err := runIMAPScenario(ctx, cfg, servers.imapAddr, seed)
		if err != nil {
			return results, fmt.Errorf("IMAP scenario: %w", err)
		}
		results = append(results, r)
	}

	if cfg.Scenarios&ScenarioSMTP != 0 {
		r, err := runSMTPScenario(ctx, cfg, servers.smtpAddr, seed)
		if err != nil {
			return results, fmt.Errorf("SMTP scenario: %w", err)
		}
		results = append(results, r)
	}

	if cfg.Scenarios&ScenarioHTTP != 0 {
		r, err := runHTTPScenario(ctx, cfg, servers.httpAddr)
		if err != nil {
			return results, fmt.Errorf("HTTP scenario: %w", err)
		}
		results = append(results, r)
	}

	if cfg.Scenarios&ScenarioCalDAV != 0 {
		r, err := runCalDAVScenario(ctx, cfg, servers.httpAddr, seed)
		if err != nil {
			return results, fmt.Errorf("CalDAV scenario: %w", err)
		}
		results = append(results, r)
	}

	return results, nil
}

// PrintResults prints a formatted summary of load test results to stdout.
func PrintResults(results []*Result) {
	fmt.Println()
	fmt.Println("=== Load Test Results ===")
	fmt.Println()
	for _, r := range results {
		fmt.Printf("--- %s ---\n", r.Name)
		fmt.Printf("  Duration:  %s\n", r.Duration.Round(time.Millisecond))
		fmt.Printf("  Total Reqs:  %d\n", r.TotalReqs)
		fmt.Printf("  Errors:  %d (%.1f%%)\n", r.Errors, r.ErrorRate*100)
		fmt.Printf("  Req/Sec:  %.1f\n", r.ReqPerSec)
		fmt.Printf("  Latency P50: %s\n", r.P50.Round(time.Microsecond))
		fmt.Printf("  Latency P95: %s\n", r.P95.Round(time.Microsecond))
		fmt.Printf("  Latency P99: %s\n", r.P99.Round(time.Microsecond))
		fmt.Printf("  Mem Alloc:  %.1f MB\n\n", r.MemAllocMB)
	}
}

// ---------------------------------------------------------------------------
// Server management
// ---------------------------------------------------------------------------

type testServers struct {
	imapAddr string
	smtpAddr string
	httpAddr string
	imapSrv  *imap.Server
	smtpSrv  *smtp.Server
	httpSrv  *http.Server
	cancel   context.CancelFunc
}

func startServers(ctx context.Context, ts *model.TypedStore, met *metrics.Metrics, cfg *Config) (*testServers, error) {
	srv := &testServers{}
	sctx, cancel := context.WithCancel(ctx)
	srv.cancel = cancel

	// IMAP server
	imapSrv := imap.New(&imap.Config{
		ServerName:     cfg.ServerAddr,
		AuthMechanisms: []string{"PLAIN", "LOGIN"},
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if password == "testpass" {
				return username, nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		TypedStore: ts,
		Metrics:    met,
	})
	imapLn, err := imapSrv.Listen("127.0.0.1:0")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("imap listen: %w", err)
	}
	srv.imapAddr = imapLn.Addr().String()
	srv.imapSrv = imapSrv
	go imapSrv.Accept(sctx, imapLn)

	// SMTP server
	smtpSrv := smtp.New(&smtp.Config{
		ServerName:     cfg.ServerAddr,
		AuthMechanisms: []string{"PLAIN"},
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if password == "testpass" {
				return username, nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		Delivery: &smtp.Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				parts := strings.Split(addr, "@")
				if len(parts) < 2 {
					return "", "", fmt.Errorf("invalid address")
				}
				userID := parts[0]
				folderID := model.InboxFolderID(userID)
				return folderID, userID, nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return ts.ItemStore().Append(ctx, folderID, data, headers)
			},
		},
		Metrics: met,
	})
	smtpLn, err := smtpSrv.Listen("127.0.0.1:0")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("smtp listen: %w", err)
	}
	srv.smtpAddr = smtpLn.Addr().String()
	srv.smtpSrv = smtpSrv
	go smtpSrv.Accept(sctx, smtpLn)

	// HTTP server (minimal health + users endpoint)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		users, _ := ts.UserStore().List(r.Context())
		out := make([]struct {
			ID string `json:"id"`
		}, len(users))
		for i, u := range users {
			out[i] = struct {
				ID string `json:"id"`
			}{ID: u.ID}
		}
		resp, _ := json.Marshal(out)
		w.Write(resp)
	})
	mux.HandleFunc("GET /api/v1/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		userID := r.PathValue("id")
		u, err := ts.UserStore().Get(r.Context(), userID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		resp, _ := json.Marshal(struct {
			ID   string `json:"id"`
			Name string `json:"display_name"`
		}{ID: u.ID, Name: u.DisplayName})
		w.Write(resp)
	})
	mux.HandleFunc("GET /api/v1/folders", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		folders, _ := ts.FolderStore().ListAll(r.Context())
		out := make([]struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}, len(folders))
		for i, f := range folders {
			out[i] = struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}{ID: f.ID, Name: f.Name}
		}
		resp, _ := json.Marshal(out)
		w.Write(resp)
	})
	mux.HandleFunc("GET /api/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		folderID := r.URL.Query().Get("folder_id")
		if folderID == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		keys, _ := ts.ItemStore().List(r.Context(), folderID)
		w.Write([]byte(fmt.Sprintf(`{"count":%d}`, len(keys))))
	})

	// CalDAV handler
	caldavHandler := caldav.New(ts, &caldav.Config{
		ServerName:        cfg.ServerAddr,
		Metrics:           met,
		MaxWebdavFileSize: 10 * 1024 * 1024,
	})
	mux.Handle("/dav/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="CalDAV"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		u, err := ts.UserStore().Get(r.Context(), user)
		if err != nil || u.PasswordHash == "" || pass != "testpass" {
			w.Header().Set("WWW-Authenticate", `Basic realm="CalDAV"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		caldavHandler.ServeHTTP(w, r)
	}))

	httpSrv := &http.Server{Handler: mux, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second}
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("http listen: %w", err)
	}
	srv.httpAddr = httpLn.Addr().String()
	srv.httpSrv = httpSrv
	go httpSrv.Serve(httpLn)

	return srv, nil
}

func (s *testServers) close() {
	s.cancel()
	if s.imapSrv != nil {
		s.imapSrv.Close()
	}
	if s.smtpSrv != nil {
		s.smtpSrv.Close()
	}
	if s.httpSrv != nil {
		s.httpSrv.Close()
	}
}

// ---------------------------------------------------------------------------
// Seed data
// ---------------------------------------------------------------------------

// SeedData represents the created test users and their resources.
type SeedData struct {
	Users    []string // user IDs
	Password string   // all users share this password
}

// createSeedData creates N users with email addresses, default folders, and messages.
func createSeedData(ctx context.Context, ts *model.TypedStore, numUsers, msgsPerUser int) (*SeedData, error) {
	seed := &SeedData{Password: "testpass"}

	for i := 0; i < numUsers; i++ {
		userID := fmt.Sprintf("user-%d", i)
		displayName := fmt.Sprintf("User %d", i)

		if err := ts.UserStore().Create(ctx, userID, displayName, seed.Password); err != nil {
			return seed, fmt.Errorf("create user %s: %w", userID, err)
		}

		// Add email address
		email := fmt.Sprintf("%s@example.com", userID)
		if err := ts.UserStore().AddEmailAddress(ctx, email, userID, "example.com", true); err != nil {
			return seed, fmt.Errorf("add email %s: %w", email, err)
		}

		// Create default folders
		if err := ts.FolderStore().CreateForUser(ctx, userID); err != nil {
			return seed, fmt.Errorf("create folders for %s: %w", userID, err)
		}

		// Seed messages
		inboxID := model.InboxFolderID(userID)
		for j := 0; j < msgsPerUser; j++ {
			msg := fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: Test Message %d\r\n\r\nThis is test message body %d for %s\r\n",
				email, j, j, userID)
			if _, err := ts.ItemStore().Append(ctx, inboxID, []byte(msg), map[string]string{
				"From":    "sender@example.com",
				"To":      email,
				"Subject": fmt.Sprintf("Test Message %d", j),
			}); err != nil {
				return seed, fmt.Errorf("append message for %s: %w", userID, err)
			}
		}

		seed.Users = append(seed.Users, userID)
	}

	return seed, nil
}

// CleanupSeedData removes all seeded users, folders, items, and email addresses.
func CleanupSeedData(ctx context.Context, ts *model.TypedStore, seed *SeedData) error {
	for _, userID := range seed.Users {
		// Delete items in all folders
		folders, err := ts.FolderStore().ListForUser(ctx, userID)
		if err != nil {
			continue
		}
		for _, f := range folders {
			keys, err := ts.ItemStore().List(ctx, f.ID)
			if err != nil {
				continue
			}
			for _, k := range keys {
				ts.ItemStore().Delete(ctx, k)
			}
		}

		// Delete folders
		for _, f := range folders {
			ts.FolderStore().Delete(ctx, f.ID)
		}

		// Delete email addresses
		emailAddrs, err := ts.UserStore().ListEmailAddressesForUser(ctx, userID)
		if err == nil {
			for _, ea := range emailAddrs {
				ts.UserStore().DeleteEmailAddress(ctx, ea.ID)
			}
		}

		// Delete user
		ts.UserStore().Delete(ctx, userID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// IMAP load test scenario
// ---------------------------------------------------------------------------

func runIMAPScenario(ctx context.Context, cfg *Config, addr string, seed *SeedData) (*Result, error) {
	r := &Result{Name: "IMAP"}
	var totalReqs, errors int64
	var latenciesMu sync.Mutex
	latencies := make([]time.Duration, 0, cfg.Concurrency*100)

	testStart := time.Now()
	done := make(chan struct{})
	if cfg.Duration > 0 {
		go func() {
			timer := time.NewTimer(cfg.Duration)
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
			timer.Stop()
			close(done)
		}()
	}

	randomSeed := time.Now().UnixNano()
	opNames := []string{"login", "select", "fetch", "search", "store", "append"}

	var wg sync.WaitGroup
	for w := 0; w < cfg.Concurrency; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			rg := rand.New(rand.NewSource(randomSeed + int64(worker)))
			for {
				select {
				case <-done:
					return
				case <-ctx.Done():
					return
				default:
				}

				userIdx := rg.Intn(len(seed.Users))
				userID := seed.Users[userIdx]

				start := time.Now()
				err := imapWorker(ctx, addr, userID, seed.Password, opNames[userIdx%len(opNames)])
				elapsed := time.Since(start)

				atomic.AddInt64(&totalReqs, 1)
				if err != nil {
					atomic.AddInt64(&errors, 1)
				}
				latenciesMu.Lock()
				latencies = append(latencies, elapsed)
				latenciesMu.Unlock()
			}
		}(w)
	}

	wg.Wait()
	r.TotalReqs = atomic.LoadInt64(&totalReqs)
	r.Errors = atomic.LoadInt64(&errors)
	r.Latencies = latencies
	r.Duration = time.Since(testStart)
	calcMetrics(r)
	return r, nil
}

func imapWorker(ctx context.Context, addr, userID, password, op string) error {
	client, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		return err
	}
	// LOGOUT drains the client's command stream before closing. A bare Close
	// can race the library's post-authentication capability refresh.
	defer func() { _ = client.Logout().Wait() }()
	if err := client.WaitGreeting(); err != nil {
		return err
	}

	switch op {
	case "login":
		return client.Login(userID, password).Wait()
	case "select":
		if err := client.Login(userID, password).Wait(); err != nil {
			return err
		}
		_, err := client.Select("INBOX", nil).Wait()
		return err
	case "fetch":
		if err := client.Login(userID, password).Wait(); err != nil {
			return err
		}
		if _, err := client.Select("INBOX", nil).Wait(); err != nil {
			return err
		}
		cmd := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{Flags: true, UID: true})
		cmd.Close()
		_, err := cmd.Collect()
		return err
	case "search":
		if err := client.Login(userID, password).Wait(); err != nil {
			return err
		}
		if _, err := client.Select("INBOX", nil).Wait(); err != nil {
			return err
		}
		_, err := client.Search(&imapv2.SearchCriteria{}, nil).Wait()
		return err
	case "store":
		if err := client.Login(userID, password).Wait(); err != nil {
			return err
		}
		if _, err := client.Select("INBOX", nil).Wait(); err != nil {
			return err
		}
		cmd := client.Store(imapv2.SeqSetNum(1), &imapv2.StoreFlags{
			Op:    imapv2.StoreFlagsAdd,
			Flags: []imapv2.Flag{imapv2.FlagSeen},
		}, nil)
		return cmd.Close()
	case "append":
		if err := client.Login(userID, password).Wait(); err != nil {
			return err
		}
		msg := "From: loadtest@example.com\r\nTo: user@example.com\r\nSubject: Load Test\r\n\r\nTest body\r\n"
		cmd := client.Append("INBOX", int64(len(msg)), nil)
		cmd.Write([]byte(msg))
		cmd.Close()
		_, err := cmd.Wait()
		return err
	default:
		return client.Login(userID, password).Wait()
	}
}

// ---------------------------------------------------------------------------
// SMTP load test scenario
// ---------------------------------------------------------------------------

func runSMTPScenario(ctx context.Context, cfg *Config, addr string, seed *SeedData) (*Result, error) {
	r := &Result{Name: "SMTP"}
	var totalReqs, errors int64
	var latenciesMu sync.Mutex
	latencies := make([]time.Duration, 0, cfg.Concurrency*100)

	testStart := time.Now()
	done := make(chan struct{})
	if cfg.Duration > 0 {
		go func() {
			timer := time.NewTimer(cfg.Duration)
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
			timer.Stop()
			close(done)
		}()
	}

	randomSeed := time.Now().UnixNano() + 1

	var wg sync.WaitGroup
	for w := 0; w < cfg.Concurrency; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			rg := rand.New(rand.NewSource(randomSeed + int64(worker)))
			for {
				select {
				case <-done:
					return
				case <-ctx.Done():
					return
				default:
				}

				userIdx := rg.Intn(len(seed.Users))
				userID := seed.Users[userIdx]
				email := fmt.Sprintf("%s@example.com", userID)

				start := time.Now()
				err := smtpWorker(ctx, addr, userID, seed.Password, email)
				elapsed := time.Since(start)

				atomic.AddInt64(&totalReqs, 1)
				if err != nil {
					atomic.AddInt64(&errors, 1)
				}
				latenciesMu.Lock()
				latencies = append(latencies, elapsed)
				latenciesMu.Unlock()
			}
		}(w)
	}

	wg.Wait()
	r.TotalReqs = atomic.LoadInt64(&totalReqs)
	r.Errors = atomic.LoadInt64(&errors)
	r.Latencies = latencies
	r.Duration = time.Since(testStart)
	calcMetrics(r)
	return r, nil
}

func smtpWorker(ctx context.Context, addr, userID, password, email string) error {
	client, err := gosmtp.Dial(addr)
	if err != nil {
		return err
	}
	defer client.Quit()

	// AUTH PLAIN
	saslClient := sasl.NewPlainClient("", userID, password)
	if err := client.Auth(saslClient); err != nil {
		return err
	}

	// Send mail
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: Load Test\r\n\r\nThis is a load test message body.\r\n", email, email)
	return client.SendMail(email, []string{email}, strings.NewReader(msg))
}

// ---------------------------------------------------------------------------
// HTTP load test scenario
// ---------------------------------------------------------------------------

func runHTTPScenario(ctx context.Context, cfg *Config, addr string) (*Result, error) {
	r := &Result{Name: "HTTP"}
	var totalReqs, errors int64
	var latenciesMu sync.Mutex
	latencies := make([]time.Duration, 0, cfg.Concurrency*100)

	testStart := time.Now()
	done := make(chan struct{})
	if cfg.Duration > 0 {
		go func() {
			timer := time.NewTimer(cfg.Duration)
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
			timer.Stop()
			close(done)
		}()
	}

	randomSeed := time.Now().UnixNano() + 2

	endpoints := []string{
		"/health",
		"/api/v1/users",
		"/api/v1/folders",
		"/api/v1/messages?folder_id=test:INBOX",
	}

	client := &http.Client{Timeout: 5 * time.Second}

	var wg sync.WaitGroup
	for w := 0; w < cfg.Concurrency; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			rg := rand.New(rand.NewSource(randomSeed + int64(worker)))
			for {
				select {
				case <-done:
					return
				case <-ctx.Done():
					return
				default:
				}

				ep := endpoints[rg.Intn(len(endpoints))]
				url := fmt.Sprintf("http://%s%s", addr, ep)

				start := time.Now()
				resp, err := client.Get(url)
				elapsed := time.Since(start)

				if resp != nil {
					resp.Body.Close()
				}

				atomic.AddInt64(&totalReqs, 1)
				if err != nil {
					atomic.AddInt64(&errors, 1)
				}
				latenciesMu.Lock()
				latencies = append(latencies, elapsed)
				latenciesMu.Unlock()
			}
		}(w)
	}

	wg.Wait()
	r.TotalReqs = atomic.LoadInt64(&totalReqs)
	r.Errors = atomic.LoadInt64(&errors)
	r.Latencies = latencies
	r.Duration = time.Since(testStart)
	calcMetrics(r)
	return r, nil
}

// ---------------------------------------------------------------------------
// CalDAV load test scenario
// ---------------------------------------------------------------------------

func runCalDAVScenario(ctx context.Context, cfg *Config, addr string, seed *SeedData) (*Result, error) {
	r := &Result{Name: "CalDAV"}
	var totalReqs, errors int64
	var latenciesMu sync.Mutex
	latencies := make([]time.Duration, 0, cfg.Concurrency*100)

	testStart := time.Now()
	done := make(chan struct{})
	if cfg.Duration > 0 {
		go func() {
			timer := time.NewTimer(cfg.Duration)
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
			timer.Stop()
			close(done)
		}()
	}

	randomSeed := time.Now().UnixNano() + 3

	client := &http.Client{Timeout: 5 * time.Second}

	var wg sync.WaitGroup
	for w := 0; w < cfg.Concurrency; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			rg := rand.New(rand.NewSource(randomSeed + int64(worker)))
			for {
				select {
				case <-done:
					return
				case <-ctx.Done():
					return
				default:
				}

				userIdx := rg.Intn(len(seed.Users))
				userID := seed.Users[userIdx]

				start := time.Now()
				err := caldavWorker(ctx, client, addr, userID, seed.Password, rg.Intn(3))
				elapsed := time.Since(start)

				atomic.AddInt64(&totalReqs, 1)
				if err != nil {
					atomic.AddInt64(&errors, 1)
				}
				latenciesMu.Lock()
				latencies = append(latencies, elapsed)
				latenciesMu.Unlock()
			}
		}(w)
	}

	wg.Wait()
	r.TotalReqs = atomic.LoadInt64(&totalReqs)
	r.Errors = atomic.LoadInt64(&errors)
	r.Latencies = latencies
	r.Duration = time.Since(testStart)
	calcMetrics(r)
	return r, nil
}

func caldavWorker(ctx context.Context, client *http.Client, addr, userID, password string, op int) error {
	url := fmt.Sprintf("http://%s/dav/%s/Calendar/", addr, userID)

	switch op {
	case 0:
		// PROPFIND
		req, err := http.NewRequestWithContext(ctx, "PROPFIND", url, nil)
		if err != nil {
			return err
		}
		req.SetBasicAuth(userID, password)
		req.Header.Set("Depth", "1")
		req.Header.Set("Content-Type", "application/xml")
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		return err
	case 1:
		// calendar-query
		req, err := http.NewRequestWithContext(ctx, "REPORT", url, strings.NewReader(`<?xml version="1.0"?>
		<C:calendar-query xmlns:D="DA:" xmlns:C="urn:ietf:params:xml:ns:caldav">
			<D:prop>
				<C:calendar-data>
					<C:comp-filter name="VCALENDAR">
						<C:comp-filter name="VEVENT"/>
					</C:comp-filter>
				</C:calendar-data>
			</D:prop>
			<D:filter>
				<C:comp-filter name="VCALENDAR">
					<C:comp-filter name="VEVENT"/>
				</C:comp-filter>
			</D:filter>
		</C:calendar-query>`))
		if err != nil {
			return err
		}
		req.SetBasicAuth(userID, password)
		req.Header.Set("Depth", "1")
		req.Header.Set("Content-Type", "text/xml; charset=utf-8")
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		return err
	default:
		// PROPFIND (simple)
		req, err := http.NewRequestWithContext(ctx, "PROPFIND", url, nil)
		if err != nil {
			return err
		}
		req.SetBasicAuth(userID, password)
		req.Header.Set("Depth", "0")
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		return err
	}
}

// ---------------------------------------------------------------------------
// Metrics calculation
// ---------------------------------------------------------------------------

func calcMetrics(r *Result) {
	if len(r.Latencies) == 0 {
		return
	}

	sort.Slice(r.Latencies, func(i, j int) bool {
		return r.Latencies[i] < r.Latencies[j]
	})

	n := len(r.Latencies)
	r.P50 = r.Latencies[int(float64(n)*0.5)]
	r.P95 = r.Latencies[int(float64(n)*0.95)]
	r.P99 = r.Latencies[int(float64(n)*0.99)]

	if r.Duration.Seconds() > 0 {
		r.ReqPerSec = float64(r.TotalReqs) / r.Duration.Seconds()
	}
	if r.TotalReqs > 0 {
		r.ErrorRate = float64(r.Errors) / float64(r.TotalReqs)
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	r.MemAllocMB = float64(m.Alloc) / 1024.0 / 1024.0
}
