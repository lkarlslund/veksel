package tlsrpt

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type resolverFunc func(context.Context, string) ([]string, error)

func (f resolverFunc) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return f(ctx, name)
}

type ipResolverFunc func(context.Context, string) ([]netip.Addr, error)

func (f ipResolverFunc) LookupNetIP(ctx context.Context, _, name string) ([]netip.Addr, error) {
	return f(ctx, name)
}

func newReporterTest(t *testing.T, now *time.Time, resolver TXTResolver, poster HTTPSPoster, mailer Mailer) (*Recorder, *Reporter, func()) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := NewRecorder(t.Context(), backend, RecorderOptions{Now: func() time.Time { return *now }})
	if err != nil {
		_ = backend.Close()
		t.Fatal(err)
	}
	reporter, err := NewReporter(recorder, ReporterOptions{Metadata: ReportMetadata{OrganizationName: "Veksel", ContactInfo: "postmaster@sender.test", SubmitterDomain: "sender.test"},
		Resolver: resolver, Poster: poster, Mailer: mailer, Now: func() time.Time { return *now }})
	if err != nil {
		_ = backend.Close()
		t.Fatal(err)
	}
	return recorder, reporter, func() { _ = backend.Close() }
}

func TestReporterDeliversHTTPSOnceAndCleansAggregates(t *testing.T) {
	now := time.Date(2026, 8, 19, 2, 0, 0, 0, time.UTC)
	resolver := resolverFunc(func(context.Context, string) ([]string, error) {
		return []string{"v=TLSRPTv1; rua=https://reports.example.test/v1"}, nil
	})
	var posts atomic.Int32
	poster := HTTPSPosterFunc(func(_ context.Context, endpoint string, body []byte) error {
		posts.Add(1)
		if endpoint != "https://reports.example.test/v1" || len(body) == 0 {
			t.Fatalf("POST %q with %d bytes", endpoint, len(body))
		}
		return nil
	})
	recorder, reporter, closeReporter := newReporterTest(t, &now, resolver, poster, nil)
	defer closeReporter()
	event := baseEvent("attempt-1", true)
	if err := recorder.Record(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	jobs, err := reporter.ProcessDay(t.Context(), "2026-08-18")
	if err != nil || len(jobs) != 1 || jobs[0].Status != ReportDelivered || posts.Load() != 1 {
		t.Fatalf("ProcessDay() = %#v, %v, posts %d", jobs, err, posts.Load())
	}
	if aggregates, err := recorder.Aggregates(t.Context(), "2026-08-18", ""); err != nil || len(aggregates) != 0 {
		t.Fatalf("aggregates after delivery = %#v, %v", aggregates, err)
	}
	jobs, err = reporter.Jobs(t.Context())
	if err != nil || len(jobs) != 1 || jobs[0].Report.ReportID == "" || len(jobs[0].GZIP) == 0 {
		t.Fatalf("Jobs() = %#v, %v", jobs, err)
	}
	if _, err := reporter.ProcessDay(t.Context(), "2026-08-18"); err != nil || posts.Load() != 1 {
		t.Fatalf("terminal report repeated, posts %d, err %v", posts.Load(), err)
	}
}

func TestReporterFallsBackToDKIMMailEndpoint(t *testing.T) {
	now := time.Date(2026, 8, 19, 2, 0, 0, 0, time.UTC)
	resolver := resolverFunc(func(context.Context, string) ([]string, error) {
		return []string{"v=TLSRPTv1; rua=https://fail.example.test,mailto:tls@example.test"}, nil
	})
	poster := HTTPSPosterFunc(func(context.Context, string, []byte) error { return errors.New("HTTPS unavailable") })
	var mailed MailReport
	var suppressed bool
	mailer := MailerFunc(func(ctx context.Context, report MailReport) error {
		suppressed = IsSuppressed(ctx)
		mailed = report
		return nil
	})
	recorder, reporter, closeReporter := newReporterTest(t, &now, resolver, poster, mailer)
	defer closeReporter()
	if err := recorder.Record(t.Context(), baseEvent("attempt-1", false)); err != nil {
		t.Fatal(err)
	}
	jobs, err := reporter.ProcessDay(t.Context(), "2026-08-18")
	if err != nil || len(jobs) != 1 || jobs[0].Status != ReportDelivered || mailed.Recipient != "tls@example.test" || !suppressed || !strings.HasSuffix(mailed.Filename, ".json.gz") {
		t.Fatalf("ProcessDay() = %#v, %v, mail %#v suppressed %t", jobs, err, mailed, suppressed)
	}
}

func TestReporterIgnoresAbsentPolicy(t *testing.T) {
	now := time.Date(2026, 8, 19, 2, 0, 0, 0, time.UTC)
	resolver := resolverFunc(func(context.Context, string) ([]string, error) {
		return nil, &net.DNSError{Err: "not found", IsNotFound: true}
	})
	recorder, reporter, closeReporter := newReporterTest(t, &now, resolver, HTTPSPosterFunc(func(context.Context, string, []byte) error {
		t.Fatal("poster called")
		return nil
	}), nil)
	defer closeReporter()
	if err := recorder.Record(t.Context(), baseEvent("attempt-1", true)); err != nil {
		t.Fatal(err)
	}
	jobs, err := reporter.ProcessDay(t.Context(), "2026-08-18")
	if err != nil || len(jobs) != 1 || jobs[0].Status != ReportIgnored {
		t.Fatalf("ProcessDay() = %#v, %v", jobs, err)
	}
}

func TestReporterRetriesDNSAndPreservesPreparedIdentity(t *testing.T) {
	now := time.Date(2026, 8, 19, 2, 0, 0, 0, time.UTC)
	fail := true
	resolver := resolverFunc(func(context.Context, string) ([]string, error) {
		if fail {
			return nil, errors.New("temporary DNS failure")
		}
		return []string{"v=TLSRPTv1; rua=https://reports.example.test"}, nil
	})
	recorder, reporter, closeReporter := newReporterTest(t, &now, resolver, HTTPSPosterFunc(func(context.Context, string, []byte) error { return nil }), nil)
	defer closeReporter()
	if err := recorder.Record(t.Context(), baseEvent("attempt-1", true)); err != nil {
		t.Fatal(err)
	}
	jobs, err := reporter.ProcessDay(t.Context(), "2026-08-18")
	if err != nil || jobs[0].Status != ReportRetrying || jobs[0].ID == "" {
		t.Fatalf("first ProcessDay() = %#v, %v", jobs, err)
	}
	id := jobs[0].ID
	fail = false
	now = jobs[0].NextAttemptAt.Add(time.Second)
	jobs, err = reporter.ProcessDay(t.Context(), "2026-08-18")
	if err != nil || jobs[0].Status != ReportDelivered || jobs[0].ID != id {
		t.Fatalf("retry ProcessDay() = %#v, %v", jobs, err)
	}
}

func TestReporterRetrySurvivesReporterReopen(t *testing.T) {
	now := time.Date(2026, 8, 19, 2, 0, 0, 0, time.UTC)
	failingResolver := resolverFunc(func(context.Context, string) ([]string, error) {
		return nil, errors.New("temporary DNS failure")
	})
	recorder, reporter, closeReporter := newReporterTest(t, &now, failingResolver, nil, nil)
	defer closeReporter()
	if err := recorder.Record(t.Context(), baseEvent("attempt-1", true)); err != nil {
		t.Fatal(err)
	}
	jobs, err := reporter.ProcessDay(t.Context(), "2026-08-18")
	if err != nil || len(jobs) != 1 || jobs[0].Status != ReportRetrying {
		t.Fatalf("first ProcessDay() = %#v, %v", jobs, err)
	}
	preparedID := jobs[0].ID
	preparedPayload := append([]byte(nil), jobs[0].GZIP...)
	now = jobs[0].NextAttemptAt.Add(time.Second)
	var posts atomic.Int32
	reopened, err := NewReporter(recorder, ReporterOptions{
		Metadata: ReportMetadata{OrganizationName: "Veksel", ContactInfo: "postmaster@sender.test", SubmitterDomain: "sender.test"},
		Resolver: resolverFunc(func(context.Context, string) ([]string, error) {
			return []string{"v=TLSRPTv1; rua=https://reports.example.test"}, nil
		}),
		Poster: HTTPSPosterFunc(func(_ context.Context, _ string, payload []byte) error {
			posts.Add(1)
			if !bytes.Equal(payload, preparedPayload) {
				t.Fatal("reopened reporter changed the prepared payload")
			}
			return nil
		}),
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	jobs, err = reopened.ProcessDay(t.Context(), "2026-08-18")
	if err != nil || len(jobs) != 1 || jobs[0].Status != ReportDelivered || jobs[0].ID != preparedID || posts.Load() != 1 {
		t.Fatalf("reopened ProcessDay() = %#v, %v, posts %d", jobs, err, posts.Load())
	}
}

func TestReporterExpiresAfterDeliveryWindow(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC)
	recorder, reporter, closeReporter := newReporterTest(t, &now, resolverFunc(func(context.Context, string) ([]string, error) {
		t.Fatal("resolver called after expiry")
		return nil, nil
	}), HTTPSPosterFunc(func(context.Context, string, []byte) error { return nil }), nil)
	defer closeReporter()
	event := baseEvent("attempt-1", true)
	if err := recorder.Record(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	jobs, err := reporter.ProcessDay(t.Context(), "2026-08-18")
	if err != nil || len(jobs) != 1 || jobs[0].Status != ReportExpired {
		t.Fatalf("ProcessDay() = %#v, %v", jobs, err)
	}
}

func TestSafeHTTPSPosterRejectsPrivateDNSResultBeforeDial(t *testing.T) {
	// Carrier-grade NAT and IPv6 forms embedding a private IPv4 address are
	// as private as loopback.
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "64:ff9b::7f00:1", "2002:a00:1::1", "::ffff:169.254.169.254"} {
		poster := &SafeHTTPSPoster{Timeout: time.Second, Resolver: ipResolverFunc(func(_ context.Context, name string) ([]netip.Addr, error) {
			if name != "reports.example.test" {
				t.Fatalf("resolved host = %q", name)
			}
			return []netip.Addr{netip.MustParseAddr(address)}, nil
		})}
		err := poster.Post(t.Context(), "https://reports.example.test/submit", []byte("report"))
		if err == nil || !strings.Contains(err.Error(), "non-public") {
			t.Fatalf("Post() to %s error = %v", address, err)
		}
	}
}
