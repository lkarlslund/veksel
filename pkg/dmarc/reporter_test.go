package dmarc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func newAggregateReporterTest(t *testing.T, now *time.Time, resolver TXTResolver, mailer AggregateMailer) (*AggregateRecorder, *AggregateReporter, func()) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := NewAggregateRecorder(t.Context(), backend, AggregateRecorderOptions{Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := NewAggregateReporter(recorder, AggregateReporterOptions{Identity: AggregateReportIdentity{Organization: "Veksel", Email: "dmarc@receiver.test"},
		SubmitterDomain: "receiver.test", Resolver: resolver, Mailer: mailer, Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	return recorder, reporter, func() { _ = backend.Close() }
}

func recordReporterObservation(t *testing.T, recorder *AggregateRecorder, destination string) {
	t.Helper()
	observation := aggregateObservation("attempt")
	observation.Policy.RUA = []string{destination}
	if err := recorder.Record(t.Context(), observation); err != nil {
		t.Fatal(err)
	}
}

func TestAggregateReporterQueuesSameOrganizationDestinationExactlyOnce(t *testing.T) {
	now := time.Date(2026, 8, 28, 2, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	var sent AggregateMailReport
	resolver := resolverFunc(func(context.Context, string) ([]string, error) {
		t.Fatal("same-organization destination caused DNS authorization")
		return nil, nil
	})
	mailer := AggregateMailerFunc(func(_ context.Context, report AggregateMailReport) error { calls.Add(1); sent = report; return nil })
	recorder, reporter, closeReporter := newAggregateReporterTest(t, &now, resolver, mailer)
	defer closeReporter()
	recordReporterObservation(t, recorder, "mailto:dmarc@reports.sender.example")
	jobs, err := reporter.ProcessDay(t.Context(), "2026-08-27")
	if err != nil || len(jobs) != 1 || jobs[0].Status != AggregateReportDelivered || sent.Recipient != "dmarc@reports.sender.example" || calls.Load() != 1 {
		t.Fatalf("jobs=%#v err=%v sent=%#v calls=%d", jobs, err, sent, calls.Load())
	}
	jobs, err = reporter.ProcessDay(t.Context(), "2026-08-27")
	if err != nil || calls.Load() != 1 || jobs[0].ID == "" {
		t.Fatalf("terminal job repeated: %#v %v calls=%d", jobs, err, calls.Load())
	}
}

func TestAggregateReporterRequiresExternalAuthorizationAndHonorsOverride(t *testing.T) {
	now := time.Date(2026, 8, 28, 2, 0, 0, 0, time.UTC)
	var sent AggregateMailReport
	resolver := resolverFunc(func(_ context.Context, name string) ([]string, error) {
		if name != "sender.example._report._dmarc.external.test." {
			t.Fatalf("lookup=%q", name)
		}
		return []string{"v=DMARC1; rua=mailto:override@external.test"}, nil
	})
	recorder, reporter, closeReporter := newAggregateReporterTest(t, &now, resolver, AggregateMailerFunc(func(_ context.Context, report AggregateMailReport) error { sent = report; return nil }))
	defer closeReporter()
	recordReporterObservation(t, recorder, "mailto:original@external.test!10m")
	jobs, err := reporter.ProcessDay(t.Context(), "2026-08-27")
	if err != nil || len(jobs) != 1 || jobs[0].Status != AggregateReportDelivered || sent.Recipient != "override@external.test" {
		t.Fatalf("jobs=%#v err=%v sent=%#v", jobs, err, sent)
	}
}

func TestAggregateReporterIgnoresUnauthorizedExternalDestination(t *testing.T) {
	now := time.Date(2026, 8, 28, 2, 0, 0, 0, time.UTC)
	resolver := resolverFunc(func(context.Context, string) ([]string, error) {
		return nil, &net.DNSError{Err: "not found", IsNotFound: true}
	})
	recorder, reporter, closeReporter := newAggregateReporterTest(t, &now, resolver, AggregateMailerFunc(func(context.Context, AggregateMailReport) error { t.Fatal("mailer called"); return nil }))
	defer closeReporter()
	recordReporterObservation(t, recorder, "mailto:dmarc@external.test")
	jobs, err := reporter.ProcessDay(t.Context(), "2026-08-27")
	if err != nil || len(jobs) != 1 || jobs[0].Status != AggregateReportIgnored {
		t.Fatalf("jobs=%#v err=%v", jobs, err)
	}
}

func TestAggregateReporterRetryStateSurvivesReopen(t *testing.T) {
	now := time.Date(2026, 8, 28, 2, 0, 0, 0, time.UTC)
	fail := true
	resolver := resolverFunc(func(context.Context, string) ([]string, error) {
		if fail {
			return nil, errors.New("DNS unavailable")
		}
		return []string{"v=DMARC1"}, nil
	})
	recorder, reporter, closeReporter := newAggregateReporterTest(t, &now, resolver, nil)
	defer closeReporter()
	recordReporterObservation(t, recorder, "mailto:dmarc@external.test")
	jobs, err := reporter.ProcessDay(t.Context(), "2026-08-27")
	if err != nil || jobs[0].Status != AggregateReportRetrying {
		t.Fatalf("jobs=%#v err=%v", jobs, err)
	}
	id := jobs[0].ID
	now = jobs[0].NextAttemptAt.Add(time.Second)
	fail = false
	reopened, err := NewAggregateReporter(recorder, AggregateReporterOptions{Identity: AggregateReportIdentity{Organization: "Veksel", Email: "dmarc@receiver.test"}, SubmitterDomain: "receiver.test", Resolver: resolver, Mailer: AggregateMailerFunc(func(context.Context, AggregateMailReport) error { return nil }), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	jobs, err = reopened.ProcessDay(t.Context(), "2026-08-27")
	if err != nil || jobs[0].Status != AggregateReportDelivered || jobs[0].ID != id || jobs[0].Attempts != 2 {
		t.Fatalf("reopened jobs=%#v err=%v", jobs, err)
	}
}

func TestAggregateReporterRetriesQueueAdmissionWithStablePayload(t *testing.T) {
	now := time.Date(2026, 8, 28, 2, 0, 0, 0, time.UTC)
	fail := true
	var id string
	var payload []byte
	mailer := AggregateMailerFunc(func(_ context.Context, report AggregateMailReport) error {
		if id == "" {
			id = report.ReportID
			payload = append([]byte(nil), report.GZIP...)
		} else if report.ReportID != id || !bytes.Equal(report.GZIP, payload) {
			t.Fatal("retry changed prepared identity or payload")
		}
		if fail {
			return errors.New("queue unavailable")
		}
		return nil
	})
	recorder, reporter, closeReporter := newAggregateReporterTest(t, &now, resolverFunc(func(context.Context, string) ([]string, error) {
		t.Fatal("same organization authorization lookup")
		return nil, nil
	}), mailer)
	defer closeReporter()
	recordReporterObservation(t, recorder, "mailto:dmarc@reports.sender.example")
	jobs, err := reporter.ProcessDay(t.Context(), "2026-08-27")
	if err != nil || jobs[0].Status != AggregateReportRetrying {
		t.Fatalf("jobs=%#v err=%v", jobs, err)
	}
	now = jobs[0].NextAttemptAt.Add(time.Second)
	fail = false
	jobs, err = reporter.ProcessDay(t.Context(), "2026-08-27")
	if err != nil || jobs[0].Status != AggregateReportDelivered || jobs[0].Attempts != 2 {
		t.Fatalf("retry jobs=%#v err=%v", jobs, err)
	}
}

func TestAggregateReporterExpiresOldUndeliveredJobs(t *testing.T) {
	now := time.Date(2026, 9, 4, 1, 0, 0, 0, time.UTC)
	recorder, reporter, closeReporter := newAggregateReporterTest(t, &now, resolverFunc(func(context.Context, string) ([]string, error) {
		t.Fatal("expired report resolved DNS")
		return nil, nil
	}), nil)
	defer closeReporter()
	recordReporterObservation(t, recorder, "mailto:dmarc@external.test")
	jobs, err := reporter.ProcessDay(t.Context(), "2026-08-27")
	if err != nil || jobs[0].Status != AggregateReportExpired {
		t.Fatalf("expired jobs=%#v err=%v", jobs, err)
	}
}
