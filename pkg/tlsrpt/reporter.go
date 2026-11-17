package tlsrpt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/netguard"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	reportJobPrefix = "report/"
	ReportPending   = "pending"
	ReportRetrying  = "retrying"
	ReportDelivered = "delivered"
	ReportIgnored   = "ignored"
	ReportExpired   = "expired"
)

// HTTPSPoster submits one gzip report body.
type HTTPSPoster interface {
	Post(context.Context, string, []byte) error
}

// HTTPSPosterFunc adapts a function for tests and integrations.
type HTTPSPosterFunc func(context.Context, string, []byte) error

func (f HTTPSPosterFunc) Post(ctx context.Context, endpoint string, body []byte) error {
	return f(ctx, endpoint, body)
}

// MailReport is the machine-readable attachment and routing metadata needed
// to construct, DKIM-sign, and durably enqueue an RFC 8460 email report.
type MailReport struct {
	Recipient       string
	PolicyDomain    string
	SubmitterDomain string
	ReportID        string
	Filename        string
	GZIP            []byte
}

// Mailer admits a TLS report to durable email delivery.
type Mailer interface {
	QueueTLSReport(context.Context, MailReport) error
}

// MailerFunc adapts a function to Mailer.
type MailerFunc func(context.Context, MailReport) error

func (f MailerFunc) QueueTLSReport(ctx context.Context, report MailReport) error {
	return f(ctx, report)
}

// ReporterOptions supplies report identity, DNS, and delivery dependencies.
type ReporterOptions struct {
	Metadata ReportMetadata
	Resolver TXTResolver
	Poster   HTTPSPoster
	Mailer   Mailer
	Now      func() time.Time
}

// TXTResolver is the reporting-policy DNS capability.
type TXTResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

// ReportJob is the durable, restart-safe delivery state for one domain/day.
type ReportJob struct {
	ID            string          `json:"id"`
	Day           string          `json:"day"`
	PolicyDomain  string          `json:"policy_domain"`
	Status        string          `json:"status"`
	Policy        ReportingPolicy `json:"reporting_policy"`
	Report        Report          `json:"report"`
	Filename      string          `json:"filename"`
	GZIP          []byte          `json:"gzip,omitempty"`
	Attempts      int             `json:"attempts"`
	LastError     string          `json:"last_error,omitempty"`
	LastAttemptAt time.Time       `json:"last_attempt_at,omitzero"`
	NextAttemptAt time.Time       `json:"next_attempt_at,omitzero"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// Reporter discovers recipient reporting policies and delivers completed UTC
// day aggregates. Prepared report IDs and payloads survive restarts.
type Reporter struct {
	recorder *Recorder
	store    store.Store
	metadata ReportMetadata
	resolver TXTResolver
	poster   HTTPSPoster
	mailer   Mailer
	now      func() time.Time
}

func NewReporter(recorder *Recorder, options ReporterOptions) (*Reporter, error) {
	if recorder == nil {
		return nil, errors.New("TLS report recorder is required")
	}
	if _, _, _, err := validateReportMetadata(options.Metadata); err != nil {
		return nil, fmt.Errorf("TLS report metadata: %w", err)
	}
	if options.Resolver == nil {
		options.Resolver = net.DefaultResolver
	}
	if options.Poster == nil {
		options.Poster = NewSafeHTTPSPoster()
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Reporter{recorder: recorder, store: recorder.store, metadata: options.Metadata,
		resolver: options.Resolver, poster: options.Poster, mailer: options.Mailer, now: options.Now}, nil
}

// ProcessDay prepares and attempts every domain report for one completed UTC
// day. A delivered/ignored terminal job is never submitted again.
func (r *Reporter) ProcessDay(ctx context.Context, day string) ([]ReportJob, error) {
	start, err := time.Parse(time.DateOnly, day)
	if err != nil {
		return nil, errors.New("TLS report day must use YYYY-MM-DD")
	}
	now := r.now().UTC()
	if start.Add(24 * time.Hour).After(now) {
		return nil, errors.New("TLS reports require a completed UTC day")
	}
	aggregates, err := r.recorder.Aggregates(ctx, day, "")
	if err != nil {
		return nil, err
	}
	byDomain := make(map[string][]Aggregate)
	for _, aggregate := range aggregates {
		byDomain[aggregate.Policy.Domain] = append(byDomain[aggregate.Policy.Domain], aggregate)
	}
	domains := make([]string, 0, len(byDomain))
	for domain := range byDomain {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	jobs := make([]ReportJob, 0, len(domains))
	for _, domain := range domains {
		job, err := r.processDomain(ctx, start, domain, byDomain[domain])
		if err != nil {
			return jobs, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

// Jobs returns durable delivery evidence ordered newest first.
func (r *Reporter) Jobs(ctx context.Context) ([]ReportJob, error) {
	return listReportJobs(ctx, r.store)
}

// Jobs returns durable delivery evidence directly from the recorder's shared
// namespace. Administration can therefore inspect jobs even when report
// scheduling is unavailable because no submitter identity is configured.
func (r *Recorder) Jobs(ctx context.Context) ([]ReportJob, error) {
	return listReportJobs(ctx, r.store)
}

func listReportJobs(ctx context.Context, backend store.Store) ([]ReportJob, error) {
	jobs := make([]ReportJob, 0)
	err := backend.Iterate(ctx, model.NSTLSRPT, reportJobPrefix, func(_ string, value []byte) (bool, error) {
		var job ReportJob
		if err := json.Unmarshal(value, &job); err != nil {
			return false, err
		}
		jobs = append(jobs, job)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].Day == jobs[j].Day {
			return jobs[i].PolicyDomain < jobs[j].PolicyDomain
		}
		return jobs[i].Day > jobs[j].Day
	})
	return jobs, nil
}

func (r *Reporter) processDomain(ctx context.Context, start time.Time, domain string, aggregates []Aggregate) (ReportJob, error) {
	now := r.now().UTC()
	key := reportJobPrefix + start.Format(time.DateOnly) + "/" + domain
	job, found, err := r.loadJob(ctx, key)
	if err != nil {
		return ReportJob{}, err
	}
	if found && (job.Status == ReportDelivered || job.Status == ReportIgnored || job.Status == ReportExpired) {
		_, cleanupErr := r.recorder.DeleteDayDomain(ctx, job.Day, job.PolicyDomain)
		return job, cleanupErr
	}
	if found && now.Before(job.NextAttemptAt) {
		return job, nil
	}
	if !found {
		report, filename, err := BuildReport(start.Format(time.DateOnly), aggregates, r.metadata)
		if err != nil {
			return ReportJob{}, err
		}
		compressed, err := MarshalReportGZIP(report)
		if err != nil {
			return ReportJob{}, err
		}
		job = ReportJob{ID: report.ReportID, Day: start.Format(time.DateOnly), PolicyDomain: domain,
			Status: ReportPending, Report: report, Filename: filename, GZIP: compressed, CreatedAt: now, UpdatedAt: now}
		if err := r.saveJob(ctx, key, job); err != nil {
			return ReportJob{}, err
		}
	}
	if !now.Before(start.Add(48 * time.Hour)) {
		job.Status, job.LastError, job.UpdatedAt = ReportExpired, "report delivery window expired", now
		if err := r.saveJob(ctx, key, job); err != nil {
			return ReportJob{}, err
		}
		_, err := r.recorder.DeleteDayDomain(ctx, job.Day, domain)
		return job, err
	}

	records, lookupErr := r.resolver.LookupTXT(ctx, "_smtp._tls."+domain)
	if lookupErr != nil {
		var dnsError *net.DNSError
		if errors.As(lookupErr, &dnsError) && dnsError.IsNotFound {
			records = nil
		} else {
			return r.retry(ctx, key, job, "reporting policy DNS lookup failed")
		}
	}
	policy, available, policyErr := ParseReportingPolicy(domain, records)
	if policyErr != nil || !available {
		job.Status, job.Policy, job.LastError, job.UpdatedAt = ReportIgnored, policy, "no valid SMTP TLS reporting policy", now
		if err := r.saveJob(ctx, key, job); err != nil {
			return ReportJob{}, err
		}
		_, err := r.recorder.DeleteDayDomain(ctx, job.Day, domain)
		return job, err
	}
	job.Policy = policy
	job.Attempts++
	job.LastAttemptAt = now
	job.UpdatedAt = now
	if err := r.saveJob(ctx, key, job); err != nil {
		return ReportJob{}, err
	}

	var failures []error
	for _, endpoint := range policy.URIs {
		parsed, _ := url.Parse(endpoint)
		switch parsed.Scheme {
		case "https":
			if err := r.poster.Post(ctx, endpoint, job.GZIP); err == nil {
				return r.complete(ctx, key, job)
			} else {
				failures = append(failures, err)
			}
		case "mailto":
			if r.mailer == nil {
				failures = append(failures, errors.New("DKIM email report delivery is not configured"))
				continue
			}
			address, _ := url.PathUnescape(parsed.Opaque)
			err := r.mailer.QueueTLSReport(Suppress(ctx), MailReport{Recipient: address, PolicyDomain: domain,
				SubmitterDomain: r.metadata.SubmitterDomain, ReportID: job.ID, Filename: job.Filename, GZIP: append([]byte(nil), job.GZIP...)})
			if err == nil {
				return r.complete(ctx, key, job)
			}
			failures = append(failures, err)
		}
	}
	if len(failures) == 0 {
		failures = append(failures, errors.New("reporting policy has no supported delivery endpoint"))
	}
	return r.retry(ctx, key, job, errors.Join(failures...).Error())
}

func (r *Reporter) complete(ctx context.Context, key string, job ReportJob) (ReportJob, error) {
	job.Status, job.LastError, job.NextAttemptAt, job.UpdatedAt = ReportDelivered, "", time.Time{}, r.now().UTC()
	if err := r.saveJob(ctx, key, job); err != nil {
		return ReportJob{}, err
	}
	_, err := r.recorder.DeleteDayDomain(ctx, job.Day, job.PolicyDomain)
	return job, err
}

func (r *Reporter) retry(ctx context.Context, key string, job ReportJob, message string) (ReportJob, error) {
	job.Status = ReportRetrying
	job.LastError = bound(strings.TrimSpace(message), maxReasonLength)
	job.UpdatedAt = r.now().UTC()
	delay := time.Duration(1<<min(job.Attempts, 6)) * 5 * time.Minute
	job.NextAttemptAt = job.UpdatedAt.Add(delay)
	if err := r.saveJob(ctx, key, job); err != nil {
		return ReportJob{}, err
	}
	return job, nil
}

func (r *Reporter) loadJob(ctx context.Context, key string) (ReportJob, bool, error) {
	data, err := r.store.Get(ctx, model.NSTLSRPT, key)
	if errors.Is(err, store.ErrNotFound) {
		return ReportJob{}, false, nil
	}
	if err != nil {
		return ReportJob{}, false, err
	}
	var job ReportJob
	if err := json.Unmarshal(data, &job); err != nil {
		return ReportJob{}, false, err
	}
	return job, true, nil
}

func (r *Reporter) saveJob(ctx context.Context, key string, job ReportJob) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return r.store.Set(ctx, model.NSTLSRPT, key, data)
}

// SafeHTTPSPoster blocks redirects, credentials, address literals, and DNS
// results that could turn a recipient-published endpoint into an SSRF probe.
type SafeHTTPSPoster struct {
	// Resolver looks hosts up; nil uses net.DefaultResolver.
	Resolver netguard.Resolver
	Timeout  time.Duration
}

func NewSafeHTTPSPoster() *SafeHTTPSPoster {
	return &SafeHTTPSPoster{Resolver: net.DefaultResolver, Timeout: 30 * time.Second}
}

func (p *SafeHTTPSPoster) Post(ctx context.Context, endpoint string, body []byte) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || net.ParseIP(parsed.Hostname()) != nil {
		return errors.New("unsafe HTTPS TLS report endpoint")
	}
	// Recipient domains publish the endpoint, so private networks are
	// never reachable through it.
	transport := (&netguard.Dialer{Resolver: p.Resolver}).Transport()
	defer transport.CloseIdleConnections()
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/tlsrpt+gzip")
	response, err := client.Do(request)
	if errors.Is(err, netguard.ErrForbiddenAddress) {
		return errors.New("HTTPS TLS report endpoint resolved to a non-public address")
	}
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("HTTPS TLS report endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}
