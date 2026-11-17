package dmarc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	dmarcJobPrefix           = "report/"
	AggregateReportPending   = "pending"
	AggregateReportRetrying  = "retrying"
	AggregateReportDelivered = "delivered"
	AggregateReportIgnored   = "ignored"
	AggregateReportExpired   = "expired"
)

type AggregateMailReport struct {
	Recipient       string
	PolicyDomain    string
	SubmitterDomain string
	ReportID        string
	Filename        string
	GZIP            []byte
}

type AggregateMailer interface {
	QueueDMARCAggregate(context.Context, AggregateMailReport) error
}
type AggregateMailerFunc func(context.Context, AggregateMailReport) error

func (f AggregateMailerFunc) QueueDMARCAggregate(ctx context.Context, report AggregateMailReport) error {
	return f(ctx, report)
}

type AggregateReporterOptions struct {
	Identity        AggregateReportIdentity
	SubmitterDomain string
	Resolver        TXTResolver
	Mailer          AggregateMailer
	Now             func() time.Time
}

type AggregateReportJob struct {
	ID            string    `json:"id"`
	Day           string    `json:"day"`
	PolicyDomain  string    `json:"policy_domain"`
	Destination   string    `json:"destination"`
	Recipient     string    `json:"recipient,omitempty"`
	Status        string    `json:"status"`
	ReportID      string    `json:"report_id"`
	Filename      string    `json:"filename"`
	GZIP          []byte    `json:"gzip,omitempty"`
	Attempts      int       `json:"attempts"`
	LastError     string    `json:"last_error,omitempty"`
	LastAttemptAt time.Time `json:"last_attempt_at,omitzero"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitzero"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type AggregateReporter struct {
	recorder  *AggregateRecorder
	store     store.Store
	identity  AggregateReportIdentity
	submitter string
	resolver  TXTResolver
	mailer    AggregateMailer
	now       func() time.Time
}

func NewAggregateReporter(recorder *AggregateRecorder, options AggregateReporterOptions) (*AggregateReporter, error) {
	if recorder == nil {
		return nil, errors.New("DMARC aggregate recorder is required")
	}
	if _, err := normalizeReportDomain(options.SubmitterDomain); err != nil {
		return nil, errors.New("DMARC submitter domain is invalid")
	}
	if strings.TrimSpace(options.Identity.Organization) == "" {
		return nil, errors.New("DMARC report organization is required")
	}
	address, err := mail.ParseAddress(options.Identity.Email)
	if err != nil || address.Address != options.Identity.Email {
		return nil, errors.New("DMARC report email is invalid")
	}
	if options.Resolver == nil {
		options.Resolver = net.DefaultResolver
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &AggregateReporter{recorder: recorder, store: recorder.store, identity: options.Identity,
		submitter: strings.ToLower(options.SubmitterDomain), resolver: options.Resolver, mailer: options.Mailer, now: options.Now}, nil
}

// ProcessDay prepares and admits one durable queue item per authorized rua
// destination. Terminal jobs are idempotent across restarts.
func (r *AggregateReporter) ProcessDay(ctx context.Context, day string) ([]AggregateReportJob, error) {
	start, err := time.Parse(time.DateOnly, day)
	if err != nil {
		return nil, errors.New("DMARC report day must use YYYY-MM-DD")
	}
	if start.Add(24 * time.Hour).After(r.now().UTC()) {
		return nil, errors.New("DMARC reports require a completed UTC day")
	}
	aggregates, err := r.recorder.Aggregates(ctx, day, "")
	if err != nil {
		return nil, err
	}
	var jobs []AggregateReportJob
	for _, aggregate := range aggregates {
		generated, err := GenerateAggregateReport(aggregate, r.identity)
		if err != nil {
			return jobs, err
		}
		for index, destination := range aggregate.Policy.RUA {
			job, err := r.processDestination(ctx, start, aggregate.Policy.Domain, aggregate.ID, index, destination, generated)
			if err != nil {
				return jobs, err
			}
			jobs = append(jobs, job)
		}
	}
	return jobs, nil
}

func (r *AggregateReporter) processDestination(ctx context.Context, start time.Time, policyDomain, aggregateID string, index int, destination string, generated GeneratedAggregateReport) (AggregateReportJob, error) {
	key := dmarcJobPrefix + start.Format(time.DateOnly) + "/" + policyDomain + "/" + aggregateID + "/" + digestStrings(strconv.Itoa(index), destination)
	job, found, err := r.loadJob(ctx, key)
	if err != nil {
		return job, err
	}
	now := r.now().UTC()
	if found && isAggregateTerminal(job.Status) {
		return job, nil
	}
	if found && now.Before(job.NextAttemptAt) {
		return job, nil
	}
	if !found {
		job = AggregateReportJob{ID: digestStrings(generated.ID, destination), Day: start.Format(time.DateOnly), PolicyDomain: policyDomain,
			Destination: destination, Status: AggregateReportPending, ReportID: generated.ID, Filename: generated.Filename,
			GZIP: append([]byte(nil), generated.GZIP...), CreatedAt: now, UpdatedAt: now}
		if err := r.saveJob(ctx, key, job); err != nil {
			return job, err
		}
	}
	if now.After(start.Add(7 * 24 * time.Hour)) {
		return r.terminal(ctx, key, job, AggregateReportExpired, "report delivery window expired")
	}
	job.Attempts++
	job.LastAttemptAt = now
	job.UpdatedAt = now
	if err := r.saveJob(ctx, key, job); err != nil {
		return job, err
	}
	recipient, destinationDomain, err := parseAggregateDestination(destination)
	if err != nil {
		return r.terminal(ctx, key, job, AggregateReportIgnored, err.Error())
	}
	job.Recipient = recipient
	if organizationalDomain(policyDomain) != organizationalDomain(destinationDomain) {
		authorized, override, temporary, authErr := r.authorizeExternal(ctx, policyDomain, destinationDomain)
		if temporary {
			return r.retry(ctx, key, job, authErr.Error())
		}
		if authErr != nil || !authorized {
			return r.terminal(ctx, key, job, AggregateReportIgnored, "external report destination is not authorized")
		}
		if override != "" {
			recipient, _, err = parseAggregateDestination(override)
			if err != nil {
				return r.terminal(ctx, key, job, AggregateReportIgnored, "external authorization override is invalid")
			}
			job.Recipient = recipient
		}
	}
	if r.mailer == nil {
		return r.retry(ctx, key, job, "DMARC aggregate mail delivery is not configured")
	}
	err = r.mailer.QueueDMARCAggregate(ctx, AggregateMailReport{Recipient: job.Recipient, PolicyDomain: policyDomain,
		SubmitterDomain: r.submitter, ReportID: job.ReportID, Filename: job.Filename, GZIP: append([]byte(nil), job.GZIP...)})
	if err != nil {
		return r.retry(ctx, key, job, err.Error())
	}
	return r.terminal(ctx, key, job, AggregateReportDelivered, "")
}

func (r *AggregateReporter) authorizeExternal(ctx context.Context, policyDomain, destinationDomain string) (bool, string, bool, error) {
	name := policyDomain + "._report._dmarc." + destinationDomain + "."
	records, err := r.resolver.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, "", false, err
		}
		return false, "", true, fmt.Errorf("external authorization DNS lookup failed: %w", err)
	}
	var candidate string
	for _, record := range records {
		if isDMARCRecord(record) {
			if candidate != "" {
				return false, "", false, errors.New("multiple authorization records")
			}
			candidate = record
		}
	}
	if candidate == "" {
		return false, "", false, errors.New("authorization record absent")
	}
	for _, field := range splitDmarcFields(candidate) {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "rua") {
			for _, endpoint := range strings.Split(value, ",") {
				_, domain, parseErr := parseAggregateDestination(strings.TrimSpace(endpoint))
				if parseErr == nil && domain == destinationDomain {
					return true, strings.TrimSpace(endpoint), false, nil
				}
			}
			return false, "", false, errors.New("authorization override does not target authorizing domain")
		}
	}
	return true, "", false, nil
}

func parseAggregateDestination(raw string) (string, string, error) {
	value := strings.TrimSpace(raw)
	if bang := strings.LastIndex(value, "!"); bang > strings.LastIndex(value, "@") {
		value = value[:bang]
	}
	parsed, err := url.Parse(value)
	if err != nil || !strings.EqualFold(parsed.Scheme, "mailto") || parsed.Opaque == "" || parsed.RawQuery != "" {
		return "", "", errors.New("unsupported or malformed DMARC rua URI")
	}
	recipient, err := url.PathUnescape(parsed.Opaque)
	if err != nil {
		return "", "", errors.New("malformed DMARC rua URI")
	}
	address, err := mail.ParseAddress(recipient)
	if err != nil || address.Address != recipient {
		return "", "", errors.New("DMARC rua must contain one addr-spec")
	}
	at := strings.LastIndex(recipient, "@")
	domain, err := normalizeReportDomain(recipient[at+1:])
	if err != nil {
		return "", "", err
	}
	return recipient, domain, nil
}

func (r *AggregateReporter) retry(ctx context.Context, key string, job AggregateReportJob, message string) (AggregateReportJob, error) {
	job.Status = AggregateReportRetrying
	job.LastError = truncate(message, 512)
	job.UpdatedAt = r.now().UTC()
	job.NextAttemptAt = job.UpdatedAt.Add(time.Duration(1<<min(job.Attempts, 6)) * 5 * time.Minute)
	return job, r.saveJob(ctx, key, job)
}
func (r *AggregateReporter) terminal(ctx context.Context, key string, job AggregateReportJob, status, message string) (AggregateReportJob, error) {
	job.Status = status
	job.LastError = truncate(message, 512)
	job.NextAttemptAt = time.Time{}
	job.UpdatedAt = r.now().UTC()
	return job, r.saveJob(ctx, key, job)
}
func isAggregateTerminal(status string) bool {
	return status == AggregateReportDelivered || status == AggregateReportIgnored || status == AggregateReportExpired
}
func (r *AggregateReporter) loadJob(ctx context.Context, key string) (AggregateReportJob, bool, error) {
	data, err := r.store.Get(ctx, model.NSDMARCAggregates, key)
	if errors.Is(err, store.ErrNotFound) {
		return AggregateReportJob{}, false, nil
	}
	if err != nil {
		return AggregateReportJob{}, false, err
	}
	var job AggregateReportJob
	err = json.Unmarshal(data, &job)
	return job, true, err
}
func (r *AggregateReporter) saveJob(ctx context.Context, key string, job AggregateReportJob) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return r.store.Set(ctx, model.NSDMARCAggregates, key, data)
}
func (r *AggregateReporter) Jobs(ctx context.Context) ([]AggregateReportJob, error) {
	return listAggregateReportJobs(ctx, r.store)
}
func (r *AggregateRecorder) Jobs(ctx context.Context) ([]AggregateReportJob, error) {
	return listAggregateReportJobs(ctx, r.store)
}
func listAggregateReportJobs(ctx context.Context, backend store.Store) ([]AggregateReportJob, error) {
	var jobs []AggregateReportJob
	err := backend.Iterate(ctx, model.NSDMARCAggregates, dmarcJobPrefix, func(_ string, value []byte) (bool, error) {
		var job AggregateReportJob
		if err := json.Unmarshal(value, &job); err != nil {
			return false, err
		}
		jobs = append(jobs, job)
		return true, nil
	})
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].UpdatedAt.After(jobs[j].UpdatedAt) })
	return jobs, err
}
