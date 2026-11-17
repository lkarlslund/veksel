package app

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/alertnotify"
	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/certificates"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/dane"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/mailidentity"
	"github.com/lkarlslund/veksel/pkg/messagetrace"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Check statuses shared by the first-run checklist and the deliverability
// self-test.
const (
	checkPass    = "pass"
	checkWarn    = "warn"
	checkFail    = "fail"
	checkUnknown = "unknown"
)

const (
	// setupChecklistTTL bounds how long gathered evidence is reused before
	// the next view re-reads DNS and runtime state.
	setupChecklistTTL = 10 * time.Minute
	// setupDismissedKey stores dismissed checklist items in the metadata
	// namespace, shared by every system administrator.
	setupDismissedKey = "setup_checklist_dismissed"
	// port25ProbeDomain names the mail domain whose MX the optional active
	// probe dials; any large, always-reachable receiver works.
	port25ProbeDomain  = "gmail.com"
	port25ProbeTimeout = 8 * time.Second
)

// adminCheck is one pass/warn/fail finding with the evidence behind it and
// how to fix it. The checklist links to a fixing page; the deliverability
// report explains the remedy in text.
type adminCheck struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Status      string   `json:"status"`
	Detail      string   `json:"detail"`
	Items       []string `json:"items,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	FixURL      string   `json:"fix_url,omitempty"`
	FixLabel    string   `json:"fix_label,omitempty"`
	// Action names an in-page action the UI offers instead of a link.
	Action    string `json:"action,omitempty"`
	Dismissed bool   `json:"dismissed"`
}

// port25Result is the outcome of the optional outbound SMTP probe.
type port25Result struct {
	Target    string    `json:"target"`
	OK        bool      `json:"ok"`
	Banner    string    `json:"banner,omitempty"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// setupEvidence is everything the checklist inspects, gathered once and
// cached, so every check is a pure function of it.
type setupEvidence struct {
	Domains    []model.Domain
	DomainsErr error
	ServerName string
	Config     *config.Config
	// Health is nil when runtime health is unavailable.
	Health      []health.Component
	DNS         []dnsGuidanceResponse
	PTR         []dnsGuidanceRecord
	Backup      *backup.ScheduleStatus
	Alerts      *alertnotify.Status
	AlertsErr   error
	DANE        dane.Status
	TraceKnown  bool
	Delivered   *messagetrace.Record
	Port25      *port25Result
	GatheredAt  time.Time
	healthKnown bool
}

func (e setupEvidence) component(id string) (health.Component, bool) {
	for _, component := range e.Health {
		if component.ID == id {
			return component, true
		}
	}
	return health.Component{}, false
}

// setupChecks are the cached installation checks in display order. The
// administrator's own second factor is checked per request.
var setupChecks = []func(setupEvidence) adminCheck{
	setupHostedDomain, setupHostName, setupHTTPSCertificate, setupMailTLS, setupMailDNS, setupReverseDNS,
	setupOutboundPort25, setupScheduledBackups, setupAlertDelivery, setupLocalResolver, setupTestDelivery,
}

// setupCheckIDs lists every checklist item that can be dismissed.
var setupCheckIDs = []string{
	"hosted-domain", "host-name", "https-certificate", "mail-tls", "mail-dns", "reverse-dns",
	"outbound-port25", "scheduled-backups", "alert-delivery", "local-resolver", "admin-two-factor", "test-delivery",
}

func setupHostedDomain(e setupEvidence) adminCheck {
	check := adminCheck{ID: "hosted-domain", Label: "Hosted domain exists", FixURL: "/app/admin/domains", FixLabel: "Add a domain"}
	switch {
	case e.DomainsErr != nil:
		check.Status, check.Detail = checkUnknown, "Domains could not be read: "+e.DomainsErr.Error()
	case len(e.Domains) == 0:
		check.Status, check.Detail = checkFail, "No mail domain is hosted yet; mail cannot be received."
	default:
		enabled := 0
		for _, domain := range e.Domains {
			if domain.Enabled {
				enabled++
				check.Items = append(check.Items, domain.ID)
			}
		}
		check.Status, check.Detail = checkPass, fmt.Sprintf("%d hosted domain(s).", enabled)
		if enabled == 0 {
			check.Status, check.Detail = checkFail, "Every hosted domain is disabled."
		}
	}
	return check
}

func setupHostName(e setupEvidence) adminCheck {
	check := adminCheck{ID: "host-name", Label: "Public host name is a fully qualified domain name", FixURL: "/app/admin/protocols/smtp", FixLabel: "Set the SMTP host name"}
	if err := mailidentity.ValidateFQDN(e.ServerName); err != nil {
		check.Status, check.Detail = checkFail, fmt.Sprintf("%q: %v", e.ServerName, err)
		return check
	}
	check.Status, check.Detail = checkPass, e.ServerName
	return check
}

func setupHTTPSCertificate(e setupEvidence) adminCheck {
	check := adminCheck{ID: "https-certificate", Label: "HTTPS certificate assigned and valid", FixURL: "/app/admin/certificates", FixLabel: "Manage certificates"}
	if e.Config == nil {
		check.Status, check.Detail = checkUnknown, "Configuration is unavailable."
		return check
	}
	worst := checkPass
	raise := func(status string) {
		rank := map[string]int{checkPass: 0, checkUnknown: 1, checkWarn: 2, checkFail: 3}
		if rank[status] > rank[worst] {
			worst = status
		}
	}
	for _, listener := range e.Config.HTTPListeners {
		if !listener.Enabled || listener.Transport != config.HTTPSTransport {
			continue
		}
		assignment := strings.TrimSpace(listener.Certificate)
		label := listener.Name + ": " + assignment
		switch {
		case strings.HasPrefix(assignment, certificates.ACMEPrefix):
			check.Items = append(check.Items, label+" (issued and renewed automatically)")
		case strings.HasPrefix(assignment, certificates.StoredPrefix):
			name := strings.TrimSpace(strings.TrimPrefix(assignment, certificates.StoredPrefix))
			component, found := e.component("certificate:" + name)
			switch {
			case !e.healthKnown || !found:
				raise(checkUnknown)
				check.Items = append(check.Items, label+" (certificate health unknown)")
			case component.State == health.StateHealthy:
				check.Items = append(check.Items, label+" (valid until "+component.Details["expires_at"]+")")
			case component.State == health.StateDegraded:
				raise(checkWarn)
				check.Items = append(check.Items, label+": "+component.Reason)
			default:
				raise(checkFail)
				check.Items = append(check.Items, label+": "+component.Reason)
			}
		default:
			raise(checkFail)
			check.Items = append(check.Items, listener.Name+": no certificate assigned")
		}
	}
	switch {
	case len(check.Items) == 0 && len(e.Config.HTTPTrustedProxies) > 0:
		check.Status, check.Detail = checkWarn, "No HTTPS listener; HTTPS is expected to terminate at the trusted reverse proxy."
	case len(check.Items) == 0:
		check.Status, check.Detail = checkFail, "No HTTPS listener is enabled; browsers and clients connect without TLS."
	default:
		check.Status = worst
		check.Detail = map[string]string{checkPass: "Every HTTPS listener has a valid certificate.", checkWarn: "A certificate expires soon.", checkFail: "An HTTPS listener lacks a usable certificate.", checkUnknown: "Certificate health could not be confirmed."}[worst]
	}
	return check
}

// mailTLSProtocols are the mail listener health components, with the admin
// page that assigns their certificate.
var mailTLSProtocols = []struct{ id, page string }{
	{"smtp", "/app/admin/protocols/smtp"},
	{"imap", "/app/admin/protocols/imap"},
	{"pop3", "/app/admin/protocols/pop3"},
	{"managesieve", "/app/admin/protocols/managesieve"},
}

// setupMailTLS fails while an enabled mail listener runs without a
// certificate: SMTP then offers no STARTTLS (MTA-STS and DANE senders cannot
// deliver) and clients sign in unencrypted or not at all. It reads the
// listeners' own health reasons, so it follows exactly what they serve.
func setupMailTLS(e setupEvidence) adminCheck {
	check := adminCheck{ID: "mail-tls", Label: "Mail protocols offer TLS", FixURL: "/app/admin/protocols/smtp", FixLabel: "Assign a certificate"}
	if !e.healthKnown {
		check.Status, check.Detail = checkUnknown, "Listener health is unavailable."
		return check
	}
	enabled := 0
	for _, protocol := range mailTLSProtocols {
		component, found := e.component(protocol.id)
		if !found || component.State == health.StateDisabled {
			continue
		}
		enabled++
		if reason := component.Reason; strings.Contains(reason, "no assigned certificate") || strings.Contains(reason, "no certificate is assigned") {
			if len(check.Items) == 0 {
				check.FixURL = protocol.page
			}
			check.Items = append(check.Items, component.Label+": "+reason)
		}
	}
	switch {
	case len(check.Items) > 0:
		check.Status, check.Detail = checkFail, "An enabled mail listener has no certificate."
		check.Remediation = "Assign a certificate (for example the HTTPS host's) in the protocol's Certificate setting."
	case enabled == 0:
		check.Status, check.Detail = checkPass, "No mail listener is enabled."
	default:
		check.Status, check.Detail = checkPass, "Every enabled mail listener has a certificate."
	}
	return check
}

func setupMailDNS(e setupEvidence) adminCheck {
	check := adminCheck{ID: "mail-dns", Label: "MX, SPF, DKIM, and DMARC records published", FixURL: "/app/admin/domains", FixLabel: "Review DNS records"}
	if len(e.DNS) == 0 {
		check.Status, check.Detail = checkUnknown, "No hosted domain to check."
		return check
	}
	failing := 0
	for _, guidance := range e.DNS {
		var problems []string
		for _, record := range guidance.Records {
			if record.Type == "PTR" || record.Status == dnsOK {
				continue
			}
			problems = append(problems, record.Type+" "+record.Status)
		}
		if !slices.ContainsFunc(guidance.Records, func(record dnsGuidanceRecord) bool { return record.Type == "DKIM" }) {
			problems = append(problems, "DKIM no key")
		}
		if len(problems) == 0 {
			check.Items = append(check.Items, guidance.Domain+": all records published")
			continue
		}
		failing++
		check.Items = append(check.Items, guidance.Domain+": "+strings.Join(problems, ", "))
	}
	check.Status, check.Detail = checkPass, "Every hosted domain publishes the expected records."
	if failing > 0 {
		check.Status, check.Detail = checkFail, fmt.Sprintf("%d of %d domain(s) are missing or mismatching records.", failing, len(e.DNS))
	}
	return check
}

func setupReverseDNS(e setupEvidence) adminCheck {
	check := adminCheck{ID: "reverse-dns", Label: "Reverse DNS (PTR) matches the host name and forward-confirms", FixURL: "/app/admin/domains", FixLabel: "View PTR guidance"}
	if len(e.PTR) == 0 {
		check.Status, check.Detail = checkUnknown, "Reverse DNS was not checked."
		return check
	}
	ok := 0
	for _, record := range e.PTR {
		item := record.Name + " → " + strings.Join(record.Live, ", ")
		if len(record.Live) == 0 {
			item = record.Name + " → (" + record.Status + ")"
		}
		if record.Status != dnsOK {
			item += ": " + cmp.Or(record.Error, record.Note)
		} else {
			ok++
		}
		check.Items = append(check.Items, item)
	}
	check.Status, check.Detail = checkPass, "Every address reverse-resolves to "+e.ServerName+"."
	if ok < len(e.PTR) {
		check.Status, check.Detail = checkFail, "Set the PTR record at your IP provider to "+e.ServerName+"; many receivers reject mail without it."
	}
	return check
}

func setupOutboundPort25(e setupEvidence) adminCheck {
	check := adminCheck{ID: "outbound-port25", Label: "Outbound port 25 reachable", Action: "probe-port25", FixURL: "/app/admin/routing", FixLabel: "Configure a smarthost"}
	switch {
	case e.Port25 == nil:
		check.Status, check.Detail = checkUnknown, "Not probed. Run the probe to dial a public mail server on port 25."
	case e.Port25.OK:
		check.Status, check.Detail = checkPass, "Connected to "+e.Port25.Target+"."
		if e.Port25.Banner != "" {
			check.Items = []string{e.Port25.Banner}
		}
	default:
		check.Status, check.Detail = checkFail, "Could not reach "+e.Port25.Target+": "+e.Port25.Error+". Many networks block port 25; relay through a smarthost on port 587."
	}
	return check
}

func setupScheduledBackups(e setupEvidence) adminCheck {
	check := adminCheck{ID: "scheduled-backups", Label: "Scheduled backups write outside the data directory", FixURL: "/app/admin/operations/backup", FixLabel: "Configure backups"}
	status := e.Backup
	switch {
	case status == nil:
		check.Status, check.Detail = checkUnknown, "Backup configuration could not be read."
	case !status.Enabled:
		check.Status, check.Detail = checkFail, "Scheduled backups are off."
	case status.Downloadable:
		check.Status, check.Detail = checkWarn, "Backups are written to "+status.Directory+", inside the data directory; a disk failure loses both. Point backup_directory at another disk or mount."
	case status.State.LastResult == backup.ResultFailed:
		check.Status, check.Detail = checkFail, "The last scheduled backup failed: "+status.State.LastError
	default:
		check.Status, check.Detail = checkPass, status.Schedule+" into "+status.Directory+"."
		if !status.State.LastSuccessAt.IsZero() {
			check.Items = []string{"Last success " + status.State.LastSuccessAt.UTC().Format(time.RFC3339)}
		}
	}
	return check
}

func setupAlertDelivery(e setupEvidence) adminCheck {
	check := adminCheck{ID: "alert-delivery", Label: "Alert delivery channel configured", FixURL: "/app/admin/notifications", FixLabel: "Configure alert channels"}
	switch {
	case e.AlertsErr != nil:
		check.Status, check.Detail = checkUnknown, "Alert delivery status could not be read: "+e.AlertsErr.Error()
	case e.Alerts == nil:
		check.Status, check.Detail = checkUnknown, "Alert delivery is unavailable."
	case !e.Alerts.Enabled:
		check.Status, check.Detail = checkFail, "Alert notifications are disabled."
	default:
		for _, channel := range e.Alerts.Channels {
			if channel.Configured {
				check.Items = append(check.Items, channel.Label)
			}
		}
		check.Status, check.Detail = checkPass, "Alerts are delivered through "+strings.Join(check.Items, ", ")+"."
		if len(check.Items) == 0 {
			check.Status, check.Detail = checkFail, "No alert channel (mail, webhook, or push) is configured; failures are only visible in the console."
		}
	}
	return check
}

func setupLocalResolver(e setupEvidence) adminCheck {
	check := adminCheck{ID: "local-resolver", Label: "Local validating, caching DNS resolver", FixURL: "/app/admin/outbound-tls", FixLabel: "Configure resolvers"}
	validating := e.DANE.Validating == dane.ValidatingYes
	check.Items = append(check.Items, "DNSSEC validation: "+e.DANE.Validating+prefixed(": ", e.DANE.Detail))
	spamDNS, known := e.component("antispam-dns")
	blocklistsOK := true
	if known && spamDNS.State != health.StateDisabled {
		blocklistsOK = spamDNS.State == health.StateHealthy
		check.Items = append(check.Items, "Blocklist lookups via "+cmp.Or(spamDNS.Details["resolver"], "system resolver")+": "+cmp.Or(spamDNS.Reason, spamDNS.State))
	}
	switch {
	case validating && blocklistsOK:
		check.Status, check.Detail = checkPass, "A validating resolver answers DANE lookups and blocklists accept its queries."
	case !blocklistsOK:
		check.Status, check.Detail = checkWarn, "Blocklists refuse or fail queries from the configured resolver; run a local caching resolver such as Unbound."
	default:
		check.Status, check.Detail = checkWarn, "No DNSSEC-validating resolver was detected; DANE is inactive. Run a local validating resolver and set dane_resolvers."
	}
	return check
}

func setupTestDelivery(e setupEvidence) adminCheck {
	check := adminCheck{ID: "test-delivery", Label: "Test message delivered to an external address", Action: "self-test"}
	switch {
	case !e.TraceKnown:
		check.Status, check.Detail = checkUnknown, "Message trace is unavailable."
	case e.Delivered == nil:
		check.Status, check.Detail = checkWarn, "No deliverability test message has been delivered yet. Run the deliverability self-test."
	default:
		check.Status, check.Detail = checkPass, "Delivered to "+e.Delivered.Recipient+" at "+e.Delivered.UpdatedAt.UTC().Format(time.RFC3339)+"."
	}
	return check
}

// setupAdminTwoFactor checks the signed-in administrator's own account.
func setupAdminTwoFactor(factors model.SecondFactors, err error) adminCheck {
	check := adminCheck{ID: "admin-two-factor", Label: "Two-factor authentication on your administrator account", FixURL: "/app/settings/two-factor", FixLabel: "Enable two-factor"}
	switch {
	case err != nil && !errors.Is(err, store.ErrNotFound):
		check.Status, check.Detail = checkUnknown, "Second factors could not be read."
	case factors.Enabled():
		check.Status, check.Detail = checkPass, "A second factor protects this account."
	default:
		check.Status, check.Detail = checkFail, "This administrator signs in with a password alone."
	}
	return check
}

func prefixed(prefix, value string) string {
	if value == "" {
		return ""
	}
	return prefix + value
}

// setupChecklistCache holds the last gathered evidence and the last port 25
// probe, which only an explicit administrator action runs.
type setupChecklistCache struct {
	mu       sync.Mutex
	evidence *setupEvidence
	port25   *port25Result
}

// gatherSetupEvidence reads every input of the checklist. DNS checks run
// through the shared DNS guidance builder.
func (h *Handler) gatherSetupEvidence(ctx context.Context) setupEvidence {
	evidence := setupEvidence{Config: h.effectiveConfig(), ServerName: h.smtpIdentity(), DANE: h.outboundDANEStatus(), GatheredAt: time.Now().UTC()}
	evidence.Domains, evidence.DomainsErr = h.ts.DomainStore().List(ctx)
	sort.Slice(evidence.Domains, func(i, j int) bool { return evidence.Domains[i].ID < evidence.Domains[j].ID })
	resolver, publicAddr := h.guidanceResolver(), h.smtpPublicAddress()
	var wg sync.WaitGroup
	evidence.DNS = make([]dnsGuidanceResponse, 0, len(evidence.Domains))
	guidance := make([]*dnsGuidanceResponse, len(evidence.Domains))
	for index, domain := range evidence.Domains {
		if !domain.Enabled {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := buildDNSGuidance(ctx, resolver, domain, evidence.ServerName, publicAddr, dnsOptions{})
			guidance[index] = &response
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		lookupCtx, cancel := context.WithTimeout(ctx, dnsGuidanceTimeout)
		defer cancel()
		evidence.PTR = serverPTRRecords(lookupCtx, resolver, evidence.ServerName, publicAddr)
	}()
	if snapshot, ok := h.healthSnapshot(ctx); ok {
		evidence.Health, evidence.healthKnown = snapshot.Components, true
	}
	if h.backupScheduler != nil {
		status := h.backupScheduler.Status()
		evidence.Backup = &status
	} else if evidence.Config != nil {
		if policy, err := backup.SchedulePolicyFromConfig(evidence.Config); err == nil {
			evidence.Backup = &backup.ScheduleStatus{Schedule: policy.Schedule.String(), Enabled: policy.Schedule.Enabled, Directory: policy.Directory, Downloadable: policy.Downloadable()}
		}
	}
	if h.alertNotifier != nil {
		status, err := h.alertNotifier.Status(ctx)
		evidence.Alerts, evidence.AlertsErr = &status, err
	}
	if h.messageTrace != nil {
		evidence.TraceKnown = true
		page, err := h.messageTrace.List(ctx, messagetrace.Query{Status: string(queue.StatusDelivered), Direction: "outbound", Limit: 1,
			Visible: func(record messagetrace.Record) bool { return record.Kind == deliverabilityKind }})
		if err == nil && len(page.Records) > 0 {
			evidence.Delivered = &page.Records[0]
		}
		evidence.TraceKnown = err == nil
	}
	wg.Wait()
	for _, response := range guidance {
		if response != nil {
			evidence.DNS = append(evidence.DNS, *response)
		}
	}
	return evidence
}

// setupChecklistResponse is the Overview checklist projection.
type setupChecklistResponse struct {
	Checks     []adminCheck `json:"checks"`
	CheckedAt  time.Time    `json:"checked_at"`
	Passed     int          `json:"passed"`
	Attention  int          `json:"attention"`
	Dismissed  int          `json:"dismissed"`
	Identities []string     `json:"identities"`
}

// setupChecklist evaluates every check over cached evidence, refreshing it
// when stale or when refresh is requested.
func (h *Handler) setupChecklistFor(ctx context.Context, actorID string, refresh bool) setupChecklistResponse {
	cache := &h.setupChecklist
	cache.mu.Lock()
	if refresh || cache.evidence == nil || time.Since(cache.evidence.GatheredAt) > setupChecklistTTL {
		evidence := h.gatherSetupEvidence(ctx)
		cache.evidence = &evidence
	}
	evidence := *cache.evidence
	evidence.Port25 = cache.port25
	cache.mu.Unlock()
	checks := make([]adminCheck, 0, len(setupChecks)+1)
	for _, check := range setupChecks {
		checks = append(checks, check(evidence))
	}
	factors, err := h.secondFactors.Get(ctx, actorID)
	checks = slices.Insert(checks, len(checks)-1, setupAdminTwoFactor(factors, err))
	dismissed := h.setupDismissed(ctx)
	response := setupChecklistResponse{Checks: checks, CheckedAt: evidence.GatheredAt, Identities: h.senderIdentities(ctx, actorID)}
	for index := range response.Checks {
		check := &response.Checks[index]
		_, check.Dismissed = dismissed[check.ID]
		switch {
		case check.Dismissed:
			response.Dismissed++
		case check.Status == checkPass:
			response.Passed++
		default:
			response.Attention++
		}
	}
	return response
}

// senderIdentities lists enabled hosted identities for the self-test
// sender picker, the administrator's own first.
func (h *Handler) senderIdentities(ctx context.Context, actorID string) []string {
	const limit = 200
	addresses, err := h.users.ListAllEmailAddresses(ctx)
	if err != nil {
		return []string{}
	}
	sort.SliceStable(addresses, func(i, j int) bool {
		mineI, mineJ := addresses[i].UserID == actorID, addresses[j].UserID == actorID
		if mineI != mineJ {
			return mineI
		}
		return addresses[i].ID < addresses[j].ID
	})
	identities := make([]string, 0, min(len(addresses), limit))
	for _, address := range addresses {
		if address.Enabled && len(identities) < limit {
			identities = append(identities, address.ID)
		}
	}
	return identities
}

func (h *Handler) setupDismissed(ctx context.Context) map[string]time.Time {
	dismissed := map[string]time.Time{}
	if err := h.ts.Get(ctx, model.NSMetadata, setupDismissedKey, &dismissed); err != nil {
		return map[string]time.Time{}
	}
	return dismissed
}

func (h *Handler) apiAdminSetupChecklist(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	jsonResponse(w, http.StatusOK, h.setupChecklistFor(r.Context(), currentActor(r).ID, r.URL.Query().Get("refresh") == "1"))
}

func (h *Handler) apiAdminSetupChecklistDismiss(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var request struct {
		ID        string `json:"id"`
		Dismissed bool   `json:"dismissed"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !slices.Contains(setupCheckIDs, request.ID) {
		jsonError(w, http.StatusBadRequest, "unknown checklist item")
		return
	}
	dismissed := h.setupDismissed(r.Context())
	if request.Dismissed {
		dismissed[request.ID] = time.Now().UTC()
	} else {
		delete(dismissed, request.ID)
	}
	if err := h.ts.Set(r.Context(), model.NSMetadata, setupDismissedKey, dismissed); err != nil {
		apiError(w, err)
		return
	}
	action := "setup.checklist.dismiss"
	if !request.Dismissed {
		action = "setup.checklist.restore"
	}
	h.audit.Log(currentActor(r).ID, action, request.ID, nil)
	jsonResponse(w, http.StatusOK, h.setupChecklistFor(r.Context(), currentActor(r).ID, false))
}

// apiAdminSetupPort25Probe runs the optional active outbound port 25 probe
// and records its result in the checklist.
func (h *Handler) apiAdminSetupPort25Probe(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), port25ProbeTimeout)
	defer cancel()
	result := h.probePort25(ctx)
	h.setupChecklist.mu.Lock()
	h.setupChecklist.port25 = &result
	h.setupChecklist.mu.Unlock()
	h.audit.Log(currentActor(r).ID, "setup.port25_probe", result.Target, map[string]string{"ok": fmt.Sprint(result.OK), "error": result.Error})
	jsonResponse(w, http.StatusOK, h.setupChecklistFor(r.Context(), currentActor(r).ID, false))
}

// probePort25 dials the first MX of port25ProbeDomain on port 25 and reads
// its greeting.
func (h *Handler) probePort25(ctx context.Context) port25Result {
	result := port25Result{Target: port25ProbeDomain, CheckedAt: time.Now().UTC()}
	mx, err := h.guidanceResolver().LookupMX(ctx, port25ProbeDomain)
	if err != nil || len(mx) == 0 {
		result.Error = "cannot resolve the MX of " + port25ProbeDomain
		if err != nil {
			result.Error += ": " + err.Error()
		}
		return result
	}
	result.Target = net.JoinHostPort(normDNSHost(mx[0].Host), "25")
	dial := h.port25Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, "tcp", result.Target)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	}
	banner, err := bufio.NewReader(conn).ReadString('\n')
	banner = strings.TrimSpace(banner)
	switch {
	case strings.HasPrefix(banner, "220"):
		result.OK, result.Banner = true, banner
	case err != nil:
		result.Error = "connected but no SMTP greeting: " + err.Error()
	default:
		result.Error = "unexpected greeting: " + banner
	}
	return result
}
