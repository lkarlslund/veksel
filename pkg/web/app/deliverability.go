package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/dmarc"
	"github.com/lkarlslund/veksel/pkg/mailidentity"
	"github.com/lkarlslund/veksel/pkg/messagetrace"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	// deliverabilityKind marks test messages in the queue and message trace.
	deliverabilityKind = "deliverability-test"
	// The self-test sends external mail, so it is limited installation-wide:
	// a burst of three, then one every five minutes.
	deliverabilityBurst           = 3
	deliverabilityRefillPerSecond = 1.0 / 300
	deliverabilityLimiterKey      = "deliverability-self-test"
	deliverabilityTimeout         = 15 * time.Second
)

// deliverabilityChecks are the local DNS and reputation checks for one
// sending domain and the server's public addresses.
type deliverabilityChecks struct {
	resolver   DNSResolver
	blocklists SpamBlocklists
	zones      []spam.Zone
	server     string
	domain     model.Domain
	from       string
	addrs      []netip.Addr
	addrsErr   error
}

func (c deliverabilityChecks) run(ctx context.Context) []adminCheck {
	spfCheck, spfPass := c.spf(ctx)
	dkimCheck, dkimPass := c.dkim(ctx)
	return []adminCheck{spfCheck, dkimCheck, c.dmarc(ctx, spfPass, dkimPass), c.reverseDNS(ctx), c.blocklistListing(ctx)}
}

func (c deliverabilityChecks) addressList() string {
	parts := make([]string, len(c.addrs))
	for index, addr := range c.addrs {
		parts[index] = addr.String()
	}
	return strings.Join(parts, ", ")
}

// spf evaluates the sending domain's SPF policy for every public address.
func (c deliverabilityChecks) spf(ctx context.Context) (adminCheck, bool) {
	check := adminCheck{ID: "spf", Label: "SPF authorizes the server's public addresses"}
	if len(c.addrs) == 0 {
		check.Status, check.Detail = checkFail, "The server's public address is unknown"+prefixed(": ", errorText(c.addrsErr))
		check.Remediation = "Publish an A/AAAA record for " + c.server + " or set smtp_public_address."
		return check, false
	}
	pass := true
	for _, addr := range c.addrs {
		verdict := evaluateSPF(ctx, c.resolver, c.domain.ID, c.server, addr)
		switch {
		case verdict.problem != "":
			pass = false
			check.Items = append(check.Items, addr.String()+": "+verdict.problem)
		case verdict.authorized:
			check.Items = append(check.Items, addr.String()+": "+string(verdict.outcome.Result))
		default:
			pass = false
			check.Items = append(check.Items, addr.String()+": not authorized (SPF "+string(verdict.outcome.Result)+")")
		}
	}
	if pass {
		check.Status, check.Detail = checkPass, "SPF for "+c.domain.ID+" passes for "+c.addressList()+"."
		return check, true
	}
	check.Status, check.Detail = checkFail, "SPF for "+c.domain.ID+" does not pass for every public address."
	check.Remediation = "Publish one TXT record at " + c.domain.ID + " such as \"" + dkim.SPFDNSRecord(true) + "\", or add ip4:/ip6: terms for " + c.addressList() + "."
	return check, false
}

// dkim signs a sample message with the domain's active key and verifies the
// signature against the key published in DNS.
func (c deliverabilityChecks) dkim(ctx context.Context) (adminCheck, bool) {
	check := adminCheck{ID: "dkim", Label: "DKIM signature verifies against published DNS"}
	key, ok := model.ActiveDKIMKey(c.domain)
	if !ok {
		check.Status, check.Detail = checkFail, c.domain.ID+" has no active DKIM key, so outgoing mail is unsigned."
		check.Remediation = "Generate and activate a DKIM key for " + c.domain.ID + " under Domains, then publish its TXT record."
		return check, false
	}
	sample := "From: " + c.from + "\r\nTo: " + c.from + "\r\nSubject: Veksel DKIM self-test\r\nDate: " + time.Now().UTC().Format(time.RFC1123Z) +
		"\r\nMessage-ID: <dkim-self-test@" + c.domain.ID + ">\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nDKIM self-test.\r\n"
	signed, err := dkim.Sign([]byte(sample), c.domain.ID, key.Selector, []byte(key.PrivateKey))
	if err != nil {
		check.Status, check.Detail = checkFail, "Signing with selector "+key.Selector+" failed: "+err.Error()
		check.Remediation = "Rotate the DKIM key for " + c.domain.ID + "."
		return check, false
	}
	result := dkim.Verifier{LookupTXT: c.resolver.LookupTXT}.Verify(ctx, signed)
	check.Items = []string{"Selector " + key.Selector + "._domainkey." + c.domain.ID + ": " + result.Status}
	if result.Pass {
		check.Status, check.Detail = checkPass, "Signed with selector "+key.Selector+" and verified against DNS."
		return check, true
	}
	check.Status, check.Detail = checkFail, "Verification "+result.Status+prefixed(": ", result.Reason)
	check.Remediation = "Publish the TXT record \"" + dkim.DKIMDNSRecord([]byte(key.PublicKey)) + "\" at " + key.Selector + "._domainkey." + c.domain.ID + "."
	return check, false
}

// dmarc evaluates the published policy for a message From the domain with
// the SPF and DKIM outcomes above, which both use the From domain.
func (c deliverabilityChecks) dmarc(ctx context.Context, spfPass, dkimPass bool) adminCheck {
	check := adminCheck{ID: "dmarc", Label: "DMARC policy published and aligned"}
	evaluator := dmarc.Evaluator{Resolver: c.resolver, Timeout: dnsGuidanceTimeout, Sample: func(int) bool { return true }}
	result := evaluator.Evaluate(ctx, &dmarc.DmarcPolicy{Mode: dmarc.DmarcPolicyWarn}, c.domain.ID, c.domain.ID, spfPass, []string{c.domain.ID}, dkimPass)
	remediation := "Publish a TXT record at _dmarc." + c.domain.ID + " such as \"" + dkim.DMARCDNSRecord(10, "dmarc@"+c.domain.ID) + "\"."
	if result.Reporting != nil {
		check.Items = []string{"Policy p=" + result.Reporting.Policy + " published at _dmarc." + result.Reporting.Domain}
	}
	switch {
	case result.Result == "none":
		check.Status, check.Detail, check.Remediation = checkFail, "No DMARC record is published for "+c.domain.ID+".", remediation
	case result.Result == "pass" && result.Reporting != nil && result.Reporting.Policy == "none":
		check.Status, check.Detail = checkWarn, "Aligned, but p=none only monitors; receivers may still treat the mail as unauthenticated."
		check.Remediation = "Once reports look clean, raise the policy to p=quarantine or p=reject."
	case result.Result == "pass":
		check.Status, check.Detail = checkPass, "Aligned through "+alignedVia(result)+"."
	case result.Result == "fail":
		check.Status, check.Detail = checkFail, "Neither SPF nor DKIM aligns with "+c.domain.ID+"."
		check.Remediation = "Fix the SPF and DKIM findings above; either one aligned is enough."
	default:
		check.Status, check.Detail, check.Remediation = checkFail, "The DMARC record could not be evaluated ("+result.Result+").", remediation
	}
	return check
}

func alignedVia(result *dmarc.DmarcResult) string {
	switch {
	case result.SpfPass && result.DkimPass:
		return "SPF and DKIM"
	case result.SpfPass:
		return "SPF"
	}
	return "DKIM"
}

// reverseDNS verifies forward-confirmed reverse DNS of every address.
func (c deliverabilityChecks) reverseDNS(ctx context.Context) adminCheck {
	check := adminCheck{ID: "reverse-dns", Label: "Reverse DNS (PTR) forward-confirms the host name"}
	if len(c.addrs) == 0 {
		check.Status, check.Detail = checkFail, "The server's public address is unknown."
		check.Remediation = "Publish an A/AAAA record for " + c.server + " or set smtp_public_address."
		return check
	}
	failed := false
	for _, addr := range c.addrs {
		if problems := mailidentity.FCrDNS(ctx, c.resolver, c.server, addr.String()); len(problems) > 0 {
			failed = true
			check.Items = append(check.Items, addr.String()+": "+strings.Join(problems, "; "))
		} else {
			check.Items = append(check.Items, addr.String()+": "+c.server)
		}
	}
	if failed {
		check.Status, check.Detail = checkFail, "Reverse DNS does not confirm "+c.server+"."
		check.Remediation = "Ask your IP provider to set the PTR record of " + c.addressList() + " to " + c.server + "."
		return check
	}
	check.Status, check.Detail = checkPass, "Every address reverse-resolves to "+c.server+" and back."
	return check
}

// blocklistListing queries the configured DNSBL zones for every public
// address through the shared antispam DNS layer.
func (c deliverabilityChecks) blocklistListing(ctx context.Context) adminCheck {
	check := adminCheck{ID: "dnsbl", Label: "Public addresses are not on DNS blocklists"}
	switch {
	case c.blocklists == nil:
		check.Status, check.Detail = checkUnknown, "Blocklist lookups are unavailable."
		return check
	case len(c.zones) == 0:
		check.Status, check.Detail = checkUnknown, "No DNSBL zones are configured."
		return check
	case len(c.addrs) == 0:
		check.Status, check.Detail = checkUnknown, "The server's public address is unknown."
		return check
	}
	listed, inconclusive := 0, 0
	for _, addr := range c.addrs {
		for _, listing := range c.blocklists.CheckAddress(ctx, addr, c.zones) {
			switch {
			case listing.Listed:
				listed++
				check.Items = append(check.Items, addr.String()+" listed on "+listing.Zone+prefixed(": ", strings.Join(listing.Reasons, ", ")))
			case listing.Refused:
				inconclusive++
				check.Items = append(check.Items, listing.Zone+" refused the query (public resolver?)")
			case listing.Error != "":
				inconclusive++
				check.Items = append(check.Items, listing.Zone+": "+listing.Error)
			}
		}
	}
	switch {
	case listed > 0:
		check.Status, check.Detail = checkFail, fmt.Sprintf("%d blocklist listing(s) found.", listed)
		check.Remediation = "Find and stop the cause (compromised account, open relay, shared address), then request delisting at each list's website."
	case inconclusive > 0:
		check.Status, check.Detail = checkWarn, "Some blocklists could not be checked."
		check.Remediation = "Run a local caching resolver and set antispam_dns_resolver; public resolvers are refused by most lists."
	default:
		check.Status, check.Detail = checkPass, fmt.Sprintf("Not listed on %d zone(s).", len(c.zones))
	}
	return check
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// publicAddresses returns the server's egress addresses: the configured
// smtp_public_address, otherwise the addresses of the SMTP host name.
func publicAddresses(ctx context.Context, resolver DNSResolver, server, publicAddr string) ([]netip.Addr, error) {
	if publicAddr != "" {
		addr, err := netip.ParseAddr(publicAddr)
		if err != nil {
			return nil, fmt.Errorf("smtp_public_address %q is not an IP address", publicAddr)
		}
		return []netip.Addr{addr.Unmap()}, nil
	}
	hosts, err := resolver.LookupHost(ctx, server)
	addrs := parseAddrs(hosts)
	if len(addrs) == 0 && err == nil {
		err = errors.New(server + " has no addresses")
	}
	return addrs, err
}

// deliverabilityMessage is the queue and trace outcome of a test message.
type deliverabilityMessage struct {
	QueueID           string               `json:"queue_id"`
	Recipient         string               `json:"recipient"`
	Status            string               `json:"status"`
	Final             bool                 `json:"final"`
	TransportSecurity string               `json:"transport_security,omitempty"`
	TLSPolicy         string               `json:"tls_policy,omitempty"`
	Destination       string               `json:"destination,omitempty"`
	Code              string               `json:"code,omitempty"`
	Response          string               `json:"response,omitempty"`
	Events            []messagetrace.Event `json:"events"`
}

// deliverabilityOutcome projects the trace record of a test message; the
// latest event carrying delivery evidence supplies the remote outcome.
func deliverabilityOutcome(record messagetrace.Record) deliverabilityMessage {
	message := deliverabilityMessage{QueueID: record.QueueID, Recipient: record.Recipient, Status: record.Status,
		TransportSecurity: record.TransportSecurity, Events: record.Events}
	if message.Events == nil {
		message.Events = []messagetrace.Event{}
	}
	switch queue.Status(record.Status) {
	case queue.StatusDelivered, queue.StatusFailed, queue.StatusCancelled:
		message.Final = true
	}
	for _, event := range record.Events {
		if event.Destination != "" {
			message.Destination = event.Destination
		}
		if event.TLSPolicy != "" {
			message.TLSPolicy = event.TLSPolicy
		}
		if event.Code != "" || event.Response != "" {
			message.Code, message.Response = event.Code, event.Response
		}
	}
	return message
}

type deliverabilityReport struct {
	From        string                 `json:"from"`
	Domain      string                 `json:"domain"`
	ServerName  string                 `json:"server_name"`
	Addresses   []string               `json:"addresses"`
	Checks      []adminCheck           `json:"checks"`
	Passed      int                    `json:"passed"`
	Failed      int                    `json:"failed"`
	TestMessage *deliverabilityMessage `json:"test_message,omitempty"`
	CheckedAt   time.Time              `json:"checked_at"`
}

// blocklistZones returns the configured DNSBL zones.
func (h *Handler) blocklistZones() []spam.Zone {
	cfg := h.effectiveConfig()
	if cfg == nil {
		return nil
	}
	settings, err := spam.ParseSettings(cfg.AntispamSettings())
	if err != nil {
		return nil
	}
	return settings.DNSBL
}

// apiAdminDeliverabilitySelfTest runs the local checks for the chosen
// sending identity and, when a recipient is given, queues a DKIM-signed test
// message through normal outbound delivery.
func (h *Handler) apiAdminDeliverabilitySelfTest(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var request struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	from := strings.ToLower(strings.TrimSpace(request.From))
	identity, err := h.users.GetEmailAddress(r.Context(), from)
	if err != nil || !identity.Enabled {
		jsonError(w, http.StatusBadRequest, "choose an enabled hosted identity to send from")
		return
	}
	domain, err := h.ts.DomainStore().Get(r.Context(), addressDomain(identity.ID))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "the identity's domain is not hosted")
		return
	}
	to := ""
	if strings.TrimSpace(request.To) != "" {
		parsed, err := mail.ParseAddress(strings.TrimSpace(request.To))
		if err != nil || addressDomain(parsed.Address) == "" {
			jsonError(w, http.StatusBadRequest, "recipient must be a single email address")
			return
		}
		to = strings.ToLower(parsed.Address)
		if _, err := h.ts.DomainStore().Get(r.Context(), addressDomain(to)); err == nil {
			jsonError(w, http.StatusBadRequest, "send the test to an external address; a hosted domain never leaves this server")
			return
		}
	}
	if !h.deliverabilityLimiter.Allow(deliverabilityLimiterKey) {
		w.Header().Set("Retry-After", strconv.Itoa(max(int(h.deliverabilityLimiter.RetryAfter(deliverabilityLimiterKey).Seconds()), 1)))
		jsonError(w, http.StatusTooManyRequests, "the deliverability self-test is rate limited; try again later")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), deliverabilityTimeout)
	defer cancel()
	server, resolver := h.smtpIdentity(), h.guidanceResolver()
	checks := deliverabilityChecks{resolver: resolver, blocklists: h.spamBlocklists, zones: h.blocklistZones(), server: server, domain: domain, from: identity.ID}
	checks.addrs, checks.addrsErr = publicAddresses(ctx, resolver, server, h.smtpPublicAddress())
	report := deliverabilityReport{From: identity.ID, Domain: domain.ID, ServerName: server, Addresses: []string{}, Checks: checks.run(ctx), CheckedAt: time.Now().UTC()}
	for _, addr := range checks.addrs {
		report.Addresses = append(report.Addresses, addr.String())
	}
	for _, check := range report.Checks {
		switch check.Status {
		case checkPass:
			report.Passed++
		case checkFail:
			report.Failed++
		}
	}
	actor := currentActor(r).ID
	details := map[string]string{"from": identity.ID, "passed": strconv.Itoa(report.Passed), "failed": strconv.Itoa(report.Failed)}
	if to != "" {
		queueID, err := h.enqueueDeliverabilityTest(actor, identity.ID, to)
		if err != nil {
			h.audit.Log(actor, "deliverability.self_test", identity.ID, details)
			jsonError(w, http.StatusServiceUnavailable, "the test message could not be queued: "+err.Error())
			return
		}
		details["to"], details["queue_id"] = to, queueID
		report.TestMessage = &deliverabilityMessage{QueueID: queueID, Recipient: to, Status: string(queue.StatusPending), Events: []messagetrace.Event{}}
	}
	h.audit.Log(actor, "deliverability.self_test", identity.ID, details)
	jsonResponse(w, http.StatusOK, report)
}

// enqueueDeliverabilityTest queues a fixed-content test message. The queue
// signs it with the From domain's DKIM key and delivers it like any other
// outbound message, recording the outcome in message trace.
func (h *Handler) enqueueDeliverabilityTest(actor, from, to string) (string, error) {
	enqueuer, ok := h.systemQueue.(interface{ Enqueue(*queue.Message) error })
	if !ok {
		return "", errors.New("the outbound queue is unavailable")
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	id := deliverabilityKind + "-" + hex.EncodeToString(nonce)
	now := time.Now().UTC()
	headers := map[string]string{
		"From":         (&mail.Address{Name: "Veksel deliverability test", Address: from}).String(),
		"To":           (&mail.Address{Address: to}).String(),
		"Subject":      "Veksel deliverability test",
		"Message-ID":   "<" + id + "@" + addressDomain(from) + ">",
		"Date":         now.Format(time.RFC1123Z),
		"MIME-Version": "1.0",
		"Content-Type": "text/plain; charset=utf-8",
	}
	body := []byte("This message was sent by a Veksel administrator to test outbound delivery,\r\n" +
		"SPF, DKIM, and DMARC from " + from + ".\r\n\r\n" +
		"Receivers record their authentication verdict in the Authentication-Results\r\n" +
		"header of this message. No reply is needed.\r\n")
	message := &queue.Message{ID: id, Kind: deliverabilityKind, Direction: queue.DirectionOutbound, EnvelopeSender: from, Recipient: to,
		Headers: headers, Body: body, Status: queue.StatusPending, CreatedAt: now, CorrelationID: id, AuthenticatedActor: actor, DKIM: &dkim.Request{}}
	if err := enqueuer.Enqueue(message); err != nil {
		return "", err
	}
	return id, nil
}

// apiAdminDeliverabilityMessage reports the queue and trace outcome of a
// test message sent by the self-test.
func (h *Handler) apiAdminDeliverabilityMessage(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	id := r.PathValue("id")
	if !strings.HasPrefix(id, deliverabilityKind+"-") {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if h.messageTrace == nil {
		jsonError(w, http.StatusServiceUnavailable, "message trace is unavailable")
		return
	}
	record, err := h.messageTrace.Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		jsonResponse(w, http.StatusOK, deliverabilityMessage{QueueID: id, Status: string(queue.StatusPending), Events: []messagetrace.Event{}})
		return
	}
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, deliverabilityOutcome(record))
}
