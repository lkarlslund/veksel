package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/dnsprovider"
	"github.com/lkarlslund/veksel/pkg/mailidentity"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/mtasts"
	"github.com/lkarlslund/veksel/pkg/pgpkey"
)

// DNSResolver is the subset of *net.Resolver used for DNS guidance checks, so
// tests can substitute a fake without touching the network.
type DNSResolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

const dnsGuidanceTimeout = 4 * time.Second

// DNS record check statuses.
const (
	dnsOK       = "ok"
	dnsMissing  = "missing"
	dnsMismatch = "mismatch"
	dnsError    = "error"
)

type dnsGuidanceRecord struct {
	Type     string   `json:"type"`
	Name     string   `json:"name"`
	Expected string   `json:"expected"`
	Status   string   `json:"status"`
	Live     []string `json:"live"`
	Error    string   `json:"error,omitempty"`
	Note     string   `json:"note,omitempty"`
}

type dnsGuidanceResponse struct {
	Domain     string              `json:"domain"`
	ServerName string              `json:"server_name"`
	Records    []dnsGuidanceRecord `json:"records"`
	// Provider is the DNS provider zone covering the domain, when one is
	// configured, so the records can be published.
	Provider *dnsprovider.ZoneView `json:"provider,omitempty"`
}

// SetDNSResolver replaces the resolver used by DNS guidance (nil restores the
// system resolver).
func (h *Handler) SetDNSResolver(resolver DNSResolver) { h.dnsResolver = resolver }

// effectiveConfig is the live managed configuration, or the startup
// configuration when none is managed.
func (h *Handler) effectiveConfig() *config.Config {
	if h.configService != nil {
		return h.configService.Current().Config
	}
	return h.cfg
}

func (h *Handler) smtpIdentity() string {
	cfg := h.effectiveConfig()
	name := ""
	if cfg != nil {
		name = cfg.SmtpServerName
	}
	if strings.TrimSpace(name) == "" {
		name, _ = os.Hostname()
	}
	return normDNSHost(name)
}

func (h *Handler) smtpPublicAddress() string {
	cfg := h.effectiveConfig()
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.SmtpPublicAddress)
}

func (h *Handler) apiAdminDNSGuidance(w http.ResponseWriter, r *http.Request) {
	if !h.requireDomainAction(w, r, r.PathValue("id"), authz.DomainRead) {
		return
	}
	domain, err := h.ts.DomainStore().Get(r.Context(), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	response := h.domainDNSGuidance(r.Context(), domain)
	if view, err := h.dnsZones.ViewFor(r.Context(), domain.ID); err == nil {
		response.Provider = &view
	}
	jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) domainDNSGuidance(ctx context.Context, domain model.Domain) dnsGuidanceResponse {
	return buildDNSGuidance(ctx, h.guidanceResolver(), domain, h.smtpIdentity(), h.smtpPublicAddress(), h.dnsOptions())
}

// guidanceResolver is the resolver for operator DNS checks: the injected
// one in tests, otherwise the system resolver.
func (h *Handler) guidanceResolver() DNSResolver {
	if h.dnsResolver != nil {
		return h.dnsResolver
	}
	return net.DefaultResolver
}

// dnsExpectation is one record Veksel expects for a domain. DNS guidance
// checks it against live DNS and publishing writes it through a DNS
// provider, so the two can never disagree. Kind is the guidance label.
type dnsExpectation struct {
	Kind string
	dnsprovider.Desired
	Note string
}

// wkdEnabled reports whether the OpenPGP Web Key Directory is on, which
// adds the advanced-method host to the expected records.
func (h *Handler) wkdEnabled() bool {
	cfg := h.effectiveConfig()
	return cfg != nil && cfg.WkdEnabled
}

// dnsOptions are the installation settings that add optional records to a
// domain's DNS guidance.
type dnsOptions struct {
	WKD bool
	// MTASTSMode is the published MTA-STS policy mode; "" or "off" publishes
	// none.
	MTASTSMode string
}

func (h *Handler) dnsOptions() dnsOptions {
	options := dnsOptions{WKD: h.wkdEnabled()}
	if cfg := h.effectiveConfig(); cfg != nil {
		options.MTASTSMode = cfg.MtaStsMode
	}
	return options
}

// dnsExpectations returns the publishable records for a domain: MX, SPF,
// DMARC, one DKIM record per key (including staged keys awaiting publication
// and retiring keys still inside their DNS overlap), and with wkd the
// openpgpkey host of the Web Key Directory advanced method.
func dnsExpectations(domain model.Domain, server string, options dnsOptions) []dnsExpectation {
	name := domain.ID
	txt := func(owner, value string) dnsprovider.Record {
		return dnsprovider.Record{Type: "TXT", Name: owner, Value: value}
	}
	out := []dnsExpectation{
		{Kind: "MX", Desired: dnsprovider.Desired{Record: dnsprovider.Record{Type: "MX", Name: name, Value: "10 " + server + "."}, Accept: func(value string) bool {
			_, host, _ := strings.Cut(strings.TrimSpace(value), " ")
			return normDNSHost(host) == server
		}}},
		{Kind: "SPF", Desired: dnsprovider.Desired{Record: txt(name, dkim.SPFDNSRecord(true)), Prefix: "v=spf1"},
			Note: spfNote},
		{Kind: "DMARC", Desired: dnsprovider.Desired{Record: txt("_dmarc."+name, dkim.DMARCDNSRecord(10, "dmarc@"+name)), Prefix: "v=dmarc1", Accept: func(string) bool { return true }},
			Note: "Any DMARC policy counts as ok; the expected value is a monitoring-first starting point."},
	}
	for _, key := range model.DKIMKeys(domain) {
		expected := dkim.DKIMDNSRecord([]byte(key.PublicKey))
		if expected == "" {
			continue
		}
		out = append(out, dnsExpectation{Kind: "DKIM", Note: "Selector " + key.Selector + " (" + string(key.State) + ").",
			Desired: dnsprovider.Desired{Record: txt(key.Selector+"._domainkey."+name, expected), Prefix: "v=dkim1", Accept: func(value string) bool {
				return dkimPublicKey(value) == dkimPublicKey(expected)
			}}})
	}
	if options.MTASTSMode != "" && options.MTASTSMode != mtasts.PublishedOff {
		_, id := mtasts.PublishedPolicy(options.MTASTSMode, []string{server})
		out = append(out, dnsExpectation{Kind: "MTA-STS", Note: "MTA-STS policy (" + options.MTASTSMode + ") served at https://mta-sts." + name + "/.well-known/mta-sts.txt; mta-sts." + name + " must reach this server over HTTPS with a valid certificate. The id changes with the policy.",
			Desired: dnsprovider.Desired{Record: txt("_mta-sts."+name, mtasts.PublishedRecord(id)), Prefix: "v=stsv1"}})
	}
	if options.WKD {
		out = append(out, dnsExpectation{Kind: "WKD", Note: "OpenPGP Web Key Directory (advanced method); it may also be an A or AAAA record for the server. Optional: the direct method needs only the domain itself to serve /.well-known/openpgpkey/.",
			Desired: dnsprovider.Desired{Record: dnsprovider.Record{Type: "CNAME", Name: pgpkey.AdvancedHost(name), Value: server + "."}, Accept: func(value string) bool {
				return normDNSHost(value) == server
			}}})
	}
	return out
}

func buildDNSGuidance(parent context.Context, resolver DNSResolver, domain model.Domain, server, publicAddr string, options dnsOptions) dnsGuidanceResponse {
	ctx, cancel := context.WithTimeout(parent, dnsGuidanceTimeout)
	defer cancel()
	name := domain.ID
	var checks []func() []dnsGuidanceRecord
	for _, want := range dnsExpectations(domain, server, options) {
		checks = append(checks, func() []dnsGuidanceRecord {
			switch want.Kind {
			case "MX":
				return []dnsGuidanceRecord{checkMX(ctx, resolver, name, server)}
			case "SPF":
				return []dnsGuidanceRecord{checkSPF(ctx, resolver, name, server, publicAddr)}
			case "WKD":
				return []dnsGuidanceRecord{checkWKDHost(ctx, resolver, want, server)}
			}
			rec := checkTXT(ctx, resolver, want.Kind, want.Name, want.Value, want.Prefix, want.Note)
			if rec.Status == dnsMismatch && want.Accept != nil {
				for _, live := range rec.Live {
					if want.Accept(live) {
						rec.Status = dnsOK
					}
				}
			}
			return []dnsGuidanceRecord{rec}
		})
	}
	checks = append(checks, func() []dnsGuidanceRecord { return serverPTRRecords(ctx, resolver, server, publicAddr) })
	results := make([][]dnsGuidanceRecord, len(checks))
	var wg sync.WaitGroup
	for i, check := range checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = check()
		}()
	}
	wg.Wait()
	response := dnsGuidanceResponse{Domain: name, ServerName: server, Records: []dnsGuidanceRecord{}}
	for _, group := range results {
		response.Records = append(response.Records, group...)
	}
	return response
}

func dnsFailure(rec *dnsGuidanceRecord, err error) {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		rec.Status = dnsMissing
		return
	}
	rec.Status, rec.Error = dnsError, err.Error()
}

func normDNSHost(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

func checkMX(ctx context.Context, resolver DNSResolver, domain, server string) dnsGuidanceRecord {
	rec := dnsGuidanceRecord{Type: "MX", Name: domain, Expected: "10 " + server + ".", Live: []string{}}
	mx, err := resolver.LookupMX(ctx, domain)
	for _, m := range mx {
		rec.Live = append(rec.Live, strconv.Itoa(int(m.Pref))+" "+m.Host)
	}
	if len(mx) == 0 {
		if err == nil {
			rec.Status = dnsMissing
		} else {
			dnsFailure(&rec, err)
		}
		return rec
	}
	rec.Status = dnsMismatch
	for _, m := range mx {
		if normDNSHost(m.Host) == server {
			rec.Status = dnsOK
		}
	}
	return rec
}

// checkWKDHost verifies that the openpgpkey host resolves to the same
// addresses as the server, which a CNAME or its own A and AAAA records do.
func checkWKDHost(ctx context.Context, resolver DNSResolver, want dnsExpectation, server string) dnsGuidanceRecord {
	rec := dnsGuidanceRecord{Type: want.Type, Name: want.Name, Expected: want.Value, Live: []string{}, Note: want.Note}
	hosts, err := resolver.LookupHost(ctx, want.Name)
	rec.Live = append(rec.Live, hosts...)
	if len(hosts) == 0 {
		if err != nil {
			dnsFailure(&rec, err)
		} else {
			rec.Status = dnsMissing
		}
		return rec
	}
	rec.Status = dnsMismatch
	serverHosts, _ := resolver.LookupHost(ctx, server)
	for _, host := range hosts {
		if slices.Contains(serverHosts, host) {
			rec.Status = dnsOK
		}
	}
	return rec
}

func checkTXT(ctx context.Context, resolver DNSResolver, kind, name, expected, prefix, note string) dnsGuidanceRecord {
	rec := dnsGuidanceRecord{Type: kind, Name: name, Expected: expected, Live: []string{}, Note: note}
	txt, err := resolver.LookupTXT(ctx, name)
	for _, t := range txt {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), prefix) {
			rec.Live = append(rec.Live, t)
		}
	}
	if len(rec.Live) == 0 {
		if err != nil {
			dnsFailure(&rec, err)
		} else {
			rec.Status = dnsMissing
		}
		return rec
	}
	rec.Status = dnsMismatch
	for _, t := range rec.Live {
		if strings.Join(strings.Fields(t), " ") == strings.Join(strings.Fields(expected), " ") {
			rec.Status = dnsOK
		}
	}
	return rec
}

// dkimPublicKey extracts the whitespace-free p= tag from a DKIM TXT value.
func dkimPublicKey(record string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			return strings.Join(strings.Fields(part[2:]), "")
		}
	}
	return ""
}

// serverPTRRecords checks reverse DNS for the SMTP server: the configured
// public egress address when set, otherwise every address of server.
func serverPTRRecords(ctx context.Context, resolver DNSResolver, server, publicAddr string) []dnsGuidanceRecord {
	if publicAddr != "" {
		return []dnsGuidanceRecord{checkPublicPTR(ctx, resolver, server, publicAddr)}
	}
	return checkPTR(ctx, resolver, server)
}

func checkPTR(ctx context.Context, resolver DNSResolver, server string) []dnsGuidanceRecord {
	note := "Set at your IP provider: each address of the SMTP server name should reverse-resolve to it. If this server is behind NAT, set smtp_public_address to the real egress IP."
	addrs, err := resolver.LookupHost(ctx, server)
	if len(addrs) == 0 {
		rec := dnsGuidanceRecord{Type: "PTR", Name: server, Expected: server + ".", Live: []string{}, Note: note}
		if err == nil {
			rec.Status = dnsMissing
		} else {
			dnsFailure(&rec, err)
		}
		return []dnsGuidanceRecord{rec}
	}
	out := make([]dnsGuidanceRecord, len(addrs))
	var wg sync.WaitGroup
	for i, addr := range addrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := dnsGuidanceRecord{Type: "PTR", Name: addr, Expected: server + ".", Live: []string{}, Note: note}
			names, err := resolver.LookupAddr(ctx, addr)
			rec.Live = append(rec.Live, names...)
			switch {
			case len(names) == 0 && err != nil:
				dnsFailure(&rec, err)
			case len(names) == 0:
				rec.Status = dnsMissing
			default:
				rec.Status = dnsMismatch
				for _, n := range names {
					if normDNSHost(n) == server {
						rec.Status = dnsOK
					}
				}
			}
			out[i] = rec
		}()
	}
	wg.Wait()
	return out
}

// checkPublicPTR verifies forward-confirmed reverse DNS for the configured
// public egress address using the shared mailidentity check.
func checkPublicPTR(ctx context.Context, resolver DNSResolver, server, publicAddr string) dnsGuidanceRecord {
	rec := dnsGuidanceRecord{Type: "PTR", Name: publicAddr, Expected: server + ".", Live: []string{}, Note: "Verified against smtp_public_address (forward-confirmed reverse DNS)."}
	names, err := resolver.LookupAddr(ctx, publicAddr)
	rec.Live = append(rec.Live, names...)
	problems := mailidentity.FCrDNS(ctx, resolver, server, publicAddr)
	switch {
	case len(problems) == 0:
		rec.Status = dnsOK
	case len(names) == 0 && err != nil:
		dnsFailure(&rec, err)
		rec.Note = strings.Join(problems, "; ")
	case len(names) == 0:
		rec.Status, rec.Note = dnsMissing, strings.Join(problems, "; ")
	default:
		rec.Status, rec.Note = dnsMismatch, strings.Join(problems, "; ")
	}
	return rec
}
