package dnsprovider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// RFC2136 updates a zone on its primary server with RFC 2136 dynamic update
// messages signed by a TSIG key (RFC 8945). Queries and updates use TCP so
// DKIM-sized TXT records are never truncated.
type RFC2136 struct {
	Zone      string
	Server    string // host:port of the primary
	KeyName   string
	Algorithm string // dns.HmacSHA256 and friends
	Secret    string // base64 TSIG secret
	Timeout   time.Duration
}

// TSIGAlgorithms maps accepted algorithm names to their canonical form.
var TSIGAlgorithms = map[string]string{
	"hmac-sha1": dns.HmacSHA1, "hmac-sha224": dns.HmacSHA224, "hmac-sha256": dns.HmacSHA256,
	"hmac-sha384": dns.HmacSHA384, "hmac-sha512": dns.HmacSHA512,
}

func (p *RFC2136) client() *dns.Client {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &dns.Client{Net: "tcp", Timeout: timeout, TsigSecret: map[string]string{dns.Fqdn(p.KeyName): p.Secret}}
}

// exchange sends a TSIG-signed message. An NXDOMAIN reply is returned
// without error when allowNXDomain is set, for queries of absent names.
func (p *RFC2136) exchange(ctx context.Context, msg *dns.Msg, allowNXDomain bool) (*dns.Msg, error) {
	msg.SetTsig(dns.Fqdn(p.KeyName), p.Algorithm, 300, time.Now().Unix())
	reply, _, err := p.client().ExchangeContext(ctx, msg, p.Server)
	if err != nil {
		return nil, fmt.Errorf("DNS server %s: %w", p.Server, err)
	}
	if reply.Rcode != dns.RcodeSuccess && (!allowNXDomain || reply.Rcode != dns.RcodeNameError) {
		return nil, fmt.Errorf("DNS server %s answered %s", p.Server, dns.RcodeToString[reply.Rcode])
	}
	return reply, nil
}

// ListRecords queries the primary directly, so the result reflects the zone
// without resolver caching.
func (p *RFC2136) ListRecords(ctx context.Context, name, rtype string) ([]Record, error) {
	qtype, ok := dns.StringToType[strings.ToUpper(rtype)]
	if !ok {
		return nil, fmt.Errorf("unsupported record type %q", rtype)
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(NormalizeName(name)), qtype)
	msg.RecursionDesired = false
	reply, err := p.exchange(ctx, msg, true)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, rr := range reply.Answer {
		if rr.Header().Rrtype != qtype || NormalizeName(rr.Header().Name) != NormalizeName(name) {
			continue
		}
		value := rrValue(rr)
		out = append(out, Record{ID: value, Type: strings.ToUpper(rtype), Name: NormalizeName(name), Value: value, TTL: int(rr.Header().Ttl)})
	}
	return out, nil
}

// UpsertRecord adds rec, deleting the listed record in the same atomic
// update when rec.ID names one.
func (p *RFC2136) UpsertRecord(ctx context.Context, rec Record) error {
	if err := validateRecord(p.Zone, rec); err != nil {
		return err
	}
	insert, err := RecordRR(rec)
	if err != nil {
		return err
	}
	msg := new(dns.Msg)
	msg.SetUpdate(dns.Fqdn(NormalizeName(p.Zone)))
	if rec.ID != "" && !SameValue(rec.Type, rec.ID, rec.Value) {
		old, err := RecordRR(Record{Type: rec.Type, Name: rec.Name, Value: rec.ID})
		if err != nil {
			return err
		}
		msg.Remove([]dns.RR{old})
	}
	msg.Insert([]dns.RR{insert})
	_, err = p.exchange(ctx, msg, false)
	return err
}

// DeleteRecord removes exactly one resource record.
func (p *RFC2136) DeleteRecord(ctx context.Context, rec Record) error {
	if rec.ID != "" {
		rec.Value = rec.ID
	}
	if err := validateRecord(p.Zone, rec); err != nil {
		return err
	}
	rr, err := RecordRR(rec)
	if err != nil {
		return err
	}
	msg := new(dns.Msg)
	msg.SetUpdate(dns.Fqdn(NormalizeName(p.Zone)))
	msg.Remove([]dns.RR{rr})
	_, err = p.exchange(ctx, msg, false)
	return err
}

// RecordRR converts a Record to wire form. TXT data is split into 255-byte
// character strings as RFC 7208 and RFC 6376 require for long values.
func RecordRR(rec Record) (dns.RR, error) {
	header := dns.RR_Header{Name: dns.Fqdn(NormalizeName(rec.Name)), Class: dns.ClassINET, Ttl: uint32(ttlOrDefault(rec.TTL))}
	if strings.EqualFold(rec.Type, "TXT") {
		header.Rrtype = dns.TypeTXT
		var chunks []string
		for value := rec.Value; value != ""; {
			n := min(len(value), 255)
			chunks = append(chunks, value[:n])
			value = value[n:]
		}
		return &dns.TXT{Hdr: header, Txt: chunks}, nil
	}
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", header.Name, header.Ttl, strings.ToUpper(rec.Type), rec.Value))
	if err != nil {
		return nil, fmt.Errorf("invalid %s record %q: %w", rec.Type, rec.Value, err)
	}
	if rr == nil {
		return nil, errors.New("empty record")
	}
	return rr, nil
}

// rrValue renders RR data in Record.Value form.
func rrValue(rr dns.RR) string {
	if txt, ok := rr.(*dns.TXT); ok {
		return strings.Join(txt.Txt, "")
	}
	return strings.TrimSpace(strings.TrimPrefix(rr.String(), rr.Header().String()))
}

// withDefaultPort appends the DNS port when server has none.
func withDefaultPort(server string) string {
	server = strings.TrimSpace(server)
	if _, _, err := net.SplitHostPort(server); err != nil {
		return net.JoinHostPort(strings.Trim(server, "[]"), "53")
	}
	return server
}
