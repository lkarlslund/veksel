package dnsprovider

import (
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// tsigServer is an in-process authoritative server that applies RFC 2136
// updates only when their TSIG signature verifies.
type tsigServer struct {
	addr    string
	mu      sync.Mutex
	records []dns.RR
	updates []*dns.Msg
}

const testKeyName = "veksel-key."

func startTSIGServer(t *testing.T, secret string) *tsigServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts := &tsigServer{addr: listener.Addr().String()}
	started := make(chan struct{})
	server := &dns.Server{Listener: listener, Net: "tcp", TsigSecret: map[string]string{testKeyName: secret}, NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(ts.serve), MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept }}
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	return ts
}

func (s *tsigServer) serve(w dns.ResponseWriter, r *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetReply(r)
	if r.IsTsig() == nil || w.TsigStatus() != nil {
		reply.Rcode = dns.RcodeNotAuth
		_ = w.WriteMsg(reply)
		return
	}
	s.mu.Lock()
	switch r.Opcode {
	case dns.OpcodeUpdate:
		s.updates = append(s.updates, r.Copy())
		for _, rr := range r.Ns {
			if rr.Header().Class == dns.ClassNONE {
				for i, existing := range s.records {
					if existing.Header().Name == rr.Header().Name && rrValue(existing) == rrValue(rr) {
						s.records = append(s.records[:i], s.records[i+1:]...)
						break
					}
				}
				continue
			}
			s.records = append(s.records, dns.Copy(rr))
		}
	default:
		q := r.Question[0]
		for _, rr := range s.records {
			if strings.EqualFold(rr.Header().Name, q.Name) && rr.Header().Rrtype == q.Qtype {
				reply.Answer = append(reply.Answer, rr)
			}
		}
		if len(reply.Answer) == 0 {
			reply.Rcode = dns.RcodeNameError
		}
	}
	s.mu.Unlock()
	reply.SetTsig(testKeyName, dns.HmacSHA256, 300, time.Now().Unix())
	_ = w.WriteMsg(reply)
}

func (s *tsigServer) lastUpdate(t *testing.T) *dns.Msg {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.updates) == 0 {
		t.Fatal("server received no update")
	}
	return s.updates[len(s.updates)-1]
}

func TestRFC2136SignedUpdatesAgainstInProcessServer(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	server := startTSIGServer(t, secret)
	provider := &RFC2136{Zone: "example.test", Server: server.addr, KeyName: "veksel-key", Algorithm: dns.HmacSHA256, Secret: secret}
	ctx := t.Context()

	if records, err := provider.ListRecords(ctx, "s1._domainkey.example.test", "TXT"); err != nil || len(records) != 0 {
		t.Fatalf("absent name: %v %v", records, err)
	}
	long := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 600)
	if err := provider.UpsertRecord(ctx, Record{Type: "TXT", Name: "s1._domainkey.example.test", Value: long}); err != nil {
		t.Fatal(err)
	}
	update := server.lastUpdate(t)
	if update.Opcode != dns.OpcodeUpdate || len(update.Question) != 1 || update.Question[0].Name != "example.test." || update.Question[0].Qtype != dns.TypeSOA {
		t.Fatalf("zone section: %+v", update.Question)
	}
	if update.IsTsig() == nil || update.IsTsig().Hdr.Name != testKeyName {
		t.Fatal("update is not TSIG signed with the configured key")
	}
	if len(update.Ns) != 1 {
		t.Fatalf("update section: %v", update.Ns)
	}
	txt, ok := update.Ns[0].(*dns.TXT)
	if !ok || txt.Hdr.Class != dns.ClassINET || txt.Hdr.Ttl != DefaultTTL || len(txt.Txt) != 3 || strings.Join(txt.Txt, "") != long {
		t.Fatalf("TXT insert is not split into 255-byte strings: %#v", update.Ns[0])
	}
	records, err := provider.ListRecords(ctx, "s1._domainkey.example.test", "TXT")
	if err != nil || len(records) != 1 || records[0].Value != long || records[0].ID != long {
		t.Fatalf("listed: %+v %v", records, err)
	}

	if err := provider.UpsertRecord(ctx, Record{Type: "MX", Name: "example.test", Value: "10 old.example.test."}); err != nil {
		t.Fatal(err)
	}
	mx, _ := provider.ListRecords(ctx, "example.test", "MX")
	mx[0].Value = "10 mail.example.test."
	if err := provider.UpsertRecord(ctx, mx[0]); err != nil {
		t.Fatal(err)
	}
	update = server.lastUpdate(t)
	if len(update.Ns) != 2 || update.Ns[0].Header().Class != dns.ClassNONE || rrValue(update.Ns[0]) != "10 old.example.test." || rrValue(update.Ns[1]) != "10 mail.example.test." {
		t.Fatalf("replacement must delete the old RR and add the new one atomically: %v", update.Ns)
	}
	if err := provider.DeleteRecord(ctx, Record{Type: "TXT", Name: "s1._domainkey.example.test", Value: long}); err != nil {
		t.Fatal(err)
	}
	if records, _ := provider.ListRecords(ctx, "s1._domainkey.example.test", "TXT"); len(records) != 0 {
		t.Fatalf("deleted record still listed: %v", records)
	}
	if err := provider.UpsertRecord(ctx, Record{Type: "TXT", Name: "other.test", Value: "x"}); err == nil {
		t.Fatal("record outside the zone was accepted")
	}

	wrong := *provider
	wrong.Secret = base64.StdEncoding.EncodeToString([]byte("not-the-right-secret-at-all-0000"))
	if err := wrong.UpsertRecord(ctx, Record{Type: "TXT", Name: "x.example.test", Value: "y"}); err == nil {
		t.Fatal("update with a wrong TSIG secret succeeded")
	}
}
