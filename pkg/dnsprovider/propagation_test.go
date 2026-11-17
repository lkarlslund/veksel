package dnsprovider

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestPropagationQueriesAuthoritativeServersUntilServed(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int32
	started := make(chan struct{})
	server := &dns.Server{PacketConn: conn, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.Authoritative = true
		// The record appears from the third query on.
		if queries.Add(1) >= 3 {
			reply.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"tok", "en"}}}
		}
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })

	propagation := Propagation{Interval: time.Millisecond, Nameservers: func(_ context.Context, zone string) ([]string, error) {
		if zone != "example.test" {
			t.Errorf("zone %q", zone)
		}
		return []string{conn.LocalAddr().String()}, nil
	}}
	if err := propagation.WaitTXT(t.Context(), "example.test", "_acme-challenge.example.test", "token", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if queries.Load() < 3 {
		t.Fatalf("returned before the record was served (%d queries)", queries.Load())
	}
	if err := propagation.WaitTXT(t.Context(), "example.test", "_acme-challenge.example.test", "other", 30*time.Millisecond); err == nil {
		t.Fatal("unserved value reported as propagated")
	}
}
