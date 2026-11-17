package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// addrConn is a net.Conn that only reports a remote address.
type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

var receivedTestTime = time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)

func TestReceivedFieldFormat(t *testing.T) {
	t.Parallel()
	ipv4 := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 41000}
	ipv6 := &net.TCPAddr{IP: net.ParseIP("2001:db8::25"), Port: 41000}
	tests := []struct {
		name    string
		session *Session
		want    string
	}{
		{"HELO", &Session{heloHostname: "client.example.org", recipients: []string{"bob@example.com"}},
			"Received: from client.example.org ([192.0.2.10])\r\n\tby mx.example.com (Veksel) with SMTP id tx-1\r\n\tfor <bob@example.com>; Fri, 02 Jan 2026 15:04:05 +0000"},
		{"EHLO with reverse DNS", &Session{heloHostname: "client.example.org", ehloGiven: true, heloResult: &HeloResult{ReverseDNS: "mail.example.org"}, recipients: []string{"bob@example.com"}},
			"Received: from client.example.org (mail.example.org [192.0.2.10])\r\n\tby mx.example.com (Veksel) with ESMTP id tx-1\r\n\tfor <bob@example.com>; Fri, 02 Jan 2026 15:04:05 +0000"},
		{"ESMTPS", &Session{heloHostname: "client.example.org", ehloGiven: true, tlsDone: true, recipients: []string{"bob@example.com"}},
			"Received: from client.example.org ([192.0.2.10])\r\n\tby mx.example.com (Veksel) with ESMTPS id tx-1\r\n\tfor <bob@example.com>; Fri, 02 Jan 2026 15:04:05 +0000"},
		{"ESMTPA", &Session{heloHostname: "laptop", ehloGiven: true, authenticated: true, recipients: []string{"bob@example.com"}},
			"Received: from laptop ([192.0.2.10])\r\n\tby mx.example.com (Veksel) with ESMTPA id tx-1\r\n\tfor <bob@example.com>; Fri, 02 Jan 2026 15:04:05 +0000"},
		{"ESMTPSA", &Session{heloHostname: "laptop", ehloGiven: true, tlsDone: true, authenticated: true, recipients: []string{"bob@example.com"}},
			"Received: from laptop ([192.0.2.10])\r\n\tby mx.example.com (Veksel) with ESMTPSA id tx-1\r\n\tfor <bob@example.com>; Fri, 02 Jan 2026 15:04:05 +0000"},
		{"IPv6 and several recipients", &Session{conn: addrConn{remote: ipv6}, heloHostname: "client.example.org", ehloGiven: true, recipients: []string{"bob@example.com", "carol@example.com"}},
			"Received: from client.example.org ([IPv6:2001:db8::25])\r\n\tby mx.example.com (Veksel) with ESMTP id tx-1; Fri, 02 Jan 2026 15:04:05 +0000"},
		{"no HELO name", &Session{recipients: []string{"bob@example.com"}},
			"Received: from [192.0.2.10] ([192.0.2.10])\r\n\tby mx.example.com (Veksel) with SMTP id tx-1\r\n\tfor <bob@example.com>; Fri, 02 Jan 2026 15:04:05 +0000"},
		{"hostile HELO cannot break the field", &Session{heloHostname: "evil (x);\r\n\tby forged", ehloGiven: true, recipients: []string{"bob@example.com"}},
			"Received: from evilxbyforged ([192.0.2.10])\r\n\tby mx.example.com (Veksel) with ESMTP id tx-1\r\n\tfor <bob@example.com>; Fri, 02 Jan 2026 15:04:05 +0000"},
		{"privacy hides the submitter", &Session{cfg: &Config{ServerName: "mx.example.com", SubmissionReceivedPrivacy: true}, heloHostname: "laptop", ehloGiven: true, tlsDone: true, authenticated: true, heloResult: &HeloResult{ReverseDNS: "home.example.net"}, recipients: []string{"bob@example.com"}},
			"Received: from laptop\r\n\tby mx.example.com (Veksel) with ESMTPSA id tx-1\r\n\tfor <bob@example.com>; Fri, 02 Jan 2026 15:04:05 +0000"},
		{"privacy leaves relayed mail alone", &Session{cfg: &Config{ServerName: "mx.example.com", SubmissionReceivedPrivacy: true}, heloHostname: "client.example.org", ehloGiven: true, recipients: []string{"bob@example.com"}},
			"Received: from client.example.org ([192.0.2.10])\r\n\tby mx.example.com (Veksel) with ESMTP id tx-1\r\n\tfor <bob@example.com>; Fri, 02 Jan 2026 15:04:05 +0000"},
	}
	for _, test := range tests {
		session := test.session
		if session.cfg == nil {
			session.cfg = &Config{ServerName: "mx.example.com"}
		}
		if session.conn == nil {
			session.conn = addrConn{remote: ipv4}
		}
		if got := session.receivedField("tx-1", receivedTestTime); got != test.want {
			t.Errorf("%s:\ngot  %q\nwant %q", test.name, got, test.want)
		}
	}
}

func TestReceivedFieldNamesNegotiatedTLS(t *testing.T) {
	t.Parallel()
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = serverSide.Close(); _ = clientSide.Close() })
	server := tls.Server(serverSide, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	client := tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	go func() { _ = client.Handshake() }()
	if err := server.Handshake(); err != nil {
		t.Fatal(err)
	}
	session := &Session{cfg: &Config{ServerName: "mx.example.com"}, conn: addrConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10")}},
		tlsConn: server, tlsDone: true, ehloGiven: true, heloHostname: "client.example.org", recipients: []string{"bob@example.com"}}
	state := server.ConnectionState()
	want := "Received: from client.example.org ([192.0.2.10])\r\n\tby mx.example.com (Veksel) with ESMTPS id tx-1\r\n\t(using TLSv1.3 with cipher " +
		tls.CipherSuiteName(state.CipherSuite) + ")\r\n\tfor <bob@example.com>; Fri, 02 Jan 2026 15:04:05 +0000"
	if got := session.receivedField("tx-1", receivedTestTime); got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

// TestAcceptedMessagesCarryOneNewReceivedField checks DATA and BDAT
// transactions on one connection: each gets exactly one new trace field on
// top, the peer's Received fields keep their order and folding, and the for
// clause appears only for a single recipient.
func TestAcceptedMessagesCarryOneNewReceivedField(t *testing.T) {
	var delivered [][]byte
	c := makeTestServer(t, &Config{
		ServerName: "mx.example.test",
		Delivery: &Delivery{
			ResolveRecipient: func(_ context.Context, addr string) (string, string, error) { return addr + ":INBOX", "user", nil },
			AppendMessage: func(_ context.Context, _ string, data []byte, _ map[string]string) (string, error) {
				delivered = append(delivered, append([]byte(nil), data...))
				return "item", nil
			},
		},
	})
	peer := "Received: from relay.example.net\r\n\tby gateway.example.net; Thu, 01 Jan 2026 10:00:01 +0000\r\n" +
		"Received: from origin.example.net by relay.example.net; Thu, 01 Jan 2026 10:00:00 +0000\r\n"
	c.send("EHLO client.example.org")
	c.send("MAIL FROM:<sender@example.net>")
	c.send("RCPT TO:<alice@example.test>")
	if code, _ := c.send("DATA"); code != 354 {
		t.Fatalf("DATA = %d", code)
	}
	c.writeData(peer + "From: sender@example.net\r\nSubject: data\r\n\r\nbody\r\n.\r\n")
	if code, text, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA end = %d %s", code, text)
	}
	bdat := peer + "From: sender@example.net\r\nSubject: bdat\r\n\r\nbody\r\n"
	c.send("MAIL FROM:<sender@example.net>")
	c.send("RCPT TO:<alice@example.test>")
	c.send("RCPT TO:<bob@example.test>")
	c.writeData("BDAT " + strconv.Itoa(len(bdat)) + " LAST\r\n" + bdat)
	if code, text, _ := c.readReply(); code != 250 {
		t.Fatalf("BDAT = %d %s", code, text)
	}
	if len(delivered) != 3 {
		t.Fatalf("delivered %d copies, want 3", len(delivered))
	}
	for index, message := range delivered {
		received := model.ParseHeaderValues(message)["received"]
		if len(received) != 3 {
			t.Fatalf("copy %d has Received fields %q", index, received)
		}
		ours := received[0]
		if !strings.HasPrefix(ours, "from client.example.org ([127.0.0.1]) by mx.example.test (Veksel) with ESMTP id smtp-transaction-") {
			t.Errorf("copy %d trace field = %q", index, ours)
		}
		if single := index == 0; strings.Contains(ours, " for <alice@example.test>;") != single {
			t.Errorf("copy %d for clause (single recipient %t): %q", index, single, ours)
		}
		if !strings.Contains(string(message), "Received: from client.example.org ([127.0.0.1])\r\n\tby mx.example.test (Veksel) with ESMTP id ") {
			t.Errorf("copy %d trace field is not a folded field:\n%s", index, message)
		}
		if !strings.Contains(string(message), "\r\n"+peer) {
			t.Errorf("copy %d lost the peer's trace fields or their order:\n%s", index, message)
		}
		if strings.Index(string(message), "Received: from client.example.org") > strings.Index(string(message), peer) {
			t.Errorf("copy %d trace field is below the peer's:\n%s", index, message)
		}
	}
}

// TestSubmissionReceivedFieldAndPrivacy sends an authenticated submission
// over STARTTLS and checks the queued relay copy's exact trace field.
func TestSubmissionReceivedFieldAndPrivacy(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	for _, privacy := range []bool{false, true} {
		q := &recordingSystemQueue{}
		c := makeTestServer(t, &Config{
			ServerName: "mx.example.test", TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
			AuthMechanisms: []string{"PLAIN"}, SaslIrEnabled: true, SubmissionReceivedPrivacy: privacy,
			AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
			Delivery: &Delivery{
				ResolveRecipient:        func(context.Context, string) (string, string, error) { return "", "", store.ErrNotFound },
				MailQueue:               q,
				AllowAuthenticatedRelay: true,
			},
		})
		c.send("EHLO laptop")
		if code, _ := c.send("STARTTLS"); code != 220 {
			t.Fatalf("STARTTLS = %d", code)
		}
		tlsConn := tls.Client(c.Conn, &tls.Config{InsecureSkipVerify: true})
		if err := tlsConn.Handshake(); err != nil {
			t.Fatal(err)
		}
		c.Conn, c.r = tlsConn, bufio.NewReader(tlsConn)
		c.send("EHLO laptop")
		if code, text := c.send("AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret"))); code != 235 {
			t.Fatalf("AUTH = %d %s", code, text)
		}
		c.send("MAIL FROM:<alice@example.test>")
		if code, text := c.send("RCPT TO:<carol@remote.test>"); code != 250 {
			t.Fatalf("RCPT = %d %s", code, text)
		}
		c.send("DATA")
		c.writeData("From: alice@example.test\r\nTo: carol@remote.test\r\nSubject: hi\r\n\r\nbody\r\n.\r\n")
		if code, text, _ := c.readReply(); code != 250 {
			t.Fatalf("DATA = %d %s", code, text)
		}
		if len(q.messages) != 1 || len(q.messages[0].Content) == 0 {
			t.Fatalf("queued = %+v", q.messages)
		}
		content := string(q.messages[0].Content)
		from := "Received: from laptop ([127.0.0.1])\r\n\tby mx.example.test"
		if privacy {
			from = "Received: from laptop\r\n\tby mx.example.test"
		}
		if !strings.Contains(content, from+" (Veksel) with ESMTPSA id smtp-transaction-") ||
			!strings.Contains(content, "\r\n\t(using TLSv1.3 with cipher TLS_") || !strings.Contains(content, "\r\n\tfor <carol@remote.test>; ") {
			t.Errorf("privacy=%t trace field:\n%s", privacy, content)
		}
		if privacy && strings.Contains(content, "127.0.0.1") {
			t.Errorf("privacy kept the client address:\n%s", content)
		}
	}
}
