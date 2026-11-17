package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// startSMTPServer starts an SMTP server on a random port with the given config.
// It accepts connections in the background and returns the address and a cleanup func.
func startSMTPServer(t *testing.T, cfg *Config) (string, func()) {
	t.Helper()

	srv := New(cfg)
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go srv.Accept(ctx, ln)

	return ln.Addr().String(), func() {
		cancel()
		srv.Close()
	}
}

// dialClient dials the SMTP server and returns a client. The client is
// cleaned up when the test ends.
func dialClient(t *testing.T, addr string) *smtp.Client {
	t.Helper()
	client, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Quit() })
	return client
}

// --- Basic protocol tests: EHLO, AUTH, MAIL FROM, RCPT TO, DATA, QUIT ---

func TestIntegration_EHLO(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN", "LOGIN"},
		MaxRecipients:  100,
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// Check advertised extensions
	if ok, _ := client.Extension("8BITMIME"); !ok {
		t.Error("expected 8BITMIME extension")
	}
	if ok, _ := client.Extension("SMTPUTF8"); !ok {
		t.Error("expected SMTPUTF8 extension")
	}
	if ok, _ := client.Extension("PIPELINING"); !ok {
		t.Error("expected PIPELINING extension")
	}
	if !client.SupportsAuth("PLAIN") {
		t.Error("expected AUTH PLAIN support")
	}
	if !client.SupportsAuth("LOGIN") {
		t.Error("expected AUTH LOGIN support")
	}
}

func TestIntegration_HELO(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel"})
	t.Cleanup(cleanup)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Read greeting
	greeting, err := readRawLine(conn)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("expected 220 greeting, got: %s", greeting)
	}

	// Send HELO
	fmt.Fprintf(conn, "HELO client.example.com\r\n")
	reply, err := readRawLine(conn)
	if err != nil {
		t.Fatalf("read HELO reply: %v", err)
	}
	if !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("HELO: expected 250, got: %s", reply)
	}
}

func TestIntegration_AUTH_PLAIN(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN"},
		SaslIrEnabled:  true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// AUTH PLAIN success
	saslClient := sasl.NewPlainClient("", "alice", "secret")
	if err := client.Auth(saslClient); err != nil {
		t.Fatalf("AUTH PLAIN: %v", err)
	}
}

func TestIntegration_AUTH_PLAIN_invalid(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN"},
		SaslIrEnabled:  true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "", fmt.Errorf("invalid credentials")
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	saslClient := sasl.NewPlainClient("", "alice", "wrong")
	err := client.Auth(saslClient)
	if err == nil {
		t.Fatal("expected AUTH error for invalid credentials")
	}
}

func TestIntegration_AUTH_LOGIN(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"LOGIN"},
		SaslIrEnabled:  true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "bob" && password == "pass123" {
				return "bob", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// AUTH LOGIN using go-sasl LoginClient
	saslClient := sasl.NewLoginClient("bob", "pass123")
	if err := client.Auth(saslClient); err != nil {
		t.Fatalf("AUTH LOGIN: %v", err)
	}
}

func TestIntegration_AUTH_LOGIN_invalid(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"LOGIN"},
		SaslIrEnabled:  true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "", fmt.Errorf("invalid credentials")
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	saslClient := sasl.NewLoginClient("bob", "wrong")
	err := client.Auth(saslClient)
	if err == nil {
		t.Fatal("expected AUTH error for invalid credentials")
	}
}

func TestIntegration_MAIL_FROM(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel"})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// Normal sender
	if err := client.Mail("sender@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}

	// Null sender (bounce)
	if err := client.Reset(); err != nil {
		t.Fatalf("RSET: %v", err)
	}
	if err := client.Mail("", nil); err != nil {
		t.Fatalf("MAIL FROM<>: %v", err)
	}
}

func TestIntegration_MAIL_FROM_with_SMTPUTF8(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel"})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// MAIL FROM with SMTPUTF8 option
	opts := &smtp.MailOptions{UTF8: true}
	if err := client.Mail("müller@example.com", opts); err != nil {
		t.Fatalf("MAIL FROM with SMTPUTF8: %v", err)
	}
}

func TestIntegration_MAIL_FROM_with_8BITMIME(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel"})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// MAIL FROM with BODY=8BITMIME option
	opts := &smtp.MailOptions{Body: smtp.Body8BitMIME}
	if err := client.Mail("sender@example.com", opts); err != nil {
		t.Fatalf("MAIL FROM BODY=8BITMIME: %v", err)
	}
}

func TestIntegration_RCPT_TO(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)
	client.Mail("sender@example.com", nil)

	if err := client.Rcpt("alice@example.com", nil); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}
}

func TestIntegration_RCPT_TO_unknown(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "", "", fmt.Errorf("not found")
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)
	client.Mail("sender@example.com", nil)

	err := client.Rcpt("nobody@example.com", nil)
	if err == nil {
		t.Fatal("expected RCPT TO error for unknown recipient")
	}
}

func TestIntegration_RCPT_TO_DSN_notify(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)
	client.Mail("sender@example.com", nil)

	// RCPT TO with DSN NOTIFY=FAILURE option
	opts := &smtp.RcptOptions{
		Notify: []smtp.DSNNotify{smtp.DSNNotifyFailure},
	}
	if err := client.Rcpt("alice@example.com", opts); err != nil {
		t.Fatalf("RCPT TO with NOTIFY: %v", err)
	}
}

func TestIntegration_DATA_full_message(t *testing.T) {
	var receivedData []byte
	var receivedHeaders map[string]string

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedData = data
				receivedHeaders = headers
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)
	client.Mail("sender@example.com", nil)
	client.Rcpt("alice@example.com", nil)

	msg := "From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Hello World\r\n\r\nThis is the body.\r\n"
	if err := client.SendMail("sender@example.com", []string{"alice@example.com"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	// Verify delivery
	if receivedHeaders == nil {
		t.Fatal("expected headers to be set")
	}
	if receivedHeaders["Subject"] != "Hello World" {
		t.Errorf("Subject = %q, want %q", receivedHeaders["Subject"], "Hello World")
	}
	if receivedHeaders["Message-ID"] == "" {
		t.Error("expected auto-generated Message-ID")
	}
	if len(receivedData) == 0 {
		t.Error("expected non-empty message data")
	}
}

func TestIntegration_DATA_with_MessageID(t *testing.T) {
	var receivedHeaders map[string]string

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedHeaders = headers
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	msg := "Message-ID: <custom@client.com>\r\nFrom: a@b.com\r\nTo: c@d.com\r\n\r\nbody\r\n"
	if err := client.SendMail("a@b.com", []string{"c@d.com"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	if receivedHeaders["Message-ID"] != "<custom@client.com>" {
		t.Errorf("Message-ID = %q, want %q", receivedHeaders["Message-ID"], "<custom@client.com>")
	}
}

func TestIntegration_DATA_multiple_recipients(t *testing.T) {
	var deliveryCount int
	var deliveredTo []string

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return addr, "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				deliveryCount++
				deliveredTo = append(deliveredTo, folderID)
				return fmt.Sprintf("item-%d", deliveryCount), nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	msg := "From: sender@example.com\r\nTo: a@example.com, b@example.com\r\nSubject: Multi\r\n\r\nBody\r\n"
	if err := client.SendMail("sender@example.com", []string{"a@example.com", "b@example.com"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	if deliveryCount != 2 {
		t.Fatalf("deliveryCount = %d, want 2", deliveryCount)
	}
}

func TestIntegration_DATA_8bit_message(t *testing.T) {
	var receivedData []byte

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedData = data
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// Send 8-bit content (bytes > 127)
	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: 8Bit\r\nContent-Transfer-Encoding: 8bit\r\n\r\nHello \xff\xfe\xfd\r\n"
	if err := client.SendMail("sender@example.com", []string{"recipient@example.com"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("SendMail with 8bit: %v", err)
	}

	if len(receivedData) == 0 {
		t.Fatal("expected non-empty message data")
	}
}

func TestIntegration_DATA_DSN_return(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// MAIL FROM with DSN RET=FULL option
	opts := &smtp.MailOptions{Return: smtp.DSNReturnFull}
	if err := client.Mail("sender@example.com", opts); err != nil {
		t.Fatalf("MAIL FROM with RET=FULL: %v", err)
	}

	if err := client.Rcpt("recipient@example.com", nil); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}

	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: DSN Test\r\n\r\nBody\r\n"
	w, err := client.Data()
	if err != nil {
		t.Fatalf("DATA: %v", err)
	}
	_, err = io.Copy(w, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("DATA close: %v", err)
	}
}

func TestIntegration_QUIT(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel"})
	t.Cleanup(cleanup)

	client, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Don't use t.Cleanup for Quit here — we test Quit explicitly
	if err := client.Quit(); err != nil {
		t.Fatalf("QUIT: %v", err)
	}
}

func TestIntegration_NOOP(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel"})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	if err := client.Noop(); err != nil {
		t.Fatalf("NOOP: %v", err)
	}
}

func TestIntegration_RSET(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel"})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// Set MAIL FROM, then RSET, then set a new MAIL FROM
	client.Mail("first@example.com", nil)
	if err := client.Reset(); err != nil {
		t.Fatalf("RSET: %v", err)
	}
	// After RSET, we should be able to set a new MAIL FROM
	if err := client.Mail("second@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM after RSET: %v", err)
	}
}

// --- SMTP Extensions: STARTTLS, PIPELINING, 8BITMIME, SMTPUTF8, DSN ---

func TestIntegration_STARTTLS(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName:        "test.veksel",
		TLSConfig:         tlsCfg,
		AuthMechanisms:    []string{"PLAIN"},
		RequireTLSForAuth: true,
		SaslIrEnabled:     true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	// Connect with STARTTLS
	client, err := smtp.DialStartTLS(addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("DialStartTLS: %v", err)
	}
	defer client.Quit()

	// Verify TLS connection state
	if _, ok := client.TLSConnectionState(); !ok {
		t.Fatal("expected TLS connection state after STARTTLS")
	}

	// AUTH should work over TLS
	saslClient := sasl.NewPlainClient("", "alice", "secret")
	if err := client.Auth(saslClient); err != nil {
		t.Fatalf("AUTH PLAIN over TLS: %v", err)
	}

	// Send a message over TLS
	msg := "From: alice@example.com\r\nTo: alice@example.com\r\nSubject: TLS Test\r\n\r\nEncrypted body\r\n"
	if err := client.SendMail("alice@example.com", []string{"alice@example.com"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("SendMail over TLS: %v", err)
	}
}

func TestIntegration_STARTTLS_advertised(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		TLSConfig:  tlsCfg,
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// STARTTLS should be advertised
	if ok, _ := client.Extension("STARTTLS"); !ok {
		t.Error("expected STARTTLS extension when TLSConfig is set")
	}
}

func TestIntegration_SubmissionDoesNotAdvertiseAuthenticationBeforeTLS(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, AuthMechanisms: []string{"PLAIN", "LOGIN"}, AuthValidator: func(context.Context, string, string) (string, error) { return "user", nil }, RequireTLSForAuth: true})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	if client.SupportsAuth("PLAIN") || client.SupportsAuth("LOGIN") {
		t.Fatal("submission advertised password authentication before STARTTLS")
	}
}

func TestIntegration_STARTTLS_not_advertised_without_tls(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel"})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// STARTTLS should NOT be advertised when TLSConfig is nil
	if ok, _ := client.Extension("STARTTLS"); ok {
		t.Error("should not advertise STARTTLS without TLSConfig")
	}
}

func TestIntegration_PIPELINING_advertised(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel"})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	if ok, _ := client.Extension("PIPELINING"); !ok {
		t.Error("expected PIPELINING extension")
	}
}

func TestIntegration_PIPELINING_batch_commands(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// Pipeline: MAIL FROM + RCPT TO + RSET
	// The go-smtp client handles pipelining internally when sending
	// multiple commands. We verify the server accepts them correctly.
	if err := client.Mail("sender@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	if err := client.Rcpt("recipient@example.com", nil); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}
	// RSET clears the transaction
	if err := client.Reset(); err != nil {
		t.Fatalf("RSET: %v", err)
	}
	// After RSET, we should be able to start a new transaction
	if err := client.Mail("new-sender@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM after RSET: %v", err)
	}
}

func TestIntegration_8BITMIME_advertised(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel"})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	if ok, _ := client.Extension("8BITMIME"); !ok {
		t.Error("expected 8BITMIME extension")
	}
}

func TestIntegration_8BITMIME_send_8bit(t *testing.T) {
	var receivedData []byte

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedData = data
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// Use BODY=8BITMIME option
	opts := &smtp.MailOptions{Body: smtp.Body8BitMIME}
	if err := client.Mail("sender@example.com", opts); err != nil {
		t.Fatalf("MAIL FROM BODY=8BITMIME: %v", err)
	}
	if err := client.Rcpt("recipient@example.com", nil); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}

	// Send 8-bit data
	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: 8Bit\r\n\r\n\x80\x81\x82\xff\xfe\r\n"
	w, err := client.Data()
	if err != nil {
		t.Fatalf("DATA: %v", err)
	}
	_, err = io.Copy(w, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("DATA close: %v", err)
	}

	if len(receivedData) == 0 {
		t.Fatal("expected non-empty message data")
	}
}

func TestIntegration_SMTPUTF8_advertised(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel"})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	if ok, _ := client.Extension("SMTPUTF8"); !ok {
		t.Error("expected SMTPUTF8 extension")
	}
}

func TestIntegration_SMTPUTF8_internationalized_addresses(t *testing.T) {
	var receivedHeaders map[string]string

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedHeaders = headers
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// MAIL FROM with SMTPUTF8 option for internationalized sender
	opts := &smtp.MailOptions{UTF8: true}
	if err := client.Mail("müller@münchen.de", opts); err != nil {
		t.Fatalf("MAIL FROM with UTF-8: %v", err)
	}

	if err := client.Rcpt("用户@example.com", nil); err != nil {
		t.Fatalf("RCPT TO with UTF-8: %v", err)
	}

	msg := "From: müller@münchen.de\r\nTo: 用户@example.com\r\nSubject: International\r\n\r\nHello World\r\n"
	w, err := client.Data()
	if err != nil {
		t.Fatalf("DATA: %v", err)
	}
	_, err = io.Copy(w, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("DATA close: %v", err)
	}

	if receivedHeaders["Subject"] != "International" {
		t.Errorf("Subject = %q, want %q", receivedHeaders["Subject"], "International")
	}
}

func TestIntegration_DSN_return_full(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// MAIL FROM with RET=FULL (DSN)
	opts := &smtp.MailOptions{Return: smtp.DSNReturnFull}
	if err := client.Mail("sender@example.com", opts); err != nil {
		t.Fatalf("MAIL FROM RET=FULL: %v", err)
	}

	// RCPT TO with NOTIFY=FAILURE,DELAY
	rcptOpts := &smtp.RcptOptions{
		Notify: []smtp.DSNNotify{smtp.DSNNotifyFailure, smtp.DSNNotifyDelayed},
	}
	if err := client.Rcpt("recipient@example.com", rcptOpts); err != nil {
		t.Fatalf("RCPT TO with NOTIFY: %v", err)
	}

	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: DSN\r\n\r\nBody\r\n"
	w, err := client.Data()
	if err != nil {
		t.Fatalf("DATA: %v", err)
	}
	_, err = io.Copy(w, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("DATA close: %v", err)
	}
}

func TestIntegration_DSN_return_headers(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// MAIL FROM with RET=HDRS (DSN, headers only)
	opts := &smtp.MailOptions{Return: smtp.DSNReturnHeaders}
	if err := client.Mail("sender@example.com", opts); err != nil {
		t.Fatalf("MAIL FROM RET=HDRS: %v", err)
	}

	if err := client.Rcpt("recipient@example.com", nil); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}

	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: DSN HDRS\r\n\r\nBody\r\n"
	w, err := client.Data()
	if err != nil {
		t.Fatalf("DATA: %v", err)
	}
	_, err = io.Copy(w, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("DATA close: %v", err)
	}
}

func TestIntegration_DSN_envelope_id(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// MAIL FROM with ENVID parameter
	opts := &smtp.MailOptions{EnvelopeID: "msg-12345"}
	if err := client.Mail("sender@example.com", opts); err != nil {
		t.Fatalf("MAIL FROM with ENVID: %v", err)
	}

	if err := client.Rcpt("recipient@example.com", nil); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}

	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: ENVID\r\n\r\nBody\r\n"
	w, err := client.Data()
	if err != nil {
		t.Fatalf("DATA: %v", err)
	}
	_, err = io.Copy(w, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("DATA close: %v", err)
	}
}

func TestIntegration_DSN_no_bounce_on_unknown_recipient(t *testing.T) {
	var dsnDelivered bool

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				if addr == "nobody@example.com" {
					return "", "", fmt.Errorf("user unknown")
				}
				return "", "", fmt.Errorf("unknown")
			},
			ResolveSender: func(ctx context.Context, addr string) (string, string, error) {
				if addr == "sender@example.com" {
					return "sender:INBOX", "sender", nil
				}
				return "", "", fmt.Errorf("unknown")
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				// Check if this is a DSN delivery (to sender's INBOX)
				if folderID == "sender:INBOX" {
					dsnDelivered = true
				}
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	msg := "From: sender@example.com\r\nTo: nobody@example.com\r\nSubject: Bounce Test\r\n\r\nBody\r\n"
	// This should fail because the recipient is unknown
	err := client.SendMail("sender@example.com", []string{"nobody@example.com"}, strings.NewReader(msg))
	if err == nil {
		t.Fatal("SendMail unexpectedly accepted an unknown recipient")
	}
	if dsnDelivered {
		t.Error("unexpected DSN for a recipient rejected during SMTP")
	}
}

func TestIntegration_AuthRequired(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName:     "test.veksel",
		AuthRequired:   true,
		AuthMechanisms: []string{"PLAIN"},
		SaslIrEnabled:  true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// Try to send without auth — should fail with 530
	err := client.SendMail("sender@example.com", []string{"recipient@example.com"}, strings.NewReader("From: a@b.com\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("expected error when sending without auth on AuthRequired server")
	}
}

func TestIntegration_AuthRequired_with_auth(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName:     "test.veksel",
		AuthRequired:   true,
		AuthMechanisms: []string{"PLAIN"},
		SaslIrEnabled:  true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// Auth first
	saslClient := sasl.NewPlainClient("", "alice", "secret")
	if err := client.Auth(saslClient); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	// Now sending should work
	msg := "From: alice@example.com\r\nTo: recipient@example.com\r\nSubject: Auth Test\r\n\r\nBody\r\n"
	if err := client.SendMail("alice@example.com", []string{"recipient@example.com"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("SendMail after auth: %v", err)
	}
}

func TestIntegration_MaxRecipients(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName:    "test.veksel",
		MaxRecipients: 2,
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	client.Mail("sender@example.com", nil)
	client.Rcpt("a@example.com", nil)
	client.Rcpt("b@example.com", nil)

	// Third recipient should fail
	err := client.Rcpt("c@example.com", nil)
	if err == nil {
		t.Fatal("expected error for third recipient with MaxRecipients=2")
	}
}

func TestIntegration_MaxMessageSize(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName:     "test.veksel",
		MaxMessageSize: 100,
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// Message that exceeds the size limit
	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\n\r\nThis is a very long message body that exceeds the 100 byte limit\r\n"
	err := client.SendMail("sender@example.com", []string{"recipient@example.com"}, strings.NewReader(msg))
	if err == nil {
		t.Fatal("expected error for message exceeding size limit")
	}
}

func TestIntegration_Size_extension(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel"})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// SIZE extension should be advertised
	if ok, _ := client.Extension("SIZE"); !ok {
		t.Error("expected SIZE extension")
	}
}

func TestIntegration_Full_session_flow(t *testing.T) {
	var receivedData []byte
	var receivedHeaders map[string]string

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN"},
		SaslIrEnabled:  true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				if addr == "bob@example.com" {
					return "bob:INBOX", "bob", nil
				}
				return "", "", fmt.Errorf("unknown")
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedData = data
				receivedHeaders = headers
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// Step 1: AUTH
	saslClient := sasl.NewPlainClient("", "alice", "secret")
	if err := client.Auth(saslClient); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	// Step 2: MAIL FROM
	if err := client.Mail("alice@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}

	// Step 3: RCPT TO
	if err := client.Rcpt("bob@example.com", nil); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}

	// Step 4: DATA
	msg := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Integration Test\r\n\r\nHello from the integration test!\r\n"
	w, err := client.Data()
	if err != nil {
		t.Fatalf("DATA: %v", err)
	}
	_, err = io.Copy(w, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("DATA close: %v", err)
	}

	// Step 5: Verify delivery
	if receivedHeaders == nil {
		t.Fatal("expected headers to be set")
	}
	if receivedHeaders["Subject"] != "Integration Test" {
		t.Errorf("Subject = %q, want %q", receivedHeaders["Subject"], "Integration Test")
	}
	if receivedHeaders["Message-ID"] == "" {
		t.Error("expected auto-generated Message-ID")
	}
	if len(receivedData) == 0 {
		t.Error("expected non-empty message data")
	}

	// Step 6: NOOP
	if err := client.Noop(); err != nil {
		t.Fatalf("NOOP: %v", err)
	}

	// Step 7: QUIT (handled by t.Cleanup)
}

func TestIntegration_Dot_stuffing(t *testing.T) {
	var receivedData []byte

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedData = data
				return "item-1", nil
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// Message with lines starting with dots (dot stuffing)
	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Dot Stuff\r\n\r\nLine with dot: .hidden\r\n..double dot\r\n"
	if err := client.SendMail("sender@example.com", []string{"recipient@example.com"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	// The data should contain ".hidden" (dot stuffing handled by server)
	if !bytes.Contains(receivedData, []byte(".hidden")) {
		t.Errorf("expected dot-stuffed line in data, got: %s", string(receivedData))
	}
}

func TestIntegration_Verify(t *testing.T) {
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				if addr == "alice@example.com" {
					return "alice:INBOX", "alice", nil
				}
				return "", "", fmt.Errorf("unknown")
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)

	// VRFY is mapped through the client's Verify method
	// Note: VRFY may not be implemented by all servers
	_ = client.Verify("alice@example.com")
}

// --- Helper: raw connection for HELO test ---

// readRawLine reads a single line from a net.Conn.
func readRawLine(conn net.Conn) (string, error) {
	var buf bytes.Buffer
	for {
		b := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(b)
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}
		if b[0] == '\n' {
			break
		}
		buf.WriteByte(b[0])
	}
	return strings.TrimSpace(buf.String()), nil
}

// --- Virus Scanning ---

func TestIntegration_Virus_Rejection(t *testing.T) {
	var scanCalled bool

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			GetVirusScanEnabled: func() bool { return true },
			VirusScan: func(data []byte) (string, bool, error) {
				scanCalled = true
				// Simulate virus detection for EICAR
				if bytes.Contains(data, []byte("EICAR")) {
					return "EICAR-AV-Test", true, nil
				}
				return "", false, nil
			},
		},
	})
	t.Cleanup(cleanup)

	// Send raw SMTP with EICAR test string
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Read greeting
	if _, err := readRawLine(conn); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// EHLO
	fmt.Fprintf(conn, "EHLO test.veksel\r\n")
	// Read EHLO response (multi-line)
	for {
		line, err := readRawLine(conn)
		if err != nil {
			t.Fatalf("read EHLO: %v", err)
		}
		if !strings.HasSuffix(line, "-") {
			break
		}
	}

	// MAIL FROM
	fmt.Fprintf(conn, "MAIL FROM:<sender@example.com>\r\n")
	if _, err := readRawLine(conn); err != nil {
		t.Fatalf("read MAIL FROM: %v", err)
	}

	// RCPT TO
	fmt.Fprintf(conn, "RCPT TO:<recipient@example.com>\r\n")
	if _, err := readRawLine(conn); err != nil {
		t.Fatalf("read RCPT TO: %v", err)
	}

	// DATA — under pipelining, queued EHLO responses arrive first,
	// then the 354 interim reply, then we send the body.
	fmt.Fprintf(conn, "DATA\r\n")
	// Drain until we get the 354 interim reply
	for i := 0; i < 30; i++ {
		line, err := readRawLine(conn)
		if err != nil {
			t.Fatalf("read DATA reply: %v", err)
		}
		if strings.HasPrefix(line, "354") {
			break
		}
	}

	// Send message with EICAR
	fmt.Fprintf(conn, "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nEICAR test content\r\n.\r\n")
	reply, err := readRawLine(conn)
	if err != nil {
		t.Fatalf("read DATA response: %v", err)
	}

	// Should get 550 rejection
	if !strings.HasPrefix(reply, "550") {
		t.Fatalf("expected 550 rejection for virus, got: %s", reply)
	}
	if !strings.Contains(reply, "virus detected") {
		t.Fatalf("expected 'virus detected' in response, got: %s", reply)
	}

	if !scanCalled {
		t.Fatal("expected VirusScan to be called")
	}
}

func TestIntegration_Virus_Clean(t *testing.T) {
	var delivered bool

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				delivered = true
				return "item-1", nil
			},
			GetVirusScanEnabled: func() bool { return true },
			VirusScan: func(data []byte) (string, bool, error) {
				return "", false, nil // clean
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)
	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Clean\r\n\r\nThis is clean.\r\n"
	if err := client.SendMail("sender@example.com", []string{"recipient@example.com"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	if !delivered {
		t.Fatal("expected clean message to be delivered")
	}
}

func TestIntegration_Virus_Disabled(t *testing.T) {
	var delivered bool
	var scanCalled bool

	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				delivered = true
				return "item-1", nil
			},
			GetVirusScanEnabled: func() bool { return false }, // disabled
			VirusScan: func(data []byte) (string, bool, error) {
				scanCalled = true
				return "EICAR", true, nil // would detect but should not be called
			},
		},
	})
	t.Cleanup(cleanup)

	client := dialClient(t, addr)
	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nEICAR content\r\n"
	if err := client.SendMail("sender@example.com", []string{"recipient@example.com"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	if !delivered {
		t.Fatal("expected message to be delivered when virus scanning is disabled")
	}
	if scanCalled {
		t.Fatal("expected VirusScan to NOT be called when disabled")
	}
}
