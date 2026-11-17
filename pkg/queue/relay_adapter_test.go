package queue

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/smtp"
)

func TestRelayAdapter_New(t *testing.T) {
	relay := smtp.NewRelayClient(&smtp.RelayConfig{
		Host: "smtp.test.com",
		Port: 587,
	})
	adapter := NewRelayAdapter(relay)
	if adapter == nil {
		t.Fatal("expected non-nil adapter")
	}
}

func TestRelayAdapter_Deliver_Interface(t *testing.T) {
	// Verify that RelayAdapter.Deliver can be used as a DeliveryFunc
	relay := smtp.NewRelayClient(&smtp.RelayConfig{
		Host: "smtp.test.com",
		Port: 587,
	})
	adapter := NewRelayAdapter(relay)
	var _ DeliveryFunc = adapter.Deliver
}

func TestRelayAdapter_Deliver_NilRelay(t *testing.T) {
	adapter := NewRelayAdapter(nil)
	msg := &Message{
		ID:             "test-1",
		EnvelopeSender: "sender@example.com",
		Recipient:      "recipient@example.com",
		Headers:        map[string]string{"Subject": "Test"},
		Body:           []byte("Hello"),
	}
	err := adapter.Deliver(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error when relay is nil, got nil")
	}
}

func TestResponseClass(t *testing.T) {
	for _, test := range []struct{ message, want string }{
		{"RCPT TO: 550 mailbox missing", "5.0.0"},
		{"remote response 4.2.0 mailbox busy", "4.2.0"},
		{"connection reset", ""},
	} {
		if got := responseClass(test.message); got != test.want {
			t.Errorf("responseClass(%q) = %q, want %q", test.message, got, test.want)
		}
	}
}

func TestRelayAdapterPreservesPostDataUncertainty(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		_, _ = fmt.Fprint(rw, "220 test ESMTP\r\n")
		_ = rw.Flush()
		for {
			line, readErr := rw.ReadString('\n')
			if readErr != nil {
				return
			}
			switch {
			case strings.HasPrefix(strings.ToUpper(line), "EHLO"):
				_, _ = fmt.Fprint(rw, "250 test\r\n")
			case strings.HasPrefix(strings.ToUpper(line), "MAIL FROM"), strings.HasPrefix(strings.ToUpper(line), "RCPT TO"):
				_, _ = fmt.Fprint(rw, "250 OK\r\n")
			case strings.HasPrefix(strings.ToUpper(line), "DATA"):
				_, _ = fmt.Fprint(rw, "354 continue\r\n")
				_ = rw.Flush()
				for {
					dataLine, dataErr := rw.ReadString('\n')
					if dataErr != nil || strings.TrimSpace(dataLine) == "." {
						return
					}
				}
			}
			_ = rw.Flush()
		}
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	adapter := NewRelayAdapter(smtp.NewRelayClient(&smtp.RelayConfig{Host: host, Port: port, ServerName: "test.veksel"}))
	err = adapter.Deliver(t.Context(), &Message{ID: "uncertain", EnvelopeSender: "sender@example.test", Recipient: "recipient@example.test", Headers: map[string]string{"Subject": "test"}, Body: []byte("body")})
	var deliveryErr *DeliveryError
	if !errors.As(err, &deliveryErr) || deliveryErr.Class != DeliveryUncertain {
		t.Fatalf("adapter error = %#v", err)
	}
}
