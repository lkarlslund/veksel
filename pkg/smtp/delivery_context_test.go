package smtp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// TestLocalDeliveryPassesSessionContext replays the interop crash where a
// local delivery handed a nil context to the Sieve lookup, whose folder cache
// read ctx.Value and took the whole server down. Every delivery callback must
// receive a usable context.
func TestLocalDeliveryPassesSessionContext(t *testing.T) {
	var mu sync.Mutex
	var nilCalls []string
	check := func(name string, ctx context.Context) error {
		if ctx == nil {
			mu.Lock()
			nilCalls = append(nilCalls, name)
			mu.Unlock()
			return errors.New(name + " received a nil context")
		}
		_ = ctx.Value(struct{}{})
		return nil
	}
	mailQueue := &recordingSystemQueue{}
	delivery := srsDelivery(t, testSRSCodec(t), mailQueue)
	resolve := delivery.ResolveRecipient
	delivery.ResolveRecipient = func(ctx context.Context, address string) (string, string, error) {
		if err := check("ResolveRecipient", ctx); err != nil {
			return "", "", err
		}
		return resolve(ctx, address)
	}
	delivery.GetSieveScript = func(ctx context.Context, _ string) (string, bool, error) {
		return "", false, check("GetSieveScript", ctx)
	}
	delivery.VacationActive = func(ctx context.Context, _ string) bool {
		_ = check("VacationActive", ctx)
		return false
	}
	address, cleanup := startSMTPServer(t, &Config{ServerName: "mx.example.test", Delivery: delivery})
	t.Cleanup(cleanup)
	if err := dialClient(t, address).SendMail("bob@remote.example", []string{"alice@example.test"}, strings.NewReader("Subject: x\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(nilCalls) != 0 {
		t.Fatalf("delivery callbacks received nil contexts: %v", nilCalls)
	}
	if len(mailQueue.messages) != 1 {
		t.Fatalf("delivered %d messages, want 1", len(mailQueue.messages))
	}
}
