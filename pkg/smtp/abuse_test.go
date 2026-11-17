package smtp

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/ban"
)

type recordingReporter struct {
	mu      sync.Mutex
	strikes []ban.Trigger
}

func (r *recordingReporter) Strike(ip string, trigger ban.Trigger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ip == "127.0.0.1" {
		r.strikes = append(r.strikes, trigger)
	}
}

func (r *recordingReporter) recorded() []ban.Trigger {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.strikes)
}

// TestSessionReportsHarvestingAndCommandErrors checks the abuse strikes an
// unauthenticated SMTP session reports to the ban engine.
func TestSessionReportsHarvestingAndCommandErrors(t *testing.T) {
	reporter := &recordingReporter{}
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Abuse:      reporter,
		Delivery: &Delivery{ResolveRecipient: func(context.Context, string) (string, string, error) {
			return "", "", errors.New("not found")
		}},
	})
	if code, _ := c.send("DATA"); code != 503 {
		t.Fatalf("DATA before EHLO = %d", code)
	}
	if code, _ := c.send("BOGUS"); code/100 != 5 {
		t.Fatalf("unknown command = %d", code)
	}
	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	if code, _ := c.send("RCPT TO:<nobody@example.com>"); code != 550 {
		t.Fatalf("unknown recipient = %d", code)
	}
	c.send("QUIT")
	want := []ban.Trigger{ban.TriggerProtocol, ban.TriggerProtocol, ban.TriggerRecipient}
	if got := reporter.recorded(); !slices.Equal(got, want) {
		t.Fatalf("strikes = %v, want %v", got, want)
	}
}
