package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Recipient callout bounds. Positive answers are stable (a mailbox rarely
// disappears), negative ones are kept shorter so a newly created mailbox on
// the other server starts receiving soon.
const (
	calloutTimeout     = 15 * time.Second
	calloutPositiveTTL = time.Hour
	calloutNegativeTTL = 10 * time.Minute
	calloutMaxEntries  = 10000
)

// RecipientCallout asks another SMTP server whether it accepts a recipient,
// with MAIL FROM:<> and RCPT TO, and caches the answer. Split delivery uses it
// to accept mail at RCPT time only for addresses the other server hosts, so
// mail for addresses no system hosts is refused instead of bounced later.
type RecipientCallout struct {
	// ServerName returns the EHLO name; nil or empty uses "localhost".
	ServerName func() string
	// Dial opens the connection; nil uses a net.Dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Now returns the current time; nil uses time.Now.
	Now func() time.Time

	mu    sync.Mutex
	cache map[string]calloutAnswer
}

type calloutAnswer struct {
	accepted bool
	expires  time.Time
}

// CalloutTarget is the server a callout asks.
type CalloutTarget struct {
	Host string
	Port int
	// TLSSkipVerify accepts any certificate after STARTTLS, as an internal
	// server with a self-signed certificate needs.
	TLSSkipVerify bool
}

func (c *RecipientCallout) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Check reports whether target accepts recipient. A 5xx answer is a
// definite no; a 4xx answer or a connection failure is an error, so the
// sending server retries.
func (c *RecipientCallout) Check(ctx context.Context, target CalloutTarget, recipient string) (bool, error) {
	recipient = strings.ToLower(strings.TrimSpace(recipient))
	key := strings.ToLower(target.Host) + "|" + strconv.Itoa(target.Port) + "|" + recipient
	now := c.now()
	c.mu.Lock()
	if answer, ok := c.cache[key]; ok && now.Before(answer.expires) {
		c.mu.Unlock()
		return answer.accepted, nil
	}
	c.mu.Unlock()

	accepted, err := c.ask(ctx, target, recipient)
	if err != nil {
		return false, err
	}
	ttl := calloutNegativeTTL
	if accepted {
		ttl = calloutPositiveTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = make(map[string]calloutAnswer)
	}
	if len(c.cache) >= calloutMaxEntries {
		for k, answer := range c.cache {
			if !now.Before(answer.expires) || len(c.cache) >= calloutMaxEntries {
				delete(c.cache, k)
			}
			if len(c.cache) < calloutMaxEntries/2 {
				break
			}
		}
	}
	c.cache[key] = calloutAnswer{accepted: accepted, expires: now.Add(ttl)}
	return accepted, nil
}

func (c *RecipientCallout) ask(ctx context.Context, target CalloutTarget, recipient string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, calloutTimeout)
	defer cancel()
	dial := c.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	port := target.Port
	if port == 0 {
		port = 25
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(port)))
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	client, err := smtp.NewClient(conn, target.Host)
	if err != nil {
		return false, err
	}
	defer client.Close()
	name := ""
	if c.ServerName != nil {
		name = c.ServerName()
	}
	if name == "" {
		name = "localhost"
	}
	if err := client.Hello(name); err != nil {
		return false, err
	}
	if ok, _ := client.Extension("STARTTLS"); ok {
		//nolint:gosec // TLSSkipVerify is the route's explicit setting for an internal server.
		if err := client.StartTLS(&tls.Config{ServerName: target.Host, InsecureSkipVerify: target.TLSSkipVerify, MinVersion: tls.VersionTLS12}); err != nil {
			return false, err
		}
	}
	if err := client.Mail(""); err != nil {
		return false, err
	}
	err = client.Rcpt(recipient)
	_ = client.Quit()
	if err == nil {
		return true, nil
	}
	var protocolErr *textproto.Error
	if errors.As(err, &protocolErr) && protocolErr.Code >= 500 {
		return false, nil
	}
	return false, err
}
