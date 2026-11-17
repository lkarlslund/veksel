package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// proxiedSession dials addr as client through a PROXY v1 header and returns
// the server's replies to each command; the first reply is the greeting. An
// empty greeting means the connection was closed before any protocol bytes.
func proxiedSession(t *testing.T, addr, client string, commands ...string) []string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "PROXY TCP4 "+client+" 192.0.2.1 40000 25\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	readReply := func() string {
		var reply string
		for {
			line, err := reader.ReadString('\n')
			reply += line
			// SMTP continuation lines carry a hyphen after the code.
			if err != nil || len(line) < 4 || line[3] != '-' {
				return reply
			}
		}
	}
	replies := []string{readReply()}
	if replies[0] == "" {
		return replies
	}
	for _, command := range commands {
		if _, err := io.WriteString(conn, command+"\r\n"); err != nil {
			t.Fatal(err)
		}
		replies = append(replies, readReply())
	}
	return replies
}

// TestBannedClientsAreRefusedAtMailAccept checks enforcement by the relayed
// client address on IMAP and SMTP accept, and that unknown-recipient
// harvesting over SMTP bans the client.
func TestBannedClientsAreRefusedAtMailAccept(t *testing.T) {
	control := newTestProtocolControl(t)
	controllers := control.controllers
	policy := ban.DefaultPolicy()
	policy.Rules[ban.TriggerRecipient] = ban.Rule{Count: 3, Window: time.Minute}
	bans, err := ban.New(t.Context(), controllers.ts.Store(), nil, nil, policy)
	if err != nil {
		t.Fatal(err)
	}
	controllers.bans = bans
	controllers.cfg.MailProxyProtocol, controllers.cfg.MailProxyProtocolTrusted = []string{"imap", "smtp"}, []string{"127.0.0.1"}
	controllers.setSMTPDependencies(smtpDependencies{delivery: &smtp.Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "", "", errors.New("unknown") },
	}})
	controllers.start(t.Context(), &imapProtocol)
	controllers.start(t.Context(), &smtpProtocol)
	imapAddr := imapProtocol.state(controllers).status().Listeners[0]
	smtpAddr := smtpProtocol.state(controllers).status().Listeners[0]

	network, _ := ban.ParseNetwork("203.0.113.7")
	if _, err := bans.Ban(t.Context(), network, time.Hour, "owner", ""); err != nil {
		t.Fatal(err)
	}
	if greeting := proxiedSession(t, imapAddr, "203.0.113.7")[0]; greeting != "" {
		t.Fatalf("banned IMAP client greeted: %q", greeting)
	}
	if greeting := proxiedSession(t, imapAddr, "203.0.113.8")[0]; !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("unbanned IMAP client refused: %q", greeting)
	}
	if greeting := proxiedSession(t, smtpAddr, "203.0.113.7")[0]; greeting != "" {
		t.Fatalf("banned SMTP client greeted: %q", greeting)
	}

	replies := proxiedSession(t, smtpAddr, "198.51.100.5", "EHLO client.example.test", "MAIL FROM:<a@example.test>",
		"RCPT TO:<x1@example.test>", "RCPT TO:<x2@example.test>", "RCPT TO:<x3@example.test>")
	for _, reply := range replies[3:] {
		if !strings.HasPrefix(reply, "550") {
			t.Fatalf("unknown recipient reply = %q (all %q)", reply, replies)
		}
	}
	if greeting := proxiedSession(t, smtpAddr, "198.51.100.5")[0]; greeting != "" {
		t.Fatalf("harvesting SMTP client not banned: %q", greeting)
	}
	if listed := bans.List("198.51.100.5"); len(listed) != 1 || listed[0].Reason != ban.TriggerRecipient || listed[0].Hits != 1 {
		t.Fatalf("bans = %+v", listed)
	}
}

// TestBanSettingsApplyLiveAndFailedLoginsBan drives the ban engine through
// managed configuration and the shared protocol login throttle.
func TestBanSettingsApplyLiveAndFailedLoginsBan(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	service, err := config.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := model.NewTypedStore(backend, service.Current().Config.StoreBackend)
	if err := ts.EnsureNamespace(t.Context(), model.NSUsers); err != nil {
		t.Fatal(err)
	}
	s := withTestBackground(t, &server{cfgService: service, cfg: service.Current().Config, ts: ts, met: metrics.New(backend), protocolAuth: protocolauth.New(ts)})
	if err := s.startBans(); err != nil {
		t.Fatal(err)
	}
	unapplied := service.UnappliedKeys()
	for _, key := range banSettings {
		if slices.Contains(unapplied, key) {
			t.Errorf("%s still requires a restart", key)
		}
	}

	changes := map[string]any{"ban_auth_failures": "2/1m", "ban_durations": []string{"5m", "2h"}, "ban_ipv6_prefix": int64(56)}
	snapshot, err := service.Patch(service.Current().Revision, changes)
	if err != nil {
		t.Fatal(err)
	}
	service.Apply(snapshot, changes)
	policy := s.bans.Policy()
	if policy.Rules[ban.TriggerAuth] != (ban.Rule{Count: 2, Window: time.Minute}) || !slices.Equal(policy.Durations, []time.Duration{5 * time.Minute, 2 * time.Hour}) || policy.IPv6Prefix != 56 {
		t.Fatalf("policy = %+v", policy)
	}
	for key, value := range map[string]any{"ban_durations": []string{"1h", "10m"}, "ban_auth_failures": "ten/10m", "ban_ipv6_prefix": int64(8)} {
		if _, err := service.Patch(service.Current().Revision, map[string]any{key: value}); err == nil {
			t.Errorf("invalid %s = %v accepted", key, value)
		}
	}

	ctx := ratelimit.WithClientIP(t.Context(), "192.0.2.9")
	for range 2 {
		if _, err := s.protocolAuth.Authenticate(ctx, "nobody", "wrong", model.AppProtocolIMAP); err == nil {
			t.Fatal("unknown account authenticated")
		}
	}
	if !s.bans.Banned("192.0.2.9", "imap") {
		t.Fatal("failed protocol logins did not ban the client")
	}
	if listed := s.bans.List(""); len(listed) != 1 || listed[0].ExpiresAt.Sub(listed[0].CreatedAt) != 5*time.Minute {
		t.Fatalf("bans = %+v", listed)
	}

	disable := map[string]any{"ban_enabled": false}
	snapshot, err = service.Patch(service.Current().Revision, disable)
	if err != nil {
		t.Fatal(err)
	}
	service.Apply(snapshot, disable)
	if s.bans.Banned("192.0.2.9", "imap") {
		t.Fatal("disabling bans did not apply live")
	}
}
