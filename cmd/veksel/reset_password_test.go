package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestResetPasswordSetsUsablePassword(t *testing.T) {
	dir := t.TempDir()
	withUserStore(t, dir, func(users *model.UserStore) {
		if err := users.Create(context.Background(), "alice", "Alice", "old-password"); err != nil {
			t.Fatal(err)
		}
	})

	var stdout, stderr bytes.Buffer
	if err := runResetPassword([]string{"--data-dir", dir, "alice"}, nil, &stdout, &stderr); err != nil {
		t.Fatalf("reset: %v (%s)", err, stderr.String())
	}
	password, ok := strings.CutPrefix(strings.TrimSpace(stdout.String()), "new password for alice: ")
	if !ok || password == "" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	withUserStore(t, dir, func(users *model.UserStore) {
		user, err := users.Get(context.Background(), "alice")
		if err != nil || !auth.ComparePassword(password, user.PasswordHash) || auth.ComparePassword("old-password", user.PasswordHash) {
			t.Fatalf("password was not replaced: %v", err)
		}
	})

	stderr.Reset()
	if err := runResetPassword([]string{"--data-dir", dir}, nil, &stdout, &stderr); err == nil || !strings.Contains(stderr.String(), "  alice") {
		t.Fatalf("missing user: err=%v stderr=%q", err, stderr.String())
	}
}

func withUserStore(t *testing.T, dir string, fn func(*model.UserStore)) {
	t.Helper()
	withTypedStore(t, dir, func(ts *model.TypedStore) { fn(model.NewUserStore(ts)) })
}

func withTypedStore(t *testing.T, dir string, fn func(*model.TypedStore)) {
	t.Helper()
	service, err := config.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := service.Current().Config
	backend, err := cfg.OpenStore()
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	ts := model.NewTypedStore(backend, cfg.StoreBackend)
	for _, namespace := range model.Namespaces() {
		if err := ts.EnsureNamespace(context.Background(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	fn(ts)
}

func TestResetPasswordClearsTwoFactor(t *testing.T) {
	dir := t.TempDir()
	withTypedStore(t, dir, func(ts *model.TypedStore) {
		ctx := context.Background()
		if err := model.NewUserStore(ts).Create(ctx, "alice", "Alice", "old-password"); err != nil {
			t.Fatal(err)
		}
		if _, err := model.NewSecondFactorStore(ts).Update(ctx, "alice", func(factors *model.SecondFactors) error {
			factors.TOTP = &model.TOTPFactor{SealedSecret: []byte("sealed")}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	var stdout, stderr bytes.Buffer
	if err := runResetPassword([]string{"--data-dir", dir, "--keep-password", "alice"}, nil, &stdout, &stderr); err == nil {
		t.Fatal("--keep-password without --clear-2fa was accepted")
	}
	if err := runResetPassword([]string{"--data-dir", dir, "--clear-2fa", "--keep-password", "alice"}, nil, &stdout, &stderr); err != nil {
		t.Fatalf("clear: %v (%s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "two-factor sign-in cleared for alice") || strings.Contains(stdout.String(), "new password") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	withTypedStore(t, dir, func(ts *model.TypedStore) {
		user, err := model.NewUserStore(ts).Get(context.Background(), "alice")
		if err != nil || !auth.ComparePassword("old-password", user.PasswordHash) {
			t.Fatalf("password changed despite --keep-password: %v", err)
		}
		factors, err := model.NewSecondFactorStore(ts).Get(context.Background(), "alice")
		if err != nil || factors.Enabled() {
			t.Fatalf("factors after clear = %+v err=%v", factors, err)
		}
		if entries, err := audit.New(ts).Query(context.Background(), time.Time{}, "account.two_factor.reset", "cli", 10); err != nil || len(entries) != 1 {
			t.Fatalf("reset audit = %+v err=%v", entries, err)
		}
	})
}

func TestResetPasswordReadsChosenPasswordFromStdin(t *testing.T) {
	dir := t.TempDir()
	withUserStore(t, dir, func(users *model.UserStore) {
		if err := users.Create(context.Background(), "alice", "Alice", "old-password"); err != nil {
			t.Fatal(err)
		}
	})
	var stdout, stderr bytes.Buffer
	if err := runResetPassword([]string{"--data-dir", dir, "--password-stdin", "alice"}, strings.NewReader("chosen-secret\n"), &stdout, &stderr); err != nil {
		t.Fatalf("reset: %v (%s)", err, stderr.String())
	}
	if strings.Contains(stdout.String(), "chosen-secret") {
		t.Fatalf("stdout echoes the password: %q", stdout.String())
	}
	withUserStore(t, dir, func(users *model.UserStore) {
		user, err := users.Get(context.Background(), "alice")
		if err != nil || !auth.ComparePassword("chosen-secret", user.PasswordHash) {
			t.Fatalf("password was not set: %v", err)
		}
	})
	if err := runResetPassword([]string{"--data-dir", dir, "--password-stdin", "alice"}, strings.NewReader("\n"), &stdout, &stderr); err == nil {
		t.Fatal("empty password accepted")
	}
}
