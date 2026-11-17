package protocolauth

import (
	"errors"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
)

// An account with a second factor signs in to protocols with application
// passwords only, so its primary password alone cannot read its mail.
func TestSecondFactorAccountsUseApplicationPasswordsOnProtocols(t *testing.T) {
	typed, service := protocolAuthFixture(t)
	if _, err := model.NewSecondFactorStore(typed).Update(t.Context(), "alice", func(f *model.SecondFactors) error {
		f.TOTP = &model.TOTPFactor{SealedSecret: []byte("sealed"), EnabledAt: time.Now()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, secret, err := model.NewAppPasswordStore(typed).Create(t.Context(), "alice", "Phone", []string{model.AppProtocolIMAP})
	if err != nil {
		t.Fatal(err)
	}

	// A device still configured with the primary password is refused but
	// never charged as guessing.
	throttle := ratelimit.NewAuthThrottleWithLimits(2, 2, time.Minute)
	service.SetThrottle(throttle)
	client := ratelimit.WithClientIP(t.Context(), "192.0.2.7")
	for range 5 {
		if _, err := service.Authenticate(client, "alice", "primary-password", model.AppProtocolIMAP); !errors.Is(err, ErrAppPasswordRequired) || !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("primary password with a second factor: %v", err)
		}
	}
	if result, err := service.Authenticate(client, "alice", secret, model.AppProtocolIMAP); err != nil || result.AppPasswordID == "" {
		t.Fatalf("application password = %+v, %v", result, err)
	}
	// Web sign-in still checks the primary password (and then the factor).
	if _, err := service.VerifyPassword(t.Context(), "alice", "primary-password"); err != nil {
		t.Fatalf("web primary password: %v", err)
	}

	service.SetRequireAppPasswords(false)
	if result, err := service.Authenticate(client, "alice", "primary-password", model.AppProtocolIMAP); err != nil || result.User.ID != "alice" {
		t.Fatalf("primary password with the policy off = %+v, %v", result, err)
	}
}
