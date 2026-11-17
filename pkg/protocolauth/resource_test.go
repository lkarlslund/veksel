package protocolauth

import (
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestServiceRefusesResourceAccountEveryPath(t *testing.T) {
	typed, service := protocolAuthFixture(t)
	users := typed.UserStore()
	if err := users.Create(t.Context(), "room", "Room", "room-password"); err != nil {
		t.Fatal(err)
	}
	if err := users.AddEmailAddress(t.Context(), "room@example.test", "room", "example.test", true); err != nil {
		t.Fatal(err)
	}
	appPasswords := model.NewAppPasswordStore(typed)
	_, secret, err := appPasswords.Create(t.Context(), "room", "Before", []string{model.AppProtocolIMAP})
	if err != nil {
		t.Fatal(err)
	}
	if err := users.Update(t.Context(), "room", func(user *model.User) { user.Resource = &model.ResourceProfile{Kind: model.BookableRoom} }); err != nil {
		t.Fatal(err)
	}
	for _, login := range []string{"room", "room@example.test"} {
		for _, password := range []string{"room-password", secret} {
			if _, err := service.Authenticate(t.Context(), login, password, model.AppProtocolIMAP); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Authenticate(%s) accepted a resource account: %v", login, err)
			}
			if _, err := service.VerifyPassword(t.Context(), login, password); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("VerifyPassword(%s) accepted a resource account: %v", login, err)
			}
		}
	}
	if _, _, err := appPasswords.Create(t.Context(), "room", "After", nil); !errors.Is(err, model.ErrResourceAccount) {
		t.Fatalf("app password for a resource: %v", err)
	}
	if _, err := appPasswords.Authenticate(t.Context(), "room", secret, model.AppProtocolIMAP); !errors.Is(err, model.ErrResourceAccount) {
		t.Fatalf("app password store authenticated a resource: %v", err)
	}
	keys := model.NewAPIKeyStore(typed)
	if _, _, err := keys.Create(t.Context(), "room", "key"); !errors.Is(err, model.ErrResourceAccount) {
		t.Fatalf("api key for a resource: %v", err)
	}
	_, keySecret, err := keys.Create(t.Context(), "alice", "key")
	if err != nil {
		t.Fatal(err)
	}
	if key, err := keys.GetBySecret(t.Context(), keySecret); err != nil || key == nil {
		t.Fatalf("ordinary key = %v, %v", key, err)
	}
	// A key minted before the account became a resource stops working.
	if err := users.Update(t.Context(), "alice", func(user *model.User) { user.Resource = &model.ResourceProfile{} }); err != nil {
		t.Fatal(err)
	}
	if key, err := keys.GetBySecret(t.Context(), keySecret); err != nil || key != nil {
		t.Fatalf("resource key = %v, %v", key, err)
	}
}
