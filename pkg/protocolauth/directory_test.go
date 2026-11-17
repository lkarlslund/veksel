package protocolauth

import (
	"context"
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

// stubDirectory verifies one password per login and counts directory binds.
type stubDirectory struct {
	users map[string]model.User
	err   error
	calls int
}

func (d *stubDirectory) Authenticate(_ context.Context, login, password string) (model.User, error) {
	d.calls++
	if d.err != nil {
		return model.User{}, d.err
	}
	user, ok := d.users[login]
	if !ok || password != "directory-password" {
		return model.User{}, errors.New("directory: invalid credentials")
	}
	return user, nil
}

func directoryAccount(t *testing.T, typed *model.TypedStore, id string) model.User {
	t.Helper()
	// A stale local hash must never authenticate a directory account.
	if err := typed.UserStore().Create(t.Context(), id, id, "stale-local-password"); err != nil {
		t.Fatal(err)
	}
	user, err := typed.UserStore().Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	user.Source, user.DirectoryDN = model.UserSourceLDAP, "uid="+id+",dc=example,dc=test"
	if err := typed.Set(t.Context(), model.NSUsers, user.ID, user); err != nil {
		t.Fatal(err)
	}
	return user
}

func TestDirectoryAccountsVerifyOnlyAgainstTheDirectory(t *testing.T) {
	typed, service := protocolAuthFixture(t)
	dave := directoryAccount(t, typed, "dave")
	directory := &stubDirectory{users: map[string]model.User{"dave": dave, "newcomer": {ID: "newcomer", Enabled: true}, "alice": dave}}
	service.SetDirectory(directory)
	if user, err := service.VerifyPassword(t.Context(), "dave", "directory-password"); err != nil || user.ID != "dave" {
		t.Fatalf("directory password = %+v, %v", user, err)
	}
	if _, err := service.VerifyPassword(t.Context(), "dave", "stale-local-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("stale local hash accepted: %v", err)
	}
	if _, err := service.Authenticate(t.Context(), "dave", "", model.AppProtocolIMAP); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty password accepted: %v", err)
	}
	if user, err := service.VerifyPassword(t.Context(), "newcomer", "directory-password"); err != nil || user.ID != "newcomer" {
		t.Fatalf("unknown login not offered to the directory: %+v, %v", user, err)
	}
	// A local account never falls through to the directory, even when the
	// directory would vouch for the same login.
	before := directory.calls
	if _, err := service.VerifyPassword(t.Context(), "alice", "directory-password"); !errors.Is(err, ErrInvalidCredentials) || directory.calls != before {
		t.Fatalf("local account consulted the directory: %v (calls %d)", err, directory.calls-before)
	}
	// The directory must answer for the account the login resolved to.
	directory.users["dave"] = model.User{ID: "mallory", Enabled: true}
	if _, err := service.VerifyPassword(t.Context(), "dave", "directory-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("directory answer for another account accepted: %v", err)
	}
}

func TestLocalOwnerAndAppPasswordsWorkWhenDirectoryIsDown(t *testing.T) {
	typed, service := protocolAuthFixture(t)
	directoryAccount(t, typed, "dave")
	directory := &stubDirectory{err: errors.New("directory is unavailable")}
	service.SetDirectory(directory)
	if result, err := service.Authenticate(t.Context(), "alice", "primary-password", model.AppProtocolIMAP); err != nil || result.User.ID != "alice" {
		t.Fatalf("local account while directory is down = %+v, %v", result, err)
	}
	created, secret, err := model.NewAppPasswordStore(typed).Create(t.Context(), "dave", "Phone", []string{model.AppProtocolIMAP})
	if err != nil {
		t.Fatal(err)
	}
	calls := directory.calls
	result, err := service.Authenticate(t.Context(), "dave", secret, model.AppProtocolIMAP)
	if err != nil || result.User.ID != "dave" || result.AppPasswordID != created.ID {
		t.Fatalf("app password for directory account = %+v, %v", result, err)
	}
	if directory.calls != calls {
		t.Fatal("an application password cost a directory bind")
	}
	if _, err := service.Authenticate(t.Context(), "dave", "directory-password", model.AppProtocolIMAP); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("directory password accepted while directory is down: %v", err)
	}
}
