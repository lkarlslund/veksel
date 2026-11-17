// Package protocolauth provides one credential boundary for mail and
// groupware protocols. Browser sessions, REST API keys, and MCP credentials do
// not use this service, but browser sign-in shares its primary password check
// (VerifyPassword).
package protocolauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrAppPasswordRequired refuses an account's correct primary password on a
// protocol because the account has a second factor and must use an
// application password there. It wraps ErrInvalidCredentials, so protocols
// answer it as an ordinary failed login.
var ErrAppPasswordRequired = fmt.Errorf("%w: accounts with a second factor must use an application password", ErrInvalidCredentials)

// AuthenticateFunc verifies a protocol credential and returns the canonical
// account ID. Protocol servers receive one bound to their protocol by the
// server bootstrap; ctx should carry the client IP (ratelimit.WithClientIP) so
// the shared failed-login throttle sees every protocol.
type AuthenticateFunc func(ctx context.Context, username, password string) (string, error)

// Directory verifies passwords against an external account directory. A
// successful Authenticate returns the local account for the directory entry,
// provisioning or refreshing it first.
type Directory interface {
	Authenticate(ctx context.Context, login, password string) (model.User, error)
}

type Result struct {
	User          model.User
	AppPasswordID string
}

type Service struct {
	users     *model.UserStore
	passwords *model.AppPasswordStore
	throttle  *ratelimit.AuthThrottle
	compare   func(password, hash string) bool
	directory atomic.Pointer[Directory]
	logins    atomic.Pointer[LoginObserver]
	factors   *model.SecondFactorStore
	// allowPrimaryWith2FA lets accounts with a second factor keep using
	// their primary password on protocols (two_factor_requires_app_passwords
	// off). By default they must use application passwords, so a stolen
	// password alone cannot read mail over IMAP, EWS or ActiveSync.
	allowPrimaryWith2FA atomic.Bool
}

// LoginObserver learns about each successful protocol login and its client
// address, which may be empty.
type LoginObserver func(ctx context.Context, account, ip string)

func New(ts *model.TypedStore) *Service {
	return &Service{users: ts.UserStore(), passwords: model.NewAppPasswordStore(ts), throttle: ratelimit.NewAuthThrottle(), compare: auth.ComparePassword,
		factors: model.NewSecondFactorStore(ts)}
}

// SetRequireAppPasswords selects whether accounts with a second factor must
// use application passwords on protocols (the default) or may also use their
// primary password.
func (s *Service) SetRequireAppPasswords(require bool) { s.allowPrimaryWith2FA.Store(!require) }

// Throttle returns the failed-authentication throttle so other credential
// boundaries, such as browser login, can share one budget per client.
func (s *Service) Throttle() *ratelimit.AuthThrottle { return s.throttle }

// SetThrottle replaces the failed-authentication throttle; nil disables it.
func (s *Service) SetThrottle(throttle *ratelimit.AuthThrottle) { s.throttle = throttle }

// SetLoginObserver installs the successful-login observer; nil removes it.
func (s *Service) SetLoginObserver(observer LoginObserver) {
	if observer == nil {
		s.logins.Store(nil)
		return
	}
	s.logins.Store(&observer)
}

// SetDirectory installs the directory that verifies directory accounts and
// logins matching no local account; nil leaves only local accounts.
func (s *Service) SetDirectory(directory Directory) {
	if directory == nil {
		s.directory.Store(nil)
		return
	}
	s.directory.Store(&directory)
}

// Authenticate verifies protocol credentials. When ctx carries a client IP
// (ratelimit.WithClientIP), repeated failures from that client are refused
// with a ratelimit.ErrAuthThrottled error before any password hash is
// compared.
func (s *Service) Authenticate(ctx context.Context, username, password, protocol string) (result Result, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !model.IsSupportedAppProtocol(protocol) {
		return Result{}, ErrInvalidCredentials
	}
	ip := ratelimit.ClientIP(ctx)
	if err := s.throttle.Begin(ip, username); err != nil {
		logFailedLogin(protocol, username, ip, err)
		return Result{}, err
	}
	// A refused correct primary password is not guessing: it neither counts
	// toward throttling and bans nor locks out a device still configured
	// with the old password.
	defer func() {
		s.throttle.End(ip, username, err == nil || errors.Is(err, ErrAppPasswordRequired))
		if err != nil {
			logFailedLogin(protocol, username, ip, err)
		}
	}()
	result, err = s.authenticate(ctx, username, password, protocol)
	if observer := s.logins.Load(); err == nil && observer != nil {
		(*observer)(ctx, result.User.ID, ip)
	}
	return result, err
}

func (s *Service) authenticate(ctx context.Context, username, password, protocol string) (Result, error) {
	user, found, err := s.lookup(ctx, username)
	if err != nil {
		return Result{}, err
	}
	// Application passwords are local credentials. A directory account tries
	// them first so a client's app password never costs a directory bind or
	// counts toward the directory's own lockout.
	if found && user.Directory() {
		if credential, err := s.passwords.Authenticate(ctx, user.ID, password, protocol); err == nil && credential != nil {
			return Result{User: user, AppPasswordID: credential.ID}, nil
		}
	}
	if verified, err := s.verify(ctx, username, password, user, found); err == nil {
		if !s.allowPrimaryWith2FA.Load() && s.factors != nil {
			factors, err := s.factors.Get(ctx, verified.ID)
			if err != nil {
				return Result{}, err
			}
			if factors.Enabled() {
				return Result{}, ErrAppPasswordRequired
			}
		}
		return Result{User: verified}, nil
	}
	if !found || user.Directory() {
		return Result{}, ErrInvalidCredentials
	}
	credential, err := s.passwords.Authenticate(ctx, user.ID, password, protocol)
	if err != nil || credential == nil {
		return Result{}, ErrInvalidCredentials
	}
	return Result{User: user, AppPasswordID: credential.ID}, nil
}

// VerifyPassword checks an account's primary password, the one credential
// shared by browser sign-in and protocols: a local account against its local
// hash, a directory account only against the directory, and a login matching
// no local account against the directory, which may provision it. It does not
// consult the failed-login throttle; callers own that budget.
func (s *Service) VerifyPassword(ctx context.Context, username, password string) (model.User, error) {
	user, found, err := s.lookup(ctx, username)
	if err != nil {
		return model.User{}, err
	}
	return s.verify(ctx, username, password, user, found)
}

// lookup resolves a login (account ID or enabled email identity) to an
// enabled account. found is false when no local account matches, which only
// the directory can then answer; a disabled match is an error.
func (s *Service) lookup(ctx context.Context, username string) (model.User, bool, error) {
	userID := strings.ToLower(strings.TrimSpace(username))
	if strings.Contains(userID, "@") {
		identity, err := s.users.GetEmailAddress(ctx, userID)
		if err != nil {
			return model.User{}, false, nil
		}
		if !identity.Enabled {
			return model.User{}, false, ErrInvalidCredentials
		}
		userID = identity.UserID
	}
	user, err := s.users.Get(ctx, userID)
	if err != nil {
		return model.User{}, false, nil
	}
	if !user.Enabled || user.Resource != nil {
		return model.User{}, false, ErrInvalidCredentials
	}
	return user, true, nil
}

func (s *Service) verify(ctx context.Context, username, password string, user model.User, found bool) (model.User, error) {
	if password == "" {
		return model.User{}, ErrInvalidCredentials
	}
	if found && !user.Directory() {
		if s.compare(password, user.PasswordHash) {
			return user, nil
		}
		return model.User{}, ErrInvalidCredentials
	}
	directory := s.directory.Load()
	if directory == nil {
		return model.User{}, ErrInvalidCredentials
	}
	verified, err := (*directory).Authenticate(ctx, strings.TrimSpace(username), password)
	if err != nil || !verified.Enabled || (found && verified.ID != user.ID) {
		return model.User{}, ErrInvalidCredentials
	}
	return verified, nil
}

var authLog = log.For(log.ModuleAuth)

// logFailedLogin records a refused protocol login with the login name as
// typed (bounded), the client address, and the reason, so operators and log
// based tooling see failures without debug logging.
func logFailedLogin(protocol, username, ip string, err error) {
	username = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, username)
	if len(username) > 128 {
		username = username[:128]
	}
	reason := "invalid credentials"
	switch {
	case errors.Is(err, ErrAppPasswordRequired):
		reason = "application password required (second factor enabled)"
	case !errors.Is(err, ErrInvalidCredentials):
		reason = err.Error()
	}
	authLog.Warn("protocol login failed", "protocol", protocol, "user", username, "ip", ip, "reason", reason)
}
