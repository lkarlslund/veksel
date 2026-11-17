package main

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/pgpkey"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/store"
)

// openpgpSettings holds the live OpenPGP key discovery switches.
type openpgpSettings struct {
	wkd, autocrypt atomic.Bool
}

// registerOpenPGP applies wkd_enabled and autocrypt_enabled live and serves
// the Web Key Directory on the shared mux. The directory sits under
// /.well-known/, so it is reached through the autodiscover HTTP service.
func (s *server) registerOpenPGP() error {
	s.openpgp.wkd.Store(s.cfg.WkdEnabled)
	s.openpgp.autocrypt.Store(s.cfg.AutocryptEnabled)
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		s.openpgp.wkd.Store(cfg.WkdEnabled)
		s.openpgp.autocrypt.Store(cfg.AutocryptEnabled)
		return nil
	}, "wkd_enabled", "autocrypt_enabled"); err != nil {
		return err
	}
	if s.mux != nil {
		s.mux.Handle("/.well-known/openpgpkey/", s.keyDirectory())
	}
	return nil
}

// keyDirectory serves the keys users published for enabled identities of
// hosted domains.
func (s *server) keyDirectory() *pgpkey.Directory {
	return &pgpkey.Directory{
		Enabled: s.openpgp.wkd.Load,
		Hosted:  s.isHostedDomain,
		Key: func(ctx context.Context, domain, hash string) ([]byte, bool, error) {
			key, err := s.ts.PGPKeyStore().ByHash(ctx, domain, hash)
			if errors.Is(err, store.ErrNotFound) {
				return nil, false, nil
			}
			if err != nil {
				return nil, false, err
			}
			if key.Expired(time.Now()) {
				return nil, false, nil
			}
			identity, err := s.ts.UserStore().GetEmailAddress(ctx, key.Address)
			switch {
			case errors.Is(err, store.ErrNotFound), err == nil && (!identity.Enabled || identity.UserID != key.UserID):
				return nil, false, nil
			case err != nil:
				return nil, false, err
			}
			return key.Binary, true, nil
		},
	}
}

// addAutocrypt adds an Autocrypt header advertising the sender's published
// key to mail the sender's own account submitted, when the identity turned
// Autocrypt on. It runs at queue admission after rewriting and before the
// DKIM signature, so the signed message carries the header. A key too
// large for a header is skipped with a warning.
func (s *server) addAutocrypt(ctx context.Context, message *queue.Message) error {
	if message == nil || message.Kind != "" || message.AuthenticatedActor == "" || !s.openpgp.autocrypt.Load() ||
		queueHeader(message.Headers, "Autocrypt") != "" {
		return nil
	}
	from, err := mail.ParseAddress(queueHeader(message.Headers, "From"))
	if err != nil {
		return nil
	}
	key, err := s.ts.PGPKeyStore().Get(ctx, from.Address)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !key.Autocrypt || key.UserID != message.AuthenticatedActor || key.Expired(time.Now()) {
		return nil
	}
	identity, err := s.ts.UserStore().GetEmailAddress(ctx, key.Address)
	if err != nil || !identity.Enabled || identity.UserID != key.UserID {
		return nil
	}
	field, err := pgpkey.AutocryptHeader(strings.ToLower(from.Address), key.Binary)
	if err != nil {
		log.Warn("Autocrypt: header skipped", "address", key.Address, "error", err)
		return nil
	}
	if message.Headers == nil {
		message.Headers = make(map[string]string)
	}
	setQueueHeader(message.Headers, "Autocrypt", strings.TrimPrefix(field, "Autocrypt: "))
	if len(message.Content) > 0 {
		message.Content = model.PrependHeaderField(message.Content, field)
	}
	return nil
}
