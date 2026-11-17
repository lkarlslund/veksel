package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/batv"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/srs"
	"github.com/lkarlslund/veksel/pkg/store"
)

// addressingPolicy is one immutable snapshot of the recipient delimiter and
// Sender Rewriting Scheme settings.
type addressingPolicy struct {
	delimiters string
	srsEnabled bool
	srsDomain  string // empty uses the SMTP server name
}

func addressingFromConfig(cfg *config.Config) *addressingPolicy {
	return &addressingPolicy{delimiters: cfg.RecipientDelimiter, srsEnabled: cfg.SrsEnabled, srsDomain: strings.ToLower(cfg.SrsDomain)}
}

// addressing returns the current addressing policy.
func (s *server) addressing() *addressingPolicy {
	if policy := s.delivery.addressing.Load(); policy != nil {
		return policy
	}
	return addressingFromConfig(s.cfg)
}

// srsSecretsKey and batvSecretsKey hold the installation's SRS and BATV
// signing secrets, newest first: the first signs new addresses and every
// listed secret verifies returns, so a secret can be rotated by prepending a
// new one.
const (
	srsSecretsKey  = "srs-secrets"
	batvSecretsKey = "batv-secrets"
	// batvEnabledAtKey records when signed return paths were enabled, which
	// starts the grace period for untagged bounces.
	batvEnabledAtKey = "batv-enabled-at"
)

// openAddressing loads (creating on first start) the SRS and BATV secrets and
// installs the configured addressing and backscatter policies.
func (s *server) openAddressing() error {
	secrets, err := loadSigningSecrets(s.ctx, s.ts, srsSecretsKey)
	if err != nil {
		return startupError("initialize sender rewriting", err)
	}
	if s.delivery.srs, err = srs.New(secrets); err != nil {
		return startupError("initialize sender rewriting", err)
	}
	if secrets, err = loadSigningSecrets(s.ctx, s.ts, batvSecretsKey); err != nil {
		return startupError("initialize signed return paths", err)
	}
	if s.delivery.batv, err = batv.New(secrets); err != nil {
		return startupError("initialize signed return paths", err)
	}
	if err := s.applyBATV(s.cfg); err != nil {
		return startupError("initialize signed return paths", err)
	}
	s.delivery.addressing.Store(addressingFromConfig(s.cfg))
	s.loadSpamtraps()
	if s.appHandler != nil {
		s.appHandler.ConfigureRecipientMailbox(s.recipientMailbox)
	}
	return nil
}

// loadSigningSecrets returns the secret list stored under key, creating one
// random secret on first use.
func loadSigningSecrets(ctx context.Context, ts *model.TypedStore, key string) ([][]byte, error) {
	var secrets [][]byte
	err := store.Batch(ctx, ts.Store(), func(batchCtx context.Context) error {
		var encoded []string
		if err := ts.Get(batchCtx, model.NSMetadata, key, &encoded); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if len(encoded) == 0 {
			secret := make([]byte, 32)
			if _, err := rand.Read(secret); err != nil {
				return fmt.Errorf("generate %s: %w", key, err)
			}
			encoded = []string{base64.RawURLEncoding.EncodeToString(secret)}
			if err := ts.Put(batchCtx, model.NSMetadata, key, encoded); err != nil {
				return err
			}
		}
		for _, value := range encoded {
			secret, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return fmt.Errorf("stored %s entry is invalid", key)
			}
			secrets = append(secrets, secret)
		}
		return nil
	})
	return secrets, err
}

// srsDomain is the domain of rewritten forward senders.
func (s *server) srsDomain() string {
	if domain := s.addressing().srsDomain; domain != "" {
		return domain
	}
	return strings.ToLower(s.smtpServerName())
}

// rewriteForwardSender applies SRS to the envelope sender of forwarded and
// redirected mail. The null sender, hosted-domain senders, and senders
// already at the SRS domain keep their address.
func (s *server) rewriteForwardSender(ctx context.Context, sender string) string {
	codec, domain := s.delivery.srs, s.srsDomain()
	at := strings.LastIndex(sender, "@")
	if codec == nil || !s.addressing().srsEnabled || at <= 0 || strings.EqualFold(sender[at+1:], domain) {
		return sender
	}
	if _, err := s.ts.DomainStore().Get(ctx, sender[at+1:]); !errors.Is(err, store.ErrNotFound) {
		return sender // a hosted domain, or the lookup failed
	}
	rewritten, err := codec.Forward(sender, domain)
	if err != nil {
		log.Warn("SRS: keeping original forward sender", "sender", sender, "error", err)
		return sender
	}
	return rewritten
}

// reverseSRS verifies an SRS recipient at the SRS domain. Returns stay
// verifiable while rewriting is disabled so mail already forwarded can
// still bounce.
func (s *server) reverseSRS(_ context.Context, address string) (string, bool, error) {
	at := strings.LastIndex(address, "@")
	if s.delivery.srs == nil || at <= 0 || !strings.EqualFold(address[at+1:], s.srsDomain()) || !srs.IsSRS(address[:at]) {
		return "", false, nil
	}
	original, err := s.delivery.srs.Reverse(address)
	return original, true, err
}

// applyBATV installs the backscatter policy for cfg. Enabling records the
// time once, durably, so the grace period for untagged bounces survives
// restarts; disabling clears it so a later enable starts a new one.
func (s *server) applyBATV(cfg *config.Config) error {
	var enabledAt time.Time
	err := store.Batch(s.ctx, s.ts.Store(), func(batchCtx context.Context) error {
		if !cfg.BatvEnabled {
			if err := s.ts.Store().Delete(batchCtx, model.NSMetadata, batvEnabledAtKey); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			return nil
		}
		err := s.ts.Get(batchCtx, model.NSMetadata, batvEnabledAtKey, &enabledAt)
		if errors.Is(err, store.ErrNotFound) {
			enabledAt = time.Now().UTC()
			return s.ts.Put(batchCtx, model.NSMetadata, batvEnabledAtKey, enabledAt)
		}
		return err
	})
	if err != nil {
		return err
	}
	s.delivery.backscatter.Store(&batv.Policy{Codec: s.delivery.batv, Enabled: cfg.BatvEnabled,
		GraceUntil: enabledAt.Add(time.Duration(cfg.BatvGracePeriodHours) * time.Hour)})
	return nil
}

// signReturnPath tags the envelope sender of mail from a hosted domain for
// BATV while it is enabled. The null sender, SRS senders, already tagged
// senders, and senders at other domains keep their address.
func (s *server) signReturnPath(ctx context.Context, sender string) string {
	policy := s.delivery.backscatter.Load()
	at := strings.LastIndex(sender, "@")
	if policy == nil || !policy.Enabled || policy.Codec == nil || at <= 0 || srs.IsSRS(sender[:at]) || batv.IsTagged(sender[:at]) {
		return sender
	}
	if hosted, err := s.isHostedDomain(ctx, sender[at+1:]); err != nil || !hosted {
		return sender
	}
	signed, err := policy.Codec.Sign(sender)
	if err != nil {
		log.Warn("BATV: keeping unsigned envelope sender", "sender", sender, "error", err)
		return sender
	}
	return signed
}

// checkReturnPath applies the backscatter policy to a recipient at a hosted
// domain for SMTP; see smtp.Delivery.CheckReturnPath.
func (s *server) checkReturnPath(ctx context.Context, address string, bounce bool) (string, error) {
	policy := s.delivery.backscatter.Load()
	at := strings.LastIndex(address, "@")
	if policy == nil || at <= 0 {
		return address, nil
	}
	if hosted, err := s.isHostedDomain(ctx, address[at+1:]); err != nil || !hosted {
		return address, err
	}
	recipient, err := policy.Recipient(address, bounce, time.Now())
	if err != nil {
		return "", fmt.Errorf("%w: %w", smtp.ErrBackscatter, err)
	}
	return recipient, nil
}

// relay delivers msg through adapter with its envelope sender signed for
// BATV when that applies. The queued message keeps its original sender.
func (s *server) relay(ctx context.Context, adapter *queue.RelayAdapter, msg *queue.Message) error {
	if signed := s.signReturnPath(ctx, msg.EnvelopeSender); signed != msg.EnvelopeSender {
		attempt := *msg
		attempt.EnvelopeSender = signed
		msg = &attempt
	}
	return adapter.Deliver(ctx, msg)
}

// resolveRecipient routes an envelope recipient through exact identities,
// aliases, subaddresses, and the domain catch-all. Every local-recipient
// lookup goes through it.
func (s *server) resolveRecipient(ctx context.Context, address string) (model.RecipientRoute, error) {
	address, err := s.rewriteRecipient(ctx, address)
	if err != nil {
		return model.RecipientRoute{}, err
	}
	return s.ts.ResolveRecipient(ctx, address, s.addressing().delimiters)
}

// recipientMailbox resolves a recipient to the one identity that receives
// it. Aliases, which have no single mailbox, are not found.
func (s *server) recipientMailbox(ctx context.Context, addr string) (model.EmailAddress, error) {
	route, err := s.resolveRecipient(ctx, addr)
	if err != nil {
		return model.EmailAddress{}, err
	}
	return route.Mailbox()
}

// resolveLocalAddress maps a recipient that resolves to one enabled identity
// to its owner's inbox, or to the folder a temporary alias delivers to. An
// inactive alias set to discard reports smtp.ErrRecipientDiscarded.
func (s *server) resolveLocalAddress(ctx context.Context, addr string) (string, string, error) {
	route, err := s.resolveRecipient(ctx, addr)
	if err != nil {
		return "", "", fmt.Errorf("address not found: %w", err)
	}
	if route.Discard {
		return "", "", smtp.ErrRecipientDiscarded
	}
	identity, err := route.Mailbox()
	if err != nil {
		return "", "", fmt.Errorf("address not found: %w", err)
	}
	if !identity.Enabled {
		return "", "", fmt.Errorf("address disabled")
	}
	return s.routeFolderID(ctx, identity.UserID, route.FolderPath), identity.UserID, nil
}

// startUserAliasCleanup retires long-expired temporary aliases into
// tombstones and releases tombstones whose reservation has ended.
func (s *server) startUserAliasCleanup() {
	ctx := s.ctx
	process := func() {
		tombstoned, purged, err := s.ts.UserAliasStore().Cleanup(ctx, time.Now())
		if err != nil {
			log.Error("clean up temporary aliases", "error", err)
			return
		}
		if tombstoned+purged > 0 {
			log.Info("temporary aliases cleaned up", "tombstoned", tombstoned, "released", purged)
		}
	}
	s.background.Every(time.Hour, true, process)
}

// routeFolderID returns the folder receiving a route: the owner's Inbox
// unless a temporary alias names an existing folder.
func (s *server) routeFolderID(ctx context.Context, userID, folderPath string) string {
	if folderPath != "" {
		if folder, err := s.ts.FolderStore().GetByPath(ctx, userID, folderPath); err == nil {
			return folder.ID
		}
	}
	return model.InboxFolderID(userID)
}

// expandRecipient reports the terminal identities of an alias recipient.
func (s *server) expandRecipient(ctx context.Context, addr string) ([]string, bool, error) {
	route, err := s.resolveRecipient(ctx, addr)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	return route.Targets, route.Targets != nil, nil
}
