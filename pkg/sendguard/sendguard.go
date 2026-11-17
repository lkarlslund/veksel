// Package sendguard protects outbound mail from abused accounts. Every
// locally originated submission (SMTP submission, webmail, JMAP, EWS, EAS,
// and scheduled send) reaches the durable queue as one admission batch, and
// the guard screens that batch: it enforces per-account sending limits and
// scores the account's recent behaviour for signs of compromise. When the
// score crosses the configured threshold the account's outbound mail is held
// in the queue until an administrator reviews and releases or purges it.
//
// Counters live in memory and restart empty; hold state is persisted on the
// account record so a held account stays held across restarts.
package sendguard

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/store"
)

var logger = log.For(log.ModuleQueue)

// HoldReason marks queue messages held by the guard. Release and purge only
// act on paused messages carrying it, never on operator holds.
const HoldReason = "Outbound mail held: suspected account compromise"

// DefaultCompromiseThreshold needs two independent heuristics to agree.
const DefaultCompromiseThreshold = 80

const (
	auditActor          = "system:sendguard"
	quotaAuditInterval  = 10 * time.Minute
	suspicionLifetime   = 24 * time.Hour
	healthComponentKind = "account"
	healthComponentID   = "outbound-hold:"
)

// Config is the live guard configuration.
type Config struct {
	Defaults Limits
	// CompromiseThreshold is the assessment score that trips the guard;
	// zero disables compromise detection.
	CompromiseThreshold float64
	// HoldEnabled holds a tripped account's outbound mail. When false a
	// tripped account only raises an alert.
	HoldEnabled bool
}

// Validate reports the first invalid value.
func (c Config) Validate() error {
	if c.CompromiseThreshold < 0 || c.CompromiseThreshold > 1000 {
		return errors.New("outbound compromise threshold must be between 0 and 1000")
	}
	for _, value := range []int{c.Defaults.MessagesPerHour, c.Defaults.RecipientsPerHour, c.Defaults.RecipientsPerDay} {
		if value < 0 || value > MaxLimit {
			return fmt.Errorf("outbound rate limits must be between 0 and %d", MaxLimit)
		}
	}
	return nil
}

// Queue is the part of the durable queue the guard manages held mail with.
type Queue interface {
	List(queue.Status) []*queue.Message
	HoldWithReason(id, reason string) bool
	Release(id string) bool
	Cancel(id string) bool
}

// ContentScorer scores one outbound message with outbound-appropriate spam
// rules and reports whether it reached the junk threshold.
type ContentScorer func(context.Context, *queue.Message) (score float64, spam bool)

// HoldNotifier tells the account owner that their outbound mail is held.
type HoldNotifier func(ctx context.Context, account string, hold model.OutboundHold)

type suspicion struct {
	at         time.Time
	assessment Assessment
}

// Guard screens submissions and manages compromise holds. It is safe for
// concurrent use.
type Guard struct {
	users   *model.UserStore
	domains *model.DomainStore
	audit   *audit.Logger
	now     func() time.Time

	mu        sync.Mutex
	cfg       Config
	queue     Queue
	scorer    ContentScorer
	notify    HoldNotifier
	accounts  map[string]*accountState
	held      map[string]model.OutboundHold
	suspected map[string]suspicion
	async     sync.WaitGroup
}

// New creates a guard and loads the accounts that are already held.
func New(ctx context.Context, ts *model.TypedStore, cfg Config) (*Guard, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	g := &Guard{users: ts.UserStore(), domains: ts.DomainStore(), audit: audit.New(ts), now: time.Now, cfg: cfg,
		accounts: make(map[string]*accountState), held: make(map[string]model.OutboundHold), suspected: make(map[string]suspicion)}
	users, err := g.users.List(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("load outbound holds: %w", err)
	}
	for _, user := range users {
		if user.OutboundHold != nil {
			g.held[user.ID] = cloneHold(*user.OutboundHold)
		}
	}
	return g, nil
}

// SetConfig applies a new configuration to subsequent submissions.
func (g *Guard) SetConfig(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	g.mu.Lock()
	g.cfg = cfg
	g.mu.Unlock()
	return nil
}

// Config returns the configuration in effect.
func (g *Guard) Config() Config {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cfg
}

// AttachQueue connects the queue whose held messages the guard manages.
func (g *Guard) AttachQueue(q Queue) { g.mu.Lock(); g.queue = q; g.mu.Unlock() }

// SetContentScorer installs the optional outbound content scorer.
func (g *Guard) SetContentScorer(scorer ContentScorer) { g.mu.Lock(); g.scorer = scorer; g.mu.Unlock() }

// SetHoldNotifier installs the account-owner notification sent on a hold.
func (g *Guard) SetHoldNotifier(notify HoldNotifier) { g.mu.Lock(); g.notify = notify; g.mu.Unlock() }

// submission identifies the account and distinct recipients of a batch. Only
// authenticated, non-derived messages count.
func submission(batch []*queue.Message) (account string, recipients, domains []string) {
	seenRecipients, seenDomains := make(map[string]bool), make(map[string]bool)
	for _, message := range batch {
		if message == nil || message.AuthenticatedActor == "" || message.Kind != "" || message.ParentID != "" {
			continue
		}
		actor := strings.ToLower(message.AuthenticatedActor)
		if account == "" {
			account = actor
		}
		if actor != account {
			continue
		}
		recipient := strings.ToLower(strings.TrimSpace(message.Recipient))
		if recipient == "" || seenRecipients[recipient] {
			continue
		}
		seenRecipients[recipient] = true
		recipients = append(recipients, recipient)
		if at := strings.LastIndex(recipient, "@"); at >= 0 && at < len(recipient)-1 && !seenDomains[recipient[at+1:]] {
			seenDomains[recipient[at+1:]] = true
			domains = append(domains, recipient[at+1:])
		}
	}
	return account, recipients, domains
}

// Screen implements queue.Config.Screen. It enforces the account's sending
// limits, scores the account, and holds the batch while the account is held.
func (g *Guard) Screen(ctx context.Context, batch []*queue.Message) (func(), error) {
	account, recipients, domains := submission(batch)
	if account == "" {
		return nil, nil
	}
	limits := g.accountDefaults(ctx, g.Config().Defaults, account)
	if user, err := g.users.Get(ctx, account); err == nil {
		limits = limits.Override(user.SendLimits)
	}
	spam := false
	g.mu.Lock()
	scorer, detecting := g.scorer, g.cfg.CompromiseThreshold > 0
	g.mu.Unlock()
	if scorer != nil && detecting {
		for _, message := range batch {
			if message != nil && message.Direction == queue.DirectionOutbound && message.Kind == "" {
				_, spam = scorer(ctx, message)
				break
			}
		}
	}
	now := g.now().UTC()
	g.mu.Lock()
	defer g.mu.Unlock()
	state := g.stateLocked(account, now)
	if quota := state.checkQuota(limits, len(recipients), now); quota != nil {
		if now.Sub(state.audited[quota.Limit]) >= quotaAuditInterval {
			state.audited[quota.Limit] = now
			g.audit.Log(auditActor, "mail.send_limit", account, map[string]string{
				"limit": quota.Limit, "max": strconv.Itoa(quota.Max), "recipients": strconv.Itoa(len(recipients)),
			})
		}
		logger.Info("sendguard: submission deferred by sending limit", "account", account, "limit", quota.Limit, "max", quota.Max)
		return nil, quota
	}
	undo := state.record(now, len(recipients), domains)
	if spam {
		state.recordSpam(now)
	}
	g.evaluateLocked(ctx, account, state, now)
	if _, held := g.held[account]; held && g.cfg.HoldEnabled {
		for _, message := range batch {
			if message != nil && message.Kind == "" && strings.EqualFold(message.AuthenticatedActor, account) {
				message.Status, message.HoldReason, message.HeldAt = queue.StatusPaused, HoldReason, now
				message.NextRetry, message.ReleasedAt = time.Time{}, time.Time{}
			}
		}
	}
	return func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		undo()
	}, nil
}

// RecordLogin feeds a successful login into the account's profile.
func (g *Guard) RecordLogin(ctx context.Context, account, ip string) {
	prefix := networkPrefix(ip)
	account = strings.ToLower(strings.TrimSpace(account))
	if prefix == "" || account == "" {
		return
	}
	now := g.now().UTC()
	g.mu.Lock()
	defer g.mu.Unlock()
	state := g.stateLocked(account, now)
	state.recordLogin(now, prefix)
	g.evaluateLocked(ctx, account, state, now)
}

// RecordOutcome feeds an outbound delivery result of a submitted message
// into its account's bounce rate. Temporary failures are not outcomes.
func (g *Guard) RecordOutcome(ctx context.Context, message queue.Message, status queue.Status) {
	if message.Direction != queue.DirectionOutbound || message.AuthenticatedActor == "" || message.Kind != "" || message.ParentID != "" {
		return
	}
	if status != queue.StatusDelivered && status != queue.StatusFailed {
		return
	}
	account := strings.ToLower(message.AuthenticatedActor)
	now := g.now().UTC()
	g.mu.Lock()
	defer g.mu.Unlock()
	state := g.stateLocked(account, now)
	state.recordOutcome(now, status == queue.StatusFailed)
	if status == queue.StatusFailed {
		g.evaluateLocked(ctx, account, state, now)
	}
}

func (g *Guard) stateLocked(account string, now time.Time) *accountState {
	state := g.accounts[account]
	if state == nil {
		state = newAccountState(now)
		g.accounts[account] = state
	}
	return state
}

// evaluateLocked trips the guard once when the account's score reaches the
// threshold. A held account is not re-evaluated until it is released.
func (g *Guard) evaluateLocked(ctx context.Context, account string, state *accountState, now time.Time) {
	if g.cfg.CompromiseThreshold <= 0 {
		return
	}
	if _, held := g.held[account]; held {
		return
	}
	assessment := state.assess(now, g.cfg.CompromiseThreshold)
	if assessment.Score < g.cfg.CompromiseThreshold {
		return
	}
	signals := make([]string, 0, len(assessment.Signals))
	for _, signal := range assessment.Signals {
		signals = append(signals, signal.Name)
	}
	details := map[string]string{"score": formatScore(assessment.Score), "threshold": formatScore(assessment.Threshold), "signals": strings.Join(signals, ",")}
	if !g.cfg.HoldEnabled {
		if previous, found := g.suspected[account]; !found || now.Sub(previous.at) >= suspicionLifetime {
			g.audit.Log(auditActor, "outbound.compromise_suspected", account, details)
			logger.Warn("sendguard: account shows signs of compromise; holding is disabled", "account", account, "score", assessment.Score, "signals", signals)
		}
		g.suspected[account] = suspicion{at: now, assessment: assessment}
		return
	}
	hold := model.OutboundHold{Since: now, Score: assessment.Score, Signals: signals}
	if err := g.users.Update(ctx, account, func(user *model.User) {
		copied := cloneHold(hold)
		user.OutboundHold = &copied
	}); err != nil && !errors.Is(err, store.ErrNotFound) {
		logger.Error("sendguard: persist outbound hold", "account", account, "error", err)
		return
	}
	g.held[account] = hold
	delete(g.suspected, account)
	g.audit.Log(auditActor, "outbound.hold", account, details)
	logger.Warn("sendguard: holding outbound mail of suspected compromised account", "account", account, "score", assessment.Score, "signals", signals)
	// The queue may be locked by the admission that tripped the guard, so
	// queued mail is held and the owner notified asynchronously.
	q, notify := g.queue, g.notify
	g.async.Add(1)
	go func() {
		defer g.async.Done()
		if q != nil {
			held := 0
			for _, message := range q.List("") {
				if strings.EqualFold(message.AuthenticatedActor, account) && message.Kind == "" && message.ParentID == "" &&
					(message.Status == queue.StatusPending || message.Status == queue.StatusRetrying || message.Status == queue.StatusHeld || message.Status == queue.StatusProcessing) &&
					q.HoldWithReason(message.ID, HoldReason) {
					held++
				}
			}
			if held > 0 {
				logger.Info("sendguard: held queued outbound mail", "account", account, "messages", held)
			}
		}
		if notify != nil {
			notify(context.WithoutCancel(ctx), account, cloneHold(hold))
		}
	}()
}

// DeliveryHold implements queue.Config.DeliveryHold: mail of a held account
// is paused when claimed for delivery instead of attempted. This backs up the
// hold placed on the account's queued mail when the guard trips.
func (g *Guard) DeliveryHold(message *queue.Message) string {
	if message.Kind != "" || message.ParentID != "" || message.AuthenticatedActor == "" {
		return ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, held := g.held[strings.ToLower(message.AuthenticatedActor)]; held && g.cfg.HoldEnabled {
		return HoldReason
	}
	return ""
}

// Wait blocks until asynchronous hold work has finished. Shutdown calls it
// before closing the queue and store the work uses.
func (g *Guard) Wait() { g.async.Wait() }

// HeldMessage is the metadata of one held queue message; content is never
// exposed.
type HeldMessage struct {
	ID             string    `json:"id"`
	EnvelopeSender string    `json:"envelope_sender"`
	Recipient      string    `json:"recipient"`
	Subject        string    `json:"subject,omitempty"`
	SizeBytes      int       `json:"size_bytes"`
	CreatedAt      time.Time `json:"created_at"`
	HeldAt         time.Time `json:"held_at"`
}

func (g *Guard) heldMessages(account string) []*queue.Message {
	g.mu.Lock()
	q := g.queue
	g.mu.Unlock()
	if q == nil {
		return nil
	}
	var result []*queue.Message
	for _, message := range q.List(queue.StatusPaused) {
		if strings.EqualFold(message.AuthenticatedActor, account) && message.HoldReason == HoldReason {
			result = append(result, message)
		}
	}
	return result
}

// HeldMessages lists the account's held messages, oldest first.
func (g *Guard) HeldMessages(account string) []HeldMessage {
	messages := g.heldMessages(account)
	result := make([]HeldMessage, 0, len(messages))
	for _, message := range messages {
		size := len(message.Content)
		if size == 0 {
			size = len(message.Body)
		}
		subject := ""
		for name, value := range message.Headers {
			if strings.EqualFold(name, "Subject") {
				subject = value
			}
		}
		result = append(result, HeldMessage{ID: message.ID, EnvelopeSender: message.EnvelopeSender, Recipient: message.Recipient,
			Subject: subject, SizeBytes: size, CreatedAt: message.CreatedAt, HeldAt: message.HeldAt})
	}
	slices.SortFunc(result, func(left, right HeldMessage) int { return left.CreatedAt.Compare(right.CreatedAt) })
	return result
}

// Release lifts the account's hold, resumes its held messages, and starts a
// clean evaluation window. It returns the number of messages resumed.
func (g *Guard) Release(ctx context.Context, actor, account string) (int, error) {
	account = strings.ToLower(strings.TrimSpace(account))
	if err := g.users.Update(ctx, account, func(user *model.User) { user.OutboundHold = nil }); err != nil {
		return 0, err
	}
	now := g.now().UTC()
	g.mu.Lock()
	delete(g.held, account)
	delete(g.suspected, account)
	g.stateLocked(account, now).releasedAt = now
	q := g.queue
	g.mu.Unlock()
	released := 0
	if q != nil {
		for _, message := range g.heldMessages(account) {
			if q.Release(message.ID) {
				released++
			}
		}
		// Withdraw holds still waiting for an in-progress attempt to end.
		for _, message := range q.List(queue.StatusProcessing) {
			if strings.EqualFold(message.AuthenticatedActor, account) && message.PendingHoldReason == HoldReason && q.Release(message.ID) {
				released++
			}
		}
	}
	g.audit.Log(actor, "outbound.release", account, map[string]string{"released_messages": strconv.Itoa(released)})
	return released, nil
}

// Purge cancels the account's held messages without lifting the hold.
func (g *Guard) Purge(ctx context.Context, actor, account string) (int, error) {
	account = strings.ToLower(strings.TrimSpace(account))
	if _, err := g.users.Get(ctx, account); err != nil {
		return 0, err
	}
	g.mu.Lock()
	q := g.queue
	g.mu.Unlock()
	purged := 0
	if q != nil {
		for _, message := range g.heldMessages(account) {
			if q.Cancel(message.ID) {
				purged++
			}
		}
	}
	g.audit.Log(actor, "outbound.purge", account, map[string]string{"purged_messages": strconv.Itoa(purged)})
	return purged, nil
}

// accountDefaults layers the default sending limits of the account's
// domain (by primary identity) over the server defaults. The account's own
// overrides apply on top of the result.
func (g *Guard) accountDefaults(ctx context.Context, defaults Limits, account string) Limits {
	domain, err := g.users.PrimaryDomain(ctx, account)
	if err != nil || domain == "" {
		return defaults
	}
	record, err := g.domains.Get(ctx, domain)
	if err != nil {
		return defaults
	}
	return defaults.Override(record.Limits.DefaultSendLimits)
}

// AccountDefaults reports the limits an account inherits before its own
// overrides: the server defaults with its domain's defaults applied.
func (g *Guard) AccountDefaults(ctx context.Context, account string) Limits {
	return g.accountDefaults(ctx, g.Config().Defaults, strings.ToLower(strings.TrimSpace(account)))
}

// SetLimits replaces the account's limit overrides; nil restores defaults.
func (g *Guard) SetLimits(ctx context.Context, actor, account string, limits *model.SendLimits) error {
	if err := ValidateOverride(limits); err != nil {
		return err
	}
	if limits != nil && limits.MessagesPerHour == nil && limits.RecipientsPerHour == nil && limits.RecipientsPerDay == nil {
		limits = nil
	}
	if err := g.users.Update(ctx, account, func(user *model.User) { user.SendLimits = limits }); err != nil {
		return err
	}
	var override model.SendLimits
	if limits != nil {
		override = *limits
	}
	details := map[string]string{}
	for name, value := range map[string]*int{LimitMessagesPerHour: override.MessagesPerHour, LimitRecipientsPerHour: override.RecipientsPerHour, LimitRecipientsPerDay: override.RecipientsPerDay} {
		details[name] = "default"
		if value != nil {
			details[name] = strconv.Itoa(*value)
		}
	}
	g.audit.Log(actor, "account.send_limits", account, details)
	return nil
}

// AccountStatus is the administrative view of one account's sending state.
type AccountStatus struct {
	Account      string              `json:"account"`
	Defaults     Limits              `json:"defaults"`
	Override     *model.SendLimits   `json:"override,omitempty"`
	Effective    Limits              `json:"effective"`
	Usage        Usage               `json:"usage"`
	Assessment   Assessment          `json:"assessment"`
	Hold         *model.OutboundHold `json:"hold,omitempty"`
	Suspected    bool                `json:"suspected"`
	HoldEnabled  bool                `json:"hold_enabled"`
	HeldMessages []HeldMessage       `json:"held_messages"`
}

// Status reports an account's limits, usage, score, and hold.
func (g *Guard) Status(ctx context.Context, account string) (AccountStatus, error) {
	account = strings.ToLower(strings.TrimSpace(account))
	user, err := g.users.Get(ctx, account)
	if err != nil {
		return AccountStatus{}, err
	}
	now := g.now().UTC()
	defaults := g.accountDefaults(ctx, g.Config().Defaults, account)
	g.mu.Lock()
	status := AccountStatus{Account: account, Defaults: defaults, Override: user.SendLimits, HoldEnabled: g.cfg.HoldEnabled,
		Effective: defaults.Override(user.SendLimits), Assessment: Assessment{Threshold: g.cfg.CompromiseThreshold, Signals: []Signal{}}}
	if state := g.accounts[account]; state != nil {
		status.Usage = state.usage(now)
		status.Assessment = state.assess(now, g.cfg.CompromiseThreshold)
		if status.Assessment.Signals == nil {
			status.Assessment.Signals = []Signal{}
		}
	}
	if previous, found := g.suspected[account]; found && now.Sub(previous.at) < suspicionLifetime {
		status.Suspected = true
	}
	g.mu.Unlock()
	if user.OutboundHold != nil {
		hold := cloneHold(*user.OutboundHold)
		status.Hold = &hold
	}
	status.HeldMessages = g.HeldMessages(account)
	return status, nil
}

// HeldAccount summarizes one held or suspected account.
type HeldAccount struct {
	Account      string    `json:"account"`
	Held         bool      `json:"held"`
	Since        time.Time `json:"since"`
	Score        float64   `json:"score"`
	Signals      []string  `json:"signals"`
	HeldMessages int       `json:"held_messages"`
}

// HeldAccounts lists held accounts, then accounts that tripped while holding
// was disabled, newest first.
func (g *Guard) HeldAccounts() []HeldAccount {
	now := g.now().UTC()
	g.mu.Lock()
	result := make([]HeldAccount, 0, len(g.held)+len(g.suspected))
	for account, hold := range g.held {
		result = append(result, HeldAccount{Account: account, Held: true, Since: hold.Since, Score: hold.Score, Signals: slices.Clone(hold.Signals)})
	}
	for account, suspected := range g.suspected {
		if now.Sub(suspected.at) >= suspicionLifetime {
			continue
		}
		signals := make([]string, 0, len(suspected.assessment.Signals))
		for _, signal := range suspected.assessment.Signals {
			signals = append(signals, signal.Name)
		}
		result = append(result, HeldAccount{Account: account, Since: suspected.at, Score: suspected.assessment.Score, Signals: signals})
	}
	g.mu.Unlock()
	for index := range result {
		if result[index].Held {
			result[index].HeldMessages = len(g.heldMessages(result[index].Account))
		}
	}
	slices.SortFunc(result, func(left, right HeldAccount) int {
		if left.Held != right.Held {
			if left.Held {
				return -1
			}
			return 1
		}
		return right.Since.Compare(left.Since)
	})
	return result
}

// Observations reports one health component per held or suspected account,
// so the alert lifecycle raises exactly one alert per account and resolves
// it when the account is released.
func (g *Guard) Observations() []health.Observation {
	accounts := g.HeldAccounts()
	observations := make([]health.Observation, 0, len(accounts))
	for _, account := range accounts {
		observation := health.Observation{ID: healthComponentID + account.Account, Kind: healthComponentKind, Desired: true,
			State: health.StateDegraded, Details: map[string]string{
				"account": account.Account, "since": account.Since.Format(time.RFC3339),
				"score": formatScore(account.Score), "signals": strings.Join(account.Signals, ", "),
			}}
		if account.Held {
			observation.Label = "Outbound mail held: " + account.Account
			observation.Severity = health.SeverityCritical
			observation.Reason = fmt.Sprintf("Suspected compromise (score %s: %s); %d message(s) held until an administrator releases the account",
				formatScore(account.Score), strings.Join(account.Signals, ", "), account.HeldMessages)
			observation.Details["held_messages"] = strconv.Itoa(account.HeldMessages)
		} else {
			observation.Label = "Suspected compromised account: " + account.Account
			observation.Severity = health.SeverityWarning
			observation.Reason = fmt.Sprintf("Suspected compromise (score %s: %s); outbound holding is disabled", formatScore(account.Score), strings.Join(account.Signals, ", "))
		}
		observations = append(observations, observation)
	}
	return observations
}

func cloneHold(hold model.OutboundHold) model.OutboundHold {
	hold.Signals = slices.Clone(hold.Signals)
	return hold
}

func formatScore(score float64) string { return strconv.FormatFloat(score, 'f', -1, 64) }
