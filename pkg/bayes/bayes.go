// Package bayes trains and applies Veksel' built-in statistical spam
// classifier. Every account has its own model, kept in a namespace of the
// account's index so it moves, converts, and exports with the account, and
// an optional shared model in the system store learns from every user's
// explicit actions. Models train when a user moves a message into Junk
// (spam) or out of Junk to anything but Trash (ham), through any protocol,
// and optionally from confidently scored deliveries. Each trained message
// is recorded by its sample key, so moving it back retrains it rather than
// counting it twice. A model scores nothing until it has learned a minimum
// number of messages of each class.
package bayes

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/store"
)

var logger = log.For(log.ModuleContentScan)

const (
	// Namespace holds an account's model in its index store.
	Namespace = "bayes"
	// GlobalNamespace holds the shared model in the system store.
	GlobalNamespace = "bayes_global"
	// DefaultMinLearns is the number of spam and of ham messages a model
	// must learn before it scores.
	DefaultMinLearns = 200
	// DefaultMaxTokens caps the tokens one model keeps.
	DefaultMaxTokens = 500_000
	// DefaultMaxRecords caps the per-message training records one account
	// keeps for retraining corrections.
	DefaultMaxRecords = 20_000
	// MaxMinLearns bounds the configurable minimum.
	MaxMinLearns = 100_000
	queueSize    = 1024
	// autolearnHamScore is the highest pre-classifier score auto-learning
	// treats as ham, and only for a trusted, authenticated sender.
	autolearnHamScore = 1.0
	modelUser         = "user"
	modelGlobal       = "global"
)

// Settings are the live classifier settings.
type Settings struct {
	Enabled bool
	// MinLearns is the spam and ham count a model needs before it scores.
	MinLearns int
	// Autolearn trains from deliveries scored at confident extremes.
	Autolearn bool
	// Global trains the shared model from explicit actions and scores with
	// it, including at the transaction stage, when an account's own model
	// is not ready.
	Global bool
	// MaxTokens and MaxRecords default to DefaultMaxTokens and
	// DefaultMaxRecords.
	MaxTokens  int
	MaxRecords int
}

// Accounts opens one account's index store for the duration of fn.
type Accounts interface {
	WithIndex(ctx context.Context, userID string, fn func(context.Context, store.Store) error) error
}

// Symbols turns a probability into a scored symbol with the spam engine's
// overrides; false while scoring is disabled. spam.Switch implements it.
type Symbols interface {
	BayesSymbol(probability float64, model string) (spam.Symbol, bool)
}

// Feedback learns from the same explicit Junk and Not-junk moves that train
// the models, given the moved message and its headers. spam.MoveFeedback
// implements it.
type Feedback interface {
	Moved(raw []byte, headers map[string]string, junk bool)
}

// Config wires the classifier to its storage and the folder space it
// observes.
type Config struct {
	// Space reads the folders and source items of observed moves.
	Space    service.FolderSpace
	Accounts Accounts
	// Global stores the shared model; nil disables it.
	Global  store.Store
	Symbols Symbols
	// Feedback optionally receives every user Junk and Not-junk move,
	// whether or not the classifier itself is enabled.
	Feedback Feedback
}

// Stats describe one model.
type Stats struct {
	Enabled   bool       `json:"enabled"`
	Ready     bool       `json:"ready"`
	Spam      uint32     `json:"spam"`
	Ham       uint32     `json:"ham"`
	MinLearns int        `json:"min_learns"`
	Tokens    int        `json:"tokens"`
	Records   int        `json:"records"`
	Updated   *time.Time `json:"updated,omitzero"`
}

// Status is the administrator's view: settings, the shared model, and the
// training counters since startup.
type Status struct {
	Enabled     bool   `json:"enabled"`
	Autolearn   bool   `json:"autolearn"`
	Global      bool   `json:"global"`
	MinLearns   int    `json:"min_learns"`
	GlobalModel Stats  `json:"global_model"`
	LearnedSpam uint64 `json:"learned_spam"`
	LearnedHam  uint64 `json:"learned_ham"`
	Autolearned uint64 `json:"autolearned"`
	Dropped     uint64 `json:"dropped"`
	Queued      int    `json:"queued"`
}

type job struct {
	userID string
	data   []byte // raw message, tokenized by the worker; else sample
	sample spam.Sample
	class  Class
	source Source
}

// Service is the classifier. Training runs on one background worker so
// protocol moves never wait for it; Classify reads models directly.
type Service struct {
	cfg      Config
	settings atomic.Pointer[Settings]
	jobs     chan job
	pending  sync.WaitGroup
	pruning  sync.Map   // models with a scheduled pruning pass
	pruneMu  sync.Mutex // serializes pruning passes
	stop     chan struct{}
	done     chan struct{}
	close    sync.Once
	// background tracks pruning passes; ctx ends them on Close.
	background sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc

	learnedSpam, learnedHam, autolearned, dropped atomic.Uint64
}

// New starts a classifier with settings.
func New(cfg Config, settings Settings) (*Service, error) {
	if cfg.Space == nil || cfg.Accounts == nil || cfg.Symbols == nil {
		return nil, errors.New("classifier requires a folder space, account storage, and symbols")
	}
	s := &Service{cfg: cfg, jobs: make(chan job, queueSize), stop: make(chan struct{}), done: make(chan struct{})}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.SetSettings(settings)
	go s.work()
	return s, nil
}

// Close stops training and pruning; queued messages are dropped.
func (s *Service) Close() {
	s.close.Do(func() {
		close(s.stop)
		s.cancel()
		<-s.done
		s.background.Wait()
	})
}

// SetSettings applies settings to subsequent training and scoring.
func (s *Service) SetSettings(settings Settings) {
	if settings.MinLearns <= 0 {
		settings.MinLearns = DefaultMinLearns
	}
	if settings.MaxTokens <= 0 {
		settings.MaxTokens = DefaultMaxTokens
	}
	if settings.MaxRecords <= 0 {
		settings.MaxRecords = DefaultMaxRecords
	}
	s.settings.Store(&settings)
}

// Settings returns the current settings.
func (s *Service) Settings() Settings { return *s.settings.Load() }

// Wait blocks until every queued training job has finished.
func (s *Service) Wait() { s.pending.Wait() }

func (s *Service) work() {
	defer close(s.done)
	for {
		select {
		case <-s.stop:
			for {
				select {
				case <-s.jobs:
					s.pending.Done()
				default:
					return
				}
			}
		case j := <-s.jobs:
			if err := s.learn(s.ctx, j); err != nil {
				logger.Warn("spam classifier: training failed", "user", j.userID, "class", j.class, "error", err)
			}
			s.pending.Done()
		}
	}
}

func (s *Service) enqueue(j job) {
	s.pending.Add(1)
	select {
	case s.jobs <- j:
	default:
		s.pending.Done()
		s.dropped.Add(1)
		logger.Warn("spam classifier: training queue full; message not learned", "user", j.userID, "class", j.class)
	}
}

// Train queues an explicit training of raw as class for userID.
func (s *Service) Train(userID string, raw []byte, class Class) {
	if s.Settings().Enabled && userID != "" {
		s.enqueue(job{userID: userID, data: raw, class: class, source: SourceUser})
	}
}

// learn trains one message into the account model and, for explicit
// actions with the shared model enabled, the shared model.
func (s *Service) learn(ctx context.Context, j job) error {
	sample := j.sample
	if j.data != nil {
		sample = spam.NewSample(j.data)
	}
	if len(sample.Tokens) == 0 {
		return nil
	}
	settings := s.Settings()
	var previous record
	var found, changed, prune bool
	trained := record{Class: j.class, Source: j.source, Global: settings.Global && s.cfg.Global != nil && j.source == SourceUser, Day: today()}
	err := s.cfg.Accounts.WithIndex(ctx, j.userID, func(ctx context.Context, index store.Store) error {
		account := tokenModel{store: index, namespace: Namespace}
		if err := account.ensure(ctx); err != nil {
			return err
		}
		return store.Batch(ctx, index, func(batchCtx context.Context) error {
			var err error
			if previous, found, err = account.record(batchCtx, sample.Key); err != nil {
				return err
			}
			switch {
			case found && previous.Class == j.class:
				if j.source == SourceUser && previous.Source == SourceAuto {
					previous.Source = SourceUser
					return account.setJSON(batchCtx, recordPrefix+sample.Key, previous)
				}
				return nil
			case found && j.source == SourceAuto:
				return nil
			}
			current, err := account.meta(batchCtx)
			if err != nil {
				return err
			}
			if found {
				if err := account.train(batchCtx, &current, sample.Tokens, previous.Class, -1); err != nil {
					return err
				}
			} else {
				current.Records++
			}
			if err := account.train(batchCtx, &current, sample.Tokens, j.class, 1); err != nil {
				return err
			}
			if err := account.setJSON(batchCtx, metaKey, current); err != nil {
				return err
			}
			changed = true
			prune = current.Tokens > settings.MaxTokens || current.Records > settings.MaxRecords
			return account.setJSON(batchCtx, recordPrefix+sample.Key, trained)
		})
	})
	if err != nil || !changed {
		return err
	}
	s.count(j)
	if prune {
		s.schedulePrune(j.userID)
	}
	var globalPrevious, globalClass Class
	if found && previous.Global {
		globalPrevious = previous.Class
	}
	if trained.Global {
		globalClass = j.class
	}
	if s.cfg.Global == nil || globalPrevious == globalClass {
		return nil
	}
	global := tokenModel{store: s.cfg.Global, namespace: GlobalNamespace}
	if err := global.ensure(ctx); err != nil {
		return err
	}
	if err := global.apply(ctx, sample.Tokens, globalPrevious, globalClass); err != nil {
		return err
	}
	if current, err := global.meta(ctx); err == nil && current.Tokens > settings.MaxTokens {
		s.schedulePrune("")
	}
	return nil
}

func (s *Service) count(j job) {
	switch {
	case j.source == SourceAuto:
		s.autolearned.Add(1)
	case j.class == ClassSpam:
		s.learnedSpam.Add(1)
	default:
		s.learnedHam.Add(1)
	}
}

// schedulePrune shrinks an over-cap model in the background; "" names the
// shared model. It is called only by the training worker, so Close never
// waits for a pass that has not been added yet.
func (s *Service) schedulePrune(userID string) {
	if _, running := s.pruning.LoadOrStore(userID, true); running {
		return
	}
	s.background.Add(1)
	go func() {
		defer s.background.Done()
		defer s.pruning.Delete(userID)
		if err := s.Prune(s.ctx, userID); err != nil && s.ctx.Err() == nil {
			logger.Warn("spam classifier: pruning failed", "user", userID, "error", err)
		}
	}()
}

// Prune removes the least valuable tokens and oldest training records
// beyond the caps of userID's model, or of the shared model for "".
func (s *Service) Prune(ctx context.Context, userID string) error {
	s.pruneMu.Lock()
	defer s.pruneMu.Unlock()
	settings := s.Settings()
	run := func(ctx context.Context, m tokenModel) error {
		tokens, records, err := m.prune(ctx, settings.MaxTokens, settings.MaxRecords)
		if tokens+records > 0 {
			logger.Info("spam classifier: pruned model", "user", userID, "terms", tokens, "records", records)
		}
		return err
	}
	if userID == "" {
		if s.cfg.Global == nil {
			return nil
		}
		return run(ctx, tokenModel{store: s.cfg.Global, namespace: GlobalNamespace})
	}
	return s.cfg.Accounts.WithIndex(ctx, userID, func(ctx context.Context, index store.Store) error {
		return run(ctx, tokenModel{store: index, namespace: Namespace})
	})
}

// Classify returns the classifier symbol for tokens: from userID's own
// model when it is ready, else from the shared model when enabled and
// ready. An empty userID consults only the shared model, which is what
// the SMTP transaction stage does. It returns false when no model scores.
func (s *Service) Classify(ctx context.Context, userID string, tokens []string) (spam.Symbol, bool) {
	settings := s.Settings()
	if !settings.Enabled || len(tokens) == 0 {
		return spam.Symbol{}, false
	}
	if userID != "" {
		var probability float64
		var ready bool
		err := s.cfg.Accounts.WithIndex(ctx, userID, func(ctx context.Context, index store.Store) error {
			var err error
			probability, ready, err = classify(ctx, tokenModel{store: index, namespace: Namespace}, tokens, settings.MinLearns)
			return err
		})
		if err != nil {
			logger.Warn("spam classifier: account model unavailable", "user", userID, "error", err)
		}
		if ready {
			return s.cfg.Symbols.BayesSymbol(probability, modelUser)
		}
	}
	if !settings.Global || s.cfg.Global == nil {
		return spam.Symbol{}, false
	}
	probability, ready, err := classify(ctx, tokenModel{store: s.cfg.Global, namespace: GlobalNamespace}, tokens, settings.MinLearns)
	if err != nil {
		logger.Warn("spam classifier: shared model unavailable", "error", err)
	}
	if !ready {
		return spam.Symbol{}, false
	}
	return s.cfg.Symbols.BayesSymbol(probability, modelGlobal)
}

func classify(ctx context.Context, m tokenModel, tokens []string, minLearns int) (float64, bool, error) {
	current, err := m.meta(ctx)
	if err != nil || !ready(current, minLearns) {
		return 0, false, err
	}
	counts, err := m.counts(ctx, tokens)
	if err != nil {
		return 0, false, err
	}
	return spam.Probability(counts, current.Spam, current.Ham), true, nil
}

func ready(current meta, minLearns int) bool {
	return int(current.Spam) >= minLearns && int(current.Ham) >= minLearns
}

// Autolearn trains userID's model from a delivered message whose score,
// without classifier symbols, is confidently spam (halfway from the Junk
// to the reject threshold, or twice the Junk threshold without one), or
// confidently ham (at most autolearnHamScore from a trustedSender). It
// never overrides an explicit action and never trains the shared model.
func (s *Service) Autolearn(_ context.Context, userID string, sample spam.Sample, result spam.Result, trustedSender bool) {
	settings := s.Settings()
	if !settings.Enabled || !settings.Autolearn || userID == "" || len(sample.Tokens) == 0 {
		return
	}
	score, thresholds := result.ScoreWithoutBayes(), result.Thresholds
	spamScore := 2 * thresholds.Junk
	if thresholds.Reject > 0 {
		spamScore = (thresholds.Junk + thresholds.Reject) / 2
	}
	var class Class
	switch {
	case score >= spamScore:
		class = ClassSpam
	case score <= autolearnHamScore && trustedSender:
		class = ClassHam
	default:
		return
	}
	s.enqueue(job{userID: userID, sample: sample, class: class, source: SourceAuto})
}

// ItemWritten implements rules.ItemObserver; writes do not train.
func (s *Service) ItemWritten(context.Context, service.AccessContext, model.Item) {}

// ItemRemoved implements rules.ItemObserver; removals do not train.
func (s *Service) ItemRemoved(context.Context, service.AccessContext, string) {}

// ItemMoving implements rules.ItemMoveObserver: a user's move or copy into
// Junk trains spam and one out of Junk to anything but Trash trains ham,
// for the destination folder's owner, and reaches the configured Feedback.
// Server-internal flows never train.
func (s *Service) ItemMoving(ctx context.Context, access service.AccessContext, itemID, destinationFolderID string, _ bool) func(context.Context, model.Item) {
	enabled := s.Settings().Enabled
	if !enabled && s.cfg.Feedback == nil || access.Actor.Kind != model.PrincipalUser || strings.HasPrefix(access.Protocol, "system") || strings.HasPrefix(access.Protocol, "smtp") {
		return nil
	}
	destination, err := s.cfg.Space.GetFolder(ctx, access, destinationFolderID)
	if err != nil || destination.Type != model.FolderTypeMail || destination.SpecialUse == model.SpecialUseTrash {
		return nil
	}
	item, err := s.cfg.Space.GetItem(ctx, access, itemID)
	if err != nil || item.FolderID == destinationFolderID {
		return nil
	}
	source, err := s.cfg.Space.GetFolder(ctx, access, item.FolderID)
	if err != nil {
		return nil
	}
	var class Class
	switch {
	case destination.SpecialUse == model.SpecialUseJunk && source.SpecialUse != model.SpecialUseJunk:
		class = ClassSpam
	case source.SpecialUse == model.SpecialUseJunk && destination.SpecialUse != model.SpecialUseJunk:
		class = ClassHam
	default:
		return nil
	}
	owner, data, headers := destination.UserID, item.Data, item.Headers
	return func(context.Context, model.Item) {
		if enabled {
			s.Train(owner, data, class)
		}
		if s.cfg.Feedback != nil {
			s.cfg.Feedback.Moved(data, headers, class == ClassSpam)
		}
	}
}

// Stats describes userID's model.
func (s *Service) Stats(ctx context.Context, userID string) (Stats, error) {
	var stats Stats
	err := s.cfg.Accounts.WithIndex(ctx, userID, func(ctx context.Context, index store.Store) error {
		var err error
		stats, err = s.stats(ctx, tokenModel{store: index, namespace: Namespace})
		return err
	})
	return stats, err
}

func (s *Service) stats(ctx context.Context, m tokenModel) (Stats, error) {
	settings := s.Settings()
	current, err := m.meta(ctx)
	if err != nil {
		return Stats{}, err
	}
	stats := Stats{
		Enabled: settings.Enabled, Ready: ready(current, settings.MinLearns), Spam: current.Spam, Ham: current.Ham,
		MinLearns: settings.MinLearns, Tokens: current.Tokens, Records: current.Records,
	}
	if current.Updated > 0 {
		updated := time.Unix(current.Updated, 0).UTC()
		stats.Updated = &updated
	}
	return stats, nil
}

// Reset forgets userID's model.
func (s *Service) Reset(ctx context.Context, userID string) error {
	return s.cfg.Accounts.WithIndex(ctx, userID, func(ctx context.Context, index store.Store) error {
		return tokenModel{store: index, namespace: Namespace}.reset(ctx)
	})
}

// ResetGlobal forgets the shared model.
func (s *Service) ResetGlobal(ctx context.Context) error {
	if s.cfg.Global == nil {
		return nil
	}
	return tokenModel{store: s.cfg.Global, namespace: GlobalNamespace}.reset(ctx)
}

// Status reports settings, the shared model, and training counters.
func (s *Service) Status(ctx context.Context) (Status, error) {
	settings := s.Settings()
	status := Status{
		Enabled: settings.Enabled, Autolearn: settings.Autolearn, Global: settings.Global, MinLearns: settings.MinLearns,
		LearnedSpam: s.learnedSpam.Load(), LearnedHam: s.learnedHam.Load(), Autolearned: s.autolearned.Load(),
		Dropped: s.dropped.Load(), Queued: len(s.jobs),
	}
	if s.cfg.Global == nil {
		return status, nil
	}
	var err error
	status.GlobalModel, err = s.stats(ctx, tokenModel{store: s.cfg.Global, namespace: GlobalNamespace})
	return status, err
}
