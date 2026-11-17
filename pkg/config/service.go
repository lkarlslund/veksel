package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/lkarlslund/veksel/pkg/attachment"
	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/pelletier/go-toml/v2"
)

const configFileName = "config.toml"
const previousConfigFileName = "config.previous.toml"

var ErrRevisionConflict = errors.New("configuration revision conflict")

// FilePath returns the managed configuration file inside dataDir.
func FilePath(dataDir string) string {
	return filepath.Join(filepath.Clean(dataDir), configFileName)
}

// Path returns the managed configuration file.
func (s *Service) Path() string { return s.path }

// Parse decodes and validates a configuration document as it would be loaded
// from dataDir, without touching the filesystem.
func Parse(dataDir string, contents []byte) (*Config, error) {
	s := &Service{dataDir: filepath.Clean(dataDir), path: FilePath(dataDir), schema: buildSchema()}
	return s.decode(contents)
}

// SettingSpec describes a public configuration value for API and UI clients.
// The file remains authoritative; this schema is presentation and validation
// metadata, not a second configuration source.
type SettingSpec struct {
	Key             string `json:"key"`
	Type            string `json:"type"`
	Category        string `json:"category"`
	Level           string `json:"level"`
	RestartRequired bool   `json:"restart_required"`
	Sensitive       bool   `json:"sensitive"`
	Description     string `json:"description"`
}

// Snapshot is an immutable view of desired configuration.
type Snapshot struct {
	Config   *Config       `json:"config"`
	Revision string        `json:"revision"`
	Schema   []SettingSpec `json:"schema,omitempty"`
}

// Service owns data/config.toml and serializes all changes to it.
type Service struct {
	mu         sync.RWMutex
	dataDir    string
	path       string
	historyDir string
	desired    *Config
	effective  map[string]any
	apply      map[string]applyEvidence
	revision   string
	schema     []SettingSpec
	appliers   []applierGroup
}

// Open loads the managed configuration, creating a documented default file
// when this is a new installation.
func Open(dataDir string) (*Service, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("data directory is required")
	}
	dataDir = filepath.Clean(dataDir)
	if info, err := os.Lstat(dataDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("data directory cannot be a symlink")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	s := &Service{
		dataDir: dataDir, path: filepath.Join(dataDir, configFileName),
		historyDir: filepath.Join(dataDir, configHistoryDirName), schema: buildSchema(),
		apply: make(map[string]applyEvidence),
	}
	if info, err := os.Lstat(s.historyDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("configuration history directory cannot be a symlink")
	}
	if err := os.MkdirAll(s.historyDir, 0o700); err != nil {
		return nil, fmt.Errorf("create configuration history: %w", err)
	}
	if info, err := os.Lstat(s.path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("configuration file cannot be a symlink")
	}
	contents, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		contents, err = defaultDocument(DefaultAt(dataDir))
		if err == nil {
			err = atomicWrite(s.path, contents, 0o600)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("open configuration: %w", err)
	}
	if err := s.load(contents); err != nil {
		return nil, err
	}
	history, err := s.historyLocked(1)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		if _, err := s.prepareRevision(nil, contents, nil, s.desired, MutationMetadata{Source: "initial"}); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func defaultDocument(cfg *Config) ([]byte, error) {
	body, err := toml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("encode default configuration: %w", err)
	}
	header := "# Veksel configuration. Managed through the administration API and UI.\n" +
		"# Comments and ordering are preserved when individual settings change.\n\n"
	return append([]byte(header), body...), nil
}

func (s *Service) load(contents []byte) error {
	cfg, err := s.decode(contents)
	if err != nil {
		return err
	}
	s.desired = clone(cfg)
	s.effective = publicConfigValues(cfg)
	s.revision = revision(contents)
	return nil
}

func (s *Service) decode(contents []byte) (*Config, error) {
	cfg := DefaultAt(s.dataDir)
	var document map[string]any
	if err := toml.Unmarshal(contents, &document); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path, err)
	}
	_, hasHTTPListeners := document["http_listeners"]
	if !hasHTTPListeners {
		cfg.HTTPListeners = nil
	}
	if err := toml.Unmarshal(contents, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path, err)
	}
	if !hasHTTPListeners {
		cfg.HTTPListeners = migratedHTTPListeners(cfg)
	}
	derive(cfg, s.dataDir)
	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("validate %s: %w", s.path, err)
	}
	return cfg, nil
}

// Current returns a detached snapshot safe for a caller to retain.
func (s *Service) Current() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Snapshot{Config: clone(s.desired), Revision: s.revision, Schema: slices.Clone(s.schema)}
}

// Reload reads changes made outside Veksel and validates them before publish.
func (s *Service) Reload() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	contents, err := os.ReadFile(s.path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read configuration: %w", err)
	}
	candidate, err := s.decode(contents)
	if err != nil {
		return Snapshot{}, err
	}
	if revision(contents) != s.revision {
		previousContents, readErr := os.ReadFile(s.historySnapshotPath(s.revision))
		if readErr != nil {
			return Snapshot{}, fmt.Errorf("read current configuration history: %w", readErr)
		}
		if _, err := s.prepareRevision(previousContents, contents, s.desired, candidate, MutationMetadata{Source: "reload"}); err != nil {
			return Snapshot{}, err
		}
	}
	s.desired = clone(candidate)
	s.revision = revision(contents)
	if err := s.pruneHistoryLocked(); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Config: clone(s.desired), Revision: s.revision, Schema: slices.Clone(s.schema)}, nil
}

// Patch applies exact top-level keys to the existing TOML syntax tree. A
// revision is mandatory so two administrators cannot silently overwrite each
// other. No partial write is published when validation fails.
func (s *Service) Patch(expectedRevision string, changes map[string]any) (Snapshot, error) {
	return s.PatchWithMetadata(expectedRevision, changes, MutationMetadata{Source: "patch"})
}

func (s *Service) PatchWithMetadata(expectedRevision string, changes map[string]any, metadata MutationMetadata) (Snapshot, error) {
	snapshot, _, err := s.PatchWithPlan(expectedRevision, changes, metadata)
	return snapshot, err
}

// PatchWithPlan validates and publishes the exact prepared candidate while
// holding the same revision lock. The returned plan is therefore the plan that
// actually committed, not a second reconstruction after the write.
func (s *Service) PatchWithPlan(expectedRevision string, changes map[string]any, metadata MutationMetadata) (Snapshot, ChangePlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prepared, err := s.preparePatchLocked(expectedRevision, changes)
	if err != nil {
		return Snapshot{}, ChangePlan{}, err
	}
	if len(prepared.Changes) == 0 {
		return Snapshot{Config: clone(s.desired), Revision: s.revision, Schema: slices.Clone(s.schema)}, prepared.ChangePlan, nil
	}
	contents, next, candidate := prepared.previous, prepared.contents, prepared.candidate
	if err := atomicWrite(filepath.Join(s.dataDir, previousConfigFileName), contents, 0o600); err != nil {
		return Snapshot{}, ChangePlan{}, fmt.Errorf("save previous configuration: %w", err)
	}
	if _, err := s.prepareRevision(contents, next, s.desired, candidate, metadata); err != nil {
		return Snapshot{}, ChangePlan{}, err
	}
	if err := s.pruneHistoryLocked(); err != nil {
		return Snapshot{}, ChangePlan{}, fmt.Errorf("prune configuration history: %w", err)
	}
	if err := atomicWrite(s.path, next, 0o600); err != nil {
		return Snapshot{}, ChangePlan{}, err
	}
	s.desired = clone(candidate)
	s.revision = revision(next)
	return Snapshot{Config: clone(candidate), Revision: s.revision, Schema: slices.Clone(s.schema)}, prepared.ChangePlan, nil
}

// ValidatePatch applies a proposed patch in memory and returns the resulting
// snapshot without changing either configuration file.
func (s *Service) ValidatePatch(expectedRevision string, changes map[string]any) (Snapshot, error) {
	snapshot, _, err := s.PreviewPatch(expectedRevision, changes)
	return snapshot, err
}

// RecoverPrevious atomically restores the last configuration replaced by a
// successful patch. The displaced current revision becomes the new recovery
// file, making the operation reversible.
func (s *Service) RecoverPrevious(expectedRevision string) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expectedRevision == "" || expectedRevision != s.revision {
		return Snapshot{}, ErrRevisionConflict
	}
	previousPath := filepath.Join(s.dataDir, previousConfigFileName)
	previous, err := os.ReadFile(previousPath)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read previous configuration: %w", err)
	}
	candidate := DefaultAt(s.dataDir)
	if err := toml.Unmarshal(previous, candidate); err != nil {
		return Snapshot{}, fmt.Errorf("parse previous configuration: %w", err)
	}
	derive(candidate, s.dataDir)
	if err := Validate(candidate); err != nil {
		return Snapshot{}, fmt.Errorf("validate previous configuration: %w", err)
	}
	current, err := os.ReadFile(s.path)
	if err != nil {
		return Snapshot{}, err
	}
	if err := atomicWrite(previousPath, current, 0o600); err != nil {
		return Snapshot{}, err
	}
	if _, err := s.prepareRevision(current, previous, s.desired, candidate, MutationMetadata{Source: "recover"}); err != nil {
		return Snapshot{}, err
	}
	if err := s.pruneHistoryLocked(); err != nil {
		return Snapshot{}, err
	}
	if err := atomicWrite(s.path, previous, 0o600); err != nil {
		return Snapshot{}, err
	}
	s.desired = clone(candidate)
	s.revision = revision(previous)
	return Snapshot{Config: clone(candidate), Revision: s.revision, Schema: slices.Clone(s.schema)}, nil
}

func derive(cfg *Config, dataDir string) {
	cfg.DataDir = dataDir
	// Keep the established on-disk system database location. Account data uses
	// data/accounts independently; moving this path implicitly would make an
	// upgraded installation appear empty.
	cfg.StorePath = filepath.Join(dataDir, "pebble")
	cfg.LogDir = filepath.Join(dataDir, "logs")
	cfg.AttachmentDir = filepath.Join(dataDir, "attachments")
	// Empty protocol identities mean "this machine"; relays announce the
	// SMTP identity unless configured separately.
	for _, name := range []*string{&cfg.SmtpServerName, &cfg.ImapServerName, &cfg.Pop3ServerName} {
		if strings.TrimSpace(*name) == "" {
			*name = systemHostname()
		}
	}
	if strings.TrimSpace(cfg.RelayServerName) == "" {
		cfg.RelayServerName = cfg.SmtpServerName
	}
}

// systemHostname is the machine host name, or "localhost" when unknown.
var systemHostname = func() string {
	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}
	return "localhost"
}

func revision(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}

func clone(cfg *Config) *Config {
	if cfg == nil {
		return nil
	}
	copy := *cfg
	copy.HTTPListeners = slices.Clone(cfg.HTTPListeners)
	for i := range copy.HTTPListeners {
		copy.HTTPListeners[i].Services = slices.Clone(cfg.HTTPListeners[i].Services)
		if cfg.HTTPListeners[i].HSTSMaxAgeDays != nil {
			value := *cfg.HTTPListeners[i].HSTSMaxAgeDays
			copy.HTTPListeners[i].HSTSMaxAgeDays = &value
		}
	}
	copy.HTTPTrustedProxies = slices.Clone(cfg.HTTPTrustedProxies)
	copy.SyncPrivateNetworks = slices.Clone(cfg.SyncPrivateNetworks)
	copy.WebhookPrivateDestinations = slices.Clone(cfg.WebhookPrivateDestinations)
	copy.MailConnectionLimitExempt = slices.Clone(cfg.MailConnectionLimitExempt)
	copy.MailProxyProtocol = slices.Clone(cfg.MailProxyProtocol)
	copy.MailProxyProtocolTrusted = slices.Clone(cfg.MailProxyProtocolTrusted)
	copy.BanDurations = slices.Clone(cfg.BanDurations)
	copy.DaneResolvers = slices.Clone(cfg.DaneResolvers)
	copy.UserAliasesDomains = slices.Clone(cfg.UserAliasesDomains)
	copy.AlertEmailRecipients = slices.Clone(cfg.AlertEmailRecipients)
	copy.AccountStorageRoots = slices.Clone(cfg.AccountStorageRoots)
	copy.LdapURLs = slices.Clone(cfg.LdapURLs)
	copy.LdapIDAttributes = slices.Clone(cfg.LdapIDAttributes)
	copy.AntispamSymbolScores = slices.Clone(cfg.AntispamSymbolScores)
	copy.AntispamDNSBLZones = slices.Clone(cfg.AntispamDNSBLZones)
	copy.AntispamRHSBLZones = slices.Clone(cfg.AntispamRHSBLZones)
	copy.AntispamURIBLZones = slices.Clone(cfg.AntispamURIBLZones)
	copy.AntispamTrustedNetworks = slices.Clone(cfg.AntispamTrustedNetworks)
	copy.AntispamProtectedBrands = slices.Clone(cfg.AntispamProtectedBrands)
	copy.AntispamURLShorteners = slices.Clone(cfg.AntispamURLShorteners)
	copy.AttachmentBlockedExtensions = slices.Clone(cfg.AttachmentBlockedExtensions)
	copy.OutboundRateLimits = slices.Clone(cfg.OutboundRateLimits)
	copy.AntispamSpamtraps = slices.Clone(cfg.AntispamSpamtraps)
	copy.ArcTrustedSealers = slices.Clone(cfg.ArcTrustedSealers)
	copy.LogModuleLevels = make(map[string]string, len(cfg.LogModuleLevels))
	for module, level := range cfg.LogModuleLevels {
		copy.LogModuleLevels[module] = level
	}
	return &copy
}

func atomicWrite(path string, contents []byte, mode fs.FileMode) (retErr error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create configuration temporary file: %w", err)
	}
	tmp := f.Name()
	defer func() {
		_ = f.Close()
		if retErr != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("secure configuration temporary file: %w", err)
	}
	if _, err := f.Write(contents); err != nil {
		return fmt.Errorf("write configuration: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync configuration: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close configuration: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("publish configuration: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open configuration directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync configuration directory: %w", err)
	}
	return nil
}

// Validate rejects configurations that would otherwise fail much later while
// starting listeners or opening storage.
func Validate(cfg *Config) error {
	if cfg == nil {
		return errors.New("configuration is required")
	}
	if err := validateHTTPListeners(cfg.HTTPListeners); err != nil {
		return err
	}
	if _, err := ParseTrustedProxies(cfg.HTTPTrustedProxies); err != nil {
		return err
	}
	if _, err := ParseDestinations("webhook_private_destinations", cfg.WebhookPrivateDestinations); err != nil {
		return err
	}
	if _, err := ParseAddressPrefixes("sync_private_networks", cfg.SyncPrivateNetworks); err != nil {
		return err
	}
	if cfg.MtaStsMode != "" && !slices.Contains([]string{"off", "none", "testing", "enforce"}, cfg.MtaStsMode) {
		return fmt.Errorf("mta_sts_mode must be off, none, testing or enforce")
	}
	if !ValidForwardedHeader(cfg.HTTPForwardedHeader) {
		return fmt.Errorf("http_forwarded_header must be %q or %q", ForwardedHeaderX, ForwardedHeaderRFC7239)
	}
	if _, err := ParseAddressPrefixes("mail_connection_limit_exempt", cfg.MailConnectionLimitExempt); err != nil {
		return err
	}
	if err := validateMailProxyProtocol(cfg); err != nil {
		return err
	}
	if err := validateBans(cfg); err != nil {
		return err
	}
	if err := validateDNSServer(cfg); err != nil {
		return err
	}
	if _, err := ParseResolverAddresses("dane_resolvers", cfg.DaneResolvers); err != nil {
		return err
	}
	if cfg.MailMaxConnectionsPerIP < 0 || cfg.MailMaxConnectionsPerIP > 100000 {
		return errors.New("mail_max_connections_per_ip must be between 0 and 100000")
	}
	if cfg.StoreBackend != store.BackendPebble && cfg.StoreBackend != store.BackendBadger {
		return fmt.Errorf("system_engine must be %q or %q", store.BackendPebble, store.BackendBadger)
	}
	if cfg.DefaultAccountEngine != store.BackendPebble && cfg.DefaultAccountEngine != store.BackendBadger {
		return fmt.Errorf("default_account_engine must be %q or %q", store.BackendPebble, store.BackendBadger)
	}
	for key, values := range map[string][]string{} {
		for _, value := range values {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s must not contain empty values", key)
			}
		}
	}
	for key, value := range map[string]string{"log_console_level": cfg.LogConsoleLevel, "log_file_level": cfg.LogFileLevel} {
		if _, err := logpkg.ParseLevelStrict(value); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	if err := logpkg.ValidateModuleLevels(cfg.LogModuleLevels); err != nil {
		return fmt.Errorf("log_module_levels: %w", err)
	}
	if err := validateMetricsToken(cfg.MetricsToken); err != nil {
		return fmt.Errorf("metrics_token: %w", err)
	}
	if cfg.LogFileRetentionDays < 1 || cfg.LogFileRetentionDays > 3650 {
		return errors.New("log_file_retention_days must be between 1 and 3650")
	}
	if cfg.LogFileMaxFiles < 1 || cfg.LogFileMaxFiles > 3650 {
		return errors.New("log_file_max_files must be between 1 and 3650")
	}
	if cfg.LogFormat != "text" && cfg.LogFormat != "json" {
		return errors.New("log_format must be text or json")
	}
	rootIDs := make(map[string]struct{}, len(cfg.AccountStorageRoots))
	rootPaths := make([]string, 0, len(cfg.AccountStorageRoots))
	for _, definition := range cfg.AccountStorageRoots {
		id, path, found := strings.Cut(definition, "=")
		id, path = strings.TrimSpace(id), strings.TrimSpace(path)
		if !found || id == "" || path == "" || strings.ContainsAny(id, "/\\\x00") {
			return fmt.Errorf("invalid account_storage_roots entry %q; expected id=path", definition)
		}
		if _, duplicate := rootIDs[id]; duplicate {
			return fmt.Errorf("duplicate account storage root %q", id)
		}
		rootIDs[id] = struct{}{}
		if !filepath.IsAbs(path) {
			path = filepath.Join(cfg.DataDir, path)
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("resolve account storage root %q: %w", id, err)
		}
		for _, existing := range rootPaths {
			separator := string(os.PathSeparator)
			if absolute == existing || strings.HasPrefix(absolute+separator, existing+separator) || strings.HasPrefix(existing+separator, absolute+separator) {
				return errors.New("account storage roots cannot overlap")
			}
		}
		rootPaths = append(rootPaths, absolute)
	}
	if _, found := rootIDs[cfg.PrimaryAccountRoot]; !found {
		return errors.New("primary_account_root must name a configured account storage root")
	}
	listeners := map[string]string{
		"listen_addr": cfg.ListenAddr, "https_listen": cfg.HTTPSListen, "pprof_listen": cfg.PprofListenAddr,
		"smtp_listen": cfg.SmtpListen, "smtp_submission_listen": cfg.SmtpSubmissionListen,
		"smtp_tls_listen": cfg.SmtpTLSListen, "imap_listen": cfg.ImapListen,
		"imap_tls_listen": cfg.ImapTlsListen, "pop3_listen": cfg.Pop3Listen,
		"pop3_tls_listen": cfg.Pop3TlsListen, "acme_http_listen": cfg.AcmeHTTPListen,
	}
	for key, address := range listeners {
		if address == "" && key == "pprof_listen" {
			continue
		}
		if err := validateAddress(address); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	activeListeners := make(map[string]string)
	claimAddress := func(name, address string, enabled bool) error {
		if !enabled || address == "" {
			return nil
		}
		canonical := canonicalListenAddress(address)
		if existing, found := activeListeners[canonical]; found {
			return fmt.Errorf("enabled listeners %s and %s collide on %s", existing, name, address)
		}
		activeListeners[canonical] = name
		return nil
	}
	for _, listener := range cfg.HTTPListeners {
		if err := claimAddress("http_listeners."+listener.ID, listener.Address, listener.Enabled); err != nil {
			return err
		}
	}
	for _, listener := range []struct {
		name    string
		address string
		enabled bool
	}{
		{"pprof_listen", cfg.PprofListenAddr, cfg.PprofListenAddr != ""},
		{"smtp_listen", cfg.SmtpListen, cfg.SmtpEnabled}, {"smtp_submission_listen", cfg.SmtpSubmissionListen, cfg.SmtpSubmissionEnabled},
		{"smtp_tls_listen", cfg.SmtpTLSListen, cfg.SmtpImplicitTLSEnabled}, {"imap_listen", cfg.ImapListen, cfg.ImapEnabled},
		{"imap_tls_listen", cfg.ImapTlsListen, cfg.ImapTLSEnabled}, {"pop3_listen", cfg.Pop3Listen, cfg.Pop3Enabled},
		{"pop3_tls_listen", cfg.Pop3TlsListen, cfg.Pop3TLSEnabled}, {"acme_http_listen", cfg.AcmeHTTPListen, cfg.AcmeEnabled},
		{"dns_server_listen", cfg.DNSServerListen, cfg.DNSServerEnabled},
	} {
		if err := claimAddress(listener.name, listener.address, listener.enabled); err != nil {
			return err
		}
	}
	if cfg.SmtpMaxRecipients < 1 || cfg.SmtpMaxRecipients > 1000 {
		return errors.New("smtp_max_recipients must be between 1 and 1000")
	}
	if cfg.QueueMaxSize < 1 || cfg.QueueWorkers < 1 || cfg.QueueWorkers > 128 || cfg.QueueMaxPerDestination < 1 || cfg.QueueMaxPerDestination > cfg.QueueWorkers ||
		cfg.QueueMaxAgeHours < 1 || cfg.QueueRetryInitialSecs < 1 || cfg.QueueRetryMaxSecs < cfg.QueueRetryInitialSecs {
		return errors.New("queue settings require positive limits, 1-128 workers, per-destination workers not above total workers, and retry maximum not below retry initial")
	}
	if cfg.MessageTraceRetentionDays < 1 || cfg.MessageTraceRetentionDays > 3650 {
		return errors.New("message_trace_retention_days must be between 1 and 3650")
	}
	if cfg.QueueReceiptRetentionDays < 1 || cfg.QueueReceiptRetentionDays > 3650 {
		return errors.New("queue_receipt_retention_days must be between 1 and 3650")
	}
	if cfg.SmtpMaxMessageSize < 1024 || cfg.WebdavMaxFileSize < 1024 {
		return errors.New("message and WebDAV size limits must be at least 1024 bytes")
	}
	if cfg.SmtpMaxReceivedHeaders < 1 || cfg.SmtpMaxReceivedHeaders > 1000 {
		return errors.New("smtp_max_received_headers must be between 1 and 1000")
	}
	if cfg.SmtpGreetDelayMs < 0 || cfg.SmtpGreetDelayMs > 6000 {
		return errors.New("smtp_greet_delay_ms must be between 0 and 6000")
	}
	if value := cfg.SmtpPregreetAction; value != "off" && value != "score" && value != "reject" {
		return errors.New("smtp_pregreet_action must be off, score, or reject")
	}
	if cfg.SmtpProtocolViolationLimit < 0 || cfg.SmtpProtocolViolationLimit > 1000 {
		return errors.New("smtp_protocol_violation_limit must be between 0 and 1000")
	}
	if cfg.SmtpTarpitAfterUnknownRcpts < 0 || cfg.SmtpTarpitAfterUnknownRcpts > 1000 {
		return errors.New("smtp_tarpit_after_unknown_rcpts must be between 0 and 1000")
	}
	if addr := strings.TrimSpace(cfg.SmtpPublicAddress); addr != "" {
		ip, err := netip.ParseAddr(addr)
		if err != nil || ip.IsUnspecified() || ip.IsLoopback() {
			return errors.New("smtp_public_address must be a routable IP address or empty")
		}
	}
	if cfg.TrashRetentionDays < 1 || cfg.TrashRetentionDays > 3650 {
		return errors.New("trash_retention_days must be between 1 and 3650")
	}
	if interval, err := time.ParseDuration(cfg.RetentionJobInterval); err != nil || interval < 15*time.Minute || interval > 7*24*time.Hour {
		return errors.New("retention_job_interval must be a duration between 15m and 168h")
	}
	if cfg.RetentionMinDays < 1 || cfg.RetentionMinDays > 36500 {
		return errors.New("retention_min_days must be between 1 and 36500")
	}
	if cfg.ChangeHistoryRetentionDays < 1 || cfg.ChangeHistoryRetentionDays > 3650 || cfg.ChangeHistoryMaxEntries < 1 {
		return errors.New("change history requires 1-3650 retention days and a positive entry limit")
	}
	if cfg.AccountIdleCloseSeconds < 0 || cfg.AccountIdleCloseSeconds > 86400 {
		return errors.New("account_idle_close_seconds must be between 0 and 86400")
	}
	if cfg.AccountRetainedCleanupDays < 1 || cfg.AccountRetainedCleanupDays > 3650 {
		return errors.New("account_retained_cleanup_days must be between 1 and 3650")
	}
	if cfg.AccountVerificationIntervalHrs < 1 || cfg.AccountVerificationIntervalHrs > 8760 || cfg.AccountVerificationWorkers < 1 || cfg.AccountVerificationWorkers > 16 {
		return errors.New("account verification requires a 1-8760 hour interval and 1-16 workers")
	}
	if cfg.QuotaWarningPercent < 1 || cfg.QuotaWarningPercent > 99 || cfg.QuotaCriticalPercent < 2 || cfg.QuotaCriticalPercent > 100 || cfg.QuotaWarningPercent >= cfg.QuotaCriticalPercent {
		return errors.New("quota thresholds require warning between 1 and 99, critical between 2 and 100, and warning below critical")
	}
	if cfg.AlertEvaluationSeconds < 5 || cfg.AlertEvaluationSeconds > 3600 {
		return errors.New("alert_evaluation_seconds must be between 5 and 3600")
	}
	if cfg.AlertQueueWarningMinutes < 1 || cfg.AlertQueueCriticalMinutes <= cfg.AlertQueueWarningMinutes || cfg.AlertQueueCriticalMinutes > 10080 {
		return errors.New("queue alert thresholds require a positive warning and a greater critical threshold not above 10080 minutes")
	}
	if cfg.AlertWebhookWarningMinutes < 1 || cfg.AlertWebhookCriticalMinutes <= cfg.AlertWebhookWarningMinutes || cfg.AlertWebhookCriticalMinutes > 10080 {
		return errors.New("webhook alert thresholds require a positive warning and a greater critical threshold not above 10080 minutes")
	}
	if cfg.AlertStorageCriticalFreePercent < 1 || cfg.AlertStorageWarningFreePercent <= cfg.AlertStorageCriticalFreePercent || cfg.AlertStorageWarningFreePercent > 99 {
		return errors.New("storage free-space alert thresholds require a positive critical percentage below the warning percentage")
	}
	if cfg.AlertCertCriticalDays < 1 || cfg.AlertCertWarningDays <= cfg.AlertCertCriticalDays || cfg.AlertCertWarningDays > 3650 {
		return errors.New("certificate alert thresholds require a positive critical window and a greater warning window not above 3650 days")
	}
	if err := validateBackups(cfg); err != nil {
		return err
	}
	if err := validateAlertDelivery(cfg); err != nil {
		return err
	}
	if err := validateACME(cfg); err != nil {
		return err
	}
	if cfg.FolderCacheTTLSeconds < 1 || cfg.FolderCacheTTLSeconds > 86400 || cfg.FolderCacheMaxEntries < 1 || cfg.FolderCacheMaxBytes < 1<<20 {
		return errors.New("folder cache requires a 1-86400 second TTL, positive entry limit, and at least 1 MiB")
	}
	minimumDelay := time.Duration(cfg.GreylistMinimumDelaySeconds) * time.Second
	retryWindow := time.Duration(cfg.GreylistRetryWindowMinutes) * time.Minute
	pendingLifetime := time.Duration(cfg.GreylistPendingLifetimeHours) * time.Hour
	passLifetime := time.Duration(cfg.GreylistPassLifetimeDays) * 24 * time.Hour
	if minimumDelay < time.Second || minimumDelay > 24*time.Hour || retryWindow <= minimumDelay || retryWindow > 7*24*time.Hour || pendingLifetime < retryWindow || pendingLifetime > 30*24*time.Hour || passLifetime < retryWindow || passLifetime > 365*24*time.Hour {
		return errors.New("greylisting requires a 1 second-24 hour delay, a greater retry window up to 7 days, and pending/pass lifetimes that cover the retry window")
	}
	if cfg.GreylistIPv4PrefixBits < 0 || cfg.GreylistIPv4PrefixBits > 32 || cfg.GreylistIPv6PrefixBits < 0 || cfg.GreylistIPv6PrefixBits > 128 || cfg.GreylistMaxEntries < 100 || cfg.GreylistMaxEntries > 10_000_000 {
		return errors.New("greylisting requires valid IP prefix lengths and 100-10000000 maximum entries")
	}
	if cfg.GreylistAutoWhitelistPasses < 0 || cfg.GreylistAutoWhitelistPasses > 1000 || cfg.GreylistAutoWhitelistDays < 1 || cfg.GreylistAutoWhitelistDays > 365 {
		return errors.New("greylist auto-whitelisting requires 0-1000 passes and 1-365 days")
	}
	if cfg.BatvGracePeriodHours < 0 || cfg.BatvGracePeriodHours > 720 {
		return errors.New("batv_grace_period_hours must be between 0 and 720")
	}
	if cfg.SearchIndexWorkers < 1 || cfg.SearchIndexWorkers > 128 || cfg.SearchBatchSize < 1 || cfg.SearchBatchSize > 10000 || cfg.SearchIdleCloseSeconds < 1 || cfg.SearchIdleCloseSeconds > 86400 || cfg.SearchMaxExtractedBytes < 0 || cfg.SearchQueryMaxResults < 1 || cfg.SearchQueryMaxResults > 1000 {
		return errors.New("search requires 1-128 workers, batch size 1-10000, idle close 1-86400 seconds, non-negative extraction limit, and query limit 1-1000")
	}
	if cfg.VirusScanEnabled && !cfg.BuiltinScannerEnabled && !cfg.ClamdEnabled && !cfg.RspamdEnabled {
		return errors.New("content scanning is enabled but no scanner engine is enabled")
	}
	if cfg.QuarantineRetentionDays < 1 || cfg.QuarantineRetentionDays > 3650 || cfg.QuarantineMaxEntries < 1 || cfg.QuarantineMaxEntries > 100_000_000 || cfg.QuarantineMaxBytes < 1<<20 || cfg.QuarantineMaxBytes > 1<<50 {
		return errors.New("quarantine requires 1-3650 retention days, 1-100000000 entries, and 1 MiB-1 PiB storage")
	}
	if cfg.QuarantineCleanupMinutes < 1 || cfg.QuarantineCleanupMinutes > 1440 || cfg.QuarantineCleanupBatchSize < 1 || cfg.QuarantineCleanupBatchSize > 1_000_000 {
		return errors.New("quarantine cleanup requires a 1-1440 minute interval and batch size 1-1000000")
	}
	if cfg.QuarantineDigestPollMins < 1 || cfg.QuarantineDigestPollMins > 1440 || cfg.QuarantineDigestMaxEntries < 1 || cfg.QuarantineDigestMaxEntries > 1000 || cfg.QuarantineDigestMaxJobs < 1 || cfg.QuarantineDigestMaxJobs > 10000 || cfg.QuarantineDigestMaxRetries < 1 || cfg.QuarantineDigestMaxRetries > 100 || cfg.QuarantineDigestRetrySecs < 1 || cfg.QuarantineDigestRetrySecs > 86400 || cfg.QuarantineDigestJobDays < 1 || cfg.QuarantineDigestJobDays > 3650 || cfg.QuarantineActionTTLHours < 1 || cfg.QuarantineActionTTLHours > 8760 {
		return errors.New("quarantine digest polling, batch, retry, retention, or action TTL limits are invalid")
	}
	if _, err := mail.ParseAddress(cfg.QuarantineDigestFrom); err != nil {
		return errors.New("quarantine_digest_from must be a valid email address")
	}
	if cfg.QuarantineDigestEnabled {
		base, err := url.Parse(strings.TrimSpace(cfg.QuarantineDigestBaseURL))
		loopbackHTTP := err == nil && base.Scheme == "http" && (base.Hostname() == "localhost" || base.Hostname() == "127.0.0.1" || base.Hostname() == "::1")
		if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Path != "" && base.Path != "/" || base.Scheme != "https" && !loopbackHTTP {
			return errors.New("enabled quarantine digests require an HTTPS origin base URL (HTTP is allowed only for loopback)")
		}
	}
	for key, value := range map[string]int{
		"builtin_scanner_timeout_seconds": cfg.BuiltinScannerTimeoutSeconds,
		"clamd_timeout_seconds":           cfg.ClamdTimeoutSeconds,
		"rspamd_timeout_seconds":          cfg.RspamdTimeoutSeconds,
	} {
		if value < 1 || value > 600 {
			return fmt.Errorf("%s must be between 1 and 600", key)
		}
	}
	for key, value := range map[string]int64{
		"builtin_scanner_max_bytes": cfg.BuiltinScannerMaxBytes,
		"clamd_max_bytes":           cfg.ClamdMaxBytes,
		"rspamd_max_bytes":          cfg.RspamdMaxBytes,
	} {
		if value < 1024 || value > 1<<30 {
			return fmt.Errorf("%s must be between 1024 and 1073741824", key)
		}
	}
	for key, value := range map[string]string{
		"builtin_scanner_failure_policy": cfg.BuiltinScannerFailurePolicy,
		"clamd_failure_policy":           cfg.ClamdFailurePolicy,
		"rspamd_failure_policy":          cfg.RspamdFailurePolicy,
	} {
		if value != "fail-open" && value != "fail-closed" && value != "quarantine" {
			return fmt.Errorf("%s must be fail-open, fail-closed, or quarantine", key)
		}
	}
	if cfg.ClamdEnabled {
		endpoint := strings.TrimSpace(strings.TrimPrefix(cfg.ClamdSocket, "unix:"))
		if endpoint == "" {
			return errors.New("clamd_socket is required when ClamAV is enabled")
		}
		if !strings.HasPrefix(endpoint, "/") {
			if err := validateAddress(endpoint); err != nil {
				return fmt.Errorf("clamd_socket: %w", err)
			}
		}
	}
	if cfg.RspamdEnabled {
		endpoint, err := url.Parse(strings.TrimSpace(cfg.RspamdEndpoint))
		if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return errors.New("rspamd_endpoint must be an http(s) URL without user information, query, or fragment")
		}
	}
	if _, err := spam.ParseSettings(cfg.AntispamSettings()); err != nil {
		return fmt.Errorf("antispam: %w", err)
	}
	if _, err := ParseAddressPrefixes("antispam_trusted_networks", cfg.AntispamTrustedNetworks); err != nil {
		return err
	}
	if _, err := spam.ResolverAddress(cfg.AntispamDNSResolver); err != nil {
		return fmt.Errorf("antispam_dns_resolver: %w", err)
	}
	if _, err := attachment.NewPolicy(cfg.AttachmentSettings()); err != nil {
		return err
	}
	if outbound, err := cfg.OutboundProtection(); err != nil {
		return err
	} else if err := outbound.Validate(); err != nil {
		return fmt.Errorf("outbound_compromise_threshold: %w", err)
	}
	if cfg.AntispamBayesMinLearns < 1 || cfg.AntispamBayesMinLearns > 100_000 {
		return errors.New("antispam_bayes_min_learns must be between 1 and 100000")
	}
	if cfg.AntispamReputationMinSamples < 1 || cfg.AntispamReputationMinSamples > 100_000 {
		return errors.New("antispam_reputation_min_samples must be between 1 and 100000")
	}
	if cfg.AntispamFuzzyThreshold < 50 || cfg.AntispamFuzzyThreshold > 100 {
		return errors.New("antispam_fuzzy_threshold must be between 50 and 100")
	}
	if cfg.AntispamBulkThreshold < 2 || cfg.AntispamBulkThreshold > 60 {
		return errors.New("antispam_bulk_threshold must be between 2 and 60")
	}
	if _, err := ParseSpamtraps(cfg.AntispamSpamtraps); err != nil {
		return err
	}
	if _, err := ParseARCTrustedSealers(cfg.ArcTrustedSealers); err != nil {
		return err
	}
	if cfg.GreylistTrigger != "always" && cfg.GreylistTrigger != "score" {
		return errors.New("greylist_trigger must be always or score")
	}
	if value := cfg.WebTwoFactorRequired; value != "off" && value != "administrators" && value != "all" {
		return errors.New("web_two_factor_required must be off, administrators, or all")
	}
	for key, value := range map[string]string{"helo_policy": cfg.HeloPolicy, "spf_policy": cfg.SpfPolicy, "dkim_verify_policy": cfg.DkimVerifyPolicy, "dmarc_policy": cfg.DmarcPolicy, "local_domain_spoof_policy": cfg.LocalDomainSpoofPolicy} {
		if value != "off" && value != "warn" && value != "reject" {
			return fmt.Errorf("%s must be off, warn, or reject", key)
		}
	}
	if len(cfg.RecipientDelimiter) > 8 || strings.IndexFunc(cfg.RecipientDelimiter, func(r rune) bool {
		return r <= ' ' || r >= 0x7f || r == '@' || r == '.' || r == '"' || unicode.IsLetter(r) || unicode.IsDigit(r)
	}) >= 0 {
		return errors.New("recipient_delimiter must be up to 8 ASCII punctuation characters other than @, dot, and quote")
	}
	if cfg.UserAliasesMaxPerUser < 1 || cfg.UserAliasesMaxPerUser > 10000 {
		return errors.New("user_aliases_max_per_user must be between 1 and 10000")
	}
	for _, domain := range cfg.UserAliasesDomains {
		if !validDomainName(domain) {
			return fmt.Errorf("user_aliases_domains entry %q is not a domain name", domain)
		}
	}
	// Server names go into EHLO, Message-IDs, bounce fields, and published
	// DNS records; whitespace or control characters there inject protocol
	// lines and header fields. (Host names of the machine itself may not be
	// strict DNS names, so only those characters are refused.)
	for key, name := range map[string]string{"smtp_server_name": cfg.SmtpServerName, "imap_server_name": cfg.ImapServerName, "pop3_server_name": cfg.Pop3ServerName, "relay_server_name": cfg.RelayServerName} {
		if strings.IndexFunc(name, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0 {
			return fmt.Errorf("%s must not contain spaces or control characters", key)
		}
	}
	if cfg.SrsDomain != "" && !validDomainName(cfg.SrsDomain) {
		return errors.New("srs_domain must be empty or a domain name")
	}
	if strings.TrimSpace(cfg.DmarcAggregateOrganization) == "" || len([]rune(cfg.DmarcAggregateOrganization)) > 256 {
		return errors.New("dmarc_aggregate_organization must contain 1 to 256 characters")
	}
	if cfg.DmarcAggregateEmail != "" {
		address, err := mail.ParseAddress(strings.TrimSpace(cfg.DmarcAggregateEmail))
		if err != nil || address.Address != strings.TrimSpace(cfg.DmarcAggregateEmail) {
			return errors.New("dmarc_aggregate_email must be one addr-spec or empty")
		}
	}
	if cfg.DmarcAggregateRetentionDays < 7 || cfg.DmarcAggregateRetentionDays > 3650 {
		return errors.New("dmarc_aggregate_retention_days must be between 7 and 3650")
	}
	for key, value := range map[string]string{"webhook_base_delay": cfg.WebhookBaseDelay, "webhook_timeout": cfg.WebhookTimeout} {
		d, err := time.ParseDuration(value)
		if err != nil || d <= 0 {
			return fmt.Errorf("%s must be a positive duration", key)
		}
	}
	if cfg.RelayPort < 1 || cfg.RelayPort > 65535 {
		return errors.New("relay_port must be between 1 and 65535")
	}
	if err := validateLDAP(cfg); err != nil {
		return err
	}
	return nil
}

// validDomainName reports whether name is a DNS domain name of
// letter-digit-hyphen labels.
func validDomainName(name string) bool {
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// MinMetricsTokenLength is the shortest accepted non-empty metrics_token.
const MinMetricsTokenLength = 16

func validateMetricsToken(token string) error {
	if token == "" {
		return nil
	}
	if len(token) < MinMetricsTokenLength {
		return fmt.Errorf("must be empty or at least %d characters", MinMetricsTokenLength)
	}
	if strings.IndexFunc(token, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0 {
		return errors.New("must not contain whitespace or control characters")
	}
	return nil
}

func validateAddress(address string) error {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("must be a host:port listen address")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func canonicalListenAddress(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "*"
	}
	return net.JoinHostPort(host, port)
}

func buildSchema() []SettingSpec {
	t := reflect.TypeFor[Config]()
	result := make([]SettingSpec, 0, t.NumField())
	for i := range t.NumField() {
		field := t.Field(i)
		key := field.Tag.Get("toml")
		if key == "" || key == "-" {
			continue
		}
		typeName := field.Type.Kind().String()
		if field.Type == reflect.TypeFor[store.Backend]() {
			typeName = "enum"
		} else if field.Type.Kind() == reflect.Slice {
			typeName = "list"
		} else if field.Type.Kind() == reflect.Map {
			typeName = "map"
		}
		category := strings.SplitN(key, "_", 2)[0]
		if category == "listen" || category == "system" || category == "pprof" || category == "log" || category == "trash" {
			category = "system"
		}
		result = append(result, SettingSpec{
			Key: key, Type: typeName, Category: category, Level: settingLevel(key),
			RestartRequired: true, Sensitive: sensitiveSetting(key),
			Description: strings.ReplaceAll(key, "_", " "),
		})
	}
	return result
}

// sensitiveSetting reports whether key holds a credential whose value is
// redacted from history, plans, apply state and administration reads. The
// alert push URL counts: ntfy, Gotify and similar receivers often carry their
// credential in the path or query.
func sensitiveSetting(key string) bool {
	return strings.Contains(key, "password") || strings.Contains(key, "token") || strings.Contains(key, "tsig") || key == "alert_notify_url"
}

func settingLevel(key string) string {
	normal := map[string]bool{
		"listen_addr": true, "system_engine": true, "smtp_enabled": true, "smtp_submission_enabled": true,
		"imap_enabled": true, "pop3_enabled": true, "managesieve_enabled": true, "dav_enabled": true, "jmap_enabled": true, "mcp_enabled": true,
		"ews_enabled": true, "eas_enabled": true, "virus_scan_enabled": true, "local_domain_spoof_policy": true,
		"trash_retention_days": true, "log_console_level": true, "search_enabled": true, "greylist_enabled": true,
		"account_verification_enabled": true, "ldap_enabled": true, "antispam_enabled": true,
		"retention_enabled": true, "legal_hold_domain_admins": true,
	}
	if normal[key] {
		return "normal"
	}
	return "advanced"
}
