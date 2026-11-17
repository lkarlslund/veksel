package log

import (
	"fmt"
	"sort"
	"strings"
)

// Module identifies one independently filterable Veksel runtime area.
type Module string

const (
	ModuleSystem       Module = "system"
	ModuleAccounts     Module = "accounts"
	ModuleAPI          Module = "api"
	ModuleAudit        Module = "audit"
	ModuleAuth         Module = "auth"
	ModuleBackup       Module = "backup"
	ModuleCache        Module = "cache"
	ModuleCalDAV       Module = "caldav"
	ModuleCertificates Module = "certificates"
	ModuleConfig       Module = "config"
	ModuleContentScan  Module = "content-scan"
	ModuleDKIM         Module = "dkim"
	ModuleDMARC        Module = "dmarc"
	ModuleEAS          Module = "eas"
	ModuleEWS          Module = "ews"
	ModuleGreylisting  Module = "greylisting"
	ModuleIMAP         Module = "imap"
	ModuleJMAP         Module = "jmap"
	ModuleMCP          Module = "mcp"
	ModuleManageSieve  Module = "managesieve"
	ModuleMetrics      Module = "metrics"
	ModuleModel        Module = "model"
	ModulePOP3         Module = "pop3"
	ModuleQueue        Module = "queue"
	ModuleRateLimit    Module = "rate-limit"
	ModuleRules        Module = "rules"
	ModuleSearch       Module = "search"
	ModuleSharing      Module = "sharing"
	ModuleSieve        Module = "sieve"
	ModuleSMTP         Module = "smtp"
	ModuleStatic       Module = "static"
	ModuleStorage      Module = "storage"
	ModuleSync         Module = "sync"
	ModuleVirus        Module = "virus"
	ModuleWeb          Module = "web"
	ModuleWebhook      Module = "webhook"
)

// ModuleInfo is stable configuration and presentation metadata.
type ModuleInfo struct {
	ID       Module `json:"id"`
	Label    string `json:"label"`
	Settings string `json:"settings,omitempty"`
	Level    string `json:"level,omitempty"`
}

var moduleCatalog = []ModuleInfo{
	{ModuleSystem, "System", "/app/admin/settings", ""},
	{ModuleAccounts, "Accounts", "/app/admin/accounts", ""},
	{ModuleAPI, "REST API", "/app/admin/settings", ""},
	{ModuleAudit, "Audit", "/app/admin/operations", ""},
	{ModuleAuth, "Authentication", "/app/admin/security", ""},
	{ModuleBackup, "Backup and recovery", "/app/admin/operations", ""},
	{ModuleCache, "Folder cache", "/app/admin/settings", ""},
	{ModuleCalDAV, "CalDAV and CardDAV", "/app/admin/protocols/dav", ""},
	{ModuleCertificates, "Certificates", "/app/admin/certificates", ""},
	{ModuleConfig, "Managed configuration", "/app/admin/settings", ""},
	{ModuleContentScan, "Content scanning", "/app/admin/security", ""},
	{ModuleDKIM, "DKIM", "/app/admin/security", ""},
	{ModuleDMARC, "DMARC", "/app/admin/security", ""},
	{ModuleEAS, "Exchange ActiveSync (EAS)", "/app/admin/protocols/eas", ""},
	{ModuleEWS, "Exchange Web Services (EWS)", "/app/admin/protocols/ews", ""},
	{ModuleGreylisting, "Greylisting", "/app/admin/security", ""},
	{ModuleIMAP, "Internet Message Access Protocol (IMAP)", "/app/admin/protocols/imap", ""},
	{ModuleJMAP, "JSON Meta Application Protocol (JMAP)", "/app/admin/protocols/jmap", ""},
	{ModuleMCP, "Model Context Protocol (MCP)", "/app/admin/protocols/mcp", ""},
	{ModuleManageSieve, "ManageSieve", "/app/admin/protocols/managesieve", ""},
	{ModuleMetrics, "Metrics", "/app/admin/operations", ""},
	{ModuleModel, "Domain model", "/app/admin/settings", ""},
	{ModulePOP3, "Post Office Protocol (POP3)", "/app/admin/protocols/pop3", ""},
	{ModuleQueue, "System queue", "/app/admin/operations", ""},
	{ModuleRateLimit, "Rate limiting", "/app/admin/security", ""},
	{ModuleRules, "Rules and automation", "/app/admin/policies", ""},
	{ModuleSearch, "Search", "/app/admin/settings", ""},
	{ModuleSharing, "Sharing and delegation", "/app/admin/settings", ""},
	{ModuleSieve, "Sieve", "/app/admin/protocols/smtp", ""},
	{ModuleSMTP, "Simple Mail Transfer Protocol (SMTP)", "/app/admin/protocols/smtp", ""},
	{ModuleStatic, "Static web assets", "/app/admin/settings", ""},
	{ModuleStorage, "Storage", "/app/admin/settings", ""},
	{ModuleSync, "Mailbox synchronization and import", "/app/admin/accounts", ""},
	{ModuleVirus, "Malware scanning", "/app/admin/security", ""},
	{ModuleWeb, "Web interface", "/app/admin/settings", ""},
	{ModuleWebhook, "Webhooks", "/app/admin/notifications", ""},
}

var knownModules = func() map[Module]ModuleInfo {
	result := make(map[Module]ModuleInfo, len(moduleCatalog))
	for _, module := range moduleCatalog {
		if module.ID == "" || result[module.ID].ID != "" {
			panic("log: invalid or duplicate module " + string(module.ID))
		}
		result[module.ID] = module
	}
	return result
}()

// Modules returns the complete registry in stable label order.
func Modules() []ModuleInfo {
	mu.Lock()
	defer mu.Unlock()
	result := make([]ModuleInfo, len(moduleCatalog))
	for index, module := range moduleCatalog {
		module.Level = moduleLevelLocked(module.ID).ConfigString()
		result[index] = module
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Label < result[j].Label })
	return result
}

// DefaultModuleLevels returns a detached complete configuration map.
func DefaultModuleLevels() map[string]string {
	result := make(map[string]string, len(moduleCatalog))
	for _, module := range moduleCatalog {
		result[string(module.ID)] = "info"
	}
	return result
}

func DefaultModuleLevelValues() map[Module]Level {
	result := make(map[Module]Level, len(moduleCatalog))
	for _, module := range moduleCatalog {
		result[module.ID] = LevelInfo
	}
	return result
}

// ValidateModuleLevels requires exactly known module names and valid levels.
// Missing modules inherit info, allowing older configuration files to upgrade.
func ValidateModuleLevels(levels map[string]string) error {
	for name, value := range levels {
		module := Module(strings.TrimSpace(name))
		if _, ok := knownModules[module]; !ok {
			return fmt.Errorf("unknown log module %q", name)
		}
		if _, err := ParseLevelStrict(value); err != nil {
			return fmt.Errorf("log module %q: %w", name, err)
		}
	}
	return nil
}

// ConfigureModules atomically replaces all effective module thresholds.
func ConfigureModules(levels map[string]string) error {
	if err := ValidateModuleLevels(levels); err != nil {
		return err
	}
	next := make(map[Module]Level, len(moduleCatalog))
	for _, module := range moduleCatalog {
		level := LevelInfo
		if configured, ok := levels[string(module.ID)]; ok {
			level, _ = ParseLevelStrict(configured)
		}
		next[module.ID] = level
	}
	mu.Lock()
	moduleLevels = next
	mu.Unlock()
	return nil
}

// SetModuleLevel changes one module immediately.
func SetModuleLevel(module Module, level Level) error {
	if _, ok := knownModules[module]; !ok {
		return fmt.Errorf("unknown log module %q", module)
	}
	if !level.Valid() {
		return fmt.Errorf("invalid log level %d", level)
	}
	mu.Lock()
	if moduleLevels == nil {
		moduleLevels = make(map[Module]Level, len(moduleCatalog))
	}
	moduleLevels[module] = level
	mu.Unlock()
	return nil
}

func moduleLevelLocked(module Module) Level {
	if level, ok := moduleLevels[module]; ok {
		return level
	}
	return LevelInfo
}
