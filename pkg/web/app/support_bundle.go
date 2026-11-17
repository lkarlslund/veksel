package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/diagnostics"
	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"github.com/pelletier/go-toml/v2"
)

type supportConfigValue struct {
	Key      string `json:"key"`
	Category string `json:"category"`
	Level    string `json:"level"`
	Value    any    `json:"value"`
}

type supportLogRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	Level       string    `json:"level"`
	Module      string    `json:"module"`
	Fingerprint string    `json:"fingerprint"`
}

func (h *Handler) apiAdminSupportBundlePreview(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	bundle, err := h.buildSupportBundle(r)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, bundle.Manifest())
}

func (h *Handler) apiAdminSupportBundleDownload(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	actor := currentActor(r).ID
	bundle, err := h.buildSupportBundle(r)
	if err != nil {
		h.audit.Log(actor, "support_bundle.download", "system", map[string]string{"result": "failed"})
		apiError(w, err)
		return
	}
	var archive bytes.Buffer
	if err := bundle.WriteArchive(&archive); err != nil {
		h.audit.Log(actor, "support_bundle.download", "system", map[string]string{"result": "failed"})
		apiError(w, err)
		return
	}
	manifest := bundle.Manifest()
	h.audit.Log(actor, "support_bundle.download", "system", map[string]string{
		"result": "succeeded", "sections": strconv.Itoa(len(manifest.Files)), "bytes": strconv.Itoa(archive.Len()),
	})
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="veksel-support-%s.zip"`, manifest.GeneratedAt.Format("20060102T150405Z")))
	w.Header().Set("Content-Length", strconv.Itoa(archive.Len()))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(archive.Bytes())
}

func (h *Handler) buildSupportBundle(r *http.Request) (diagnostics.SupportBundle, error) {
	now := time.Now().UTC()
	sections := make([]diagnostics.SupportSection, 0, 5)
	add := func(name, description, privacy string, value any) error {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		sections = append(sections, diagnostics.SupportSection{Name: name, Description: description, Privacy: privacy, Data: data})
		return nil
	}

	buildVersion := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok && strings.TrimSpace(info.Main.Version) != "" {
		buildVersion = info.Main.Version
	}
	if err := add("runtime.json", "Application build and Go runtime characteristics", "No hostnames, paths, process arguments, environment, profiles, or network addresses", map[string]any{
		"application": "veksel", "module_version": buildVersion, "go_version": runtime.Version(),
		"os": runtime.GOOS, "architecture": runtime.GOARCH, "logical_cpus": runtime.NumCPU(),
	}); err != nil {
		return diagnostics.SupportBundle{}, err
	}

	users, err := h.users.List(r.Context())
	if err != nil {
		return diagnostics.SupportBundle{}, fmt.Errorf("count support-bundle accounts: %w", err)
	}
	domains, err := h.ts.DomainStore().List(r.Context())
	if err != nil {
		return diagnostics.SupportBundle{}, fmt.Errorf("count support-bundle domains: %w", err)
	}
	enabledUsers, enabledDomains := 0, 0
	for _, user := range users {
		if user.Enabled {
			enabledUsers++
		}
	}
	for _, domain := range domains {
		if domain.Enabled {
			enabledDomains++
		}
	}
	protocols := map[string]any{}
	if provider, ok := h.protocols.(protocolRuntimeStatusProvider); ok {
		for _, name := range []string{"smtp", "imap", "pop3", "managesieve"} {
			status := provider.ProtocolRuntimeStatus(name)
			protocols[name] = map[string]any{
				"running": status.Running, "listener_count": len(status.Listeners), "has_error": status.Error != "",
				"attempt": status.Attempt, "attempted_at": status.AttemptedAt,
			}
		}
	}
	capabilities := make(map[string]bool, len(h.capabilities))
	for name, enabled := range h.capabilities {
		capabilities[name] = enabled
	}
	if err := add("inventory.json", "Aggregate installation and protocol inventory", "Counts and state only; account names, addresses, domains, listeners, and errors are omitted", map[string]any{
		"accounts":     map[string]int{"total": len(users), "enabled": enabledUsers, "disabled": len(users) - enabledUsers},
		"domains":      map[string]int{"total": len(domains), "enabled": enabledDomains, "disabled": len(domains) - enabledDomains},
		"capabilities": capabilities, "protocols": protocols,
	}); err != nil {
		return diagnostics.SupportBundle{}, err
	}

	configuration := map[string]any{"available": false}
	if h.configService != nil {
		snapshot := h.configService.Current()
		encoded, marshalErr := toml.Marshal(snapshot.Config)
		if marshalErr != nil {
			return diagnostics.SupportBundle{}, marshalErr
		}
		values := map[string]any{}
		if err := toml.Unmarshal(encoded, &values); err != nil {
			return diagnostics.SupportBundle{}, err
		}
		settings := make([]supportConfigValue, 0, len(snapshot.Schema))
		for _, spec := range snapshot.Schema {
			value := values[spec.Key]
			switch {
			case spec.Sensitive || supportSecretKey(spec.Key):
				value = "[redacted]"
			case supportIdentityKey(spec.Key):
				value = "[identity omitted]"
			case supportLocationKey(spec.Key):
				value = "[network/location omitted]"
			case supportPathKey(spec.Key):
				value = "[path omitted]"
			}
			settings = append(settings, supportConfigValue{Key: spec.Key, Category: spec.Category, Level: spec.Level, Value: value})
		}
		sort.Slice(settings, func(i, j int) bool { return settings[i].Key < settings[j].Key })
		configuration = map[string]any{"available": true, "revision": snapshot.Revision, "settings": settings}
	}
	if err := add("configuration.json", "Managed desired configuration with classified values removed", "Secrets, identity-like values, and filesystem paths are replaced with explicit markers", configuration); err != nil {
		return diagnostics.SupportBundle{}, err
	}

	healthDocument := map[string]any{"available": false}
	if h.runtimeHealth != nil {
		if h.refreshHealth != nil {
			h.refreshHealth(r.Context())
		}
		snapshot := h.runtimeHealth.Snapshot(now)
		components := make([]map[string]any, 0, len(snapshot.Components))
		for _, component := range snapshot.Components {
			identity := sha256.Sum256([]byte(component.ID))
			components = append(components, map[string]any{
				"component_fingerprint": hex.EncodeToString(identity[:8]), "kind": component.Kind, "desired": component.Desired, "required": component.Required,
				"state": component.State, "severity": component.Severity, "since": component.Since, "observed_at": component.ObservedAt,
			})
		}
		healthDocument = map[string]any{"available": true, "status": snapshot.Status, "generated_at": snapshot.GeneratedAt, "components": components}
	}
	if err := add("health.json", "Current runtime component states", "State and timestamps only; labels, reasons, details, paths, addresses, and errors are omitted", healthDocument); err != nil {
		return diagnostics.SupportBundle{}, err
	}

	logDocument := map[string]any{"available": false, "records": []supportLogRecord{}}
	if h.configService != nil {
		records := make([]supportLogRecord, 0, 150)
		for _, level := range []string{"FATAL", "ERROR", "WARN"} {
			page, err := logpkg.QueryManagedLogs(h.configService.Current().Config.LogDir, logpkg.LogQuery{Limit: 50, Level: level})
			if err != nil {
				return diagnostics.SupportBundle{}, fmt.Errorf("read support-bundle logs: %w", err)
			}
			for _, record := range page.Records {
				encoded, _ := json.Marshal(record)
				digest := sha256.Sum256(encoded)
				records = append(records, supportLogRecord{Timestamp: record.Timestamp, Level: record.Level, Module: record.Module, Fingerprint: hex.EncodeToString(digest[:8])})
			}
		}
		slices.SortFunc(records, func(left, right supportLogRecord) int { return right.Timestamp.Compare(left.Timestamp) })
		logDocument = map[string]any{"available": true, "maximum": 150, "records": records}
	}
	if err := add("severe-logs.json", "Newest bounded warning, error, and fatal log metadata", "Messages, fields, callers, identities, and paths are omitted; opaque fingerprints permit duplicate correlation", logDocument); err != nil {
		return diagnostics.SupportBundle{}, err
	}

	return diagnostics.NewSupportBundle(now, sections)
}

func supportSecretKey(key string) bool {
	return containsSupportKey(key, "password", "secret", "token", "private", "credential", "key")
}

func supportIdentityKey(key string) bool {
	return containsSupportKey(key, "email", "domain", "host", "user", "sender", "recipient")
}

func supportPathKey(key string) bool {
	return containsSupportKey(key, "path", "dir", "root", "file")
}

func supportLocationKey(key string) bool {
	return containsSupportKey(key, "listen", "endpoint", "origin", "socket", "server_name", "base_url", "url", "certificate")
}

func containsSupportKey(key string, values ...string) bool {
	key = strings.ToLower(key)
	for _, value := range values {
		if strings.Contains(key, value) {
			return true
		}
	}
	return false
}
