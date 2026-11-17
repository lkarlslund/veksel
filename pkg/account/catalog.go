package account

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// Issue explains why a discovered account was excluded from resolution.
type Issue struct {
	Path      string `json:"path"`
	AccountID string `json:"account_id,omitempty"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}

// Entry is a discovered account and its physical directory.
type Entry struct {
	Manifest Manifest `json:"manifest"`
	Path     string   `json:"path"`
	RootID   string   `json:"root_id"`
}

// Root is a named physical account placement root.
type Root struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

// Catalog is the rebuildable runtime address, login, and account-location index.
type Catalog struct {
	mu        sync.RWMutex
	byID      map[string]Entry
	byLogin   map[string]string
	byAddress map[string]string
	issues    []Issue
}

// Discover scans an accounts root without following account-directory symlinks.
func Discover(root string) (*Catalog, error) {
	catalog := &Catalog{
		byID:      make(map[string]Entry),
		byLogin:   make(map[string]string),
		byAddress: make(map[string]string),
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create accounts root: %w", err)
	}
	rootPath, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve accounts root: %w", err)
	}
	entries, err := os.ReadDir(rootPath)
	if err != nil {
		return nil, fmt.Errorf("read accounts root: %w", err)
	}
	for _, directory := range entries {
		if !strings.HasPrefix(directory.Name(), "acc_") {
			continue
		}
		path := filepath.Join(rootPath, directory.Name())
		info, err := os.Lstat(path)
		if err != nil {
			catalog.addIssue(path, "", "inspect_failed", err)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			catalog.addIssue(path, "", "symlink_rejected", errors.New("account directories cannot be symlinks"))
			continue
		}
		if !info.IsDir() {
			catalog.addIssue(path, "", "not_directory", errors.New("account path is not a directory"))
			continue
		}
		manifestPath := filepath.Join(path, ManifestFilename)
		manifestInfo, err := os.Lstat(manifestPath)
		if err != nil {
			catalog.addIssue(path, "", "invalid_manifest", err)
			continue
		}
		if manifestInfo.Mode()&os.ModeSymlink != 0 || !manifestInfo.Mode().IsRegular() {
			catalog.addIssue(path, "", "invalid_manifest", errors.New("account manifest must be a regular file, not a symlink"))
			continue
		}
		manifest, err := ReadManifest(manifestPath)
		if err != nil {
			catalog.addIssue(path, "", "invalid_manifest", err)
			continue
		}
		if directory.Name() != manifest.ID {
			catalog.addIssue(path, manifest.ID, "id_path_mismatch", fmt.Errorf("directory %q does not match account ID", directory.Name()))
			continue
		}
		generationPath := filepath.Join(path, "generations", manifest.ActiveGeneration)
		if generationInfo, err := os.Lstat(generationPath); err != nil || !generationInfo.IsDir() || generationInfo.Mode()&os.ModeSymlink != 0 {
			if err == nil {
				err = errors.New("active generation must be a directory, not a symlink")
			}
			catalog.addIssue(path, manifest.ID, "generation_unavailable", err)
			continue
		}
		catalog.byID[manifest.ID] = Entry{Manifest: manifest, Path: path}
	}
	catalog.buildIndexes()
	return catalog, nil
}

// DiscoverRoots builds one conflict-checked catalog from all configured roots.
func DiscoverRoots(roots []Root) (*Catalog, error) {
	combined := &Catalog{byID: make(map[string]Entry), byLogin: make(map[string]string), byAddress: make(map[string]string)}
	conflictedIDs := make(map[string]struct{})
	for _, root := range roots {
		catalog, err := Discover(root.Path)
		if err != nil {
			return nil, fmt.Errorf("discover account root %q: %w", root.ID, err)
		}
		combined.issues = append(combined.issues, catalog.Issues()...)
		for _, entry := range catalog.Entries() {
			entry.RootID = root.ID
			if _, conflicted := conflictedIDs[entry.Manifest.ID]; conflicted {
				combined.addIssue(entry.Path, entry.Manifest.ID, "duplicate_account_id", errors.New("account ID exists in more than one configured root"))
				continue
			}
			if existing, duplicate := combined.byID[entry.Manifest.ID]; duplicate {
				combined.addIssue(existing.Path, existing.Manifest.ID, "duplicate_account_id", fmt.Errorf("account ID also exists at %s", entry.Path))
				combined.addIssue(entry.Path, entry.Manifest.ID, "duplicate_account_id", fmt.Errorf("account ID also exists at %s", existing.Path))
				delete(combined.byID, entry.Manifest.ID)
				conflictedIDs[entry.Manifest.ID] = struct{}{}
				continue
			}
			combined.byID[entry.Manifest.ID] = entry
		}
	}
	combined.buildIndexes()
	return combined, nil
}

func (c *Catalog) buildIndexes() {
	conflicted := make(map[string]struct{})
	for id, entry := range c.byID {
		if existing, found := c.byLogin[entry.Manifest.Login]; found {
			conflicted[id] = struct{}{}
			conflicted[existing] = struct{}{}
			c.addIssue(entry.Path, id, "duplicate_login", fmt.Errorf("login %q also belongs to %s", entry.Manifest.Login, existing))
		} else {
			c.byLogin[entry.Manifest.Login] = id
		}
		for _, address := range entry.Manifest.Addresses {
			if existing, found := c.byAddress[address]; found {
				conflicted[id] = struct{}{}
				conflicted[existing] = struct{}{}
				c.addIssue(entry.Path, id, "duplicate_address", fmt.Errorf("address %q also belongs to %s", address, existing))
			} else {
				c.byAddress[address] = id
			}
		}
	}
	if len(conflicted) == 0 {
		return
	}
	for id := range conflicted {
		delete(c.byID, id)
	}
	for login, id := range c.byLogin {
		if _, found := conflicted[id]; found {
			delete(c.byLogin, login)
		}
	}
	for address, id := range c.byAddress {
		if _, found := conflicted[id]; found {
			delete(c.byAddress, address)
		}
	}
}

func (c *Catalog) addIssue(path, accountID, code string, err error) {
	c.issues = append(c.issues, Issue{Path: path, AccountID: accountID, Code: code, Message: err.Error()})
}

// ByID resolves an available account ID.
func (c *Catalog) ByID(id string) (Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, found := c.byID[id]
	return entry, found
}

// ByLogin resolves a normalized login.
func (c *Catalog) ByLogin(login string) (Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	id, found := c.byLogin[normalizeLogin(login)]
	if !found {
		return Entry{}, false
	}
	entry, found := c.byID[id]
	return entry, found
}

// ByAddress resolves a normalized email address.
func (c *Catalog) ByAddress(address string) (Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	id, found := c.byAddress[normalizeAddress(address)]
	if !found {
		return Entry{}, false
	}
	entry, found := c.byID[id]
	return entry, found
}

// Entries returns available entries ordered by account ID.
func (c *Catalog) Entries() []Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entries := make([]Entry, 0, len(c.byID))
	for _, entry := range c.byID {
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Manifest.ID, b.Manifest.ID) })
	return entries
}

// Issues returns a copy of all discovery issues.
func (c *Catalog) Issues() []Issue {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return slices.Clone(c.issues)
}
