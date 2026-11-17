package account

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SetRoots replaces the configured placement roots and primary root on a
// running manager. Roots may be added and the primary may change (it only
// decides where new accounts are created). A root that still holds accounts,
// or undiscoverable account data, can be neither removed nor repointed: the
// call fails and the previous configuration stays in force.
func (m *Manager) SetRoots(roots []Root, primaryRoot string) error {
	roots, rootMap, primaryPath, err := normalizeRoots(roots, primaryRoot)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkRootsRetainedLocked(rootMap); err != nil {
		return err
	}
	var added []Root
	for _, root := range roots {
		if _, found := m.roots[root.ID]; !found {
			added = append(added, root)
		}
	}
	if err := recoverMoves(added); err != nil {
		return err
	}
	previousRoots, previousCatalog, previousPrimary := m.roots, m.catalog, m.Root()
	if primaryPath != previousPrimary {
		if err := m.relocateLifecycleJobs(previousPrimary, primaryPath); err != nil {
			return err
		}
	}
	m.roots = rootMap
	if err := m.refreshLocked(); err != nil {
		m.roots, m.catalog = previousRoots, previousCatalog
		if primaryPath != previousPrimary {
			_ = m.relocateLifecycleJobs(primaryPath, previousPrimary)
		}
		return err
	}
	m.primaryRoot = primaryRoot
	return nil
}

// checkRootsRetainedLocked rejects a root set that drops or repoints a root
// holding accounts or unreadable account data.
func (m *Manager) checkRootsRetainedLocked(next map[string]string) error {
	for id, path := range m.roots {
		if next[id] == path {
			continue
		}
		for _, entry := range m.catalog.Entries() {
			if entry.RootID == id {
				return fmt.Errorf("account root %q still holds accounts (for example %q) and cannot be removed or moved; move the accounts to another root first", id, entry.Manifest.Login)
			}
		}
		for _, issue := range m.catalog.Issues() {
			if strings.HasPrefix(issue.Path, path+string(os.PathSeparator)) {
				return fmt.Errorf("account root %q still holds account data that failed discovery (%s) and cannot be removed or moved", id, issue.Path)
			}
		}
	}
	return nil
}

// relocateLifecycleJobs carries lifecycle job records from the old primary
// root to the new one and switches the primary. Active jobs block the change.
func (m *Manager) relocateLifecycleJobs(from, to string) error {
	jobs, err := m.LifecycleJobs("")
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if job.Phase == LifecycleQueued || job.Phase == LifecycleRunning {
			return fmt.Errorf("account lifecycle job %s is still %s; wait for it before changing the primary account root", job.ID, job.Phase)
		}
	}
	m.root.Store(&to)
	for _, job := range jobs {
		if err := m.writeLifecycleJob(job); err != nil {
			m.root.Store(&from)
			return err
		}
	}
	for _, job := range jobs {
		_ = os.Remove(filepath.Join(from, ".lifecycle-jobs", job.ID+".json"))
	}
	return nil
}
