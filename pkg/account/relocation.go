package account

// RelocationObserver keeps derived state that lives inside an account
// directory, such as the search index, consistent with Move.
//
// AccountRelocating runs once the account is fenced for maintenance and before
// its directory is renamed away. The observer must stop using every file under
// path, closing open handles and waiting for in-flight users, before it
// returns; it must not acquire the account, which is unavailable meanwhile.
//
// AccountRelocated runs after the move finished and the account is available
// again. path is the account's current directory: the new one when the move
// committed, the unchanged one when it failed. retained is the directory the
// previous contents were kept under after a committed move, or empty.
type RelocationObserver interface {
	AccountRelocating(login, path string)
	AccountRelocated(login, path, retained string)
}

// OnRelocation registers observer for account moves. The returned function
// unregisters it.
func (m *Manager) OnRelocation(observer RelocationObserver) func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.relocationSeq++
	id := m.relocationSeq
	if m.relocationObservers == nil {
		m.relocationObservers = make(map[uint64]RelocationObserver)
	}
	m.relocationObservers[id] = observer
	return func() {
		m.mu.Lock()
		delete(m.relocationObservers, id)
		m.mu.Unlock()
	}
}

func (m *Manager) relocationObserverList() []RelocationObserver {
	m.mu.RLock()
	defer m.mu.RUnlock()
	observers := make([]RelocationObserver, 0, len(m.relocationObservers))
	for _, observer := range m.relocationObservers {
		observers = append(observers, observer)
	}
	return observers
}

// beginRelocation tells observers that entry's directory is about to change
// and returns the function reporting the outcome. finish reads the account's
// current path itself, so it must run after the catalog was refreshed.
func (m *Manager) beginRelocation(entry Entry) (finish func(retained string)) {
	observers := m.relocationObserverList()
	for _, observer := range observers {
		observer.AccountRelocating(entry.Manifest.Login, entry.Path)
	}
	return func(retained string) {
		path := entry.Path
		if current, found := m.ByLogin(entry.Manifest.Login); found {
			path = current.Path
		}
		if path == entry.Path {
			retained = ""
		}
		for _, observer := range observers {
			observer.AccountRelocated(entry.Manifest.Login, path, retained)
		}
	}
}
