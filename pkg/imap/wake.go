package imap

import (
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// Change wake-ups. A session waiting for changes (IDLE, and NOTIFY between
// commands) registers the folders and accounts it reports on. Every commit
// the folder space announces, whichever protocol or background job made it,
// marks the touched folders on the registrations that watch them and
// signals those sessions. A session settles briefly, so a burst of commits
// costs one check, then compares what it last told the client (the mailbox
// view, the NOTIFY folder snapshot) with the store and reports the
// difference. A wake carries no event, so a change announced twice is still
// reported once, and a session whose folders were not touched is never
// signalled and reads nothing.

// wakeSettle is how long a woken session waits for the rest of a burst.
const wakeSettle = 25 * time.Millisecond

// sessionWake is one session's registration.
type sessionWake struct {
	// signal has capacity one, so wakes coalesce until the session checks.
	signal chan struct{}

	mu sync.Mutex
	// touched lists the folders changed since the session last checked; all
	// means any folder of a watched account may have changed.
	touched map[string]struct{}
	all     bool
	// interrupt, while set, ends the session's blocked command read so it
	// can report between commands. It is called with mu held.
	interrupt func()

	// folders and accounts are the registration, guarded by wakeIndex.mu.
	// An account maps to true when every folder of it is watched, and to
	// false when it only owns a watched folder.
	folders  []string
	accounts map[string]bool
}

func newSessionWake() *sessionWake {
	return &sessionWake{signal: make(chan struct{}, 1)}
}

// mark records changed folders and signals the session.
func (w *sessionWake) mark(folderIDs []string, all bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if all {
		w.all = true
	}
	for _, folderID := range folderIDs {
		if w.touched == nil {
			w.touched = make(map[string]struct{})
		}
		w.touched[folderID] = struct{}{}
	}
	select {
	case w.signal <- struct{}{}:
	default:
	}
	if w.interrupt != nil {
		w.interrupt()
	}
}

// take returns and clears what changed since the last take.
func (w *sessionWake) take() (map[string]struct{}, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	touched, all := w.touched, w.all
	w.touched, w.all = nil, false
	select {
	case <-w.signal:
	default:
	}
	return touched, all
}

// arm installs interrupt for the next blocking read; when a change is
// already pending it fires at once.
func (w *sessionWake) arm(interrupt func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.interrupt = interrupt
	if w.all || len(w.touched) > 0 {
		interrupt()
	}
}

// disarm removes the interrupt. Once it returns no interrupt is running or
// will run, so the caller may reset what the interrupt changed.
func (w *sessionWake) disarm() {
	w.mu.Lock()
	w.interrupt = nil
	w.mu.Unlock()
}

// wakeIndex indexes registrations by watched folder and by account.
type wakeIndex struct {
	mu        sync.Mutex
	byFolder  map[string]map[*sessionWake]struct{}
	byAccount map[string]map[*sessionWake]struct{}
	// count is the number of registrations.
	count int
}

// set replaces a registration; nil folders and accounts remove it. It
// reports the folders the registration did not watch before.
func (x *wakeIndex) set(w *sessionWake, folders []string, accounts map[string]bool) []string {
	x.mu.Lock()
	defer x.mu.Unlock()
	if slices.Equal(w.folders, folders) && maps.Equal(w.accounts, accounts) {
		return nil
	}
	var added []string
	for _, folderID := range folders {
		if !slices.Contains(w.folders, folderID) {
			added = append(added, folderID)
		}
	}
	if len(w.folders) == 0 && len(w.accounts) == 0 {
		x.count++
	}
	if len(folders) == 0 && len(accounts) == 0 {
		x.count--
	}
	for _, folderID := range w.folders {
		removeWake(x.byFolder, folderID, w)
	}
	for accountID := range w.accounts {
		removeWake(x.byAccount, accountID, w)
	}
	w.folders, w.accounts = folders, accounts
	if x.byFolder == nil {
		x.byFolder = make(map[string]map[*sessionWake]struct{})
		x.byAccount = make(map[string]map[*sessionWake]struct{})
	}
	for _, folderID := range folders {
		addWake(x.byFolder, folderID, w)
	}
	for accountID := range accounts {
		addWake(x.byAccount, accountID, w)
	}
	return added
}

// changed wakes the registrations a commit concerns. folderIDs nil means
// any folder of accountID; an empty accountID means the owner is unknown,
// so every registration watching whole accounts is told about the folders.
func (x *wakeIndex) changed(accountID string, folderIDs []string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if folderIDs == nil {
		for w := range x.byAccount[accountID] {
			w.mark(nil, true)
		}
		return
	}
	for _, folderID := range folderIDs {
		for w := range x.byFolder[folderID] {
			w.mark([]string{folderID}, false)
		}
	}
	if accountID != "" {
		for w := range x.byAccount[accountID] {
			if w.accounts[accountID] {
				w.mark(folderIDs, false)
			}
		}
		return
	}
	for _, watchers := range x.byAccount {
		for w := range watchers {
			if watchesWholeAccount(w) {
				w.mark(folderIDs, false)
			}
		}
	}
}

func watchesWholeAccount(w *sessionWake) bool {
	for _, every := range w.accounts {
		if every {
			return true
		}
	}
	return false
}

// renamed wakes the registrations watching every folder of accountID to
// look for mailbox name and subscription changes.
func (x *wakeIndex) renamed(accountID string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for w := range x.byAccount[accountID] {
		if w.accounts[accountID] {
			w.mark(nil, true)
		}
	}
}

// registered reports the number of registrations.
func (x *wakeIndex) registered() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.count
}

func addWake(index map[string]map[*sessionWake]struct{}, key string, w *sessionWake) {
	if index[key] == nil {
		index[key] = make(map[*sessionWake]struct{})
	}
	index[key][w] = struct{}{}
}

func removeWake(index map[string]map[*sessionWake]struct{}, key string, w *sessionWake) {
	delete(index[key], w)
	if len(index[key]) == 0 {
		delete(index, key)
	}
}

// changesCommitted is the service.FolderChangeNotifier listener. It runs on
// the committing goroutine, so it only marks and signals.
func (s *Server) changesCommitted(accountID string, folderIDs []string) {
	s.wakes.changed(accountID, folderIDs)
}

// followCommits listens for the folder space's commits while any session is
// registered, and not otherwise, so a server with no waiting sessions (or one
// retired by a reconfiguration) costs committers nothing. With replace it
// moves an existing listener to the current configuration's folder space,
// adding the new listener before removing the old so no commit goes
// unannounced. It must not be called with wakes.mu held: the listener
// registry calls the listener under its own lock.
func (s *Server) followCommits(replace bool) {
	s.followMu.Lock()
	defer s.followMu.Unlock()
	want := s.wakes.registered() > 0
	if want == (s.unfollow != nil) && !(want && replace) {
		return
	}
	previous := s.unfollow
	s.unfollow = nil
	if want {
		if notifier, ok := s.cfg.Load().FolderSpace.(service.FolderChangeNotifier); ok {
			s.unfollow = notifier.OnChangesCommitted(s.changesCommitted)
		}
	}
	if previous != nil {
		previous()
	}
}

// wakeScope is what the session reports on right now: the selected mailbox
// while idling or under NOTIFY, and the user's whole account under NOTIFY.
func (s *Session) wakeScope() ([]string, map[string]bool) {
	if s.notify == nil && s.curState != stateIdle {
		return nil, nil
	}
	var folders []string
	accounts := make(map[string]bool)
	if s.selectedFolderID != "" && s.viewActive {
		folders = []string{s.selectedFolderID}
		// A shared mailbox's commits are announced under its owner.
		if owner := s.selectedFolder.UserID; owner != "" {
			accounts[owner] = false
		}
	}
	if s.notify != nil && s.userID != "" {
		accounts[s.userID] = true
	}
	if len(folders) == 0 && len(accounts) == 0 {
		return nil, nil
	}
	return folders, accounts
}

// refreshWake brings the session's registration in line with its state. A
// newly watched folder is checked once, covering changes made before the
// registration.
func (s *Session) refreshWake() {
	folders, accounts := s.wakeScope()
	if folders == nil && accounts == nil {
		s.dropWake()
		return
	}
	if s.wake == nil {
		s.wake = newSessionWake()
	}
	added := s.server.wakes.set(s.wake, folders, accounts)
	s.server.followCommits(false)
	if len(added) > 0 {
		s.wake.mark(added, false)
	}
}

// takeWake returns and clears the changes woken so far.
func (s *Session) takeWake() (map[string]struct{}, bool) {
	if s.wake == nil {
		return nil, false
	}
	return s.wake.take()
}

// dropWake removes the session's registration.
func (s *Session) dropWake() {
	if s.wake != nil {
		s.server.wakes.set(s.wake, nil, nil)
		s.server.followCommits(false)
		s.wake = nil
	}
	s.ownFolders, s.ownPaths = nil, nil
}

// wakeSignal is the channel that signals pending changes, nil when the
// session is not registered.
func (s *Session) wakeSignal() <-chan struct{} {
	if s.wake == nil {
		return nil
	}
	return s.wake.signal
}

// reportChanges reports what changed in the folders woken since the last
// check. The selected mailbox is synchronized while idling or when NOTIFY
// selects it; NOTIFY reports the other mailboxes from its snapshot.
func (s *Session) reportChanges() {
	if s.wake == nil {
		return
	}
	touched, all := s.wake.take()
	if !all && len(touched) == 0 {
		return
	}
	_, selectedTouched := touched[s.selectedFolderID]
	if (all || selectedTouched) && s.viewActive && (s.curState == stateIdle || s.notify.coversSelected()) {
		s.syncView(true)
		s.sendNewMessageAttrs()
	}
	if s.notify != nil {
		s.reportNotifyFolders(touched, all)
	}
	s.ownFolders, s.ownPaths = nil, nil
}

// publish records a change this session made to folder, which NOTIFY does
// not report back to it, and wakes the other sessions watching the folder.
// The folder space's commit notification normally woke them already; the
// second wake coalesces with it and covers folder spaces that announce
// nothing.
func (s *Session) publish(folder model.Folder) {
	if s.notify != nil {
		if s.ownFolders == nil {
			s.ownFolders = make(map[string]struct{})
		}
		s.ownFolders[folder.ID] = struct{}{}
	}
	s.server.wakes.changed(folder.UserID, []string{folder.ID})
}

// publishMailbox records a mailbox created, renamed, deleted, or
// (un)subscribed by this session, by path and previous path.
func (s *Session) publishMailbox(paths ...string) {
	if s.notify != nil {
		for _, path := range paths {
			if path != "" {
				s.ownPaths = append(s.ownPaths, path)
			}
		}
	}
	s.server.wakes.renamed(s.userID)
}

// ownPath reports whether this session itself changed path or a mailbox
// above it since the last check.
func (s *Session) ownPath(path string) bool {
	return slices.ContainsFunc(s.ownPaths, func(own string) bool { return pathWithin(path, own) })
}
