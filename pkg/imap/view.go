package imap

import (
	"fmt"
	"slices"
	"sort"

	"github.com/lkarlslund/veksel/pkg/model"
)

// The mailbox view is the selected mailbox as the client knows it: the
// messages it was told about, in sequence order, with the metadata last
// reported. Message sequence numbers in commands refer to this view, never
// to the live mailbox, and changes made elsewhere (delivery, other
// sessions, other protocols) reach the client as EXISTS, EXPUNGE (or
// VANISHED with QRESYNC), and FETCH FLAGS responses at the points RFC 3501
// 7.4.1 allows: before the tagged completion of a command, and during IDLE.
// Before the view existed every command used the live listing, so a client
// polling with NOOP never heard of new mail and a message expunged by
// another session silently renumbered the rest.

// setView starts a view from the listing SELECT or EXAMINE reported.
func (s *Session) setView(items []model.Item) {
	s.view = make([]model.Item, len(items))
	for index, item := range items {
		s.view[index] = viewEntry(item)
	}
	s.viewActive = true
	s.viewPending = nil
}

// clearView ends the view when the mailbox is closed.
func (s *Session) clearView() {
	s.view, s.viewActive, s.viewPending = nil, false, nil
}

// viewEntry keeps the metadata a view needs, never message content.
func viewEntry(item model.Item) model.Item {
	item.Data = nil
	return item
}

// viewItems maps the live listing onto the view. A message expunged since
// the client was last told keeps its sequence position, with its last known
// metadata, until the expunge is reported; viewPending lists those UIDs so
// commands skip them.
func (s *Session) viewItems(live []model.Item) []model.Item {
	byUID := make(map[uint32]model.Item, len(live))
	for _, item := range live {
		byUID[item.UID] = item
	}
	items := make([]model.Item, len(s.view))
	s.viewPending = nil
	for index, known := range s.view {
		if item, ok := byUID[known.UID]; ok {
			items[index] = item
			continue
		}
		items[index] = known
		if s.viewPending == nil {
			s.viewPending = make(map[uint32]struct{})
		}
		s.viewPending[known.UID] = struct{}{}
	}
	return items
}

// expungedPending reports whether uid is expunged but not yet reported.
func (s *Session) expungedPending(uid uint32) bool {
	_, pending := s.viewPending[uid]
	return pending
}

// updateViewItem records metadata this session already reported, such as
// the flags in a STORE response, so the next sync does not repeat it. seq is
// the message's sequence number in the view, checked before searching, so a
// STORE over the whole mailbox stays linear.
func (s *Session) updateViewItem(seq int, item model.Item) {
	if !s.viewActive {
		return
	}
	if seq >= 1 && seq <= len(s.view) && s.view[seq-1].UID == item.UID {
		s.view[seq-1] = viewEntry(item)
		return
	}
	for index := range s.view {
		if s.view[index].UID == item.UID {
			s.view[index] = viewEntry(item)
			return
		}
	}
}

// viewSyncCommands lists the commands whose completion does not report
// mailbox changes: selection changes replace the view, and FETCH, STORE,
// and SEARCH must not be answered with EXPUNGE (RFC 3501 7.4.1), nor SORT
// and THREAD, which also return sequence numbers (RFC 5256). Their UID
// forms may carry it.
var viewSyncSkipped = map[string]bool{"": true, "SELECT": true, "EXAMINE": true, "UNSELECT": true, "CLOSE": true, "LOGOUT": true}
var viewSyncNoExpunge = map[string]bool{"FETCH": true, "STORE": true, "SEARCH": true, "SORT": true, "THREAD": true}

// syncBeforeCompletion reports mailbox changes before the tagged completion
// of the current command.
func (s *Session) syncBeforeCompletion() {
	if !s.viewActive || s.viewSyncing || viewSyncSkipped[s.commandName] {
		return
	}
	s.syncView(!viewSyncNoExpunge[s.commandName])
}

// syncView compares the view with the live mailbox and reports the
// difference: expunges first (highest sequence first, so no renumbering is
// needed, or one VANISHED with QRESYNC), then flag changes, then new
// messages with EXISTS. Expunges are held back when not allowed.
func (s *Session) syncView(allowExpunge bool) {
	if !s.viewActive || s.viewSyncing {
		return
	}
	s.viewSyncing = true
	defer func() { s.viewSyncing = false }()
	live, err := s.loadItems()
	if err != nil {
		return
	}
	byUID := make(map[uint32]model.Item, len(live))
	for _, item := range live {
		byUID[item.UID] = item
	}

	if allowExpunge {
		var vanished []uint32
		kept := make([]model.Item, 0, len(s.view))
		for index := len(s.view) - 1; index >= 0; index-- {
			known := s.view[index]
			if _, ok := byUID[known.UID]; ok {
				kept = append(kept, known)
				continue
			}
			if s.qresyncEnabled {
				vanished = append(vanished, known.UID)
			} else {
				s.sendUntagged(fmt.Sprintf("* %d EXPUNGE", index+1))
			}
		}
		slices.Reverse(kept)
		s.view = kept
		if len(vanished) > 0 {
			sort.Slice(vanished, func(i, j int) bool { return vanished[i] < vanished[j] })
			s.sendUntagged("* VANISHED " + formatUIDSet(vanished))
		}
		s.viewPending = nil
	}

	known := make(map[uint32]struct{}, len(s.view))
	for index, entry := range s.view {
		known[entry.UID] = struct{}{}
		item, ok := byUID[entry.UID]
		if !ok {
			continue
		}
		if item.ModSeq != entry.ModSeq && formatFlags(item.Flags) != formatFlags(entry.Flags) {
			response := fmt.Sprintf("* %d FETCH (UID %d FLAGS %s", index+1, item.UID, formatFlags(item.Flags))
			if s.condstoreEnabled {
				response += fmt.Sprintf(" MODSEQ (%d)", item.ModSeq)
			}
			s.sendUntagged(response + ")")
		}
		s.view[index] = viewEntry(item)
	}

	added := 0
	for _, item := range live {
		if _, ok := known[item.UID]; !ok {
			s.view = append(s.view, viewEntry(item))
			added++
		}
	}
	if added > 0 {
		s.sendUntagged(fmt.Sprintf("* %d EXISTS", len(s.view)))
		if !s.rev2Enabled {
			recent := 0
			for _, entry := range s.view {
				if slices.Contains(entry.Flags, model.FlagRecent) {
					recent++
				}
			}
			s.sendUntagged(fmt.Sprintf("* %d RECENT", recent))
		}
	}
}
