package eas

import (
	"encoding/json"

	"github.com/lkarlslund/veksel/pkg/service"
)

// Echo is one change the device made itself. Its journal entries are not
// reported back to the device; later changes by others still are, which
// is why an echo is bounded by the item's mod-sequence after the device's
// change, or marks the device's removal of the item from the collection.
type Echo struct {
	ID      string `json:"id"`
	ModSeq  uint64 `json:"mod_seq,omitempty"`
	Removed bool   `json:"removed,omitempty"`
}

// UnmarshalJSON also accepts a bare item ID, the form earlier builds of
// the partnership state stored.
func (e *Echo) UnmarshalJSON(data []byte) error {
	var id string
	if err := json.Unmarshal(data, &id); err == nil {
		*e = Echo{ID: id}
		return nil
	}
	type plain Echo
	return json.Unmarshal(data, (*plain)(e))
}

// beforeEchoHook, when set by a test, runs after the device's mutation and
// before its echo is recorded.
var beforeEchoHook func(id string)

// maxEchoes bounds the remembered own changes per collection; a device
// that stops synchronizing a collection must not grow its state forever.
const maxEchoes = 2000

// addEcho records the device's own change, replacing an older echo of the
// same item.
func (s *DeviceState) addEcho(folderID string, echo Echo) {
	echoes := s.CollectionEchoes[folderID]
	for index := range echoes {
		if echoes[index].ID == echo.ID {
			echoes[index] = echo
			return
		}
	}
	echoes = append(echoes, echo)
	if excess := len(echoes) - maxEchoes; excess > 0 {
		echoes = echoes[excess:]
	}
	s.CollectionEchoes[folderID] = echoes
}

type echoSet map[string]Echo

func newEchoSet(echoes []Echo) echoSet {
	set := make(echoSet, len(echoes))
	for _, echo := range echoes {
		set[echo.ID] = echo
	}
	return set
}

func removesFrom(change service.Change, folderID string) bool {
	return change.Operation == service.ChangeDestroy || change.Operation == service.ChangeTrash ||
		change.Operation == service.ChangeMove && change.FolderID != folderID
}

// suppresses reports whether change is the device's own effect.
func (set echoSet) suppresses(change service.Change, folderID string) bool {
	echo, ok := set[change.ID]
	if !ok {
		return false
	}
	if echo.Removed {
		return removesFrom(change, folderID)
	}
	if removesFrom(change, folderID) {
		return false
	}
	return change.ModSeq == 0 || change.ModSeq <= echo.ModSeq
}

// pendingIDs lists, in journal order, the items with changes the device
// has not made itself. An item the device removed from the collection is
// left out entirely: later edits of it no longer concern this collection.
func (set echoSet) pendingIDs(page service.ChangePage, folderID string) []string {
	removed := map[string]bool{}
	listed := map[string]bool{}
	var order []string
	for _, record := range page.Records {
		for _, change := range record.Changes {
			if change.Object != "" && change.Object != service.ChangeObjectItem {
				continue
			}
			if set.suppresses(change, folderID) {
				if removesFrom(change, folderID) {
					removed[change.ID] = true
				}
				continue
			}
			if !listed[change.ID] {
				listed[change.ID] = true
				order = append(order, change.ID)
			}
		}
	}
	pending := order[:0]
	for _, id := range order {
		if !removed[id] {
			pending = append(pending, id)
		}
	}
	return pending
}

// forgetEchoes drops the echoes whose own journal entries the page holds.
// A page truncated by the window may mention an item only through an
// earlier entry; its echo is kept until the entry at or past the echo's
// mod-sequence (or, for a removal, the removing entry) has been read.
func forgetEchoes(echoes []Echo, page service.ChangePage, folderID string) []Echo {
	type seen struct {
		removed   bool
		modSeq    uint64
		unbounded bool
	}
	read := map[string]*seen{}
	for _, record := range page.Records {
		for _, change := range record.Changes {
			entry := read[change.ID]
			if entry == nil {
				entry = &seen{}
				read[change.ID] = entry
			}
			switch {
			case removesFrom(change, folderID):
				entry.removed = true
			case change.ModSeq == 0:
				entry.unbounded = true
			default:
				entry.modSeq = max(entry.modSeq, change.ModSeq)
			}
		}
	}
	covered := func(echo Echo) bool {
		entry := read[echo.ID]
		switch {
		case entry == nil:
			return false
		case echo.Removed:
			return entry.removed
		case echo.ModSeq == 0:
			return true
		default:
			return entry.removed || entry.unbounded || entry.modSeq >= echo.ModSeq
		}
	}
	kept := echoes[:0:0]
	for _, echo := range echoes {
		if !covered(echo) {
			kept = append(kept, echo)
		}
	}
	return kept
}
