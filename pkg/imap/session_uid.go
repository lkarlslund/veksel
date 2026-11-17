package imap

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// cmdUID handles the UID command prefix (RFC 3501).
func (s *Session) cmdUID(tag string, args []string) {
	if len(args) < 1 {
		s.sendBAD(tag, "Expected: UID command args")
		return
	}

	subCmd := strings.ToUpper(args[0])
	subArgs := args[1:]

	switch subCmd {
	case "FETCH":
		s.cmdUIDFetch(tag, subArgs)
	case "STORE":
		s.cmdUIDStore(tag, subArgs)
	case "SEARCH":
		s.cmdUIDSearch(tag, subArgs)
	case "SORT":
		s.cmdSortMode(tag, subArgs, true)
	case "THREAD":
		s.cmdThreadMode(tag, subArgs, true)
	case "COPY":
		s.cmdUIDCopy(tag, subArgs)
	case "EXPUNGE":
		s.cmdUIDExpunge(tag, subArgs)
	case "MOVE":
		s.cmdUIDMove(tag, subArgs)
	default:
		s.sendBAD(tag, fmt.Sprintf("UID %s not implemented", args[0]))
	}
}

// cmdUIDFetch handles UID FETCH.
// With CONDSTORE (RFC 4551), supports IFMODSEQ guards.
func (s *Session) cmdUIDFetch(tag string, args []string) {
	if len(args) < 2 {
		s.sendBAD(tag, "Expected: UID FETCH uid-set macro/section")
		return
	}

	uidSet, err := parseUIDSet(args[0], s)
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid UID set: %v", err))
		return
	}
	defer s.beginContentPass(len(uidSet))()

	fetchAttrs := strings.ToUpper(strings.Join(args[1:], " "))
	// Extract IFMODSEQ guard if present
	ifModSeq, attrsNoGuard := extractIfModSeq(fetchAttrs)
	attrsNoGuard, modifierText := splitFetchModifiers(attrsNoGuard)
	modifiers, err := parseFetchModifiers(modifierText)
	if err != nil {
		s.sendBAD(tag, "Invalid FETCH modifier: "+err.Error())
		return
	}
	if modifiers.vanished && (!s.qresyncEnabled || !modifiers.hasChangedSince) {
		s.sendBAD(tag, "VANISHED requires ENABLE QRESYNC and CHANGEDSINCE")
		return
	}
	changedSince := modifiers.changedSince
	attrsNoGuard = s.prepareFetchItems(attrsNoGuard, true, modifiers.hasChangedSince)
	s.loadStoredPreviews(attrsNoGuard)
	items, err := s.getSequenceItems()
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("UID FETCH failed: %v", err))
		return
	}
	if modifiers.vanished {
		s.sendFetchVanished(args[0], changedSince, items)
	}
	byUID := make(map[uint32]int, len(items))
	for index, item := range items {
		byUID[item.UID] = index
	}

	for _, uidInt := range uidSet {
		uid := uint32(uidInt)
		index, ok := byUID[uid]
		if !ok {
			continue
		}
		item, seq := items[index], index+1
		if s.expungedPending(item.UID) {
			continue
		}

		if ifModSeq > 0 && item.ModSeq > ifModSeq {
			continue
		}
		if changedSince > 0 && item.ModSeq <= changedSince {
			continue
		}

		if !s.readOnly && fetchSetsSeen(attrsNoGuard) {
			s.addFlagToItem(item.ID, model.FlagSeen)
		}

		if err := s.fetchItem(seq, item, attrsNoGuard); err != nil {
			s.sendFetchError(tag, err)
			return
		}
	}

	s.sendOK(tag, "UID FETCH completed")
}

// cmdUIDStore handles UID STORE.
func (s *Session) cmdUIDStore(tag string, args []string) {
	s.cmdStoreMode(tag, args, true)
}

// cmdUIDCopy handles UID COPY.
func (s *Session) cmdUIDCopy(tag string, args []string) {
	if len(args) != 2 {
		s.sendBAD(tag, "Expected: UID COPY uid-set mailbox")
		return
	}

	uidSet, err := parseUIDSet(args[0], s)
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid UID set: %v", err))
		return
	}

	destMailbox := args[1]
	destFolder, err := s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), destMailbox)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("[TRYCREATE] Mailbox %s does not exist", destMailbox))
		return
	}

	var newUIDs []uint32
	origUIDs := make([]string, 0, len(uidSet))

	for _, uidInt := range uidSet {
		uid := uint32(uidInt)
		item, err := s.cfg.FolderSpace.GetItemByUID(*s.ctx, s.access(), s.selectedFolderID, uid)
		if err != nil {
			continue
		}

		newItem, err := s.cfg.FolderSpace.CreateItem(*s.ctx, s.access(), destFolder.ID, service.ItemInput{
			Data: item.Data, Headers: item.Headers, InternalDate: item.InternalDate, Flags: copiedFlags(item.Flags),
		})
		if err != nil {
			s.sendOperationError(tag, "UID COPY", err)
			return
		}
		newUIDs = append(newUIDs, newItem.UID)
		origUIDs = append(origUIDs, strconv.FormatUint(uint64(uid), 10))
	}

	if len(newUIDs) > 0 {
		s.publish(destFolder)
		s.sendOKCode(tag, fmt.Sprintf("COPYUID %d %s %s", destFolder.UIDValidity,
			strings.Join(origUIDs, ","), formatUIDSet(newUIDs)), "UID COPY completed")
		return
	}

	s.sendOK(tag, "UID COPY completed")
}

// cmdUIDExpunge handles UID EXPUNGE (RFC 4315).
func (s *Session) cmdUIDExpunge(tag string, args []string) {
	if len(args) != 1 {
		s.sendBAD(tag, "Expected: UID EXPUNGE uid-set")
		return
	}

	uidSet, err := parseUIDSet(args[0], s)
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid UID set: %v", err))
		return
	}

	items, err := s.getSequenceItems()
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("UID EXPUNGE failed: %v", err))
		return
	}
	sequences := sequenceNumbers(items)
	// RFC 4315 2.1: only messages with \Deleted are removed. The view sync
	// reports them (EXPUNGE, or VANISHED with QRESYNC) before completion.
	for _, uidInt := range uidSet {
		uid := uint32(uidInt)
		listed, ok := sequences[uid]
		if !ok || s.expungedPending(uid) {
			continue
		}
		item := items[listed-1]
		if !hasFlagInsensitive(item, model.FlagDeleted) {
			continue
		}
		if err := s.cfg.FolderSpace.DeleteItem(*s.ctx, s.access(), item.ID); err != nil {
			continue
		}
		s.publish(s.selectedFolder)
	}

	s.sendOK(tag, "UID EXPUNGE completed")
}
