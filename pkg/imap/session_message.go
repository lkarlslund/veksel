package imap

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// cmdStore handles the STORE command (RFC 3501).
func (s *Session) cmdStore(tag string, args []string) {
	s.cmdStoreMode(tag, args, false)
}

// cmdCopy handles the COPY command (RFC 3501).
func (s *Session) cmdCopy(tag string, args []string) {
	if len(args) != 2 {
		s.sendBAD(tag, "Expected: COPY sequence-set mailbox")
		return
	}

	seqSet, err := parseSeqSet(args[0], s)
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid sequence set: %v", err))
		return
	}
	defer s.beginContentPass(len(seqSet))()

	destMailbox := args[1]
	destFolder, err := s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), destMailbox)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("[TRYCREATE] Mailbox %s does not exist", destMailbox))
		return
	}

	items, err := s.getSequenceItems()
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("COPY failed: %v", err))
		return
	}
	var newUIDs []uint32
	var originalUIDs []uint32
	for _, seq := range seqSet {
		if seq < 1 || seq > len(items) {
			continue
		}
		item, err := s.withContent(items[seq-1])
		if err != nil {
			continue
		}

		newItem, err := s.cfg.FolderSpace.CreateItem(*s.ctx, s.access(), destFolder.ID, service.ItemInput{
			Data: item.Data, Headers: item.Headers, InternalDate: item.InternalDate, Flags: copiedFlags(item.Flags),
		})
		if err != nil {
			s.sendOperationError(tag, "COPY", err)
			return
		}
		originalUIDs = append(originalUIDs, item.UID)
		newUIDs = append(newUIDs, newItem.UID)
	}

	if len(newUIDs) > 0 {
		s.publish(destFolder)
		s.sendOKCode(tag, fmt.Sprintf("COPYUID %d %s %s", destFolder.UIDValidity,
			formatUIDSet(originalUIDs), formatUIDSet(newUIDs)), "COPY completed")
		return
	}

	s.sendOK(tag, "COPY completed")
}

// cmdAppend handles APPEND and atomic MULTIAPPEND (RFC 3502).
// With BINARY (RFC 3516), literals are already read as exact bytes.
func (s *Session) cmdAppend(tag string, args []string) {
	if len(args) < 2 {
		s.sendBAD(tag, "Expected: APPEND mailbox 1*([flags] [date-time] literal)")
		return
	}

	mailbox := args[0]
	destFolder, err := s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), mailbox)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("[TRYCREATE] Mailbox %s does not exist", mailbox))
		return
	}

	descriptor := args[1:]
	inputs := make([]service.ItemInput, 0, 1)
	var totalSize int64
	for {
		flags, dateTime, literal, parseErr := parseAppendDescriptor(descriptor)
		if parseErr != nil {
			s.sendBAD(tag, parseErr.Error())
			return
		}
		if literal.utf8 && !s.utf8Accept {
			s.sendBAD(tag, "APPEND UTF8 requires ENABLE UTF8=ACCEPT")
			return
		}
		size, nonSynchronizing := literal.size, literal.nonSynchronizing
		maxLiteralSize := s.appendLiteralLimit()
		if size > maxLiteralSize || totalSize > maxLiteralSize-size {
			if nonSynchronizing {
				// RFC 7888 4: the literal is already on its way and
				// cannot be refused without reading it, so the
				// connection ends here; nothing is left to skip.
				s.sendBAD(tag, "Literal exceeds configured APPEND limit")
				s.unreadLiteral = unreadLiteral{}
				_ = s.conn.Close()
			} else {
				s.sendNO(tag, "[TOOBIG] Literal exceeds configured APPEND limit")
			}
			return
		}
		if !nonSynchronizing {
			s.sendContinuation("Ready")
		}
		s.unreadLiteral = unreadLiteral{}
		data := make([]byte, size)
		if _, err := io.ReadFull(s.rw.Reader, data); err != nil {
			s.sendNO(tag, fmt.Sprintf("Failed to read literal: %v", err))
			return
		}
		headers, _ := model.ParseMessageHeaders(data)
		if dateTime.IsZero() {
			dateTime = time.Now().UTC()
		}
		inputs = append(inputs, service.ItemInput{Data: data, Headers: headers, Flags: flags, InternalDate: dateTime})
		totalSize += size

		continuation, err := s.readLine()
		if err != nil {
			s.sendNO(tag, fmt.Sprintf("Failed to read APPEND continuation: %v", err))
			return
		}
		s.expectLiteral(continuation, maxLiteralSize-totalSize+maxCommandLineLength)
		if literal.utf8 {
			// RFC 6855 4: the UTF8 form closes its parenthesis after the
			// literal.
			rest, closed := strings.CutPrefix(continuation, ")")
			if !closed {
				s.sendBAD(tag, "Expected ) after APPEND UTF8 literal")
				return
			}
			continuation = rest
		}
		if strings.TrimSpace(continuation) == "" {
			break
		}
		descriptor = strings.Fields(strings.TrimSpace(continuation))
	}

	var items []model.Item
	if len(inputs) == 1 {
		item, createErr := s.cfg.FolderSpace.CreateItem(*s.ctx, s.access(), destFolder.ID, inputs[0])
		if createErr == nil {
			items = []model.Item{item}
		}
		err = createErr
	} else if creator, ok := s.cfg.FolderSpace.(service.FolderItemBatchCreator); ok {
		items, err = creator.CreateItems(*s.ctx, s.access(), destFolder.ID, inputs)
	} else {
		err = errors.New("atomic MULTIAPPEND is unavailable")
	}
	if err != nil {
		s.sendOperationError(tag, "APPEND", err)
		return
	}

	// A message appended to the selected mailbox is reported with EXISTS by
	// the view sync before the tagged completion.
	s.publish(destFolder)

	uids := make([]string, len(items))
	for index, item := range items {
		uids[index] = strconv.FormatUint(uint64(item.UID), 10)
	}
	s.sendOKCode(tag, fmt.Sprintf("APPENDUID %d %s", destFolder.UIDValidity, strings.Join(uids, ",")), "APPEND completed")
}

// appendLiteral is the message literal an APPEND descriptor announces.
type appendLiteral struct {
	size             int64
	nonSynchronizing bool
	// binary marks a literal8 ("~{n}", RFC 3516), whose octets may hold
	// NUL and are stored unmodified.
	binary bool
	// utf8 marks the RFC 6855 form "UTF8 (~{n})", allowed only after
	// ENABLE UTF8=ACCEPT; its closing parenthesis follows the literal.
	utf8 bool
}

func parseAppendDescriptor(tokens []string) (flags []string, dateTime time.Time, literal appendLiteral, err error) {
	if len(tokens) == 0 {
		return nil, time.Time{}, literal, errors.New("Expected APPEND literal descriptor")
	}
	idx := 0
	if strings.HasPrefix(tokens[idx], "(") && !strings.HasPrefix(tokens[idx], "(~{") {
		start := idx
		for idx < len(tokens) && !strings.HasSuffix(tokens[idx], ")") {
			idx++
		}
		if idx >= len(tokens) {
			return nil, time.Time{}, literal, errors.New("Unterminated APPEND flags")
		}
		flags = parseFlagsArg(strings.Join(tokens[start:idx+1], " "))
		idx++
	}
	if idx < len(tokens) && strings.EqualFold(tokens[idx], "BINARY") {
		idx++
	}
	if idx >= len(tokens) {
		return nil, time.Time{}, literal, errors.New("Expected APPEND literal size")
	}
	literalIndex := len(tokens) - 1
	token := tokens[literalIndex]
	if strings.HasPrefix(token, "(") {
		if literalIndex == idx || !strings.EqualFold(tokens[literalIndex-1], "UTF8") || !strings.HasPrefix(token, "(~{") {
			return nil, time.Time{}, literal, errors.New("Expected APPEND UTF8 (literal8)")
		}
		literal.utf8 = true
		token = token[1:]
		literalIndex--
	}
	if strings.HasPrefix(token, "~") {
		literal.binary = true
		token = token[1:]
	}
	literal.size, literal.nonSynchronizing, err = parseLiteralSize(token)
	if err != nil {
		return nil, time.Time{}, literal, fmt.Errorf("Invalid APPEND literal size: %w", err)
	}
	if idx < literalIndex {
		dateValue := strings.Trim(strings.Join(tokens[idx:literalIndex], " "), "\"")
		if !strings.EqualFold(dateValue, "NIL") && !strings.EqualFold(dateValue, "\\NIL") {
			dateTime, err = parseIMAPDateTime(dateValue)
			if err != nil {
				return nil, time.Time{}, literal, err
			}
		}
	}
	return flags, dateTime, literal, nil
}

func parseLiteralSize(token string) (size int64, nonSynchronizing bool, err error) {
	if len(token) < 3 || token[0] != '{' || token[len(token)-1] != '}' {
		return 0, false, errors.New("expected {size} or {size+}")
	}
	spec := token[1 : len(token)-1]
	if strings.HasSuffix(spec, "+") {
		nonSynchronizing = true
		spec = strings.TrimSuffix(spec, "+")
	}
	if spec == "" || strings.TrimSpace(spec) != spec {
		return 0, false, errors.New("invalid size")
	}
	size, err = strconv.ParseInt(spec, 10, 64)
	if err != nil || size < 0 {
		return 0, false, errors.New("invalid size")
	}
	return size, nonSynchronizing, nil
}

// cmdMove handles the MOVE command (RFC 6851).
// Atomically moves messages from the current mailbox to another.
func (s *Session) cmdMove(tag string, args []string) {
	if s.curState != stateSelected {
		s.sendBAD(tag, "No mailbox selected")
		return
	}

	if len(args) != 2 {
		s.sendBAD(tag, "Expected: MOVE sequence-set mailbox")
		return
	}

	seqSetStr := args[0]
	destMailbox := args[1]

	seqSet, err := parseSeqSet(seqSetStr, s)
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid sequence set: %v", err))
		return
	}

	destFolder, err := s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), destMailbox)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("[TRYCREATE] Mailbox %s does not exist", destMailbox))
		return
	}

	var newUIDs []uint32
	origUIDs := make([]string, 0, len(seqSet))
	expungeSeqs := make([]int, 0, len(seqSet))
	sequenceItems, err := s.getSequenceItems()
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("MOVE failed: %v", err))
		return
	}

	for _, seq := range seqSet {
		if seq < 1 || seq > len(sequenceItems) {
			continue
		}
		item := sequenceItems[seq-1]
		moved, err := s.cfg.FolderSpace.MoveItem(*s.ctx, s.access(), item.ID, destFolder.ID, item.ID+".eml")
		if err != nil {
			s.sendNO(tag, fmt.Sprintf("MOVE failed: %v", err))
			return
		}
		newUIDs = append(newUIDs, moved.UID)
		origUIDs = append(origUIDs, strconv.FormatUint(uint64(item.UID), 10))
		expungeSeqs = append(expungeSeqs, seq)
	}

	s.finishMove(tag, "MOVE", destFolder, origUIDs, newUIDs, expungeSeqs)
}

// cmdUIDMove handles UID MOVE.
func (s *Session) cmdUIDMove(tag string, args []string) {
	if s.curState != stateSelected {
		s.sendBAD(tag, "No mailbox selected")
		return
	}

	if len(args) != 2 {
		s.sendBAD(tag, "Expected: UID MOVE uid-set mailbox")
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
	expungeSeqs := make([]int, 0, len(uidSet))
	type selectedMoveItem struct {
		item model.Item
		seq  int
	}
	itemsToMove := make([]selectedMoveItem, 0, len(uidSet))
	selected, err := s.getSequenceItems()
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("UID MOVE failed: %v", err))
		return
	}
	sequences := sequenceNumbers(selected)
	for _, uidInt := range uidSet {
		if seq, ok := sequences[uint32(uidInt)]; ok {
			itemsToMove = append(itemsToMove, selectedMoveItem{item: selected[seq-1], seq: seq})
		}
	}

	for _, selected := range itemsToMove {
		item := selected.item
		moved, err := s.cfg.FolderSpace.MoveItem(*s.ctx, s.access(), item.ID, destFolder.ID, item.ID+".eml")
		if err != nil {
			s.sendNO(tag, fmt.Sprintf("UID MOVE failed: %v", err))
			return
		}
		newUIDs = append(newUIDs, moved.UID)
		origUIDs = append(origUIDs, strconv.FormatUint(uint64(item.UID), 10))
		expungeSeqs = append(expungeSeqs, selected.seq)
	}

	s.finishMove(tag, "UID MOVE", destFolder, origUIDs, newUIDs, expungeSeqs)
}

// finishMove completes MOVE and UID MOVE (RFC 6851 4.3): COPYUID goes in an
// untagged OK before the expunges, which the view sync reports (EXPUNGE, or
// VANISHED with QRESYNC) just before the tagged completion.
func (s *Session) finishMove(tag, command string, destFolder model.Folder, origUIDs []string, newUIDs []uint32, expungeSeqs []int) {
	if len(expungeSeqs) > 0 {
		s.publish(s.selectedFolder)
	}
	if len(newUIDs) > 0 {
		s.publish(destFolder)
		s.sendUntagged(fmt.Sprintf("* OK [COPYUID %d %s %s] Moved", destFolder.UIDValidity,
			strings.Join(origUIDs, ","), formatUIDSet(newUIDs)))
	}
	s.sendOK(tag, command+" completed")
}

// addFlagToItem adds a flag to an item.
func (s *Session) addFlagToItem(itemID string, flag string) {
	item, err := s.cfg.FolderSpace.GetItem(*s.ctx, s.access(), itemID)
	if err != nil || hasFlagInsensitive(item, flag) {
		return
	}
	_, _ = s.cfg.FolderSpace.SetFlags(*s.ctx, s.access(), itemID, append(item.Flags, flag))
}

func (s *Session) applyFlags(item model.Item, operation string, flags []string) (model.Item, error) {
	updated := append([]string(nil), item.Flags...)
	switch operation {
	case "+":
		for _, flag := range flags {
			if !hasFlagInsensitive(model.Item{Flags: updated}, flag) {
				updated = append(updated, flag)
			}
		}
	case "-":
		remove := make(map[string]struct{}, len(flags))
		for _, flag := range flags {
			remove[strings.ToLower(flag)] = struct{}{}
		}
		kept := updated[:0]
		for _, flag := range updated {
			if _, found := remove[strings.ToLower(flag)]; !found {
				kept = append(kept, flag)
			}
		}
		updated = kept
	default:
		updated = append([]string(nil), flags...)
	}
	return s.cfg.FolderSpace.SetFlags(*s.ctx, s.access(), item.ID, updated)
}
