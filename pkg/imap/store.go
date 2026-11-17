package imap

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
)

// storeRequest is a parsed STORE or UID STORE argument list:
//
//	[ "(" "UNCHANGEDSINCE" mod-sequence ")" ] ["+" / "-"] "FLAGS" [".SILENT"] flag-list
type storeRequest struct {
	operation      string // "+", "-", or "" to replace
	silent         bool
	flags          []string
	unchangedSince uint64
	conditional    bool
	ifModSeq       uint64 // legacy CONDSTORE draft guard
}

// parseStoreRequest parses the arguments after the message set. A malformed
// request is an error: it must never fall through to a FLAGS replacement,
// which used to wipe every flag of the message.
func parseStoreRequest(args []string) (storeRequest, error) {
	var request storeRequest
	text := strings.TrimSpace(strings.Join(args, " "))
	if index := strings.Index(strings.ToUpper(text), "IFMODSEQ"); index >= 0 {
		request.ifModSeq, text = extractIfModSeq(text[:index] + "IFMODSEQ" + text[index+len("IFMODSEQ"):])
	}
	if strings.HasPrefix(text, "(") {
		end := strings.IndexByte(text, ')')
		if end < 0 {
			return request, errors.New("unterminated STORE modifier list")
		}
		fields := strings.Fields(strings.ToUpper(text[1:end]))
		for index := 0; index < len(fields); index++ {
			if fields[index] != "UNCHANGEDSINCE" || index+1 >= len(fields) {
				return request, fmt.Errorf("unknown STORE modifier %q", fields[index])
			}
			index++
			value, err := strconv.ParseUint(fields[index], 10, 63)
			if err != nil {
				return request, fmt.Errorf("invalid UNCHANGEDSINCE value %q", fields[index])
			}
			request.unchangedSince, request.conditional = value, true
		}
		text = strings.TrimSpace(text[end+1:])
	}
	name, rest, _ := strings.Cut(text, " ")
	switch strings.ToUpper(name) {
	case "FLAGS", "FLAGS.SILENT":
	case "+FLAGS", "+FLAGS.SILENT":
		request.operation = "+"
	case "-FLAGS", "-FLAGS.SILENT":
		request.operation = "-"
	default:
		return request, fmt.Errorf("unknown STORE data item %q", name)
	}
	request.silent = strings.HasSuffix(strings.ToUpper(name), ".SILENT")
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "(") {
		if !strings.HasSuffix(rest, ")") {
			return request, errors.New("unterminated flag list")
		}
		rest = rest[1 : len(rest)-1]
	}
	for _, flag := range strings.Fields(rest) {
		if strings.HasPrefix(flag, `\`) {
			canonical, ok := systemFlagCase[strings.ToUpper(flag)]
			if !ok || canonical == model.FlagRecent {
				return request, fmt.Errorf("invalid flag %q", flag)
			}
			flag = canonical
		} else if strings.ContainsAny(flag, `(){%*"]`) {
			return request, fmt.Errorf("invalid keyword %q", flag)
		}
		request.flags = append(request.flags, flag)
	}
	return request, nil
}

// storeTarget is one message addressed by STORE: its sequence number in the
// session and its listing.
type storeTarget struct {
	seq  int
	item model.Item
}

// cmdStoreMode implements STORE and UID STORE (RFC 3501 6.4.6, RFC 7162).
func (s *Session) cmdStoreMode(tag string, args []string, uid bool) {
	command := "STORE"
	if uid {
		command = "UID STORE"
	}
	if s.readOnly {
		s.sendNO(tag, "Mailbox is read-only")
		return
	}
	if len(args) < 3 {
		s.sendBAD(tag, "Expected: "+command+" set [(UNCHANGEDSINCE n)] item flags")
		return
	}
	request, err := parseStoreRequest(args[1:])
	if err != nil {
		s.sendBAD(tag, "Invalid "+command+": "+err.Error())
		return
	}
	if request.conditional {
		s.condstoreEnabled = true
	}
	var numbers []int
	if uid {
		numbers, err = parseUIDSet(args[0], s)
	} else {
		numbers, err = parseSeqSet(args[0], s)
	}
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid message set: %v", err))
		return
	}
	items, err := s.getSequenceItems()
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("%s failed: %v", command, err))
		return
	}
	targets := make([]storeTarget, 0, len(numbers))
	if uid {
		sequences := sequenceNumbers(items)
		for _, number := range numbers {
			if seq, ok := sequences[uint32(number)]; ok {
				targets = append(targets, storeTarget{seq: seq, item: items[seq-1]})
			}
		}
	} else {
		for _, seq := range numbers {
			if seq >= 1 && seq <= len(items) {
				targets = append(targets, storeTarget{seq: seq, item: items[seq-1]})
			}
		}
	}

	var modified []uint32
	for _, target := range targets {
		item := target.item
		if s.expungedPending(item.UID) {
			continue
		}
		if request.ifModSeq > 0 && item.ModSeq > request.ifModSeq {
			continue
		}
		if request.conditional && item.ModSeq > request.unchangedSince {
			// RFC 7162 3.1.3: leave the message alone and report it in the
			// MODIFIED response code.
			if uid {
				modified = append(modified, item.UID)
			} else {
				modified = append(modified, uint32(target.seq))
			}
			continue
		}
		updated, err := s.applyFlags(item, request.operation, request.flags)
		if err != nil {
			s.sendOperationError(tag, command, err)
			return
		}
		s.publish(s.selectedFolder)
		// The client made this change (and was told unless it asked for
		// .SILENT), so the next sync must not report it again.
		s.updateViewItem(target.seq, updated)
		if request.silent && !request.conditional {
			continue
		}
		response := fmt.Sprintf("* %d FETCH (UID %d", target.seq, updated.UID)
		if !request.silent {
			response += " FLAGS " + formatFlags(updated.Flags)
		}
		if s.condstoreEnabled {
			response += fmt.Sprintf(" MODSEQ (%d)", updated.ModSeq)
		}
		s.sendUntagged(response + ")")
	}
	if len(modified) > 0 {
		s.sendOKCode(tag, "MODIFIED "+formatUIDSet(modified), "Conditional "+command+" failed for some messages")
		return
	}
	s.sendOK(tag, command+" completed")
}

// copiedFlags returns the flags a COPY carries to the new message: RFC 3501
// 6.4.7 preserves flags, except \Recent, which is set by the destination.
func copiedFlags(flags []string) []string {
	copied := make([]string, 0, len(flags))
	for _, flag := range flags {
		if !strings.EqualFold(flag, model.FlagRecent) {
			copied = append(copied, flag)
		}
	}
	return copied
}
