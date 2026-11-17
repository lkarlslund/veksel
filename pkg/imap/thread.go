package imap

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/threading"
)

// threadAlgorithm identifies the THREAD algorithm (RFC 5256 §2).
type threadAlgorithm int

const (
	threadReferences threadAlgorithm = iota
	threadOrderedSubject
	threadFlat
)

// cmdThread handles the THREAD command (RFC 5256).
//
// THREAD {REFERENCES|ORDEREDSUBJECT mailbox|FLAT} search-criteria
func (s *Session) cmdThread(tag string, args []string) {
	s.cmdThreadMode(tag, args, false)
}

func (s *Session) cmdThreadMode(tag string, args []string, uid bool) {
	if s.curState != stateSelected {
		s.sendBAD(tag, "No mailbox selected")
		return
	}

	if len(args) < 2 {
		s.sendBAD(tag, "Expected: THREAD algorithm charset search-criteria")
		return
	}

	algorithm := strings.ToUpper(args[0])
	charset := "UTF-8"
	rest := args[1:]
	if strings.EqualFold(args[1], "UTF-8") || strings.EqualFold(args[1], "US-ASCII") {
		charset = args[1]
		rest = args[2:]
	} else if algorithm == "ORDEREDSUBJECT" && len(args) >= 3 {
		// Retain the historical Veksel mailbox argument as rev1 compatibility.
		rest = args[2:]
	}
	_ = charset
	if len(rest) == 0 {
		s.sendBAD(tag, "THREAD requires search criteria")
		return
	}

	var algo threadAlgorithm
	switch algorithm {
	case "REFERENCES":
		algo = threadReferences
	case "ORDEREDSUBJECT":
		algo = threadOrderedSubject
	case "FLAT":
		algo = threadFlat
	default:
		s.sendBAD(tag, fmt.Sprintf("Unknown THREAD algorithm: %s", algorithm))
		return
	}

	// Parse search criteria
	criteria, err := parseSearchCriteria(rest)
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid SEARCH criteria: %v", err))
		return
	}
	hydrateSavedSearchCriteria(criteria, s.savedSearchUIDs)

	// Get all items in the folder
	items, err := s.getSequenceItems()
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("THREAD failed: %v", err))
		return
	}

	// Filter by search criteria
	matches, err := s.matchItems(items, criteria)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("THREAD failed: %v", err))
		return
	}
	matching := make([]model.Item, len(matches))
	for position, index := range matches {
		matching[position] = items[index]
	}

	// Build threads
	var threads [][]uint32 // each thread is a list of UIDs in receipt order

	switch algo {
	case threadReferences:
		threads = buildReferenceThreads(matching)
	case threadOrderedSubject:
		threads = buildOrderedSubjectThreads(matching, "")
	case threadFlat:
		threads = buildFlatThread(matching)
	}

	if !uid {
		sequences := sequenceNumbers(items)
		for threadIndex := range threads {
			for itemIndex, messageUID := range threads[threadIndex] {
				threads[threadIndex][itemIndex] = uint32(sequences[messageUID])
			}
		}
	}
	uidSets := make([]string, len(threads))
	for i, thread := range threads {
		uids := make([]string, len(thread))
		for j, uid := range thread {
			uids[j] = strconv.FormatUint(uint64(uid), 10)
		}
		uidSets[i] = "(" + strings.Join(uids, " ") + ")"
	}

	response := "* THREAD"
	if len(uidSets) > 0 {
		response += " " + strings.Join(uidSets, " ")
	}
	s.sendUntagged(response)
	s.sendOK(tag, "THREAD completed")
}

// buildReferenceThreads builds conversation threads from References and
// In-Reply-To headers (RFC 5256 §2, THREAD REFERENCES) through the shared
// threading package; each thread lists UIDs oldest first.
func buildReferenceThreads(items []model.Item) [][]uint32 {
	messages := make([]threading.Message, len(items))
	for index, item := range items {
		messages[index] = threading.Message{ID: threading.CanonicalID(getMessageID(item)), Parents: threading.Parents(getReferences(item), getInReplyTo(item)), Date: item.InternalDate}
	}
	var threads [][]uint32
	for _, members := range threading.Build(messages, threading.Options{}) {
		thread := make([]uint32, len(members))
		for position, index := range members {
			thread[position] = items[index].UID
		}
		threads = append(threads, thread)
	}
	return threads
}

// buildOrderedSubjectThreads builds threads based on subject prefix within a
// mailbox (RFC 5256 §2, THREAD ORDEREDSUBJECT).
//
// Messages are grouped by their "base subject" (subject with Re:/Fw: prefixes
// stripped), then sorted within each group by date.
func buildOrderedSubjectThreads(items []model.Item, _ string) [][]uint32 {
	if len(items) == 0 {
		return nil
	}

	// Group by base subject
	groups := make(map[string][]model.Item)
	for _, item := range items {
		subject := getSubject(item)
		base := threading.BaseSubject(subject)
		groups[base] = append(groups[base], item)
	}

	// Sort each group by InternalDate (receipt order)
	var threads [][]uint32
	for _, group := range groups {
		sort.Slice(group, func(i, j int) bool {
			return group[i].InternalDate.Before(group[j].InternalDate)
		})
		var thread []uint32
		for _, item := range group {
			thread = append(thread, item.UID)
		}
		threads = append(threads, thread)
	}

	// Sort threads by the first UID for deterministic output
	sort.Slice(threads, func(i, j int) bool {
		return threads[i][0] < threads[j][0]
	})

	return threads
}

// buildFlatThread returns a flat list sorted by thread order (RFC 5256 §2,
// THREAD FLAT). This is essentially a SEARCH with results sorted by
// threading — messages that belong to the same thread are grouped together.
func buildFlatThread(items []model.Item) [][]uint32 {
	if len(items) == 0 {
		return nil
	}

	// Sort all items by InternalDate (receipt order)
	sort.Slice(items, func(i, j int) bool {
		return items[i].InternalDate.Before(items[j].InternalDate)
	})

	var thread []uint32
	for _, item := range items {
		thread = append(thread, item.UID)
	}

	return [][]uint32{thread}
}

// --- Header extraction helpers ---

// getMessageID returns the Message-ID header value.
func getMessageID(item model.Item) string { return getHeaderValue(item, "Message-Id") }

// getInReplyTo returns the In-Reply-To header value.
func getInReplyTo(item model.Item) string { return getHeaderValue(item, "In-Reply-To") }

// getSubject returns the Subject header value.
func getSubject(item model.Item) string { return getHeaderValue(item, "Subject") }

// parseReferences returns the list of Message-IDs from the References header.
func parseReferences(item model.Item) []string {
	return threading.ParseIDs(getReferences(item))
}

// getReferences returns the raw References header value.
func getReferences(item model.Item) string { return getHeaderValue(item, "References") }

// headersStored reports whether item's stored header map holds the parsed
// header block of the message: every message parsed on arrival has at least
// one of these fields, while items created from partial input (for example a
// subject only) do not.
func headersStored(item model.Item) bool {
	for _, name := range []string{"Message-Id", "From", "Date"} {
		for key := range item.Headers {
			if strings.EqualFold(key, name) {
				return true
			}
		}
	}
	return false
}

// extractHeaderFromData parses a specific header from raw message data.
func extractHeaderFromData(data []byte, headerName string) string {
	headers := extractHeaders(data)
	headerKey := strings.ToLower(headerName) + ":"
	headerText := strings.ToLower(string(headers))

	idx := strings.Index(headerText, headerKey)
	if idx < 0 {
		return ""
	}

	// Move past the header key
	pos := idx + len(headerKey)

	// Collect the header value, handling continuation lines
	var result strings.Builder
	for pos < len(headerText) {
		// Find the end of this line
		end := strings.Index(headerText[pos:], "\n")
		if end < 0 {
			end = len(headerText) - pos
		}

		line := strings.TrimSpace(headerText[pos : pos+end])
		if line != "" {
			result.WriteString(line)
		}

		// Move to the next line
		pos += end + 1 // +1 to skip the \n

		// Check for continuation (line starts with space or tab)
		if pos < len(headerText) && (headerText[pos] == ' ' || headerText[pos] == '\t') {
			if result.Len() > 0 {
				result.WriteString(" ")
			}
			continue
		}

		break
	}

	return strings.TrimSpace(result.String())
}
