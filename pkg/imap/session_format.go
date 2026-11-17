package imap

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// formatFlags formats IMAP flags for a response.
func formatFlags(flags []string) string {
	if len(flags) == 0 {
		return "()"
	}
	return "(" + strings.Join(flags, " ") + ")"
}

func formatUIDSet(uids []uint32) string {
	values := make([]int, len(uids))
	for index, uid := range uids {
		values[index] = int(uid)
	}
	return compactNumberSet(values)
}

// formatInternalDate formats a time as an IMAP internal date.
func formatInternalDate(t time.Time) string {
	return "\"" + t.UTC().Format("02") + "-" + t.UTC().Format("Jan") + "-" + t.UTC().Format("2006") + " " +
		t.UTC().Format("15:04:05") + " " + formatTimezone(t.UTC()) + "\""
}

// formatTimezone formats the timezone offset.
func formatTimezone(t time.Time) string {
	_, offset := t.Zone()
	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	hours := offset / 3600
	mins := (offset % 3600) / 60
	return fmt.Sprintf("%s%04d", sign, hours*100+mins)
}

// parseIMAPDateTime parses an IMAP date-time string.
func parseIMAPDateTime(s string) (time.Time, error) {
	// Try common formats
	formats := []string{
		"02-Jan-2006 15:04:05 -0700",
		"02-Jan-2006 15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid IMAP date-time: %q", s)
}

// parseFlagsArg parses a flags argument like "(\\Seen \\Flagged)" or "\\Seen".
func parseFlagsArg(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "()")
	return strings.Fields(s)
}

// systemFlagCase maps the upper-cased RFC 3501 system flags to the spelling
// used by the rest of Veksel (model.Flag*).
var systemFlagCase = map[string]string{
	`\SEEN`: model.FlagSeen, `\ANSWERED`: model.FlagAnswered, `\FLAGGED`: model.FlagFlagged,
	`\DELETED`: model.FlagDeleted, `\DRAFT`: model.FlagDraft, `\RECENT`: model.FlagRecent,
}

// parseSeqSet parses an IMAP sequence set. A bare * is the largest current
// sequence number; it does not mean the whole mailbox (1:* does).
func parseSeqSet(s string, sess *Session) ([]int, error) {
	return parseMessageSet(s, sess, false)
}

func parseUIDSet(s string, sess *Session) ([]int, error) {
	return parseMessageSet(s, sess, true)
}

func parseMessageSet(s string, sess *Session, uid bool) ([]int, error) {
	if s == "$" {
		if !sess.savedSearchSet {
			return nil, errors.New("no saved SEARCH result")
		}
		result := make([]int, 0, len(sess.savedSearchUIDs))
		if uid {
			for _, savedUID := range sess.savedSearchUIDs {
				result = append(result, int(savedUID))
			}
			return result, nil
		}
		items, err := sess.getSequenceItems()
		if err != nil {
			return nil, err
		}
		sequences := sequenceNumbers(items)
		for _, savedUID := range sess.savedSearchUIDs {
			if sequence, ok := sequences[savedUID]; ok {
				result = append(result, sequence)
			}
		}
		return result, nil
	}
	items, err := sess.getSequenceItems()
	if err != nil {
		return nil, err
	}
	if !uid {
		return resolveMessageSet(s, len(items), nil)
	}
	uids := make([]int, len(items))
	maximum := 0
	for index, item := range items {
		uids[index] = int(item.UID)
		maximum = max(maximum, int(item.UID))
	}
	slices.Sort(uids)
	return resolveMessageSet(s, maximum, uids)
}

// messageRange is one inclusive member of a parsed sequence or UID set.
type messageRange struct{ low, high int }

// resolveMessageSet returns, in ascending order and without duplicates, the
// members of the set s that name an existing message. maximum is the value of
// "*". existing lists the ascending UIDs present in the mailbox; when it is
// nil the existing values are the sequence numbers 1..maximum.
//
// The set is never expanded value by value: a client-supplied range such as
// 1:4294967295 would otherwise allocate billions of entries. Ranges are
// merged and intersected with the existing values instead, so the work is
// bounded by the length of s and the size of the mailbox.
func resolveMessageSet(s string, maximum int, existing []int) ([]int, error) {
	ranges, err := parseMessageRanges(s, maximum)
	if err != nil {
		return nil, err
	}
	var result []int
	if existing == nil {
		for _, member := range ranges {
			for value := max(member.low, 1); value <= min(member.high, maximum); value++ {
				result = append(result, value)
			}
		}
		return result, nil
	}
	next := 0
	for _, value := range existing {
		for next < len(ranges) && ranges[next].high < value {
			next++
		}
		if next == len(ranges) {
			break
		}
		if value >= ranges[next].low && (len(result) == 0 || result[len(result)-1] != value) {
			result = append(result, value)
		}
	}
	return result, nil
}

// parseMessageRanges parses an IMAP sequence set into sorted, disjoint,
// inclusive ranges. maximum is substituted for "*".
func parseMessageRanges(s string, maximum int) ([]messageRange, error) {
	parseValue := func(value string) (int, error) {
		if value == "*" {
			return maximum, nil
		}
		number, parseErr := strconv.ParseUint(value, 10, 32)
		if parseErr != nil || number == 0 {
			return 0, fmt.Errorf("invalid message number: %s", value)
		}
		return int(number), nil
	}
	var ranges []messageRange
	for member := range strings.SplitSeq(s, ",") {
		member = strings.TrimSpace(member)
		if member == "" {
			return nil, errors.New("empty message set member")
		}
		first, last, isRange := strings.Cut(member, ":")
		start, err := parseValue(first)
		if err != nil {
			return nil, err
		}
		end := start
		if isRange {
			if end, err = parseValue(last); err != nil {
				return nil, err
			}
		}
		ranges = append(ranges, messageRange{low: min(start, end), high: max(start, end)})
	}
	slices.SortFunc(ranges, func(a, b messageRange) int { return cmp.Compare(a.low, b.low) })
	merged := ranges[:0]
	for _, member := range ranges {
		if last := len(merged) - 1; last >= 0 && member.low <= merged[last].high+1 {
			merged[last].high = max(merged[last].high, member.high)
			continue
		}
		merged = append(merged, member)
	}
	return merged, nil
}

// sortByUID sorts items by UID.
func sortByUID(items []model.Item) {
	slices.SortFunc(items, func(a, b model.Item) int { return cmp.Compare(a.UID, b.UID) })
}

// extractHeaders extracts the header section from raw message data.
func extractHeaders(data []byte) []byte {
	idx, separatorSize := messageSeparator(data)
	if idx < 0 {
		return data
	}
	return data[:idx+separatorSize]
}

// extractBody extracts the body section from raw message data.
func extractBody(data []byte) []byte {
	idx, separatorSize := messageSeparator(data)
	if idx < 0 {
		return data
	}
	return data[idx+separatorSize:]
}

func messageSeparator(data []byte) (int, int) {
	if idx := bytes.Index(data, []byte("\r\n\r\n")); idx >= 0 {
		return idx, 4
	}
	if idx := bytes.Index(data, []byte("\n\n")); idx >= 0 {
		return idx, 2
	}
	return -1, 0
}
