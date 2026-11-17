package imap

import (
	"fmt"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/threading"
)

// sortCriterion represents one SORT criterion from RFC 5256 §4.
type sortCriterion int

const (
	sortFrom sortCriterion = iota
	sortTo
	sortSubject
	sortDate
	sortArrival
	sortCc
	sortSize
)

// parseSortCriteria parses the SORT criterion-set tokens.
// Each token is a criterion name (FROM, TO, SUBJECT, DATE, ARRIVAL, CC, SIZE).
// The optional REVERSE keyword may appear before any criterion to reverse that criterion's order.
func parseSortCriteria(args []string) ([]sortCriterion, []bool, error) {
	var criteria []sortCriterion
	var reverses []bool // parallel: reverses[i] corresponds to criteria[i]
	reverseNext := false

	for index, token := range args {
		upper := strings.ToUpper(token)
		if upper == "REVERSE" {
			if index == len(args)-1 && len(criteria) > 0 && !reverseNext {
				reverses[len(reverses)-1] = true // legacy Veksel syntax
				continue
			}
			if reverseNext {
				return nil, nil, fmt.Errorf("REVERSE requires a sort criterion")
			}
			reverseNext = true
			continue
		}
		var criterion sortCriterion
		switch upper {
		case "FROM":
			criterion = sortFrom
		case "TO":
			criterion = sortTo
		case "SUBJECT":
			criterion = sortSubject
		case "DATE":
			criterion = sortDate
		case "ARRIVAL":
			criterion = sortArrival
		case "CC":
			criterion = sortCc
		case "SIZE":
			criterion = sortSize
		default:
			return nil, nil, fmt.Errorf("unknown SORT criterion: %s", token)
		}
		criteria = append(criteria, criterion)
		reverses = append(reverses, reverseNext)
		reverseNext = false
	}

	if len(criteria) == 0 || reverseNext {
		return nil, nil, fmt.Errorf("no SORT criteria specified")
	}

	return criteria, reverses, nil
}

// cmdSort handles the SORT command (RFC 5256 §4).
//
// # SORT criterion-set charset SELECTOR
//
// The charset argument is accepted but currently ignored (UTF-8 is assumed).
// The selector is parsed as SEARCH criteria to filter messages before sorting.
func (s *Session) cmdSort(tag string, args []string) {
	s.cmdSortMode(tag, args, false)
}

func (s *Session) cmdSortMode(tag string, args []string, uid bool) {
	if s.curState != stateSelected {
		s.sendBAD(tag, "No mailbox selected")
		return
	}

	saveResult := false
	start := 0
	if len(args) > 0 && strings.EqualFold(args[0], "RETURN") {
		options, next, err := consumeParenthesized(args, 1)
		if err != nil || len(options) != 1 || !strings.EqualFold(options[0], "SAVE") {
			s.sendBAD(tag, "SORT RETURN supports only SAVE")
			return
		}
		saveResult = true
		s.savedSearchUIDs = nil
		s.savedSearchSet = true
		start = next
	}
	args = args[start:]
	if len(args) < 2 {
		s.sendBAD(tag, "Expected: SORT criterion-set charset [SELECTOR]")
		return
	}
	var sortArgs []string
	next := 0
	var err error
	if args[0] == "(" {
		sortArgs, next, err = consumeParenthesized(args, 0)
		if err != nil || next >= len(args) {
			s.sendBAD(tag, "Invalid SORT criterion list")
			return
		}
	} else {
		sortKeywords := map[string]bool{"FROM": true, "TO": true, "SUBJECT": true, "DATE": true, "ARRIVAL": true, "CC": true, "SIZE": true, "REVERSE": true}
		for next < len(args) && sortKeywords[strings.ToUpper(args[next])] {
			next++
		}
		if next == 0 || next >= len(args) {
			s.sendBAD(tag, "Expected charset after SORT criteria")
			return
		}
		sortArgs = args[:next]
	}
	charset := args[next]
	if !strings.EqualFold(charset, "UTF-8") && !strings.EqualFold(charset, "US-ASCII") {
		s.sendNO(tag, "[BADCHARSET (UTF-8 US-ASCII)] Unsupported charset")
		return
	}
	selectorArgs := args[next+1:]
	if len(selectorArgs) == 0 {
		selectorArgs = []string{"ALL"}
	}
	criteria, reverses, err := parseSortCriteria(sortArgs)
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid SORT criteria: %v", err))
		return
	}

	// Parse search criteria from the selector
	searchCriteria, err := parseSearchCriteria(selectorArgs)
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid SEARCH criteria: %v", err))
		return
	}
	hydrateSavedSearchCriteria(searchCriteria, s.savedSearchUIDs)

	// Get all items in the folder
	items, err := s.getSequenceItems()
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("SORT failed: %v", err))
		return
	}

	// Filter by search criteria
	matches, err := s.matchItems(items, searchCriteria)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("SORT failed: %v", err))
		return
	}
	matching := make([]model.Item, len(matches))
	for position, index := range matches {
		matching[position] = items[index]
	}

	// Sort the matching items
	sortItems(matching, criteria, reverses)

	var sequences map[uint32]int
	if !uid {
		sequences = sequenceNumbers(items)
	}
	identifiers := make([]string, len(matching))
	for i, item := range matching {
		identifier := uint64(item.UID)
		if !uid {
			identifier = uint64(sequences[item.UID])
		}
		identifiers[i] = strconv.FormatUint(identifier, 10)
	}
	if saveResult {
		s.savedSearchUIDs = s.savedSearchUIDs[:0]
		for _, item := range matching {
			s.savedSearchUIDs = append(s.savedSearchUIDs, item.UID)
		}
		s.savedSearchSet = true
		s.sendOK(tag, "SORT completed")
		return
	}

	if len(identifiers) == 0 {
		s.sendUntagged("* SORT")
	} else {
		s.sendUntagged(fmt.Sprintf("* SORT %s", strings.Join(identifiers, " ")))
	}

	s.sendOK(tag, "SORT completed")
}

// sortItems sorts the items in place according to the criteria and reverse
// flags. Items arrive in sequence order, and RFC 5256 breaks ties by sequence
// number, which a stable sort preserves.
func sortItems(items []model.Item, criteria []sortCriterion, reverses []bool) {
	keys := make([][]sortKey, len(items))
	for index, item := range items {
		keys[index] = make([]sortKey, len(criteria))
		for position, criterion := range criteria {
			keys[index][position] = makeSortKey(item, criterion)
		}
	}
	order := make([]int, len(items))
	for index := range order {
		order[index] = index
	}
	sort.SliceStable(order, func(i, j int) bool {
		for position := range criteria {
			comparison := keys[order[i]][position].compare(keys[order[j]][position])
			if reverses[position] {
				comparison = -comparison
			}
			if comparison != 0 {
				return comparison < 0
			}
		}
		return false
	})
	sorted := make([]model.Item, len(items))
	for position, index := range order {
		sorted[position] = items[index]
	}
	copy(items, sorted)
}

// sortKey is one RFC 5256 sort key: a time, a size, or a string compared
// with i;ascii-casemap.
type sortKey struct {
	text   string
	number int64
}

func (key sortKey) compare(other sortKey) int {
	if key.number != other.number {
		if key.number < other.number {
			return -1
		}
		return 1
	}
	return strings.Compare(key.text, other.text)
}

// makeSortKey derives an RFC 5256 section 3 key. DATE is the sent date
// (the Date header, or the internal date when it is missing or invalid);
// FROM, TO, and CC use the mailbox (local part) of the first address;
// SUBJECT uses the base subject. Comparing raw header text sorted
// "Thu, ..." before "Wed, ..." regardless of the actual dates.
func makeSortKey(item model.Item, criterion sortCriterion) sortKey {
	switch criterion {
	case sortArrival:
		return sortKey{number: item.InternalDate.UnixNano()}
	case sortDate:
		return sortKey{number: sentDate(item).UnixNano()}
	case sortSize:
		return sortKey{number: item.Size}
	case sortFrom:
		return sortKey{text: firstAddressMailbox(getHeaderValue(item, "From"))}
	case sortTo:
		return sortKey{text: firstAddressMailbox(getHeaderValue(item, "To"))}
	case sortCc:
		return sortKey{text: firstAddressMailbox(getHeaderValue(item, "Cc"))}
	case sortSubject:
		return sortKey{text: strings.ToLower(threading.BaseSubject(model.DecodeHeaderValue(getHeaderValue(item, "Subject"))))}
	default:
		return sortKey{}
	}
}

// sentDate is the message's Date header, falling back to its internal date.
func sentDate(item model.Item) time.Time {
	if value := strings.TrimSpace(getHeaderValue(item, "Date")); value != "" {
		if parsed, err := mail.ParseDate(value); err == nil {
			return parsed
		}
	}
	return item.InternalDate
}

// firstAddressMailbox returns the lower-cased local part of the first
// address in an address header, or "" when there is none.
func firstAddressMailbox(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	addresses, err := mail.ParseAddressList(value)
	if err != nil || len(addresses) == 0 {
		return ""
	}
	mailbox, _, _ := strings.Cut(addresses[0].Address, "@")
	return strings.ToLower(mailbox)
}

// getHeaderValue retrieves a header value from an item, checking stored headers
// first and falling back to raw data parsing.
func getHeaderValue(item model.Item, headerName string) string {
	// Check stored headers first: the exact name, then any case of it.
	if v, ok := item.Headers[headerName]; ok {
		return v
	}
	for k, v := range item.Headers {
		if strings.EqualFold(k, headerName) {
			return v
		}
	}

	// Fall back to parsing from raw data
	return extractHeaderFromData(item.Data, headerName)
}
