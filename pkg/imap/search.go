package imap

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"golang.org/x/sync/errgroup"
)

// cmdSearch handles the SEARCH command (RFC 3501).
func (s *Session) cmdSearch(tag string, args []string) {
	s.cmdSearchMode(tag, args, false)
}

func (s *Session) cmdUIDSearch(tag string, args []string) {
	s.cmdSearchMode(tag, args, true)
}

type searchReturnOptions struct {
	min   bool
	max   bool
	all   bool
	count bool
	save  bool
}

func (s *Session) cmdSearchMode(tag string, args []string, uid bool) {
	if s.curState != stateSelected {
		s.sendBAD(tag, "No mailbox selected")
		return
	}
	args, err := s.resolveSearchLiterals(args)
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid SEARCH literal: %v", err))
		return
	}
	for _, argument := range args {
		if !utf8.ValidString(argument) {
			s.sendBAD(tag, "SEARCH contains invalid UTF-8")
			return
		}
	}
	options, charset, criteriaArgs, err := parseSearchCommand(args)
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid SEARCH syntax: %v", err))
		return
	}
	if charset != "" && !strings.EqualFold(charset, "UTF-8") && !strings.EqualFold(charset, "US-ASCII") {
		s.sendNO(tag, "[BADCHARSET (UTF-8 US-ASCII)] Unsupported charset")
		return
	}
	if strings.EqualFold(charset, "US-ASCII") {
		for _, argument := range criteriaArgs {
			for _, character := range argument {
				if character > 0x7f {
					s.sendBAD(tag, "US-ASCII SEARCH contains non-ASCII text")
					return
				}
			}
		}
	}
	criteria, err := parseSearchCriteria(criteriaArgs)
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid SEARCH criteria: %v", err))
		return
	}
	hydrateSavedSearchCriteria(criteria, s.savedSearchUIDs)
	if options.save {
		// A syntactically valid SAVE search that later returns NO leaves a
		// valid empty result; successful execution replaces it below.
		s.savedSearchUIDs = nil
		s.savedSearchSet = true
	}
	s.searchExecute(tag, criteria, options, uid)
}

const maxSearchLiteralSize = 1 << 20

// resolveSearchLiterals reads the literals of a SEARCH command. The octets
// of all of them together are capped at maxSearchLiteralSize, since a
// command may chain literals without end.
func (s *Session) resolveSearchLiterals(args []string) ([]string, error) {
	resolved := make([]string, 0, len(args))
	total := int64(0)
	for index := 0; index < len(args); index++ {
		token := args[index]
		if !strings.HasPrefix(token, "{") || !strings.HasSuffix(token, "}") {
			resolved = append(resolved, token)
			continue
		}
		size, nonSynchronizing, err := parseLiteralSize(token)
		if err != nil {
			return nil, err
		}
		if total += size; size > maxSearchLiteralSize || total > maxSearchLiteralSize {
			return nil, fmt.Errorf("literals exceed %d bytes", maxSearchLiteralSize)
		}
		if !nonSynchronizing {
			s.sendContinuation("Ready for SEARCH literal")
		}
		s.unreadLiteral = unreadLiteral{}
		value := make([]byte, int(size))
		if _, err := io.ReadFull(s.rw, value); err != nil {
			return nil, fmt.Errorf("read literal: %w", err)
		}
		resolved = append(resolved, string(value))
		remainder, err := s.readLine()
		if err != nil {
			return nil, fmt.Errorf("read literal continuation: %w", err)
		}
		s.expectLiteral(remainder, maxSearchLiteralSize-total)
		continuation, err := tokenizeSearchCommandArgs(strings.TrimSpace(remainder))
		if err != nil {
			return nil, err
		}
		args = append(args[:index+1], append(continuation, args[index+1:]...)...)
	}
	return resolved, nil
}

// searchExecute runs the search criteria against items in the selected folder.
func (s *Session) searchExecute(tag string, criteria []searchCriterion, options searchReturnOptions, uid bool) {
	var matching []int
	// The index only helps when it can narrow the candidates; without a
	// candidate filter it would return every item of the mailbox, which the
	// metadata listing already holds.
	if s.cfg.Search != nil && indexedCandidateFilter(criteria) != nil {
		var err error
		matching, err = s.searchIndexed(criteria, uid)
		switch {
		case err == nil:
			s.sendSearchResults(tag, matching, options, uid)
			return
		case errors.Is(err, service.ErrSearchNotIndexed):
			// Encrypted accounts have no index; scan the folder below.
			matching = nil
		case errors.Is(err, service.ErrForbidden):
			s.sendNO(tag, "[NOPERM] SEARCH permission denied")
			return
		case errors.Is(err, service.ErrSearchUnavailable):
			s.sendNO(tag, "[UNAVAILABLE] Search index is not ready")
			return
		default:
			s.sendNO(tag, fmt.Sprintf("SEARCH failed: %v", err))
			return
		}
	}
	items, err := s.getSequenceItems()
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("SEARCH failed: %v", err))
		return
	}
	matches, err := s.matchItems(items, criteria)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("SEARCH failed: %v", err))
		return
	}
	for _, index := range matches {
		if uid {
			matching = append(matching, int(items[index].UID))
		} else {
			matching = append(matching, index+1)
		}
	}
	s.sendSearchResults(tag, matching, options, uid)
}

// contentSearchWorkers bounds the messages one command reads and matches at
// once when criteria need message content.
var contentSearchWorkers = min(runtime.GOMAXPROCS(0), 8)

// matchItems returns the indexes of items that match criteria, in order.
// Items whose criteria need message content are read and matched
// concurrently; the content is not retained. Items whose stored header map
// is partial come back with their content (see withHeaders), so header
// lookups on the returned items stay exact.
func (s *Session) matchItems(items []model.Item, criteria []searchCriterion) ([]int, error) {
	resolveSearchSets(criteria, items)
	matched := make([]bool, len(items))
	match := func(index int) error {
		item := items[index]
		if s.expungedPending(item.UID) {
			return nil
		}
		stored := headersStored(item)
		if searchNeedsContent(criteria, stored) || !stored {
			full, err := s.withContent(item)
			if err != nil {
				return err
			}
			if !stored {
				items[index] = full
			}
			item = full
		}
		matched[index] = matchSearchCriteria(item, criteria)
		return nil
	}
	var pending []int
	for index, item := range items {
		if !searchNeedsContent(criteria, headersStored(item)) {
			if err := match(index); err != nil {
				return nil, err
			}
			continue
		}
		pending = append(pending, index)
	}
	if len(pending) > 0 {
		defer s.beginContentPass(len(pending))()
		group, _ := errgroup.WithContext(*s.ctx)
		group.SetLimit(contentSearchWorkers)
		for _, index := range pending {
			group.Go(func() error { return match(index) })
		}
		if err := group.Wait(); err != nil {
			return nil, err
		}
	}
	var matches []int
	for index, ok := range matched {
		if ok {
			matches = append(matches, index)
		}
	}
	return matches, nil
}

func (s *Session) searchIndexed(criteria []searchCriterion, uid bool) ([]int, error) {
	query := service.SearchQuery{
		AccountID: s.selectedFolder.UserID, FolderIDs: []string{s.selectedFolderID},
		Types: []model.FolderType{model.FolderTypeMail}, Filter: indexedCandidateFilter(criteria),
		Limit: 100, Sort: "date_asc",
	}
	// Index hits are candidates that are re-checked against the exact
	// criteria. The selected mailbox's metadata answers flag, date and size
	// criteria; content is read only for the criteria that need it.
	selected, err := s.getSequenceItems()
	if err != nil {
		return nil, err
	}
	resolveSearchSets(criteria, selected)
	byID := make(map[string]int, len(selected))
	for index, item := range selected {
		byID[item.ID] = index
	}
	var matching []int
	for {
		page, err := s.cfg.Search.Search(*s.ctx, s.access(), query)
		if err != nil {
			return nil, err
		}
		for _, hit := range page.Hits {
			index, ok := byID[hit.ItemID]
			if !ok {
				// Not in the mailbox snapshot: changed since the listing.
				continue
			}
			item := selected[index]
			if searchNeedsContent(criteria, headersStored(item)) {
				if item, err = s.withContent(item); err != nil {
					return nil, err
				}
			}
			if matchSearchCriteria(item, criteria) {
				identifier := int(item.UID)
				if !uid {
					identifier = index + 1
				}
				matching = append(matching, identifier)
			}
		}
		if page.NextCursor == "" {
			break
		}
		query.Cursor = page.NextCursor
	}
	sort.Ints(matching)
	return matching, nil
}

func parseSearchCommand(args []string) (searchReturnOptions, string, []string, error) {
	options := searchReturnOptions{}
	index := 0
	if index < len(args) && strings.EqualFold(args[index], "RETURN") {
		values, next, err := consumeParenthesized(args, index+1)
		if err != nil {
			return options, "", nil, errors.New("RETURN requires an option list")
		}
		if len(values) == 0 {
			options.all = true
		}
		for _, value := range values {
			switch strings.ToUpper(value) {
			case "MIN":
				options.min = true
			case "MAX":
				options.max = true
			case "ALL":
				options.all = true
			case "COUNT":
				options.count = true
			case "SAVE":
				options.save = true
			default:
				return options, "", nil, fmt.Errorf("unsupported RETURN option %s", value)
			}
		}
		index = next
	}
	charset := ""
	if index < len(args) && strings.EqualFold(args[index], "CHARSET") {
		if index+1 >= len(args) {
			return options, "", nil, errors.New("CHARSET requires a name")
		}
		charset = args[index+1]
		index += 2
	}
	criteria := args[index:]
	if len(criteria) == 0 {
		criteria = []string{"ALL"}
	}
	return options, charset, criteria, nil
}

func (s *Session) sendSearchResults(tag string, matching []int, options searchReturnOptions, uid bool) {
	if options.save {
		saved := matching
		if !options.all && !options.count && (options.min || options.max) && len(matching) > 0 {
			saved = nil
			if options.min {
				saved = append(saved, slices.Min(matching))
			}
			if options.max && (!options.min || slices.Max(matching) != slices.Min(matching)) {
				saved = append(saved, slices.Max(matching))
			}
		}
		s.savedSearchUIDs = s.savedSearchUIDs[:0]
		var items []model.Item
		if !uid {
			items, _ = s.getSequenceItems()
		}
		for _, identifier := range saved {
			if uid {
				s.savedSearchUIDs = append(s.savedSearchUIDs, uint32(identifier))
				continue
			}
			if identifier >= 1 && identifier <= len(items) {
				s.savedSearchUIDs = append(s.savedSearchUIDs, items[identifier-1].UID)
			}
		}
		s.savedSearchSet = true
	}
	if options.save && !options.min && !options.max && !options.all && !options.count {
		s.sendOK(tag, "SEARCH completed")
		return
	}
	useESearch := s.rev2Enabled || options != (searchReturnOptions{})
	if !useESearch {
		values := make([]string, len(matching))
		for index, value := range matching {
			values[index] = strconv.Itoa(value)
		}
		response := "* SEARCH"
		if len(values) > 0 {
			response += " " + strings.Join(values, " ")
		}
		s.sendUntagged(response)
		s.sendOK(tag, "SEARCH completed")
		return
	}
	if s.rev2Enabled && !options.min && !options.max && !options.all && !options.count && !options.save {
		options.all = true
	}
	parts := []string{"* ESEARCH", `(TAG "` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(tag) + `")`}
	if uid {
		parts = append(parts, "UID")
	}
	if options.min && len(matching) > 0 {
		parts = append(parts, "MIN", strconv.Itoa(slices.Min(matching)))
	}
	if options.max && len(matching) > 0 {
		parts = append(parts, "MAX", strconv.Itoa(slices.Max(matching)))
	}
	if options.all && len(matching) > 0 {
		parts = append(parts, "ALL", compactNumberSet(matching))
	}
	if options.count {
		parts = append(parts, "COUNT", strconv.Itoa(len(matching)))
	}
	s.sendUntagged(strings.Join(parts, " "))
	s.sendOK(tag, "SEARCH completed")
}

func compactNumberSet(values []int) string {
	if len(values) == 0 {
		return ""
	}
	values = append([]int(nil), values...)
	sort.Ints(values)
	parts := make([]string, 0, len(values))
	for start := 0; start < len(values); {
		end := start
		for end+1 < len(values) && values[end+1] == values[end]+1 {
			end++
		}
		if end == start {
			parts = append(parts, strconv.Itoa(values[start]))
		} else {
			parts = append(parts, strconv.Itoa(values[start])+":"+strconv.Itoa(values[end]))
		}
		start = end + 1
	}
	return strings.Join(parts, ",")
}

// indexedCandidateFilter returns only restrictions that cannot exclude a true
// RFC match. Final matching always uses the existing exact IMAP evaluator.
func indexedCandidateFilter(criteria []searchCriterion) *service.SearchFilter {
	// IMAP defines case-insensitive substring matching, while the user-facing
	// Bleve mapping is token based. Until the dedicated n-gram mapping lands,
	// asking Bleve for every indexed item is the only complete candidate set.
	// Exact evaluation below still preserves every RFC criterion.
	return nil
}

// searchCriterion represents a single search criterion.
type searchCriterion struct {
	typ     searchCriterionType
	arg     string
	args    []string
	negated bool
	sub     []searchCriterion // for AND/OR/NOT
	// members holds the UIDs a sequence-set or UID-set criterion names,
	// resolved against the selected mailbox before matching.
	members map[uint32]struct{}
}

type searchCriterionType int

const (
	critAll searchCriterionType = iota
	critFrom
	critTo
	critSubject
	critBody
	critText
	critBodyFields
	critSentBefore
	critSentOn
	critSentSince
	critBefore
	critOn
	critSince
	critAnswered
	critUnanswered
	critBcc
	critCallback
	critDeleted
	critUndeleted
	critDraft
	critUndraft
	critFlagged
	critUnflagged
	critKeyword
	critUnkeyword
	critNew
	critUnseen
	critOld
	critSeen
	critSubscribed
	critUid
	critLarger
	critSmaller
	critHeader
	critNot
	critOr
	critAnd
	critGmailMessageId
	critGmailLabel
	critSaved
	critEmailID
	critThreadID
	critSavedBefore
	critSavedOn
	critSavedSince
	critSequenceSet
)

// parseSearchCriteria parses IMAP SEARCH criteria tokens.
func parseSearchCriteria(args []string) ([]searchCriterion, error) {
	var criteria []searchCriterion
	i := 0

	for i < len(args) {
		if args[i] == ")" {
			return nil, errors.New("unexpected closing parenthesis")
		}
		crit, consumed, err := parseOneCriterion(args[i:], 0)
		if err != nil {
			return nil, err
		}
		criteria = append(criteria, crit)
		i += consumed
	}

	return criteria, nil
}

// maxSearchDepth bounds how deeply NOT, OR, AND and parenthesized groups may
// nest. Parsing and matching both recurse once per level, so an unbounded
// client-chosen depth would let one command exhaust the goroutine stack.
const maxSearchDepth = 64

// parseOneCriterion parses a single search criterion from args starting at
// index 0, nested depth levels deep. It returns the criterion, the number of
// tokens consumed, and any error.
func parseOneCriterion(args []string, depth int) (searchCriterion, int, error) {
	if len(args) == 0 {
		return searchCriterion{}, 0, fmt.Errorf("expected search criterion, got empty input")
	}
	if depth > maxSearchDepth {
		return searchCriterion{}, 0, fmt.Errorf("search criteria nest deeper than %d levels", maxSearchDepth)
	}

	token := strings.ToUpper(args[0])
	var crit searchCriterion

	switch token {
	case "(":
		var grouped []searchCriterion
		consumed := 1
		for consumed < len(args) && args[consumed] != ")" {
			sub, count, err := parseOneCriterion(args[consumed:], depth+1)
			if err != nil {
				return searchCriterion{}, 0, err
			}
			grouped = append(grouped, sub)
			consumed += count
		}
		if consumed >= len(args) || args[consumed] != ")" {
			return searchCriterion{}, 0, errors.New("unterminated search group")
		}
		if len(grouped) == 0 {
			return searchCriterion{}, 0, errors.New("empty search group")
		}
		crit.typ = critAnd
		crit.sub = grouped
		return crit, consumed + 1, nil
	case ")":
		return searchCriterion{}, 0, errors.New("unexpected closing parenthesis")
	case "ALL":
		crit.typ = critAll
		return crit, 1, nil
	case "$":
		crit.typ = critSaved
		return crit, 1, nil
	case "FROM":
		crit.typ = critFrom
		return criterionWithArgument(crit, args, "FROM")
	case "TO":
		crit.typ = critTo
		return criterionWithArgument(crit, args, "TO")
	case "SUBJECT":
		crit.typ = critSubject
		return criterionWithArgument(crit, args, "SUBJECT")
	case "BODY":
		if len(args) > 1 && strings.HasPrefix(strings.ToUpper(args[1]), "[") {
			crit.typ = critBodyFields
			crit.arg = args[1]
			crit.args = parseBodyHeaderFields(args[1])
			return crit, 2, nil
		}
		crit.typ = critBody
		return criterionWithArgument(crit, args, "BODY")
	case "TEXT":
		crit.typ = critText
		return criterionWithArgument(crit, args, "TEXT")
	case "SENTBEFORE":
		crit.typ = critSentBefore
		return criterionWithArgument(crit, args, "SENTBEFORE")
	case "SENTON":
		crit.typ = critSentOn
		return criterionWithArgument(crit, args, "SENTON")
	case "SENTSINCE":
		crit.typ = critSentSince
		return criterionWithArgument(crit, args, "SENTSINCE")
	case "BEFORE":
		crit.typ = critBefore
		return criterionWithArgument(crit, args, "BEFORE")
	case "ON":
		crit.typ = critOn
		return criterionWithArgument(crit, args, "ON")
	case "SINCE":
		crit.typ = critSince
		return criterionWithArgument(crit, args, "SINCE")
	case "SAVEDBEFORE":
		crit.typ = critSavedBefore
		return criterionWithArgument(crit, args, "SAVEDBEFORE")
	case "SAVEDON":
		crit.typ = critSavedOn
		return criterionWithArgument(crit, args, "SAVEDON")
	case "SAVEDSINCE":
		crit.typ = critSavedSince
		return criterionWithArgument(crit, args, "SAVEDSINCE")
	case "EMAILID":
		crit.typ = critEmailID
		return criterionWithArgument(crit, args, "EMAILID")
	case "THREADID":
		crit.typ = critThreadID
		return criterionWithArgument(crit, args, "THREADID")
	case "ANSWERED":
		crit.typ = critAnswered
		return crit, 1, nil
	case "UNANSWERED":
		crit.typ = critUnanswered
		return crit, 1, nil
	case "DELETED":
		crit.typ = critDeleted
		return crit, 1, nil
	case "UNDELETED":
		crit.typ = critUndeleted
		return crit, 1, nil
	case "DRAFT":
		crit.typ = critDraft
		return crit, 1, nil
	case "UNDRAFT":
		crit.typ = critUndraft
		return crit, 1, nil
	case "FLAGGED":
		crit.typ = critFlagged
		return crit, 1, nil
	case "UNFLAGGED":
		crit.typ = critUnflagged
		return crit, 1, nil
	case "NEW":
		crit.typ = critNew
		return crit, 1, nil
	case "UNSEEN":
		crit.typ = critUnseen
		return crit, 1, nil
	case "OLD":
		crit.typ = critOld
		return crit, 1, nil
	case "SEEN":
		crit.typ = critSeen
		return crit, 1, nil
	case "LARGER":
		crit.typ = critLarger
		return criterionWithArgument(crit, args, "LARGER")
	case "SMALLER":
		crit.typ = critSmaller
		return criterionWithArgument(crit, args, "SMALLER")
	case "HEADER":
		crit.typ = critHeader
		if len(args) < 3 {
			return searchCriterion{}, 0, errors.New("HEADER requires a field and value")
		}
		crit.args = []string{args[1], args[2]}
		return crit, 3, nil
	case "UID":
		crit.typ = critUid
		return criterionWithArgument(crit, args, "UID")
	case "NOT":
		crit.typ = critNot
		if len(args) < 2 {
			return searchCriterion{}, 0, fmt.Errorf("NOT requires a sub-criterion")
		}
		sub, consumed, err := parseOneCriterion(args[1:], depth+1)
		if err != nil {
			return searchCriterion{}, 0, err
		}
		crit.sub = []searchCriterion{sub}
		return crit, 1 + consumed, nil
	case "OR":
		crit.typ = critOr
		if len(args) < 2 {
			return searchCriterion{}, 0, fmt.Errorf("OR requires two sub-criteria")
		}
		sub1, consumed1, err := parseOneCriterion(args[1:], depth+1)
		if err != nil {
			return searchCriterion{}, 0, err
		}
		crit.sub = []searchCriterion{sub1}
		remaining := args[1+consumed1:]
		if len(remaining) == 0 {
			return searchCriterion{}, 0, fmt.Errorf("OR requires two sub-criteria")
		}
		sub2, consumed2, err := parseOneCriterion(remaining, depth+1)
		if err != nil {
			return searchCriterion{}, 0, err
		}
		crit.sub = append(crit.sub, sub2)
		return crit, 1 + consumed1 + consumed2, nil
	case "AND":
		crit.typ = critAnd
		if len(args) < 2 {
			return searchCriterion{}, 0, fmt.Errorf("AND requires two sub-criteria")
		}
		sub1, consumed1, err := parseOneCriterion(args[1:], depth+1)
		if err != nil {
			return searchCriterion{}, 0, err
		}
		crit.sub = []searchCriterion{sub1}
		remaining := args[1+consumed1:]
		if len(remaining) == 0 {
			return searchCriterion{}, 0, fmt.Errorf("AND requires two sub-criteria")
		}
		sub2, consumed2, err := parseOneCriterion(remaining, depth+1)
		if err != nil {
			return searchCriterion{}, 0, err
		}
		crit.sub = append(crit.sub, sub2)
		return crit, 1 + consumed1 + consumed2, nil
	default:
		// RFC 3501 6.4.4: a bare sequence set is a search key ("SEARCH
		// 1:* NOT DELETED", "UID SEARCH 1:* UNSEEN").
		if validSequenceSet(token) {
			crit.typ = critSequenceSet
			crit.arg = token
			return crit, 1, nil
		}
		return searchCriterion{}, 0, fmt.Errorf("unknown search criterion: %s", token)
	}
}

// validSequenceSet reports whether value is an RFC 3501 sequence-set.
func validSequenceSet(value string) bool {
	if value == "" {
		return false
	}
	for _, member := range strings.Split(value, ",") {
		bounds := strings.Split(member, ":")
		if len(bounds) > 2 {
			return false
		}
		for _, bound := range bounds {
			if bound == "*" {
				continue
			}
			number, err := strconv.ParseUint(bound, 10, 32)
			if err != nil || number == 0 {
				return false
			}
		}
	}
	return true
}

// resolveSearchSets fills the members of sequence-set and UID-set criteria
// from the selected mailbox listing (in sequence order), where "*" is the
// last message or the highest UID.
func resolveSearchSets(criteria []searchCriterion, items []model.Item) {
	for index := range criteria {
		criterion := &criteria[index]
		resolveSearchSets(criterion.sub, items)
		if criterion.typ != critSequenceSet && (criterion.typ != critUid || criterion.arg == "$") {
			continue
		}
		criterion.members = make(map[uint32]struct{})
		if len(items) == 0 {
			continue
		}
		highest := uint64(len(items))
		if criterion.typ == critUid {
			highest = uint64(items[len(items)-1].UID)
		}
		var byUID map[uint32]struct{}
		if criterion.typ == critUid {
			byUID = make(map[uint32]struct{}, len(items))
			for _, item := range items {
				byUID[item.UID] = struct{}{}
			}
		}
		for _, member := range strings.Split(criterion.arg, ",") {
			first, last, ok := strings.Cut(member, ":")
			if !ok {
				last = first
			}
			low, high := searchSetBound(first, highest), searchSetBound(last, highest)
			if low > high {
				low, high = high, low
			}
			high = min(high, highest)
			if criterion.typ == critSequenceSet {
				for seq := low; seq <= high; seq++ {
					criterion.members[items[seq-1].UID] = struct{}{}
				}
				continue
			}
			// UID ranges may be sparse and huge; walk the existing UIDs.
			for uid := range byUID {
				if uint64(uid) >= low && uint64(uid) <= high {
					criterion.members[uid] = struct{}{}
				}
			}
		}
	}
}

func searchSetBound(value string, highest uint64) uint64 {
	if value == "*" {
		return highest
	}
	number, _ := strconv.ParseUint(value, 10, 32)
	return number
}

func criterionWithArgument(criterion searchCriterion, args []string, name string) (searchCriterion, int, error) {
	if len(args) < 2 {
		return searchCriterion{}, 0, fmt.Errorf("%s requires an argument", name)
	}
	criterion.arg = args[1]
	return criterion, 2, nil
}

// searchNeedsContent reports whether any criterion, at any depth, is matched
// against the message content rather than metadata. FROM, TO and SUBJECT
// read the stored header map when it holds the parsed header block
// (headersStored); other header keys may repeat and search the raw block.
func searchNeedsContent(criteria []searchCriterion, headersStored bool) bool {
	for _, criterion := range criteria {
		switch criterion.typ {
		case critFrom, critTo, critSubject, critThreadID, critSentBefore, critSentOn, critSentSince:
			if !headersStored {
				return true
			}
		case critBody, critText, critBodyFields, critBcc, critHeader, critCallback:
			return true
		}
		if searchNeedsContent(criterion.sub, headersStored) {
			return true
		}
	}
	return false
}

// matchSearchCriteria checks if an item matches all search criteria (implicit AND).
func matchSearchCriteria(item model.Item, criteria []searchCriterion) bool {
	if len(criteria) == 0 {
		return true
	}

	for _, crit := range criteria {
		if !matchCriterion(item, crit) {
			return false
		}
	}
	return true
}

// matchCriterion checks if an item matches a single search criterion.
func matchCriterion(item model.Item, crit searchCriterion) bool {
	result := true

	switch crit.typ {
	case critAll:
		result = true
	case critFrom:
		result = matchHeader(item, "From", crit.arg)
	case critTo:
		result = matchHeader(item, "To", crit.arg)
	case critSubject:
		result = matchHeader(item, "Subject", crit.arg)
	case critBody:
		body := searchableBody(item.Data)
		result = strings.Contains(canonicalSearchText(body), canonicalSearchText(crit.arg))
	case critText:
		body := searchableBody(item.Data)
		text := searchableHeaders(item.Data) + body
		result = strings.Contains(canonicalSearchText(text), canonicalSearchText(crit.arg))
	case critBodyFields:
		// BODY[HEADER.FIELDS (from to subject)] — search only specified headers
		headers := extractHeaders(item.Data)
		headerLower := strings.ToLower(string(headers))
		searchLower := strings.ToLower(crit.arg)
		// Check that the search string appears within one of the specified headers
		result = matchBodyFields(headerLower, crit.args, searchLower)
	case critBefore:
		result = matchDateBefore(item.InternalDate, crit.arg)
	case critOn:
		result = matchDateOn(item.InternalDate, crit.arg)
	case critSince:
		result = matchDateSince(item.InternalDate, crit.arg)
	// SENT* use the Date header (RFC 3501 6.4.4), not the internal date.
	case critSentBefore:
		result = matchDateBefore(sentDay(item), crit.arg)
	case critSentOn:
		result = matchDateOn(sentDay(item), crit.arg)
	case critSentSince:
		result = matchDateSince(sentDay(item), crit.arg)
	case critSavedBefore:
		result = !savedAt(item).IsZero() && matchDateBefore(savedAt(item), crit.arg)
	case critSavedOn:
		result = !savedAt(item).IsZero() && matchDateOn(savedAt(item), crit.arg)
	case critSavedSince:
		result = !savedAt(item).IsZero() && matchDateSince(savedAt(item), crit.arg)
	case critEmailID:
		result = emailID(item) == crit.arg
	case critThreadID:
		result = threadID(item) == crit.arg
	case critAnswered:
		result = hasFlag(item, model.FlagAnswered)
	case critUnanswered:
		result = !hasFlag(item, model.FlagAnswered)
	case critDeleted:
		result = hasFlag(item, model.FlagDeleted)
	case critUndeleted:
		result = !hasFlag(item, model.FlagDeleted)
	case critDraft:
		result = hasFlag(item, model.FlagDraft) || item.Size == 0
	case critUndraft:
		result = !hasFlag(item, model.FlagDraft) && item.Size > 0
	case critFlagged:
		result = hasFlag(item, model.FlagFlagged)
	case critUnflagged:
		result = !hasFlag(item, model.FlagFlagged)
	case critNew:
		result = hasFlag(item, model.FlagRecent) && !hasFlag(item, model.FlagSeen)
	case critUnseen:
		result = !hasFlag(item, model.FlagSeen)
	case critOld:
		result = hasFlag(item, model.FlagSeen)
	case critSeen:
		result = hasFlag(item, model.FlagSeen)
	case critLarger:
		if n, err := strconv.ParseInt(crit.arg, 10, 64); err == nil {
			result = item.Size > n
		}
	case critSmaller:
		if n, err := strconv.ParseInt(crit.arg, 10, 64); err == nil {
			result = item.Size < n
		}
	case critHeader:
		result = len(crit.args) == 2 && matchHeader(item, crit.args[0], crit.args[1])
	case critSequenceSet:
		_, result = crit.members[item.UID]
	case critUid:
		if crit.members != nil {
			_, result = crit.members[item.UID]
		} else if crit.arg == "$" {
			result = slices.Contains(crit.args, strconv.FormatUint(uint64(item.UID), 10))
		} else if uid, err := strconv.ParseUint(crit.arg, 10, 32); err == nil {
			result = item.UID == uint32(uid)
		}
	case critSaved:
		result = slices.Contains(crit.args, strconv.FormatUint(uint64(item.UID), 10))
	case critNot:
		subResult := true
		for _, sub := range crit.sub {
			if !matchCriterion(item, sub) {
				subResult = false
				break
			}
		}
		result = !subResult
	case critOr:
		result = false
		if len(crit.sub) >= 2 {
			// Split into two halves
			mid := len(crit.sub) / 2
			leftResult := true
			for _, sub := range crit.sub[:mid] {
				if !matchCriterion(item, sub) {
					leftResult = false
					break
				}
			}
			rightResult := true
			for _, sub := range crit.sub[mid:] {
				if !matchCriterion(item, sub) {
					rightResult = false
					break
				}
			}
			result = leftResult || rightResult
		}
	case critAnd:
		result = true
		for _, sub := range crit.sub {
			if !matchCriterion(item, sub) {
				result = false
				break
			}
		}
	}

	if crit.negated {
		result = !result
	}

	return result
}

func hydrateSavedSearchCriteria(criteria []searchCriterion, savedUIDs []uint32) {
	values := make([]string, len(savedUIDs))
	for index, uid := range savedUIDs {
		values[index] = strconv.FormatUint(uint64(uid), 10)
	}
	var hydrate func([]searchCriterion)
	hydrate = func(items []searchCriterion) {
		for index := range items {
			if items[index].typ == critSaved || (items[index].typ == critUid && items[index].arg == "$") {
				items[index].args = append([]string(nil), values...)
			}
			hydrate(items[index].sub)
		}
	}
	hydrate(criteria)
}

// matchHeader checks if a header value contains the given string (case-insensitive).
func matchHeader(item model.Item, headerName, searchStr string) bool {
	needle := canonicalSearchText(searchStr)
	if header := decodedMessageHeaders(item.Data); header != nil {
		for name, values := range header {
			if !strings.EqualFold(name, headerName) {
				continue
			}
			for _, value := range values {
				if strings.Contains(canonicalSearchText(decodedHeaderValue(value)), needle) {
					return true
				}
			}
			return needle == ""
		}
	}
	for name, value := range item.Headers {
		if strings.EqualFold(name, headerName) {
			return strings.Contains(canonicalSearchText(decodedHeaderValue(value)), needle)
		}
	}
	return false
}

// hasFlag checks if an item has a specific flag.
func hasFlag(item model.Item, flag string) bool {
	for _, f := range item.Flags {
		if strings.EqualFold(f, flag) {
			return true
		}
	}
	return false
}

// matchDateBefore checks if the item date is before the given date.
func matchDateBefore(itemDate time.Time, dateStr string) bool {
	date, err := parseSearchDate(dateStr)
	if err != nil {
		return false
	}
	// Before means the item date is before the start of the given date
	return itemDate.Before(date)
}

// matchDateOn checks if the item date is on the given date.
// sentDay is the calendar day of the message's Date header in its own time
// zone, which RFC 3501 SENT* criteria compare without regard to time or zone.
func sentDay(item model.Item) time.Time {
	year, month, day := sentDate(item).Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

func matchDateOn(itemDate time.Time, dateStr string) bool {
	date, err := parseSearchDate(dateStr)
	if err != nil {
		return false
	}
	// On means the item date is within the given calendar day
	end := date.Add(24 * time.Hour)
	return (!itemDate.Before(date)) && itemDate.Before(end)
}

// matchDateSince checks if the item date is on or after the given date.
func matchDateSince(itemDate time.Time, dateStr string) bool {
	date, err := parseSearchDate(dateStr)
	if err != nil {
		return false
	}
	return !itemDate.Before(date)
}

// parseSearchDate parses a date string for SEARCH criteria.
func parseSearchDate(s string) (time.Time, error) {
	// Try DD-Mon-YYYY format first (IMAP date format, with leading zero)
	if t, err := time.Parse("02-Jan-2006", s); err == nil {
		return t, nil
	}
	// Try D-Mon-YYYY (IMAP client libraries often omit the leading zero)
	if t, err := time.Parse("2-Jan-2006", s); err == nil {
		return t, nil
	}
	// Try YYYY-MM-DD
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	// Try just a day number (e.g., "15") — use current month/year
	if day, err := strconv.Atoi(s); err == nil && day > 0 && day <= 31 {
		now := time.Now().UTC()
		return time.Date(now.Year(), now.Month(), day, 0, 0, 0, 0, time.UTC), nil
	}
	return time.Time{}, fmt.Errorf("invalid date: %q", s)
}

// parseBodyHeaderFields extracts header field names from a BODY section specifier
// like "[HEADER.FIELDS (from to subject)]".
func parseBodyHeaderFields(s string) []string {
	// Strip leading [ and trailing ]
	s = strings.TrimSpace(s)
	if len(s) > 0 && s[0] == '[' {
		s = s[1:]
	}
	if len(s) > 0 && s[len(s)-1] == ']' {
		s = s[:len(s)-1]
	}

	// Find HEADER.FIELDS (
	prefix := strings.ToUpper("HEADER.FIELDS")
	if !strings.HasPrefix(strings.ToUpper(s), prefix) {
		return nil
	}
	s = s[len(prefix):]

	// Find the opening paren
	open := strings.Index(s, "(")
	if open < 0 {
		return nil
	}
	s = s[open+1:]

	close := strings.LastIndex(s, ")")
	if close >= 0 {
		s = s[:close]
	}

	// Split and trim the field names
	parts := strings.Fields(strings.ToLower(s))
	return parts
}

// matchBodyFields checks whether searchStr appears within any of the specified
// header fields in the raw header text.
func matchBodyFields(headerLower string, headerNames []string, searchLower string) bool {
	for _, name := range headerNames {
		// Find the header line in raw text
		key := name + ":"
		idx := 0
		for idx >= 0 {
			idx = strings.Index(headerLower[idx:], key)
			if idx < 0 {
				break
			}
			// idx is relative to headerLower[idx:], so adjust
			start := idx + len(key)
			// Find the end of this header line
			end := strings.Index(headerLower[start:], "\n")
			if end < 0 {
				end = len(headerLower) - start
			}
			line := headerLower[start : start+end]
			if strings.Contains(line, searchLower) {
				return true
			}
			idx++ // move past this match to find next occurrence
		}
	}
	return false
}
