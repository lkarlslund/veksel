package imap

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

const maxQResyncSequenceMatches = 100_000

type qresyncUIDRange struct {
	first uint32
	last  uint32
}

type qresyncSequenceMatch struct {
	sequences []qresyncUIDRange
	uids      []qresyncUIDRange
}

type qresyncRequest struct {
	UIDValidity  uint32
	ModSeq       uint64
	KnownUIDs    []qresyncUIDRange
	HasKnownUIDs bool
	Match        *qresyncSequenceMatch
}

type qresyncTokenStream struct {
	tokens []string
	index  int
}

// parseQResyncSelectOptions parses RFC 7162 SELECT parameters before the
// mailbox is opened. The legacy IMAP tokenizer deliberately retains attached
// parentheses, so this parser first creates a structural token stream.
func parseQResyncSelectOptions(options []string) (*qresyncRequest, error) {
	if len(options) == 0 {
		return nil, nil
	}
	tokens, err := tokenizeQResyncOptions(strings.Join(options, " "))
	if err != nil {
		return nil, err
	}
	stream := qresyncTokenStream{tokens: tokens}
	if !stream.consume("(") {
		return nil, errors.New("parameter list must be parenthesized")
	}
	var request *qresyncRequest
	parameterCount := 0
	for !stream.consume(")") {
		parameter, ok := stream.next()
		if !ok {
			return nil, errors.New("unterminated parameter list")
		}
		parameterCount++
		switch strings.ToUpper(parameter) {
		case "CONDSTORE":
			// CONDSTORE has no value and QRESYNC itself enables CONDSTORE
			// semantics. It is accepted here so both standard parameters can
			// coexist in the generic SELECT parameter list.
		case "QRESYNC":
			if request != nil {
				return nil, errors.New("duplicate QRESYNC parameter")
			}
			parsed, parseErr := parseQResyncParameter(&stream)
			if parseErr != nil {
				return nil, parseErr
			}
			request = &parsed
		default:
			return nil, fmt.Errorf("unsupported parameter %q", parameter)
		}
	}
	if parameterCount == 0 {
		return nil, errors.New("parameter list cannot be empty")
	}
	if stream.index != len(stream.tokens) {
		return nil, errors.New("data follows parameter list")
	}
	return request, nil
}

func tokenizeQResyncOptions(value string) ([]string, error) {
	var tokens []string
	for index := 0; index < len(value); {
		switch value[index] {
		case ' ', '\t':
			index++
		case '(', ')':
			tokens = append(tokens, value[index:index+1])
			index++
		case '\r', '\n', 0:
			return nil, errors.New("invalid control character")
		default:
			start := index
			for index < len(value) && value[index] != ' ' && value[index] != '\t' && value[index] != '(' && value[index] != ')' {
				if value[index] == '\r' || value[index] == '\n' || value[index] == 0 {
					return nil, errors.New("invalid control character")
				}
				index++
			}
			tokens = append(tokens, value[start:index])
		}
	}
	return tokens, nil
}

func parseQResyncParameter(stream *qresyncTokenStream) (qresyncRequest, error) {
	if !stream.consume("(") {
		return qresyncRequest{}, errors.New("QRESYNC value must be parenthesized")
	}
	uidValidityAtom, ok := stream.nextAtom()
	if !ok {
		return qresyncRequest{}, errors.New("QRESYNC requires UIDVALIDITY")
	}
	uidValidity, err := parseQResyncNumber(uidValidityAtom, 32)
	if err != nil || uidValidity == 0 {
		return qresyncRequest{}, errors.New("QRESYNC UIDVALIDITY must be a non-zero 32-bit number")
	}
	modSeqAtom, ok := stream.nextAtom()
	if !ok {
		return qresyncRequest{}, errors.New("QRESYNC requires a modification sequence")
	}
	modSeq, err := parseQResyncNumber(modSeqAtom, 63)
	if err != nil || modSeq == 0 {
		return qresyncRequest{}, errors.New("QRESYNC modification sequence must be a positive unsigned 63-bit number")
	}

	request := qresyncRequest{UIDValidity: uint32(uidValidity), ModSeq: modSeq}
	if atom, present := stream.peekAtom(); present {
		ranges, rangeErr := parseQResyncSet(atom, false)
		if rangeErr != nil {
			return qresyncRequest{}, fmt.Errorf("invalid QRESYNC known UID set: %w", rangeErr)
		}
		stream.index++
		request.KnownUIDs = ranges
		request.HasKnownUIDs = true
	}
	if stream.consume("(") {
		sequencesAtom, sequencesOK := stream.nextAtom()
		uidsAtom, uidsOK := stream.nextAtom()
		if !sequencesOK || !uidsOK || !stream.consume(")") {
			return qresyncRequest{}, errors.New("QRESYNC sequence-match data requires two sets")
		}
		sequences, sequenceCount, rangeErr := parseQResyncOrderedSet(sequencesAtom)
		if rangeErr != nil {
			return qresyncRequest{}, fmt.Errorf("invalid QRESYNC known sequence set: %w", rangeErr)
		}
		uids, uidCount, rangeErr := parseQResyncOrderedSet(uidsAtom)
		if rangeErr != nil {
			return qresyncRequest{}, fmt.Errorf("invalid QRESYNC matched UID set: %w", rangeErr)
		}
		if sequenceCount != uidCount {
			return qresyncRequest{}, errors.New("QRESYNC sequence-match sets have different cardinality")
		}
		if sequenceCount > maxQResyncSequenceMatches {
			return qresyncRequest{}, fmt.Errorf("QRESYNC sequence-match data exceeds %d pairs", maxQResyncSequenceMatches)
		}
		request.Match = &qresyncSequenceMatch{sequences: sequences, uids: uids}
	}
	if !stream.consume(")") {
		return qresyncRequest{}, errors.New("unexpected or missing QRESYNC value")
	}
	return request, nil
}

func parseQResyncNumber(value string, bits int) (uint64, error) {
	if value == "" || value[0] == '+' || value[0] == '-' {
		return 0, errors.New("invalid number")
	}
	number, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return 0, err
	}
	return number, nil
}

func parseQResyncSet(value string, ordered bool) ([]qresyncUIDRange, error) {
	if value == "" || strings.Contains(value, "*") {
		return nil, errors.New("wildcards and empty sets are not allowed")
	}
	ranges := make([]qresyncUIDRange, 0, strings.Count(value, ",")+1)
	for _, component := range strings.Split(value, ",") {
		bounds := strings.Split(component, ":")
		if len(bounds) < 1 || len(bounds) > 2 {
			return nil, errors.New("invalid range")
		}
		first, err := parseQResyncNumber(bounds[0], 32)
		if err != nil || first == 0 {
			return nil, errors.New("set values must be non-zero 32-bit numbers")
		}
		last := first
		if len(bounds) == 2 {
			last, err = parseQResyncNumber(bounds[1], 32)
			if err != nil || last == 0 {
				return nil, errors.New("set values must be non-zero 32-bit numbers")
			}
		}
		if ordered && first > last {
			return nil, errors.New("ranges must be ascending")
		}
		if first > last {
			first, last = last, first
		}
		current := qresyncUIDRange{first: uint32(first), last: uint32(last)}
		if ordered && len(ranges) > 0 && current.first <= ranges[len(ranges)-1].last {
			return nil, errors.New("values must be strictly ascending")
		}
		ranges = append(ranges, current)
	}
	if ordered {
		return ranges, nil
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].first == ranges[j].first {
			return ranges[i].last < ranges[j].last
		}
		return ranges[i].first < ranges[j].first
	})
	merged := ranges[:0]
	for _, current := range ranges {
		if len(merged) == 0 || uint64(current.first) > uint64(merged[len(merged)-1].last)+1 {
			merged = append(merged, current)
			continue
		}
		if current.last > merged[len(merged)-1].last {
			merged[len(merged)-1].last = current.last
		}
	}
	return merged, nil
}

func parseQResyncOrderedSet(value string) ([]qresyncUIDRange, uint64, error) {
	ranges, err := parseQResyncSet(value, true)
	if err != nil {
		return nil, 0, err
	}
	var count uint64
	for _, interval := range ranges {
		count += uint64(interval.last) - uint64(interval.first) + 1
		if count > maxQResyncSequenceMatches {
			// Keep counting unnecessary and potentially overflowing values out
			// of the parser. The caller reports one stable resource bound.
			return ranges, count, nil
		}
	}
	return ranges, count, nil
}

func (stream *qresyncTokenStream) next() (string, bool) {
	if stream.index >= len(stream.tokens) {
		return "", false
	}
	value := stream.tokens[stream.index]
	stream.index++
	return value, true
}

func (stream *qresyncTokenStream) nextAtom() (string, bool) {
	value, ok := stream.next()
	if !ok || value == "(" || value == ")" {
		if ok {
			stream.index--
		}
		return "", false
	}
	return value, true
}

func (stream *qresyncTokenStream) peekAtom() (string, bool) {
	if stream.index >= len(stream.tokens) || stream.tokens[stream.index] == "(" || stream.tokens[stream.index] == ")" {
		return "", false
	}
	return stream.tokens[stream.index], true
}

func (stream *qresyncTokenStream) consume(value string) bool {
	if stream.index >= len(stream.tokens) || stream.tokens[stream.index] != value {
		return false
	}
	stream.index++
	return true
}

func (request qresyncRequest) scope(maxUID uint32) []qresyncUIDRange {
	if request.HasKnownUIDs {
		return request.KnownUIDs
	}
	if maxUID == 0 {
		return nil
	}
	return []qresyncUIDRange{{first: 1, last: maxUID}}
}

func (request qresyncRequest) includes(uid, maxUID uint32) bool {
	for _, interval := range request.scope(maxUID) {
		if uid < interval.first {
			return false
		}
		if uid <= interval.last {
			return true
		}
	}
	return false
}

func (s *Session) sendQResyncChanges(request qresyncRequest, items []model.Item) {
	if request.ModSeq >= s.highestModSeq {
		return
	}
	lowerBound := uint64(1)
	if request.Match != nil {
		lowerBound = qresyncMatchLowerBound(*request.Match, items)
	}
	missing, complete := s.qresyncRetainedDeleted(request, lowerBound)
	if !complete {
		// RFC 7162 permits a server without sufficient retained expunge state
		// to return every currently missing UID in the requested scope. This
		// comparison is range based, so even 1:4294967295 is not expanded.
		missing = qresyncMissingUIDs(request.scope(s.selectedFolder.NextUID), items, lowerBound)
	}
	if len(missing) > 0 {
		s.sendUntagged("* VANISHED (EARLIER) " + formatQResyncSet(missing))
	}
	for sequence, item := range items {
		if item.ModSeq > request.ModSeq && request.includes(item.UID, s.selectedFolder.NextUID) {
			s.sendUntagged(fmt.Sprintf("* %d FETCH (UID %d FLAGS %s MODSEQ (%d))", sequence+1, item.UID, formatFlags(item.Flags), item.ModSeq))
		}
	}
}

func (s *Session) qresyncRetainedDeleted(request qresyncRequest, lowerBound uint64) ([]qresyncUIDRange, bool) {
	reader, ok := s.cfg.FolderSpace.(service.FolderChangeReader)
	if !ok {
		return nil, false
	}
	deleted := make(map[uint32]struct{})
	state := ""
	for {
		page, err := reader.ListChanges(*s.ctx, s.access(), service.ChangeScope{
			FolderID: s.selectedFolderID,
			Object:   service.ChangeObjectItem,
		}, state, 10_000)
		if err != nil {
			return nil, false
		}
		for _, record := range page.Records {
			for _, change := range record.Changes {
				if qresyncRemovalMetadataMissing(change, s.selectedFolderID) {
					return nil, false
				}
				uid, modSeq, removed := qresyncRemovalFromFolder(change, s.selectedFolderID)
				if !removed || modSeq <= request.ModSeq || uint64(uid) < lowerBound || !request.includes(uid, s.selectedFolder.NextUID) {
					continue
				}
				deleted[uid] = struct{}{}
			}
		}
		state = page.NewState
		if !page.HasMoreChanges {
			break
		}
	}
	return qresyncUIDMapRanges(deleted), true
}

func qresyncRemovalMetadataMissing(change service.Change, folderID string) bool {
	switch change.Operation {
	case service.ChangeMove, service.ChangeTrash:
		return change.PreviousFolderID == folderID && (change.PreviousUID == 0 || change.PreviousModSeq == 0)
	case service.ChangeDestroy:
		return change.FolderID == folderID && (change.UID == 0 || change.ModSeq == 0)
	default:
		return false
	}
}

func qresyncRemovalFromFolder(change service.Change, folderID string) (uint32, uint64, bool) {
	switch change.Operation {
	case service.ChangeMove, service.ChangeTrash:
		if change.PreviousFolderID == folderID && change.PreviousUID != 0 {
			return change.PreviousUID, change.PreviousModSeq, true
		}
	case service.ChangeDestroy:
		if change.FolderID == folderID && change.UID != 0 {
			return change.UID, change.ModSeq, true
		}
	}
	return 0, 0, false
}

func qresyncUIDMapRanges(values map[uint32]struct{}) []qresyncUIDRange {
	if len(values) == 0 {
		return nil
	}
	uids := make([]uint32, 0, len(values))
	for uid := range values {
		uids = append(uids, uid)
	}
	sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
	ranges := []qresyncUIDRange{{first: uids[0], last: uids[0]}}
	for _, uid := range uids[1:] {
		last := &ranges[len(ranges)-1]
		if uint64(uid) == uint64(last.last)+1 {
			last.last = uid
			continue
		}
		ranges = append(ranges, qresyncUIDRange{first: uid, last: uid})
	}
	return ranges
}

func qresyncMatchLowerBound(match qresyncSequenceMatch, items []model.Item) uint64 {
	sequenceIterator := newQResyncRangeIterator(match.sequences)
	uidIterator := newQResyncRangeIterator(match.uids)
	lowerBound := uint64(1)
	for {
		sequence, sequenceOK := sequenceIterator.next()
		uid, uidOK := uidIterator.next()
		if !sequenceOK || !uidOK {
			return lowerBound
		}
		if uint64(sequence) > uint64(len(items)) || items[int(sequence)-1].UID != uid {
			return lowerBound
		}
		lowerBound = uint64(uid) + 1
	}
}

func qresyncMissingUIDs(scope []qresyncUIDRange, items []model.Item, lowerBound uint64) []qresyncUIDRange {
	if lowerBound > math.MaxUint32 {
		return nil
	}
	current := make([]uint32, 0, len(items))
	for _, item := range items {
		current = append(current, item.UID)
	}
	sort.Slice(current, func(i, j int) bool { return current[i] < current[j] })
	missing := make([]qresyncUIDRange, 0)
	itemIndex := 0
	for _, interval := range scope {
		first := uint64(interval.first)
		if first < lowerBound {
			first = lowerBound
		}
		if first > uint64(interval.last) {
			continue
		}
		for itemIndex < len(current) && uint64(current[itemIndex]) < first {
			itemIndex++
		}
		cursor := first
		for itemIndex < len(current) && current[itemIndex] <= interval.last {
			uid := uint64(current[itemIndex])
			if uid > cursor {
				missing = append(missing, qresyncUIDRange{first: uint32(cursor), last: uint32(uid - 1)})
			}
			if uid == math.MaxUint32 {
				cursor = uint64(math.MaxUint32) + 1
				break
			}
			cursor = uid + 1
			itemIndex++
		}
		if cursor <= uint64(interval.last) {
			missing = append(missing, qresyncUIDRange{first: uint32(cursor), last: interval.last})
		}
	}
	return missing
}

func formatQResyncSet(ranges []qresyncUIDRange) string {
	values := make([]string, 0, len(ranges))
	for _, interval := range ranges {
		if interval.first == interval.last {
			values = append(values, strconv.FormatUint(uint64(interval.first), 10))
		} else {
			values = append(values, fmt.Sprintf("%d:%d", interval.first, interval.last))
		}
	}
	return strings.Join(values, ",")
}

type qresyncRangeIterator struct {
	ranges []qresyncUIDRange
	index  int
	nextID uint64
}

func newQResyncRangeIterator(ranges []qresyncUIDRange) *qresyncRangeIterator {
	iterator := &qresyncRangeIterator{ranges: ranges}
	if len(ranges) > 0 {
		iterator.nextID = uint64(ranges[0].first)
	}
	return iterator
}

func (iterator *qresyncRangeIterator) next() (uint32, bool) {
	if iterator.index >= len(iterator.ranges) {
		return 0, false
	}
	current := iterator.ranges[iterator.index]
	value := uint32(iterator.nextID)
	if iterator.nextID == uint64(current.last) {
		iterator.index++
		if iterator.index < len(iterator.ranges) {
			iterator.nextID = uint64(iterator.ranges[iterator.index].first)
		}
	} else {
		iterator.nextID++
	}
	return value, true
}

// sendFetchVanished reports the UIDs in a UID FETCH set that were expunged
// after changedSince, for UID FETCH ... (CHANGEDSINCE n VANISHED) (RFC 7162
// 3.2.6). Without retained expunge history every missing UID in the set is
// reported, which the RFC permits.
func (s *Session) sendFetchVanished(set string, changedSince uint64, items []model.Item) {
	maxUID := s.selectedFolder.NextUID
	if folder, err := s.cfg.FolderSpace.GetFolder(*s.ctx, s.access(), s.selectedFolderID); err == nil {
		maxUID = folder.NextUID
	}
	if maxUID == 0 {
		return
	}
	known, err := parseQResyncSet(strings.ReplaceAll(set, "*", strconv.FormatUint(uint64(maxUID), 10)), false)
	if err != nil {
		return
	}
	for index := range known {
		known[index].last = min(known[index].last, maxUID)
	}
	request := qresyncRequest{ModSeq: changedSince, KnownUIDs: known, HasKnownUIDs: true}
	missing, complete := s.qresyncRetainedDeleted(request, 1)
	if !complete {
		missing = qresyncMissingUIDs(request.scope(maxUID), items, 1)
	}
	if len(missing) > 0 {
		s.sendUntagged("* VANISHED (EARLIER) " + formatQResyncSet(missing))
	}
}
