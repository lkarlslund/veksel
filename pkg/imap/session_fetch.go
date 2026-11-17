package imap

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// loadItems loads all non-expunged items for the selected folder, sorted by
// UID. The items carry metadata and headers but no message content; commands
// that need the content read it per message with withContent, so flag, UID
// and search commands never read every payload of a large mailbox.
func (s *Session) loadItems() ([]model.Item, error) {
	return s.listMailboxItems(s.selectedFolderID)
}

// listMailboxItems lists a mailbox's items without content, in UID order. The
// listing is authorized as a content read because sessions serve message
// content from it.
func (s *Session) listMailboxItems(folderID string) ([]model.Item, error) {
	items, err := s.cfg.FolderSpace.ListItems(*s.ctx, s.access(), folderID, service.ItemQuery{MetadataOnly: true, RequireRead: true})
	if err != nil {
		return nil, err
	}

	// Sort by UID for consistent sequence numbers
	sortByUID(items)
	return items, nil
}

// withContent returns item with its message content, reading it when the
// item came from the metadata-only mailbox listing. The listing's flags and
// mod-sequence are kept so one command reports one consistent snapshot.
func (s *Session) withContent(item model.Item) (model.Item, error) {
	if item.Data != nil || item.Size == 0 {
		return item, nil
	}
	ctx := *s.ctx
	if s.bulkContent {
		ctx = service.WithBulkRead(ctx)
	}
	full, err := s.cfg.FolderSpace.GetItem(ctx, s.access(), item.ID)
	if err != nil {
		return item, err
	}
	item.Data = full.Data
	return item, nil
}

// beginContentPass marks the command in progress as a one-pass content read
// when it covers more than one message, and returns the function that ends
// the mark. A single message is read interactively and stays cacheable.
func (s *Session) beginContentPass(messages int) func() {
	if messages <= 1 || s.bulkContent {
		return func() {}
	}
	s.bulkContent = true
	return func() { s.bulkContent = false }
}

// sequenceNumbers maps each UID of items, which must be in UID order, to its
// 1-based message sequence number.
func sequenceNumbers(items []model.Item) map[uint32]int {
	sequences := make(map[uint32]int, len(items))
	for index, item := range items {
		sequences[item.UID] = index + 1
	}
	return sequences
}

// getSequenceItems returns items with their 1-based sequence numbers.
func (s *Session) getSequenceItems() ([]model.Item, error) {
	items, err := s.loadItems()
	if err != nil || !s.viewActive {
		return items, err
	}
	return s.viewItems(items), nil
}

// cmdFetch handles the FETCH command (RFC 3501).
// With CONDSTORE (RFC 4551), supports IFMODSEQ guards.
func (s *Session) cmdFetch(tag string, args []string) {
	if len(args) < 2 {
		s.sendBAD(tag, "Expected: FETCH sequence-set macro/section")
		return
	}

	seqSet, err := parseSeqSet(args[0], s)
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid sequence set: %v", err))
		return
	}
	defer s.beginContentPass(len(seqSet))()

	fetchAttrs := strings.ToUpper(strings.Join(args[1:], " "))
	// Extract IFMODSEQ guard if present
	ifModSeq, attrsNoGuard := extractIfModSeq(fetchAttrs)
	attrsNoGuard, modifierText := splitFetchModifiers(attrsNoGuard)
	modifiers, err := parseFetchModifiers(modifierText)
	if err != nil {
		s.sendBAD(tag, "Invalid FETCH modifier: "+err.Error())
		return
	}
	if modifiers.vanished {
		s.sendBAD(tag, "VANISHED is only valid with UID FETCH")
		return
	}
	changedSince := modifiers.changedSince
	attrsNoGuard = s.prepareFetchItems(attrsNoGuard, false, modifiers.hasChangedSince)
	s.loadStoredPreviews(attrsNoGuard)
	items, err := s.getSequenceItems()
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("FETCH failed: %v", err))
		return
	}

	for _, seq := range seqSet {
		if seq < 1 || seq > len(items) {
			continue
		}
		item := items[seq-1]
		if s.expungedPending(item.UID) {
			// RFC 3501 7.4.1: the expunge is reported after this command.
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

	s.sendOK(tag, "FETCH completed")
}

// fetchItem formats and sends a FETCH response for a single item.
func (s *Session) fetchItem(seq int, item model.Item, attrs string) error {
	if expanded, ok := fetchMacros[attrs]; ok {
		attrs = expanded
	}

	parts, literals, err := s.parseFetchAttrs(attrs, item)
	if err != nil {
		return err
	}
	// Build FETCH response, handling literals per RFC 3501 §2.3.2.
	// The literal size specifier {N} must be the last token before CRLF.
	if len(literals) == 0 {
		s.sendUntagged(fmt.Sprintf("* %d FETCH (%s)", seq, strings.Join(parts, " ")))
	} else {
		if _, err := fmt.Fprintf(s.rw, "* %d FETCH (", seq); err != nil {
			return err
		}
		literalIndex := 0
		for index, part := range parts {
			if index > 0 {
				if _, err := s.rw.WriteString(" "); err != nil {
					return err
				}
			}
			if _, err := s.rw.WriteString(part); err != nil {
				return err
			}
			if strings.Contains(part, "{") {
				if literalIndex >= len(literals) {
					return errors.New("FETCH literal marker has no data")
				}
				if _, err := s.rw.WriteString("\r\n"); err != nil {
					return err
				}
				if err := s.flush(); err != nil {
					return err
				}
				if _, err := s.rw.Write(literals[literalIndex].data); err != nil {
					return err
				}
				literalIndex++
			}
		}
		if literalIndex != len(literals) {
			return errors.New("FETCH literal data has no marker")
		}
		if _, err := s.rw.WriteString(")\r\n"); err != nil {
			return err
		}
		if err := s.flush(); err != nil {
			return err
		}
	}
	return nil
}

// fetchLiteral holds a literal data chunk to be sent after the response line.
type fetchLiteral struct {
	label string // e.g. "BODY[]", "BODY[HEADER]", "BODY[TEXT]"
	data  []byte
}

var errFetchSyntax = errors.New("invalid FETCH syntax")

// parseFetchAttrs parses the FETCH attribute list and returns formatted parts
// plus any literal data that must be sent after the response line.
func (s *Session) parseFetchAttrs(attrs string, item model.Item) ([]string, []fetchLiteral, error) {
	var parts []string
	var literals []fetchLiteral
	// Strip outer parentheses from IMAP list syntax: "(UID FLAGS)" → "UID FLAGS"
	attrs = strings.TrimSpace(attrs)
	if len(attrs) >= 2 && attrs[0] == '(' && attrs[len(attrs)-1] == ')' {
		attrs = attrs[1 : len(attrs)-1]
	}
	tokens := mergePreviewModifiers(tokenizeFetchAttrs(attrs))
	if len(tokens) == 0 {
		return nil, nil, fmt.Errorf("%w: no data items", errFetchSyntax)
	}
	// loadContent reads the message content once, for the first data item
	// that needs it; flag and size items are answered from metadata.
	loadContent := func() error {
		var err error
		item, err = s.withContent(item)
		return err
	}

	for _, token := range tokens {
		token = strings.ToUpper(token)
		bodyRequest, body, err := parseBodyFetch(token)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", errFetchSyntax, err)
		}
		if body || fetchItemNeedsContent(token) || token == "PREVIEW" && !s.hasStoredPreview(item) || token == "THREADID" && !headersStored(item) {
			if err := loadContent(); err != nil {
				return nil, nil, err
			}
		}
		if body {
			data, sectionErr := bodySection(item.Data, bodyRequest.section)
			if sectionErr != nil {
				return nil, nil, sectionErr
			}
			label := "BODY[" + bodyRequest.section + "]"
			if bodyRequest.partial {
				start := min(bodyRequest.partialFrom, int64(len(data)))
				end := start + min(bodyRequest.partialSize, int64(len(data))-start)
				data = data[int(start):int(end)]
				label += fmt.Sprintf("<%d>", bodyRequest.partialFrom)
			}
			parts = append(parts, fmt.Sprintf("%s {%d}", label, len(data)))
			literals = append(literals, fetchLiteral{label: label, data: data})
			continue
		}
		binaryRequest, binary, err := parseBinaryFetch(token)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", errFetchSyntax, err)
		}
		if binary {
			if err := loadContent(); err != nil {
				return nil, nil, err
			}
			data, sectionErr := binarySection(item.Data, binaryRequest.section)
			if sectionErr != nil {
				return nil, nil, sectionErr
			}
			label := "BINARY[" + binaryRequest.section + "]"
			if binaryRequest.sizeOnly {
				parts = append(parts, fmt.Sprintf("BINARY.SIZE[%s] %d", binaryRequest.section, len(data)))
				continue
			}
			if binaryRequest.partial {
				start := min(binaryRequest.partialFrom, int64(len(data)))
				end := start + min(binaryRequest.partialSize, int64(len(data))-start)
				data = data[int(start):int(end)]
				label += fmt.Sprintf("<%d>", binaryRequest.partialFrom)
			}
			literalMarker := fmt.Sprintf("{%d}", len(data))
			if bytes.IndexByte(data, 0) >= 0 {
				literalMarker = fmt.Sprintf("~{%d}", len(data))
			}
			parts = append(parts, label+" "+literalMarker)
			literals = append(literals, fetchLiteral{label: label, data: data})
			continue
		}
		switch {
		case token == "FLAGS":
			flags := formatFlags(item.Flags)
			parts = append(parts, fmt.Sprintf("FLAGS %s", flags))
		case token == "INTERNALDATE":
			parts = append(parts, fmt.Sprintf("INTERNALDATE %s", formatInternalDate(item.InternalDate)))
		case token == "RFC822.SIZE":
			if item.Size < 0 {
				return nil, nil, errors.New("invalid negative message size")
			}
			parts = append(parts, fmt.Sprintf("RFC822.SIZE %d", item.Size))
		case token == "UID":
			parts = append(parts, fmt.Sprintf("UID %d", item.UID))
		case token == "MODSEQ":
			parts = append(parts, fmt.Sprintf("MODSEQ (%d)", item.ModSeq))
		case token == "EMAILID":
			parts = append(parts, fmt.Sprintf("EMAILID (%s)", emailID(item)))
		case token == "THREADID":
			parts = append(parts, fmt.Sprintf("THREADID (%s)", threadID(item)))
		case token == "SAVEDATE":
			parts = append(parts, formatSaveDate(item))
		case token == "PREVIEW" || token == "PREVIEW(LAZY)":
			part, literal := s.previewFetchItem(item, token == "PREVIEW(LAZY)")
			parts = append(parts, part)
			if literal != nil {
				literals = append(literals, *literal)
			}
		case token == "ENVELOPE":
			parts = append(parts, "ENVELOPE "+envelope(item))
		case token == "BODY":
			parts = append(parts, "BODY "+bodyStructure(item, false))
		case token == "BODY.BINARY":
			// RFC 3516 BODY.BINARY — return raw binary data without MIME decoding
			// BODY.BINARY is like BODY[] but guarantees no 7-bit translation
			parts = append(parts, fmt.Sprintf("BODY.BINARY {%d}", len(item.Data)))
			literals = append(literals, fetchLiteral{label: "BODY.BINARY", data: item.Data})
		case token == "BODYSTRUCTURE":
			parts = append(parts, "BODYSTRUCTURE "+bodyStructure(item, true))
		default:
			return nil, nil, fmt.Errorf("%w: unknown data item %q", errFetchSyntax, token)
		}
	}

	return parts, literals, nil
}

// fetchItemNeedsContent reports whether a non-section FETCH data item is
// computed from the message content rather than its metadata.
func fetchItemNeedsContent(token string) bool {
	switch token {
	case "ENVELOPE", "BODY", "BODY.BINARY", "BODYSTRUCTURE":
		return true
	}
	return false
}

func fetchSetsSeen(attrs string) bool {
	upper := strings.ToUpper(attrs)
	for _, token := range tokenizeFetchAttrs(upper) {
		if strings.HasPrefix(token, "BODY[") || strings.HasPrefix(token, "BINARY[") {
			return true
		}
	}
	return false
}

func (s *Session) sendFetchError(tag string, err error) {
	if errors.Is(err, errFetchSyntax) {
		s.sendBAD(tag, err.Error())
		return
	}
	if errors.Is(err, errUnknownCTE) {
		s.sendNO(tag, "[UNKNOWN-CTE] FETCH section cannot be decoded")
		return
	}
	s.sendNO(tag, fmt.Sprintf("FETCH failed: %v", err))
}

// tokenizeFetchAttrs splits FETCH attributes handling parentheses and brackets.
func tokenizeFetchAttrs(s string) []string {
	var tokens []string
	var current strings.Builder
	parenDepth := 0
	bracketDepth := 0

	for _, r := range s {
		switch r {
		case '(':
			parenDepth++
			current.WriteRune(r)
		case ')':
			parenDepth--
			current.WriteRune(r)
		case '[':
			bracketDepth++
			current.WriteRune(r)
		case ']':
			bracketDepth--
			current.WriteRune(r)
		case ' ':
			if parenDepth == 0 && bracketDepth == 0 {
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(r)
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// extractIfModSeq parses IFMODSEQ(modseq) from FETCH attributes.
// Returns the modseq value (0 if not present) and the remaining attributes.
func extractIfModSeq(attrs string) (uint64, string) {
	// IFMODSEQ appears as a token like "IFMODSEQ(1234)"
	idx := strings.Index(attrs, "IFMODSEQ")
	if idx < 0 {
		return 0, attrs
	}

	// Find the opening paren
	open := strings.Index(attrs[idx:], "(")
	if open < 0 {
		return 0, attrs
	}
	open += idx

	close := strings.Index(attrs[open:], ")")
	if close < 0 {
		return 0, attrs
	}
	close += open

	modSeqStr := strings.TrimSpace(attrs[open+1 : close])
	modSeq, err := strconv.ParseUint(modSeqStr, 10, 64)
	if err != nil {
		return 0, attrs
	}

	// Remove IFMODSEQ(...) from the attribute string
	remaining := strings.TrimSpace(attrs[:idx] + attrs[close+1:])
	return modSeq, remaining
}

// fetchModifiers holds the RFC 4466 fetch modifiers Veksel supports:
// CHANGEDSINCE (RFC 7162 3.1.4) and VANISHED (RFC 7162 3.2.6).
type fetchModifiers struct {
	changedSince    uint64
	hasChangedSince bool
	vanished        bool
}

// splitFetchModifiers separates a trailing fetch-modifier list from the data
// items, as in "(FLAGS) (CHANGEDSINCE 5 VANISHED)". The list is recognised
// only when it starts with a known modifier, so a data item list is never
// mistaken for one.
func splitFetchModifiers(attrs string) (string, string) {
	tokens := tokenizeFetchAttrs(strings.TrimSpace(attrs))
	if len(tokens) < 2 {
		return attrs, ""
	}
	last := tokens[len(tokens)-1]
	if len(last) < 2 || last[0] != '(' || last[len(last)-1] != ')' {
		return attrs, ""
	}
	inner := strings.Fields(strings.ToUpper(last[1 : len(last)-1]))
	if len(inner) == 0 || (inner[0] != "CHANGEDSINCE" && inner[0] != "VANISHED") {
		return attrs, ""
	}
	return strings.Join(tokens[:len(tokens)-1], " "), strings.Join(inner, " ")
}

func parseFetchModifiers(text string) (fetchModifiers, error) {
	var modifiers fetchModifiers
	fields := strings.Fields(text)
	for index := 0; index < len(fields); index++ {
		switch fields[index] {
		case "CHANGEDSINCE":
			if index+1 >= len(fields) {
				return modifiers, errors.New("CHANGEDSINCE requires a mod-sequence")
			}
			index++
			value, err := strconv.ParseUint(fields[index], 10, 63)
			if err != nil {
				return modifiers, fmt.Errorf("invalid CHANGEDSINCE value %q", fields[index])
			}
			modifiers.changedSince, modifiers.hasChangedSince = value, true
		case "VANISHED":
			modifiers.vanished = true
		default:
			return modifiers, fmt.Errorf("unknown fetch modifier %q", fields[index])
		}
	}
	return modifiers, nil
}

// fetchMacros expands the RFC 3501 6.4.5 macros.
var fetchMacros = map[string]string{
	"ALL":  "(FLAGS INTERNALDATE RFC822.SIZE ENVELOPE)",
	"FAST": "(FLAGS INTERNALDATE RFC822.SIZE)",
	"FULL": "(FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY)",
}

// prepareFetchItems expands a macro and adds the data items a response must
// carry although the client did not name them: UID for UID FETCH (RFC 3501
// 6.4.8) and MODSEQ once CONDSTORE is in use (RFC 7162 3.1.4).
func (s *Session) prepareFetchItems(attrs string, uid, changedSince bool) string {
	attrs = strings.TrimSpace(attrs)
	if expanded, ok := fetchMacros[attrs]; ok {
		attrs = expanded
	}
	list := attrs
	if len(list) >= 2 && list[0] == '(' && list[len(list)-1] == ')' {
		list = list[1 : len(list)-1]
	}
	tokens := tokenizeFetchAttrs(list)
	hasUID, hasFlags, hasModSeq := false, false, false
	for _, token := range tokens {
		switch token {
		case "UID":
			hasUID = true
		case "FLAGS":
			hasFlags = true
		case "MODSEQ":
			hasModSeq = true
		}
	}
	if hasModSeq || changedSince {
		s.condstoreEnabled = true
	}
	if uid && !hasUID {
		tokens = append([]string{"UID"}, tokens...)
	}
	if !hasModSeq && (changedSince || s.condstoreEnabled && hasFlags) {
		tokens = append(tokens, "MODSEQ")
	}
	return "(" + strings.Join(tokens, " ") + ")"
}
