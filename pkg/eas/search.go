package eas

import (
	"bytes"
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

const (
	defaultSearchRange = 100
	maxSearchResults   = 1000
	// maxScannedItems bounds the fallback scan when no search index exists.
	maxScannedItems = 5000
)

// parseRange reads an EAS Range ("0-99") as a start index and count.
func searchRange(value string) (int, int) {
	first, last, ok := strings.Cut(value, "-")
	start, err1 := strconv.Atoi(first)
	end, err2 := strconv.Atoi(last)
	if !ok || err1 != nil || err2 != nil || start < 0 || end < start {
		return 0, defaultSearchRange
	}
	return start, min(end-start+1, maxSearchResults)
}

func (h *Handler) search(command *commandContext) (*Node, error) {
	store := command.request.Child("Store")
	if store == nil {
		return E(15, "Search", T(15, "Status", "2")), nil
	}
	name := strings.ToLower(childText(store, "Name"))
	options := store.Child("Options")
	start, count := searchRange(childText(options, "Range"))
	var result *Node
	var err error
	switch name {
	case "gal":
		result = h.searchDirectory(command, childText(store, "Query"), start, count)
	case "mailbox":
		result, err = h.searchMailbox(command, store.Child("Query"), options, start, count)
	default:
		result = E(15, "Store", T(15, "Status", "3"))
	}
	if err != nil {
		return nil, err
	}
	return E(15, "Search", T(15, "Status", "1"), E(15, "Response", result)), nil
}

func searchStore(results []*Node, start, total int) *Node {
	store := E(15, "Store", T(15, "Status", "1"))
	if len(results) == 0 {
		store.Children = append(store.Children, E(15, "Result"), T(15, "Total", "0"))
		return store
	}
	store.Children = append(store.Children, results...)
	store.Children = append(store.Children, T(15, "Range", strconv.Itoa(start)+"-"+strconv.Itoa(start+len(results)-1)), T(15, "Total", strconv.Itoa(total)))
	return store
}

func (h *Handler) searchDirectory(command *commandContext, query string, start, count int) *Node {
	query = strings.TrimSpace(query)
	if h.account == nil || query == "" {
		return searchStore(nil, start, 0)
	}
	entries, err := h.account.Directory(command.ctx, command.userID, query, start+count)
	if err != nil {
		return E(15, "Store", T(15, "Status", "10"))
	}
	var results []*Node
	for index := start; index < len(entries) && len(results) < count; index++ {
		results = append(results, E(15, "Result", galProperties(entries[index])))
	}
	return searchStore(results, start, len(entries))
}

func galProperties(entry Profile) *Node {
	properties := E(15, "Properties")
	add := func(tag, value string) {
		if value = strings.TrimSpace(value); value != "" {
			properties.Children = append(properties.Children, T(16, tag, value))
		}
	}
	add("DisplayName", firstNonEmpty(entry.DisplayName, entry.primary(), entry.ID))
	if first, last, ok := strings.Cut(strings.TrimSpace(entry.DisplayName), " "); ok {
		add("FirstName", first)
		add("LastName", last)
	}
	add("Alias", entry.ID)
	add("EmailAddress", entry.primary())
	return properties
}

// searchMailbox runs a Search Mailbox query: FreeText within the requested
// collection (or every mail folder with DeepTraversal), newest first.
func (h *Handler) searchMailbox(command *commandContext, query, options *Node, start, count int) (*Node, error) {
	if query == nil {
		return E(15, "Store", T(15, "Status", "2")), nil
	}
	text := strings.TrimSpace(nodeText(query, "FreeText"))
	var folderIDs []string
	for _, node := range collectNodes(query, "CollectionId") {
		if folderID, err := decodeServerID(node.Text, "f:"); err == nil {
			folderIDs = append(folderIDs, folderID)
		}
	}
	var after time.Time
	if greater := query.Descendant("GreaterThan"); greater != nil {
		after, _ = parseEASTime(childText(greater, "Value"))
	}
	hits, err := h.mailboxHits(command, text, folderIDs, options.Child("DeepTraversal") != nil || len(folderIDs) == 0, after)
	if err != nil {
		return nil, err
	}
	settings := SyncOptions{BodyPreferences: parseBodyPreferences(options), MIMESupport: atoi(childText(options, "MIMESupport"))}
	if len(settings.BodyPreferences) == 0 {
		settings.BodyPreferences = []BodyPreference{{Type: bodyText, TruncationSize: 512}}
	}
	var results []*Node
	for index := start; index < len(hits) && len(results) < count; index++ {
		hit := hits[index]
		properties := h.emailData(command, hit.folder, hit.item, settings)
		properties.Page, properties.Tag = 15, "Properties"
		results = append(results, E(15, "Result",
			T(0, "Class", "Email"),
			T(15, "LongId", encodeServerID("i:", hit.item.ID)),
			T(0, "CollectionId", encodeServerID("f:", hit.folder.ID)),
			properties))
	}
	return searchStore(results, start, len(hits)), nil
}

func atoi(value string) int {
	number, _ := strconv.Atoi(value)
	return number
}

func collectNodes(root *Node, tag string) []*Node {
	if root == nil {
		return nil
	}
	var result []*Node
	if root.Tag == tag {
		result = append(result, root)
	}
	for _, child := range root.Children {
		result = append(result, collectNodes(child, tag)...)
	}
	return result
}

type mailboxHit struct {
	folder model.Folder
	item   model.Item
}

// mailboxHits searches with the account search index when one is
// configured, and otherwise scans headers in the selected folders.
func (h *Handler) mailboxHits(command *commandContext, text string, folderIDs []string, deep bool, after time.Time) ([]mailboxHit, error) {
	folders, err := h.space.ListFolders(command.ctx, command.access, service.FolderQuery{Type: model.FolderTypeMail})
	if err != nil {
		return nil, err
	}
	byID := map[string]model.Folder{}
	for _, folder := range folders {
		byID[folder.ID] = folder
	}
	selected := folderIDs
	if deep {
		selected = selected[:0:0]
		for _, folder := range folders {
			if strings.EqualFold(strings.TrimPrefix(folder.SpecialUse, "\\"), model.SpecialUseTrash) || strings.EqualFold(strings.TrimPrefix(folder.SpecialUse, "\\"), model.SpecialUseJunk) {
				continue
			}
			selected = append(selected, folder.ID)
		}
	}
	var hits []mailboxHit
	if h.searchIndex != nil && text != "" {
		page, searchErr := h.searchIndex.Search(command.ctx, command.access, service.SearchQuery{
			AccountID: command.userID, Text: text, FolderIDs: selected, Types: []model.FolderType{model.FolderTypeMail},
			Limit: maxSearchResults, OmitSnippets: true, Sort: "date_desc",
		})
		if searchErr == nil {
			for _, found := range page.Hits {
				folder, ok := byID[found.FolderID]
				if !ok {
					continue
				}
				item, getErr := h.space.GetItem(command.ctx, command.access, found.ItemID)
				if getErr != nil || (!after.IsZero() && item.InternalDate.Before(after)) {
					continue
				}
				hits = append(hits, mailboxHit{folder: folder, item: item})
			}
			return hits, nil
		}
	}
	needle := strings.ToLower(text)
	scanned := 0
	for _, folderID := range selected {
		folder, ok := byID[folderID]
		if !ok {
			continue
		}
		items, listErr := h.space.ListItems(command.ctx, command.access, folderID, service.ItemQuery{Since: after, MetadataOnly: true, RequireRead: true})
		if listErr != nil {
			return nil, listErr
		}
		for _, item := range items {
			if scanned >= maxScannedItems || len(hits) >= maxSearchResults {
				break
			}
			scanned++
			haystack := strings.ToLower(item.Headers["Subject"] + " " + item.Headers["From"] + " " + item.Headers["To"] + " " + item.Headers["Cc"])
			if needle != "" && !strings.Contains(haystack, needle) {
				continue
			}
			full, getErr := h.space.GetItem(command.ctx, command.access, item.ID)
			if getErr == nil {
				hits = append(hits, mailboxHit{folder: folder, item: full})
			}
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].item.InternalDate.After(hits[j].item.InternalDate) })
	return hits, nil
}

// find implements the protocol 16.1 Find command for mailbox and GAL
// criteria.
func (h *Handler) find(command *commandContext) (*Node, error) {
	request := command.request
	searchID := childText(request, "SearchId")
	execute := request.Child("ExecuteSearch")
	if execute == nil {
		return E(25, "Find", T(25, "Status", "2")), nil
	}
	if criterion := execute.Child("GalSearchCriterion"); criterion != nil {
		start, count := searchRange(childText(criterion.Child("Options"), "Range"))
		entries := []Profile(nil)
		if h.account != nil {
			if query := strings.TrimSpace(nodeText(criterion.Child("Query"), "FreeText")); query != "" {
				entries, _ = h.account.Directory(command.ctx, command.userID, query, start+count)
			}
		}
		response := E(25, "Response", T(20, "Store", "GAL"), T(25, "Status", "1"))
		returned := 0
		for index := start; index < len(entries) && returned < count; index++ {
			properties := galProperties(entries[index])
			properties.Page = 25
			response.Children = append(response.Children, E(25, "Result", properties))
			returned++
		}
		if returned > 0 {
			response.Children = append(response.Children, T(25, "Range", strconv.Itoa(start)+"-"+strconv.Itoa(start+returned-1)))
		}
		response.Children = append(response.Children, T(25, "Total", strconv.Itoa(len(entries))))
		return E(25, "Find", T(25, "SearchId", searchID), T(25, "Status", "1"), response), nil
	}
	criterion := execute.Child("MailBoxSearchCriterion")
	if criterion == nil {
		return E(25, "Find", T(25, "Status", "2")), nil
	}
	query := criterion.Child("Query")
	options := criterion.Child("Options")
	start, count := searchRange(childText(options, "Range"))
	var folderIDs []string
	if folderID, err := decodeServerID(childText(query, "CollectionId"), "f:"); err == nil {
		folderIDs = append(folderIDs, folderID)
	}
	hits, err := h.mailboxHits(command, strings.TrimSpace(childText(query, "FreeText")), folderIDs, options.Child("DeepTraversal") != nil || len(folderIDs) == 0, time.Time{})
	if err != nil {
		return nil, err
	}
	response := E(25, "Response", T(20, "Store", "Mailbox"), T(25, "Status", "1"))
	returned := 0
	for index := start; index < len(hits) && returned < count; index++ {
		hit := hits[index]
		projection, _ := service.ProjectMIME(hit.item.Data)
		text := projection.Text
		if text == "" && projection.HTML != "" {
			text = service.HTMLToText(projection.HTML)
		}
		properties := E(25, "Properties",
			T(2, "Subject", itemSubject(hit.item)),
			T(2, "DateReceived", hit.item.InternalDate.UTC().Format(easDateFormat)),
			T(25, "DisplayTo", displayNames(projection.Headers["To"])),
			T(2, "Importance", easImportance(hit.item.Headers)),
			T(2, "Read", boolNumber(hasFlag(hit.item.Flags, model.FlagSeen))),
			T(25, "Preview", string(truncateUTF8([]byte(collapseWhitespace(text)), 255, true))),
			T(25, "HasAttachments", boolNumber(len(projection.Attachments) > 0)),
			T(2, "From", projection.Headers["From"]),
		)
		response.Children = append(response.Children, E(25, "Result",
			T(0, "Class", "Email"),
			T(0, "ServerId", encodeServerID("i:", hit.item.ID)),
			T(0, "CollectionId", encodeServerID("f:", hit.folder.ID)),
			properties))
		returned++
	}
	if returned > 0 {
		response.Children = append(response.Children, T(25, "Range", strconv.Itoa(start)+"-"+strconv.Itoa(start+returned-1)))
	}
	response.Children = append(response.Children, T(25, "Total", strconv.Itoa(len(hits))))
	return E(25, "Find", T(25, "SearchId", searchID), T(25, "Status", "1"), response), nil
}

// resolveRecipients resolves each To against the GAL and the user's
// contacts (MS-ASCMD 2.2.1.15).
func (h *Handler) resolveRecipients(command *commandContext) (*Node, error) {
	request := command.request
	if request == nil {
		return E(10, "ResolveRecipients", T(10, "Status", "5")), nil
	}
	options := request.Child("Options")
	maxAmbiguous := 20
	if value := atoi(childText(options, "MaxAmbiguousRecipients")); value > 0 {
		maxAmbiguous = min(value, 100)
	}
	response := E(10, "ResolveRecipients", T(10, "Status", "1"))
	for _, to := range request.ChildrenNamed("To") {
		query := strings.TrimSpace(to.Text)
		matches := h.recipientMatches(command, query, maxAmbiguous)
		entry := E(10, "Response", T(10, "To", query))
		switch {
		case len(matches) == 0:
			entry.Children = append(entry.Children, T(10, "Status", "4"), T(10, "RecipientCount", "0"))
		default:
			status := "1"
			if len(matches) > 1 {
				status = "2"
			}
			entry.Children = append(entry.Children, T(10, "Status", status), T(10, "RecipientCount", strconv.Itoa(len(matches))))
			for _, match := range matches {
				recipient := E(10, "Recipient", T(10, "Type", match.kind), T(10, "DisplayName", firstNonEmpty(match.name, match.address)), T(10, "EmailAddress", match.address))
				if availability := options.Child("Availability"); availability != nil {
					recipient.Children = append(recipient.Children, h.availability(command, match.address, availability))
				}
				if retrieval := childText(options, "CertificateRetrieval"); retrieval == "2" || retrieval == "3" {
					recipient.Children = append(recipient.Children, E(10, "Certificates", T(10, "Status", "7"), T(10, "CertificateCount", "0")))
				}
				entry.Children = append(entry.Children, recipient)
			}
		}
		response.Children = append(response.Children, entry)
	}
	return response, nil
}

type recipientMatch struct {
	kind    string // 1 GAL, 2 contact
	name    string
	address string
}

func (h *Handler) recipientMatches(command *commandContext, query string, limit int) []recipientMatch {
	if query == "" {
		return nil
	}
	var matches []recipientMatch
	seen := map[string]bool{}
	if h.account != nil {
		entries, err := h.account.Directory(command.ctx, command.userID, query, limit)
		if err == nil {
			for _, entry := range entries {
				if address := entry.primary(); address != "" && !seen[address] {
					seen[address] = true
					matches = append(matches, recipientMatch{kind: "1", name: entry.DisplayName, address: address})
				}
			}
		}
	}
	folders, err := h.space.ListFolders(command.ctx, command.access, service.FolderQuery{Type: model.FolderTypeContacts})
	if err != nil {
		return matches
	}
	needle := strings.ToLower(query)
	for _, folder := range folders {
		if folder.SpecialUse == model.SpecialUseRecentRecipients {
			continue
		}
		items, listErr := h.space.ListItems(command.ctx, command.access, folder.ID, service.ItemQuery{})
		if listErr != nil {
			continue
		}
		for _, item := range items {
			if len(matches) >= limit {
				return matches
			}
			contact := model.ParseVCard(item.Data)
			for _, address := range contact.Emails {
				address = strings.ToLower(strings.TrimSpace(address))
				if address == "" || seen[address] {
					continue
				}
				if strings.Contains(address, needle) || strings.Contains(strings.ToLower(contact.FN), needle) {
					seen[address] = true
					matches = append(matches, recipientMatch{kind: "2", name: contact.FN, address: address})
				}
			}
		}
	}
	return matches
}

// BusyPeriod is one busy interval of an attendee.
type BusyPeriod struct {
	Start, End time.Time
	Tentative  bool
}

// FreeBusyReader is the optional Account capability behind
// ResolveRecipients availability. It reports known=false when the
// requester may not see the address's free/busy information.
type FreeBusyReader interface {
	FreeBusy(ctx context.Context, access service.AccessContext, address string, start, end time.Time) ([]BusyPeriod, bool, error)
}

// maxAvailabilitySlots bounds MergedFreeBusy to 42 days of half hours.
const maxAvailabilitySlots = 42 * 48

// availability renders MergedFreeBusy: one digit per 30 minutes, 0 free,
// 1 tentative, 2 busy (MS-ASCMD 2.2.3.108).
func (h *Handler) availability(command *commandContext, address string, request *Node) *Node {
	reader, ok := h.account.(FreeBusyReader)
	start, okStart := parseEASTime(childText(request, "StartTime"))
	end, okEnd := parseEASTime(childText(request, "EndTime"))
	if !okStart || !okEnd || !end.After(start) {
		return E(10, "Availability", T(10, "Status", "162"))
	}
	if !ok {
		return E(10, "Availability", T(10, "Status", "162"))
	}
	slots := int(end.Sub(start) / (30 * time.Minute))
	if end.Sub(start)%(30*time.Minute) != 0 {
		slots++
	}
	if slots > maxAvailabilitySlots {
		return E(10, "Availability", T(10, "Status", "162"))
	}
	periods, known, err := reader.FreeBusy(command.ctx, command.access, address, start, end)
	if err != nil || !known {
		return E(10, "Availability", T(10, "Status", "163"))
	}
	merged := bytes.Repeat([]byte{'0'}, slots)
	for _, period := range periods {
		for slot := range merged {
			slotStart := start.Add(time.Duration(slot) * 30 * time.Minute)
			if period.Start.Before(slotStart.Add(30*time.Minute)) && period.End.After(slotStart) {
				value := byte('2')
				if period.Tentative {
					value = '1'
				}
				if merged[slot] < value {
					merged[slot] = value
				}
			}
		}
	}
	return E(10, "Availability", T(10, "Status", "1"), T(10, "MergedFreeBusy", string(merged)))
}
