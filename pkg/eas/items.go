package eas

import (
	"encoding/base64"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// maxFetchBytes bounds one in-band attachment fetch.
const maxFetchBytes = 32 << 20

func (h *Handler) itemEstimate(command *commandContext) (*Node, error) {
	response := E(6, "GetItemEstimate")
	collections := command.request.Child("Collections")
	if collections == nil {
		return E(6, "GetItemEstimate", T(6, "Status", "2")), nil
	}
	for _, collection := range collections.ChildrenNamed("Collection") {
		collectionID := childText(collection, "CollectionId")
		entry := func(status, estimate string) *Node {
			result := E(6, "Response", T(6, "Status", status))
			body := E(6, "Collection", T(6, "CollectionId", collectionID))
			if estimate != "" {
				body.Children = append(body.Children, T(6, "Estimate", estimate))
			}
			result.Children = append(result.Children, body)
			return result
		}
		folderID, err := decodeServerID(collectionID, "f:")
		if err != nil {
			response.Children = append(response.Children, entry("2", ""))
			continue
		}
		folder, err := h.space.GetFolder(command.ctx, command.access, folderID)
		if err != nil || !easSyncable(folder.Type) {
			response.Children = append(response.Children, entry("2", ""))
			continue
		}
		key := childText(collection, "SyncKey")
		switch {
		case key == "0" || command.state.CollectionKeys[folderID] == "":
			response.Children = append(response.Children, entry("3", ""))
			continue
		case key != "" && key != command.state.CollectionKeys[folderID]:
			response.Children = append(response.Children, entry("4", ""))
			continue
		}
		options := command.state.CollectionOptions[folderID]
		if parsed, present := parseSyncOptions(collection, folder.Type); present {
			options = parsed
		}
		estimate, err := h.estimate(command, folder, options)
		if errors.Is(err, service.ErrChangeStateExpired) {
			response.Children = append(response.Children, entry("4", ""))
			continue
		}
		if err != nil {
			return nil, err
		}
		response.Children = append(response.Children, entry("1", strconv.Itoa(estimate)))
	}
	return response, nil
}

// estimate counts what the next Sync windows would deliver without
// advancing any state.
func (h *Handler) estimate(command *commandContext, folder model.Folder, options SyncOptions) (int, error) {
	state := command.state
	if _, initial := state.CollectionInitialStates[folder.ID]; initial {
		cursor, startedAt := state.cursor(folder.ID)
		query := service.ItemQuery{MetadataOnly: true}
		if folder.Type == model.FolderTypeMail {
			query.Since = filterCutoff(options.FilterType, time.Now().UTC())
		}
		items, err := h.space.ListItems(command.ctx, command.access, folder.ID, query)
		if err != nil {
			return 0, err
		}
		count := 0
		for _, item := range items {
			if strings.HasPrefix(cursor, "uid:") {
				// UID enumeration walks downwards from the newest item.
				if before, _ := strconv.ParseUint(strings.TrimPrefix(cursor, "uid:"), 10, 32); before == 0 || uint64(item.UID) < before {
					count++
				}
				continue
			}
			if item.ID > cursor && (startedAt.IsZero() || !item.CreatedAt.After(startedAt)) {
				count++
			}
		}
		return count, nil
	}
	base := state.CollectionStates[folder.ID]
	if base == "" {
		return 0, nil
	}
	reader := h.space.(service.FolderChangeReader)
	page, err := reader.ListChanges(command.ctx, command.access, service.ChangeScope{FolderID: folder.ID, Object: service.ChangeObjectItem}, base, maxWindowSize)
	if err != nil {
		return 0, err
	}
	return len(newEchoSet(state.CollectionEchoes[folder.ID]).pendingIDs(page, folder.ID)), nil
}

func (h *Handler) itemOperations(command *commandContext) (*Node, error) {
	if command.request == nil {
		return E(20, "ItemOperations", T(20, "Status", "2")), nil
	}
	results := E(20, "Response")
	for _, operation := range command.request.Children {
		switch operation.Tag {
		case "Fetch":
			results.Children = append(results.Children, h.fetch(command, operation))
		case "EmptyFolderContents":
			node, err := h.emptyFolder(command, operation)
			if err != nil {
				return nil, err
			}
			results.Children = append(results.Children, node)
		case "Move":
			results.Children = append(results.Children, E(20, "Move", T(20, "Status", "2"), T(20, "ConversationId", childText(operation, "ConversationId"))))
		}
	}
	return E(20, "ItemOperations", T(20, "Status", "1"), results), nil
}

// fetch implements ItemOperations Fetch of a mailbox item (ServerId with
// CollectionId, or a Search LongId) or of an attachment (FileReference).
func (h *Handler) fetch(command *commandContext, request *Node) *Node {
	if store := childText(request, "Store"); store != "" && !strings.EqualFold(store, "Mailbox") {
		return E(20, "Fetch", T(20, "Status", "9"))
	}
	options := request.Child("Options")
	if reference := childText(request, "FileReference"); reference != "" {
		return h.fetchAttachment(command, reference, childText(options, "Range"))
	}
	serverID := childText(request, "ServerId")
	collectionID := childText(request, "CollectionId")
	longID := childText(request, "LongId")
	fetchID := serverID
	if fetchID == "" {
		fetchID = longID
	}
	id, err := decodeServerID(fetchID, "i:")
	failure := func(status string) *Node {
		node := E(20, "Fetch", T(20, "Status", status))
		if collectionID != "" {
			node.Children = append(node.Children, T(0, "CollectionId", collectionID))
		}
		if serverID != "" {
			node.Children = append(node.Children, T(0, "ServerId", serverID))
		} else if longID != "" {
			node.Children = append(node.Children, T(15, "LongId", longID))
		}
		return node
	}
	if err != nil {
		return failure("6")
	}
	item, err := h.space.GetItem(command.ctx, command.access, id)
	if err != nil || !item.TrashedAt.IsZero() {
		return failure("6")
	}
	folder, err := h.space.GetFolder(command.ctx, command.access, item.FolderID)
	if err != nil || !easSyncable(folder.Type) {
		return failure("6")
	}
	settings := command.state.CollectionOptions[folder.ID]
	if options != nil {
		if preferences := parseBodyPreferences(options); len(preferences) > 0 {
			settings.BodyPreferences = preferences
		} else {
			settings.BodyPreferences = untruncated(settings.BodyPreferences)
		}
		if support := childText(options, "MIMESupport"); support != "" {
			settings.MIMESupport, _ = strconv.Atoi(support)
		}
	} else {
		settings.BodyPreferences = untruncated(settings.BodyPreferences)
	}
	properties := h.applicationData(command, folder, item, settings)
	properties.Page, properties.Tag = 20, "Properties"
	node := failure("1")
	node.Children = append(node.Children, T(0, "Class", easClass(folder.Type)), properties)
	return node
}

func (h *Handler) fetchAttachment(command *commandContext, reference, byteRange string) *Node {
	failure := func(status string) *Node {
		return E(20, "Fetch", T(20, "Status", status), T(17, "FileReference", reference))
	}
	decoded, err := decodeServerID(reference, "a:")
	separator := strings.LastIndex(decoded, "/")
	if err != nil || separator <= 0 {
		return failure("15")
	}
	itemID, partID := decoded[:separator], decoded[separator+1:]
	stream, err := service.NewMIMEReader(h.space).OpenAttachment(command.ctx, command.access, itemID, partID)
	if err != nil {
		return failure("15")
	}
	defer func() { _ = stream.Reader.Close() }()
	content, err := io.ReadAll(io.LimitReader(stream.Reader, maxFetchBytes+1))
	if err != nil {
		return failure("3")
	}
	if len(content) > maxFetchBytes {
		return failure("11")
	}
	total := len(content)
	properties := E(20, "Properties", T(17, "ContentType", stream.ContentType))
	if byteRange != "" {
		first, last, ok := parseRange(byteRange, total)
		if !ok {
			return failure("8")
		}
		content = content[first : last+1]
		properties.Children = append(properties.Children, T(20, "Range", strconv.Itoa(first)+"-"+strconv.Itoa(last)), T(20, "Total", strconv.Itoa(total)))
	}
	properties.Children = append(properties.Children, T(20, "Data", base64.StdEncoding.EncodeToString(content)))
	return E(20, "Fetch", T(20, "Status", "1"), T(17, "FileReference", reference), properties)
}

func parseRange(value string, total int) (int, int, bool) {
	firstText, lastText, ok := strings.Cut(value, "-")
	first, err1 := strconv.Atoi(firstText)
	last, err2 := strconv.Atoi(lastText)
	if !ok || err1 != nil || err2 != nil || first < 0 || first > last || total == 0 || first >= total {
		return 0, 0, false
	}
	return first, min(last, total-1), true
}

// getAttachment serves the protocol 12.1 GetAttachment command, which
// returns the attachment bytes as the HTTP body.
func (h *Handler) getAttachment(command *commandContext) (*Node, error) {
	reference := command.line.Attachment
	decoded, err := decodeServerID(reference, "a:")
	separator := strings.LastIndex(decoded, "/")
	if err != nil || separator <= 0 {
		return nil, errAttachmentNotFound
	}
	stream, err := service.NewMIMEReader(h.space).OpenAttachment(command.ctx, command.access, decoded[:separator], decoded[separator+1:])
	if err != nil {
		return nil, errAttachmentNotFound
	}
	defer func() { _ = stream.Reader.Close() }()
	content, err := io.ReadAll(io.LimitReader(stream.Reader, maxFetchBytes+1))
	if err != nil || len(content) > maxFetchBytes {
		return nil, errAttachmentNotFound
	}
	command.rawResponse, command.rawContentType = content, stream.ContentType
	return nil, nil
}

var errAttachmentNotFound = errors.New("attachment not found")

func (h *Handler) emptyFolder(command *commandContext, request *Node) (*Node, error) {
	collectionID := childText(request, "CollectionId")
	result := func(status string) *Node {
		return E(20, "EmptyFolderContents", T(20, "Status", status), T(0, "CollectionId", collectionID))
	}
	folderID, err := decodeServerID(collectionID, "f:")
	if err != nil {
		return result("6"), nil
	}
	folder, err := h.space.GetFolder(command.ctx, command.access, folderID)
	if err != nil || !easSyncable(folder.Type) {
		return result("6"), nil
	}
	items, err := h.space.ListItems(command.ctx, command.access, folderID, service.ItemQuery{MetadataOnly: true})
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if err := h.space.DeleteItem(command.ctx, command.access, item.ID); err != nil {
			if service.IsTemporarilyUnavailable(err) {
				return nil, err
			}
			return result("3"), nil
		}
		command.state.addEcho(folderID, Echo{ID: item.ID, Removed: true})
	}
	if request.Descendant("DeleteSubFolders") != nil {
		folders, err := h.space.ListFolders(command.ctx, command.access, service.FolderQuery{})
		if err != nil {
			return nil, err
		}
		// Delete the deepest folders first.
		sort.Slice(folders, func(i, j int) bool { return len(folders[i].Path) > len(folders[j].Path) })
		for _, child := range folders {
			if strings.HasPrefix(child.Path, folder.Path+child.Delimiter) && child.Path != folder.Path && child.SpecialUse == "" {
				if err := h.space.DeleteFolder(command.ctx, command.access, child.ID); err != nil && service.IsTemporarilyUnavailable(err) {
					return nil, err
				}
			}
		}
	}
	return result("1"), nil
}

// MoveItems status codes (MS-ASCMD 2.2.3.177.9).
const (
	moveInvalidSource      = "1"
	moveInvalidDestination = "2"
	moveSuccess            = "3"
	moveSameFolder         = "4"
	moveFailed             = "5"
)

func (h *Handler) moveItems(command *commandContext) (*Node, error) {
	response := E(5, "MoveItems")
	for _, move := range command.request.ChildrenNamed("Move") {
		source := childText(move, "SrcMsgId")
		result := E(5, "Response", T(5, "SrcMsgId", source))
		status, destinationID, err := h.moveItem(command, source, childText(move, "SrcFldId"), childText(move, "DstFldId"))
		if err != nil {
			return nil, err
		}
		result.Children = append(result.Children, T(5, "Status", status))
		if status == moveSuccess {
			result.Children = append(result.Children, T(5, "DstMsgId", destinationID))
		}
		response.Children = append(response.Children, result)
	}
	return response, nil
}

func (h *Handler) moveItem(command *commandContext, source, sourceFolder, destination string) (string, string, error) {
	itemID, err := decodeServerID(source, "i:")
	if err != nil {
		return moveInvalidSource, "", nil
	}
	item, err := h.space.GetItem(command.ctx, command.access, itemID)
	if err != nil || !item.TrashedAt.IsZero() {
		return moveInvalidSource, "", nil
	}
	if sourceFolder != "" {
		if sourceID, decodeErr := decodeServerID(sourceFolder, "f:"); decodeErr != nil || sourceID != item.FolderID {
			return moveInvalidSource, "", nil
		}
	}
	destinationID, err := decodeServerID(destination, "f:")
	if err != nil {
		return moveInvalidDestination, "", nil
	}
	target, err := h.space.GetFolder(command.ctx, command.access, destinationID)
	if err != nil || !easSyncable(target.Type) {
		return moveInvalidDestination, "", nil
	}
	if destinationID == item.FolderID {
		return moveSameFolder, "", nil
	}
	origin, err := h.space.GetFolder(command.ctx, command.access, item.FolderID)
	if err != nil || origin.Type != target.Type {
		return moveInvalidDestination, "", nil
	}
	moved, err := h.space.MoveItem(command.ctx, command.access, itemID, destinationID, "")
	if err != nil {
		if service.IsTemporarilyUnavailable(err) {
			return "", "", err
		}
		return moveFailed, "", nil
	}
	// The device already shows the item in its new folder.
	command.state.addEcho(item.FolderID, Echo{ID: itemID, Removed: true})
	command.state.addEcho(destinationID, Echo{ID: moved.ID, ModSeq: moved.ModSeq})
	return moveSuccess, encodeServerID("i:", moved.ID), nil
}
