package ews

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

var (
	errFolderNotFound        = errors.New("the specified folder could not be found in the store")
	errItemNotFound          = errors.New("the specified object was not found in the store")
	errSubmissionUnavailable = errors.New("mail submission is unavailable")
	errSubmissionFailed      = errors.New("the message could not be submitted")
)

// responseMessage is one entry of a ResponseMessages list. EWS answers every
// requested folder or item with its own message, Success or Error, in
// request order; clients match them by position, so one failed ID must not
// fail the whole request with a SOAP fault.
type responseMessage struct {
	body string
	err  error
}

// emptyContainers are the payload elements an Error message still carries.
var emptyContainers = map[string]string{
	"GetFolder": "<m:Folders/>", "CreateFolder": "<m:Folders/>", "MoveFolder": "<m:Folders/>",
	"GetItem": "<m:Items/>", "CreateItem": "<m:Items/>", "UpdateItem": "<m:Items/>",
	"MoveItem": "<m:Items/>", "CopyItem": "<m:Items/>",
	"GetAttachment": "<m:Attachments/>", "CreateAttachment": "<m:Attachments/>",
}

func responses(operation string, messages []responseMessage) string {
	var out strings.Builder
	out.WriteString(`<m:` + operation + `Response><m:ResponseMessages>`)
	for _, message := range messages {
		if message.err != nil {
			code, text := ewsError(message.err)
			out.WriteString(`<m:` + operation + `ResponseMessage ResponseClass="Error"><m:MessageText>` + escape(text) + `</m:MessageText><m:ResponseCode>` + code + `</m:ResponseCode><m:DescriptiveLinkKey>0</m:DescriptiveLinkKey>` + emptyContainers[operation] + `</m:` + operation + `ResponseMessage>`)
			continue
		}
		out.WriteString(`<m:` + operation + `ResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode>` + message.body + `</m:` + operation + `ResponseMessage>`)
	}
	out.WriteString(`</m:ResponseMessages></m:` + operation + `Response>`)
	return out.String()
}

// rootFolderID names the synthetic msgfolderroot that parents the user's
// top-level folders, so clients can rebuild the hierarchy.
const rootFolderID = "\x00msgfolderroot"

func rootFolder() model.Folder {
	return model.Folder{ID: rootFolderID, Name: "Top of Information Store", Type: model.FolderTypeMail}
}

// ewsVisible reports whether EWS presents a folder. Files, Sieve scripts,
// scheduling mailboxes, saved searches and templates have no EWS class and
// would otherwise appear as mail folders in Mac Mail and Outlook.
func ewsVisible(folder model.Folder) bool {
	if strings.HasPrefix(folder.SpecialUse, model.SpecialUseHeldDeletedPrefix) {
		return false
	}
	switch folder.Type {
	case model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeContacts, model.FolderTypeTasks, model.FolderTypeNotes:
		return true
	}
	return false
}

func visibleFolders(all []model.Folder) []model.Folder {
	visible := make([]model.Folder, 0, len(all))
	for _, folder := range all {
		if ewsVisible(folder) {
			visible = append(visible, folder)
		}
	}
	return visible
}

// parentsFirst orders folders so every parent precedes its children.
func parentsFirst(folders []model.Folder) []model.Folder {
	sorted := slices.Clone(folders)
	sort.SliceStable(sorted, func(i, j int) bool {
		return strings.Count(sorted[i].Path, "/") < strings.Count(sorted[j].Path, "/")
	})
	return sorted
}

func isDescendant(folder model.Folder, ancestor string, byID map[string]model.Folder) bool {
	if ancestor == "" {
		return true
	}
	for depth, current := 0, folder; depth < 64 && current.ParentID != ""; depth++ {
		if current.ParentID == ancestor {
			return true
		}
		current = byID[current.ParentID]
	}
	return false
}

// distinguishedFolder resolves a DistinguishedFolderId by special use among
// the user's own folders, then by its conventional path.
func (h *Handler) distinguishedFolder(ctx context.Context, access service.AccessContext, id, path string) (model.Folder, error) {
	specialUse := map[string]string{
		"inbox": model.SpecialUseInbox, "drafts": model.SpecialUseDrafts, "sentitems": model.SpecialUseSent,
		"deleteditems": model.SpecialUseTrash, "junkemail": model.SpecialUseJunk, "calendar": model.SpecialUseCalendar,
		"contacts": model.SpecialUseContacts, "archive": model.SpecialUseArchive,
		"recipientcache": model.SpecialUseRecentRecipients,
	}[id]
	folders, err := h.space.ListFolders(ctx, access, service.FolderQuery{})
	if err != nil {
		return model.Folder{}, err
	}
	for _, folder := range folders {
		if folder.UserID != access.Actor.ID {
			continue
		}
		if specialUse != "" && strings.EqualFold(strings.TrimPrefix(folder.SpecialUse, "\\"), specialUse) {
			return folder, nil
		}
		if specialUse == "" && id == "tasks" && folder.Type == model.FolderTypeTasks {
			return folder, nil
		}
		if specialUse == "" && id == "notes" && folder.Type == model.FolderTypeNotes {
			return folder, nil
		}
	}
	if path == "" {
		return model.Folder{}, errFolderNotFound
	}
	folder, err := h.space.GetFolderByPath(ctx, access, path)
	if err != nil {
		return model.Folder{}, errFolderNotFound
	}
	return folder, nil
}

func parentFolderID(folder model.Folder) string {
	if folder.ParentID == "" {
		return encodeID("f:", rootFolderID)
	}
	return encodeID("f:", folder.ParentID)
}

func folderTag(folderType model.FolderType) string {
	switch folderType {
	case model.FolderTypeCalendar:
		return "CalendarFolder"
	case model.FolderTypeContacts:
		return "ContactsFolder"
	case model.FolderTypeTasks:
		return "TasksFolder"
	}
	return "Folder"
}

func folderIdentityXML(folder model.Folder) string {
	tag := folderTag(folder.Type)
	return `<t:` + tag + `><t:FolderId Id="` + encodeID("f:", folder.ID) + `" ChangeKey="` + strconv.FormatInt(folder.UpdatedAt.UnixNano(), 10) + `"/></t:` + tag + `>`
}

// folderCounts are the TotalCount, UnreadCount and ChildFolderCount of the
// Default folder shape.
type folderCounts struct {
	total, unread, children int
}

// folderXMLCounted renders a folder in schema order (FolderId,
// ParentFolderId, FolderClass, DisplayName, TotalCount, ChildFolderCount,
// UnreadCount) with its counts.
func (h *Handler) folderXMLCounted(ctx context.Context, access service.AccessContext, folder model.Folder, all []model.Folder) string {
	counts := folderCounts{}
	for _, candidate := range all {
		if ewsVisible(candidate) && (candidate.ParentID == folder.ID || folder.ID == rootFolderID && candidate.ParentID == "") {
			counts.children++
		}
	}
	if folder.ID != rootFolderID {
		if items, err := h.space.ListItems(ctx, access, folder.ID, service.ItemQuery{MetadataOnly: true}); err == nil {
			counts.total = len(items)
			for _, item := range items {
				if !hasFlag(item.Flags, model.FlagSeen) {
					counts.unread++
				}
			}
		}
	}
	return renderFolder(folder, &counts)
}

func renderFolder(folder model.Folder, counts *folderCounts) string {
	tag := folderTag(folder.Type)
	var out strings.Builder
	out.WriteString(`<t:` + tag + `><t:FolderId Id="` + encodeID("f:", folder.ID) + `" ChangeKey="` + strconv.FormatInt(folder.UpdatedAt.UnixNano(), 10) + `"/>`)
	if folder.ID != rootFolderID {
		out.WriteString(`<t:ParentFolderId Id="` + parentFolderID(folder) + `"/><t:FolderClass>` + escape(folderClass(folder.Type)) + `</t:FolderClass>`)
	}
	out.WriteString(`<t:DisplayName>` + escape(folder.Name) + `</t:DisplayName>`)
	if counts != nil {
		out.WriteString(`<t:TotalCount>` + strconv.Itoa(counts.total) + `</t:TotalCount><t:ChildFolderCount>` + strconv.Itoa(counts.children) + `</t:ChildFolderCount>`)
		if tag == "Folder" {
			out.WriteString(`<t:UnreadCount>` + strconv.Itoa(counts.unread) + `</t:UnreadCount>`)
		}
	}
	out.WriteString(`</t:` + tag + `>`)
	return out.String()
}

// itemShape is the part of an ItemShape that changes the rendering, with
// the request and account context typed items are rendered in.
type itemShape struct {
	idOnly bool
	mime   bool
	// body is set when the body is part of the response: requested
	// explicitly, whatever the base shape, or implied by GetItem's Default
	// and AllFields shapes.
	body bool

	info    requestInfo
	profile Profile
	// zone is where all-day events and date-only task dates are anchored.
	zone *time.Location
}

func parseItemShape(shape *node) itemShape {
	result := itemShape{}
	if shape == nil {
		return result
	}
	result.idOnly = strings.EqualFold(shape.descendantText("BaseShape"), "IdOnly")
	shape.walk(func(n *node) {
		if n.Name.Local != "FieldURI" {
			return
		}
		switch strings.ToLower(n.attr("FieldURI")) {
		case "item:mimecontent":
			result.mime = true
		case "item:body", "item:textbody":
			result.body = true
		}
	})
	if include := shape.descendantText("IncludeMimeContent"); strings.EqualFold(include, "true") {
		result.mime = true
	}
	return result
}

func itemIdentityXML(item model.Item) string {
	tag := kindOf(item.Data).tag()
	return `<t:` + tag + `><t:ItemId Id="` + encodeID("i:", item.ID) + `" ChangeKey="` + strconv.FormatUint(item.ModSeq, 10) + `"/></t:` + tag + `>`
}

// renderItem renders a message in ItemType/MessageType schema order. The
// summary properties (read state, sender, recipients, attachment flag) are
// always present: Mac Mail requests them through AdditionalProperties and
// shows every message unread without IsRead.
func renderItem(item model.Item, shape itemShape) string {
	switch kindOf(item.Data) {
	case kindCalendar:
		return renderCalendarItem(item, shape, "")
	case kindContact:
		return renderContact(item, shape)
	case kindTask:
		return renderTask(item, shape)
	}
	var out strings.Builder
	out.WriteString(`<t:Message>`)
	if shape.mime || shape.body && !shape.idOnly {
		out.WriteString(`<t:MimeContent CharacterSet="UTF-8">` + base64.StdEncoding.EncodeToString(item.Data) + `</t:MimeContent>`)
	}
	out.WriteString(`<t:ItemId Id="` + encodeID("i:", item.ID) + `" ChangeKey="` + strconv.FormatUint(item.ModSeq, 10) + `"/>`)
	out.WriteString(`<t:ParentFolderId Id="` + encodeID("f:", item.FolderID) + `"/><t:ItemClass>IPM.Note</t:ItemClass>`)
	projection, err := service.ProjectMIME(item.Data)
	if err != nil {
		projection = service.MessageProjection{Headers: item.Headers}
	}
	header := func(name string) string {
		if value := projection.Headers[name]; value != "" {
			return value
		}
		return item.Headers[name]
	}
	subject := header("Subject")
	if subject == "" {
		subject = item.Name
	}
	out.WriteString(`<t:Subject>` + escape(subject) + `</t:Subject>`)
	if shape.body {
		text := projection.Text
		if text == "" && projection.HTML != "" {
			text = service.HTMLToText(projection.HTML)
		}
		out.WriteString(`<t:Body BodyType="Text">` + escape(text) + `</t:Body>`)
		if attachments := attachmentsXML(item.ID, projection.Attachments, shape.info); attachments != "" {
			out.WriteString(`<t:Attachments>` + attachments + `</t:Attachments>`)
		}
	}
	out.WriteString(`<t:DateTimeReceived>` + messageReceived(item) + `</t:DateTimeReceived><t:Size>` + strconv.FormatInt(item.Size, 10) + `</t:Size><t:Importance>` + ewsImportance(item.Headers) + `</t:Importance>`)
	if sent, err := mail.ParseDate(header("Date")); err == nil {
		out.WriteString(`<t:DateTimeSent>` + sent.UTC().Format(time.RFC3339) + `</t:DateTimeSent>`)
	}
	out.WriteString(`<t:HasAttachments>` + strconv.FormatBool(len(projection.Attachments) > 0) + `</t:HasAttachments>`)
	if preview := messagePreview(projection); preview != "" {
		out.WriteString(`<t:Preview>` + escape(preview) + `</t:Preview>`)
	}
	if recipients := mailboxesXML(header("To")); recipients != "" {
		out.WriteString(`<t:ToRecipients>` + recipients + `</t:ToRecipients>`)
	}
	if recipients := mailboxesXML(header("Cc")); recipients != "" {
		out.WriteString(`<t:CcRecipients>` + recipients + `</t:CcRecipients>`)
	}
	if from := mailboxesXML(header("From")); from != "" {
		out.WriteString(`<t:From>` + from + `</t:From>`)
	}
	if messageID := header("Message-ID"); messageID != "" {
		out.WriteString(`<t:InternetMessageId>` + escape(messageID) + `</t:InternetMessageId>`)
	}
	out.WriteString(`<t:IsRead>` + strconv.FormatBool(hasFlag(item.Flags, model.FlagSeen)) + `</t:IsRead></t:Message>`)
	return out.String()
}

func mailboxesXML(list string) string {
	addresses, err := mail.ParseAddressList(list)
	if err != nil {
		return ""
	}
	var out strings.Builder
	for _, address := range addresses {
		out.WriteString(`<t:Mailbox>`)
		if address.Name != "" {
			out.WriteString(`<t:Name>` + escape(address.Name) + `</t:Name>`)
		}
		out.WriteString(`<t:EmailAddress>` + escape(address.Address) + `</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType></t:Mailbox>`)
	}
	return out.String()
}

func hasFlag(flags []string, wanted string) bool {
	for _, flag := range flags {
		if strings.EqualFold(flag, wanted) {
			return true
		}
	}
	return false
}

func setFlag(flags []string, wanted string, enabled bool) []string {
	result := make([]string, 0, len(flags)+1)
	found := false
	for _, flag := range flags {
		if strings.EqualFold(flag, wanted) {
			found = true
			if !enabled {
				continue
			}
		}
		result = append(result, flag)
	}
	if enabled && !found {
		result = append(result, wanted)
	}
	return result
}

// splitEWSItemUpdates separates message:IsRead, which is a flag, from the
// content updates applyEWSItemUpdates rewrites into the message.
func splitEWSItemUpdates(updates *node) (*node, *bool, error) {
	if updates == nil || len(updates.Children) == 0 {
		return nil, nil, fmt.Errorf("%w: item updates are required", errEWSInvalidProperty)
	}
	content := &node{Name: updates.Name}
	var read *bool
	for _, operation := range updates.Children {
		field := ""
		if uri := operation.child("FieldURI"); uri != nil {
			field = strings.ToLower(strings.TrimSpace(uri.attr("FieldURI")))
		}
		if field == "message:isread" {
			if operation.Name.Local == "DeleteItemField" {
				value := false
				read = &value
				continue
			}
			value := strings.EqualFold(operation.descendantText("IsRead"), "true")
			read = &value
			continue
		}
		content.Children = append(content.Children, operation)
	}
	if len(content.Children) == 0 {
		return nil, read, nil
	}
	return content, read, nil
}

func (n *node) ChildrenNamed(local string) []*node {
	if n == nil {
		return nil
	}
	var result []*node
	for _, child := range n.Children {
		if child.Name.Local == local {
			result = append(result, child)
		}
	}
	return result
}

// messagePreview is the start of the message text with whitespace collapsed,
// at most 255 characters as Exchange returns it.
func messagePreview(projection service.MessageProjection) string {
	text := projection.Text
	if text == "" && projection.HTML != "" {
		text = service.HTMLToText(projection.HTML)
	}
	words := strings.Fields(text)
	var out strings.Builder
	for _, word := range words {
		if out.Len() > 0 {
			out.WriteByte(' ')
		}
		out.WriteString(word)
		if out.Len() >= 255 {
			break
		}
	}
	preview := []rune(out.String())
	if len(preview) > 255 {
		preview = preview[:255]
	}
	return string(preview)
}

// messageReceived is a message's DateTimeReceived as FindItem renders it.
func messageReceived(item model.Item) string {
	received := item.InternalDate
	if received.IsZero() {
		received = item.CreatedAt
	}
	return received.UTC().Format(time.RFC3339)
}
