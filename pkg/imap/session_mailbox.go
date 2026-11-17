package imap

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/folderindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

func (s *Session) cmdStatus(tag string, args []string) {
	if len(args) < 2 {
		s.sendBAD(tag, "Expected: STATUS mailbox (status-data-item ...)")
		return
	}
	joined := strings.Join(args[1:], " ")
	if len(joined) < 3 || joined[0] != '(' || joined[len(joined)-1] != ')' {
		s.sendBAD(tag, "STATUS data items must be a non-empty parenthesized list")
		return
	}
	requested := strings.Fields(joined[1 : len(joined)-1])
	if len(requested) == 0 {
		s.sendBAD(tag, "STATUS data items must not be empty")
		return
	}
	for index := range requested {
		requested[index] = strings.ToUpper(requested[index])
		// IMAP4rev2 removed RECENT; IMAP4rev1 sessions still use it.
		if !validStatusItem(requested[index]) || requested[index] == "RECENT" && s.rev2Enabled {
			s.sendBAD(tag, fmt.Sprintf("Unsupported STATUS data item %s", requested[index]))
			return
		}
	}

	mailbox := args[0]
	folder, _, err := s.resolveMailbox(mailbox)
	if err != nil {
		if service.IsTemporarilyUnavailable(err) {
			s.sendOperationError(tag, "STATUS", err)
		} else {
			s.sendNO(tag, "Mailbox does not exist")
		}
		return
	}

	values, err := s.statusValues(folder, requested)
	if err != nil {
		s.sendOperationError(tag, "STATUS", err)
		return
	}
	s.sendUntagged(fmt.Sprintf("* STATUS %s (%s)", s.mailboxToWire(mailbox), strings.Join(values, " ")))
	s.sendOK(tag, "STATUS completed")
}

func (s *Session) statusValues(folder model.Folder, requested []string) ([]string, error) {
	if folder.ItemCount < 0 || folder.LogicalBytes < 0 {
		return nil, errors.New("invalid negative folder accounting metadata")
	}
	if slices.Contains(requested, "HIGHESTMODSEQ") {
		s.condstoreEnabled = true
	}
	needFlags := slices.Contains(requested, "UNSEEN") || slices.Contains(requested, "DELETED") || slices.Contains(requested, "RECENT")
	var unseen, deleted, recent int64
	if needFlags && !slices.Contains(requested, "DELETED") && !slices.Contains(requested, "RECENT") {
		// The mail unseen projection answers UNSEEN without listing the
		// mailbox; while it is first built, the listing below answers.
		if count, ok := s.projectedUnseen(folder); ok {
			unseen, needFlags = count, false
		}
	}
	if needFlags {
		items, listErr := s.cfg.FolderSpace.ListItems(*s.ctx, s.access(), folder.ID, service.ItemQuery{MetadataOnly: true})
		if listErr != nil {
			return nil, listErr
		}
		for _, item := range items {
			if !slices.Contains(item.Flags, model.FlagSeen) {
				unseen++
			}
			if slices.Contains(item.Flags, model.FlagDeleted) {
				deleted++
			}
			if slices.Contains(item.Flags, model.FlagRecent) {
				recent++
			}
		}
	}

	values := make([]string, 0, len(requested)*2)
	for _, item := range requested {
		values = append(values, item)
		switch item {
		case "MESSAGES":
			values = append(values, strconv.FormatInt(folder.ItemCount, 10))
		case "UIDNEXT":
			values = append(values, strconv.FormatUint(uint64(folder.NextUID)+1, 10))
		case "UIDVALIDITY":
			values = append(values, strconv.FormatUint(uint64(folder.UIDValidity), 10))
		case "UNSEEN":
			values = append(values, strconv.FormatInt(unseen, 10))
		case "DELETED":
			values = append(values, strconv.FormatInt(deleted, 10))
		case "SIZE":
			values = append(values, strconv.FormatInt(folder.LogicalBytes, 10))
		case "MAILBOXID":
			values = append(values, "("+mailboxID(folder)+")")
		case "RECENT":
			values = append(values, strconv.FormatInt(recent, 10))
		case "HIGHESTMODSEQ":
			values = append(values, strconv.FormatUint(max(uint64(1), folder.HighestModSeq), 10))
		}
	}
	return values, nil
}

// projectedUnseen returns folder's unseen count from the mail index
// projection, which needs the same read right as listing the messages.
func (s *Session) projectedUnseen(folder model.Folder) (int64, bool) {
	if s.cfg.MailIndex == nil {
		return 0, false
	}
	if readable, err := s.hasRight(folder.ID, s.userID, "r"); err != nil || !readable {
		return 0, false
	}
	count, err := s.cfg.MailIndex.Unseen(*s.ctx, s.cfg.FolderSpace, s.access(), folder, folderindex.PriorityFolder)
	return count, err == nil
}

// cmdList handles the LIST command (RFC 3501).
// Also lists shared mailboxes with "user/owner/" prefix (RFC 4314).
func (s *Session) cmdList(tag string, args []string) {
	request, err := parseListRequest(args)
	if err != nil {
		s.sendBAD(tag, err.Error())
		return
	}
	request.Reference, err = s.mailboxFromWire(request.Reference)
	if err != nil {
		s.sendBAD(tag, "Invalid LIST reference name")
		return
	}
	delimiterQuery := len(request.Patterns) > 0
	for index, pattern := range request.Patterns {
		decoded, decodeErr := s.mailboxFromWire(pattern)
		if decodeErr != nil {
			s.sendBAD(tag, "Invalid LIST mailbox pattern")
			return
		}
		delimiterQuery = delimiterQuery && decoded == ""
		request.Patterns[index] = listPatternWithReference(request.Reference, decoded)
	}
	// RFC 3501 6.3.8: an empty mailbox pattern asks for the hierarchy
	// delimiter and root. Thunderbird, Apple Mail, and Outlook all send
	// LIST "" "" before anything else and stall without this reply.
	if delimiterQuery && len(request.Select) == 0 {
		s.sendUntagged(`* LIST (\Noselect) "/" ""`)
		s.sendOK(tag, "LIST completed")
		return
	}

	folders, err := s.cfg.FolderSpace.ListFolders(*s.ctx, s.access(), service.FolderQuery{Type: model.FolderTypeMail})
	if err != nil {
		s.sendOperationError(tag, "LIST", err)
		return
	}

	for _, f := range folders {
		if !listFolderMatches(f, f.Path, folders, request) {
			continue
		}
		if err := s.sendListResponse(f, f.Path, folders, request); err != nil {
			s.sendOperationError(tag, "LIST", err)
			return
		}
	}

	// List shared mailboxes with "user/owner/" prefix
	seenShared := make(map[string]bool)
	for _, pattern := range request.Patterns {
		s.listSharedMailboxes(tag, pattern, func(ownerID string, f model.Folder) {
			sharedPath := "user/" + ownerID + "/" + f.Path
			if seenShared[sharedPath] || !listFolderMatches(f, sharedPath, nil, request) {
				return
			}
			seenShared[sharedPath] = true
			if err := s.sendListResponse(f, sharedPath, nil, request); err != nil {
				logger.Warn("imap: shared LIST response failed", "session", s.id, "folder", f.ID, "error", err)
			}
		})
	}

	s.sendOK(tag, "LIST completed")
}

func listPatternWithReference(reference, pattern string) string {
	if reference == "" || strings.HasPrefix(pattern, "/") {
		return strings.TrimPrefix(pattern, "/")
	}
	if pattern == "" {
		return strings.TrimSuffix(reference, "/")
	}
	if strings.HasSuffix(reference, "/") {
		return reference + pattern
	}
	return reference + "/" + pattern
}

func listFolderMatches(folder model.Folder, path string, allFolders []model.Folder, request listRequest) bool {
	if request.Select["SPECIAL-USE"] && folder.SpecialUse == "" {
		return false
	}
	matched := false
	for _, pattern := range request.Patterns {
		if matchPattern(strings.ToUpper(path), strings.ToUpper(pattern)) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	if !request.Select["SUBSCRIBED"] || folder.Subscribed {
		return true
	}
	if !request.Select["RECURSIVEMATCH"] {
		return false
	}
	return listHasSubscribedDescendant(folder, allFolders)
}

func listHasSubscribedDescendant(folder model.Folder, allFolders []model.Folder) bool {
	for _, candidate := range allFolders {
		if candidate.Subscribed && strings.HasPrefix(candidate.Path, folder.Path+"/") {
			return true
		}
	}
	return false
}

func (s *Session) sendListResponse(folder model.Folder, path string, allFolders []model.Folder, request listRequest) error {
	attrs := s.listFolderAttrs(folder, allFolders)
	delimiter := folder.Delimiter
	if delimiter == "" {
		delimiter = "/"
	}
	response := fmt.Sprintf("* LIST (%s) %q %s", strings.Join(attrs, " "), delimiter, s.mailboxToWire(path))
	if request.Select["RECURSIVEMATCH"] && !folder.Subscribed && listHasSubscribedDescendant(folder, allFolders) {
		response += ` ("CHILDINFO" ("SUBSCRIBED"))`
	}
	if request.Return["STATUS"] {
		values, err := s.statusValues(folder, request.ReturnStatus)
		if err != nil {
			return err
		}
		response += fmt.Sprintf(" (STATUS (%s))", strings.Join(values, " "))
	}
	s.sendUntagged(response)
	return nil
}

// listSharedMailboxes discovers folders shared with the current user and calls fn for each.
func (s *Session) listSharedMailboxes(_ string, mailboxPattern string, fn func(ownerID string, f model.Folder)) {
	if s.cfg.Authorizer != nil {
		folders, err := s.cfg.Authorizer.AccessibleFolders(*s.ctx, model.PrincipalRef{Kind: model.PrincipalUser, ID: s.userID}, authz.FolderDiscover)
		if err != nil {
			return
		}
		mailboxUpper := strings.ToUpper(mailboxPattern)
		for _, folder := range folders {
			if folder.UserID == s.userID {
				continue
			}
			sharedPath := "user/" + folder.UserID + "/" + folder.Path
			if matchPattern(strings.ToUpper(sharedPath), mailboxUpper) {
				fn(folder.UserID, folder)
			}
		}
		return
	}
	// Scan all ACL entries to find folders shared with the current user
	aclEntries, err := s.cfg.TypedStore.FolderStore().ListACLForUser(*s.ctx, s.userID)
	if err != nil {
		return
	}

	mailboxUpper := strings.ToUpper(mailboxPattern)
	seen := make(map[string]bool)
	for folderID := range aclEntries {
		f, err := s.cfg.FolderSpace.GetFolder(*s.ctx, s.access(), folderID)
		if err != nil {
			continue
		}
		ownerID := f.UserID
		if ownerID == s.userID {
			continue
		}

		sharedPath := "user/" + ownerID + "/" + f.Path
		sharedPathUpper := strings.ToUpper(sharedPath)
		if matchPattern(sharedPathUpper, mailboxUpper) {
			key := ownerID + "/" + f.Path
			if seen[key] {
				continue
			}
			seen[key] = true
			fn(ownerID, f)
		}
	}
}

// listFolderAttrs computes the attribute list for a folder in LIST responses.
func (s *Session) listFolderAttrs(f model.Folder, allFolders []model.Folder) []string {
	if f.Type != model.FolderTypeMail {
		return []string{"\\NoSelect"}
	}

	hasChildren := false
	if allFolders != nil {
		for _, other := range allFolders {
			if other.Path != f.Path && strings.HasPrefix(other.Path, f.Path+"/") {
				hasChildren = true
				break
			}
		}
	}

	var attrs []string
	if hasChildren {
		attrs = []string{"\\HasChildren"}
	} else {
		attrs = []string{"\\HasNoChildren"}
	}

	if f.Subscribed {
		attrs = append(attrs, "\\Subscribed")
	}
	if f.Path == "INBOX" {
		attrs = append(attrs, "\\Inbox")
	}
	switch f.SpecialUse {
	case model.SpecialUseDrafts:
		attrs = append(attrs, "\\Drafts")
	case model.SpecialUseSent:
		attrs = append(attrs, "\\Sent")
	case model.SpecialUseTrash:
		attrs = append(attrs, "\\Trash")
	case model.SpecialUseJunk:
		attrs = append(attrs, "\\Junk")
	case model.SpecialUseArchive:
		attrs = append(attrs, "\\Archive")
	}
	return attrs
}

// cmdLsub handles the LSUB command (RFC 3501).
// Also lists shared mailboxes with "user/owner/" prefix (RFC 4314).
func (s *Session) cmdLsub(tag string, args []string) {
	if len(args) != 2 {
		s.sendBAD(tag, "Expected: LSUB reference mailbox")
		return
	}

	mailbox := args[1]

	folders, err := s.cfg.FolderSpace.ListFolders(*s.ctx, s.access(), service.FolderQuery{Type: model.FolderTypeMail})
	if err != nil {
		s.sendOperationError(tag, "LSUB", err)
		return
	}

	mailboxUpper := strings.ToUpper(mailbox)
	for _, f := range folders {
		if !f.Subscribed {
			continue
		}
		pathUpper := strings.ToUpper(f.Path)
		if matchPattern(pathUpper, mailboxUpper) {
			attrs := []string{}
			if f.Path == "INBOX" {
				attrs = []string{"\\Inbox"}
			}
			delimiter := f.Delimiter
			if delimiter == "" {
				delimiter = "/"
			}
			s.sendUntagged(fmt.Sprintf("* LSUB (%s) %q %s",
				strings.Join(attrs, " "), delimiter, s.mailboxToWire(f.Path)))
		}
	}

	// List shared mailboxes with "user/owner/" prefix
	s.listSharedMailboxes(tag, mailbox, func(ownerID string, f model.Folder) {
		attrs := []string{}
		if f.Path == "INBOX" {
			attrs = []string{"\\Inbox"}
		}
		sharedPath := "user/" + ownerID + "/" + f.Path
		delimiter := f.Delimiter
		if delimiter == "" {
			delimiter = "/"
		}
		s.sendUntagged(fmt.Sprintf("* LSUB (%s) %q %s",
			strings.Join(attrs, " "), delimiter, s.mailboxToWire(sharedPath)))
	})

	s.sendOK(tag, "LSUB completed")
}

// cmdCreate handles the CREATE command (RFC 3501).
func (s *Session) cmdCreate(tag string, args []string) {
	if len(args) != 1 {
		s.sendBAD(tag, "Expected: CREATE mailbox")
		return
	}

	// RFC 3501 6.3.3: a trailing delimiter only declares the intent to
	// create names below the mailbox.
	mailbox := strings.TrimSuffix(args[0], "/")
	if strings.EqualFold(mailbox, "INBOX") {
		s.sendNO(tag, "[ALREADYEXISTS] Cannot create INBOX")
		return
	}
	segments := strings.Split(mailbox, "/")
	if slices.Contains(segments, "") {
		s.sendBAD(tag, "Invalid mailbox name")
		return
	}
	if _, err := s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), mailbox); err == nil {
		s.sendNO(tag, "[ALREADYEXISTS] Mailbox already exists")
		return
	}

	parentID, err := s.ensureMailboxParents(segments)
	if err != nil {
		s.sendOperationError(tag, "CREATE", err)
		return
	}
	if _, err := s.cfg.FolderSpace.CreateFolder(*s.ctx, s.access(), segments[len(segments)-1], model.FolderTypeMail, parentID); err != nil {
		s.sendOperationError(tag, "CREATE", err)
		return
	}

	s.publishMailbox(mailbox)
	s.sendOK(tag, "CREATE completed")
}

// ensureMailboxParents creates every missing superior hierarchical name of
// a mailbox path given as segments and returns the folder ID of its direct
// parent, empty at the top level. RFC 3501 6.3.3 and 6.3.5 ask CREATE and
// RENAME to create superiors; creating only the last segment put "a/b/c" at
// the top level as "c".
func (s *Session) ensureMailboxParents(segments []string) (string, error) {
	parentID := ""
	for depth := range len(segments) - 1 {
		path := strings.Join(segments[:depth+1], "/")
		if depth == 0 && strings.EqualFold(path, "INBOX") {
			path = "INBOX"
		}
		existing, err := s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), path)
		if err == nil {
			parentID = existing.ID
			continue
		}
		if service.IsTemporarilyUnavailable(err) {
			return "", err
		}
		created, err := s.cfg.FolderSpace.CreateFolder(*s.ctx, s.access(), segments[depth], model.FolderTypeMail, parentID)
		if err != nil {
			return "", err
		}
		parentID = created.ID
		s.publishMailbox(path)
	}
	return parentID, nil
}

// cmdDelete handles the DELETE command (RFC 3501).
func (s *Session) cmdDelete(tag string, args []string) {
	if len(args) != 1 {
		s.sendBAD(tag, "Expected: DELETE mailbox")
		return
	}

	mailbox := args[0]
	if strings.ToUpper(mailbox) == "INBOX" {
		s.sendNO(tag, "Cannot delete INBOX")
		return
	}

	folder, err := s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), mailbox)
	if err != nil {
		if service.IsTemporarilyUnavailable(err) {
			s.sendOperationError(tag, "DELETE", err)
		} else {
			s.sendNO(tag, "Mailbox does not exist")
		}
		return
	}

	// Don't allow deleting the currently selected mailbox
	if s.curState == stateSelected && s.selectedFolderID == folder.ID {
		s.sendNO(tag, "Cannot delete selected mailbox")
		return
	}

	if err := s.cfg.FolderSpace.DeleteFolder(*s.ctx, s.access(), folder.ID); err != nil {
		s.sendOperationError(tag, "DELETE", err)
		return
	}

	s.publishMailbox(folder.Path)
	s.sendOK(tag, "DELETE completed")
}

// cmdRename handles the RENAME command (RFC 3501).
func (s *Session) cmdRename(tag string, args []string) {
	if len(args) != 2 {
		s.sendBAD(tag, "Expected: RENAME old new")
		return
	}

	oldMailbox := args[0]
	newMailbox := args[1]

	if strings.ToUpper(newMailbox) == "INBOX" {
		s.sendNO(tag, "Cannot rename to INBOX")
		return
	}

	folder, err := s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), oldMailbox)
	if err != nil {
		s.sendNO(tag, "Mailbox does not exist")
		return
	}

	newMailbox = strings.TrimSuffix(newMailbox, "/")
	segments := strings.Split(newMailbox, "/")
	if slices.Contains(segments, "") {
		s.sendBAD(tag, "Invalid mailbox name")
		return
	}
	if _, err := s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), newMailbox); err == nil {
		s.sendNO(tag, "[ALREADYEXISTS] Destination mailbox already exists")
		return
	}
	if strings.EqualFold(oldMailbox, "INBOX") {
		s.renameInbox(tag, folder, newMailbox, segments)
		return
	}
	name := segments[len(segments)-1]
	parentID, err := s.ensureMailboxParents(segments)
	if err != nil {
		s.sendOperationError(tag, "RENAME", err)
		return
	}
	if _, err := s.cfg.FolderSpace.MoveFolder(*s.ctx, s.access(), folder.ID, parentID, name); err != nil {
		s.sendNO(tag, fmt.Sprintf("RENAME failed: %v", err))
		return
	}

	s.publishMailbox(newMailbox, folder.Path)
	s.sendOK(tag, "RENAME completed")
}

// renameInbox implements the special case of RENAME INBOX (RFC 3501
// 6.3.5, RFC 9051 6.3.6): every message in INBOX moves to a new mailbox of
// the given name, INBOX stays in place and empty, and mailboxes below INBOX
// are not renamed. Each message moves atomically with its flags, internal
// date and modification history, so a failure part-way leaves every message
// in exactly one of the two mailboxes; the command then reports NO.
func (s *Session) renameInbox(tag string, inbox model.Folder, newMailbox string, segments []string) {
	parentID, err := s.ensureMailboxParents(segments)
	if err != nil {
		s.sendOperationError(tag, "RENAME", err)
		return
	}
	target, err := s.cfg.FolderSpace.CreateFolder(*s.ctx, s.access(), segments[len(segments)-1], model.FolderTypeMail, parentID)
	if err != nil {
		s.sendOperationError(tag, "RENAME", err)
		return
	}
	s.publishMailbox(newMailbox)

	items, err := s.cfg.FolderSpace.ListItems(*s.ctx, s.access(), inbox.ID, service.ItemQuery{MetadataOnly: true})
	if err != nil {
		s.publish(target)
		s.sendOperationError(tag, "RENAME", err)
		return
	}
	moved := 0
	for _, item := range items {
		if _, err = s.cfg.FolderSpace.MoveItem(*s.ctx, s.access(), item.ID, target.ID, item.ID+".eml"); err != nil {
			break
		}
		moved++
	}
	if moved > 0 {
		s.publish(inbox)
		s.publish(target)
	}
	if err != nil {
		s.sendOperationError(tag, "RENAME", fmt.Errorf("moved %d of %d INBOX messages: %w", moved, len(items), err))
		return
	}
	s.sendOK(tag, "RENAME completed")
}

// cmdSubscribe handles the SUBSCRIBE command (RFC 3501).
func (s *Session) cmdSubscribe(tag string, args []string) {
	if len(args) != 1 {
		s.sendBAD(tag, "Expected: SUBSCRIBE mailbox")
		return
	}

	mailbox := args[0]
	folder, err := s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), mailbox)
	if err != nil {
		s.sendNO(tag, "Mailbox does not exist")
		return
	}

	subscribed := true
	if _, err := s.cfg.FolderSpace.UpdateFolder(*s.ctx, s.access(), folder.ID, service.FolderUpdate{Subscribed: &subscribed}); err != nil {
		s.sendNO(tag, fmt.Sprintf("SUBSCRIBE failed: %v", err))
		return
	}

	s.publishMailbox(folder.Path)
	s.sendOK(tag, "SUBSCRIBE completed")
}

// cmdUnsubscribe handles the UNSUBSCRIBE command (RFC 3501).
func (s *Session) cmdUnsubscribe(tag string, args []string) {
	if len(args) != 1 {
		s.sendBAD(tag, "Expected: UNSUBSCRIBE mailbox")
		return
	}

	mailbox := args[0]
	if strings.ToUpper(mailbox) == "INBOX" {
		s.sendNO(tag, "Cannot unsubscribe from INBOX")
		return
	}

	folder, err := s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), mailbox)
	if err != nil {
		s.sendNO(tag, "Mailbox does not exist")
		return
	}

	subscribed := false
	if _, err := s.cfg.FolderSpace.UpdateFolder(*s.ctx, s.access(), folder.ID, service.FolderUpdate{Subscribed: &subscribed}); err != nil {
		s.sendNO(tag, fmt.Sprintf("UNSUBSCRIBE failed: %v", err))
		return
	}

	s.publishMailbox(folder.Path)
	s.sendOK(tag, "UNSUBSCRIBE completed")
}

// resolveMailbox resolves a mailbox name to a folder. It handles:
// - "INBOX" → current user's INBOX
// - "user/other/folder" → other user's folder (shared mailbox prefix)
// - "folder" → current user's folder
func (s *Session) resolveMailbox(mailbox string) (model.Folder, string, error) {
	// Check for shared mailbox prefix: "user/username/folder"
	if strings.HasPrefix(strings.ToLower(mailbox), "user/") {
		parts := strings.SplitN(mailbox, "/", 3)
		if len(parts) >= 3 {
			sharedUser := parts[1]
			sharedFolder := parts[2]
			folder, err := s.cfg.FolderSpace.GetFolderByOwnerPath(*s.ctx, s.access(), sharedUser, sharedFolder)
			return folder, sharedUser, err
		}
	}

	// Own mailbox
	mailboxUpper := strings.ToUpper(mailbox)
	if mailboxUpper == "INBOX" {
		folder, err := s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), "INBOX")
		return folder, s.userID, err
	}
	folder, err := s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), mailbox)
	return folder, s.userID, err
}

// cmdSelect handles the SELECT command (RFC 3501).
func (s *Session) cmdSelect(tag string, args []string) {
	if len(args) < 1 {
		s.sendBAD(tag, "Expected: SELECT mailbox")
		return
	}

	s.selectMailbox(tag, args[0], false, args[1:])
}

// cmdExamine handles the EXAMINE command (RFC 3501).
func (s *Session) cmdExamine(tag string, args []string) {
	if len(args) < 1 {
		s.sendBAD(tag, "Expected: EXAMINE mailbox")
		return
	}

	s.selectMailbox(tag, args[0], true, args[1:])
}

// selectMailbox is the shared implementation for SELECT and EXAMINE.
func (s *Session) selectMailbox(tag, mailbox string, readOnly bool, options []string) {
	qresync, err := parseQResyncSelectOptions(options)
	if err != nil {
		s.sendBAD(tag, "Invalid SELECT parameters: "+err.Error())
		return
	}
	if qresync != nil && !s.qresyncEnabled {
		s.sendBAD(tag, "ENABLE QRESYNC is required before SELECT QRESYNC")
		return
	}
	if qresync != nil || strings.Contains(strings.ToUpper(strings.Join(options, " ")), "CONDSTORE") {
		s.condstoreEnabled = true
	}

	replacingSelection := s.curState == stateSelected || s.curState == stateIdle
	mailboxUpper := strings.ToUpper(mailbox)
	var folder model.Folder

	if mailboxUpper == "INBOX" {
		folder, err = s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), "INBOX")
	} else {
		folder, err = s.cfg.FolderSpace.GetFolderByPath(*s.ctx, s.access(), mailbox)
	}

	if err != nil {
		if service.IsTemporarilyUnavailable(err) {
			s.sendOperationError(tag, "SELECT", err)
		} else {
			s.sendNO(tag, fmt.Sprintf("Mailbox %s does not exist: %v", mailbox, err))
		}
		return
	}

	// Load the replacement before changing state. A failed SELECT leaves the
	// current selection intact.
	items, err := s.listMailboxItems(folder.ID)
	if err != nil {
		s.sendOperationError(tag, "SELECT", err)
		return
	}
	if replacingSelection {
		s.sendUntagged("* OK [CLOSED] Previous mailbox closed")
	}
	s.selectedFolderID = folder.ID
	s.selectedFolder = folder
	s.readOnly = readOnly
	s.curState = stateSelected
	s.setView(items)
	// SEARCHRES is scoped to the selected mailbox. A successful selection
	// resets it to a valid empty result.
	s.savedSearchUIDs = nil
	s.savedSearchSet = true

	// Send FLAGS response with permitted flags
	flags := []string{"\\Answered", "\\Flagged", "\\Deleted", "\\Seen", "\\Draft", "$Label1", "$Label2", "$Label3", "$Label4"}
	s.sendUntagged(fmt.Sprintf("* FLAGS (%s)", strings.Join(flags, " ")))
	permanentFlags := append(append([]string(nil), flags...), "\\*")
	if readOnly {
		permanentFlags = nil
	}
	s.sendUntagged(fmt.Sprintf("* OK [PERMANENTFLAGS (%s)] Permanent flags", strings.Join(permanentFlags, " ")))

	// Send EXISTS
	s.sendUntagged(fmt.Sprintf("* %d EXISTS", len(items)))

	if !s.rev2Enabled {
		// RECENT is retained only for rev1 compatibility.
		recentCount := 0
		for _, item := range items {
			for _, flag := range item.Flags {
				if flag == model.FlagRecent {
					recentCount++
					break
				}
			}
		}
		s.sendUntagged(fmt.Sprintf("* %d RECENT", recentCount))
	}

	if s.rev2Enabled {
		folders, listErr := s.cfg.FolderSpace.ListFolders(*s.ctx, s.access(), service.FolderQuery{Type: model.FolderTypeMail})
		if listErr != nil {
			folders = nil
		}
		attrs := s.listFolderAttrs(folder, folders)
		delimiter := folder.Delimiter
		if delimiter == "" {
			delimiter = "/"
		}
		s.sendUntagged(fmt.Sprintf("* LIST (%s) %q %s", strings.Join(attrs, " "), delimiter, s.mailboxToWire(mailbox)))
	}

	// Send UIDVALIDITY
	s.sendUntagged(fmt.Sprintf("* OK [UIDVALIDITY %d] UID validity status", folder.UIDValidity))
	s.sendUntagged(fmt.Sprintf("* OK [MAILBOXID (%s)] Mailbox ID", mailboxID(folder)))
	s.sendUntagged(fmt.Sprintf("* OK [UIDNEXT %d] Predicted next UID", folder.NextUID+1))
	highestModSeq := max(uint64(1), folder.HighestModSeq)
	for _, item := range items {
		if item.ModSeq > highestModSeq {
			highestModSeq = item.ModSeq
		}
	}
	s.highestModSeq = highestModSeq
	s.notify.rebase(items)
	s.sendUntagged(fmt.Sprintf("* OK [HIGHESTMODSEQ %d] Highest modification sequence", highestModSeq))
	if qresync != nil && qresync.UIDValidity == folder.UIDValidity {
		s.sendQResyncChanges(*qresync, items)
	}

	if readOnly {
		s.sendOKCode(tag, "READONLY", "Select completed (mailbox is read-only)")
	} else {
		s.sendOKCode(tag, "READ-WRITE", "SELECT completed")
	}
}

// cmdCheck handles the CHECK command (RFC 3501).
func (s *Session) cmdCheck(tag string, args []string) {
	if len(args) != 0 {
		s.sendBAD(tag, "CHECK does not accept arguments")
		return
	}
	// In our implementation, CHECK is a no-op (data is already persisted)
	s.sendOK(tag, "CHECK completed")
}

// cmdClose handles the CLOSE command (RFC 3501).
func (s *Session) cmdClose(tag string, args []string) {
	if len(args) != 0 {
		s.sendBAD(tag, "CLOSE does not accept arguments")
		return
	}
	// Expunge all \\Deleted items, then deselect
	s.expungeAll()
	s.deselect()
	s.sendOK(tag, "CLOSE completed")
}

// cmdUnselect handles the UNSELECT command (RFC 3691).
// Deselects the current mailbox without expunging \Deleted messages.
// Different from CLOSE which does expunge.
func (s *Session) cmdUnselect(tag string, args []string) {
	if len(args) != 0 {
		s.sendBAD(tag, "UNSELECT does not accept arguments")
		return
	}
	if s.curState != stateSelected {
		s.sendBAD(tag, "No mailbox selected")
		return
	}

	s.deselect()
	s.sendOK(tag, "UNSELECT completed")
}

// matchPattern matches an IMAP mailbox name against a pattern with * and % wildcards.
func matchPattern(name, pattern string) bool {
	nameRunes, patternRunes := []rune(name), []rune(pattern)
	type position struct{ name, pattern int }
	memo := make(map[position]bool)
	seen := make(map[position]bool)
	var matches func(int, int) bool
	matches = func(nameIndex, patternIndex int) bool {
		key := position{nameIndex, patternIndex}
		if seen[key] {
			return memo[key]
		}
		seen[key] = true
		result := false
		if patternIndex == len(patternRunes) {
			result = nameIndex == len(nameRunes)
		} else {
			switch patternRunes[patternIndex] {
			case '*':
				result = matches(nameIndex, patternIndex+1) || (nameIndex < len(nameRunes) && matches(nameIndex+1, patternIndex))
			case '%':
				result = matches(nameIndex, patternIndex+1) || (nameIndex < len(nameRunes) && nameRunes[nameIndex] != '/' && matches(nameIndex+1, patternIndex))
			default:
				result = nameIndex < len(nameRunes) && nameRunes[nameIndex] == patternRunes[patternIndex] && matches(nameIndex+1, patternIndex+1)
			}
		}
		memo[key] = result
		return result
	}
	return matches(0, 0)
}
