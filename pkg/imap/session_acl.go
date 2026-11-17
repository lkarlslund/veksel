package imap

import (
	"fmt"
	"strings"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

// cmdGetACL handles the GETACL command (RFC 4314).
func (s *Session) cmdGetACL(tag string, args []string) {
	if len(args) < 1 {
		s.sendBAD(tag, "Expected: GETACL mailbox")
		return
	}

	mailbox := args[0]
	folder, ownerID, err := s.resolveMailbox(mailbox)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("Mailbox %s does not exist", mailbox))
		return
	}

	// Check lookup right
	if ownerID != s.userID {
		if ok, err := s.checkRight(tag, folder.ID, s.userID, model.RightLookup); !ok || err != nil {
			return
		}
	}

	entries, err := s.cfg.TypedStore.FolderStore().ListACL(*s.ctx, folder.ID)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("GETACL failed: %v", err))
		return
	}
	wireMailbox := s.mailboxToWire(mailbox)

	// Owner always has full access (implicit)
	s.sendUntagged(fmt.Sprintf("* GETACL %s %s %s", wireMailbox, s.userID, model.RightAll))
	for _, e := range entries {
		if e.Username == s.userID {
			continue // Already printed owner
		}
		s.sendUntagged(fmt.Sprintf("* GETACL %s %s %s", wireMailbox, e.Username, e.Rights))
	}

	s.sendOK(tag, "GETACL completed")
}

// cmdSetACL handles the SETACL command (RFC 4314).
func (s *Session) cmdSetACL(tag string, args []string) {
	if len(args) < 3 {
		s.sendBAD(tag, "Expected: SETACL mailbox user rights")
		return
	}

	mailbox := args[0]
	username := args[1]
	rights := strings.ToLower(args[2])

	folder, ownerID, err := s.resolveMailbox(mailbox)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("Mailbox %s does not exist", mailbox))
		return
	}
	// Only the owner or someone with admin right can set ACLs
	if ownerID != s.userID {
		if ok, err := s.checkRight(tag, folder.ID, s.userID, model.RightAdmin); !ok || err != nil {
			return
		}
	}

	// Validate rights characters
	for _, r := range rights {
		switch r {
		case 'l', 'r', 's', 'w', 'i', 'p', 'k', 'x', 't', 'e', 'a', 'c', 'd':
			// valid
		default:
			s.sendBAD(tag, fmt.Sprintf("Invalid right: %c", r))
			return
		}
	}

	if err := s.cfg.TypedStore.FolderStore().SetACL(*s.ctx, folder.ID, username, rights); err != nil {
		s.sendNO(tag, fmt.Sprintf("SETACL failed: %v", err))
		return
	}
	if s.cfg.Authorizer != nil {
		if err := authz.SetIMAPACLBinding(*s.ctx, s.cfg.TypedStore, folder.ID, username, rights, s.userID); err != nil {
			s.sendNO(tag, fmt.Sprintf("SETACL policy sync failed: %v", err))
			return
		}
	}

	s.sendOK(tag, "SETACL completed")
}

// cmdDeleteACL handles the DELETEACL command (RFC 4314).
func (s *Session) cmdDeleteACL(tag string, args []string) {
	if len(args) < 2 {
		s.sendBAD(tag, "Expected: DELETEACL mailbox user")
		return
	}

	mailbox := args[0]
	username := args[1]

	folder, ownerID, err := s.resolveMailbox(mailbox)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("Mailbox %s does not exist", mailbox))
		return
	}

	// Cannot remove owner's implicit access
	if username == s.userID && ownerID == s.userID {
		s.sendNO(tag, "Cannot remove owner's implicit access")
		return
	}

	// Only the owner or someone with admin right can delete ACLs
	if ownerID != s.userID {
		if ok, err := s.checkRight(tag, folder.ID, s.userID, model.RightAdmin); !ok || err != nil {
			return
		}
	}

	if err := s.cfg.TypedStore.FolderStore().DeleteACL(*s.ctx, folder.ID, username); err != nil {
		s.sendNO(tag, fmt.Sprintf("DELETEACL failed: %v", err))
		return
	}
	if s.cfg.Authorizer != nil {
		if err := authz.DeleteIMAPACLBinding(*s.ctx, s.cfg.TypedStore, folder.ID, username); err != nil {
			s.sendNO(tag, fmt.Sprintf("DELETEACL policy sync failed: %v", err))
			return
		}
	}

	s.sendOK(tag, "DELETEACL completed")
}

// cmdMyRights handles the MYRIGHTS command (RFC 4314).
func (s *Session) cmdMyRights(tag string, args []string) {
	if len(args) < 1 {
		s.sendBAD(tag, "Expected: MYRIGHTS mailbox")
		return
	}

	mailbox := args[0]
	folder, ownerID, err := s.resolveMailbox(mailbox)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("Mailbox %s does not exist", mailbox))
		return
	}
	wireMailbox := s.mailboxToWire(mailbox)

	// Owner always has full access
	if ownerID == s.userID {
		s.sendUntagged(fmt.Sprintf("* MYRIGHTS %s %s", wireMailbox, model.RightAll))
		s.sendOK(tag, "MYRIGHTS completed")
		return
	}
	// Preserve the exact RFC 4314 rights string when the share originated from
	// IMAP. Canonical policy can map multiple legacy rights to one action.
	if rights, err := s.cfg.TypedStore.FolderStore().GetUserRights(*s.ctx, folder.ID, s.userID); err == nil {
		s.sendUntagged(fmt.Sprintf("* MYRIGHTS %s %s", wireMailbox, rights))
		s.sendOK(tag, "MYRIGHTS completed")
		return
	}

	if s.cfg.Authorizer != nil {
		var rights strings.Builder
		for _, right := range model.RightAll {
			allowed, err := s.hasRight(folder.ID, s.userID, string(right))
			if err != nil {
				s.sendNO(tag, fmt.Sprintf("MYRIGHTS failed: %v", err))
				return
			}
			if allowed {
				rights.WriteRune(right)
			}
		}
		s.sendUntagged(fmt.Sprintf("* MYRIGHTS %s %s", wireMailbox, rights.String()))
		s.sendOK(tag, "MYRIGHTS completed")
		return
	}
	// Check if user has an explicit ACL entry
	rights, err := s.cfg.TypedStore.FolderStore().GetUserRights(*s.ctx, folder.ID, s.userID)
	if err != nil {
		s.sendUntagged(fmt.Sprintf("* MYRIGHTS %s l", wireMailbox))
		s.sendOK(tag, "MYRIGHTS completed")
		return
	}

	s.sendUntagged(fmt.Sprintf("* MYRIGHTS %s %s", wireMailbox, rights))
	s.sendOK(tag, "MYRIGHTS completed")
}

// checkRight checks if the current user has the specified right on the folder.
// Returns false if the check fails (and sends a NO response).
func (s *Session) checkRight(tag string, folderID, username, right string) (bool, error) {
	has, err := s.hasRight(folderID, username, right)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("Permission denied: %v", err))
		return false, err
	}
	if !has {
		s.sendNO(tag, "Permission denied")
		return false, nil
	}
	return true, nil
}

func (s *Session) hasRight(folderID, username, right string) (bool, error) {
	if s.cfg.Authorizer == nil {
		return s.cfg.TypedStore.FolderStore().HasRight(*s.ctx, folderID, username, right)
	}
	normalized := model.NormalizeACLRights(right)
	for _, value := range normalized {
		action, ok := authz.IMAPRightAction(value)
		if !ok {
			return false, fmt.Errorf("unsupported right %q", string(value))
		}
		decision, err := s.cfg.Authorizer.Check(*s.ctx, authz.Request{
			Actor: model.PrincipalRef{Kind: model.PrincipalUser, ID: username}, Action: action,
			Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folderID},
		})
		if err != nil || !decision.Allowed {
			return false, err
		}
	}
	return true, nil
}

// metadataTarget is the mailbox (or server) a METADATA command addresses.
// RFC 5464 3.2: /shared entries belong to the mailbox, /private entries to
// the mailbox and the user, so each user keeps a separate private store.
type metadataTarget struct {
	scope   string // folder ID, or "server"
	folder  string // folder ID; empty for the server
	ownerID string
}

// resolveMetadataTarget resolves "##server" or a mailbox the user can see.
func (s *Session) resolveMetadataTarget(mailbox string) (metadataTarget, error) {
	if strings.EqualFold(mailbox, "##server") {
		return metadataTarget{scope: "server"}, nil
	}
	folder, ownerID, err := s.resolveMailbox(mailbox)
	if err != nil {
		return metadataTarget{}, err
	}
	return metadataTarget{scope: folder.ID, folder: folder.ID, ownerID: ownerID}, nil
}

// storeScope is the store scope holding entryName: the target's own scope
// for /shared entries, and a per-user scope for /private entries.
func (s *Session) storeScope(target metadataTarget, entryName string) string {
	if strings.HasPrefix(entryName, "/private/") {
		return "private/" + s.userID + "/" + target.scope
	}
	return target.scope
}

// mayWriteShared reports whether the user may change /shared entries of the
// target: the mailbox owner or a holder of the write right, and for the
// server only an installation administrator.
func (s *Session) mayWriteShared(target metadataTarget) (bool, error) {
	if target.folder == "" {
		if s.cfg.Authorizer == nil {
			return false, nil
		}
		decision, err := s.cfg.Authorizer.Check(*s.ctx, authz.Request{
			Actor: model.PrincipalRef{Kind: model.PrincipalUser, ID: s.userID}, Action: authz.SystemManage,
			Resource: model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
		})
		return err == nil && decision.Allowed, err
	}
	if strings.EqualFold(target.ownerID, s.userID) {
		return true, nil
	}
	return s.hasRight(target.folder, s.userID, model.RightWrite)
}

// listMetadata returns the user's view of the entries matching pattern:
// the target's /shared entries and the user's own /private entries.
func (s *Session) listMetadata(target metadataTarget, pattern string) ([]model.MetadataEntry, error) {
	store := s.cfg.TypedStore.MetadataStore()
	var entries []model.MetadataEntry
	if pattern == "/" || pattern == "/shared/*" {
		shared, err := store.List(*s.ctx, target.scope, "/shared/*")
		if err != nil {
			return nil, err
		}
		entries = append(entries, shared...)
	}
	if pattern == "/" || pattern == "/private/*" {
		private, err := store.List(*s.ctx, s.storeScope(target, "/private/"), "/private/*")
		if err != nil {
			return nil, err
		}
		entries = append(entries, private...)
	}
	return entries, nil
}

// cmdGetMetadata handles the GETMETADATA command (RFC 5464).
// GETMETADATA mailbox entry-name-set
func (s *Session) cmdGetMetadata(tag string, args []string) {
	if len(args) < 2 {
		s.sendBAD(tag, "Expected: GETMETADATA mailbox entry-name-set")
		return
	}

	mailbox := args[0]
	entryNames := args[1:]

	target, err := s.resolveMetadataTarget(mailbox)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("Mailbox %s does not exist", mailbox))
		return
	}

	// RFC 5464 entry names: specific names, "/shared/*", "/private/*", "/".
	for _, name := range entryNames {
		if name != "/" && name != "/shared/*" && name != "/private/*" {
			if err := model.ValidateEntryName(name); err != nil {
				s.sendBAD(tag, fmt.Sprintf("Invalid entry name: %v", err))
				return
			}
		}
	}

	for _, name := range entryNames {
		if name == "/" || strings.HasSuffix(name, "/*") {
			entries, err := s.listMetadata(target, name)
			if err != nil {
				s.sendNO(tag, fmt.Sprintf("GETMETADATA failed: %v", err))
				return
			}
			for _, e := range entries {
				s.sendMetadataEntry(mailbox, e)
			}
			continue
		}
		e, err := s.cfg.TypedStore.MetadataStore().Get(*s.ctx, s.storeScope(target, name), name)
		if err != nil {
			continue // Entry not found - skip silently
		}
		s.sendMetadataEntry(mailbox, e)
	}

	s.sendOK(tag, "GETMETADATA completed")
}

// sendMetadataEntry sends an untagged METADATA response for a single entry.
func (s *Session) sendMetadataEntry(mailbox string, entry model.MetadataEntry) {
	wireMailbox := s.mailboxToWire(mailbox)
	if entry.Value == "" {
		// Entry with empty value - send as deleted
		s.sendUntagged(fmt.Sprintf("* METADATA %s %s NIL", wireMailbox, entry.Name))
	} else {
		// Send value as a literal per RFC 5464
		value := entry.Value
		if _, err := fmt.Fprintf(s.rw, "* METADATA %s %s {%d}\r\n", wireMailbox, entry.Name, len(value)); err != nil {
			return
		}
		if err := s.flush(); err != nil {
			return
		}
		if _, err := s.rw.WriteString(value); err != nil {
			return
		}
		if _, err := s.rw.WriteString("\r\n"); err != nil {
			return
		}
		_ = s.flush()
	}
}

// cmdSetMetadata handles the SETMETADATA command (RFC 5464).
// SETMETADATA mailbox entry-name1 entry-value1 [entry-name2 entry-value2 ...]
func (s *Session) cmdSetMetadata(tag string, args []string) {
	if len(args) < 3 {
		s.sendBAD(tag, "Expected: SETMETADATA mailbox entry-name1 entry-value1 [entry-name2 entry-value2 ...]")
		return
	}

	mailbox := args[0]
	rest := args[1:]

	target, err := s.resolveMetadataTarget(mailbox)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("Mailbox %s does not exist", mailbox))
		return
	}
	// RFC 5464 4.3: every entry is checked before any is changed.
	for i := 0; i < len(rest); i += 2 {
		if !strings.HasPrefix(rest[i], "/shared/") {
			continue
		}
		allowed, err := s.mayWriteShared(target)
		if err != nil {
			s.sendNO(tag, fmt.Sprintf("SETMETADATA failed: %v", err))
			return
		}
		if !allowed {
			s.sendNO(tag, "[NOPERM] Changing shared metadata needs write access")
			return
		}
		break
	}

	// Parse entry name/value pairs
	// Each pair is: entry-name entry-value (or NIL for deletion)
	i := 0
	var entryStates []string // "ok" or "toomuch" per entry
	for i < len(rest) {
		entryName := rest[i]
		i++

		if i >= len(rest) {
			s.sendBAD(tag, "Missing entry value")
			return
		}
		entryValue := rest[i]
		i++

		// Validate entry name
		if err := model.ValidateEntryName(entryName); err != nil {
			s.sendBAD(tag, fmt.Sprintf("Invalid entry name: %v", err))
			return
		}

		// Handle NIL value (deletion)
		if strings.ToUpper(entryValue) == "NIL" {
			if err := s.cfg.TypedStore.MetadataStore().Delete(*s.ctx, s.storeScope(target, entryName), entryName); err != nil {
				entryStates = append(entryStates, "toomuch")
			} else {
				entryStates = append(entryStates, "ok")
			}
			continue
		}

		// Validate entry value length
		if err := model.ValidateEntryValue(entryValue); err != nil {
			entryStates = append(entryStates, "toomuch")
			continue
		}

		if err := s.cfg.TypedStore.MetadataStore().Set(*s.ctx, s.storeScope(target, entryName), entryName, entryValue); err != nil {
			entryStates = append(entryStates, "toomuch")
		} else {
			entryStates = append(entryStates, "ok")
		}
	}

	// Send ENTRY states in the tagged response
	if len(entryStates) > 0 {
		stateStr := fmt.Sprintf("[METADATA-STATE (%s)]", strings.Join(entryStates, " "))
		s.sendOKCode(tag, stateStr, "SETMETADATA completed")
	} else {
		s.sendOK(tag, "SETMETADATA completed")
	}
}
