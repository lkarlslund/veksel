package authz

import (
	"context"
	"fmt"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
)

var imapRightActions = []struct {
	right  rune
	action Action
}{
	{'l', FolderDiscover}, {'r', FolderItemsRead}, {'s', FolderItemsUpdate},
	{'w', FolderItemsUpdate}, {'i', FolderItemsCreate}, {'p', MailRedirect},
	{'k', FolderChildrenCreate}, {'x', FolderChildrenDelete}, {'t', FolderItemsDelete},
	{'e', FolderItemsExpunge}, {'a', FolderPermissionsManage},
}

func IMAPRightAction(right rune) (Action, bool) {
	for _, mapping := range imapRightActions {
		if mapping.right == right {
			return mapping.action, true
		}
	}
	return "", false
}

func IMAPRightsPermissions(rights string) ([]string, error) {
	rights = model.NormalizeACLRights(rights)
	permissions := make([]string, 0, len(rights)+3)
	for _, right := range rights {
		action, ok := IMAPRightAction(right)
		if !ok {
			return nil, fmt.Errorf("unsupported IMAP right %q", string(right))
		}
		permissions = append(permissions, string(action))
		if right == 'r' {
			permissions = append(permissions, string(FolderMetadataRead), string(FolderItemsList))
		}
		if right == 'a' {
			permissions = append(permissions, string(FolderPermissionsRead))
		}
	}
	return permissions, nil
}

// SetIMAPACLBinding mirrors an RFC 4314 ACL entry into canonical policy.
func SetIMAPACLBinding(ctx context.Context, ts *model.TypedStore, folderID, username, rights, grantedBy string) error {
	permissions, err := IMAPRightsPermissions(rights)
	if err != nil {
		return err
	}
	if err := DeleteIMAPACLBinding(ctx, ts, folderID, username); err != nil {
		return err
	}
	if len(permissions) == 0 {
		return nil
	}
	_, err = model.NewPolicyStore(ts).Create(ctx, model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: username},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: folderID},
		Effect:    model.EffectAllow, Permissions: permissions,
		Inheritance: model.InheritanceSelf, GrantedBy: "protocol:imap:" + grantedBy,
	})
	return err
}

func DeleteIMAPACLBinding(ctx context.Context, ts *model.TypedStore, folderID, username string) error {
	store := model.NewPolicyStore(ts)
	bindings, err := store.ListForResource(ctx, model.ResourceRef{Kind: model.ResourceFolder, ID: folderID})
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		if binding.Principal == (model.PrincipalRef{Kind: model.PrincipalUser, ID: strings.ToLower(username)}) &&
			strings.HasPrefix(binding.GrantedBy, "protocol:imap:") {
			if err := store.Delete(ctx, binding.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// AccessibleFolders returns folders for which actor holds action.
func (e *Engine) AccessibleFolders(ctx context.Context, actor model.PrincipalRef, action Action) ([]model.Folder, error) {
	folders, err := e.folders.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]model.Folder, 0)
	for _, folder := range folders {
		decision, err := e.Check(ctx, Request{Actor: actor, Subject: actor, Action: action, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folder.ID}})
		if err != nil {
			return nil, err
		}
		if decision.Allowed {
			result = append(result, folder)
		}
	}
	return result, nil
}
