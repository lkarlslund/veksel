// Package authz evaluates authorization policy for Veksel resources.
package authz

import "github.com/lkarlslund/veksel/pkg/model"

// Action is a stable permission identifier.
type Action string

const (
	FolderDiscover          Action = "folder.discover"
	FolderMetadataRead      Action = "folder.metadata.read"
	FolderMetadataWrite     Action = "folder.metadata.write"
	FolderItemsList         Action = "folder.items.list"
	FolderItemsRead         Action = "folder.items.read"
	FolderItemsCreate       Action = "folder.items.create"
	FolderItemsUpdate       Action = "folder.items.update"
	FolderItemsDelete       Action = "folder.items.delete"
	FolderItemsExpunge      Action = "folder.items.expunge"
	FolderChildrenCreate    Action = "folder.children.create"
	FolderChildrenRename    Action = "folder.children.rename"
	FolderChildrenDelete    Action = "folder.children.delete"
	FolderPermissionsRead   Action = "folder.permissions.read"
	FolderPermissionsManage Action = "folder.permissions.manage"
	FolderSharesManage      Action = "folder.shares.manage"
	CalendarSchedule        Action = "calendar.schedule"
	// CalendarFreeBusyRead reveals when a calendar's events make its owner
	// busy, never what they are.
	CalendarFreeBusyRead      Action = "calendar.freebusy.read"
	MailRedirect              Action = "mail.redirect"
	IdentitySendAs            Action = "identity.send_as"
	IdentitySendOnBehalf      Action = "identity.send_on_behalf"
	IdentityPermissionsRead   Action = "identity.permissions.read"
	IdentityPermissionsManage Action = "identity.permissions.manage"
	AccountDelegate           Action = "account.delegate"
	AccountImpersonate        Action = "account.impersonate"
	AccountPermissionsRead    Action = "account.permissions.read"
	AccountPermissionsManage  Action = "account.permissions.manage"
	AccountItemsSearch        Action = "account.items.search"
	AuthorizationRolesRead    Action = "authorization.roles.read"
	AuthorizationRolesWrite   Action = "authorization.roles.write"
	AuthorizationGroupsRead   Action = "authorization.groups.read"
	AuthorizationGroupsWrite  Action = "authorization.groups.write"

	// SystemManage opens installation administration with full operational
	// access. Owner-only authority (assigning system roles, restoring
	// backups, raw configuration) is AuthorizationRolesWrite.
	SystemManage Action = "system.manage"

	// Domain actions are checked on a Domain resource. System bindings with
	// subtree inheritance (system.owner, system.admin) cover every domain;
	// a domain.admin binding covers only its own domain.
	DomainRead             Action = "domain.read"
	DomainAccountsManage   Action = "domain.accounts.manage"
	DomainIdentitiesManage Action = "domain.identities.manage"
	DomainCatchAllManage   Action = "domain.catchall.manage"
	DomainTraceRead        Action = "domain.trace.read"
	DomainLimitsManage     Action = "domain.limits.manage"
	DomainAdminsManage     Action = "domain.admins.manage"
)

const (
	RoleSystemOwner       = "system.owner"
	RoleSystemAdmin       = "system.admin"
	RoleDomainAdmin       = "domain.admin"
	RoleAuditor           = "auditor"
	RoleFolderViewer      = "folder.viewer"
	RoleFolderContributor = "folder.contributor"
	RoleFolderEditor      = "folder.editor"
	RoleFolderManager     = "folder.manager"
	RoleAccountDelegate   = "account.delegate"
	RoleAccountSearcher   = "account.searcher"
	// RoleCalendarFreeBusy shares only a calendar's busy times.
	RoleCalendarFreeBusy = "calendar.freebusy"
	// RoleCalendarDelegate edits a calendar and answers its owner's
	// invitations and booking requests on their behalf.
	RoleCalendarDelegate = "calendar.delegate"
)

var folderViewerPermissions = []string{
	string(FolderDiscover),
	string(FolderMetadataRead),
	string(FolderItemsList),
	string(FolderItemsRead),
}

// BuiltInRoles returns fresh copies of the protected built-in role definitions.
func BuiltInRoles() []model.Role {
	return []model.Role{
		{ID: RoleSystemOwner, Name: "System Owner", Description: "Unrestricted installation authority", ResourceKinds: []model.ResourceKind{model.ResourceSystem}, Permissions: []string{"*"}, BuiltIn: true},
		{ID: RoleSystemAdmin, Name: "System Administrator", Description: "Operational administration without owner assignment", ResourceKinds: []model.ResourceKind{model.ResourceSystem}, Permissions: []string{"system.*", "domain.*", "account.*", "identity.*", "folder.*"}, BuiltIn: true},
		{ID: RoleDomainAdmin, Name: "Domain Administrator", Description: "Accounts, identities, aliases, and catch-all of one domain within its limits", ResourceKinds: []model.ResourceKind{model.ResourceDomain}, Permissions: []string{string(DomainRead), string(DomainAccountsManage), string(DomainIdentitiesManage), string(DomainCatchAllManage), string(DomainTraceRead)}, BuiltIn: true},
		{ID: RoleAuditor, Name: "Auditor", ResourceKinds: []model.ResourceKind{model.ResourceSystem, model.ResourceDomain}, Permissions: []string{"system.read", "domain.read", "account.read", "audit.read"}, BuiltIn: true},
		{ID: RoleFolderViewer, Name: "Viewer", ResourceKinds: []model.ResourceKind{model.ResourceFolder}, Permissions: clone(folderViewerPermissions), BuiltIn: true},
		{ID: RoleFolderContributor, Name: "Contributor", ResourceKinds: []model.ResourceKind{model.ResourceFolder}, Permissions: append(clone(folderViewerPermissions), string(FolderItemsCreate)), BuiltIn: true},
		{ID: RoleFolderEditor, Name: "Editor", ResourceKinds: []model.ResourceKind{model.ResourceFolder}, Permissions: append(clone(folderViewerPermissions), string(FolderItemsCreate), string(FolderItemsUpdate), string(FolderItemsDelete)), BuiltIn: true},
		{ID: RoleFolderManager, Name: "Manager", ResourceKinds: []model.ResourceKind{model.ResourceFolder}, Permissions: append(clone(folderViewerPermissions), string(FolderMetadataWrite), string(FolderItemsCreate), string(FolderItemsUpdate), string(FolderItemsDelete), string(FolderItemsExpunge), string(FolderChildrenCreate), string(FolderChildrenRename), string(FolderChildrenDelete), string(FolderPermissionsRead), string(FolderPermissionsManage), string(FolderSharesManage)), BuiltIn: true},
		{ID: RoleCalendarFreeBusy, Name: "Free/busy only", Description: "See when the calendar owner is busy, without event details", ResourceKinds: []model.ResourceKind{model.ResourceFolder}, Permissions: []string{string(FolderDiscover), string(FolderMetadataRead), string(CalendarFreeBusyRead)}, BuiltIn: true},
		{ID: RoleCalendarDelegate, Name: "Delegate", Description: "Edit the calendar and answer invitations and booking requests for its owner", ResourceKinds: []model.ResourceKind{model.ResourceFolder}, Permissions: append(clone(folderViewerPermissions), string(CalendarFreeBusyRead), string(FolderItemsCreate), string(FolderItemsUpdate), string(FolderItemsDelete), string(CalendarSchedule)), BuiltIn: true},
		{ID: RoleAccountDelegate, Name: "Account Delegate", ResourceKinds: []model.ResourceKind{model.ResourceAccount}, Permissions: []string{string(AccountDelegate)}, BuiltIn: true},
		{ID: RoleAccountSearcher, Name: "Account Searcher", Description: "Search readable items in an account", ResourceKinds: []model.ResourceKind{model.ResourceAccount}, Permissions: []string{string(AccountItemsSearch)}, BuiltIn: true},
	}
}

// BuiltInRole returns a fresh copy of a built-in role by ID.
func BuiltInRole(id string) (model.Role, bool) {
	for _, role := range BuiltInRoles() {
		if role.ID == id {
			role.Permissions = clone(role.Permissions)
			role.ResourceKinds = clone(role.ResourceKinds)
			return role, true
		}
	}
	return model.Role{}, false
}

func clone[T any](values []T) []T { return append([]T(nil), values...) }
