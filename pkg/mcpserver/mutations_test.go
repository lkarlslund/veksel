package mcpserver

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type mutationFixture struct {
	typed       *model.TypedStore
	space       service.FolderSpace
	server      *httptest.Server
	readSecret  map[string]string
	writeSecret map[string]string
	items       map[string]model.Item
}

func TestDecodeMutationContentBoundaries(t *testing.T) {
	data, headers, err := decodeMutationContent(itemContentInput{Encoding: "base64", Content: "AAEC", Headers: map[string]string{"Content-Type": "application/octet-stream"}})
	if err != nil || !bytes.Equal(data, []byte{0, 1, 2}) || headers["Content-Type"] == "" {
		t.Fatalf("decoded content = %v, %#v, %v", data, headers, err)
	}
	for _, input := range []itemContentInput{
		{Encoding: "hex", Content: "00"},
		{Encoding: "base64", Content: "not-base64"},
		{Content: strings.Repeat("x", maximumMutationContentBytes+1)},
		{Content: "safe", Headers: map[string]string{"Subject": "safe\r\ninjected"}},
	} {
		if _, _, err := decodeMutationContent(input); err == nil {
			t.Fatalf("unsafe mutation input passed: encoding=%q bytes=%d headers=%#v", input.Encoding, len(input.Content), input.Headers)
		}
	}
}

func ownerAccess(userID string) service.AccessContext {
	principal := model.PrincipalRef{Kind: model.PrincipalUser, ID: userID}
	return service.AccessContext{Actor: principal, Subject: principal, Mode: authz.ActingNone, Protocol: "mcp-test"}
}

func newMutationFixture(t *testing.T) *mutationFixture {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range model.Namespaces() {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	users, keys := typed.UserStore(), model.NewAPIKeyStore(typed)
	readSecrets, writeSecrets := make(map[string]string), make(map[string]string)
	for _, userID := range []string{"alice", "bob"} {
		if err := users.Create(t.Context(), userID, userID, "secret"); err != nil {
			t.Fatal(err)
		}
		if err := typed.FolderStore().CreateForUser(t.Context(), userID); err != nil {
			t.Fatal(err)
		}
		_, readSecret, err := keys.CreateWithScopes(t.Context(), userID, "MCP reader", []string{ReadScope})
		if err != nil {
			t.Fatal(err)
		}
		_, writeSecret, err := keys.CreateWithScopes(t.Context(), userID, "MCP writer", []string{ReadScope, WriteScope})
		if err != nil {
			t.Fatal(err)
		}
		readSecrets[userID], writeSecrets[userID] = readSecret, writeSecret
	}
	space := service.NewFolderSpace(typed, authz.New(typed))
	items := make(map[string]model.Item)
	for _, userID := range []string{"alice", "bob"} {
		access := ownerAccess(userID)
		item, err := space.CreateItem(t.Context(), access, model.InboxFolderID(userID), service.ItemInput{
			Data: []byte("Subject: private " + userID + "\r\n\r\nbody-" + userID), Headers: map[string]string{"Subject": "private " + userID},
		})
		if err != nil {
			t.Fatal(err)
		}
		items[userID] = item
	}
	references, err := NewReferenceService(t.Context(), typed, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewHandler(keys, users, space, nil, references, audit.New(typed)))
	t.Cleanup(server.Close)
	return &mutationFixture{typed: typed, space: space, server: server, readSecret: readSecrets, writeSecret: writeSecrets, items: items}
}

func successfulTool[T any](t *testing.T, session *mcp.ClientSession, name string, arguments map[string]any) T {
	t.Helper()
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if result.IsError {
		messages := make([]string, 0, len(result.Content))
		for _, content := range result.Content {
			if text, ok := content.(*mcp.TextContent); ok {
				messages = append(messages, text.Text)
			}
		}
		t.Fatalf("call %s returned tool error: error=%v content=%q structured=%#v", name, result.GetError(), messages, result.StructuredContent)
	}
	return decodeStructured[T](t, result)
}

func rejectedTool(t *testing.T, session *mcp.ClientSession, name string, arguments map[string]any) {
	t.Helper()
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err == nil && !result.IsError {
		t.Fatalf("call %s unexpectedly succeeded: %#v", name, result.StructuredContent)
	}
}

func folderReferences(t *testing.T, session *mcp.ClientSession, accountID string) map[string]folderView {
	t.Helper()
	arguments := map[string]any{}
	if accountID != "" {
		arguments["account_id"] = accountID
	}
	output := successfulTool[listFoldersOutput](t, session, "veksel_list_folders", arguments)
	result := make(map[string]folderView, len(output.Folders))
	for _, folder := range output.Folders {
		result[folder.ID] = folder
	}
	return result
}

func firstItemReference(t *testing.T, session *mcp.ClientSession, folder folderView) string {
	t.Helper()
	output := successfulTool[listItemsOutput](t, session, "veksel_list_items", map[string]any{"folder_ref": folder.Reference})
	if len(output.Items) == 0 {
		t.Fatalf("folder %s has no items", folder.ID)
	}
	return output.Items[0].Reference
}

func TestMutationToolsRequireExplicitWriteScopeAndAdvertiseIntent(t *testing.T) {
	fixture := newMutationFixture(t)
	reader := connect(t, fixture.server.URL, fixture.readSecret["alice"])
	rejectedTool(t, reader, "veksel_set_item_flags", map[string]any{"item_id": fixture.items["alice"].ID, "flags": []string{model.FlagSeen}})

	item, err := fixture.space.GetItem(t.Context(), ownerAccess("alice"), fixture.items["alice"].ID)
	if err != nil || len(item.Flags) != 0 {
		t.Fatalf("read-only key changed item: item=%#v error=%v", item, err)
	}
	entries, err := audit.New(fixture.typed).QueryReverse(t.Context(), time.Time{}, "mcp.item.set_flags", "alice", 10)
	if err != nil || len(entries) != 1 || entries[0].Details["result"] != "failed" || entries[0].Target != "scope" {
		t.Fatalf("scope denial audit = %#v, error=%v", entries, err)
	}

	listed, err := reader.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	wantDestructive := map[string]bool{
		"veksel_create_item": false, "veksel_replace_item_content": true,
		"veksel_set_item_flags": true, "veksel_copy_item": false, "veksel_move_item": true,
		"veksel_trash_item": true, "veksel_restore_item": false,
		"veksel_create_folder": false, "veksel_move_folder": true, "veksel_trash_folder": true, "veksel_restore_folder": false,
	}
	for _, tool := range listed.Tools {
		destructive, ok := wantDestructive[tool.Name]
		if !ok {
			continue
		}
		delete(wantDestructive, tool.Name)
		if tool.Annotations == nil || tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint != destructive || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Errorf("tool %s annotations = %#v", tool.Name, tool.Annotations)
		}
		if !strings.Contains(tool.Description, "mcp.write") || !strings.Contains(tool.Description, "user explicitly requests") {
			t.Errorf("tool %s safety description = %q", tool.Name, tool.Description)
		}
	}
	if len(wantDestructive) != 0 {
		t.Fatalf("missing mutation tools: %#v", wantDestructive)
	}
}

func TestItemContentToolsCreateDraftReplaceConditionallyAndAudit(t *testing.T) {
	fixture := newMutationFixture(t)
	reader := connect(t, fixture.server.URL, fixture.readSecret["alice"])
	drafts := folderReferences(t, reader, "")[model.FolderKey("alice", "Drafts")]
	rejectedTool(t, reader, "veksel_create_item", map[string]any{"folder_ref": drafts.Reference, "name": "draft.eml", "content": "Subject: no\r\n\r\nwrite"})

	writer := connect(t, fixture.server.URL, fixture.writeSecret["alice"])
	drafts = folderReferences(t, writer, "")[model.FolderKey("alice", "Drafts")]
	created := successfulTool[itemMutationOutput](t, writer, "veksel_create_item", map[string]any{
		"folder_ref": drafts.Reference, "name": "draft.eml", "content": "Subject: First\r\n\r\nbody-one", "headers": map[string]string{"Content-Type": "message/rfc822"},
	})
	rejectedTool(t, writer, "veksel_create_item", map[string]any{"folder_ref": drafts.Reference, "name": "draft.eml", "content": "must not overwrite"})
	if created.Item.ModSeq == 0 || created.Item.Reference == "" || created.Item.FolderID != drafts.ID {
		t.Fatalf("created item = %#v", created.Item)
	}
	rejectedTool(t, writer, "veksel_replace_item_content", map[string]any{"item_ref": created.Item.Reference, "expected_mod_seq": created.Item.ModSeq, "confirm": false, "content": "discarded"})
	replaced := successfulTool[itemMutationOutput](t, writer, "veksel_replace_item_content", map[string]any{
		"item_ref": created.Item.Reference, "expected_mod_seq": created.Item.ModSeq, "confirm": true, "content_encoding": "base64", "content": "U3ViamVjdDogU2Vjb25kDQoNCmJvZHktdHdv",
	})
	if replaced.Item.ModSeq <= created.Item.ModSeq {
		t.Fatalf("replacement mod-sequence did not advance: before=%d after=%d", created.Item.ModSeq, replaced.Item.ModSeq)
	}
	rejectedTool(t, writer, "veksel_replace_item_content", map[string]any{"item_ref": replaced.Item.Reference, "expected_mod_seq": created.Item.ModSeq, "confirm": true, "content": "stale"})
	rejectedTool(t, writer, "veksel_replace_item_content", map[string]any{"item_ref": replaced.Item.Reference, "expected_mod_seq": replaced.Item.ModSeq, "confirm": true, "content_encoding": "base64", "content": "not-base64"})
	stored, err := fixture.space.GetItem(t.Context(), ownerAccess("alice"), created.Item.ID)
	if err != nil || !strings.Contains(string(stored.Data), "body-two") {
		t.Fatalf("stored replacement = %q, %v", stored.Data, err)
	}
	inbox := folderReferences(t, writer, "")[model.InboxFolderID("alice")]
	rejectedTool(t, writer, "veksel_create_item", map[string]any{"folder_ref": inbox.Reference, "name": "injected.eml", "content": "mail"})

	entries, err := audit.New(fixture.typed).QueryReverse(t.Context(), time.Time{}, "", "alice", 20)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, entry := range entries {
		if entry.Action == "mcp.item.create_content" || entry.Action == "mcp.item.replace_content" {
			counts[entry.Action]++
			encoded, _ := json.Marshal(entry)
			if strings.Contains(string(encoded), "body-one") || strings.Contains(string(encoded), "body-two") {
				t.Fatalf("audit leaked content: %s", encoded)
			}
		}
	}
	if counts["mcp.item.create_content"] != 4 || counts["mcp.item.replace_content"] != 4 {
		t.Fatalf("content audit counts = %#v", counts)
	}
}

func TestFolderLifecycleToolsUseReferencesRecoveryGuardsAndAudit(t *testing.T) {
	fixture := newMutationFixture(t)
	reader := connect(t, fixture.server.URL, fixture.readSecret["alice"])
	rejectedTool(t, reader, "veksel_create_folder", map[string]any{"name": "Projects", "type": "files"})

	writer := connect(t, fixture.server.URL, fixture.writeSecret["alice"])
	parent := successfulTool[folderMutationOutput](t, writer, "veksel_create_folder", map[string]any{"name": "Projects", "type": "files"})
	if parent.Folder.Name != "Projects" || parent.Folder.Type != model.FolderTypeFiles || parent.Folder.Reference == "" {
		t.Fatalf("parent = %#v", parent)
	}
	child := successfulTool[folderMutationOutput](t, writer, "veksel_create_folder", map[string]any{"name": "Current", "type": "files", "parent_ref": parent.Folder.Reference})
	if child.Folder.ParentID != parent.Folder.ID || child.Folder.ParentRef == "" || child.Folder.Path != "Projects/Current" {
		t.Fatalf("child = %#v", child)
	}
	moved := successfulTool[folderMutationOutput](t, writer, "veksel_move_folder", map[string]any{"folder_ref": child.Folder.Reference, "name": "Active"})
	if moved.Folder.ParentID != "" || moved.Folder.Path != "Active" {
		t.Fatalf("moved = %#v", moved)
	}
	rejectedTool(t, writer, "veksel_trash_folder", map[string]any{"folder_ref": moved.Folder.Reference, "confirm": false})
	if _, err := fixture.space.GetFolder(t.Context(), ownerAccess("alice"), moved.Folder.ID); err != nil {
		t.Fatalf("unconfirmed folder trash changed folder: %v", err)
	}
	trashed := successfulTool[folderMutationOutput](t, writer, "veksel_trash_folder", map[string]any{"folder_ref": moved.Folder.Reference, "confirm": true})
	if !trashed.Folder.Trashed {
		t.Fatalf("trash result = %#v", trashed)
	}
	restored := successfulTool[folderMutationOutput](t, writer, "veksel_restore_folder", map[string]any{"folder_ref": trashed.Folder.Reference})
	if restored.Folder.Trashed || restored.Folder.Path != "Active" {
		t.Fatalf("restore result = %#v", restored)
	}
	rejectedTool(t, writer, "veksel_trash_folder", map[string]any{"folder_ref": folderReferences(t, writer, "")[model.InboxFolderID("alice")].Reference, "confirm": true})
	rejectedTool(t, writer, "veksel_create_folder", map[string]any{"name": "../unsafe", "type": "files"})

	entries, err := audit.New(fixture.typed).QueryReverse(t.Context(), time.Time{}, "", "alice", 30)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"mcp.folder.create": 4, "mcp.folder.move": 1, "mcp.folder.trash": 3, "mcp.folder.restore": 1}
	for _, entry := range entries {
		if _, ok := want[entry.Action]; ok {
			want[entry.Action]--
			if entry.Details["subject"] != "alice" || entry.Details["protocol"] != "mcp" {
				t.Fatalf("incomplete folder audit = %#v", entry)
			}
		}
	}
	for action, remaining := range want {
		if remaining != 0 {
			t.Errorf("audit count for %s remaining = %d", action, remaining)
		}
	}
}

func TestDelegatedFolderMutationRechecksRBACAfterRevocation(t *testing.T) {
	fixture := newMutationFixture(t)
	policyStore := model.NewPolicyStore(fixture.typed)
	binding, err := policyStore.Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Resource:  model.ResourceRef{Kind: model.ResourceAccount, ID: "bob"}, Effect: model.EffectAllow,
		RoleID: authz.RoleAccountDelegate, Inheritance: model.InheritanceSelf, GrantedBy: "bob",
	})
	if err != nil {
		t.Fatal(err)
	}
	writer := connect(t, fixture.server.URL, fixture.writeSecret["alice"])
	created := successfulTool[folderMutationOutput](t, writer, "veksel_create_folder", map[string]any{"account_id": "bob", "name": "Delegated", "type": "mail"})
	if created.Folder.Reference == "" {
		t.Fatal("delegated create returned no reference")
	}
	if err := policyStore.Delete(t.Context(), binding.ID); err != nil {
		t.Fatal(err)
	}
	rejectedTool(t, writer, "veksel_move_folder", map[string]any{"folder_ref": created.Folder.Reference, "name": "Changed"})
	folder, err := fixture.space.GetFolder(t.Context(), ownerAccess("bob"), created.Folder.ID)
	if err != nil || folder.Path != "Delegated" {
		t.Fatalf("revoked delegated mutation changed folder: %#v, %v", folder, err)
	}
}

func TestConcurrentFolderCreatesRemainAccountIsolated(t *testing.T) {
	fixture := newMutationFixture(t)
	type result struct {
		userID, folderID string
		err              error
	}
	results := make(chan result, 2)
	sessions := map[string]*mcp.ClientSession{
		"alice": connect(t, fixture.server.URL, fixture.writeSecret["alice"]),
		"bob":   connect(t, fixture.server.URL, fixture.writeSecret["bob"]),
	}
	var start sync.WaitGroup
	start.Add(2)
	for _, userID := range []string{"alice", "bob"} {
		userID := userID
		go func() {
			start.Done()
			start.Wait()
			response, err := sessions[userID].CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_create_folder", Arguments: map[string]any{"name": "Concurrent", "type": "files"}})
			if err == nil && response.IsError {
				err = response.GetError()
			}
			folderID := ""
			if err == nil {
				data, marshalErr := json.Marshal(response.StructuredContent)
				var output folderMutationOutput
				if marshalErr == nil {
					marshalErr = json.Unmarshal(data, &output)
				}
				if marshalErr != nil {
					err = marshalErr
				} else {
					folderID = output.Folder.ID
				}
			}
			results <- result{userID: userID, folderID: folderID, err: err}
		}()
	}
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent %s create: %v", result.userID, result.err)
		}
		folder, err := fixture.space.GetFolder(t.Context(), ownerAccess(result.userID), result.folderID)
		if err != nil || folder.UserID != result.userID || folder.Path != "Concurrent" {
			t.Fatalf("concurrent %s folder = %#v, %v", result.userID, folder, err)
		}
	}
}

func TestWriteToolsUseOpaqueReferencesRecoverableTrashAndDurableAudit(t *testing.T) {
	fixture := newMutationFixture(t)
	writer := connect(t, fixture.server.URL, fixture.writeSecret["alice"])
	folders := folderReferences(t, writer, "")
	inbox, sent := folders[model.InboxFolderID("alice")], folders[model.SentFolderID("alice")]
	itemRef := firstItemReference(t, writer, inbox)

	flagged := successfulTool[itemMutationOutput](t, writer, "veksel_set_item_flags", map[string]any{"item_ref": itemRef, "flags": []string{model.FlagSeen, model.FlagSeen, model.FlagFlagged}})
	if !slices.Equal(flagged.Item.Flags, []string{model.FlagSeen, model.FlagFlagged}) {
		t.Fatalf("flags = %#v", flagged.Item.Flags)
	}
	copied := successfulTool[itemMutationOutput](t, writer, "veksel_copy_item", map[string]any{"item_ref": itemRef, "destination_folder_ref": sent.Reference, "destination_name": "copy.eml"})
	if copied.Item.FolderID != sent.ID || copied.Item.ID == fixture.items["alice"].ID {
		t.Fatalf("copy result = %#v", copied.Item)
	}
	moved := successfulTool[itemMutationOutput](t, writer, "veksel_move_item", map[string]any{"item_ref": itemRef, "destination_folder_ref": sent.Reference, "destination_name": "moved.eml"})
	if moved.Item.FolderID != sent.ID || moved.Item.ID != fixture.items["alice"].ID {
		t.Fatalf("move result = %#v", moved.Item)
	}
	rejectedTool(t, writer, "veksel_trash_item", map[string]any{"item_ref": moved.Item.Reference, "confirm": false})
	active, err := fixture.space.GetItem(t.Context(), ownerAccess("alice"), moved.Item.ID)
	if err != nil || !active.TrashedAt.IsZero() {
		t.Fatalf("unconfirmed trash changed item: item=%#v error=%v", active, err)
	}
	trashed := successfulTool[itemMutationOutput](t, writer, "veksel_trash_item", map[string]any{"item_ref": moved.Item.Reference, "confirm": true})
	if trashed.Item.ID != moved.Item.ID {
		t.Fatalf("trash result = %#v", trashed.Item)
	}
	restored := successfulTool[itemMutationOutput](t, writer, "veksel_restore_item", map[string]any{"item_ref": trashed.Item.Reference})
	if restored.Item.FolderID != sent.ID || restored.Item.ID != moved.Item.ID {
		t.Fatalf("restore result = %#v", restored.Item)
	}

	entries, err := audit.New(fixture.typed).QueryReverse(t.Context(), time.Time{}, "", "alice", 20)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"mcp.item.set_flags": 1, "mcp.item.copy": 1, "mcp.item.move": 1, "mcp.item.trash": 2, "mcp.item.restore": 1}
	for _, entry := range entries {
		if _, ok := want[entry.Action]; !ok {
			continue
		}
		want[entry.Action]--
		if entry.Actor != "alice" || entry.Details["subject"] != "alice" || entry.Details["protocol"] != "mcp" {
			t.Errorf("incomplete mutation audit: %#v", entry)
		}
		for key, value := range entry.Details {
			if strings.Contains(value, "body-alice") || strings.Contains(strings.ToLower(key), "secret") {
				t.Errorf("audit leaked item content or secret: %#v", entry)
			}
		}
	}
	for action, remaining := range want {
		if remaining != 0 {
			t.Errorf("audit count for %s remaining = %d", action, remaining)
		}
	}
}

func TestDelegatedMutationRechecksRBACAfterGrantRevocation(t *testing.T) {
	fixture := newMutationFixture(t)
	policyStore := model.NewPolicyStore(fixture.typed)
	binding, err := policyStore.Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Resource:  model.ResourceRef{Kind: model.ResourceAccount, ID: "bob"}, Effect: model.EffectAllow,
		RoleID: authz.RoleAccountDelegate, Inheritance: model.InheritanceSelf, GrantedBy: "bob",
	})
	if err != nil {
		t.Fatal(err)
	}
	writer := connect(t, fixture.server.URL, fixture.writeSecret["alice"])
	folders := folderReferences(t, writer, "bob")
	itemRef := firstItemReference(t, writer, folders[model.InboxFolderID("bob")])
	successfulTool[itemMutationOutput](t, writer, "veksel_set_item_flags", map[string]any{"item_ref": itemRef, "flags": []string{model.FlagSeen}})
	if err := policyStore.Delete(t.Context(), binding.ID); err != nil {
		t.Fatal(err)
	}
	rejectedTool(t, writer, "veksel_set_item_flags", map[string]any{"item_ref": itemRef, "flags": []string{model.FlagFlagged}})

	item, err := fixture.space.GetItem(t.Context(), ownerAccess("bob"), fixture.items["bob"].ID)
	if err != nil || !slices.Equal(item.Flags, []string{model.FlagSeen}) {
		t.Fatalf("revoked delegated mutation changed item: item=%#v error=%v", item, err)
	}
	entries, err := audit.New(fixture.typed).QueryReverse(t.Context(), time.Time{}, "mcp.item.set_flags", "alice", 10)
	if err != nil || len(entries) != 2 || entries[0].Details["subject"] != "bob" || entries[0].Details["result"] != "failed" || entries[1].Details["result"] != "succeeded" {
		t.Fatalf("delegated audit evidence = %#v, error=%v", entries, err)
	}
}

func TestMutationReferencesRemainPrincipalAndSessionBound(t *testing.T) {
	fixture := newMutationFixture(t)
	alice := connect(t, fixture.server.URL, fixture.writeSecret["alice"])
	itemRef := firstItemReference(t, alice, folderReferences(t, alice, "")[model.InboxFolderID("alice")])
	rejectedTool(t, connect(t, fixture.server.URL, fixture.writeSecret["alice"]), "veksel_set_item_flags", map[string]any{"item_ref": itemRef, "flags": []string{model.FlagSeen}})
	rejectedTool(t, connect(t, fixture.server.URL, fixture.writeSecret["bob"]), "veksel_set_item_flags", map[string]any{"item_ref": itemRef, "flags": []string{model.FlagSeen}})
}

type folderSpaceWithoutRecovery struct{ service.FolderSpace }

func TestTrashFailsSafelyWithoutRecoveryCapability(t *testing.T) {
	fixture := newMutationFixture(t)
	references, err := NewReferenceService(t.Context(), fixture.typed, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewHandler(model.NewAPIKeyStore(fixture.typed), fixture.typed.UserStore(), folderSpaceWithoutRecovery{fixture.space}, nil, references, audit.New(fixture.typed)))
	t.Cleanup(server.Close)
	writer := connect(t, server.URL, fixture.writeSecret["alice"])
	rejectedTool(t, writer, "veksel_trash_item", map[string]any{"item_id": fixture.items["alice"].ID, "confirm": true})
	item, err := fixture.space.GetItem(t.Context(), ownerAccess("alice"), fixture.items["alice"].ID)
	if err != nil || !item.TrashedAt.IsZero() {
		t.Fatalf("missing recovery capability changed item: item=%#v error=%v", item, err)
	}
}

func TestConcurrentWritersRemainAccountIsolated(t *testing.T) {
	fixture := newMutationFixture(t)
	type result struct {
		userID string
		err    error
	}
	results := make(chan result, 2)
	sessions := map[string]*mcp.ClientSession{
		"alice": connect(t, fixture.server.URL, fixture.writeSecret["alice"]),
		"bob":   connect(t, fixture.server.URL, fixture.writeSecret["bob"]),
	}
	var start sync.WaitGroup
	start.Add(2)
	for _, userID := range []string{"alice", "bob"} {
		userID := userID
		go func() {
			start.Done()
			start.Wait()
			response, err := sessions[userID].CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_set_item_flags", Arguments: map[string]any{"item_id": fixture.items[userID].ID, "flags": []string{userID}}})
			if err == nil && response.IsError {
				err = response.GetError()
			}
			results <- result{userID: userID, err: err}
		}()
	}
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent %s mutation: %v", result.userID, result.err)
		}
		item, err := fixture.space.GetItem(t.Context(), ownerAccess(result.userID), fixture.items[result.userID].ID)
		if err != nil || !slices.Equal(item.Flags, []string{result.userID}) {
			t.Fatalf("concurrent %s item = %#v, error=%v", result.userID, item, err)
		}
	}
}
