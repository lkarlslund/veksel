package service

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestProtocolPayloadsUseFolderSpace prevents new protocol adapters from
// bypassing authorization and the durable command journal. IMAP's remaining
// FolderStore calls are explicitly limited to its RFC 4314 ACL compatibility
// adapter; ACLs are authorization metadata rather than folder payload access.
func TestProtocolPayloadsUseFolderSpace(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test location")
	}
	repository := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	protocols := []string{"smtp", "imap", "pop3", "caldav", "ews", "eas", "jmap"}
	allowedACLMethods := []string{"ListACLForUser", "ListACL", "SetACL", "DeleteACL", "GetUserRights", "HasRight"}

	for _, protocol := range protocols {
		directory := filepath.Join(repository, "pkg", protocol)
		err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			text := string(data)
			if strings.Contains(text, "TypedStore.ItemStore()") || strings.Contains(text, "model.NewItemStore(") || strings.Contains(text, "model.NSItems") {
				t.Errorf("%s bypasses FolderSpace for item payloads", path)
			}
			remaining := text
			for _, method := range allowedACLMethods {
				remaining = strings.ReplaceAll(remaining, "TypedStore.FolderStore()."+method, "")
			}
			if strings.Contains(remaining, "TypedStore.FolderStore().") || strings.Contains(remaining, "model.NSFolders") {
				t.Errorf("%s bypasses FolderSpace for folder payloads", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("inspect %s: %v", protocol, err)
		}
	}
}
