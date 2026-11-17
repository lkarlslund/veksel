package service

import (
	"slices"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

// TestCommitNotificationNamesTouchedFolders: commit listeners learn every
// folder a committed record touched, including both ends of a move and the
// records of nested commits, so they can wake only interested waiters.
func TestCommitNotificationNamesTouchedFolders(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	var notified [][]string
	space.committed = func(folderIDs []string) { notified = append(notified, folderIDs) }
	access := UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	archive, err := space.CreateFolder(t.Context(), access, "Projects", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	notified = nil
	item, err := space.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: []byte("Subject: one\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.MoveItem(t.Context(), access, item.ID, archive.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := space.CreateItems(t.Context(), access, inbox.ID, []ItemInput{{Data: []byte("Subject: two\r\n\r\nbody")}, {Data: []byte("Subject: three\r\n\r\nbody")}}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{inbox.ID}, slices.Sorted(slices.Values([]string{inbox.ID, archive.ID})), {inbox.ID}}
	if len(notified) != len(want) {
		t.Fatalf("notifications = %v, want %v", notified, want)
	}
	for i := range want {
		if !slices.Equal(notified[i], want[i]) {
			t.Fatalf("notification %d = %v, want %v", i, notified[i], want[i])
		}
	}
}

// announcingSpace is a folder space that only announces commits.
type announcingSpace struct {
	FolderSpace
	listeners changeListeners
}

func (s *announcingSpace) OnChangesCommitted(listener func(string, []string)) func() {
	return s.listeners.add(listener)
}

// TestCacheForwardsCommitNotifications: the folder cache, which every
// protocol uses in production, passes commit listeners to the space it
// wraps, so long polls and IMAP IDLE wake on commits.
func TestCacheForwardsCommitNotifications(t *testing.T) {
	inner := &announcingSpace{}
	var cached FolderSpace = NewCachedFolderSpace(inner, FolderCacheConfig{Disabled: true})
	notifier, ok := cached.(FolderChangeNotifier)
	if !ok {
		t.Fatal("the folder cache does not announce commits")
	}
	var got []string
	remove := notifier.OnChangesCommitted(func(accountID string, folderIDs []string) { got = append(got, accountID+":"+folderIDs[0]) })
	inner.listeners.notify("alice", []string{"inbox"})
	remove()
	inner.listeners.notify("alice", []string{"later"})
	if !slices.Equal(got, []string{"alice:inbox"}) {
		t.Fatalf("forwarded notifications = %v", got)
	}
}
