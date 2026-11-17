package account

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// restoredSyncGap is how far a restore advances modification sequences and
// the change journal. It must exceed anything the lost installation can have
// issued after the backup was taken.
const restoredSyncGap = 1 << 32

// rebaseRestoredSyncState makes a generation rebuilt from a backup safe for
// clients that synchronized with the installation after that backup was
// taken. Such a client holds UIDs, mod-sequences, ETags, and change states
// the lost installation issued; reused with different content, they would
// silently corrupt its cache. Every folder therefore gets a greater
// UIDVALIDITY (RFC 3501 §2.3.1.1), so IMAP clients discard their cached
// UIDs, and its mod-sequence counter jumps ahead, so new ETags and
// MODSEQs never repeat earlier ones. The change journal jumps ahead and
// expires every earlier state, so CalDAV, CardDAV, JMAP, and ActiveSync
// clients resynchronize instead of being told nothing changed. Items keep
// their identities, UIDs, and mod-sequences.
func rebaseRestoredSyncState(ctx context.Context, generation *Generation, now time.Time) error {
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	if err := typed.EnsureNamespace(ctx, model.NSChanges); err != nil {
		return err
	}
	// Records below the new floor can never be read again.
	records, err := typed.Scan(ctx, model.NSChanges, model.ChangeJournalRecordPrefix)
	if err != nil {
		return fmt.Errorf("scan restored change journal: %w", err)
	}
	for _, key := range records {
		if err := typed.Delete(ctx, model.NSChanges, key); err != nil {
			return fmt.Errorf("clear restored change journal: %w", err)
		}
	}
	return store.Batch(ctx, generation.Index, func(batchCtx context.Context) error {
		folderIDs, err := typed.Scan(batchCtx, model.NSFolders, "")
		if err != nil {
			return fmt.Errorf("scan restored folders: %w", err)
		}
		validity := uint32(now.Unix())
		for _, id := range folderIDs {
			var folder model.Folder
			if err := typed.Get(batchCtx, model.NSFolders, id, &folder); err != nil {
				return fmt.Errorf("read restored folder %s: %w", id, err)
			}
			folder.UIDValidity = max(validity, folder.UIDValidity+1)
			folder.HighestModSeq += restoredSyncGap
			if err := typed.Set(batchCtx, model.NSFolders, id, folder); err != nil {
				return fmt.Errorf("rebase restored folder %s: %w", id, err)
			}
		}
		var journal model.ChangeJournalMeta
		if err := typed.Get(batchCtx, model.NSChanges, model.ChangeJournalMetaKey, &journal); err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("read restored change journal: %w", err)
		}
		journal.Current += restoredSyncGap
		journal.Floor = journal.Current
		journal.EntryCount = 0
		return typed.Set(batchCtx, model.NSChanges, model.ChangeJournalMetaKey, journal)
	})
}
