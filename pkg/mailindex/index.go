// Package mailindex adapts mail list semantics (preview text, triage marks,
// filters, sort keys, conversation keys, and unread counts) to Veksel' shared
// derived-folder-index framework. Each message is parsed once when it is
// projected, including its Message-ID and ancestor chain; listing, filtering,
// sorting, and conversation grouping then read only the stored projection,
// which the change journal keeps current one item at a time.
package mailindex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/folderindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/search"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/threading"
)

const (
	listVersion = 1
	// listRevision 2 adds the conversation keys to each projected message;
	// 3 decodes RFC 2047 encoded-words in the stored presentation headers.
	listRevision  = 3
	unseenVersion = 1
	// unseenRevision 1 adds the flagged bucket to the unread projection.
	unseenRevision = 1
	// PreviewRunes bounds the stored one-line body preview.
	PreviewRunes  = 140
	listBucket    = "m"
	unseenBucket  = "u"
	flaggedBucket = "f"
	maxPageLimit  = service.MaxItemPageLimit
	// ConversationSubjectWindow bounds the subject fallback for replies that
	// carry no threading headers: farther apart, equal subjects stay apart.
	ConversationSubjectWindow = 14 * 24 * time.Hour
	maxConversationMessages   = 100
	maxParticipants           = 6
)

// listedHeaders are the presentation headers a list row needs. The stored
// item headers win; the parsed message fills any that a writer omitted.
var listedHeaders = []string{"From", "To", "Cc", "Subject", "Date", "Importance", "X-Priority", "Priority"}

// Filter selects a triage subset of a folder.
type Filter string

const (
	FilterAll         Filter = ""
	FilterUnread      Filter = "unread"
	FilterFlagged     Filter = "flagged"
	FilterAttachments Filter = "attachments"
	FilterToMe        Filter = "to_me"
)

// Sort names a list ordering key.
type Sort string

const (
	SortDate    Sort = "date"
	SortFrom    Sort = "from"
	SortSubject Sort = "subject"
	SortSize    Sort = "size"
)

// ParseFilter validates a client filter name; "all" and "" both mean no filter.
func ParseFilter(value string) (Filter, error) {
	switch filter := Filter(strings.TrimSpace(value)); filter {
	case FilterAll, FilterUnread, FilterFlagged, FilterAttachments, FilterToMe:
		return filter, nil
	case "all":
		return FilterAll, nil
	default:
		return "", fmt.Errorf("unsupported mail filter %q", value)
	}
}

// ParseSort validates a client sort key; "" means date.
func ParseSort(value string) (Sort, error) {
	switch sortKey := Sort(strings.TrimSpace(value)); sortKey {
	case "", SortDate:
		return SortDate, nil
	case SortFrom, SortSubject, SortSize:
		return sortKey, nil
	default:
		return "", fmt.Errorf("unsupported mail sort %q", value)
	}
}

// Query selects one page of a folder's list projection.
type Query struct {
	Filter    Filter
	Sort      Sort
	Ascending bool
	// Addresses are the mailbox owner's lowercase addresses for FilterToMe.
	Addresses []string
	// Keyword, when set, keeps only messages carrying this IMAP keyword
	// (compared without case), such as a category's keyword.
	Keyword string
	Limit   int
	// Cursor is the opaque offset returned as NextCursor.
	Cursor string
	// AroundItemID centers the page on one message instead of a cursor.
	AroundItemID string
	// Conversations returns one row per conversation with a message in the
	// listed folder instead of one row per message.
	Conversations bool
	// Related are further folders of the same mailbox (Sent, Archive, ...)
	// whose messages join the listed folder's conversations. Callers must
	// have authorized item reads for each.
	Related []model.Folder
}

// Summary is the list representation of one message: the generic item summary
// plus the stored preview and attachment mark.
type Summary struct {
	service.ItemSummary
	Preview        string        `json:"preview,omitempty"`
	HasAttachments bool          `json:"has_attachments,omitempty"`
	Conversation   *Conversation `json:"conversation,omitempty"`
	// SnoozedUntil and FollowUp are triage metadata kept outside the
	// message; the caller fills them in from its own store.
	SnoozedUntil *time.Time `json:"snoozed_until,omitzero"`
	FollowUp     *FollowUp  `json:"follow_up,omitempty"`
	// Categories are the master category names the message's keywords
	// resolve to, filled in by the caller.
	Categories []string `json:"categories,omitempty"`
}

// FollowUp carries a flagged message's due and reminder times.
type FollowUp struct {
	DueAt      *time.Time `json:"due_at,omitzero"`
	ReminderAt *time.Time `json:"reminder_at,omitzero"`
}

// Annotate applies fn to every summary on the page, conversation members
// included.
func (p *Page) Annotate(fn func(*Summary)) {
	for i := range p.Items {
		fn(&p.Items[i])
		if conversation := p.Items[i].Conversation; conversation != nil {
			for j := range conversation.Messages {
				fn(&conversation.Messages[j])
			}
		}
	}
}

// Conversation describes the thread a conversation-mode row stands for. The
// row's own summary is the newest member in the listed folder; ItemIDs are
// the listed folder's members, which conversation actions apply to.
type Conversation struct {
	ID             string    `json:"id"`
	Count          int       `json:"count"`
	ItemIDs        []string  `json:"item_ids"`
	Unread         int       `json:"unread"`
	Flagged        bool      `json:"flagged,omitempty"`
	Pinned         bool      `json:"pinned,omitempty"`
	HasAttachments bool      `json:"has_attachments,omitempty"`
	Participants   []string  `json:"participants"`
	LatestDate     string    `json:"latest_date"`
	Preview        string    `json:"preview,omitempty"`
	Messages       []Summary `json:"messages"`
}

// Page is one filtered, sorted slice of a folder's messages.
type Page struct {
	Items      []Summary `json:"items"`
	Total      int64     `json:"total"`
	FolderSize int64     `json:"folder_total"`
	Unread     int64     `json:"unread"`
	Offset     int       `json:"offset"`
	NextCursor string    `json:"next_cursor,omitempty"`
	// Building marks a page served while a list projection is still being
	// built: straight from the folder's date index without the projection's
	// filters, sorts, pinning, and conversations, or empty when the query
	// needs them. Unread is unknown. Clients reload when it is ready.
	Building bool `json:"building,omitempty"`
}

type entry struct {
	Name           string            `json:"name,omitempty"`
	UID            uint32            `json:"uid"`
	ModSeq         uint64            `json:"mod_seq"`
	Size           int64             `json:"size"`
	Date           time.Time         `json:"date"`
	Flags          []string          `json:"flags,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Recipients     []string          `json:"rcpt,omitempty"`
	Preview        string            `json:"preview,omitempty"`
	HasAttachments bool              `json:"attach,omitempty"`
	FromKey        string            `json:"from_key,omitempty"`
	SubjectKey     string            `json:"subject_key,omitempty"`
	MessageID      string            `json:"mid,omitempty"`
	Parents        []string          `json:"parents,omitempty"`
	// Thread is the per-message conversation root (threading.RootKey).
	Thread string `json:"thread,omitempty"`
	// pinned orders a conversation row whose listed messages carry
	// KeywordPinned; a message row reads its own flags.
	pinned bool
}

func (e entry) isPinned() bool {
	return e.pinned || slices.Contains(e.Flags, model.KeywordPinned)
}

type listDefinition struct{}

func (listDefinition) Name() string  { return model.MailListIndex }
func (listDefinition) Version() int  { return listVersion }
func (listDefinition) Revision() int { return listRevision }
func (listDefinition) Project(item model.Item) (folderindex.Document, error) {
	raw, err := json.Marshal(project(item))
	return folderindex.Document{ItemID: item.ID, Keys: []string{listBucket}, Value: raw}, err
}

type unseenDefinition struct{}

func (unseenDefinition) Name() string       { return model.MailUnseenIndex }
func (unseenDefinition) Version() int       { return unseenVersion }
func (unseenDefinition) Revision() int      { return unseenRevision }
func (unseenDefinition) MetadataOnly() bool { return true }

// Project keys unseen messages into the unseen bucket and flagged messages
// into the flagged bucket, so unread counts and the flagged smart view read
// only the few identities they need instead of the folder's list projection.
func (unseenDefinition) Project(item model.Item) (folderindex.Document, error) {
	document := folderindex.Document{ItemID: item.ID}
	if !slices.Contains(item.Flags, model.FlagSeen) {
		document.Keys = append(document.Keys, unseenBucket)
	}
	if slices.Contains(item.Flags, model.FlagFlagged) {
		document.Keys = append(document.Keys, flaggedBucket)
	}
	return document, nil
}

func project(item model.Item) entry {
	result := entry{Name: item.Name, UID: item.UID, ModSeq: item.ModSeq, Size: item.Size, Date: item.InternalDate.UTC(), Flags: slices.Clone(item.Flags), Headers: make(map[string]string, len(listedHeaders))}
	for _, name := range listedHeaders {
		// Stored headers keep their RFC 2047 encoded-words; a list row shows
		// the decoded text, like the reading view.
		if value := strings.TrimSpace(model.DecodeHeaderValue(headerValue(item.Headers, name))); value != "" {
			result.Headers[name] = value
		}
	}
	var parsed mail.Header
	if len(item.Data) > 0 {
		if message, err := mail.ReadMessage(bytes.NewReader(item.Data)); err == nil {
			parsed = message.Header
			for _, name := range listedHeaders {
				if _, ok := result.Headers[name]; !ok {
					if value := strings.TrimSpace(model.DecodeHeaderValue(message.Header.Get(name))); value != "" {
						result.Headers[name] = value
					}
				}
			}
		}
		result.Preview, result.HasAttachments = search.MailPreview(item.Data, PreviewRunes)
	}
	threadHeader := func(name string) string {
		if value := headerValue(item.Headers, name); value != "" {
			return value
		}
		return parsed.Get(name)
	}
	result.MessageID = threading.CanonicalID(threadHeader("Message-Id"))
	result.Parents = threading.Parents(threadHeader("References"), threadHeader("In-Reply-To"))
	result.Thread = threading.RootKey(result.threadMessage())
	for _, name := range []string{"To", "Cc"} {
		if addresses, err := mail.ParseAddressList(result.Headers[name]); err == nil {
			for _, address := range addresses {
				result.Recipients = append(result.Recipients, strings.ToLower(address.Address))
			}
		}
	}
	result.FromKey = strings.ToLower(senderLabel(result.Headers["From"]))
	result.SubjectKey = subjectKey(result.Headers["Subject"])
	return result
}

func headerValue(headers map[string]string, name string) string {
	if value, ok := headers[name]; ok {
		return strings.TrimSpace(value)
	}
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func senderLabel(from string) string {
	if address, err := mail.ParseAddress(from); err == nil {
		if address.Name != "" {
			return address.Name
		}
		return address.Address
	}
	return strings.TrimSpace(from)
}

// subjectKey sorts replies and forwards with their originals.
func subjectKey(subject string) string {
	return strings.ToLower(threading.BaseSubject(subject))
}

func (e entry) threadMessage() threading.Message {
	return threading.Message{ID: e.MessageID, Parents: e.Parents, Subject: e.Headers["Subject"], Date: e.Date}
}

// Index serves mail list pages and unread counts from durable projections.
type Index struct {
	lists  *folderindex.Index
	unseen *folderindex.Index
	notify func(Ready)
}

// Ready reports a projection that became current in the background.
type Ready struct {
	Folder model.Folder
	// Index is model.MailListIndex or model.MailUnseenIndex.
	Index string
	// Unread is the folder's unseen message count.
	Unread int64
	// Waiters are the access contexts whose requests were deferred to the
	// build; a warm-up build has its own.
	Waiters []service.AccessContext
}

func New(s store.Store) *Index {
	return &Index{lists: folderindex.New(s), unseen: folderindex.New(s)}
}

// SetBuilder defers full projection builds that interactive queries would
// otherwise wait for to builder. notify, when set, hears each completed
// build. Call it before serving queries.
func (i *Index) SetBuilder(builder *folderindex.Builder, notify func(Ready)) {
	i.notify = notify
	i.lists.SetBuilder(builder)
	i.unseen.SetBuilder(builder)
}

// Warm queues background builds of folder's projections, unread count first,
// so a later query finds them current. Callers must have authorized item
// reads for folder.
func (i *Index) Warm(space service.FolderSpace, access service.AccessContext, folder model.Folder, priority folderindex.Priority) error {
	if err := i.unseen.Schedule(space, access, folder, unseenDefinition{}, i.build(priority, model.MailUnseenIndex)); err != nil {
		return err
	}
	return i.lists.Schedule(space, access, folder, listDefinition{}, i.build(priority, model.MailListIndex))
}

// build describes a background build that reports its result to notify.
func (i *Index) build(priority folderindex.Priority, index string) folderindex.Build {
	build := folderindex.Build{Priority: priority}
	if i.notify == nil {
		return build
	}
	build.Ready = func(folder model.Folder, snapshot *folderindex.Snapshot, waiters []service.AccessContext) {
		ready := Ready{Folder: folder, Index: index, Waiters: waiters}
		if index == model.MailUnseenIndex {
			ready.Unread = int64(len(snapshot.Buckets[unseenBucket]))
		} else {
			ready.Unread = unreadEntries(snapshot)
		}
		i.notify(ready)
	}
	return build
}

// SetSealer seals the stored projections of accounts encrypted at rest.
func (i *Index) SetSealer(sealer folderindex.Sealer) {
	i.lists.SetSealer(sealer)
	i.unseen.SetSealer(sealer)
}

// Unseen returns the number of unseen messages in folder. It fails with
// folderindex.ErrBuilding while the count is first built in the background
// at priority. Callers must already have authorized item reads for folder.
func (i *Index) Unseen(ctx context.Context, space service.FolderSpace, access service.AccessContext, folder model.Folder, priority folderindex.Priority) (int64, error) {
	var count int64
	err := i.unseen.WithBuiltSnapshot(ctx, space, access, folder, unseenDefinition{}, i.build(priority, model.MailUnseenIndex), func(snapshot *folderindex.Snapshot) error {
		count = int64(len(snapshot.Buckets[unseenBucket]))
		return nil
	})
	return count, err
}

// Flagged returns folder's flagged messages, newest first. The unread
// projection's flagged bucket names them, so a folder without flagged mail
// costs one small metadata snapshot and a flagged one decodes only its
// flagged list entries. While the flagged bucket is first built it falls back
// to filtering the list projection; while that is built too the folder
// contributes nothing yet. Callers must already have authorized item reads
// for folder.
func (i *Index) Flagged(ctx context.Context, space service.FolderSpace, access service.AccessContext, folder model.Folder) ([]Summary, error) {
	var flagged map[string]struct{}
	err := i.unseen.WithBuiltSnapshot(ctx, space, access, folder, unseenDefinition{}, i.build(folderindex.PriorityFolder, model.MailUnseenIndex), func(snapshot *folderindex.Snapshot) error {
		documents := snapshot.Buckets[flaggedBucket]
		flagged = make(map[string]struct{}, len(documents))
		for _, document := range documents {
			flagged[document.ItemID] = struct{}{}
		}
		return nil
	})
	if errors.Is(err, folderindex.ErrBuilding) {
		page, err := i.List(ctx, space, access, folder, Query{Filter: FilterFlagged, Sort: SortDate, Limit: maxPageLimit})
		return page.Items, err
	}
	if err != nil || len(flagged) == 0 {
		return nil, err
	}
	var candidates []candidate
	err = i.lists.WithBuiltSnapshot(ctx, space, access, folder, listDefinition{}, i.build(folderindex.PriorityFolder, model.MailListIndex), func(snapshot *folderindex.Snapshot) error {
		documents := snapshot.Buckets[listBucket]
		for n := range documents {
			if _, ok := flagged[documents[n].ItemID]; !ok {
				continue
			}
			value, err := folderindex.DecodeValue[entry](&documents[n])
			if err != nil {
				continue
			}
			candidates = append(candidates, candidate{id: documents[n].ItemID, folderID: folder.ID, entry: value, order: value})
			if len(candidates) == len(flagged) {
				break
			}
		}
		return nil
	})
	if errors.Is(err, folderindex.ErrBuilding) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sortCandidates(candidates, SortDate, false)
	summaries := make([]Summary, len(candidates))
	for n, c := range candidates {
		summaries[n] = c.summary()
	}
	return summaries, nil
}

// StoredPreview is a projected preview and the item version it describes.
type StoredPreview struct {
	ModSeq uint64
	Text   string
}

// Previews returns the folder's projected previews by item ID without
// reading message bodies. Callers must already have authorized item reads
// for folder. It fails when the folder carries no mail list index, or while
// that index is first built in the background, in which case callers fall
// back to ComputePreview.
func (i *Index) Previews(ctx context.Context, space service.FolderSpace, access service.AccessContext, folder model.Folder) (map[string]StoredPreview, error) {
	build := i.build(folderindex.PriorityFolder, model.MailListIndex)
	candidates, err := i.entries(ctx, space, access, folder, &build)
	if err != nil {
		return nil, err
	}
	previews := make(map[string]StoredPreview, len(candidates))
	for _, c := range candidates {
		previews[c.id] = StoredPreview{ModSeq: c.entry.ModSeq, Text: c.entry.Preview}
	}
	return previews, nil
}

// ComputePreview derives the bounded preview the list projection stores.
func ComputePreview(raw []byte) string {
	preview, _ := search.MailPreview(raw, PreviewRunes)
	return preview
}

type candidate struct {
	id       string
	folderID string
	entry    entry
	// order is the sort key: the entry itself, or for a conversation row the
	// entry carrying the conversation's newest date and sender.
	order        entry
	conversation *Conversation
}

// List returns one filtered and sorted page. While folder's projection is
// first built in the background, the page comes from fallbackList instead.
// Callers must already have authorized item reads for folder: a cached
// projection answers without re-checking access.
func (i *Index) List(ctx context.Context, space service.FolderSpace, access service.AccessContext, folder model.Folder, query Query) (Page, error) {
	if query.Limit < 1 || query.Limit > maxPageLimit {
		return Page{}, fmt.Errorf("page limit must be between 1 and %d", maxPageLimit)
	}
	if strings.HasPrefix(query.Cursor, fallbackCursorPrefix) {
		// Keep paging a fallback listing the way it began.
		return fallbackList(ctx, space, access, folder, query)
	}
	offset := 0
	if query.Cursor != "" {
		parsed, err := strconv.Atoi(query.Cursor)
		if err != nil || parsed < 0 {
			return Page{}, errors.New("invalid mail list cursor")
		}
		offset = parsed
	}
	build := i.build(folderindex.PriorityViewed, model.MailListIndex)
	primary, err := i.entries(ctx, space, access, folder, &build)
	if errors.Is(err, folderindex.ErrBuilding) {
		if query.Cursor != "" {
			// An offset into a projection that is being rebuilt.
			return Page{Items: []Summary{}, Building: true}, nil
		}
		return fallbackList(ctx, space, access, folder, query)
	}
	if err != nil {
		return Page{}, err
	}
	var unread int64
	for _, c := range primary {
		if !slices.Contains(c.entry.Flags, model.FlagSeen) {
			unread++
		}
	}
	var candidates []candidate
	building := false
	if query.Conversations {
		// Related folders still being built join their conversations once
		// ready; until then the page says it is incomplete.
		all, err := i.withRelated(ctx, space, access, folder, primary, query.Related, &build)
		if errors.Is(err, folderindex.ErrBuilding) {
			building = true
		} else if err != nil {
			return Page{}, err
		}
		candidates = conversationRows(all, folder.ID, query)
	} else {
		for _, c := range primary {
			if matches(c.entry, query) {
				candidates = append(candidates, c)
			}
		}
	}
	folderSize := int64(len(primary))
	sortCandidates(candidates, query.Sort, query.Ascending)
	if query.AroundItemID != "" {
		index := slices.IndexFunc(candidates, func(c candidate) bool {
			return c.id == query.AroundItemID || c.conversation != nil && slices.Contains(c.conversation.ItemIDs, query.AroundItemID)
		})
		if index < 0 {
			return Page{}, store.ErrNotFound
		}
		offset = max(0, index-query.Limit/2)
	}
	page := Page{Items: []Summary{}, Total: int64(len(candidates)), FolderSize: folderSize, Unread: unread, Offset: offset, Building: building}
	end := min(len(candidates), offset+query.Limit)
	for _, c := range candidates[min(offset, end):end] {
		summary := c.summary()
		summary.Conversation = c.conversation
		page.Items = append(page.Items, summary)
	}
	if end < len(candidates) {
		page.NextCursor = strconv.Itoa(end)
	}
	return page, nil
}

func matches(value entry, query Query) bool {
	if query.Keyword != "" && !slices.ContainsFunc(value.Flags, func(flag string) bool { return strings.EqualFold(flag, query.Keyword) }) {
		return false
	}
	switch query.Filter {
	case FilterUnread:
		return !slices.Contains(value.Flags, model.FlagSeen)
	case FilterFlagged:
		return slices.Contains(value.Flags, model.FlagFlagged)
	case FilterAttachments:
		return value.HasAttachments
	case FilterToMe:
		for _, recipient := range value.Recipients {
			if slices.Contains(query.Addresses, recipient) {
				return true
			}
		}
		return false
	}
	return true
}

func sortCandidates(candidates []candidate, key Sort, ascending bool) {
	compare := func(a, b entry) int {
		switch key {
		case SortFrom:
			return strings.Compare(a.FromKey, b.FromKey)
		case SortSubject:
			return strings.Compare(a.SubjectKey, b.SubjectKey)
		case SortSize:
			return compareInt(a.Size, b.Size)
		}
		return a.Date.Compare(b.Date)
	}
	sort.SliceStable(candidates, func(x, y int) bool {
		a, b := candidates[x].order, candidates[y].order
		// Pinned messages head a date-sorted list in either direction.
		if key == SortDate {
			if pinnedA, pinnedB := a.isPinned(), b.isPinned(); pinnedA != pinnedB {
				return pinnedA
			}
		}
		order := compare(a, b)
		if !ascending {
			order = -order
		}
		if order != 0 {
			return order < 0
		}
		// Ties fall back to newest first, then the stable folder UID.
		if date := b.Date.Compare(a.Date); date != 0 {
			return date < 0
		}
		return a.UID > b.UID
	})
}

func compareInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (c candidate) summary() Summary {
	return Summary{
		ItemSummary: service.ItemSummary{
			ID: c.id, Name: c.entry.Name, FolderID: c.folderID, Headers: c.entry.Headers, Size: c.entry.Size,
			UID: c.entry.UID, ModSeq: c.entry.ModSeq, Flags: slices.Clone(c.entry.Flags), InternalDate: c.entry.Date.Format(time.RFC3339Nano),
		},
		Preview: c.entry.Preview, HasAttachments: c.entry.HasAttachments,
	}
}

// entries decodes one folder's projected messages. With build it defers a
// full rebuild to the background and fails with folderindex.ErrBuilding.
func (i *Index) entries(ctx context.Context, space service.FolderSpace, access service.AccessContext, folder model.Folder, build *folderindex.Build) ([]candidate, error) {
	var candidates []candidate
	use := func(snapshot *folderindex.Snapshot) error {
		documents := snapshot.Buckets[listBucket]
		candidates = make([]candidate, 0, len(documents))
		for n := range documents {
			value, err := folderindex.DecodeValue[entry](&documents[n])
			if err != nil {
				continue
			}
			candidates = append(candidates, candidate{id: documents[n].ItemID, folderID: folder.ID, entry: value, order: value})
		}
		return nil
	}
	var err error
	if build == nil {
		err = i.lists.WithSnapshot(ctx, space, access, folder, listDefinition{}, use)
	} else {
		err = i.lists.WithBuiltSnapshot(ctx, space, access, folder, listDefinition{}, *build, use)
	}
	return candidates, err
}

// unreadEntries counts a list snapshot's unseen messages.
func unreadEntries(snapshot *folderindex.Snapshot) int64 {
	documents := snapshot.Buckets[listBucket]
	var unread int64
	for n := range documents {
		if value, err := folderindex.DecodeValue[entry](&documents[n]); err == nil && !slices.Contains(value.Flags, model.FlagSeen) {
			unread++
		}
	}
	return unread
}

// withRelated appends the related folders' projected messages to primary.
// With build, folders still being built are left out and the rest is
// returned with folderindex.ErrBuilding.
func (i *Index) withRelated(ctx context.Context, space service.FolderSpace, access service.AccessContext, folder model.Folder, primary []candidate, related []model.Folder, build *folderindex.Build) ([]candidate, error) {
	all := primary
	var building error
	for _, other := range related {
		if other.ID == folder.ID {
			continue
		}
		more, err := i.entries(ctx, space, access, other, build)
		if errors.Is(err, folderindex.ErrBuilding) {
			building = err
			continue
		}
		if err != nil {
			return nil, err
		}
		all = append(all[:len(all):len(all)], more...)
	}
	return all, building
}

// fallbackCursorPrefix marks the cursor of a fallbackList page.
const fallbackCursorPrefix = "folder:"

// fallbackList serves one page while folder's list projection is first being
// built: newest first, straight from the folder's bounded date index, with
// rows projected on the fly. The projection's filters, other sorts, and
// category keywords cannot be answered this way, so those queries get an
// empty building page; conversation views get message rows.
func fallbackList(ctx context.Context, space service.FolderSpace, access service.AccessContext, folder model.Folder, query Query) (Page, error) {
	page := Page{Items: []Summary{}, Building: true}
	pager, ok := space.(service.FolderItemPager)
	if !ok || query.Filter != FilterAll || query.Sort != SortDate && query.Sort != "" || query.Ascending || query.Keyword != "" {
		return page, nil
	}
	result, err := pager.ListItemPage(ctx, access, folder.ID, service.ItemPageQuery{
		Order: service.ItemPageOrderInternalDateDescending, Cursor: strings.TrimPrefix(query.Cursor, fallbackCursorPrefix),
		AnchorItemID: query.AroundItemID, Limit: query.Limit, IncludeData: true,
	})
	if err != nil {
		return Page{}, err
	}
	page.Total, page.FolderSize = result.Total, result.Total
	for _, item := range result.Items {
		page.Items = append(page.Items, candidate{id: item.ID, folderID: folder.ID, entry: project(item)}.summary())
	}
	if result.NextCursor != "" {
		page.NextCursor = fallbackCursorPrefix + result.NextCursor
	}
	return page, nil
}

// ConversationItems resolves conversation IDs from a conversation-mode list
// of folder to the folder's current member item IDs, so a conversation
// action covers messages that arrived after the list was loaded. Unknown
// conversation IDs resolve to nothing. Callers must have authorized item
// reads for folder and related.
func (i *Index) ConversationItems(ctx context.Context, space service.FolderSpace, access service.AccessContext, folder model.Folder, related []model.Folder, conversationIDs []string) ([]string, error) {
	primary, err := i.entries(ctx, space, access, folder, nil)
	if err != nil {
		return nil, err
	}
	all, err := i.withRelated(ctx, space, access, folder, primary, related, nil)
	if err != nil {
		return nil, err
	}
	var itemIDs []string
	for _, row := range conversationRows(all, folder.ID, Query{}) {
		if slices.Contains(conversationIDs, row.conversation.ID) {
			itemIDs = append(itemIDs, row.conversation.ItemIDs...)
		}
	}
	return itemIDs, nil
}

// conversationRows groups messages from the listed and related folders into
// conversations and returns one row per conversation that has a message in
// folderID matching the query filter.
func conversationRows(all []candidate, folderID string, query Query) []candidate {
	messages := make([]threading.Message, len(all))
	for n, c := range all {
		messages[n] = c.entry.threadMessage()
	}
	var rows []candidate
	for _, members := range threading.Build(messages, threading.Options{SubjectWindow: ConversationSubjectWindow}) {
		representative, matched := -1, false
		for _, n := range members {
			if all[n].folderID == folderID {
				representative = n
				matched = matched || matches(all[n].entry, query)
			}
		}
		if !matched {
			continue
		}
		newest := all[members[len(members)-1]]
		conversation := &Conversation{Count: len(members), ItemIDs: []string{}, Participants: []string{}, Messages: []Summary{}, LatestDate: newest.entry.Date.Format(time.RFC3339Nano), Preview: newest.entry.Preview}
		root := ""
		for k := len(members) - 1; k >= 0; k-- {
			c := all[members[k]]
			if root == "" || c.entry.Thread < root {
				root = c.entry.Thread
			}
			if len(conversation.Messages) < maxConversationMessages {
				conversation.Messages = append(conversation.Messages, c.summary())
			}
			if sender := senderLabel(c.entry.Headers["From"]); sender != "" && len(conversation.Participants) < maxParticipants && !slices.Contains(conversation.Participants, sender) {
				conversation.Participants = append(conversation.Participants, sender)
			}
			conversation.HasAttachments = conversation.HasAttachments || c.entry.HasAttachments
			conversation.Flagged = conversation.Flagged || slices.Contains(c.entry.Flags, model.FlagFlagged)
			if c.folderID == folderID {
				conversation.Pinned = conversation.Pinned || slices.Contains(c.entry.Flags, model.KeywordPinned)
				conversation.ItemIDs = append(conversation.ItemIDs, c.id)
				if !slices.Contains(c.entry.Flags, model.FlagSeen) {
					conversation.Unread++
				}
			}
		}
		sum := sha256.Sum256([]byte(root))
		conversation.ID = "conv-" + hex.EncodeToString(sum[:12])
		row := all[representative]
		row.order.Date, row.order.FromKey, row.order.pinned = newest.entry.Date, newest.entry.FromKey, conversation.Pinned
		row.conversation = conversation
		rows = append(rows, row)
	}
	return rows
}
