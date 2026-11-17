// Package calendarindex adapts calendar interval and recurrence semantics to
// Veksel' shared derived-folder-index framework.
package calendarindex

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	calendarcore "github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/folderindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	projectionVersion = 1
	maxBucketMonths   = 120
)

type Result struct {
	ItemID     string
	FolderID   string
	Occurrence calendarcore.Occurrence
}

type value struct {
	Event        calendarcore.Event `json:"event"`
	Start        time.Time          `json:"start"`
	End          time.Time          `json:"end"`
	RecurrenceID string             `json:"recurrence_id,omitempty"`
}

type definition struct{}

func (definition) Name() string { return model.CalendarRangeIndex }
func (definition) Version() int { return projectionVersion }

// projectionRevision 1 adds reminders, attendee roles, sequence, and the raw
// recurrence rule to stored events; older snapshots are rebuilt.
const projectionRevision = 1

func (definition) Revision() int { return projectionRevision }

// ParallelProject spreads rebuilds over several cores: parsing each event's
// iCalendar payload dominates the cost of building a large calendar.
func (definition) ParallelProject() bool { return true }
func (definition) Project(item model.Item) (folderindex.Document, error) {
	event, err := calendarcore.Project(item.Data)
	if err != nil {
		return folderindex.Document{}, err
	}
	start, end, err := eventBounds(event)
	if err != nil {
		return folderindex.Document{}, err
	}
	if event.Recurrence != "none" {
		return folderindex.Document{ItemID: item.ID, Deferred: true}, nil
	}
	keys := rangeMonths(start, end)
	if len(keys) > maxBucketMonths {
		keys = []string{"*"}
	}
	raw, err := json.Marshal(value{Event: event, Start: start, End: end})
	return folderindex.Document{ItemID: item.ID, Keys: keys, Value: raw}, err
}

type Index struct{ folders *folderindex.Index }

func New(s store.Store) *Index { return &Index{folders: folderindex.New(s)} }

// SetSealer seals the stored projections of accounts encrypted at rest.
func (i *Index) SetSealer(sealer folderindex.Sealer) { i.folders.SetSealer(sealer) }

// SetBuilder lets Warm queue projection builds on builder, the bounded pool
// shared with the mail projections.
func (i *Index) SetBuilder(builder *folderindex.Builder) { i.folders.SetBuilder(builder) }

// Warm queues a background build, catch-up, or load of folder's range
// projection, so the first query after a restart or sign-in finds it ready
// in memory. A query arriving while that build runs waits for it rather than
// building the projection a second time. Callers must have authorized item
// reads for folder.
func (i *Index) Warm(space service.FolderSpace, access service.AccessContext, folder model.Folder, priority folderindex.Priority) error {
	return i.folders.Schedule(space, access, folder, definition{}, folderindex.Build{Priority: priority})
}

func (i *Index) Query(ctx context.Context, space service.FolderSpace, access service.AccessContext, folder model.Folder, start, end time.Time) ([]Result, error) {
	var results []Result
	err := i.folders.WithSnapshot(ctx, space, access, folder, definition{}, func(snapshot *folderindex.Snapshot) error {
		months := rangeMonths(start, end)
		if err := materializeRecurrence(ctx, space, access, snapshot, months); err != nil {
			return err
		}
		// Candidates point into the snapshot so decoded values stay memoized
		// with the cached projection.
		candidates := make(map[string]*folderindex.Document)
		for _, month := range months {
			bucket := snapshot.Buckets[month]
			for n := range bucket {
				candidates[bucket[n].ItemID] = &bucket[n]
			}
			materialized := snapshot.Materialized[month]
			for n := range materialized {
				document := &materialized[n]
				candidate, decodeErr := decodeValue(document)
				if decodeErr != nil {
					continue
				}
				key := document.ItemID + "\x00" + candidate.Start.UTC().Format(time.RFC3339Nano)
				candidates[key] = document
			}
		}
		unbounded := snapshot.Buckets["*"]
		for n := range unbounded {
			candidates[unbounded[n].ItemID] = &unbounded[n]
		}
		results = make([]Result, 0, len(candidates))
		for _, document := range candidates {
			candidate, decodeErr := decodeValue(document)
			if decodeErr != nil || !candidate.Start.Before(end) || !candidate.End.After(start) {
				continue
			}
			recurrenceID := candidate.RecurrenceID
			if recurrenceID == "" {
				recurrenceID = candidate.Start.UTC().Format(time.RFC3339Nano)
			}
			occurrence := calendarcore.Occurrence{Event: candidate.Event, RecurrenceID: recurrenceID}
			results = append(results, Result{ItemID: document.ItemID, FolderID: folder.ID, Occurrence: occurrence})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(results, func(a, b int) bool { return results[a].Occurrence.Start < results[b].Occurrence.Start })
	return results, nil
}

func materializeRecurrence(ctx context.Context, space service.FolderSpace, access service.AccessContext, snapshot *folderindex.Snapshot, months []string) error {
	if snapshot.Materialized == nil {
		snapshot.Materialized = make(map[string][]folderindex.Document)
	}
	missing := make([]string, 0, len(months))
	for _, month := range months {
		if _, found := snapshot.Materialized[month]; !found {
			missing = append(missing, month)
			snapshot.Materialized[month] = []folderindex.Document{}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	first, err := time.Parse("2006-01", missing[0])
	if err != nil {
		return err
	}
	last, err := time.Parse("2006-01", missing[len(missing)-1])
	if err != nil {
		return err
	}
	missingSet := make(map[string]bool, len(missing))
	for _, month := range missing {
		missingSet[month] = true
	}
	for _, deferred := range snapshot.Deferred {
		item, getErr := space.GetItem(ctx, access, deferred.ItemID)
		if getErr != nil {
			if errors.Is(getErr, store.ErrNotFound) {
				continue
			}
			return getErr
		}
		occurrences, _, occurrenceErr := calendarcore.Occurrences(item.Data, first, last.AddDate(0, 1, 0))
		if occurrenceErr != nil {
			continue
		}
		for _, occurrence := range occurrences {
			occurrenceStart, occurrenceEnd, boundsErr := eventBounds(occurrence.Event)
			if boundsErr != nil {
				continue
			}
			document := folderindex.DecodedDocument(item.ID, value{Event: occurrence.Event, Start: occurrenceStart, End: occurrenceEnd, RecurrenceID: occurrence.RecurrenceID})
			for _, month := range rangeMonths(occurrenceStart, occurrenceEnd) {
				if missingSet[month] {
					snapshot.Materialized[month] = append(snapshot.Materialized[month], document)
				}
			}
		}
	}
	return nil
}

func decodeValue(document *folderindex.Document) (value, error) {
	return folderindex.DecodeValue[value](document)
}

func eventBounds(event calendarcore.Event) (time.Time, time.Time, error) {
	parse := func(input string) (time.Time, error) {
		if event.AllDay {
			return time.ParseInLocation(time.DateOnly, input, time.Local)
		}
		return time.Parse(time.RFC3339, input)
	}
	start, err := parse(event.Start)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	end := start.Add(time.Hour)
	if event.End != "" {
		end, err = parse(event.End)
	}
	if err != nil || !end.After(start) {
		return time.Time{}, time.Time{}, errors.New("calendar event has invalid bounds")
	}
	return start, end, nil
}

func rangeMonths(start, end time.Time) []string {
	if !end.After(start) {
		return nil
	}
	cursor := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC)
	last := end.Add(-time.Nanosecond)
	limit := time.Date(last.Year(), last.Month(), 1, 0, 0, 0, 0, time.UTC)
	result := make([]string, 0, 2)
	for !cursor.After(limit) {
		result = append(result, cursor.Format("2006-01"))
		cursor = cursor.AddDate(0, 1, 0)
		if len(result) > 1200 {
			break
		}
	}
	return result
}
