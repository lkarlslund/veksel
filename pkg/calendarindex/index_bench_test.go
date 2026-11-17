package calendarindex

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

// benchSpace serves a synthetic calendar with indexed item lookups, so the
// benchmarks measure the index rather than a linear test double.
type benchSpace struct {
	testSpace
	byID map[string]model.Item
}

func (s *benchSpace) GetItem(_ context.Context, _ service.AccessContext, id string) (model.Item, error) {
	return s.byID[id], nil
}

// benchCalendar returns a calendar of count events spread over five years,
// shaped like an imported work calendar: a meeting-invite description, eight
// attendees, an organizer, a reminder, and a VTIMEZONE. Every 47th event is
// weekly recurring with exceptions.
func benchCalendar(count int) *benchSpace {
	space := &benchSpace{testSpace: testSpace{folder: model.Folder{ID: "calendar", UserID: "alice", Type: model.FolderTypeCalendar, Indexes: model.DefaultFolderIndexes(model.FolderTypeCalendar), HighestModSeq: 1}}, byID: make(map[string]model.Item, count)}
	description := strings.Repeat("Join the meeting from your computer or mobile app. Meeting ID 123 456 789\\, passcode abc. ", 24)
	var attendees strings.Builder
	for n := range 8 {
		fmt.Fprintf(&attendees, "ATTENDEE;CN=Person %d;PARTSTAT=ACCEPTED;ROLE=REQ-PARTICIPANT:mailto:p%d@example.test\r\n", n, n)
	}
	const timezone = "BEGIN:VTIMEZONE\r\nTZID:Europe/Copenhagen\r\nBEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nRRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU\r\nEND:STANDARD\r\nBEGIN:DAYLIGHT\r\nDTSTART:19700329T020000\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\nRRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU\r\nEND:DAYLIGHT\r\nEND:VTIMEZONE\r\n"
	first := time.Date(2022, 1, 3, 9, 0, 0, 0, time.UTC)
	for n := range count {
		start := first.Add(time.Duration(n) * 5 * 365 * 24 * time.Hour / time.Duration(count)).Truncate(time.Hour)
		recurrence := ""
		if n%47 == 0 {
			recurrence = fmt.Sprintf("RRULE:FREQ=WEEKLY;COUNT=200\r\nEXDATE:%s\r\nEXDATE:%s\r\n", start.AddDate(0, 0, 14).Format("20060102T150405Z"), start.AddDate(0, 0, 70).Format("20060102T150405Z"))
		}
		data := fmt.Sprintf("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//bench//EN\r\n%sBEGIN:VEVENT\r\nUID:event-%d\r\nSUMMARY:Planning session %d\r\nDESCRIPTION:%s\r\nLOCATION:Room %d\r\nORGANIZER;CN=Boss:mailto:boss@example.test\r\n%sDTSTART:%s\r\nDTEND:%s\r\n%sBEGIN:VALARM\r\nTRIGGER:-PT15M\r\nACTION:DISPLAY\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
			timezone, n, n, description, n%40, attendees.String(), start.Format("20060102T150405Z"), start.Add(time.Hour).Format("20060102T150405Z"), recurrence)
		item := model.Item{ID: fmt.Sprintf("item-%05d", n), FolderID: "calendar", UID: uint32(n + 1), Data: []byte(data)}
		space.items = append(space.items, item)
		space.byID[item.ID] = item
	}
	space.folder.ItemCount = int64(len(space.items))
	return space
}

var (
	benchWindowStart = time.Date(2025, 3, 31, 0, 0, 0, 0, time.UTC)
	benchWindowEnd   = benchWindowStart.AddDate(0, 0, 42)
)

// BenchmarkQuerySixWeeks measures the calendar workspace request against a
// 14,000-event calendar with the projection already built and cached.
func BenchmarkQuerySixWeeks(b *testing.B) {
	backend, err := pebblestore.New(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = backend.Close() })
	space := benchCalendar(14000)
	index := New(backend)
	access := service.UserAccess("alice", "bench")
	results, err := index.Query(b.Context(), space, access, space.folder, benchWindowStart, benchWindowEnd)
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("occurrences in range: %d", len(results))
	b.ResetTimer()
	for range b.N {
		if _, err := index.Query(b.Context(), space, access, space.folder, benchWindowStart, benchWindowEnd); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkColdFirstQuery measures the first six-week request after a
// restart against a 15,000-event calendar: "rebuild" projects every event
// from scratch, "persisted" loads the projection a previous process stored.
func BenchmarkColdFirstQuery(b *testing.B) {
	space := benchCalendar(15000)
	access := service.UserAccess("alice", "bench")
	b.Run("rebuild", func(b *testing.B) {
		for range b.N {
			b.StopTimer()
			backend, err := pebblestore.New(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			b.StartTimer()
			if _, err := New(backend).Query(b.Context(), space, access, space.folder, benchWindowStart, benchWindowEnd); err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			_ = backend.Close()
			b.StartTimer()
		}
	})
	b.Run("persisted", func(b *testing.B) {
		backend, err := pebblestore.New(b.TempDir())
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = backend.Close() })
		if _, err := New(backend).Query(b.Context(), space, access, space.folder, benchWindowStart, benchWindowEnd); err != nil {
			b.Fatal(err)
		}
		b.ResetTimer()
		for range b.N {
			// A new Index has no cached snapshot, as after a restart.
			if _, err := New(backend).Query(b.Context(), space, access, space.folder, benchWindowStart, benchWindowEnd); err != nil {
				b.Fatal(err)
			}
		}
	})
}
