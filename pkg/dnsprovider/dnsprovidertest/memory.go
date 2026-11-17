// Package dnsprovidertest provides an in-memory DNS provider for tests.
package dnsprovidertest

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/lkarlslund/veksel/pkg/dnsprovider"
)

// Memory is a thread-safe in-memory zone. FailWrites makes every upsert and
// delete fail with that error.
type Memory struct {
	mu         sync.Mutex
	next       int
	records    []dnsprovider.Record
	FailWrites error
}

// Add seeds a record as if another party had created it.
func (m *Memory) Add(rtype, name, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addLocked(dnsprovider.Record{Type: rtype, Name: name, Value: value})
}

func (m *Memory) addLocked(rec dnsprovider.Record) {
	m.next++
	rec.ID = fmt.Sprintf("r%d", m.next)
	rec.Type, rec.Name = strings.ToUpper(rec.Type), dnsprovider.NormalizeName(rec.Name)
	m.records = append(m.records, rec)
}

// Values returns the data of every record of rtype at name.
func (m *Memory) Values(rtype, name string) []string {
	records, _ := m.ListRecords(context.Background(), name, rtype)
	values := make([]string, 0, len(records))
	for _, rec := range records {
		values = append(values, rec.Value)
	}
	return values
}

func (m *Memory) ListRecords(_ context.Context, name, rtype string) ([]dnsprovider.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []dnsprovider.Record
	for _, rec := range m.records {
		if rec.Name == dnsprovider.NormalizeName(name) && strings.EqualFold(rec.Type, rtype) {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (m *Memory) UpsertRecord(_ context.Context, rec dnsprovider.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailWrites != nil {
		return m.FailWrites
	}
	if rec.ID != "" {
		for i := range m.records {
			if m.records[i].ID == rec.ID {
				m.records[i].Value, m.records[i].TTL = rec.Value, rec.TTL
				return nil
			}
		}
		return fmt.Errorf("record %s not found", rec.ID)
	}
	m.addLocked(rec)
	return nil
}

func (m *Memory) DeleteRecord(_ context.Context, rec dnsprovider.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailWrites != nil {
		return m.FailWrites
	}
	for i, existing := range m.records {
		if (rec.ID != "" && existing.ID == rec.ID) || (rec.ID == "" && existing.Name == dnsprovider.NormalizeName(rec.Name) &&
			strings.EqualFold(existing.Type, rec.Type) && dnsprovider.SameValue(rec.Type, existing.Value, rec.Value)) {
			m.records = append(m.records[:i], m.records[i+1:]...)
			return nil
		}
	}
	return nil
}
