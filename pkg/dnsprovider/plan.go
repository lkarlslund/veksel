package dnsprovider

import (
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
)

// Desired is one record a hosted domain should publish. Prefix selects the
// existing records it competes with: TXT values starting with Prefix (case
// insensitive), or every record of the type at the name when empty. Accept
// reports whether an existing value already satisfies the expectation, such
// as any DMARC policy or a DKIM record carrying the same public key.
type Desired struct {
	Record
	Prefix string
	Accept func(value string) bool
}

// Plan actions.
const (
	ActionCreate    = "create"
	ActionUpdate    = "update"
	ActionUnchanged = "unchanged"
	ActionConflict  = "conflict"
	ActionDelete    = "delete"
)

// Change is one planned (and, after Apply, attempted) record change.
// Replace is the live record an update, overwritten conflict, or delete
// acts on.
type Change struct {
	Action  string   `json:"action"`
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Value   string   `json:"value"`
	Live    []string `json:"live"`
	Owned   bool     `json:"owned"`
	Reason  string   `json:"reason,omitempty"`
	Applied bool     `json:"applied,omitempty"`
	Error   string   `json:"error,omitempty"`
	Replace *Record  `json:"-"`
}

func recordKey(rtype, name string) string {
	return strings.ToUpper(rtype) + " " + NormalizeName(name)
}

func (d Desired) inSlot(rec Record) bool {
	return d.Prefix == "" || strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec.Value)), strings.ToLower(d.Prefix))
}

// computePlan compares desired records with the live records listed per
// type and name. owned reports whether Veksel created a live record. retired
// are owned records in scope that are no longer desired: live ones become
// deletions and vanished ones are returned so ownership can forget them.
// Records Veksel did not create are never deleted, and replacing one is a
// conflict that needs the administrator's confirmation.
func computePlan(desired []Desired, live map[string][]Record, owned func(Record) bool, retired []model.DNSOwnedRecord) ([]Change, []model.DNSOwnedRecord) {
	var changes []Change
	for _, want := range desired {
		var slot []Record
		for _, rec := range live[recordKey(want.Type, want.Name)] {
			if want.inSlot(rec) {
				slot = append(slot, rec)
			}
		}
		change := Change{Type: strings.ToUpper(want.Type), Name: NormalizeName(want.Name), Value: want.Value, Live: []string{}}
		for _, rec := range slot {
			change.Live = append(change.Live, rec.Value)
		}
		change.Action = ActionCreate
		for _, rec := range slot {
			if SameValue(want.Type, rec.Value, want.Value) || (want.Accept != nil && want.Accept(rec.Value)) {
				change.Action, change.Owned = ActionUnchanged, owned(rec)
				break
			}
		}
		if change.Action == ActionCreate && len(slot) > 0 {
			change.Action, change.Reason = ActionConflict, "an existing record Veksel did not create would be replaced"
			replace := slot[0]
			for _, rec := range slot {
				if owned(rec) {
					change.Action, change.Owned, change.Reason, replace = ActionUpdate, true, "", rec
					break
				}
			}
			change.Replace = &replace
		}
		changes = append(changes, change)
	}
	var vanished []model.DNSOwnedRecord
	for _, old := range retired {
		var found *Record
		for _, rec := range live[recordKey(old.Type, old.Name)] {
			if SameValue(old.Type, rec.Value, old.Value) {
				found = &rec
				break
			}
		}
		if found == nil {
			vanished = append(vanished, old)
			continue
		}
		changes = append(changes, Change{Action: ActionDelete, Type: strings.ToUpper(old.Type), Name: NormalizeName(old.Name), Value: old.Value,
			Live: []string{found.Value}, Owned: true, Reason: "published by Veksel and no longer expected", Replace: found})
	}
	return changes, vanished
}
