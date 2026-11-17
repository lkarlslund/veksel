package dnsprovider

import (
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestComputePlanDiffAndOwnershipRules(t *testing.T) {
	desired := []Desired{
		{Record: Record{Type: "MX", Name: "example.test", Value: "10 mail.example.test."}, Accept: func(v string) bool { return strings.HasSuffix(strings.TrimSuffix(v, "."), " mail.example.test") }},
		{Record: Record{Type: "TXT", Name: "example.test", Value: "v=spf1 mx -all"}, Prefix: "v=spf1"},
		{Record: Record{Type: "TXT", Name: "_dmarc.example.test", Value: "v=DMARC1; p=none"}, Prefix: "v=dmarc1"},
		{Record: Record{Type: "TXT", Name: "s2._domainkey.example.test", Value: "v=DKIM1; p=NEW"}, Prefix: "v=dkim1"},
	}
	live := map[string][]Record{
		"MX example.test":                {{ID: "1", Type: "MX", Name: "example.test", Value: "20 mail.example.test."}},
		"TXT example.test":               {{ID: "2", Type: "TXT", Name: "example.test", Value: "google-site-verification=x"}, {ID: "3", Type: "TXT", Name: "example.test", Value: "v=spf1 include:other -all"}},
		"TXT _dmarc.example.test":        {{ID: "4", Type: "TXT", Name: "_dmarc.example.test", Value: "v=DMARC1; p=quarantine"}},
		"TXT s1._domainkey.example.test": {{ID: "5", Type: "TXT", Name: "s1._domainkey.example.test", Value: "v=DKIM1; p=OLD"}},
	}
	ownedSet := map[string]bool{"4": true, "5": true}
	retired := []model.DNSOwnedRecord{
		{Purpose: "example.test", Type: "TXT", Name: "s1._domainkey.example.test", Value: "v=DKIM1; p=OLD"},
		{Purpose: "example.test", Type: "TXT", Name: "gone.example.test", Value: "x"},
	}
	changes, vanished := computePlan(desired, live, func(r Record) bool { return ownedSet[r.ID] }, retired)
	got := map[string]Change{}
	for _, change := range changes {
		got[change.Type+" "+change.Name] = change
	}
	if c := got["MX example.test"]; c.Action != ActionUnchanged {
		t.Errorf("MX with the same host must be accepted: %+v", c)
	}
	if c := got["TXT example.test"]; c.Action != ActionConflict || c.Replace.ID != "3" || len(c.Live) != 1 {
		t.Errorf("foreign SPF must conflict and ignore unrelated TXT: %+v", c)
	}
	if c := got["TXT _dmarc.example.test"]; c.Action != ActionUpdate || !c.Owned || c.Replace.ID != "4" {
		t.Errorf("owned DMARC with another value must update: %+v", c)
	}
	if c := got["TXT s2._domainkey.example.test"]; c.Action != ActionCreate {
		t.Errorf("new DKIM selector must be created: %+v", c)
	}
	if c := got["TXT s1._domainkey.example.test"]; c.Action != ActionDelete || c.Replace.ID != "5" {
		t.Errorf("retired owned DKIM must be deleted: %+v", c)
	}
	if len(vanished) != 1 || vanished[0].Name != "gone.example.test" {
		t.Errorf("vanished owned records: %+v", vanished)
	}
	// A foreign record that is not desired is never planned for deletion.
	for _, change := range changes {
		if change.Action == ActionDelete && change.Replace.ID != "5" {
			t.Errorf("unexpected deletion %+v", change)
		}
	}
}
