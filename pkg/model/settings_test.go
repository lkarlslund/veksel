package model

import (
	"encoding/json"
	"testing"
)

func TestValidateChecklist(t *testing.T) {
	setting := Setting{Type: "checklist", EnumOptions: []string{"PLAIN", "LOGIN"}}
	for _, value := range []string{"", "PLAIN", "PLAIN,LOGIN", " LOGIN , PLAIN "} {
		if err := Validate(setting, json.RawMessage(`"`+value+`"`)); err != nil {
			t.Errorf("Validate(%q): %v", value, err)
		}
	}
	if err := Validate(setting, json.RawMessage(`"PLAIN,CRAM-MD5"`)); err == nil {
		t.Fatal("unsupported checklist option was accepted")
	}
	if err := Validate(setting, json.RawMessage(`[]`)); err == nil {
		t.Fatal("non-string checklist was accepted")
	}
}
