package migration

import (
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestBuiltInSourceCapabilitiesAreExplicitlyImportOnly(t *testing.T) {
	tests := []struct {
		sourceType      string
		folderType      model.FolderType
		tracksDeletions bool
	}{
		{sourceType: "eas", folderType: model.FolderTypeCalendar, tracksDeletions: true},
		{sourceType: "ews", folderType: model.FolderTypeContacts, tracksDeletions: true},
		{sourceType: "imap", folderType: model.FolderTypeMail, tracksDeletions: true},
		{sourceType: "pop3", folderType: model.FolderTypeMail, tracksDeletions: false},
		{sourceType: "caldav", folderType: model.FolderTypeCalendar, tracksDeletions: true},
		{sourceType: "carddav", folderType: model.FolderTypeContacts, tracksDeletions: true},
	}
	for _, test := range tests {
		t.Run(test.sourceType, func(t *testing.T) {
			descriptor := DescribeSource(test.sourceType)
			capabilities := descriptor.Capabilities
			if descriptor.Type != test.sourceType || descriptor.Name == "" || capabilities.Direction != DirectionSourceToVeksel || capabilities.DirectionLabel != "Source → Veksel" || !capabilities.SourceReadOnly || !capabilities.IncrementalCheckpoints || capabilities.SourceDeletionTracking != test.tracksDeletions {
				t.Fatalf("descriptor = %+v", descriptor)
			}
			found := false
			for _, folderType := range capabilities.FolderTypes {
				found = found || folderType == test.folderType
			}
			if !found {
				t.Fatalf("%s folder types = %v", test.sourceType, capabilities.FolderTypes)
			}
		})
	}
}

func TestDescribeSourceReturnsIndependentFolderTypes(t *testing.T) {
	first := DescribeSource("imap")
	first.Capabilities.FolderTypes[0] = model.FolderTypeFiles
	second := DescribeSource("imap")
	if len(second.Capabilities.FolderTypes) != 1 || second.Capabilities.FolderTypes[0] != model.FolderTypeMail {
		t.Fatalf("shared descriptor storage was mutated: %+v", second)
	}
}
