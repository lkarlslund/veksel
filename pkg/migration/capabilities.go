package migration

import (
	"slices"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
)

// SyncDirection is the stable data-flow contract exposed by sync APIs.
type SyncDirection string

const DirectionSourceToVeksel SyncDirection = "source_to_veksel"

// SourceCapabilities describes behavior shared by the adapter and sync
// runner. SourceReadOnly means Veksel never creates, updates, or deletes data
// on the external service.
type SourceCapabilities struct {
	Direction              SyncDirection      `json:"direction"`
	DirectionLabel         string             `json:"direction_label"`
	SourceReadOnly         bool               `json:"source_read_only"`
	IncrementalCheckpoints bool               `json:"incremental_checkpoints"`
	SourceDeletionTracking bool               `json:"source_deletion_tracking"`
	FolderTypes            []model.FolderType `json:"folder_types"`
}

// SourceDescriptor is public, non-secret metadata for one sync adapter.
type SourceDescriptor struct {
	Type         string             `json:"type"`
	Name         string             `json:"name"`
	Description  string             `json:"description"`
	Capabilities SourceCapabilities `json:"capabilities"`
}

var sourceDescriptors = map[string]SourceDescriptor{
	"eas":     sourceDescriptor("eas", "Exchange ActiveSync (EAS)", "Imports Exchange mail, calendars, contacts, notes, and files into Veksel.", model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeContacts, model.FolderTypeNotes, model.FolderTypeFiles),
	"ews":     sourceDescriptor("ews", "Exchange Web Services (EWS)", "Imports Exchange mail, calendars, contacts, notes, and files into Veksel.", model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeContacts, model.FolderTypeNotes, model.FolderTypeFiles),
	"imap":    sourceDescriptor("imap", "Internet Message Access Protocol (IMAP)", "Imports remote mail folders and messages into Veksel.", model.FolderTypeMail),
	"pop3":    pop3SourceDescriptor(),
	"caldav":  sourceDescriptor("caldav", "Calendaring Extensions to WebDAV (CalDAV)", "Imports remote calendars and events into Veksel.", model.FolderTypeCalendar),
	"carddav": sourceDescriptor("carddav", "vCard Extensions to WebDAV (CardDAV)", "Imports remote address books and contacts into Veksel.", model.FolderTypeContacts),
}

func pop3SourceDescriptor() SourceDescriptor {
	descriptor := sourceDescriptor("pop3", "Post Office Protocol version 3 (POP3)", "Imports one remote mailbox into Veksel. POP3 does not expose folders, flags, or source-deletion history.", model.FolderTypeMail)
	descriptor.Capabilities.SourceDeletionTracking = false
	return descriptor
}

func sourceDescriptor(sourceType, name, description string, folderTypes ...model.FolderType) SourceDescriptor {
	return SourceDescriptor{
		Type: sourceType, Name: name, Description: description,
		Capabilities: SourceCapabilities{
			Direction: DirectionSourceToVeksel, DirectionLabel: "Source → Veksel", SourceReadOnly: true,
			IncrementalCheckpoints: true, SourceDeletionTracking: true, FolderTypes: folderTypes,
		},
	}
}

// DescribeSource returns an independent descriptor for a configured adapter.
// Unknown adapters retain the same safe import-only contract for extensions
// and tests, but advertise no item types until explicitly registered.
func DescribeSource(sourceType string) SourceDescriptor {
	sourceType = strings.ToLower(strings.TrimSpace(sourceType))
	descriptor, found := sourceDescriptors[sourceType]
	if !found {
		descriptor = sourceDescriptor(sourceType, strings.ToUpper(sourceType), "Imports data from an external source into Veksel.")
	}
	descriptor.Capabilities.FolderTypes = slices.Clone(descriptor.Capabilities.FolderTypes)
	return descriptor
}
