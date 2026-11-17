package model

// ChangeJournalMetaKey is the NSChanges key that holds an account's change
// journal head. Records live beside it under their own prefix.
const ChangeJournalMetaKey = "meta"

// ChangeJournalRecordPrefix prefixes the NSChanges keys of journal records.
const ChangeJournalRecordPrefix = "record/"

// ChangeJournalMeta is the head of an account's change journal. Current is
// the newest sequence. States below Floor are no longer answerable, so a
// client presenting one must resynchronize from scratch.
type ChangeJournalMeta struct {
	Current    uint64 `json:"current"`
	Floor      uint64 `json:"floor"`
	EntryCount int64  `json:"entry_count"`
}
