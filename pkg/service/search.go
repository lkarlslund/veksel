package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// ErrSearchUnavailable means the account's derived index cannot currently
// answer complete queries. Canonical folder operations remain available.
var ErrSearchUnavailable = errors.New("search index unavailable")

// ErrSearchNotIndexed means the account deliberately has no full-text index,
// as for accounts encrypted at rest, whose plaintext must not reach disk.
// Protocols that can scan canonical items fall back to scanning.
var ErrSearchNotIndexed = fmt.Errorf("%w: account is encrypted at rest and is not indexed", ErrSearchUnavailable)

// SearchOperator combines child filters or compares one indexed field.
type SearchOperator string

const (
	SearchAll      SearchOperator = "all"
	SearchAny      SearchOperator = "any"
	SearchNot      SearchOperator = "not"
	SearchContains SearchOperator = "contains"
	SearchEquals   SearchOperator = "equals"
	SearchPrefix   SearchOperator = "prefix"
	SearchBefore   SearchOperator = "before"
	SearchAfter    SearchOperator = "after"
	SearchBetween  SearchOperator = "between"
)

// SearchFilter is a backend-neutral query tree. Compound nodes use Children;
// comparison nodes use Field and Value, with From/To for ranges.
type SearchFilter struct {
	Operator SearchOperator `json:"operator"`
	Children []SearchFilter `json:"children,omitempty"`
	Field    string         `json:"field,omitempty"`
	Value    string         `json:"value,omitempty"`
	From     string         `json:"from,omitempty"`
	To       string         `json:"to,omitempty"`
}

// SearchQuery describes an account-wide query independent of the index engine.
type SearchQuery struct {
	AccountID string `json:"account_id,omitempty"`
	Text      string `json:"text,omitempty"`
	// Expression is an optional end-user query expression. Search providers
	// compile it into Text and Filter before executing the backend-neutral
	// query. Text remains literal for API clients that already build filters.
	Expression   string             `json:"expression,omitempty"`
	FolderIDs    []string           `json:"folder_ids,omitempty"`
	Types        []model.FolderType `json:"types,omitempty"`
	Filter       *SearchFilter      `json:"filter,omitempty"`
	IncludeTrash bool               `json:"include_trash,omitempty"`
	Sort         string             `json:"sort,omitempty"`
	Limit        int                `json:"limit,omitempty"`
	Cursor       string             `json:"cursor,omitempty"`
	// OmitSnippets tells providers that the caller renders no match snippets,
	// letting them serve text-query hits from stored summaries.
	OmitSnippets bool `json:"omit_snippets,omitempty"`
}

// SearchSnippet is plain text plus byte ranges identifying matches. It is not
// HTML and is safe for clients to escape and render themselves.
type SearchSnippet struct {
	Field  string   `json:"field"`
	Text   string   `json:"text"`
	Ranges [][2]int `json:"ranges,omitempty"`
}

// SearchHit identifies an authorized item and its safe search presentation.
type SearchHit struct {
	ItemID     string           `json:"item_id"`
	FolderID   string           `json:"folder_id"`
	FolderName string           `json:"folder_name"`
	Type       model.FolderType `json:"type"`
	Name       string           `json:"name,omitempty"`
	Title      string           `json:"title,omitempty"`
	Sender     string           `json:"sender,omitempty"`
	// ContactEmails is populated only for authorized contact hits. Keeping the
	// safe address projection here avoids fetching and parsing the same contact
	// a second time in autocomplete consumers.
	ContactEmails []string `json:"contact_emails,omitempty"`
	// The remaining contact fields are an internal projection for the contact
	// workspace. They are deliberately excluded from generic search JSON.
	ContactOrg      string `json:"-"`
	ContactPhone    string `json:"-"`
	ContactKind     string `json:"-"`
	ContactMembers  int    `json:"-"`
	ContactHasPhoto bool   `json:"-"`
	// ContactCategories are the card's CATEGORIES.
	ContactCategories []string        `json:"-"`
	Flags             []string        `json:"flags,omitempty"`
	Date              time.Time       `json:"date,omitzero"`
	Updated           time.Time       `json:"-"`
	Score             float64         `json:"score"`
	Trashed           bool            `json:"trashed"`
	Truncated         bool            `json:"truncated,omitempty"`
	Snippets          []SearchSnippet `json:"snippets,omitempty"`
}

// SearchFacetValue summarizes the complete authorized result set, not merely
// the current page. Label is presentation-safe metadata for known resources.
type SearchFacetValue struct {
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
	Count uint64 `json:"count"`
}

type SearchFacets struct {
	Types   []SearchFacetValue `json:"types"`
	Folders []SearchFacetValue `json:"folders"`
}

// SearchPage is one stable page of results from a particular index generation.
type SearchPage struct {
	Hits       []SearchHit  `json:"hits"`
	Total      uint64       `json:"total"`
	NextCursor string       `json:"next_cursor,omitempty"`
	IndexID    string       `json:"index_id"`
	Facets     SearchFacets `json:"facets"`
}

// SearchIndexStatus reports derived index health without exposing Bleve.
type SearchIndexStatus struct {
	AccountID             string    `json:"account_id"`
	State                 string    `json:"state"`
	IndexID               string    `json:"index_id,omitempty"`
	Checkpoint            string    `json:"checkpoint,omitempty"`
	Documents             uint64    `json:"documents"`
	IndexBytes            int64     `json:"index_bytes"`
	FoldersDone           int       `json:"folders_done"`
	FoldersTotal          int       `json:"folders_total"`
	ItemsDone             int64     `json:"items_done"`
	LastError             string    `json:"last_error,omitempty"`
	UpdatedAt             time.Time `json:"updated_at,omitzero"`
	ActiveGeneration      string    `json:"active_generation,omitempty"`
	Rebuilding            bool      `json:"rebuilding"`
	ServingIndexID        string    `json:"serving_index_id,omitempty"`
	ServingDocuments      uint64    `json:"serving_documents"`
	LastRecoveryIndexID   string    `json:"last_recovery_index_id,omitempty"`
	LastRecoveryReason    string    `json:"last_recovery_reason,omitempty"`
	LastRecoveryAt        time.Time `json:"last_recovery_at,omitzero"`
	BuildStartedAt        time.Time `json:"build_started_at,omitzero"`
	LastResumedAt         time.Time `json:"last_resumed_at,omitzero"`
	ResumeCount           int       `json:"resume_count"`
	LastCompletedFolderID string    `json:"last_completed_folder_id,omitempty"`
}

// SearchReader is the consumer-owned capability shared by REST and protocols.
type SearchReader interface {
	Search(context.Context, AccessContext, SearchQuery) (SearchPage, error)
	SearchStatus(context.Context, AccessContext, string) (SearchIndexStatus, error)
	RequestSearchRebuild(context.Context, AccessContext, string) error
}
