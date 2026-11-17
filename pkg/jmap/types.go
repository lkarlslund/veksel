// Package jmap implements JMAP Core and Mail (RFC 8620, RFC 8621), JMAP for
// Contacts (RFC 9610) and JMAP Calendars (draft-ietf-jmap-calendars) over
// Veksel' authorization-aware service boundaries.
package jmap

import "encoding/json"

const (
	CoreCapability       = "urn:ietf:params:jmap:core"
	MailCapability       = "urn:ietf:params:jmap:mail"
	SubmissionCapability = "urn:ietf:params:jmap:submission"
	VacationCapability   = "urn:ietf:params:jmap:vacationresponse"
	ContactsCapability   = "urn:ietf:params:jmap:contacts"
	CalendarsCapability  = "urn:ietf:params:jmap:calendars"
)

type Capability map[string]any

type Session struct {
	Capabilities    map[string]Capability `json:"capabilities"`
	Accounts        map[string]Account    `json:"accounts"`
	PrimaryAccounts map[string]string     `json:"primaryAccounts"`
	Username        string                `json:"username"`
	APIURL          string                `json:"apiUrl"`
	DownloadURL     string                `json:"downloadUrl"`
	UploadURL       string                `json:"uploadUrl"`
	EventSourceURL  string                `json:"eventSourceUrl"`
	State           string                `json:"state"`
}

type Account struct {
	Name                string         `json:"name"`
	IsPersonal          bool           `json:"isPersonal"`
	IsReadOnly          bool           `json:"isReadOnly"`
	AccountCapabilities map[string]any `json:"accountCapabilities"`
}

type Invocation [3]json.RawMessage

type Request struct {
	Using       []string          `json:"using"`
	MethodCalls []Invocation      `json:"methodCalls"`
	CreatedIDs  map[string]string `json:"createdIds,omitempty"`
}

type Response struct {
	MethodResponses []any             `json:"methodResponses"`
	CreatedIDs      map[string]string `json:"createdIds,omitempty"`
	SessionState    string            `json:"sessionState"`
}

type MethodError struct {
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Properties  []string `json:"properties,omitempty"`
	// NotFound lists the missing blob ids of a blobNotFound SetError.
	NotFound []string `json:"notFound,omitempty"`
}

type getArgs struct {
	AccountID  string   `json:"accountId"`
	IDs        []string `json:"ids"`
	Properties []string `json:"properties"`
}

type setArgs struct {
	AccountID             string                     `json:"accountId"`
	IfInState             string                     `json:"ifInState,omitempty"`
	Create                map[string]json.RawMessage `json:"create,omitempty"`
	Update                map[string]json.RawMessage `json:"update,omitempty"`
	Destroy               []string                   `json:"destroy,omitempty"`
	OnSuccessUpdateEmail  map[string]json.RawMessage `json:"onSuccessUpdateEmail,omitempty"`
	OnSuccessDestroyEmail []string                   `json:"onSuccessDestroyEmail,omitempty"`
	OnDestroyRemoveEmails bool                       `json:"onDestroyRemoveEmails,omitempty"`
}

type queryArgs struct {
	AccountID       string          `json:"accountId"`
	Filter          json.RawMessage `json:"filter,omitempty"`
	Sort            []Comparator    `json:"sort,omitempty"`
	Position        int             `json:"position,omitempty"`
	Anchor          string          `json:"anchor,omitempty"`
	AnchorOffset    int             `json:"anchorOffset,omitempty"`
	Limit           *int            `json:"limit,omitempty"`
	CalculateTotal  bool            `json:"calculateTotal,omitempty"`
	CollapseThreads bool            `json:"collapseThreads,omitempty"`
}

type Comparator struct {
	Property    string `json:"property"`
	IsAscending bool   `json:"isAscending"`
	Collation   string `json:"collation,omitempty"`
}

type changesArgs struct {
	AccountID  string `json:"accountId"`
	SinceState string `json:"sinceState"`
	MaxChanges *int   `json:"maxChanges,omitempty"`
}

type queryChangesArgs struct {
	queryArgs
	SinceQueryState string `json:"sinceQueryState"`
	MaxChanges      *int   `json:"maxChanges,omitempty"`
}

type resultReference struct {
	ResultOf string `json:"resultOf"`
	Name     string `json:"name"`
	Path     string `json:"path"`
}
