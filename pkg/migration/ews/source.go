// Package ews provides an Exchange Web Services migration source.
package ews

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
)

const (
	soapNS = "http://schemas.xmlsoap.org/soap/envelope/"
	msgNS  = "http://schemas.microsoft.com/exchange/services/2006/messages"
	typeNS = "http://schemas.microsoft.com/exchange/services/2006/types"
)

type Config struct {
	Endpoint   string
	Username   string
	Password   string
	HTTPClient *http.Client
	TLSConfig  *tls.Config
	PageSize   int
	// MaxResponseBytes bounds one response; zero uses 64 MiB.
	MaxResponseBytes int
}

type Source struct {
	endpoint string
	username string
	password string
	client   *http.Client
	pageSize int
	folders  map[string]migration.Folder
	// responseMax bounds one response held in memory.
	responseMax int
}

func New(cfg Config) (*Source, error) {
	endpoint, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return nil, errors.New("valid EWS endpoint is required")
	}
	if cfg.Username == "" {
		return nil, errors.New("EWS username is required")
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = 100
	}
	client := cfg.HTTPClient
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = cfg.TLSConfig
		client = &http.Client{Transport: transport, Timeout: 60 * time.Second}
	}
	responseMax := cfg.MaxResponseBytes
	if responseMax <= 0 {
		responseMax = defaultMaxResponseBytes
	}
	return &Source{endpoint: endpoint.String(), username: cfg.Username, password: cfg.Password, client: client, pageSize: cfg.PageSize, folders: make(map[string]migration.Folder), responseMax: responseMax}, nil
}

func (s *Source) ID() string {
	return "ews://" + s.username + "@" + strings.TrimPrefix(strings.TrimPrefix(s.endpoint, "https://"), "http://")
}
func (s *Source) Close() error           { return nil }
func (s *Source) FolderConcurrency() int { return 4 }

func (s *Source) Folders(ctx context.Context) ([]migration.Folder, error) {
	type pendingParent struct {
		RemoteID string
		SourceID string
	}
	wellKnown, err := s.wellKnownFolders(ctx)
	if err != nil {
		return nil, err
	}
	queue := []pendingParent{{RemoteID: "msgfolderroot"}}
	seen := make(map[string]struct{})
	result := make([]migration.Folder, 0, 16)
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		parentXML := `<t:FolderId Id="` + xmlEscape(parent.RemoteID) + `"/>`
		if parent.RemoteID == "msgfolderroot" {
			parentXML = `<t:DistinguishedFolderId Id="msgfolderroot"/>`
		}
		request := `<m:FindFolder Traversal="Shallow"><m:FolderShape><t:BaseShape>AllProperties</t:BaseShape></m:FolderShape><m:ParentFolderIds>` + parentXML + `</m:ParentFolderIds></m:FindFolder>`
		root, err := s.call(ctx, request)
		if err != nil {
			return nil, err
		}
		foldersNode := root.descendant("Folders")
		if foldersNode == nil {
			continue
		}
		for _, wire := range foldersNode.Children {
			idNode := wire.descendant("FolderId")
			if idNode == nil || idNode.attr("Id") == "" {
				continue
			}
			remoteID := idNode.attr("Id")
			if _, duplicate := seen[remoteID]; duplicate {
				continue
			}
			seen[remoteID] = struct{}{}
			folder := migration.Folder{ID: remoteID, ParentID: parent.SourceID, Name: wire.descendantText("DisplayName"), Type: folderType(wire.descendantText("FolderClass"))}
			if estimate, parseErr := strconv.ParseInt(wire.descendantText("TotalCount"), 10, 64); parseErr == nil && estimate >= 0 {
				folder.Estimate = estimate
				folder.EstimateKnown = true
			}
			switch {
			case wellKnown != nil:
				folder.Special = wellKnown[remoteID]
			case parent.SourceID == "":
				folder.Special = specialFolderByName(folder.Name)
			}
			s.folders[folder.ID] = folder
			result = append(result, folder)
			queue = append(queue, pendingParent{RemoteID: remoteID, SourceID: remoteID})
		}
	}
	return result, nil
}

func (s *Source) Items(ctx context.Context, folder migration.Folder, token string) (migration.Page, error) {
	var syncState string
	if token != "" {
		syncState = `<m:SyncState>` + xmlEscape(token) + `</m:SyncState>`
	}
	request := `<m:SyncFolderItems><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape><m:SyncFolderId><t:FolderId Id="` + xmlEscape(folder.ID) + `"/></m:SyncFolderId>` + syncState + `<m:MaxChangesReturned>` + strconv.Itoa(s.pageSize) + `</m:MaxChangesReturned><m:SyncScope>NormalItems</m:SyncScope></m:SyncFolderItems>`
	root, err := s.call(ctx, request)
	if err != nil {
		return migration.Page{}, err
	}
	nextState := root.descendantText("SyncState")
	if nextState == "" {
		return migration.Page{}, errors.New("EWS SyncFolderItems returned no sync state")
	}
	done := strings.EqualFold(root.descendantText("IncludesLastItemInRange"), "true")
	changes := root.descendant("Changes")
	ids := make([]string, 0)
	deletedIDs := make([]string, 0)
	versions := make(map[string]string)
	if changes != nil {
		for _, change := range changes.Children {
			if change.Name.Local == "Delete" {
				if id := change.descendant("ItemId"); id != nil && id.attr("Id") != "" {
					deletedIDs = append(deletedIDs, id.attr("Id"))
				}
				continue
			}
			if change.Name.Local != "Create" && change.Name.Local != "Update" {
				continue
			}
			id := change.descendant("ItemId")
			if id == nil || id.attr("Id") == "" {
				continue
			}
			ids = append(ids, id.attr("Id"))
			versions[id.attr("Id")] = id.attr("ChangeKey")
		}
	}
	if len(ids) == 0 {
		return migration.Page{DeletedIDs: deletedIDs, Checkpoint: nextState, Done: done}, nil
	}
	result, failures, err := s.getItems(ctx, ids, versions)
	if err != nil {
		return migration.Page{}, err
	}
	return migration.Page{Items: result, DeletedIDs: deletedIDs, ItemFailures: failures, Checkpoint: nextState, Done: done}, nil
}

// defaultMaxResponseBytes bounds one EWS response held in memory.
const defaultMaxResponseBytes = 64 << 20

// errFault marks a SOAP fault: the server understood the request and refused it.
var errFault = errors.New("EWS fault")

// errResponseTooLarge marks a response over the source's size limit.
var errResponseTooLarge = errors.New("EWS response exceeds the size limit")

// getItems fetches the MIME content of ids. A response too large to hold,
// or cut off by the server, is retried in halves down to single messages;
// a message that is too large on its own, or that Exchange reports an
// error for, becomes an item failure instead of failing the folder.
func (s *Source) getItems(ctx context.Context, ids []string, versions map[string]string) ([]migration.Item, []migration.ItemFailure, error) {
	var idXML strings.Builder
	for _, id := range ids {
		idXML.WriteString(`<t:ItemId Id="` + xmlEscape(id) + `"/>`)
	}
	// IdOnly plus MIME: AllProperties would send the body a second time.
	request := `<m:GetItem><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:IncludeMimeContent>true</t:IncludeMimeContent><t:AdditionalProperties><t:FieldURI FieldURI="item:DateTimeReceived"/></t:AdditionalProperties></m:ItemShape><m:ItemIds>` + idXML.String() + `</m:ItemIds></m:GetItem>`
	root, err := s.callRaw(ctx, request)
	if err != nil {
		var syntax *xml.SyntaxError
		var timeout interface{ Timeout() bool }
		oversize := errors.Is(err, errResponseTooLarge)
		slow := errors.As(err, &timeout) && timeout.Timeout() && ctx.Err() == nil
		if (oversize || slow || errors.As(err, &syntax)) && len(ids) > 1 {
			half := len(ids) / 2
			first, firstFailures, err := s.getItems(ctx, ids[:half], versions)
			if err != nil {
				return nil, nil, err
			}
			second, secondFailures, err := s.getItems(ctx, ids[half:], versions)
			if err != nil {
				return nil, nil, err
			}
			return append(first, second...), append(firstFailures, secondFailures...), nil
		}
		if oversize {
			return nil, []migration.ItemFailure{{ID: ids[0], Error: fmt.Sprintf("message is larger than %d KiB in EWS form and was not imported", s.responseMax>>10)}}, nil
		}
		return nil, nil, err
	}
	var items []migration.Item
	var failures []migration.ItemFailure
	// Every requested ID ends up imported or as an item failure: a message
	// Exchange leaves out must not vanish while the folder advances.
	// GetItem answers in request order, one response message per ID.
	answered := make([]bool, len(ids))
	messages := root.descendant("ResponseMessages")
	if messages == nil {
		return nil, nil, errors.New("EWS GetItem returned no response messages")
	}
	for index, message := range messages.Children {
		if !strings.EqualFold(message.attr("ResponseClass"), "Success") {
			id := ""
			if index < len(ids) {
				id = ids[index]
			}
			reason := message.descendantText("MessageText")
			if reason == "" {
				reason = message.descendantText("ResponseCode")
			}
			failures = append(failures, migration.ItemFailure{ID: id, Error: "EWS GetItem: " + reason})
			if index < len(ids) {
				answered[index] = true
			}
			continue
		}
		wire := message.descendant("Items")
		if wire == nil || len(wire.Children) == 0 {
			continue
		}
		item := wire.Children[0]
		idNode := item.descendant("ItemId")
		if idNode == nil || idNode.attr("Id") == "" {
			continue
		}
		id := idNode.attr("Id")
		if index < len(ids) {
			answered[index] = true
		}
		mimeNode := item.descendant("MimeContent")
		if mimeNode == nil {
			failures = append(failures, migration.ItemFailure{ID: id, Error: "EWS returned " + item.Name.Local + " without MIME content"})
			continue
		}
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(mimeNode.Text))
		if err != nil {
			failures = append(failures, migration.ItemFailure{ID: id, Error: "decode EWS MIME item: " + err.Error()})
			continue
		}
		version := idNode.attr("ChangeKey")
		if version == "" {
			version = versions[id]
		}
		items = append(items, migration.Item{ID: id, Version: version, Data: data, Headers: model.ParseItemHeaders(data), InternalDate: parseTime(item.descendantText("DateTimeReceived"))})
	}
	for index, id := range ids {
		if !answered[index] {
			failures = append(failures, migration.ItemFailure{ID: id, Error: "EWS GetItem returned no content for the item"})
		}
	}
	return items, failures, nil
}

func (s *Source) call(ctx context.Context, operation string) (*xmlNode, error) {
	root, err := s.callRaw(ctx, operation)
	if err != nil {
		return nil, err
	}
	if code := root.descendantText("ResponseCode"); code != "" && code != "NoError" {
		return nil, fmt.Errorf("EWS response: %s", code)
	}
	return root, nil
}

// callRaw sends operation and returns the decoded envelope, failing on
// transport errors, non-EWS responses, oversize responses and SOAP faults
// but not on per-message response codes.
func (s *Source) callRaw(ctx context.Context, operation string) (*xmlNode, error) {
	body := xml.Header + `<s:Envelope xmlns:s="` + soapNS + `" xmlns:m="` + msgNS + `" xmlns:t="` + typeNS + `"><s:Body>` + operation + `</s:Body></s:Envelope>`
	ctx, remote := migration.TraceRemote(ctx)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(s.username, s.password)
	request.Header.Set("Content-Type", "text/xml; charset=utf-8")
	request.Header.Set("X-AnchorMailbox", s.username)
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("EWS request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(s.responseMax)+1))
	if err != nil {
		return nil, fmt.Errorf("read EWS response: %w", err)
	}
	if len(data) > s.responseMax {
		return nil, errResponseTooLarge
	}
	if err := migration.CheckSourceResponse("EWS", response, remote(), len(data), "text/xml", "application/soap+xml", "application/xml"); err != nil {
		return nil, err
	}
	root, err := parseXML(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decode EWS response: %w", err)
	}
	if fault := root.descendant("Fault"); fault != nil {
		return nil, fmt.Errorf("%w: %s", errFault, fault.descendantText("faultstring"))
	}
	return root, nil
}

func parseTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339, value)
	return parsed
}

func folderType(class string) model.FolderType {
	switch strings.ToLower(class) {
	case "ipf.appointment":
		return model.FolderTypeCalendar
	case "ipf.contact":
		return model.FolderTypeContacts
	case "ipf.stickynote", "ipf.task":
		return model.FolderTypeNotes
	default:
		return model.FolderTypeMail
	}
}

// wellKnownSpecialUse maps Exchange's distinguished folder IDs to special
// uses. Exchange names these folders in the mailbox's language, so the IDs,
// not the display names, identify them.
var wellKnownSpecialUse = []struct{ id, special string }{
	{"inbox", model.SpecialUseInbox},
	{"sentitems", model.SpecialUseSent},
	{"drafts", model.SpecialUseDrafts},
	{"deleteditems", model.SpecialUseTrash},
	{"junkemail", model.SpecialUseJunk},
}

// wellKnownFolders asks Exchange which folders are its well-known ones and
// returns their special use by folder ID. It returns nil when the server
// answers none of them, and the caller falls back to display names.
func (s *Source) wellKnownFolders(ctx context.Context) (map[string]string, error) {
	var ids strings.Builder
	for _, folder := range wellKnownSpecialUse {
		ids.WriteString(`<t:DistinguishedFolderId Id="` + folder.id + `"/>`)
	}
	root, err := s.callRaw(ctx, `<m:GetFolder><m:FolderShape><t:BaseShape>IdOnly</t:BaseShape></m:FolderShape><m:FolderIds>`+ids.String()+`</m:FolderIds></m:GetFolder>`)
	if errors.Is(err, errFault) {
		return nil, nil // a server without GetFolder: names identify them
	}
	if err != nil {
		return nil, fmt.Errorf("identify well-known folders: %w", err)
	}
	messages := root.descendant("ResponseMessages")
	if messages == nil {
		return nil, nil
	}
	result := make(map[string]string, len(wellKnownSpecialUse))
	for index, message := range messages.Children {
		if index >= len(wellKnownSpecialUse) || !strings.EqualFold(message.attr("ResponseClass"), "Success") {
			continue
		}
		if id := message.descendant("FolderId"); id != nil && id.attr("Id") != "" {
			result[id.attr("Id")] = wellKnownSpecialUse[index].special
		}
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

// specialFolderNames are the display names Exchange and Outlook give the
// well-known folders in the languages Veksel supports, for servers that do
// not answer GetFolder for distinguished folders.
var specialFolderNames = map[string]string{
	// English
	"inbox": model.SpecialUseInbox, "sent": model.SpecialUseSent, "sent items": model.SpecialUseSent,
	"drafts": model.SpecialUseDrafts, "trash": model.SpecialUseTrash, "deleted items": model.SpecialUseTrash,
	"junk": model.SpecialUseJunk, "junk email": model.SpecialUseJunk, "junk e-mail": model.SpecialUseJunk,
	// Danish
	"indbakke": model.SpecialUseInbox, "sendt post": model.SpecialUseSent, "sendte elementer": model.SpecialUseSent,
	"kladder": model.SpecialUseDrafts, "slettet post": model.SpecialUseTrash, "slettede elementer": model.SpecialUseTrash,
	"uønsket mail": model.SpecialUseJunk, "uønsket e-mail": model.SpecialUseJunk,
	// Norwegian
	"innboks": model.SpecialUseInbox, "sendte e-poster": model.SpecialUseSent, "utkast": model.SpecialUseDrafts,
	"søppelpost": model.SpecialUseJunk, "useriøs e-post": model.SpecialUseJunk,
	// Swedish
	"inkorgen": model.SpecialUseInbox, "skickat": model.SpecialUseSent, "skickade objekt": model.SpecialUseSent,
	"borttaget": model.SpecialUseTrash, "borttagna objekt": model.SpecialUseTrash, "skräppost": model.SpecialUseJunk,
	// German
	"posteingang": model.SpecialUseInbox, "gesendete elemente": model.SpecialUseSent, "gesendete objekte": model.SpecialUseSent,
	"entwürfe": model.SpecialUseDrafts, "gelöschte elemente": model.SpecialUseTrash, "gelöschte objekte": model.SpecialUseTrash,
	"junk-e-mail": model.SpecialUseJunk,
}

// specialFolderByName recognises a top-level well-known folder by its
// display name.
func specialFolderByName(name string) string {
	return specialFolderNames[strings.ToLower(strings.TrimSpace(name))]
}

func xmlEscape(value string) string {
	var output strings.Builder
	_ = xml.EscapeText(&output, []byte(value))
	return output.String()
}

type xmlNode struct {
	Name     xml.Name
	Attrs    []xml.Attr
	Text     string
	Children []*xmlNode
}

func parseXML(reader io.Reader) (*xmlNode, error) {
	decoder := xml.NewDecoder(reader)
	var root *xmlNode
	stack := make([]*xmlNode, 0, 16)
	// Character data from the remote server arrives in runs split by
	// comments, CDATA sections and entities; builders keep many runs linear.
	texts := make([]*strings.Builder, 0, 16)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch token := token.(type) {
		case xml.StartElement:
			if len(stack) >= 64 {
				return nil, errors.New("EWS response nesting limit exceeded")
			}
			node := &xmlNode{Name: token.Name, Attrs: token.Attr}
			if len(stack) == 0 {
				root = node
			} else {
				stack[len(stack)-1].Children = append(stack[len(stack)-1].Children, node)
			}
			stack = append(stack, node)
			texts = append(texts, &strings.Builder{})
		case xml.CharData:
			if len(stack) > 0 {
				texts[len(texts)-1].Write(token)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("unexpected EWS XML end element")
			}
			stack[len(stack)-1].Text = texts[len(texts)-1].String()
			stack, texts = stack[:len(stack)-1], texts[:len(texts)-1]
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, errors.New("incomplete EWS XML response")
	}
	return root, nil
}

func (n *xmlNode) descendant(name string) *xmlNode {
	if n == nil {
		return nil
	}
	if n.Name.Local == name {
		return n
	}
	for _, child := range n.Children {
		if found := child.descendant(name); found != nil {
			return found
		}
	}
	return nil
}

func (n *xmlNode) descendantText(name string) string {
	if found := n.descendant(name); found != nil {
		return strings.TrimSpace(found.Text)
	}
	return ""
}

func (n *xmlNode) attr(name string) string {
	for _, attribute := range n.Attrs {
		if attribute.Name.Local == name {
			return attribute.Value
		}
	}
	return ""
}
