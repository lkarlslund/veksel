package search

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/blevesearch/bleve/v2"
	blevesearch "github.com/blevesearch/bleve/v2/search"
	blevequery "github.com/blevesearch/bleve/v2/search/query"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

type cursor struct {
	IndexID string `json:"index_id"`
	Query   string `json:"query"`
	Offset  int    `json:"offset"`
}

func (m *Manager) Search(ctx context.Context, access service.AccessContext, request service.SearchQuery) (service.SearchPage, error) {
	if err := access.Validate(); err != nil {
		return service.SearchPage{}, err
	}
	if err := validateSearchQuery(request); err != nil {
		return service.SearchPage{}, err
	}
	var err error
	request, err = expandExpression(request)
	if err != nil {
		return service.SearchPage{}, err
	}
	if err := validateSearchQuery(request); err != nil {
		return service.SearchPage{}, err
	}
	accountID := strings.ToLower(strings.TrimSpace(request.AccountID))
	if accountID == "" {
		accountID = strings.ToLower(access.Subject.ID)
	}
	if err := m.requireAccountAction(ctx, access.Actor, accountID, authz.AccountItemsSearch); err != nil {
		return service.SearchPage{}, err
	}
	if !m.settings().Enabled {
		return service.SearchPage{}, fmt.Errorf("%w: disabled", service.ErrSearchUnavailable)
	}
	if entry, found := m.accounts.ByLogin(accountID); found && entry.Manifest.Encrypted && !m.settings().IndexEncryptedAccounts {
		m.ensureBuild(accountID)
		return service.SearchPage{}, service.ErrSearchNotIndexed
	}
	folders, readAccess, err := m.visibleFolders(ctx, access, accountID, request)
	if err != nil {
		return service.SearchPage{}, err
	}
	if len(folders) == 0 {
		return service.SearchPage{Hits: []service.SearchHit{}, Facets: service.SearchFacets{
			Types: []service.SearchFacetValue{}, Folders: []service.SearchFacetValue{},
		}}, nil
	}
	request.AccountID = accountID
	request.Limit = normalizeLimit(request.Limit, m.settings().QueryMaxResults)
	hash := queryHash(request)
	offset := 0
	if request.Cursor != "" {
		decoded, err := decodeCursor(request.Cursor)
		if err != nil || decoded.Query != hash {
			return service.SearchPage{}, fmt.Errorf("invalid or expired search cursor")
		}
		offset = decoded.Offset
	}
	rt := m.runtime(accountID)
	rt.mu.Lock()
	if rt.state.State != "ready" {
		state := rt.state.State
		rt.mu.Unlock()
		m.ensureBuild(accountID)
		return service.SearchPage{}, fmt.Errorf("%w: %s", service.ErrSearchUnavailable, state)
	}
	needsOpen := rt.index == nil
	rt.mu.Unlock()
	if needsOpen {
		if _, err := m.openIndex(accountID, rt); errors.Is(err, errAccountMoved) {
			m.ensureBuild(accountID)
			return service.SearchPage{}, fmt.Errorf("%w: account is moving", service.ErrSearchUnavailable)
		} else if err != nil {
			rt.mu.Lock()
			indexID := rt.state.IndexID
			rt.mu.Unlock()
			_ = m.recoverServingIndex(accountID, rt, indexID, fmt.Errorf("open ready index: %w", err))
			m.ensureBuild(accountID)
			return service.SearchPage{}, fmt.Errorf("%w: reopen index", service.ErrSearchUnavailable)
		}
	}
	m.awaitIndexed(ctx, accountID, rt)
	rt.mu.Lock()
	if request.Cursor != "" {
		decoded, _ := decodeCursor(request.Cursor)
		if decoded.IndexID != rt.state.IndexID {
			rt.mu.Unlock()
			return service.SearchPage{}, fmt.Errorf("invalid or expired search cursor")
		}
	}
	folderIDs := make([]string, 0, len(folders))
	folderByID := make(map[string]model.Folder, len(folders))
	for _, folder := range folders {
		folderIDs = append(folderIDs, folder.ID)
		folderByID[folder.ID] = folder
	}
	compiled, err := compileQuery(request, folderIDs)
	if err != nil {
		rt.mu.Unlock()
		return service.SearchPage{}, err
	}
	searchRequest := bleve.NewSearchRequestOptions(compiled, request.Limit, offset, false)
	searchRequest.AddFacet("types", bleve.NewFacetRequest("type", 32))
	searchRequest.AddFacet("folders", bleve.NewFacetRequest("folder_id", min(len(folderIDs), 100)))
	switch request.Sort {
	case "date_asc":
		searchRequest.SortBy([]string{"date", "_id"})
	case "date_desc":
		searchRequest.SortBy([]string{"-date", "_id"})
	case "name":
		searchRequest.SortBy([]string{"name", "_id"})
	case "contact_name":
		searchRequest.SortBy([]string{"contact_name", "_id"})
	case "contact_name_desc":
		searchRequest.SortBy([]string{"-contact_name", "_id"})
	case "contact_org":
		searchRequest.SortBy([]string{"contact_org", "contact_name", "_id"})
	case "contact_org_desc":
		searchRequest.SortBy([]string{"-contact_org", "contact_name", "_id"})
	case "contact_email":
		searchRequest.SortBy([]string{"contact_email", "contact_name", "_id"})
	case "contact_email_desc":
		searchRequest.SortBy([]string{"-contact_email", "contact_name", "_id"})
	case "contact_phone":
		searchRequest.SortBy([]string{"contact_phone", "contact_name", "_id"})
	case "contact_phone_desc":
		searchRequest.SortBy([]string{"-contact_phone", "contact_name", "_id"})
	case "title":
		searchRequest.SortBy([]string{"title", "_id"})
	case "title_desc":
		searchRequest.SortBy([]string{"-title", "_id"})
	case "sender":
		searchRequest.SortBy([]string{"sender", "_id"})
	case "sender_desc":
		searchRequest.SortBy([]string{"-sender", "_id"})
	case "recipients":
		searchRequest.SortBy([]string{"recipients", "_id"})
	case "recipients_desc":
		searchRequest.SortBy([]string{"-recipients", "_id"})
	case "size":
		searchRequest.SortBy([]string{"size", "_id"})
	case "size_desc":
		searchRequest.SortBy([]string{"-size", "_id"})
	default:
		searchRequest.SortBy([]string{"-_score", "-date", "_id"})
	}
	withSnippets := strings.TrimSpace(request.Text) != "" && !request.OmitSnippets
	if !withSnippets {
		searchRequest.Fields = []string{"folder_id", "summary"}
	}
	indexID := rt.state.IndexID
	if rt.index == nil || rt.relocating {
		// Closed or detached since it was opened above.
		rt.mu.Unlock()
		m.ensureBuild(accountID)
		return service.SearchPage{}, fmt.Errorf("%w: index closed", service.ErrSearchUnavailable)
	}
	var result *bleve.SearchResult
	err = guardIndex("search", func() (searchErr error) {
		result, searchErr = rt.index.SearchInContext(ctx, searchRequest)
		return searchErr
	})
	// The checkpoint is read with the same lock as the query: catch-up applies
	// changes to the index before it advances the checkpoint, so every change
	// after it may be missing from the hits just returned.
	summaries := summaryResolver{m: m, ctx: ctx, access: readAccess, accountID: accountID, checkpoint: rt.state.Checkpoint}
	rt.lastUsed = time.Now()
	rt.mu.Unlock()
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return service.SearchPage{}, err
		}
		_ = m.recoverServingIndex(accountID, rt, indexID, fmt.Errorf("query ready index: %w", err))
		m.ensureBuild(accountID)
		return service.SearchPage{}, fmt.Errorf("%w: index recovery requested", service.ErrSearchUnavailable)
	}
	page := service.SearchPage{Hits: make([]service.SearchHit, 0, len(result.Hits)), Total: result.Total, IndexID: indexID}
	page.Facets.Types = searchFacetValues(result.Facets["types"], nil)
	page.Facets.Folders = searchFacetValues(result.Facets["folders"], func(value string) string {
		return folderByID[value].Name
	})
	for _, match := range result.Hits {
		score := match.Score
		if math.IsNaN(score) || math.IsInf(score, 0) {
			score = 0
		}
		if !withSnippets {
			if hit, ok := summaries.hit(match, folderByID, score); ok {
				page.Hits = append(page.Hits, hit)
				continue
			}
		}
		item, itemErr := m.space.GetItem(ctx, readAccess, match.ID)
		if errors.Is(itemErr, service.ErrForbidden) || errors.Is(itemErr, store.ErrNotFound) {
			page.Total = uint64(len(page.Hits))
			continue
		}
		if itemErr != nil {
			return service.SearchPage{}, itemErr
		}
		folder, ok := folderByID[item.FolderID]
		if !ok {
			page.Total = uint64(len(page.Hits))
			continue
		}
		doc := extract(folder, item, m.settings().MaxExtractedBytes)
		hit := searchHit(item.ID, folder, doc.summary(), score)
		if withSnippets {
			// Joining the document text copies the whole payload; listings
			// without a text query never have snippets.
			hit.Snippets = snippets(snippetText(doc, item.Data), request.Text)
		}
		page.Hits = append(page.Hits, hit)
	}
	if offset+len(result.Hits) < int(result.Total) {
		page.NextCursor = encodeCursor(cursor{IndexID: indexID, Query: hash, Offset: offset + len(result.Hits)})
	}
	return page, nil
}

// awaitIndexed gives a query read-your-writes freshness: when the serving
// index is a few journal records behind the position current at query time,
// for example just after the caller appended or changed a message, it wakes
// the indexer and waits for it to catch up, up to readYourWritesWait. It
// returns at once when the index is current or when a large backlog means
// the indexer could not catch up within the bound; the query then serves
// the index as it stands.
func (m *Manager) awaitIndexed(ctx context.Context, accountID string, rt *runtime) {
	current, err := m.changes.CurrentChangeState(ctx, service.UserAccess(accountID, service.ProtocolSearchIndexer), service.ChangeScope{Object: service.ChangeObjectItem})
	if err != nil {
		return
	}
	target, err := service.ChangeStateSequence(current)
	if err != nil {
		return
	}
	maxLag := uint64(readYourWritesMaxLag * m.settings().BatchSize)
	var timeout <-chan time.Time
	for {
		rt.mu.Lock()
		indexed, err := service.ChangeStateSequence(rt.state.Checkpoint)
		ready := rt.state.State == "ready"
		if rt.advanced == nil {
			rt.advanced = make(chan struct{})
		}
		advanced := rt.advanced
		rt.mu.Unlock()
		if err != nil || !ready || indexed >= target || target-indexed > maxLag {
			return
		}
		if timeout == nil {
			timer := time.NewTimer(readYourWritesWait)
			defer timer.Stop()
			timeout = timer.C
			// The commit notification normally started catch-up already;
			// this covers a mutation made through a space that does not
			// notify.
			m.changesCommitted(accountID, nil)
		}
		select {
		case <-advanced:
		case <-timeout:
			return
		case <-ctx.Done():
			return
		case <-m.ctx.Done():
			return
		}
	}
}

func searchHit(itemID string, folder model.Folder, summary indexSummary, score float64) service.SearchHit {
	return service.SearchHit{
		ItemID: itemID, FolderID: folder.ID, FolderName: folder.Name, Type: folder.Type,
		Name: summary.Name, Title: summary.Title, Sender: summary.Sender, Date: summary.Date, Updated: summary.Updated,
		ContactEmails: append([]string(nil), summary.ContactEmails...), ContactOrg: summary.ContactOrg,
		ContactPhone: summary.ContactPhone, ContactKind: summary.ContactKind,
		ContactMembers: summary.ContactMembers, ContactHasPhoto: summary.ContactHasPhoto,
		ContactCategories: append([]string(nil), summary.ContactGroups...),
		Flags:             append([]string(nil), summary.Flags...),
		Score:             score, Trashed: summary.Trashed, Truncated: summary.Truncated,
	}
}

// summaryResolver serves hits from summaries stored in the index while
// keeping the guarantees of an authorized item read: the caller must hold
// FolderItemsRead on the hit's folder, and an item changed after the serving
// index's checkpoint (edited, moved, trashed, or deleted) is read from the
// folder space instead, as is any document indexed without a summary.
type summaryResolver struct {
	m          *Manager
	ctx        context.Context
	access     service.AccessContext
	accountID  string
	checkpoint string

	pendingLoaded bool
	pendingKnown  bool
	pending       map[string]struct{}
	readable      map[string]bool
}

func (r *summaryResolver) hit(match *blevesearch.DocumentMatch, folders map[string]model.Folder, score float64) (service.SearchHit, bool) {
	encoded, _ := match.Fields["summary"].(string)
	folderID, _ := match.Fields["folder_id"].(string)
	folder, visible := folders[folderID]
	if encoded == "" || !visible || !r.unchanged(match.ID) || !r.folderReadable(folderID) {
		return service.SearchHit{}, false
	}
	var summary indexSummary
	if err := json.Unmarshal([]byte(encoded), &summary); err != nil {
		return service.SearchHit{}, false
	}
	return searchHit(match.ID, folder, summary, score), true
}

// unchanged reports whether itemID has no change after the checkpoint. The
// pending set is loaded once per query; when it cannot be bounded, every hit
// takes the item read path.
func (r *summaryResolver) unchanged(itemID string) bool {
	if !r.pendingLoaded {
		r.pendingLoaded = true
		r.pending, r.pendingKnown = r.m.pendingItemChanges(r.ctx, r.accountID, r.checkpoint)
	}
	if !r.pendingKnown {
		return false
	}
	_, changed := r.pending[itemID]
	return !changed
}

func (r *summaryResolver) folderReadable(folderID string) bool {
	if readable, ok := r.readable[folderID]; ok {
		return readable
	}
	decision, err := r.m.authorizer.Check(r.ctx, authz.Request{
		Actor: r.access.Actor, Subject: r.access.Subject, Mode: r.access.Mode, Action: authz.FolderItemsRead,
		Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folderID},
	})
	readable := err == nil && decision.Allowed
	if r.readable == nil {
		r.readable = make(map[string]bool)
	}
	r.readable[folderID] = readable
	return readable
}

// pendingItemChanges returns the IDs of items changed after checkpoint. known
// is false when the journal cannot answer within one catch-up batch.
func (m *Manager) pendingItemChanges(ctx context.Context, accountID, checkpoint string) (map[string]struct{}, bool) {
	if checkpoint == "" {
		return nil, false
	}
	page, err := m.changes.ListChanges(ctx, service.UserAccess(accountID, service.ProtocolSearchIndexer), service.ChangeScope{Object: service.ChangeObjectItem}, checkpoint, m.settings().BatchSize)
	if err != nil || page.HasMoreChanges {
		return nil, false
	}
	pending := make(map[string]struct{})
	for _, record := range page.Records {
		for _, change := range record.Changes {
			if change.Object == service.ChangeObjectItem {
				pending[change.ID] = struct{}{}
			}
		}
	}
	return pending, true
}

func searchFacetValues(facet *blevesearch.FacetResult, label func(string) string) []service.SearchFacetValue {
	if facet == nil || facet.Terms == nil {
		return []service.SearchFacetValue{}
	}
	terms := facet.Terms.Terms()
	values := make([]service.SearchFacetValue, 0, len(terms))
	for _, term := range terms {
		value := service.SearchFacetValue{Value: term.Term, Count: uint64(term.Count)}
		if label != nil {
			value.Label = label(term.Term)
		}
		values = append(values, value)
	}
	return values
}

func validateSearchQuery(request service.SearchQuery) error {
	if len(request.AccountID) > 320 || len(request.Text) > 16<<10 || len(request.Expression) > 16<<10 || len(request.Cursor) > 4<<10 || len(request.FolderIDs) > 1024 || len(request.Types) > 32 {
		return errors.New("search query exceeds supported limits")
	}
	for _, folderID := range request.FolderIDs {
		if len(folderID) > 1024 {
			return errors.New("search query exceeds supported limits")
		}
	}
	nodes := 0
	var walk func(service.SearchFilter, int) error
	walk = func(filter service.SearchFilter, depth int) error {
		nodes++
		if depth > 16 || nodes > 256 || len(filter.Field) > 128 || len(filter.Value) > 16<<10 || len(filter.From) > 256 || len(filter.To) > 256 {
			return errors.New("search filter exceeds supported limits")
		}
		for _, child := range filter.Children {
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if request.Filter != nil {
		return walk(*request.Filter, 1)
	}
	return nil
}

// ValidateQuery verifies that a backend-neutral query can be expanded and
// compiled without opening an account index. Consumers use it before retaining
// reusable definitions; executing the query still rechecks current RBAC and
// folder visibility through Manager.Search.
func ValidateQuery(request service.SearchQuery) error {
	expanded, err := expandExpression(request)
	if err != nil {
		return err
	}
	if err := validateSearchQuery(expanded); err != nil {
		return err
	}
	_, err = compileQuery(expanded, expanded.FolderIDs)
	return err
}

func (m *Manager) SearchStatus(ctx context.Context, access service.AccessContext, accountID string) (service.SearchIndexStatus, error) {
	accountID = strings.ToLower(strings.TrimSpace(accountID))
	if accountID == "" {
		accountID = strings.ToLower(access.Subject.ID)
	}
	if err := m.requireAccountAction(ctx, access.Actor, accountID, authz.AccountItemsSearch); err != nil {
		return service.SearchIndexStatus{}, err
	}
	rt := m.runtime(accountID)
	m.ensureBuild(accountID)
	rt.mu.Lock()
	state := rt.state
	serving := rt.state
	rebuilding := rt.buildState != nil || (rt.building && serving.State != "ready")
	if rt.buildState != nil {
		state = *rt.buildState
	} else if rebuilding {
		state.State = "building"
		state.UpdatedAt = time.Now().UTC()
	}
	rt.mu.Unlock()
	return service.SearchIndexStatus{
		AccountID: accountID, State: state.State, IndexID: state.IndexID, Checkpoint: state.Checkpoint,
		Documents: state.Documents, IndexBytes: m.indexDiskBytes(accountID, state.IndexID),
		FoldersDone: state.FoldersDone, FoldersTotal: state.FoldersTotal,
		ItemsDone: state.ItemsDone, LastError: state.LastError, UpdatedAt: state.UpdatedAt,
		ActiveGeneration: state.ActiveGeneration, Rebuilding: rebuilding,
		ServingIndexID: serving.IndexID, ServingDocuments: serving.Documents,
		LastRecoveryIndexID: state.LastRecoveryID, LastRecoveryReason: state.LastRecovery,
		LastRecoveryAt: state.LastRecoveryAt,
		BuildStartedAt: state.BuildStartedAt, LastResumedAt: state.LastResumedAt,
		ResumeCount: state.ResumeCount, LastCompletedFolderID: state.LastFolderID,
	}, nil
}

func (m *Manager) RequestSearchRebuild(ctx context.Context, access service.AccessContext, accountID string) error {
	accountID = strings.ToLower(strings.TrimSpace(accountID))
	if accountID == "" {
		accountID = strings.ToLower(access.Subject.ID)
	}
	if err := m.requireAccountAction(ctx, access.Actor, accountID, authz.AccountPermissionsManage); err != nil {
		return err
	}
	rt := m.runtime(accountID)
	rt.mu.Lock()
	rt.forceRebuild = true
	rt.freshBuild = true
	rt.nextAttempt = time.Time{}
	requested := persistedState{Version: mappingVersion, State: "rebuild_requested", UpdatedAt: time.Now().UTC()}
	rt.buildState = &requested
	building := rt.building
	rt.mu.Unlock()
	if !building {
		m.ensureBuild(accountID)
	}
	return nil
}

func (m *Manager) requireAccountAction(ctx context.Context, actor model.PrincipalRef, accountID string, action authz.Action) error {
	decision, err := m.authorizer.Check(ctx, authz.Request{
		Actor: actor, Subject: actor, Action: action,
		Resource: model.ResourceRef{Kind: model.ResourceAccount, ID: accountID},
	})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return fmt.Errorf("%w: %s", service.ErrForbidden, decision.Reason)
	}
	return nil
}

func compileQuery(request service.SearchQuery, folderIDs []string) (blevequery.Query, error) {
	must := []blevequery.Query{terms("folder_id", folderIDs)}
	if !request.IncludeTrash {
		trashed := bleve.NewBoolFieldQuery(false)
		trashed.SetField("trashed")
		must = append(must, trashed)
	}
	if strings.TrimSpace(request.Text) != "" {
		fields := []string{"name", "title", "sender", "recipients", "subject", "headers", "content", "attachment", "attachment_content"}
		queries := make([]blevequery.Query, 0, len(fields))
		for _, field := range fields {
			query := bleve.NewMatchQuery(request.Text)
			query.SetField(field)
			queries = append(queries, query)
		}
		must = append(must, bleve.NewDisjunctionQuery(queries...))
	}
	if request.Filter != nil {
		filter, err := compileFilter(*request.Filter)
		if err != nil {
			return nil, err
		}
		must = append(must, filter)
	}
	return bleve.NewConjunctionQuery(must...), nil
}

func compileFilter(filter service.SearchFilter) (blevequery.Query, error) {
	switch filter.Operator {
	case service.SearchAll, service.SearchAny:
		if len(filter.Children) == 0 {
			return nil, errors.New("compound search filter requires children")
		}
		children := make([]blevequery.Query, 0, len(filter.Children))
		for _, child := range filter.Children {
			compiled, err := compileFilter(child)
			if err != nil {
				return nil, err
			}
			children = append(children, compiled)
		}
		if filter.Operator == service.SearchAll {
			return bleve.NewConjunctionQuery(children...), nil
		}
		return bleve.NewDisjunctionQuery(children...), nil
	case service.SearchNot:
		if len(filter.Children) != 1 {
			return nil, errors.New("not filter requires one child")
		}
		child, err := compileFilter(filter.Children[0])
		if err != nil {
			return nil, err
		}
		result := bleve.NewBooleanQuery()
		result.AddMust(bleve.NewMatchAllQuery())
		result.AddMustNot(child)
		return result, nil
	}
	field, ok := searchFields[strings.ToLower(filter.Field)]
	if !ok {
		return nil, fmt.Errorf("unsupported search field %q", filter.Field)
	}
	switch filter.Operator {
	case service.SearchContains:
		if field == "contact_suggest" {
			return compileContactSuggestion(filter.Value)
		}
		// A field filter such as from:amy@example.net must match every
		// analyzed token, not any of them (which matched all example.net mail).
		query := bleve.NewMatchQuery(filter.Value)
		query.SetField(field)
		query.SetOperator(blevequery.MatchQueryOperatorAnd)
		return query, nil
	case service.SearchEquals:
		if field == "trashed" || field == "has_attachment" {
			value, err := strconv.ParseBool(filter.Value)
			if err != nil {
				return nil, fmt.Errorf("invalid boolean %q", filter.Value)
			}
			query := bleve.NewBoolFieldQuery(value)
			query.SetField(field)
			return query, nil
		}
		value := filter.Value
		if field == "type" || field == "categories" {
			value = strings.ToLower(strings.TrimSpace(value))
		}
		query := bleve.NewTermQuery(value)
		query.SetField(field)
		return query, nil
	case service.SearchPrefix:
		query := bleve.NewPrefixQuery(strings.ToLower(filter.Value))
		query.SetField(field)
		return query, nil
	case service.SearchBefore, service.SearchAfter, service.SearchBetween:
		if field == "size" {
			return compileNumericRange(filter, field)
		}
		var start, end time.Time
		var err error
		if filter.Operator == service.SearchBefore {
			end, err = parseTime(filter.Value)
		} else if filter.Operator == service.SearchAfter {
			start, err = parseTime(filter.Value)
		} else {
			start, err = parseTime(filter.From)
			if err == nil {
				end, err = parseTime(filter.To)
			}
		}
		if err != nil {
			return nil, err
		}
		query := bleve.NewDateRangeQuery(start, end)
		query.SetField(field)
		return query, nil
	default:
		return nil, fmt.Errorf("unsupported search operator %q", filter.Operator)
	}
}

var contactSuggestionTokens = regexp.MustCompile(`[\p{L}\p{N}]+`)

func compileContactSuggestion(value string) (blevequery.Query, error) {
	tokens := contactSuggestionTokens.FindAllString(strings.ToLower(value), -1)
	if len(tokens) == 0 {
		return nil, errors.New("contact suggestion query requires text")
	}
	if len(tokens) > 32 {
		return nil, errors.New("contact suggestion query has too many terms")
	}
	queries := make([]blevequery.Query, 0, len(tokens))
	for _, token := range tokens {
		query := bleve.NewPrefixQuery(token)
		query.SetField("contact_suggest")
		queries = append(queries, query)
	}
	if len(queries) == 1 {
		return queries[0], nil
	}
	return bleve.NewConjunctionQuery(queries...), nil
}

var searchFields = map[string]string{
	"from": "sender", "to": "recipients", "cc": "recipients", "bcc": "recipients",
	"subject": "subject", "body": "content", "content": "content", "header": "headers",
	"name": "name", "filename": "name", "attachment": "attachment", "folder": "folder_id",
	"type": "type", "flag": "flags", "category": "categories", "date": "date", "updated": "updated", "trashed": "trashed",
	"size":              "size",
	"hasattachment":     "has_attachment",
	"attachmentcontent": "attachment_content",
	"contact_suggest":   "contact_suggest",
}

func compileNumericRange(filter service.SearchFilter, field string) (blevequery.Query, error) {
	var minimum, maximum *float64
	parse := func(value string) (*float64, error) {
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid numeric search value %q", value)
		}
		return &parsed, nil
	}
	var err error
	switch filter.Operator {
	case service.SearchBefore:
		maximum, err = parse(filter.Value)
	case service.SearchAfter:
		minimum, err = parse(filter.Value)
	case service.SearchBetween:
		minimum, err = parse(filter.From)
		if err == nil {
			maximum, err = parse(filter.To)
		}
	}
	if err != nil {
		return nil, err
	}
	query := bleve.NewNumericRangeQuery(minimum, maximum)
	query.SetField(field)
	return query, nil
}

func terms(field string, values []string) blevequery.Query {
	queries := make([]blevequery.Query, 0, len(values))
	for _, value := range values {
		query := bleve.NewTermQuery(strings.ToLower(value))
		query.SetField(field)
		queries = append(queries, query)
	}
	if len(queries) == 1 {
		return queries[0]
	}
	return bleve.NewDisjunctionQuery(queries...)
}

func parseTime(value string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed, nil
	}
	parsed, err := time.Parse(time.DateOnly, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid search date %q", value)
	}
	return parsed, nil
}

func normalizeLimit(limit, maximum int) int {
	if limit < 1 {
		return min(50, maximum)
	}
	return min(limit, maximum)
}

func queryHash(request service.SearchQuery) string {
	request.Cursor = ""
	data, _ := json.Marshal(request)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func encodeCursor(value cursor) string {
	data, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeCursor(value string) (cursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return cursor{}, err
	}
	var decoded cursor
	err = json.Unmarshal(data, &decoded)
	return decoded, err
}

func snippets(content, term string) []service.SearchSnippet {
	term = strings.TrimSpace(term)
	if term == "" || content == "" {
		return nil
	}
	// model.IndexFold maps matches back to content itself: an index into a
	// lowered copy is off once lowering changes a rune's byte length.
	position, matchEnd := model.IndexFold(content, term)
	for _, token := range strings.Fields(term) {
		if position >= 0 {
			break
		}
		position, matchEnd = model.IndexFold(content, token)
	}
	if position < 0 {
		return nil
	}
	term = content[position:matchEnd]
	start := max(0, position-90)
	end := min(len(content), position+len(term)+150)
	for start > 0 && !utf8.RuneStart(content[start]) {
		start--
	}
	for end < len(content) && !utf8.RuneStart(content[end]) {
		end++
	}
	text := content[start:end]
	return []service.SearchSnippet{{Field: "content", Text: text, Ranges: [][2]int{{position - start, position - start + len(term)}}}}
}
