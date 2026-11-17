package jmap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// emailSortOptions are the Email/query sort properties (RFC 8621 §4.4.2).
var emailSortOptions = []string{"receivedAt", "sentAt", "size", "from", "to", "subject"}

// emailFilterConditions are the FilterCondition properties Email/query
// understands (RFC 8621 §4.4.1).
var emailFilterConditions = map[string]bool{"inMailbox": true, "inMailboxOtherThan": true, "before": true, "after": true,
	"minSize": true, "maxSize": true, "allInThreadHaveKeyword": true, "someInThreadHaveKeyword": true,
	"noneInThreadHaveKeyword": true, "hasKeyword": true, "notKeyword": true, "hasAttachment": true, "text": true,
	"from": true, "to": true, "cc": true, "bcc": true, "subject": true, "body": true, "header": true}

var threadKeywordConditions = []string{"allInThreadHaveKeyword", "someInThreadHaveKeyword", "noneInThreadHaveKeyword"}

// UnmarshalJSON applies the Comparator default isAscending: true (RFC 8620
// §5.5).
func (c *Comparator) UnmarshalJSON(data []byte) error {
	type plain Comparator
	value := plain{IsAscending: true}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*c = Comparator(value)
	return nil
}

// emailQuery is a validated Email/query: the search filter, thread-level
// keyword conditions applied after it, and the sort.
type emailQuery struct {
	filter        map[string]any
	threadFilters map[string]string
	sort          []Comparator
	collapse      bool
}

func parseEmailQuery(a queryArgs) (emailQuery, *MethodError) {
	q := emailQuery{sort: a.Sort, collapse: a.CollapseThreads, threadFilters: map[string]string{}}
	filter, e := decodeFilter(a.Filter)
	if e != nil {
		return q, e
	}
	if err := validateEmailFilter(filter); err != nil {
		return q, &MethodError{Type: "unsupportedFilter", Description: err.Error()}
	}
	q.filter, e = extractThreadFilters(filter, q.threadFilters)
	if e != nil {
		return q, e
	}
	for _, comparator := range a.Sort {
		if !slices.Contains(emailSortOptions, comparator.Property) {
			return q, &MethodError{Type: "unsupportedSort", Description: "cannot sort by " + comparator.Property}
		}
		if comparator.Collation != "" && comparator.Collation != "i;ascii-casemap" && comparator.Collation != "i;unicode-casemap" {
			return q, &MethodError{Type: "unsupportedSort", Description: "unsupported collation " + comparator.Collation}
		}
	}
	if a.Limit != nil && *a.Limit < 0 {
		return q, &MethodError{Type: "invalidArguments", Description: "limit must not be negative", Properties: []string{"limit"}}
	}
	return q, nil
}

func validateEmailFilter(filter map[string]any) error {
	if filter == nil {
		return nil
	}
	if operator, ok := filter["operator"]; ok {
		name, _ := operator.(string)
		if name != "AND" && name != "OR" && name != "NOT" {
			return fmt.Errorf("unknown filter operator %v", operator)
		}
		conditions, ok := filter["conditions"].([]any)
		if !ok {
			return errors.New("filter operator needs a conditions array")
		}
		for _, condition := range conditions {
			child, ok := condition.(map[string]any)
			if !ok {
				return errors.New("filter conditions must be objects")
			}
			if err := validateEmailFilter(child); err != nil {
				return err
			}
		}
		return nil
	}
	for key, value := range filter {
		if !emailFilterConditions[key] {
			return fmt.Errorf("unsupported filter condition %q", key)
		}
		switch key {
		case "inMailboxOtherThan":
			if _, ok := value.([]any); !ok {
				return fmt.Errorf("%s must be an array of ids", key)
			}
		case "header":
			list, ok := value.([]any)
			if !ok || len(list) == 0 || len(list) > 2 {
				return errors.New("header must be an array of one or two strings")
			}
		case "minSize", "maxSize":
			if _, ok := value.(float64); !ok {
				return fmt.Errorf("%s must be a number", key)
			}
		case "hasAttachment":
			if _, ok := value.(bool); !ok {
				return errors.New("hasAttachment must be a boolean")
			}
		default:
			if _, ok := value.(string); !ok {
				return fmt.Errorf("%s must be a string", key)
			}
		}
	}
	return nil
}

// extractThreadFilters moves the *InThreadHaveKeyword conditions out of a
// top-level condition or AND, where they are applied after the search;
// elsewhere they are unsupported.
func extractThreadFilters(filter map[string]any, out map[string]string) (map[string]any, *MethodError) {
	if filter == nil {
		return nil, nil
	}
	take := func(condition map[string]any) map[string]any {
		rest := map[string]any{}
		for key, value := range condition {
			if slices.Contains(threadKeywordConditions, key) {
				out[key], _ = value.(string)
			} else {
				rest[key] = value
			}
		}
		return rest
	}
	nested := func(value any) bool {
		data, _ := json.Marshal(value)
		for _, key := range threadKeywordConditions {
			if bytes.Contains(data, []byte(`"`+key+`"`)) {
				return true
			}
		}
		return false
	}
	operator, isOperator := filter["operator"].(string)
	if !isOperator {
		return take(filter), nil
	}
	if operator != "AND" {
		if nested(filter) {
			return nil, &MethodError{Type: "unsupportedFilter", Description: "thread keyword conditions are only supported at the top level or in AND"}
		}
		return filter, nil
	}
	conditions, _ := filter["conditions"].([]any)
	kept := make([]any, 0, len(conditions))
	for _, condition := range conditions {
		child, _ := condition.(map[string]any)
		if _, childOperator := child["operator"]; childOperator {
			if nested(child) {
				return nil, &MethodError{Type: "unsupportedFilter", Description: "thread keyword conditions are only supported at the top level or in AND"}
			}
			kept = append(kept, child)
			continue
		}
		kept = append(kept, take(child))
	}
	return map[string]any{"operator": "AND", "conditions": kept}, nil
}

// parseUTCDate parses a Date or UTCDate (RFC 3339).
func parseUTCDate(value string) (time.Time, error) { return time.Parse(time.RFC3339, value) }

func (h *Handler) emailQuery(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a queryArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	q, e := parseEmailQuery(a)
	if e != nil {
		return nil, e
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	state, err := h.journalState(ctx, access, service.ChangeObjectItem)
	if err != nil {
		return nil, serverError(err)
	}
	// The whole result is only needed to resolve an anchor or a negative
	// position, or to post-process threads; otherwise the search stops at
	// the end of the requested window.
	needed := -1
	if a.Anchor == "" && a.Position >= 0 && a.Limit != nil && !q.collapse && len(q.threadFilters) == 0 {
		needed = a.Position + *a.Limit
	}
	ids, total, e := h.emailQueryIDs(ctx, access, a.AccountID, q, needed)
	if e != nil {
		return nil, e
	}
	position, e := queryPosition(ids, total, a)
	if e != nil {
		return nil, e
	}
	result := map[string]any{"accountId": a.AccountID, "queryState": state, "canCalculateChanges": true,
		"position": position, "ids": window(ids, position, a.Limit), "total": total}
	return result, nil
}

// queryPosition resolves position, anchor and anchorOffset (RFC 8620
// §5.5) to the index of the first returned id.
func queryPosition(ids []string, total int, a queryArgs) (int, *MethodError) {
	if a.Anchor != "" {
		index := indexOf(ids, a.Anchor)
		if index < 0 {
			return 0, &MethodError{Type: "anchorNotFound"}
		}
		return min(max(0, index+a.AnchorOffset), len(ids)), nil
	}
	position := a.Position
	if position < 0 {
		position = max(0, total+position)
	}
	return min(position, total), nil
}

// emailQueryIDs returns the ordered query result (up to needed ids when
// needed >= 0) and the total number of results.
func (h *Handler) emailQueryIDs(ctx context.Context, access service.AccessContext, accountID string, q emailQuery, needed int) ([]string, int, *MethodError) {
	var ids []string
	total := -1
	searched := false
	if h.cfg.Search != nil && !headerOnlyFilter(q.filter) {
		var e *MethodError
		ids, total, searched, e = h.emailSearch(ctx, access, accountID, q, needed)
		if e != nil {
			return nil, 0, e
		}
	}
	if !searched {
		var e *MethodError
		ids, e = h.emailQueryLocal(ctx, access, q)
		if e != nil {
			return nil, 0, e
		}
		total = len(ids)
	}
	if q.collapse || len(q.threadFilters) > 0 {
		threads, err := h.mailThreads(ctx, access)
		if err != nil {
			return nil, 0, serverError(err)
		}
		ids = threads.apply(ids, q)
		total = len(ids)
	}
	if ids == nil {
		ids = []string{}
	}
	return ids, max(total, len(ids)), nil
}

// headerOnlyFilter reports whether a filter needs only message metadata
// and stored header fields. Such queries are answered from the folders
// directly, so they see changes the search index has not caught up with.
func headerOnlyFilter(filter map[string]any) bool {
	if filter == nil {
		return true
	}
	if _, ok := filter["operator"]; ok {
		conditions, _ := filter["conditions"].([]any)
		for _, condition := range conditions {
			child, _ := condition.(map[string]any)
			if !headerOnlyFilter(child) {
				return false
			}
		}
		return true
	}
	for key := range filter {
		switch key {
		case "text", "body", "hasAttachment":
			return false
		}
	}
	return true
}

// emailSearch runs the query on the search index. It reports false when
// the index cannot serve the account, so the caller evaluates directly.
func (h *Handler) emailSearch(ctx context.Context, access service.AccessContext, accountID string, q emailQuery, needed int) ([]string, int, bool, *MethodError) {
	var ids []string
	total := -1
	{
		filter, err := jmapSearchFilter(q.filter)
		if err != nil {
			return nil, 0, false, &MethodError{Type: "unsupportedFilter", Description: err.Error()}
		}
		query := service.SearchQuery{AccountID: accountID, Types: []model.FolderType{model.FolderTypeMail}, Filter: filter, Sort: searchSort(q.sort), Limit: 500, OmitSnippets: true}
		for {
			page, searchErr := h.cfg.Search.Search(ctx, access, query)
			if errors.Is(searchErr, service.ErrSearchUnavailable) || errors.Is(searchErr, service.ErrSearchNotIndexed) {
				return nil, 0, false, nil
			}
			if searchErr != nil {
				return nil, 0, false, serverError(searchErr)
			}
			if total < 0 {
				total = int(page.Total)
			}
			for _, hit := range page.Hits {
				ids = append(ids, hit.ItemID)
			}
			if page.NextCursor == "" || needed >= 0 && len(ids) >= needed {
				break
			}
			query.Cursor = page.NextCursor
		}
	}
	return ids, total, true, nil
}

func searchSort(comparators []Comparator) string {
	if len(comparators) == 0 {
		return "date_desc"
	}
	suffix := ""
	if !comparators[0].IsAscending {
		suffix = "_desc"
	}
	switch comparators[0].Property {
	case "subject":
		return "title" + suffix
	case "from":
		return "sender" + suffix
	case "to":
		return "recipients" + suffix
	case "size":
		return "size" + suffix
	}
	if suffix == "" {
		return "date_asc"
	}
	return "date_desc"
}

// headerView builds an Email view from an item's stored header fields,
// reading the content only when the item has none.
func (h *Handler) headerView(ctx context.Context, access service.AccessContext, item model.Item) *emailView {
	if _, ok := storedHeader(item); ok {
		fields := make([]headerField, 0, len(item.Headers))
		for _, name := range sortedKeys(item.Headers) {
			fields = append(fields, headerField{Name: name, Value: " " + item.Headers[name]})
		}
		view := &emailView{item: item, blobID: item.ID, size: item.Size, root: &mimeEntity{partID: "1", header: fields, mediaType: "text/plain", params: map[string]string{}}}
		view.text, view.html, view.attachments = bodyLists(view.root)
		return view
	}
	full, err := h.cfg.Space.GetItem(ctx, access, item.ID)
	if err != nil {
		return nil
	}
	return newEmailView(full, full.ID, full.Data)
}

// emailQueryLocal evaluates the query over the account's messages: without
// a search index, for header-only filters, or while the index is
// unavailable.
func (h *Handler) emailQueryLocal(ctx context.Context, access service.AccessContext, q emailQuery) ([]string, *MethodError) {
	headerOnly := headerOnlyFilter(q.filter)
	query := service.ItemQuery{}
	if headerOnly {
		query = service.ItemQuery{MetadataOnly: true, RequireRead: true}
	}
	items, err := h.listMailItems(ctx, access, query)
	if err != nil {
		return nil, serverError(err)
	}
	type row struct {
		item model.Item
		view *emailView
	}
	rows := make([]row, 0, len(items))
	for _, item := range items {
		var view *emailView
		if headerOnly {
			view = h.headerView(ctx, access, item)
		} else {
			view = newEmailView(item, item.ID, item.Data)
		}
		if view == nil {
			continue
		}
		if evalFilter(q.filter, func(condition map[string]any) bool { return matchesEmail(view, condition) }) {
			rows = append(rows, row{item: item, view: view})
		}
	}
	sortKey := func(r row, property string) string {
		switch property {
		case "size":
			return fmt.Sprintf("%020d", r.item.Size)
		case "subject":
			return strings.ToLower(threadingSubject(fmt.Sprint(r.view.property("subject", emailOptions{}))))
		case "from", "to":
			list, _ := r.view.property(property, emailOptions{}).([]address)
			if len(list) == 0 {
				return ""
			}
			if list[0].Name != nil {
				return strings.ToLower(*list[0].Name)
			}
			return strings.ToLower(list[0].Email)
		case "sentAt":
			value, _ := r.view.property("sentAt", emailOptions{}).(string)
			if t, err := parseUTCDate(value); err == nil {
				return formatUTCDate(t)
			}
			return value
		}
		return formatUTCDate(r.item.InternalDate)
	}
	comparators := q.sort
	if len(comparators) == 0 {
		comparators = []Comparator{{Property: "receivedAt"}}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		for _, comparator := range comparators {
			left, right := sortKey(rows[i], comparator.Property), sortKey(rows[j], comparator.Property)
			if left != right {
				return (left < right) == comparator.IsAscending
			}
		}
		return rows[i].item.ID < rows[j].item.ID
	})
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.item.ID
	}
	return ids, nil
}

func threadingSubject(subject string) string {
	for {
		trimmed := strings.TrimSpace(subject)
		lower := strings.ToLower(trimmed)
		cut := false
		for _, prefix := range []string{"re:", "fwd:", "fw:"} {
			if strings.HasPrefix(lower, prefix) {
				trimmed, cut = trimmed[len(prefix):], true
				break
			}
		}
		subject = trimmed
		if !cut {
			return subject
		}
	}
}

// matchesEmail evaluates one FilterCondition without a search index.
func matchesEmail(v *emailView, f map[string]any) bool {
	text := func(property string) string {
		switch value := v.property(property, emailOptions{}).(type) {
		case string:
			return value
		case []address:
			var parts []string
			for _, a := range value {
				if a.Name != nil {
					parts = append(parts, *a.Name)
				}
				parts = append(parts, a.Email)
			}
			return strings.Join(parts, " ")
		}
		return ""
	}
	body := func() string {
		var parts []string
		for _, value := range v.bodyValues(emailOptions{fetchAll: true}) {
			parts = append(parts, value.Value)
		}
		return strings.Join(parts, " ")
	}
	for key, value := range f {
		needle, _ := value.(string)
		switch key {
		case "subject", "from", "to", "cc", "bcc":
			if !containsFold(text(key), needle) {
				return false
			}
		case "body":
			if !containsFold(body(), needle) {
				return false
			}
		case "text":
			if !containsFold(text("subject")+" "+text("from")+" "+text("to")+" "+text("cc")+" "+body(), needle) {
				return false
			}
		case "inMailbox":
			if v.item.FolderID != needle {
				return false
			}
		case "inMailboxOtherThan":
			for _, id := range value.([]any) {
				if id == v.item.FolderID {
					return false
				}
			}
		case "hasKeyword", "notKeyword":
			if keywords(v.item.Flags)[strings.ToLower(needle)] != (key == "hasKeyword") {
				return false
			}
		case "hasAttachment":
			if v.hasAttachment() != value.(bool) {
				return false
			}
		case "minSize":
			if n, _ := number(value); v.size < n {
				return false
			}
		case "maxSize":
			if n, _ := number(value); v.size >= n {
				return false
			}
		case "before", "after":
			t, err := parseUTCDate(needle)
			if err != nil || (key == "before") != v.item.InternalDate.Before(t) {
				return false
			}
		case "header":
			list := value.([]any)
			name, _ := list[0].(string)
			values := allHeaderValues(v.root.header, name)
			if len(values) == 0 {
				return false
			}
			if len(list) > 1 {
				want, _ := list[1].(string)
				found := false
				for _, raw := range values {
					found = found || containsFold(headerText(raw), want)
				}
				if !found {
					return false
				}
			}
		}
	}
	return true
}

// mailThreadIndex maps the account's messages to their threads.
type mailThreadIndex struct {
	threadOf map[string]string
	members  map[string][]model.Item // oldest first
}

func (h *Handler) mailThreads(ctx context.Context, access service.AccessContext) (mailThreadIndex, error) {
	items, err := h.mailItemMetadata(ctx, access)
	if err != nil {
		return mailThreadIndex{}, err
	}
	index := mailThreadIndex{threadOf: make(map[string]string, len(items)), members: map[string][]model.Item{}}
	for _, item := range items {
		header, ok := storedHeader(item)
		if !ok {
			full, err := h.cfg.Space.GetItem(ctx, access, item.ID)
			if err != nil {
				continue
			}
			m, err := mail.ReadMessage(bytes.NewReader(full.Data))
			if err != nil {
				continue
			}
			header = m.Header
		}
		thread := threadID(header)
		index.threadOf[item.ID] = thread
		index.members[thread] = append(index.members[thread], item)
	}
	for _, members := range index.members {
		sort.SliceStable(members, func(i, j int) bool {
			if !members[i].InternalDate.Equal(members[j].InternalDate) {
				return members[i].InternalDate.Before(members[j].InternalDate)
			}
			return members[i].ID < members[j].ID
		})
	}
	return index, nil
}

// apply filters ids by the thread keyword conditions and, when collapsing,
// keeps only the first id of each thread.
func (t mailThreadIndex) apply(ids []string, q emailQuery) []string {
	out := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		thread, ok := t.threadOf[id]
		if !ok {
			thread = id
		}
		if !t.threadMatches(thread, q.threadFilters) {
			continue
		}
		if q.collapse {
			if seen[thread] {
				continue
			}
			seen[thread] = true
		}
		out = append(out, id)
	}
	return out
}

func (t mailThreadIndex) threadMatches(thread string, filters map[string]string) bool {
	for condition, keyword := range filters {
		keyword = strings.ToLower(keyword)
		count := 0
		members := t.members[thread]
		for _, member := range members {
			if keywords(member.Flags)[keyword] {
				count++
			}
		}
		switch condition {
		case "allInThreadHaveKeyword":
			if count != len(members) || len(members) == 0 {
				return false
			}
		case "someInThreadHaveKeyword":
			if count == 0 {
				return false
			}
		case "noneInThreadHaveKeyword":
			if count != 0 {
				return false
			}
		}
	}
	return true
}

// emailQueryChanges derives query changes from the item journal: every
// email changed since the old state is reported removed and, if it still
// matches, added at its current index. RFC 8620 §5.6 permits these extra
// removals. Collapsed queries cannot follow a destroyed thread exemplar, so
// they report cannotCalculateChanges when messages were destroyed.
func (h *Handler) emailQueryChanges(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a queryChangesArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	q, e := parseEmailQuery(a.queryArgs)
	if e != nil {
		return nil, e
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	folders, err := h.mailFolders(ctx, access)
	if err != nil {
		return nil, serverError(err)
	}
	page, err := h.collectionChanges(ctx, access, folders, service.ChangeObjectItem, a.SinceQueryState, 10_000)
	if err != nil {
		return nil, changesError(err)
	}
	if page.HasMoreChanges {
		return nil, &MethodError{Type: "cannotCalculateChanges", Description: "too many changes since the query state"}
	}
	created, updated, destroyed := projectJMAPChanges(page.Records, false)
	if (q.collapse || len(q.threadFilters) > 0) && len(destroyed) > 0 {
		return nil, &MethodError{Type: "cannotCalculateChanges", Description: "thread results changed by destroyed messages"}
	}
	ids, total, e := h.emailQueryIDs(ctx, access, a.AccountID, q, -1)
	if e != nil {
		return nil, e
	}
	touched := idSet(append(append([]string{}, created...), updated...))
	if q.collapse || len(q.threadFilters) > 0 {
		// A change anywhere in a thread can change which of its messages
		// represents it, so every current member of a touched thread moves.
		threads, err := h.mailThreads(ctx, access)
		if err != nil {
			return nil, serverError(err)
		}
		for id := range idSet(append(append([]string{}, created...), updated...)) {
			for _, member := range threads.members[threads.threadOf[id]] {
				touched[member.ID] = true
			}
		}
	}
	removed := append([]string{}, destroyed...)
	for id := range touched {
		removed = append(removed, id)
	}
	sort.Strings(removed)
	added := []any{}
	for index, id := range ids {
		if touched[id] {
			added = append(added, map[string]any{"id": id, "index": index})
		}
	}
	if a.MaxChanges != nil && *a.MaxChanges > 0 && len(removed)+len(added) > *a.MaxChanges {
		return nil, &MethodError{Type: "tooManyChanges"}
	}
	return map[string]any{"accountId": a.AccountID, "oldQueryState": a.SinceQueryState, "newQueryState": page.NewState,
		"removed": removed, "added": added, "total": total}, nil
}

// threadGet lists each requested thread's emails oldest first (RFC 8621
// §3).
func (h *Handler) threadGet(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a getArgs
	if e := decodeGetArgs(raw, &a, func() []string { return a.IDs }); e != nil {
		return nil, e
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	threads, err := h.mailThreads(ctx, access)
	if err != nil {
		return nil, serverError(err)
	}
	ids := a.IDs
	if ids == nil {
		ids = make([]string, 0, len(threads.members))
		for id := range threads.members {
			ids = append(ids, id)
		}
		sort.Strings(ids)
	}
	list := []any{}
	found := map[string]bool{}
	for _, id := range ids {
		members, ok := threads.members[id]
		if !ok || found[id] {
			continue
		}
		found[id] = true
		emailIDs := make([]string, len(members))
		for i, member := range members {
			emailIDs[i] = member.ID
		}
		list = append(list, map[string]any{"id": id, "emailIds": emailIDs})
	}
	state, err := h.journalState(ctx, access, service.ChangeObjectItem)
	if err != nil {
		return nil, serverError(err)
	}
	return map[string]any{"accountId": a.AccountID, "state": state, "list": list, "notFound": missing(a.IDs, found)}, nil
}
