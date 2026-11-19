package ews

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// FindItem filters, sorts and pages in this order. A restriction, query
// string or sort field that cannot be evaluated fails the request: a client
// must never read an unfiltered listing as the answer to a filtered one.
var (
	errInvalidRestriction = errors.New("invalid restriction")
	errUnsupportedPath    = errors.New("unsupported property path for query")
)

// queryFieldKind says how a property's values compare.
type queryFieldKind int

const (
	textField queryFieldKind = iota
	timeField
	intField
	boolField
	mailboxField // Mailbox elements: matched by name and address
	listField    // String elements
)

// queryField maps a FieldURI to the elements FindItem renders for it; the
// first one present wins.
type queryField struct {
	elements []string
	kind     queryFieldKind
}

var queryFields = map[string]queryField{
	"item:Subject":              {[]string{"Subject"}, textField},
	"item:ItemClass":            {[]string{"ItemClass"}, textField},
	"item:DateTimeReceived":     {[]string{"DateTimeReceived"}, timeField},
	"item:DateTimeSent":         {[]string{"DateTimeSent", "DateTimeReceived"}, timeField},
	"item:DateTimeCreated":      {[]string{"DateTimeCreated", "DateTimeReceived"}, timeField},
	"item:LastModifiedTime":     {[]string{"LastModifiedTime", "DateTimeCreated", "DateTimeReceived"}, timeField},
	"item:Size":                 {[]string{"Size"}, intField},
	"item:Importance":           {[]string{"Importance"}, textField},
	"item:HasAttachments":       {[]string{"HasAttachments"}, boolField},
	"item:Categories":           {[]string{"Categories"}, listField},
	"message:IsRead":            {[]string{"IsRead"}, boolField},
	"message:From":              {[]string{"From"}, mailboxField},
	"message:Sender":            {[]string{"Sender", "From"}, mailboxField},
	"message:ToRecipients":      {[]string{"ToRecipients"}, mailboxField},
	"message:CcRecipients":      {[]string{"CcRecipients"}, mailboxField},
	"message:InternetMessageId": {[]string{"InternetMessageId"}, textField},
	"calendar:Start":            {[]string{"Start"}, timeField},
	"calendar:End":              {[]string{"End"}, timeField},
	"calendar:IsAllDayEvent":    {[]string{"IsAllDayEvent"}, boolField},
	"calendar:Location":         {[]string{"Location"}, textField},
	"calendar:Organizer":        {[]string{"Organizer"}, mailboxField},
	"task:DueDate":              {[]string{"DueDate"}, timeField},
	"task:StartDate":            {[]string{"StartDate"}, timeField},
	"task:Status":               {[]string{"Status"}, textField},
	"contacts:DisplayName":      {[]string{"DisplayName"}, textField},
	"contacts:CompanyName":      {[]string{"CompanyName"}, textField},
}

// itemFacts are the properties a restriction, query string or sort order
// reads. They come from the item as FindItem renders it, so a filter always
// agrees with the values the client is shown.
type itemFacts struct {
	item     model.Item
	zone     *time.Location
	rendered *node
	text     *string
}

func (f *itemFacts) properties() *node {
	if f.rendered == nil {
		f.rendered = &node{}
		document := `<r xmlns:t="` + typeNS + `">` + renderItem(f.item, itemShape{zone: f.zone}) + `</r>`
		if parsed, err := decodeXML(strings.NewReader(document)); err == nil && len(parsed.Children) > 0 {
			f.rendered = parsed.Children[0]
		}
	}
	return f.rendered
}

// values returns a property's values; nil when the item has none.
func (f *itemFacts) values(field queryField) []string {
	if value, ok := f.storedValue(field.elements[0]); ok {
		return []string{value}
	}
	properties := f.properties()
	for _, element := range field.elements {
		found := properties.child(element)
		if found == nil {
			continue
		}
		switch field.kind {
		case mailboxField:
			var out []string
			found.walk(func(n *node) {
				if n.Name.Local == "Name" || n.Name.Local == "EmailAddress" {
					if value := strings.TrimSpace(n.Text); value != "" {
						out = append(out, value)
					}
				}
			})
			return out
		case listField:
			var out []string
			for _, item := range found.ChildrenNamed("String") {
				out = append(out, strings.TrimSpace(item.Text))
			}
			return out
		default:
			return []string{strings.TrimSpace(found.Text)}
		}
	}
	return nil
}

// storedValue reads the message properties that come from the stored item
// rather than its MIME content, so a date or flag filter over a large
// folder does not parse every message.
func (f *itemFacts) storedValue(element string) (string, bool) {
	if f.rendered != nil || kindOf(f.item.Data) != kindMessage {
		return "", false
	}
	switch element {
	case "DateTimeReceived":
		return messageReceived(f.item), true
	case "Size":
		return strconv.FormatInt(f.item.Size, 10), true
	case "IsRead":
		return strconv.FormatBool(hasFlag(f.item.Flags, model.FlagSeen)), true
	case "ItemClass":
		return "IPM.Note", true
	}
	return "", false
}

// body is the searchable text of the item: the message text, or the
// iCalendar or vCard source of a typed item.
func (f *itemFacts) body() string {
	if f.text == nil {
		text := ""
		if kindOf(f.item.Data) == kindMessage {
			if projection, err := service.ProjectMIME(f.item.Data); err == nil {
				text = projection.Text
				if text == "" && projection.HTML != "" {
					text = service.HTMLToText(projection.HTML)
				}
				for _, attachment := range projection.Attachments {
					text += "\n" + attachment.Name
				}
			}
		} else {
			text = string(f.item.Data)
		}
		f.text = &text
	}
	return *f.text
}

type predicate func(*itemFacts) bool

func lookupField(path *node) (queryField, string, error) {
	if path == nil {
		return queryField{}, "", fmt.Errorf("%w: a property path is required", errInvalidRestriction)
	}
	if path.Name.Local != "FieldURI" {
		return queryField{}, "", fmt.Errorf("%w: %s", errUnsupportedPath, path.Name.Local)
	}
	uri := path.attr("FieldURI")
	field, ok := queryFields[uri]
	if !ok {
		return queryField{}, "", fmt.Errorf("%w: %s", errUnsupportedPath, uri)
	}
	return field, uri, nil
}

func pathChild(n *node) *node {
	for _, child := range n.Children {
		switch child.Name.Local {
		case "FieldURI", "IndexedFieldURI", "ExtendedFieldURI", "Path":
			return child
		}
	}
	return nil
}

// compileRestriction compiles an EWS Restriction element.
func compileRestriction(restriction *node, zone *time.Location) (predicate, error) {
	if len(restriction.Children) != 1 {
		return nil, fmt.Errorf("%w: a restriction holds exactly one search expression", errInvalidRestriction)
	}
	return compileExpression(restriction.Children[0], zone)
}

func compileExpression(n *node, zone *time.Location) (predicate, error) {
	switch n.Name.Local {
	case "And", "Or":
		if len(n.Children) == 0 {
			return nil, fmt.Errorf("%w: %s needs search expressions", errInvalidRestriction, n.Name.Local)
		}
		parts := make([]predicate, 0, len(n.Children))
		for _, child := range n.Children {
			part, err := compileExpression(child, zone)
			if err != nil {
				return nil, err
			}
			parts = append(parts, part)
		}
		if n.Name.Local == "And" {
			return allOf(parts), nil
		}
		return anyOf(parts), nil
	case "Not":
		if len(n.Children) != 1 {
			return nil, fmt.Errorf("%w: Not takes one search expression", errInvalidRestriction)
		}
		inner, err := compileExpression(n.Children[0], zone)
		if err != nil {
			return nil, err
		}
		return func(f *itemFacts) bool { return !inner(f) }, nil
	case "Exists":
		field, _, err := lookupField(pathChild(n))
		if err != nil {
			return nil, err
		}
		return func(f *itemFacts) bool { return len(f.values(field)) > 0 }, nil
	case "IsEqualTo", "IsNotEqualTo", "IsGreaterThan", "IsGreaterThanOrEqualTo", "IsLessThan", "IsLessThanOrEqualTo":
		field, uri, err := lookupField(pathChild(n))
		if err != nil {
			return nil, err
		}
		operand := n.child("FieldURIOrConstant")
		constant := operand.child("Constant")
		if constant == nil {
			return nil, fmt.Errorf("%w: %s compares %s with a constant only", errInvalidRestriction, n.Name.Local, uri)
		}
		test, err := comparison(n.Name.Local)
		if err != nil {
			return nil, err
		}
		compare, err := compileConstant(field, uri, constant.attr("Value"), zone)
		if err != nil {
			return nil, err
		}
		if n.Name.Local == "IsNotEqualTo" {
			return func(f *itemFacts) bool { return !matchAny(f.values(field), compare, isZero) }, nil
		}
		return func(f *itemFacts) bool { return matchAny(f.values(field), compare, test) }, nil
	case "Contains":
		field, uri, err := lookupField(pathChild(n))
		if err != nil {
			return nil, err
		}
		if field.kind != textField && field.kind != mailboxField && field.kind != listField {
			return nil, fmt.Errorf("%w: Contains applies to text, not %s", errInvalidRestriction, uri)
		}
		constant := n.child("Constant")
		if constant == nil {
			return nil, fmt.Errorf("%w: Contains needs a Constant", errInvalidRestriction)
		}
		contains, err := containment(n.attr("ContainmentMode"), n.attr("ContainmentComparison"), constant.attr("Value"))
		if err != nil {
			return nil, err
		}
		return func(f *itemFacts) bool { return slices.ContainsFunc(f.values(field), contains) }, nil
	default:
		return nil, fmt.Errorf("%w: %s is not supported", errInvalidRestriction, n.Name.Local)
	}
}

func allOf(parts []predicate) predicate {
	return func(f *itemFacts) bool {
		for _, part := range parts {
			if !part(f) {
				return false
			}
		}
		return true
	}
}

func anyOf(parts []predicate) predicate {
	return func(f *itemFacts) bool {
		for _, part := range parts {
			if part(f) {
				return true
			}
		}
		return false
	}
}

func isZero(c int) bool { return c == 0 }

func comparison(operator string) (func(int) bool, error) {
	switch operator {
	case "IsEqualTo", "IsNotEqualTo":
		return isZero, nil
	case "IsGreaterThan":
		return func(c int) bool { return c > 0 }, nil
	case "IsGreaterThanOrEqualTo":
		return func(c int) bool { return c >= 0 }, nil
	case "IsLessThan":
		return func(c int) bool { return c < 0 }, nil
	case "IsLessThanOrEqualTo":
		return func(c int) bool { return c <= 0 }, nil
	}
	return nil, fmt.Errorf("%w: %s", errInvalidRestriction, operator)
}

// matchAny reports whether any value compares as test wants; a value
// that cannot be read does not match.
func matchAny(values []string, compare func(string) (int, bool), test func(int) bool) bool {
	for _, value := range values {
		if c, ok := compare(value); ok && test(c) {
			return true
		}
	}
	return false
}

// compileConstant returns a function comparing a property value with the
// constant: negative when the value sorts before it.
func compileConstant(field queryField, uri, constant string, zone *time.Location) (func(string) (int, bool), error) {
	switch field.kind {
	case timeField:
		at, err := parseQueryTime(constant, zone)
		if err != nil {
			return nil, fmt.Errorf("%w: %s needs a date and time: %v", errInvalidRestriction, uri, err)
		}
		return func(value string) (int, bool) {
			parsed, err := time.Parse(time.RFC3339, value)
			return parsed.Compare(at), err == nil
		}, nil
	case intField:
		want, err := strconv.ParseInt(constant, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: %s needs a number", errInvalidRestriction, uri)
		}
		return func(value string) (int, bool) {
			parsed, err := strconv.ParseInt(value, 10, 64)
			return cmp.Compare(parsed, want), err == nil
		}, nil
	case boolField:
		want, err := strconv.ParseBool(constant)
		if err != nil {
			return nil, fmt.Errorf("%w: %s needs true or false", errInvalidRestriction, uri)
		}
		return func(value string) (int, bool) {
			parsed, err := strconv.ParseBool(value)
			return compareBool(parsed, want), err == nil
		}, nil
	default:
		want := strings.ToLower(constant)
		return func(value string) (int, bool) { return strings.Compare(strings.ToLower(value), want), true }, nil
	}
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case b:
		return -1
	}
	return 1
}

// parseQueryTime reads an RFC 3339 timestamp, or a date taken as midnight
// in the mailbox's zone.
func parseQueryTime(value string, zone *time.Location) (time.Time, error) {
	if at, err := time.Parse(time.RFC3339, value); err == nil {
		return at, nil
	}
	if zone == nil {
		zone = time.UTC
	}
	if day, err := time.ParseInLocation(time.DateOnly, value, zone); err == nil {
		return day, nil
	}
	return time.ParseInLocation("2006-01-02T15:04:05", value, zone)
}

func containment(mode, comparison, constant string) (func(string) bool, error) {
	fold := strings.Contains(comparison, "IgnoreCase") || strings.HasPrefix(comparison, "Loose")
	norm := func(value string) string {
		if fold {
			return strings.ToLower(value)
		}
		return value
	}
	want := norm(constant)
	switch mode {
	case "", "FullString":
		return func(value string) bool { return norm(value) == want }, nil
	case "Prefixed":
		return func(value string) bool { return strings.HasPrefix(norm(value), want) }, nil
	case "Substring":
		return func(value string) bool { return strings.Contains(norm(value), want) }, nil
	case "PrefixOnWords", "ExactPhrase":
		return func(value string) bool { return containsAtWord(norm(value), want) }, nil
	}
	return nil, fmt.Errorf("%w: ContainmentMode %q", errInvalidRestriction, mode)
}

// containsAtWord reports whether want occurs in value starting at a word.
func containsAtWord(value, want string) bool {
	for offset := 0; ; {
		i := strings.Index(value[offset:], want)
		if i < 0 {
			return false
		}
		at := offset + i
		if at == 0 || !isWordRune(rune(value[at-1])) {
			return true
		}
		offset = at + 1
	}
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// sortOrder compiles a SortOrder element into a comparison of two items.
func compileSortOrder(order *node) (func(a, b *itemFacts) int, error) {
	type key struct {
		field      queryField
		descending bool
	}
	var keys []key
	for _, fieldOrder := range order.ChildrenNamed("FieldOrder") {
		field, uri, err := lookupField(pathChild(fieldOrder))
		if err != nil {
			return nil, err
		}
		if field.kind == listField {
			return nil, fmt.Errorf("%w: cannot sort by %s", errUnsupportedPath, uri)
		}
		descending := false
		switch fieldOrder.attr("Order") {
		case "", "Ascending":
		case "Descending":
			descending = true
		default:
			return nil, fmt.Errorf("%w: sort order %q", errInvalidRestriction, fieldOrder.attr("Order"))
		}
		keys = append(keys, key{field, descending})
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: SortOrder needs a FieldOrder", errInvalidRestriction)
	}
	return func(a, b *itemFacts) int {
		for _, k := range keys {
			c := compareValues(k.field.kind, a.values(k.field), b.values(k.field))
			if k.descending {
				c = -c
			}
			if c != 0 {
				return c
			}
		}
		return 0
	}, nil
}

// compareValues orders by the first value; an item without one sorts first.
func compareValues(kind queryFieldKind, a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return -1
	case len(b) == 0:
		return 1
	}
	switch kind {
	case timeField:
		x, _ := time.Parse(time.RFC3339, a[0])
		y, _ := time.Parse(time.RFC3339, b[0])
		return x.Compare(y)
	case intField:
		x, _ := strconv.ParseInt(a[0], 10, 64)
		y, _ := strconv.ParseInt(b[0], 10, 64)
		return cmp.Compare(x, y)
	case boolField:
		x, _ := strconv.ParseBool(a[0])
		y, _ := strconv.ParseBool(b[0])
		return compareBool(x, y)
	}
	return strings.Compare(strings.ToLower(a[0]), strings.ToLower(b[0]))
}

// findItemQuery is the filter, order and page of one FindItem request.
type findItemQuery struct {
	filter predicate
	order  func(a, b *itemFacts) int
	// page picks [start, end) of the matching items and the RootFolder
	// attributes that tell the client where the next page starts.
	page func(total int) (start, end int, paging string)
}

func parseFindItemQuery(op *node, zone *time.Location) (findItemQuery, error) {
	var query findItemQuery
	var filters []predicate
	if restriction := op.child("Restriction"); restriction != nil {
		filter, err := compileRestriction(restriction, zone)
		if err != nil {
			return query, err
		}
		filters = append(filters, filter)
	}
	if queryString := op.child("QueryString"); queryString != nil {
		if text := strings.TrimSpace(queryString.Text); text != "" {
			filter, err := compileAQS(text, zone)
			if err != nil {
				return query, err
			}
			filters = append(filters, filter)
		}
	}
	if len(filters) > 0 {
		query.filter = allOf(filters)
	}
	if order := op.child("SortOrder"); order != nil {
		compare, err := compileSortOrder(order)
		if err != nil {
			return query, err
		}
		query.order = compare
	}
	if op.child("GroupBy") != nil || op.child("DistinguishedGroupBy") != nil {
		return query, fmt.Errorf("%w: grouped FindItem views are not supported", errInvalidRestriction)
	}
	page, err := parsePageView(op)
	if err != nil {
		return query, err
	}
	query.page = page
	return query, nil
}

func parsePageView(op *node) (func(total int) (int, int, string), error) {
	if view := op.child("IndexedPageItemView"); view != nil {
		offset, err := viewNumber(view, "Offset", 0)
		if err != nil {
			return nil, err
		}
		limit, err := viewNumber(view, "MaxEntriesReturned", -1)
		if err != nil {
			return nil, err
		}
		fromEnd := false
		switch view.attr("BasePoint") {
		case "", "Beginning":
		case "End":
			fromEnd = true
		default:
			return nil, fmt.Errorf("%w: BasePoint %q", errInvalidRestriction, view.attr("BasePoint"))
		}
		return func(total int) (int, int, string) {
			if fromEnd {
				// Offset counts back from the last item.
				end := max(total-offset, 0)
				start := 0
				if limit >= 0 {
					start = max(end-limit, 0)
				}
				return start, end, fmt.Sprintf(`IndexedPagingOffset="%d" IncludesLastItemInRange="%t"`, offset+end-start, start == 0)
			}
			start, end := min(offset, total), total
			if limit >= 0 {
				end = min(start+limit, total)
			}
			return start, end, fmt.Sprintf(`IndexedPagingOffset="%d" IncludesLastItemInRange="%t"`, end, end >= total)
		}, nil
	}
	if view := op.child("FractionalPageItemView"); view != nil {
		numerator, err := viewNumber(view, "Numerator", 0)
		if err != nil {
			return nil, err
		}
		denominator, err := viewNumber(view, "Denominator", 1)
		if err != nil || denominator == 0 || numerator > denominator {
			return nil, fmt.Errorf("%w: FractionalPageItemView needs 0 <= Numerator <= Denominator", errInvalidRestriction)
		}
		limit, err := viewNumber(view, "MaxEntriesReturned", -1)
		if err != nil {
			return nil, err
		}
		return func(total int) (int, int, string) {
			start := total * numerator / denominator
			end := total
			if limit >= 0 {
				end = min(start+limit, total)
			}
			return start, end, fmt.Sprintf(`NumeratorOffset="%d" AbsoluteDenominator="%d" IncludesLastItemInRange="%t"`, end, total, end >= total)
		}, nil
	}
	if op.child("ContactsView") != nil {
		return nil, fmt.Errorf("%w: ContactsView is not supported; use a restriction", errInvalidRestriction)
	}
	return func(total int) (int, int, string) {
		return 0, total, fmt.Sprintf(`IndexedPagingOffset="%d" IncludesLastItemInRange="true"`, total)
	}, nil
}

func viewNumber(view *node, name string, fallback int) (int, error) {
	value := view.attr(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%w: %s must be a non-negative number", errInvalidRestriction, name)
	}
	return parsed, nil
}

// apply filters, sorts and pages items. It returns the page, the number
// of matching items, and the RootFolder paging attributes.
func (q findItemQuery) apply(items []model.Item, zone *time.Location) (page []model.Item, total int, paging string) {
	if q.filter == nil && q.order == nil {
		total = len(items)
		start, end, paging := q.page(total)
		return items[start:end], total, paging
	}
	facts := make([]*itemFacts, 0, len(items))
	for _, item := range items {
		f := &itemFacts{item: item, zone: zone}
		if q.filter == nil || q.filter(f) {
			facts = append(facts, f)
		}
	}
	if q.order != nil {
		slices.SortStableFunc(facts, q.order)
	}
	total = len(facts)
	start, end, paging := q.page(total)
	page = make([]model.Item, 0, end-start)
	for _, f := range facts[start:end] {
		page = append(page, f.item)
	}
	return page, total, paging
}
