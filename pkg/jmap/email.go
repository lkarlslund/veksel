package jmap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/mail"
	"net/textproto"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/threading"
)

func (h *Handler) emailGet(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a struct {
		getArgs
		emailFetchArgs
	}
	if e := decodeGetArgs(raw, &a, func() []string { return a.IDs }); e != nil {
		return nil, e
	}
	opts, e := a.options(a.Properties, defaultEmailProperties)
	if e != nil {
		return nil, e
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	items, err := h.mailItemsByID(ctx, access, a.IDs)
	if err != nil {
		return nil, serverError(err)
	}
	found := map[string]bool{}
	list := make([]map[string]any, 0, len(items))
	for _, item := range items {
		found[item.ID] = true
		list = append(list, newEmailView(item, item.ID, item.Data).object(opts))
	}
	state, err := h.journalState(ctx, access, service.ChangeObjectItem)
	if err != nil {
		return nil, serverError(err)
	}
	return map[string]any{"accountId": a.AccountID, "state": state, "list": list, "notFound": missing(a.IDs, found)}, nil
}

// storedHeader returns item's stored header map as a mail.Header. It reports
// false when the map is not the message's parsed header block, as for items
// created from a subject only; those must be read from the content.
func storedHeader(item model.Item) (mail.Header, bool) {
	header := make(mail.Header, len(item.Headers))
	for name, value := range item.Headers {
		key := textproto.CanonicalMIMEHeaderKey(name)
		header[key] = append(header[key], value)
	}
	for _, name := range []string{"Message-Id", "From", "Date"} {
		if _, ok := header[name]; ok {
			return header, true
		}
	}
	return nil, false
}

// threadID derives a stable Thread id from the conversation root shared by
// every message of a well-formed thread (see threading.RootKey).
func threadID(h mail.Header) string {
	return threading.ID(threading.Message{ID: threading.CanonicalID(h.Get("Message-Id")), Parents: threading.Parents(h.Get("References"), h.Get("In-Reply-To")), Subject: model.DecodeHeaderValue(h.Get("Subject"))})
}

// keywords maps stored flags to JMAP keywords, which are case-insensitive
// and reported in lower case (RFC 8621 §4.1.1).
func keywords(flags []string) map[string]bool {
	m := map[string]bool{}
	for _, f := range flags {
		if strings.HasPrefix(f, "\\") && keywordForFlag(f) == "" {
			continue
		}
		m[keywordOf(f)] = true
	}
	return m
}
func splitHeaderList(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
func trimPreview(v string) string {
	v = strings.Join(strings.Fields(v), " ")
	r := []rune(v)
	if len(r) > 256 {
		return string(r[:256])
	}
	return v
}

func jmapSearchFilter(filter map[string]any) (*service.SearchFilter, error) {
	if len(filter) == 0 {
		return nil, nil
	}
	if operator, _ := filter["operator"].(string); operator != "" {
		rawChildren, _ := filter["conditions"].([]any)
		children := make([]service.SearchFilter, 0, len(rawChildren))
		for _, rawChild := range rawChildren {
			childMap, ok := rawChild.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid JMAP filter condition")
			}
			child, err := jmapSearchFilter(childMap)
			if err != nil {
				return nil, err
			}
			if child != nil {
				children = append(children, *child)
			}
		}
		if len(children) == 0 {
			return nil, nil
		}
		switch strings.ToUpper(operator) {
		case "AND":
			return &service.SearchFilter{Operator: service.SearchAll, Children: children}, nil
		case "OR":
			return &service.SearchFilter{Operator: service.SearchAny, Children: children}, nil
		case "NOT":
			// NOT matches when none of its conditions do (RFC 8620 §5.5).
			return &service.SearchFilter{Operator: service.SearchNot, Children: []service.SearchFilter{{Operator: service.SearchAny, Children: children}}}, nil
		default:
			return nil, fmt.Errorf("unsupported JMAP filter operator %q", operator)
		}
	}
	children := make([]service.SearchFilter, 0, len(filter))
	addContains := func(field, key string) {
		if value, _ := filter[key].(string); value != "" {
			children = append(children, service.SearchFilter{Operator: service.SearchContains, Field: field, Value: value})
		}
	}
	addContains("subject", "subject")
	addContains("body", "body")
	addContains("from", "from")
	addContains("to", "to")
	addContains("to", "cc")
	addContains("to", "bcc")
	if value, _ := filter["text"].(string); value != "" {
		children = append(children, service.SearchFilter{Operator: service.SearchAny, Children: []service.SearchFilter{
			{Operator: service.SearchContains, Field: "subject", Value: value},
			{Operator: service.SearchContains, Field: "from", Value: value},
			{Operator: service.SearchContains, Field: "to", Value: value},
			{Operator: service.SearchContains, Field: "header", Value: value},
			{Operator: service.SearchContains, Field: "body", Value: value},
		}})
	}
	for key, operator := range map[string]service.SearchOperator{"before": service.SearchBefore, "after": service.SearchAfter} {
		if value, _ := filter[key].(string); value != "" {
			children = append(children, service.SearchFilter{Operator: operator, Field: "date", Value: value})
		}
	}
	if value, _ := filter["inMailbox"].(string); value != "" {
		children = append(children, service.SearchFilter{Operator: service.SearchEquals, Field: "folder", Value: value})
	}
	if values, ok := filter["inMailboxOtherThan"].([]any); ok && len(values) > 0 {
		excluded := make([]service.SearchFilter, 0, len(values))
		for _, raw := range values {
			if value, ok := raw.(string); ok && value != "" {
				excluded = append(excluded, service.SearchFilter{Operator: service.SearchEquals, Field: "folder", Value: value})
			}
		}
		if len(excluded) > 0 {
			children = append(children, service.SearchFilter{Operator: service.SearchNot, Children: []service.SearchFilter{{Operator: service.SearchAny, Children: excluded}}})
		}
	}
	if value, _ := filter["hasKeyword"].(string); value != "" {
		children = append(children, service.SearchFilter{Operator: service.SearchEquals, Field: "flag", Value: keywordFlag(value)})
	}
	if value, _ := filter["notKeyword"].(string); value != "" {
		children = append(children, service.SearchFilter{Operator: service.SearchNot, Children: []service.SearchFilter{{Operator: service.SearchEquals, Field: "flag", Value: keywordFlag(value)}}})
	}
	if value, ok := filter["hasAttachment"].(bool); ok {
		children = append(children, service.SearchFilter{Operator: service.SearchEquals, Field: "hasAttachment", Value: fmt.Sprint(value)})
	}
	if header, ok := filter["header"].([]any); ok && len(header) > 0 {
		for _, raw := range header[:min(len(header), 2)] {
			if value, ok := raw.(string); ok && value != "" {
				children = append(children, service.SearchFilter{Operator: service.SearchContains, Field: "header", Value: value})
			}
		}
	}
	if value, ok := number(filter["minSize"]); ok {
		children = append(children, service.SearchFilter{Operator: service.SearchAfter, Field: "size", Value: fmt.Sprint(value)})
	}
	if value, ok := number(filter["maxSize"]); ok {
		children = append(children, service.SearchFilter{Operator: service.SearchBefore, Field: "size", Value: fmt.Sprint(value)})
	}
	if len(children) == 0 {
		return nil, nil
	}
	return &service.SearchFilter{Operator: service.SearchAll, Children: children}, nil
}

func keywordFlag(keyword string) string {
	switch strings.ToLower(keyword) {
	case "$seen":
		return model.FlagSeen
	case "$flagged":
		return model.FlagFlagged
	case "$answered":
		return model.FlagAnswered
	case "$draft":
		return model.FlagDraft
	default:
		return keyword
	}
}
func number(v any) (int64, bool) { n, ok := v.(float64); return int64(n), ok }
