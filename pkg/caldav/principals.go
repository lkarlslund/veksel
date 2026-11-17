package caldav

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// principalPropertySearch is a DAV:principal-property-search REPORT
// (RFC 3744 §9.4), which Apple Calendar sends to the
// principal-collection-set to look up attendees and the current user.
type principalPropertySearch struct {
	XMLName xml.Name `xml:"DAV: principal-property-search"`
	Test    string   `xml:"test,attr"`
	Search  []struct {
		Prop  prop   `xml:"DAV: prop"`
		Match string `xml:"DAV: match"`
	} `xml:"DAV: property-search"`
	Prop *prop `xml:"DAV: prop"`
}

// handlePrincipalReport answers the principal reports Apple Calendar and
// python caldav send to /dav/ or a principal; they were refused with 400 or
// 404. principal-property-search matches only the actor's own principal, so
// no account list is disclosed; principal-search-property-set names the
// searchable properties.
func (h *Handler) handlePrincipalReport(w http.ResponseWriter, r *http.Request) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "cannot read body")
		return true
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	switch reportRoot(body) {
	case xml.Name{Space: NSDAV, Local: "principal-search-property-set"}:
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		fmt.Fprint(w, xml.Header+`<d:principal-search-property-set xmlns:d="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">`+
			`<d:principal-search-property><d:prop><d:displayname/></d:prop><d:description xml:lang="en">Display name</d:description></d:principal-search-property>`+
			`<d:principal-search-property><d:prop><C:calendar-user-address-set/></d:prop><d:description xml:lang="en">Calendar user address</d:description></d:principal-search-property>`+
			`</d:principal-search-property-set>`)
		return true
	case xml.Name{Space: NSDAV, Local: "principal-property-search"}:
	default:
		return false
	}
	var search principalPropertySearch
	if err := xml.Unmarshal(body, &search); err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "invalid principal-property-search")
		return true
	}
	actor, _ := r.Context().Value(authenticatedUserKey{}).(string)
	responses := []response{}
	if actor != "" && h.principalMatches(r, actor, search) {
		principal, err := h.propfindUserRoot(r.Context(), actor, nil, "0")
		if err == nil {
			responses = principal
		}
	}
	// python caldav sends an empty DAV:prop (its property list lands
	// beside it), so an empty request returns the principal's properties.
	if search.Prop != nil && len(search.Prop.Elements) > 0 {
		reportPropRequest(search.Prop).restrict(responses)
	}
	writeMultistatus(w, responses)
	return true
}

// principalMatches applies the property searches to actor's principal:
// all of them by default, any of them with test="anyof".
func (h *Handler) principalMatches(r *http.Request, actor string, search principalPropertySearch) bool {
	values := map[xml.Name][]string{
		{Space: NSDAV, Local: "displayname"}:                   {actor},
		{Space: NSSCalDAV, Local: "calendar-user-address-set"}: h.calendarUserAddresses(r.Context(), actor),
		{Space: NSCalendarServer, Local: "email-address-set"}:  h.calendarUserAddresses(r.Context(), actor),
	}
	if user, err := h.store.users.Get(r.Context(), actor); err == nil && user.DisplayName != "" {
		values[xml.Name{Space: NSDAV, Local: "displayname"}] = append(values[xml.Name{Space: NSDAV, Local: "displayname"}], user.DisplayName)
	}
	anyOf := strings.EqualFold(search.Test, "anyof")
	matched := 0
	for _, criterion := range search.Search {
		match := strings.ToLower(strings.TrimSpace(criterion.Match))
		hit := false
		for _, name := range criterion.Prop.Elements {
			for _, value := range values[name] {
				if strings.Contains(strings.ToLower(strings.TrimPrefix(value, "mailto:")), match) {
					hit = true
				}
			}
		}
		if hit {
			matched++
		}
	}
	if anyOf {
		return matched > 0
	}
	return len(search.Search) > 0 && matched == len(search.Search)
}

// reportRoot returns the root element name of a REPORT body.
func reportRoot(body []byte) xml.Name {
	decoder := xml.NewDecoder(strings.NewReader(string(body)))
	for {
		token, err := decoder.Token()
		if err != nil {
			return xml.Name{}
		}
		if start, ok := token.(xml.StartElement); ok {
			return start.Name
		}
	}
}
