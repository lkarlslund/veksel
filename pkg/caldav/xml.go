package caldav

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// --- DAV XML namespaces ---

const (
	NSDAV     = "DAV:"
	NSSCalDAV = "urn:ietf:params:xml:ns:caldav"
	NSCardDAV = "urn:ietf:params:xml:ns:carddav"
)

// --- XML request types ---

// propfind represents a DAV PROPFIND body.
type propfind struct {
	XMLName xml.Name `xml:"DAV: propfind"`
	Xmlns   string   `xml:"xmlns:DAV,attr"`

	// One of: allprop, prop, propname
	Allprop  *empty `xml:"DAV: allprop"`
	Prop     *prop  `xml:"DAV: prop"`
	Propname *empty `xml:"DAV: propname"`

	// Depth header is parsed separately
}

type prop struct {
	Elements []xml.Name `xml:",any"`
}

type empty struct{}

// calendarQuery represents a CalDAV calendar-query REPORT body.
type calendarQuery struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:caldav calendar-query"`
	Prop    *prop    `xml:"DAV: prop"`
	Filter  *filter  `xml:"urn:ietf:params:xml:ns:caldav filter"`
}

type filter struct {
	CompSet *compFilter `xml:"urn:ietf:params:xml:ns:caldav comp-filter"`
}

type compFilter struct {
	Name         string       `xml:"name,attr"`
	IsNotDefined *empty       `xml:"urn:ietf:params:xml:ns:caldav is-not-defined"`
	TimeRange    *timeRange   `xml:"urn:ietf:params:xml:ns:caldav time-range"`
	PropFilters  []propFilter `xml:"urn:ietf:params:xml:ns:caldav prop-filter"`
	CompFilters  []compFilter `xml:"urn:ietf:params:xml:ns:caldav comp-filter"`
}

type timeRange struct {
	Start  string `xml:"start,attr"`
	End    string `xml:"end,attr"`
	StartT time.Time
	EndT   time.Time
}

// multiget represents a CalDAV multiget REPORT body.
type multiget struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:caldav multiget"`
	Prop    *prop    `xml:"DAV: prop"`
	Hrefs   []href   `xml:"DAV: href"`
}

// --- XML response types ---

// multistatus is the root of most DAV XML responses.
type multistatus struct {
	XMLName   xml.Name   `xml:"d:multistatus"`
	Xmlns     string     `xml:"xmlns:d,attr"`
	XmlnsC    string     `xml:"xmlns:C,attr"`
	XmlnsCR   string     `xml:"xmlns:CR,attr"`
	XmlnsCS   string     `xml:"xmlns:CS,attr"`
	XmlnsIC   string     `xml:"xmlns:IC,attr"`
	Responses []response `xml:"d:response"`
	SyncToken *string    `xml:"d:sync-token,omitempty"`
}

type syncCollection struct {
	XMLName   xml.Name `xml:"DAV: sync-collection"`
	SyncToken string   `xml:"DAV: sync-token"`
	Prop      *prop    `xml:"DAV: prop"`
	Limit     struct {
		NResults int `xml:"DAV: nresults"`
	} `xml:"DAV: limit"`
}

type response struct {
	Href     string    `xml:"d:href"`
	Propstat *propstat `xml:"d:propstat,omitempty"`
	Prop     *propResp `xml:"d:prop,omitempty"`
	Status   string    `xml:"d:status,omitempty"`
	// request, when set, limits the 200 propstat to the requested
	// properties and reports the rest as 404 (see propRequest.restrict).
	request *propRequest
	// nameStats, when set, reports property names by status, as a
	// PROPPATCH reply does.
	nameStats []nameStat
}

// nameStat is a propstat of property names without values.
type nameStat struct {
	names  []xml.Name
	status string
}

// MarshalXML ensures properties are always wrapped in <propstat> per RFC 4918,
// which is required for compatibility with go-webdav/caldav client.
func (r response) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type rawResponse response
	// If Prop is set but Propstat is not, wrap Prop in a propstat
	if r.Prop != nil && r.Propstat == nil {
		r.Propstat = &propstat{
			Prop:   r.Prop,
			Status: r.Status,
		}
		r.Prop = nil
		r.Status = ""
	}
	if r.request != nil && r.Propstat != nil && r.Propstat.Prop != nil && r.Status == "" {
		return r.encodeRestricted(e, start)
	}
	if len(r.nameStats) > 0 {
		return r.encodeNameStats(e, start)
	}
	return e.EncodeElement((*rawResponse)(&r), start)
}

type propstat struct {
	XMLName xml.Name  `xml:"d:propstat"`
	Prop    *propResp `xml:"d:prop"`
	Status  string    `xml:"d:status"`
}

type propResp struct {
	Displayname        *string             `xml:"d:displayname,omitempty"`
	ResourceType       *resourceType       `xml:"d:resourcetype,omitempty"`
	Getcontentlength   *string             `xml:"d:getcontentlength,omitempty"`
	Getcontenttype     *string             `xml:"d:getcontenttype,omitempty"`
	Getetag            *string             `xml:"d:getetag,omitempty"`
	Getlastmodified    *string             `xml:"d:getlastmodified,omitempty"`
	SyncToken          *string             `xml:"d:sync-token,omitempty"`
	Creationdate       *string             `xml:"d:creationdate,omitempty"`
	ContentType        *string             `xml:"d:content-type,omitempty"`
	CalendarData       *string             `xml:"C:calendar-data,omitempty"`
	VCardData          *string             `xml:"CR:address-data,omitempty"`
	SupportedReportSet *supportedReportSet `xml:"d:supported-report-set,omitempty"`
	// ACL properties (RFC 3744)
	ACL                     *davACL                    `xml:"d:acl,omitempty"`
	Owner                   *davPrincipalPropertySet   `xml:"d:owner,omitempty"`
	Principal               *davPrincipalPropertySet   `xml:"d:principal,omitempty"`
	CurrentUserPrincipal    *davCurrentUserPrincipal   `xml:"d:current-user-principal,omitempty"`
	SupportedPrivilegeSet   *davSupportedPrivilegeSet  `xml:"d:supported-privilege-set,omitempty"`
	CurrentUserPrivilegeSet *davPrivilegeList          `xml:"d:current-user-privilege-set,omitempty"`
	CalendarUserAddressSet  *davCalendarUserAddressSet `xml:"C:calendar-user-address-set,omitempty"`
	// Scheduling discovery on the principal (RFC 6638 §2.1, §2.2, §2.4.2).
	ScheduleInboxURL  *davHomeSet `xml:"C:schedule-inbox-URL,omitempty"`
	ScheduleOutboxURL *davHomeSet `xml:"C:schedule-outbox-URL,omitempty"`
	CalendarUserType  *string     `xml:"C:calendar-user-type,omitempty"`
	// Client discovery (RFC 4791 section 6.2.1, RFC 6352 section 7.1.1)
	CalendarHomeSet    *davHomeSet `xml:"C:calendar-home-set,omitempty"`
	AddressbookHomeSet *davHomeSet `xml:"CR:addressbook-home-set,omitempty"`
	// SupportedComponents is RFC 4791 5.2.3: VEVENT for calendars, VTODO
	// for task lists.
	SupportedComponents *componentSet `xml:"C:supported-calendar-component-set,omitempty"`
	// Principal discovery (RFC 3744 §4.2, §5.8).
	PrincipalURL           *davHomeSet `xml:"d:principal-URL,omitempty"`
	PrincipalCollectionSet *davHomeSet `xml:"d:principal-collection-set,omitempty"`
	// Collection change tag (calendarserver ctag) and descriptive
	// properties clients read and set with PROPPATCH.
	GetCTag                *string `xml:"CS:getctag,omitempty"`
	CalendarDescription    *string `xml:"C:calendar-description,omitempty"`
	AddressbookDescription *string `xml:"CR:addressbook-description,omitempty"`
	CalendarColor          *string `xml:"IC:calendar-color,omitempty"`
	CalendarOrder          *string `xml:"IC:calendar-order,omitempty"`
	// Media types a collection stores (RFC 4791 §5.2.4, RFC 6352 §6.2.2);
	// DAVx5 writes vCard 4 only to address books that list it.
	SupportedCalendarData *dataTypes `xml:"C:supported-calendar-data,omitempty"`
	SupportedAddressData  *dataTypes `xml:"CR:supported-address-data,omitempty"`
	// Account storage (RFC 4331), returned only when requested by name.
	QuotaUsedBytes      *string `xml:"d:quota-used-bytes,omitempty"`
	QuotaAvailableBytes *string `xml:"d:quota-available-bytes,omitempty"`
}

// dataTypes lists the media types of supported-calendar-data or
// supported-address-data.
type dataTypes struct {
	Calendar []dataType `xml:"C:calendar-data,omitempty"`
	Address  []dataType `xml:"CR:address-data-type,omitempty"`
}

type dataType struct {
	ContentType string `xml:"content-type,attr"`
	Version     string `xml:"version,attr"`
}

type componentSet struct {
	Components []component `xml:"C:comp"`
}

type component struct {
	Name string `xml:"name,attr"`
}

// calendarCollection reports whether a folder is a CalDAV calendar
// collection: an event calendar or a task list.
func calendarCollection(folder model.Folder) bool {
	return folder.Type == model.FolderTypeCalendar || folder.Type == model.FolderTypeTasks
}

// collectionComponent is the one iCalendar component a calendar collection
// stores.
func collectionComponent(folder model.Folder) string {
	if folder.Type == model.FolderTypeTasks {
		return "VTODO"
	}
	return "VEVENT"
}

// davHomeSet is the href list of a calendar-home-set or addressbook-home-set.
type davHomeSet struct {
	Href string `xml:"d:href"`
}

type resourceType struct {
	Collection     *empty `xml:"d:collection,omitempty"`
	Principal      *empty `xml:"d:principal,omitempty"`
	Calendar       *empty `xml:"C:calendar,omitempty"`
	Addressbook    *empty `xml:"CR:addressbook,omitempty"`
	SharedCalendar *empty `xml:"C:shared-calendar,omitempty"`
	ScheduleInbox  *empty `xml:"C:schedule-inbox,omitempty"`
	ScheduleOutbox *empty `xml:"C:schedule-outbox,omitempty"`
}

type supportedReportSet struct {
	SupportedReport []supportedReport `xml:"d:supported-report"`
}

type supportedReport struct {
	Report reportName `xml:"d:report"`
}

// reportName is the report element inside DAV:report (RFC 3253 §3.1.5).
type reportName xml.Name

func (n reportName) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	report := xml.StartElement{Name: xml.Name(n)}
	for _, token := range []xml.Token{start, report, report.End(), start.End()} {
		if err := e.EncodeToken(token); err != nil {
			return err
		}
	}
	return nil
}

type href struct {
	Value string `xml:",chardata"`
}

// parsePropfind parses a PROPFIND body.
// An empty body is an allprop request (RFC 4918 §9.1); cadaver, macOS
// Finder, and Evolution's first probe send one.
func parsePropfind(body io.Reader) (*propfind, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return &propfind{Allprop: &empty{}}, nil
	}
	var pf propfind
	if err := xml.Unmarshal(data, &pf); err != nil {
		return nil, err
	}
	return &pf, nil
}

// parseCalendarQuery parses a calendar-query REPORT body.
func parseCalendarQuery(body io.Reader) (*calendarQuery, error) {
	var cq calendarQuery
	if err := xml.NewDecoder(body).Decode(&cq); err != nil {
		return nil, err
	}
	return &cq, nil
}

// parseMultiget parses a multiget or calendar-multiget REPORT body.
// calendar-multiget is the RFC 4791 name; multiget is an alias for compatibility.
func parseMultiget(body io.Reader) (*multiget, error) {
	decoder := xml.NewDecoder(body)
	// Token-based parsing to skip root element name check
	for {
		tok, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok {
			// Found root element, now decode children
			mg := &multiget{}
			for {
				child, err := decoder.Token()
				if err != nil {
					break
				}
				if _, ok := child.(xml.EndElement); ok {
					break
				}
				if ce, ok := child.(xml.StartElement); ok {
					if ce.Name.Space == "DAV:" && ce.Name.Local == "prop" {
						var p prop
						if err := decoder.DecodeElement(&p, &ce); err == nil {
							mg.Prop = &p
						}
					} else if ce.Name.Space == "DAV:" && ce.Name.Local == "href" {
						// Read href char data
						var charData string
						for {
							subTok, err := decoder.RawToken()
							if err != nil {
								break
							}
							if _, ok := subTok.(xml.EndElement); ok {
								break
							}
							if cd, ok := subTok.(xml.CharData); ok {
								charData += string(cd)
							}
						}
						mg.Hrefs = append(mg.Hrefs, href{Value: strings.TrimSpace(charData)})
					} else {
						decoder.Skip()
					}
				}
			}
			_ = se
			return mg, nil
		}
	}
}

// davCompliance is the DAV response header: WebDAV classes, CalDAV with
// implicit scheduling (RFC 6638 §2: clients must not schedule through the
// outbox themselves), CardDAV, and the extensions served.
const davCompliance = "1, 3, calendar-access, calendar-auto-schedule, addressbook, extended-mkcol, sync-collection"

// davAllow lists the methods the DAV handler serves.
const davAllow = "OPTIONS, GET, HEAD, PUT, DELETE, POST, PROPFIND, PROPPATCH, MKCOL, MKCALENDAR, MOVE, COPY, LOCK, UNLOCK, REPORT"

// writeMultistatus writes a 207 DAV multistatus XML response.
func writeMultistatus(w http.ResponseWriter, responses []response) {
	writeSyncMultistatus(w, responses, nil)
}

// writeSyncMultistatus writes the 207 status line itself so the XML
// Content-Type is set first: DAVx5 (dav4jvm) refuses a multistatus sent as
// text/plain without an XML declaration.
func writeSyncMultistatus(w http.ResponseWriter, responses []response, syncToken *string) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("DAV", davCompliance)
	w.WriteHeader(http.StatusMultiStatus)
	io.WriteString(w, xml.Header)
	ms := multistatus{
		Xmlns:     NSDAV,
		XmlnsC:    NSSCalDAV,
		XmlnsCR:   NSCardDAV,
		XmlnsCS:   NSCalendarServer,
		XmlnsIC:   NSAppleICal,
		Responses: responses,
		SyncToken: syncToken,
	}
	if len(responses) == 0 {
		ms.Responses = []response{}
	}
	encodeXML(w, ms)
}

// encodeXML writes an XML response with the proper Content-Type.
func encodeXML(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	xml.NewEncoder(w).Encode(v)
}

// formatHTTPTime formats a time for HTTP headers.
// Uses GMT location so the output is parseable by http.ParseTime.
var gmtLoc = func() *time.Location { l, _ := time.LoadLocation("GMT"); return l }()

func formatHTTPTime(t time.Time) string {
	return t.In(gmtLoc).Format(time.RFC1123)
}

// formatXMLTime formats a time for XML time stamps (ISO 8601).
func formatXMLTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// buildHref constructs a DAV href from username and path parts. Each
// segment is percent-encoded: an href is a URI reference, and clients
// (Apple's NSURL, DAVx5's okhttp) cannot resolve one with raw spaces or
// non-ASCII characters.
func buildHref(username string, parts ...string) string {
	var href strings.Builder
	href.WriteString("/dav/")
	href.WriteString(url.PathEscape(username))
	for _, part := range parts {
		for segment := range strings.SplitSeq(part, "/") {
			href.WriteString("/")
			href.WriteString(url.PathEscape(segment))
		}
	}
	return href.String()
}

// objectNameFromHref returns the decoded object name of an href naming
// /dav/{user}/{collection}/{object}, given as a path or an absolute URL.
func objectNameFromHref(href string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return "", false
	}
	parts := parseDestinationParts(parsed.Path)
	if len(parts) != 3 {
		return "", false
	}
	return parts[2], true
}

// itemToPropResp builds a propResp for an Item.
func itemToPropResp(item model.Item, href string) response {
	etag := fmt.Sprintf("%q", fmt.Sprintf("%016x", item.ModSeq))
	created := formatXMLTime(item.CreatedAt)
	lastMod := formatHTTPTime(item.UpdatedAt)
	size := fmt.Sprintf("%d", item.Size)

	return response{
		Href:   href,
		Status: "HTTP/1.1 200 OK",
		Prop: &propResp{
			ResourceType:     &resourceType{},
			Getcontentlength: &size,
			Getcontenttype:   strPtr("text/calendar; charset=utf-8"),
			Getetag:          &etag,
			Getlastmodified:  &lastMod,
			Creationdate:     &created,
		},
	}
}

// folderToPropRespACL builds a propResp for a Folder with ACL/sharing info.
func folderToPropRespACL(folder model.Folder, href string, sharees []model.Sharee, currentUser string) response {
	etag := fmt.Sprintf("%q", fmt.Sprintf("%016x", 0))
	lastMod := formatHTTPTime(folder.UpdatedAt)
	created := formatXMLTime(folder.CreatedAt)
	displayName := folder.Name

	rt := resourceType{Collection: &empty{}}
	if calendarCollection(folder) {
		rt.Calendar = &empty{}
		// If the calendar has sharees, mark it as a shared calendar
		if len(sharees) > 0 {
			rt.SharedCalendar = &empty{}
		}
	}
	if folder.Type == model.FolderTypeContacts {
		rt.Addressbook = &empty{}
	}
	if folder.Type == model.FolderTypeScheduleInbox {
		rt.ScheduleInbox = &empty{}
	}
	if folder.Type == model.FolderTypeScheduleOutbox {
		rt.ScheduleOutbox = &empty{}
	}

	pr := &propResp{
		Displayname:     &displayName,
		ResourceType:    &rt,
		Getetag:         &etag,
		Getlastmodified: &lastMod,
		Creationdate:    &created,
	}
	if calendarCollection(folder) {
		pr.SupportedComponents = &componentSet{Components: []component{{Name: collectionComponent(folder)}}}
	}
	pr.SupportedPrivilegeSet, pr.CurrentUserPrivilegeSet = schedulePrivileges(folder, strings.EqualFold(currentUser, folder.UserID))

	// Add ACL properties for calendar collections
	if calendarCollection(folder) && len(sharees) > 0 {
		// Build ACL entries
		aces := buildACLEntries(folder.UserID, sharees)
		pr.ACL = &davACL{PrivilegeSet: aces}

		// Calendar user address set (all users who have access)
		hrefs := make([]string, 0, len(sharees)+1)
		hrefs = append(hrefs, buildHref(folder.UserID)+"/")
		for _, s := range sharees {
			hrefs = append(hrefs, buildHref(s.UserID)+"/")
		}
		pr.CalendarUserAddressSet = &davCalendarUserAddressSet{Hrefs: hrefs}

		// Current user principal
		if currentUser != "" {
			pr.CurrentUserPrincipal = &davCurrentUserPrincipal{Href: buildHref(currentUser) + "/"}
		}

		// Supported privilege set
		pr.SupportedPrivilegeSet = &davSupportedPrivilegeSet{SupportedPrivilege: []davSupportedPrivilege{{
			Privilege: davPrivilege{All: &empty{}},
			Children:  []davSupportedPrivilege{{Privilege: davPrivilege{Read: &empty{}}}, {Privilege: davPrivilege{Write: &empty{}}}},
		}}}
	}

	return response{
		Href:   href,
		Status: "HTTP/1.1 200 OK",
		Prop:   pr,
	}
}

// strPtr returns a pointer to the given string.
func strPtr(s string) *string {
	return &s
}

// respondError sends a DAV error response.
func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, status int, errType, msg string) {
	if state, _ := r.Context().Value(davErrorStateKey{}).(*davErrorState); state != nil {
		switch {
		case service.IsTemporarilyUnavailable(state.special):
			w.Header().Set("Retry-After", "5")
			status, errType, msg = http.StatusServiceUnavailable, "temporarily-unavailable", "account is temporarily unavailable"
		case errors.Is(state.special, model.ErrQuotaExceeded):
			status, errType, msg = http.StatusInsufficientStorage, "quota-not-exceeded", "account quota exceeded"
		}
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<d:error xmlns:d="DAV:" xmlns:s="urn:ietf:params:xml:ns:caldav">
 <d:%s>%s</d:%s>
</d:error>`, errType, msg, errType)
}

// respondCalendarData sends a VEVENT/iCalendar data response.
func respondCalendarData(w http.ResponseWriter, data []byte, etag string, lastModified time.Time) {
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", formatHTTPTime(lastModified))
	w.Header().Set("Cache-Control", "must-revalidate")
	w.Write(data)
}

// --- ACL XML types (RFC 3744 / WebDAV ACL) ---

// davACL represents the DAV:acl property response.
type davACL struct {
	XMLName      xml.Name `xml:"d:acl"`
	PrivilegeSet []davACE `xml:"d:ace"`
}

// davACE represents a single Access Control Entry.
type davACE struct {
	Principal davPrincipal `xml:"d:principal"`
	Privilege davPrivilege `xml:"d:privilege,omitempty"`
}

// davPrincipal represents a principal (user) in an ACE.
type davPrincipal struct {
	Href string `xml:"d:href"`
}

// davPrivilege names one privilege: a DAV one (RFC 3744) or a CalDAV
// scheduling one (RFC 6638 §6).
type davPrivilege struct {
	Read                  *empty `xml:"d:read,omitempty"`
	Write                 *empty `xml:"d:write,omitempty"`
	All                   *empty `xml:"d:all,omitempty"`
	WriteProperties       *empty `xml:"d:write-properties,omitempty"`
	WriteContent          *empty `xml:"d:write-content,omitempty"`
	Bind                  *empty `xml:"d:bind,omitempty"`
	Unbind                *empty `xml:"d:unbind,omitempty"`
	ReadCurrentPrivileges *empty `xml:"d:read-current-user-privilege-set,omitempty"`
	ScheduleSend          *empty `xml:"C:schedule-send,omitempty"`
	ScheduleSendInvite    *empty `xml:"C:schedule-send-invite,omitempty"`
	ScheduleSendReply     *empty `xml:"C:schedule-send-reply,omitempty"`
	ScheduleSendFreeBusy  *empty `xml:"C:schedule-send-freebusy,omitempty"`
	ScheduleDeliver       *empty `xml:"C:schedule-deliver,omitempty"`
	ScheduleDeliverInvite *empty `xml:"C:schedule-deliver-invite,omitempty"`
	ScheduleDeliverReply  *empty `xml:"C:schedule-deliver-reply,omitempty"`
	ScheduleQueryFreeBusy *empty `xml:"C:schedule-query-freebusy,omitempty"`
}

// davPrincipalPropertySet represents the current principal.
type davPrincipalPropertySet struct {
	Unauthenticated *empty `xml:"d:unauthenticated,omitempty"`
	Authenticated   *empty `xml:"d:authenticated,omitempty"`
	Self            *empty `xml:"d:self,omitempty"`
	Owner           *empty `xml:"d:owner,omitempty"`
	Href            string `xml:"d:href,omitempty"`
}

// davCurrentUserPrincipal represents DAV:current-user-principal.
type davCurrentUserPrincipal struct {
	Href string `xml:"d:href"`
}

// davCalendarUserAddressSet represents the set of calendar user addresses.
type davCalendarUserAddressSet struct {
	Hrefs []string `xml:"d:href"`
}

// davSupportedPrivilegeSet is DAV:supported-privilege-set (RFC 3744 §5.3):
// a tree of supported privileges, aggregates containing their parts.
type davSupportedPrivilegeSet struct {
	SupportedPrivilege []davSupportedPrivilege `xml:"d:supported-privilege"`
}

// davSupportedPrivilege is one node of a supported-privilege tree.
type davSupportedPrivilege struct {
	Privilege davPrivilege            `xml:"d:privilege"`
	Abstract  *empty                  `xml:"d:abstract,omitempty"`
	Children  []davSupportedPrivilege `xml:"d:supported-privilege,omitempty"`
}

// davPrivilegeList is DAV:current-user-privilege-set (RFC 3744 §5.4).
type davPrivilegeList struct {
	Privilege []davPrivilege `xml:"d:privilege"`
}

// buildACLEntries builds ACL XML entries from model.Sharee list.
func buildACLEntries(ownerID string, sharees []model.Sharee) []davACE {
	aces := make([]davACE, 0, len(sharees)+1)
	// Owner ACE
	aces = append(aces, davACE{
		Principal: davPrincipal{Href: buildHref(ownerID) + "/"},
		Privilege: davPrivilege{All: &empty{}},
	})
	// Sharee ACEs
	for _, s := range sharees {
		priv := davPrivilege{}
		switch s.Role {
		case model.ShareOwner:
			priv.All = &empty{}
		case model.ShareWriter:
			priv.Write = &empty{}
		case model.ShareReader:
			priv.Read = &empty{}
		}
		aces = append(aces, davACE{
			Principal: davPrincipal{Href: buildHref(s.UserID) + "/"},
			Privilege: priv,
		})
	}
	return aces
}

// --- Free/Busy Query XML types (RFC 4791 §7.10) ---

// freeBusyQuery represents a CalDAV free-busy-query REPORT body. RFC 4791
// carries the range as a CALDAV:time-range element's start and end
// attributes; the time-range-start/-end elements are an early Veksel form
// kept for compatibility.
type freeBusyQuery struct {
	XMLName        xml.Name       `xml:"urn:ietf:params:xml:ns:caldav free-busy-query"`
	Prop           *prop          `xml:"DAV: prop"`
	TimeRange      *timeRange     `xml:"urn:ietf:params:xml:ns:caldav time-range"`
	TimeRangeStart *timeRangeElem `xml:"urn:ietf:params:xml:ns:caldav time-range-start"`
	TimeRangeEnd   *timeRangeElem `xml:"urn:ietf:params:xml:ns:caldav time-range-end"`
}

type timeRangeElem struct {
	Value string `xml:",chardata"`
}

// parseFreeBusyQuery parses a free-busy-query REPORT body.
func parseFreeBusyQuery(body io.Reader) (*freeBusyQuery, error) {
	var fbq freeBusyQuery
	if err := xml.NewDecoder(body).Decode(&fbq); err != nil {
		return nil, err
	}
	return &fbq, nil
}

// GetStart returns the start time string from the query.
func (fbq *freeBusyQuery) GetStart() string {
	if fbq.TimeRange != nil && fbq.TimeRange.Start != "" {
		return fbq.TimeRange.Start
	}
	if fbq.TimeRangeStart != nil {
		return fbq.TimeRangeStart.Value
	}
	return ""
}

// GetEnd returns the end time string from the query.
func (fbq *freeBusyQuery) GetEnd() string {
	if fbq.TimeRange != nil && fbq.TimeRange.End != "" {
		return fbq.TimeRange.End
	}
	if fbq.TimeRangeEnd != nil {
		return fbq.TimeRangeEnd.Value
	}
	return ""
}

// --- Schedule Inbox/Outbox XML types (RFC 7959) ---

// scheduleInboxQuery represents a schedule-inbox-query REPORT body.
type scheduleInboxQuery struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:caldav schedule-inbox-query"`
	Prop    *prop    `xml:"DAV: prop"`
}

// scheduleOutboxQuery represents a schedule-outbox-query REPORT body.
type scheduleOutboxQuery struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:caldav schedule-outbox-query"`
	Prop    *prop    `xml:"DAV: prop"`
}

// parseScheduleInboxQuery parses a schedule-inbox-query REPORT body.
func parseScheduleInboxQuery(body io.Reader) (*scheduleInboxQuery, error) {
	var siq scheduleInboxQuery
	if err := xml.NewDecoder(body).Decode(&siq); err != nil {
		return nil, err
	}
	return &siq, nil
}

// parseScheduleOutboxQuery parses a schedule-outbox-query REPORT body.
func parseScheduleOutboxQuery(body io.Reader) (*scheduleOutboxQuery, error) {
	var soq scheduleOutboxQuery
	if err := xml.NewDecoder(body).Decode(&soq); err != nil {
		return nil, err
	}
	return &soq, nil
}

// --- CardDAV XML request types (RFC 6352) ---

// addressbookQuery represents a CardDAV addressbook-query REPORT body.
type addressbookQuery struct {
	XMLName xml.Name       `xml:"urn:ietf:params:xml:ns:carddav addressbook-query"`
	Prop    *prop          `xml:"DAV: prop"`
	Filter  *carddavFilter `xml:"urn:ietf:params:xml:ns:carddav filter"`
	Limit   *struct {
		NResults int `xml:"urn:ietf:params:xml:ns:carddav nresults"`
	} `xml:"urn:ietf:params:xml:ns:carddav limit"`
}

// carddavFilter represents the top-level filter in a CardDAV query: RFC
// 6352 prop-filters with a test, or the comp-filter wrapper early Veksel
// callers send.
type carddavFilter struct {
	Test        string             `xml:"test,attr"`
	PropFilters []cardPropFilter   `xml:"urn:ietf:params:xml:ns:carddav prop-filter"`
	CompSet     *carddavCompFilter `xml:"urn:ietf:params:xml:ns:carddav comp-filter"`
}

// carddavCompFilter represents a component filter in a CardDAV query.
type carddavCompFilter struct {
	Name        string              `xml:"name,attr"`
	PropFilters []carddavPropFilter `xml:"urn:ietf:params:xml:ns:carddav prop-filter"`
	CompFilters []carddavCompFilter `xml:"urn:ietf:params:xml:ns:carddav comp-filter"`
}

// carddavPropFilter represents a property filter in a CardDAV query.
type carddavPropFilter struct {
	PropName  string            `xml:"name,attr"`
	TextMatch *carddavTextMatch `xml:"urn:ietf:params:xml:ns:carddav text-match"`
}

// carddavTextMatch represents a text-match element in a CardDAV property filter.
// e.g. <text-match collation="i;ascii-casemap">john</text-match>
type carddavTextMatch struct {
	Collation string `xml:"collation,attr"`
	TextValue string `xml:",chardata"`
}

// carddavMultiget represents a CardDAV multiget REPORT body.
// It deliberately has no XMLName: RFC 6352 calls the root addressbook-multiget
// while older callers send multiget, and dispatch already checked the name.
type carddavMultiget struct {
	Prop  *prop  `xml:"DAV: prop"`
	Hrefs []href `xml:"DAV: href"`
}

// parseAddressbookQuery parses an addressbook-query REPORT body.
func parseAddressbookQuery(body io.Reader) (*addressbookQuery, error) {
	var aq addressbookQuery
	if err := xml.NewDecoder(body).Decode(&aq); err != nil {
		return nil, err
	}
	return &aq, nil
}

// parseCardDAVMultiget parses a CardDAV multiget REPORT body.
func parseCardDAVMultiget(body io.Reader) (*carddavMultiget, error) {
	var mg carddavMultiget
	if err := xml.NewDecoder(body).Decode(&mg); err != nil {
		return nil, err
	}
	return &mg, nil
}
