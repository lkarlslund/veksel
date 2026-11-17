package caldav

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// Namespaces of the vendor properties Apple Calendar, Thunderbird, DAVx5,
// and Evolution read and write on collections.
const (
	NSCalendarServer = "http://calendarserver.org/ns/"
	NSAppleICal      = "http://apple.com/ns/ical/"
)

// tagPrefixes maps the literal prefixes used in propResp tags to their
// namespaces, which the multistatus root declares.
var tagPrefixes = map[string]string{"d": NSDAV, "C": NSSCalDAV, "CR": NSCardDAV, "CS": NSCalendarServer, "IC": NSAppleICal}

// propFields lists the property name of every propResp field, in field
// order, so responses can be restricted to the requested properties.
var propFields = func() []xml.Name {
	typ := reflect.TypeFor[propResp]()
	names := make([]xml.Name, typ.NumField())
	for index := range typ.NumField() {
		tag, _, _ := strings.Cut(typ.Field(index).Tag.Get("xml"), ",")
		prefix, local, _ := strings.Cut(tag, ":")
		names[index] = xml.Name{Space: tagPrefixes[prefix], Local: local}
	}
	return names
}()

// propRequest is what a PROPFIND or REPORT asked for: named properties
// (prop), property names only (propname), or everything (allprop or an
// empty body).
type propRequest struct {
	names     []xml.Name
	namesOnly bool
}

// requestFor returns the property request of a parsed PROPFIND body.
func requestFor(pf *propfind) propRequest {
	switch {
	case pf == nil || pf.Allprop != nil:
		return propRequest{}
	case pf.Propname != nil:
		return propRequest{namesOnly: true}
	case pf.Prop != nil:
		return propRequest{names: pf.Prop.Elements}
	}
	return propRequest{}
}

// wants reports whether the request asks for the property name; allprop
// asks for everything.
func (p propRequest) wants(name xml.Name) bool {
	if p.names == nil {
		return !p.namesOnly
	}
	for _, requested := range p.names {
		if requested == name {
			return true
		}
	}
	return false
}

// restrict applies the request to each response: RFC 4918 §9.1 answers a
// prop request with exactly the named properties, those the resource does
// not have in a 404 propstat, and a propname request with names only.
// Discovery clients (DAVx5, Apple, Thunderbird) ask for properties a
// resource does not carry and expect them reported as missing.
func (p propRequest) restrict(responses []response) {
	if p.names == nil && !p.namesOnly {
		return
	}
	for index := range responses {
		responses[index].request = &p
	}
}

// encodeRestricted writes r's properties limited to request.
func (r response) encodeRestricted(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	if err := e.EncodeElement(r.Href, xml.StartElement{Name: xml.Name{Local: "d:href"}}); err != nil {
		return err
	}
	var found propResp
	var present, missing []xml.Name
	value := reflect.ValueOf(r.Propstat.Prop).Elem()
	foundValue := reflect.ValueOf(&found).Elem()
	for index, name := range propFields {
		field := value.Field(index)
		if field.IsNil() {
			continue
		}
		if r.request.namesOnly {
			present = append(present, name)
		} else if r.request.wants(name) {
			foundValue.Field(index).Set(field)
			present = append(present, name)
		}
	}
	if !r.request.namesOnly {
		for _, name := range r.request.names {
			if !containsName(present, name) {
				missing = append(missing, name)
			}
		}
	}
	switch {
	case r.request.namesOnly:
		if err := encodeNamePropstat(e, present, r.Propstat.Status); err != nil {
			return err
		}
	case len(present) > 0:
		if err := e.EncodeElement(propstat{Prop: &found, Status: r.Propstat.Status}, xml.StartElement{Name: xml.Name{Local: "d:propstat"}}); err != nil {
			return err
		}
	}
	if len(missing) > 0 {
		if err := encodeNamePropstat(e, missing, "HTTP/1.1 404 Not Found"); err != nil {
			return err
		}
	}
	return e.EncodeToken(start.End())
}

// encodeNameStats writes r's href and its property names by status.
func (r response) encodeNameStats(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	if err := e.EncodeElement(r.Href, xml.StartElement{Name: xml.Name{Local: "d:href"}}); err != nil {
		return err
	}
	for _, stat := range r.nameStats {
		if err := encodeNamePropstat(e, stat.names, stat.status); err != nil {
			return err
		}
	}
	return e.EncodeToken(start.End())
}

// encodeNamePropstat writes a propstat of empty property elements.
func encodeNamePropstat(e *xml.Encoder, names []xml.Name, status string) error {
	propstatStart := xml.StartElement{Name: xml.Name{Local: "d:propstat"}}
	propStart := xml.StartElement{Name: xml.Name{Local: "d:prop"}}
	if err := e.EncodeToken(propstatStart); err != nil {
		return err
	}
	if err := e.EncodeToken(propStart); err != nil {
		return err
	}
	for _, name := range names {
		element := xml.StartElement{Name: name}
		if err := e.EncodeToken(element); err != nil {
			return err
		}
		if err := e.EncodeToken(element.End()); err != nil {
			return err
		}
	}
	if err := e.EncodeToken(propStart.End()); err != nil {
		return err
	}
	if err := e.EncodeElement(status, xml.StartElement{Name: xml.Name{Local: "d:status"}}); err != nil {
		return err
	}
	return e.EncodeToken(propstatStart.End())
}

// decorateCollection adds the properties sync clients read from a calendar
// or address book collection: the sync token and the matching
// calendarserver ctag (Apple and Thunderbird skip a collection whose ctag is
// unchanged), a collection ETag that changes with it, the supported reports
// (Thunderbird and Apple use sync-collection only when it is listed), the
// owner, the stored descriptive properties, and the actor's privileges
// (DAVx5 and Thunderbird mark a collection read-only without write).
func (h *Handler) decorateCollection(ctx context.Context, folder model.Folder, resp *response) {
	prop := resp.Prop
	if prop == nil {
		return
	}
	prop.Owner = &davPrincipalPropertySet{Href: buildHref(folder.UserID) + "/"}
	if reader, ok := h.store.space.(service.FolderChangeReader); ok {
		token, err := reader.CurrentChangeState(ctx, davAccess(ctx, ""), service.ChangeScope{FolderID: folder.ID, Object: service.ChangeObjectItem})
		if err == nil {
			syncToken, ctag := syncTokenURI(token), token
			sum := sha256.Sum256([]byte(token))
			etag := fmt.Sprintf("%q", hex.EncodeToString(sum[:8]))
			prop.SyncToken, prop.GetCTag, prop.Getetag = &syncToken, &ctag, &etag
		}
	}
	var reports []xml.Name
	switch {
	case calendarCollection(folder):
		reports = []xml.Name{{Space: NSSCalDAV, Local: "calendar-query"}, {Space: NSSCalDAV, Local: "calendar-multiget"},
			{Space: NSSCalDAV, Local: "free-busy-query"}, {Space: NSDAV, Local: "sync-collection"}}
		prop.SupportedCalendarData = &dataTypes{Calendar: []dataType{{ContentType: "text/calendar", Version: "2.0"}}}
		if folder.Description != "" {
			prop.CalendarDescription = strPtr(folder.Description)
		}
		if folder.Color != "" {
			prop.CalendarColor = strPtr(folder.Color)
		}
		if folder.Order != 0 {
			prop.CalendarOrder = strPtr(strconv.Itoa(folder.Order))
		}
	case folder.Type == model.FolderTypeContacts:
		reports = []xml.Name{{Space: NSCardDAV, Local: "addressbook-query"}, {Space: NSCardDAV, Local: "addressbook-multiget"},
			{Space: NSDAV, Local: "sync-collection"}}
		prop.SupportedAddressData = &dataTypes{Address: []dataType{{ContentType: "text/vcard", Version: "3.0"}, {ContentType: "text/vcard", Version: "4.0"}}}
		if folder.Description != "" {
			prop.AddressbookDescription = strPtr(folder.Description)
		}
	default:
		return
	}
	set := &supportedReportSet{}
	for _, report := range reports {
		set.SupportedReport = append(set.SupportedReport, supportedReport{Report: reportName(report)})
	}
	prop.SupportedReportSet = set
	if prop.CurrentUserPrivilegeSet == nil {
		prop.CurrentUserPrivilegeSet = h.collectionPrivileges(ctx, folder)
	}
}

// collectionPrivileges is DAV:current-user-privilege-set for a calendar or
// address book: everything for its owner, otherwise read with write added
// when the actor may change the collection's items.
func (h *Handler) collectionPrivileges(ctx context.Context, folder model.Folder) *davPrivilegeList {
	read := []davPrivilege{{Read: &empty{}}, {ReadCurrentPrivileges: &empty{}}}
	write := []davPrivilege{{Write: &empty{}}, {WriteContent: &empty{}}, {WriteProperties: &empty{}}, {Bind: &empty{}}, {Unbind: &empty{}}}
	actor, _ := ctx.Value(authenticatedUserKey{}).(string)
	if actor == "" || strings.EqualFold(actor, folder.UserID) {
		return &davPrivilegeList{Privilege: append(append([]davPrivilege{{All: &empty{}}}, read...), write...)}
	}
	decision, err := h.authorizer.Check(ctx, authz.Request{
		Actor:    model.PrincipalRef{Kind: model.PrincipalUser, ID: actor},
		Action:   authz.FolderItemsUpdate,
		Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folder.ID},
	})
	if err == nil && decision.Allowed {
		return &davPrivilegeList{Privilege: append(read, write...)}
	}
	return &davPrivilegeList{Privilege: read}
}

func containsName(names []xml.Name, name xml.Name) bool {
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}
