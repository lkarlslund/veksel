package caldav

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// --- CardDAV-specific methods (RFC 6352) ---

// handleCardDAVReport dispatches CardDAV REPORT requests.
// Called from handleReport when the report name is a CardDAV report.
func (h *Handler) handleCardDAVReport(w http.ResponseWriter, r *http.Request, username string, parts []string, body []byte, reportName string) {
	switch reportName {
	case "addressbook-query":
		h.handleAddressbookQuery(w, r, username, parts, body)
	case "multiget", "addressbook-multiget":
		// RFC 6352 names the report addressbook-multiget; the bare
		// multiget alias is kept for older callers.
		// We detect by checking the body for CardDAV namespace.
		h.handleCardDAVMultiget(w, r, username, parts, body)
	default:
		h.respondError(w, r, http.StatusBadRequest, "bad-report", fmt.Sprintf("unsupported report: %s", reportName))
	}
}

// isCardDAVReport checks if the report body uses the CardDAV namespace.
func isCardDAVReport(body []byte) bool {
	// Check for CardDAV namespace in the body
	if bytes.Contains(body, []byte("carddav")) {
		return true
	}
	// Also check for common CardDAV report elements
	decoder := xml.NewDecoder(bytes.NewReader(body))
	for {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		if se, ok := token.(xml.StartElement); ok {
			if se.Name.Space == NSCardDAV || se.Name.Space == "urn:ietf:params:xml:ns:carddav" {
				return true
			}
			// Check attributes for CardDAV xmlns
			for _, attr := range se.Attr {
				if attr.Value == NSCardDAV || attr.Value == "urn:ietf:params:xml:ns:carddav" {
					return true
				}
			}
			break
		}
	}
	return false
}

// isAddressbookMKCOL checks if the MKCOL body contains a CardDAV addressbook resource type.
func isAddressbookMKCOL(body []byte) bool {
	return bytes.Contains(body, []byte("addressbook"))
}

// --- vCard parsing helpers ---

// containsVCARD checks if the data contains a VCARD component.
func containsVCARD(data []byte) bool {
	upper := bytes.ToUpper(data)
	return bytes.Contains(upper, []byte("BEGIN:VCARD"))
}

// extractVCARDUID extracts the UID property from a vCard.
func extractVCARDUID(data []byte) string {
	scanner := newLineScanner(data)
	for scanner.scan() {
		line := scanner.line()
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "UID:") {
			idx := strings.Index(line, ":")
			if idx >= 0 {
				return strings.TrimSpace(line[idx+1:])
			}
		}
	}
	return ""
}

// vCardPropertyMatches checks if a vCard contains a property with the given name
// that matches the given text value (case-insensitive substring match).
// Property names in vCards may have parameters (e.g. EMAIL;TYPE=INTERNET:value).
func vCardPropertyMatches(data []byte, propName, textValue string) bool {
	if textValue == "" {
		return false
	}
	scanner := newLineScanner(data)
	searchValue := strings.ToLower(textValue)
	propUpper := strings.ToUpper(propName)

	// Handle multi-line vCard (lines starting with space/continuation)
	var currentLine strings.Builder

	flushLine := func() {
		line := currentLine.String()
		currentLine.Reset()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			return
		}
		// Find the colon separating property name (with optional params)
		// from value in trimmed itself: upper-casing can change byte lengths.
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx < 0 {
			return
		}
		propPart := strings.ToUpper(trimmed[:colonIdx])
		// Extract the base property name (before any ;)
		baseProp := propPart
		if semiIdx := strings.Index(propPart, ";"); semiIdx >= 0 {
			baseProp = propPart[:semiIdx]
		}
		if baseProp == propUpper {
			if colonIdx+1 < len(trimmed) {
				val := strings.ToLower(strings.TrimSpace(trimmed[colonIdx+1:]))
				if strings.Contains(val, searchValue) {
					scanner.matched = true
				}
			}
		}
	}

	for scanner.scan() {
		line := scanner.line()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// vCard line continuation: starts with space or tab
		if (trimmed[0] == ' ' || trimmed[0] == '\t') && currentLine.Len() > 0 {
			currentLine.WriteString(trimmed)
			continue
		}
		// Flush previous line
		if currentLine.Len() > 0 {
			flushLine()
		}
		if scanner.matched {
			return true
		}
		currentLine.WriteString(line)
	}
	// Flush last line
	if currentLine.Len() > 0 {
		flushLine()
	}
	return scanner.matched
}

// lineScanner helps iterate over vCard lines.
type lineScanner struct {
	lines   []string
	idx     int
	matched bool
}

func newLineScanner(data []byte) *lineScanner {
	return &lineScanner{lines: strings.Split(string(data), "\n")}
}

func (s *lineScanner) scan() bool {
	if s.idx < len(s.lines) {
		s.idx++
		return true
	}
	return false
}

func (s *lineScanner) line() string {
	return s.lines[s.idx-1]
}

// vCardItemToPropResp builds a propResp for a vCard Item.
func vCardItemToPropResp(item model.Item, href string) response {
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
			Getcontenttype:   strPtr("text/vcard; charset=utf-8"),
			Getetag:          &etag,
			Getlastmodified:  &lastMod,
			Creationdate:     &created,
		},
	}
}

// folderToAddressbookResp builds a propResp for an addressbook folder.
func folderToAddressbookResp(folder model.Folder, href string) response {
	etag := fmt.Sprintf("%q", fmt.Sprintf("%016x", 0))
	lastMod := formatHTTPTime(folder.UpdatedAt)
	created := formatXMLTime(folder.CreatedAt)
	displayName := folder.Name

	rt := resourceType{Collection: &empty{}, Addressbook: &empty{}}

	return response{
		Href:   href,
		Status: "HTTP/1.1 200 OK",
		Prop: &propResp{
			Displayname:     &displayName,
			ResourceType:    &rt,
			Getetag:         &etag,
			Getlastmodified: &lastMod,
			Creationdate:    &created,
		},
	}
}

// respondVCardData sends a vCard data response.
func respondVCardData(w http.ResponseWriter, data []byte, etag string, lastModified time.Time) {
	w.Header().Set("Content-Type", "text/vcard")
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", formatHTTPTime(lastModified))
	w.Header().Set("Cache-Control", "must-revalidate")
	w.Write(data)
}
