package sieve

import (
	"net/mail"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
)

// addressHeaders are the header fields the address test parses as address
// lists (RFC 5228 section 5.1 names the minimum set). Other headers hold
// no addresses for the address test.
var addressHeaders = map[string]bool{
	"from": true, "sender": true, "reply-to": true, "to": true, "cc": true, "bcc": true,
	"resent-from": true, "resent-sender": true, "resent-to": true, "resent-cc": true, "resent-bcc": true,
	"return-path": true, "delivered-to": true, "envelope-to": true, "x-original-to": true,
	"errors-to": true, "mail-followup-to": true, "mail-reply-to": true,
	"disposition-notification-to": true, "original-recipient": true,
}

// decodeHeader returns a header value as RFC 5228 section 2.7.2 compares
// it: RFC 2047 encoded words decoded, surrounding white space removed.
func decodeHeader(value string) string {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "=?") {
		if decoded, err := model.HeaderWordDecoder.DecodeHeader(value); err == nil {
			value = decoded
		}
	}
	return value
}

// parseAddressList returns the addr-specs of an address-list header,
// leniently: group syntax yields its members, display names and comments
// are dropped, and an element that does not parse is used as written with
// any angle brackets removed. It takes the raw header value: encoded words
// may only appear in display names, which are dropped, and decoding first
// could turn an encoded comma into a list separator.
func parseAddressList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if list, err := mail.ParseAddressList(value); err == nil {
		out := make([]string, 0, len(list))
		for _, address := range list {
			out = append(out, address.Address)
		}
		return out
	}
	var out []string
	for _, element := range splitAddressList(value) {
		if colon := groupColon(element); colon >= 0 {
			element = strings.TrimSpace(element[colon+1:])
		}
		element = strings.TrimSpace(strings.TrimSuffix(element, ";"))
		if element == "" {
			continue
		}
		if address, err := mail.ParseAddress(element); err == nil {
			out = append(out, address.Address)
			continue
		}
		if open := strings.LastIndexByte(element, '<'); open >= 0 {
			if end := strings.IndexByte(element[open:], '>'); end > 0 {
				element = element[open+1 : open+end]
			}
		}
		if element = strings.TrimSpace(element); element != "" {
			out = append(out, element)
		}
	}
	return out
}

// splitAddressList splits at commas and group-ending semicolons outside
// quoted strings, comments, and angle brackets.
func splitAddressList(value string) []string {
	var out []string
	depth, angle, quoted, start := 0, false, false, 0
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case quoted:
			if c == '\\' {
				i++
			} else if c == '"' {
				quoted = false
			}
		case c == '"':
			quoted = true
		case c == '(':
			depth++
		case c == ')' && depth > 0:
			depth--
		case depth > 0:
		case c == '<':
			angle = true
		case c == '>':
			angle = false
		case (c == ',' || c == ';') && !angle:
			out = append(out, value[start:i])
			start = i + 1
		}
	}
	return append(out, value[start:])
}

// groupColon returns the index of a group's display-name colon, or -1.
func groupColon(element string) int {
	quoted := false
	for i := 0; i < len(element); i++ {
		switch c := element[i]; {
		case quoted && c == '\\':
			i++
		case c == '"':
			quoted = !quoted
		case quoted:
		case c == '<' || c == '@':
			return -1
		case c == ':':
			return i
		}
	}
	return -1
}

// splitAddress separates an addr-spec at its last "@". An address without
// "@" is all local part.
func splitAddress(address string) (local, domain string, hasDomain bool) {
	if at := strings.LastIndexByte(address, '@'); at >= 0 {
		return address[:at], address[at+1:], true
	}
	return address, "", false
}

// addressPart extracts part from address; ok is false when the part does
// not exist, which makes every comparison against it fail (RFC 5233
// section 4 for :detail).
func addressPart(address string, part AddressPart, delimiters string) (string, bool) {
	local, domain, _ := splitAddress(address)
	switch part {
	case PartLocalPart:
		return local, true
	case PartDomain:
		return domain, true
	case PartUser, PartDetail:
		user, detail, ok := model.SplitSubaddress(local, delimiters)
		if part == PartUser {
			return user, true
		}
		return detail, ok
	}
	return address, true
}
