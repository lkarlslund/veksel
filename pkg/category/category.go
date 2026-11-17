// Package category implements the master category model shared by mail,
// events, tasks, and contacts. A category is a name and a color kept in the
// owner's preferences; items carry only the name, in the form their protocol
// round-trips: an IMAP keyword on a message, CATEGORIES on an iCalendar
// component, and CATEGORIES on a vCard.
package category

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	calendarcore "github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
)

const (
	// MaxCategories bounds one master list.
	MaxCategories = 100
	// MaxNameBytes bounds one category name.
	MaxNameBytes = 64
)

// ErrUnsupportedFolder rejects categories on folders whose items have no
// category representation.
var ErrUnsupportedFolder = errors.New("items in this folder cannot carry categories")

// thunderbirdLabels are Thunderbird's built-in tags. A category with one of
// these names uses the matching keyword, so the default tags round-trip.
var thunderbirdLabels = [...]struct{ keyword, name string }{
	{"$label1", "Important"}, {"$label2", "Work"}, {"$label3", "Personal"}, {"$label4", "To Do"}, {"$label5", "Later"},
}

var colorPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// Keyword returns the IMAP keyword that represents a category on a message.
// Thunderbird's default tag names map to $label1..$label5; any other name
// follows Thunderbird's tag key derivation (lower-cased, modified UTF-7, and
// characters that are not valid in an IMAP atom replaced by "_"), so tags
// created in Thunderbird and here meet on the same keyword.
func Keyword(name string) string {
	name = strings.TrimSpace(name)
	for _, label := range thunderbirdLabels {
		if strings.EqualFold(label.name, name) {
			return label.keyword
		}
	}
	encoded := modifiedUTF7(strings.ToLower(name))
	return strings.Map(func(r rune) rune {
		if r <= ' ' || r >= 0x7f || strings.ContainsRune(`()/{}[]%*<>\"`, r) {
			return '_'
		}
		return r
	}, encoded)
}

// NameForKeyword resolves a message keyword to a category name from the
// list, falling back to Thunderbird's default tag names.
func NameForKeyword(keyword string, list []model.Category) (string, bool) {
	if keyword == "" || strings.HasPrefix(keyword, `\`) {
		return "", false
	}
	for _, entry := range list {
		if strings.EqualFold(Keyword(entry.Name), keyword) {
			return entry.Name, true
		}
	}
	for _, label := range thunderbirdLabels {
		if strings.EqualFold(label.keyword, keyword) {
			return label.name, true
		}
	}
	return "", false
}

// Normalize validates a master list: names are trimmed, non-empty, unique
// without regard to case, and bounded; colors are empty or #rrggbb.
func Normalize(list []model.Category) ([]model.Category, error) {
	if len(list) > MaxCategories {
		return nil, fmt.Errorf("at most %d categories are allowed", MaxCategories)
	}
	result := make([]model.Category, 0, len(list))
	for _, entry := range list {
		name := strings.Join(strings.Fields(entry.Name), " ")
		if name == "" {
			return nil, errors.New("category names cannot be empty")
		}
		if len(name) > MaxNameBytes || !utf8.ValidString(name) || strings.ContainsAny(name, ",;\\") {
			return nil, fmt.Errorf("category %q must be at most %d bytes without commas, semicolons, or backslashes", name, MaxNameBytes)
		}
		if slices.ContainsFunc(result, func(existing model.Category) bool { return strings.EqualFold(existing.Name, name) }) {
			return nil, fmt.Errorf("category %q is listed twice", name)
		}
		color := strings.ToLower(strings.TrimSpace(entry.Color))
		if color != "" && !colorPattern.MatchString(color) {
			return nil, fmt.Errorf("category %q color must be #rrggbb", name)
		}
		result = append(result, model.Category{Name: name, Color: color})
	}
	return result, nil
}

// Supported reports whether items of the folder type carry categories.
func Supported(folderType model.FolderType) bool {
	switch folderType {
	case model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeTasks, model.FolderTypeContacts:
		return true
	}
	return false
}

// ItemCategories returns the category names an item carries. Message
// keywords resolve through the list; only keywords that name a category (or
// a Thunderbird default tag) count.
func ItemCategories(folderType model.FolderType, item model.Item, list []model.Category) []string {
	switch folderType {
	case model.FolderTypeMail:
		var names []string
		for _, flag := range item.Flags {
			if name, ok := NameForKeyword(flag, list); ok && !containsFold(names, name) {
				names = append(names, name)
			}
		}
		return names
	case model.FolderTypeCalendar, model.FolderTypeTasks:
		return calendarcore.ItemCategories(item.Data)
	case model.FolderTypeContacts:
		return model.ParseVCard(item.Data).Categories
	}
	return nil
}

// Has reports whether an item carries the named category.
func Has(folderType model.FolderType, item model.Item, name string) bool {
	if folderType == model.FolderTypeMail {
		keyword := Keyword(name)
		return slices.ContainsFunc(item.Flags, func(flag string) bool { return strings.EqualFold(flag, keyword) })
	}
	return containsFold(ItemCategories(folderType, item, nil), name)
}

// Change is the payload and flags of an item after a category change.
type Change struct {
	Data    []byte
	Flags   []string
	Changed bool
}

// Apply adds or removes one category. Messages change keywords only;
// calendar objects and cards change their CATEGORIES property only.
func Apply(folderType model.FolderType, item model.Item, name string, add bool) (Change, error) {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" || len(name) > MaxNameBytes {
		return Change{}, errors.New("a category name of at most 64 bytes is required")
	}
	change := Change{Data: item.Data, Flags: slices.Clone(item.Flags)}
	if folderType == model.FolderTypeMail {
		keyword := Keyword(name)
		present := slices.ContainsFunc(change.Flags, func(flag string) bool { return strings.EqualFold(flag, keyword) })
		switch {
		case add && !present:
			change.Flags, change.Changed = append(change.Flags, keyword), true
		case !add && present:
			change.Flags = slices.DeleteFunc(change.Flags, func(flag string) bool { return strings.EqualFold(flag, keyword) })
			change.Changed = true
		}
		return change, nil
	}
	if !Supported(folderType) {
		return Change{}, ErrUnsupportedFolder
	}
	current := ItemCategories(folderType, item, nil)
	next := slices.Clone(current)
	present := containsFold(current, name)
	switch {
	case add && !present:
		next = append(next, name)
	case !add && present:
		next = slices.DeleteFunc(next, func(value string) bool { return strings.EqualFold(value, name) })
	default:
		return change, nil
	}
	var err error
	if folderType == model.FolderTypeContacts {
		change.Data, err = model.PatchContactCategories(item.Data, next)
	} else {
		change.Data, err = calendarcore.ReplaceCategories(item.Data, next)
	}
	if err != nil {
		return Change{}, err
	}
	change.Changed = true
	return change, nil
}

func containsFold(values []string, value string) bool {
	return slices.ContainsFunc(values, func(candidate string) bool { return strings.EqualFold(candidate, value) })
}

// modifiedUTF7 encodes non-ASCII runs as IMAP modified UTF-7 (RFC 3501
// 5.1.3), as Thunderbird does for tag keys.
func modifiedUTF7(value string) string {
	var encoded strings.Builder
	var run []rune
	flush := func() {
		if len(run) == 0 {
			return
		}
		units := utf16.Encode(run)
		raw := make([]byte, len(units)*2)
		for index, unit := range units {
			binary.BigEndian.PutUint16(raw[index*2:], unit)
		}
		encoded.WriteByte('&')
		encoded.WriteString(strings.ReplaceAll(base64.RawStdEncoding.EncodeToString(raw), "/", ","))
		encoded.WriteByte('-')
		run = run[:0]
	}
	for _, character := range value {
		if character >= 0x20 && character <= 0x7e {
			flush()
			if character == '&' {
				encoded.WriteString("&-")
			} else {
				encoded.WriteRune(character)
			}
			continue
		}
		run = append(run, character)
	}
	flush()
	return encoded.String()
}
