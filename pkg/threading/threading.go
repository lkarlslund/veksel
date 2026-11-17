// Package threading groups mail messages into conversations from their
// Message-ID, References, and In-Reply-To headers. IMAP THREAD, JMAP Thread
// ids, and the webmail conversation view share this one implementation.
package threading

import (
	"cmp"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"time"
)

// MaxParents bounds the ancestor IDs kept per message. Long References
// chains keep their root and most recent ancestors, which is what clients
// preserve when they trim the header (RFC 5322 §3.6.4).
const MaxParents = 32

// Message is the threading view of one message. IDs are canonical (see
// CanonicalID).
type Message struct {
	ID string
	// Parents lists ancestor IDs oldest first: References, then In-Reply-To.
	Parents []string
	Subject string
	Date    time.Time
}

// Options tunes Build.
type Options struct {
	// SubjectWindow, when positive, lets a reply-prefixed message that carries
	// no threading headers join the nearest-dated message with the same base
	// subject, provided the two dates are at most this far apart.
	SubjectWindow time.Duration
}

// CanonicalID strips angle brackets and lowercases a Message-ID; RFC 5256
// compares Message-IDs case-insensitively.
func CanonicalID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) >= 2 && id[0] == '<' && id[len(id)-1] == '>' {
		id = id[1 : len(id)-1]
	}
	return strings.ToLower(strings.TrimSpace(id))
}

// ParseIDs returns the canonical Message-IDs in a References or In-Reply-To
// value. Bracketed IDs may be run together; unbracketed values are split on
// whitespace and commas.
func ParseIDs(value string) []string {
	var ids []string
	if strings.Contains(value, "<") {
		for rest := value; ; {
			start := strings.IndexByte(rest, '<')
			if start < 0 {
				break
			}
			end := strings.IndexByte(rest[start:], '>')
			if end < 0 {
				break
			}
			if id := CanonicalID(rest[start : start+end+1]); id != "" {
				ids = append(ids, id)
			}
			rest = rest[start+end+1:]
		}
		return ids
	}
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n' }) {
		if id := CanonicalID(field); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// Parents returns the bounded, de-duplicated ancestor chain of a message.
func Parents(references, inReplyTo string) []string {
	ids := append(ParseIDs(references), ParseIDs(inReplyTo)...)
	seen := make(map[string]struct{}, len(ids))
	parents := ids[:0]
	for _, id := range ids {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			parents = append(parents, id)
		}
	}
	if len(parents) > MaxParents {
		parents = append(parents[:1], parents[len(parents)-MaxParents+1:]...)
	}
	return slices.Clip(parents)
}

var replyPrefixes = []string{"re:", "fw:", "fwd:", "aw:", "sv:", "vs:", "r:", "wg:"}

// BaseSubject removes reply and forward prefixes (Re:, Fw:, Fwd:, and common
// localized forms), preserving the remaining text's case.
func BaseSubject(subject string) string {
	base := strings.TrimSpace(subject)
	for {
		stripped := false
		lower := strings.ToLower(base)
		for _, prefix := range replyPrefixes {
			if strings.HasPrefix(lower, prefix) {
				base = strings.TrimSpace(base[len(prefix):])
				stripped = true
				break
			}
		}
		if !stripped {
			return base
		}
	}
}

// RootKey is a message's stable per-message thread key: the oldest known
// ancestor, else its own Message-ID, else its normalized subject. Messages of
// one well-formed conversation share it without consulting each other.
func RootKey(message Message) string {
	if len(message.Parents) > 0 {
		return message.Parents[0]
	}
	if message.ID != "" {
		return message.ID
	}
	return "subject:" + strings.ToLower(BaseSubject(message.Subject))
}

// ID is the opaque conversation identifier JMAP, IMAP OBJECTID, and webmail
// expose: a digest of the message's RootKey, shared by every message of a
// well-formed thread.
func ID(message Message) string {
	sum := sha256.Sum256([]byte(RootKey(message)))
	return fmt.Sprintf("thr-%x", sum[:12])
}

// Build groups messages into conversations and returns each conversation as
// indexes into messages, ordered by date (input order breaks ties).
// Conversations are ordered by their first member's input position.
//
// Messages connect through shared IDs, so replies to a missing parent still
// join each other. A message without threading headers joins by subject only
// when Options.SubjectWindow allows it.
func Build(messages []Message, options Options) [][]int {
	if len(messages) == 0 {
		return nil
	}
	sets := newUnion(len(messages))
	byID := make(map[string]int, len(messages))
	link := func(index int, id string) {
		if other, ok := byID[id]; ok {
			sets.join(index, other)
			return
		}
		byID[id] = index
	}
	for index, message := range messages {
		if message.ID != "" {
			link(index, message.ID)
		}
		for _, parent := range message.Parents {
			link(index, parent)
		}
	}
	if options.SubjectWindow > 0 {
		joinBySubject(messages, sets, options.SubjectWindow)
	}
	groups := make(map[int][]int)
	var roots []int
	for index := range messages {
		root := sets.find(index)
		if _, ok := groups[root]; !ok {
			roots = append(roots, root)
		}
		groups[root] = append(groups[root], index)
	}
	threads := make([][]int, 0, len(roots))
	for _, root := range roots {
		members := groups[root]
		slices.SortStableFunc(members, func(a, b int) int {
			return cmp.Or(messages[a].Date.Compare(messages[b].Date), cmp.Compare(a, b))
		})
		threads = append(threads, members)
	}
	return threads
}

// joinBySubject attaches each header-less reply to the nearest-dated message
// sharing its base subject within window, preferring an earlier message.
func joinBySubject(messages []Message, sets *union, window time.Duration) {
	bySubject := make(map[string][]int)
	for index, message := range messages {
		if base := strings.ToLower(BaseSubject(message.Subject)); base != "" {
			bySubject[base] = append(bySubject[base], index)
		}
	}
	for _, group := range bySubject {
		if len(group) < 2 {
			continue
		}
		slices.SortStableFunc(group, func(a, b int) int { return messages[a].Date.Compare(messages[b].Date) })
		for position, index := range group {
			message := messages[index]
			if len(message.Parents) > 0 || BaseSubject(message.Subject) == strings.TrimSpace(message.Subject) {
				continue
			}
			within := func(other int) bool {
				gap := message.Date.Sub(messages[other].Date)
				return gap <= window && gap >= -window
			}
			if position > 0 && within(group[position-1]) {
				sets.join(index, group[position-1])
			} else if position+1 < len(group) && within(group[position+1]) {
				sets.join(index, group[position+1])
			}
		}
	}
}

type union struct{ parent []int }

func newUnion(size int) *union {
	parent := make([]int, size)
	for index := range parent {
		parent[index] = index
	}
	return &union{parent: parent}
}

func (u *union) find(index int) int {
	for u.parent[index] != index {
		u.parent[index] = u.parent[u.parent[index]]
		index = u.parent[index]
	}
	return index
}

func (u *union) join(a, b int) {
	a, b = u.find(a), u.find(b)
	if a == b {
		return
	}
	// The smaller index wins, keeping roots in input order.
	if b < a {
		a, b = b, a
	}
	u.parent[b] = a
}
