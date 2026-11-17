package imap

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// NOTIFY (RFC 5465). A session that sets NOTIFY watches its whole account
// (see wake.go) and reports, while idle and between commands, the changes its
// event groups select. The selected mailbox gets EXISTS, EXPUNGE, and FETCH
// responses from the mailbox view; other mailboxes get STATUS and mailbox
// names and subscriptions get LIST, both from comparing the account's folders
// with a snapshot of what the session last saw. Events are derived from state,
// never queued, so they cannot overflow and are never reported twice.

type notifyFilterKind int

const (
	filterSelected notifyFilterKind = iota
	filterInboxes
	filterPersonal
	filterSubscribed
	filterSubtree
	filterMailboxes
)

// notifyEvents is the set of events one group reports.
type notifyEvents struct {
	messageNew, messageExpunge, flagChange bool
	mailboxName, subscriptionChange        bool
	// newAttrs are the FETCH items sent for new messages in the selected
	// mailbox, as written by the client.
	newAttrs string
}

type notifyGroup struct {
	kind      notifyFilterKind
	mailboxes []string
	events    notifyEvents
}

// matches reports whether the group's mailbox filter selects a mailbox.
func (g notifyGroup) matches(path string, subscribed, selected bool) bool {
	switch g.kind {
	case filterSelected:
		return selected
	case filterInboxes:
		return strings.EqualFold(path, "INBOX")
	case filterPersonal:
		return true
	case filterSubscribed:
		return subscribed
	case filterSubtree:
		for _, name := range g.mailboxes {
			if pathWithin(path, name) {
				return true
			}
		}
	case filterMailboxes:
		for _, name := range g.mailboxes {
			if samePath(path, name) {
				return true
			}
		}
	}
	return false
}

func samePath(a, b string) bool {
	if strings.EqualFold(a, "INBOX") && strings.EqualFold(b, "INBOX") {
		return true
	}
	return a == b
}

func pathWithin(path, root string) bool {
	if samePath(path, root) {
		return true
	}
	if head, rest, found := strings.Cut(path, "/"); found && strings.EqualFold(head, "INBOX") {
		path = "INBOX/" + rest
	}
	if strings.EqualFold(root, "INBOX") {
		root = "INBOX"
	}
	return strings.HasPrefix(path, root+"/")
}

// notifyState is a session's active NOTIFY subscription. Its methods accept
// a nil state, which watches nothing.
type notifyState struct {
	groups []notifyGroup
	// folders is every folder the user owns as last seen, by ID.
	folders map[string]model.Folder
	// maxUID is the highest UID of the selected mailbox already reported, so
	// a MessageNew fetch covers only newer messages.
	maxUID uint32
}

// match returns the first group that selects the mailbox for an event.
func (n *notifyState) match(path string, subscribed, selected bool, wants func(notifyEvents) bool) *notifyGroup {
	if n == nil {
		return nil
	}
	for index := range n.groups {
		if wants(n.groups[index].events) && n.groups[index].matches(path, subscribed, selected) {
			return &n.groups[index]
		}
	}
	return nil
}

// coversSelected reports whether the subscription reports selected-mailbox
// changes, which then replace IDLE's own registration.
func (n *notifyState) coversSelected() bool {
	if n == nil {
		return false
	}
	return slices.ContainsFunc(n.groups, func(g notifyGroup) bool {
		return g.kind == filterSelected && (g.events.messageNew || g.events.messageExpunge || g.events.flagChange)
	})
}

// watchesFolders reports whether any group reports on mailboxes other than
// the selected one.
func (n *notifyState) watchesFolders() bool {
	return n != nil && slices.ContainsFunc(n.groups, func(g notifyGroup) bool {
		e := g.events
		return e.mailboxName || e.subscriptionChange || g.kind != filterSelected && messageEvents(e)
	})
}

// watchesNames reports whether any group reports mailbox names or
// subscriptions.
func (n *notifyState) watchesNames() bool {
	return n != nil && slices.ContainsFunc(n.groups, func(g notifyGroup) bool {
		return g.events.mailboxName || g.events.subscriptionChange
	})
}

// messageEvents selects the groups reporting any message event.
func messageEvents(e notifyEvents) bool { return e.messageNew || e.messageExpunge || e.flagChange }

// rebase records the selected mailbox's current messages as already reported.
func (n *notifyState) rebase(items []model.Item) {
	if n == nil {
		return
	}
	n.maxUID = 0
	for _, item := range items {
		n.maxUID = max(n.maxUID, item.UID)
	}
}

// notifyRequest is a parsed NOTIFY command.
type notifyRequest struct {
	none   bool
	status bool
	groups []notifyGroup
}

var errNotifySyntax = errors.New("invalid NOTIFY syntax")

// badEventError reports events the server does not implement.
type badEventError struct{ events []string }

func (e badEventError) Error() string {
	return "unsupported NOTIFY events: " + strings.Join(e.events, " ")
}

// sexp is a parenthesized-list node of a NOTIFY command.
type sexp struct {
	atom   string
	list   []sexp
	isList bool
	raw    string
}

// maxSexpDepth bounds list nesting in NOTIFY text. The reader recurses once
// per level, and legitimate event groups nest only a few levels deep.
const maxSexpDepth = 32

type sexpReader struct {
	text  string
	pos   int
	depth int
}

func (r *sexpReader) skipSpace() {
	for r.pos < len(r.text) && (r.text[r.pos] == ' ' || r.text[r.pos] == '\t') {
		r.pos++
	}
}

func (r *sexpReader) done() bool {
	r.skipSpace()
	return r.pos >= len(r.text)
}

func (r *sexpReader) next() (sexp, error) {
	r.skipSpace()
	if r.pos >= len(r.text) {
		return sexp{}, errNotifySyntax
	}
	start := r.pos
	switch r.text[r.pos] {
	case '(':
		if r.depth >= maxSexpDepth {
			return sexp{}, errNotifySyntax
		}
		r.depth++
		defer func() { r.depth-- }()
		r.pos++
		node := sexp{isList: true}
		for {
			r.skipSpace()
			if r.pos >= len(r.text) {
				return sexp{}, errNotifySyntax
			}
			if r.text[r.pos] == ')' {
				r.pos++
				node.raw = r.text[start:r.pos]
				return node, nil
			}
			child, err := r.next()
			if err != nil {
				return sexp{}, err
			}
			node.list = append(node.list, child)
		}
	case ')':
		return sexp{}, errNotifySyntax
	case '"':
		r.pos++
		var value strings.Builder
		for r.pos < len(r.text) {
			c := r.text[r.pos]
			r.pos++
			switch c {
			case '"':
				return sexp{atom: value.String(), raw: r.text[start:r.pos]}, nil
			case '\\':
				if r.pos >= len(r.text) {
					return sexp{}, errNotifySyntax
				}
				c = r.text[r.pos]
				r.pos++
				fallthrough
			default:
				value.WriteByte(c)
			}
		}
		return sexp{}, errNotifySyntax
	}
	// An atom may carry a bracketed section such as BODY.PEEK[HEADER.FIELDS (From)].
	depth := 0
	for r.pos < len(r.text) {
		c := r.text[r.pos]
		if depth == 0 && (c == ' ' || c == '\t' || c == '(' || c == ')') {
			break
		}
		switch c {
		case '[':
			depth++
		case ']':
			depth = max(0, depth-1)
		}
		r.pos++
	}
	text := r.text[start:r.pos]
	return sexp{atom: text, raw: text}, nil
}

// parseNotify parses the NOTIFY command text. wire converts mailbox names
// from their wire form.
func parseNotify(text string, wire func(string) (string, error)) (notifyRequest, error) {
	reader := &sexpReader{text: text}
	head, err := reader.next()
	if err != nil || head.isList {
		return notifyRequest{}, errNotifySyntax
	}
	switch strings.ToUpper(head.atom) {
	case "NONE":
		if !reader.done() {
			return notifyRequest{}, errNotifySyntax
		}
		return notifyRequest{none: true}, nil
	case "SET":
	default:
		return notifyRequest{}, errNotifySyntax
	}
	var request notifyRequest
	var unsupported []string
	for !reader.done() {
		node, err := reader.next()
		if err != nil {
			return notifyRequest{}, err
		}
		if !node.isList {
			if strings.EqualFold(node.atom, "STATUS") && len(request.groups) == 0 && !request.status {
				request.status = true
				continue
			}
			return notifyRequest{}, errNotifySyntax
		}
		group, groupUnsupported, err := parseNotifyGroup(node.list, wire)
		if err != nil {
			return notifyRequest{}, err
		}
		unsupported = append(unsupported, groupUnsupported...)
		request.groups = append(request.groups, group)
	}
	if len(request.groups) == 0 {
		return notifyRequest{}, errNotifySyntax
	}
	if len(unsupported) > 0 {
		return notifyRequest{}, badEventError{events: unsupported}
	}
	return request, nil
}

func parseNotifyGroup(elements []sexp, wire func(string) (string, error)) (notifyGroup, []string, error) {
	var group notifyGroup
	if len(elements) < 2 || elements[0].isList {
		return group, nil, errNotifySyntax
	}
	switch strings.ToLower(elements[0].atom) {
	case "selected", "selected-delayed":
		group.kind = filterSelected
	case "inboxes":
		group.kind = filterInboxes
	case "personal":
		group.kind = filterPersonal
	case "subscribed":
		group.kind = filterSubscribed
	case "subtree", "mailboxes":
		group.kind = filterSubtree
		if strings.EqualFold(elements[0].atom, "mailboxes") {
			group.kind = filterMailboxes
		}
		if len(elements) != 3 {
			return group, nil, errNotifySyntax
		}
		names := []sexp{elements[1]}
		if elements[1].isList {
			names = elements[1].list
		}
		if len(names) == 0 {
			return group, nil, errNotifySyntax
		}
		for _, name := range names {
			if name.isList {
				return group, nil, errNotifySyntax
			}
			decoded, err := wire(name.atom)
			if err != nil {
				return group, nil, errNotifySyntax
			}
			group.mailboxes = append(group.mailboxes, decoded)
		}
		elements = []sexp{elements[0], elements[2]}
	default:
		return group, nil, errNotifySyntax
	}
	if len(elements) != 2 {
		return group, nil, errNotifySyntax
	}
	unsupported, err := parseNotifyEvents(elements[1], &group.events)
	return group, unsupported, err
}

func parseNotifyEvents(node sexp, events *notifyEvents) ([]string, error) {
	if !node.isList {
		if strings.EqualFold(node.atom, "NONE") {
			return nil, nil
		}
		return nil, errNotifySyntax
	}
	var unsupported []string
	for index := 0; index < len(node.list); index++ {
		event := node.list[index]
		if event.isList {
			return nil, errNotifySyntax
		}
		switch strings.ToLower(event.atom) {
		case "messagenew":
			events.messageNew = true
			if index+1 < len(node.list) && node.list[index+1].isList {
				index++
				events.newAttrs = node.list[index].raw
			}
		case "messageexpunge":
			events.messageExpunge = true
		case "flagchange":
			events.flagChange = true
		case "mailboxname":
			events.mailboxName = true
		case "subscriptionchange":
			events.subscriptionChange = true
		case "annotationchange", "mailboxmetadatachange", "servermetadatachange":
			unsupported = append(unsupported, event.atom)
		default:
			return nil, errNotifySyntax
		}
	}
	// RFC 5465 5.2: the message events only make sense together.
	if events.flagChange && !(events.messageNew && events.messageExpunge) ||
		events.messageNew != events.messageExpunge {
		return nil, errNotifySyntax
	}
	return unsupported, nil
}

// cmdNotify handles NOTIFY SET and NOTIFY NONE (RFC 5465).
func (s *Session) cmdNotify(tag string, args []string) {
	if len(args) != 1 {
		s.sendBAD(tag, "Expected: NOTIFY NONE | NOTIFY SET [STATUS] event-groups")
		return
	}
	request, err := parseNotify(args[0], s.mailboxFromWire)
	var unsupported badEventError
	switch {
	case errors.As(err, &unsupported):
		s.sendNO(tag, fmt.Sprintf("[BADEVENT (%s)] %s", strings.Join(unsupported.events, " "), err))
		return
	case err != nil:
		s.sendBAD(tag, err.Error())
		return
	}
	s.stopNotify()
	if request.none {
		s.sendOK(tag, "NOTIFY completed")
		return
	}
	// Register before reading the snapshot so nothing that changes once the
	// client has its acknowledgement is missed.
	state := &notifyState{groups: request.groups}
	s.notify = state
	s.refreshWake()
	s.takeWake()
	state.folders, _ = s.ownedFolders()
	state.rebase(s.view)
	if request.status {
		s.sendNotifyStatuses()
	}
	s.sendOK(tag, "NOTIFY completed")
}

// ownedFolders lists every folder the user owns, by ID.
func (s *Session) ownedFolders() (map[string]model.Folder, error) {
	folders, err := s.cfg.FolderSpace.ListFolders(*s.ctx, s.access(), service.FolderQuery{})
	if err != nil {
		return nil, err
	}
	owned := make(map[string]model.Folder, len(folders))
	for _, folder := range folders {
		if folder.UserID == s.userID {
			owned[folder.ID] = folder
		}
	}
	return owned, nil
}

// sortedFolders returns folders in path order, so reports are stable.
func sortedFolders(folders map[string]model.Folder) []model.Folder {
	list := slices.Collect(maps.Values(folders))
	slices.SortFunc(list, func(a, b model.Folder) int { return strings.Compare(a.Path, b.Path) })
	return list
}

// sendNotifyStatuses answers NOTIFY SET STATUS with the state of every
// non-selected mailbox the groups report message changes for.
func (s *Session) sendNotifyStatuses() {
	for _, folder := range sortedFolders(s.notify.folders) {
		if folder.Type != model.FolderTypeMail || folder.ID == s.selectedFolderID {
			continue
		}
		if s.notify.match(folder.Path, folder.Subscribed, false, func(e notifyEvents) bool { return e.messageNew || e.messageExpunge }) != nil {
			s.sendMailboxStatus(folder, false)
		}
	}
}

func (s *Session) sendMailboxStatus(folder model.Folder, withUnseen bool) {
	items := []string{"MESSAGES", "UIDNEXT", "UIDVALIDITY"}
	if withUnseen {
		items = append(items, "UNSEEN")
	}
	values, err := s.statusValues(folder, items)
	if err != nil {
		return
	}
	s.sendUntagged(fmt.Sprintf("* STATUS %s (%s)", s.mailboxToWire(folder.Path), strings.Join(values, " ")))
}

// stopNotify drops the session's NOTIFY subscription.
func (s *Session) stopNotify() {
	if s.notify != nil {
		s.notify = nil
		s.refreshWake()
	}
}

// readCommandLine reads the next command. While NOTIFY is active a wake
// interrupts the blocked read, so events reach the otherwise silent
// connection as they happen.
func (s *Session) readCommandLine() (string, error) {
	if line, ok, err := s.pendingIdleLine(); ok || err != nil {
		return line, err
	}
	conn, ok := s.conn.(interface{ SetReadDeadline(time.Time) error })
	if s.notify == nil || s.wake == nil || s.compressed || !ok {
		return s.readLine()
	}
	limit := time.Now().Add(10 * time.Minute)
	var partial []byte
	for {
		s.reportChanges()
		_ = conn.SetReadDeadline(limit)
		s.wake.arm(func() { _ = conn.SetReadDeadline(time.Now()) })
		var err error
		partial, err = appendLineChunk(s.rw.Reader, partial)
		// Once disarmed no interrupt can move the deadline again.
		s.wake.disarm()
		_ = conn.SetReadDeadline(limit)
		var netErr net.Error
		switch {
		case err == nil:
			return strings.TrimRight(string(partial), "\r\n"), nil
		case errors.As(err, &netErr) && netErr.Timeout() && time.Now().Before(limit):
			// Woken: let the rest of a burst arrive, then report it.
			time.Sleep(wakeSettle)
		default:
			return "", err
		}
	}
}

// sendNewMessageAttrs sends the MessageNew fetch attributes for the
// selected mailbox's messages not yet reported to NOTIFY.
func (s *Session) sendNewMessageAttrs() {
	if s.notify == nil {
		return
	}
	reported := s.notify.maxUID
	s.notify.rebase(s.view)
	group := s.notify.match(s.selectedFolder.Path, s.selectedFolder.Subscribed, true, func(e notifyEvents) bool { return e.messageNew })
	if group == nil || group.events.newAttrs == "" {
		return
	}
	for index, item := range s.view {
		if item.UID > reported {
			_ = s.fetchItem(index+1, item, group.events.newAttrs)
		}
	}
}

// reportNotifyFolders reports the changes NOTIFY selects outside the
// selected mailbox: STATUS for message changes and LIST for mailbox names
// and subscriptions. It reads the account's folders only when a touched
// folder is one a group could report on.
func (s *Session) reportNotifyFolders(touched map[string]struct{}, all bool) {
	n := s.notify
	if !n.watchesFolders() || !all && !s.foldersRelevant(touched) {
		return
	}
	current, err := s.ownedFolders()
	if err != nil {
		return
	}
	previous := n.folders
	n.folders = current
	var mail []model.Folder
	for _, folder := range sortedFolders(current) {
		if folder.Type == model.FolderTypeMail {
			mail = append(mail, folder)
		}
	}
	if n.watchesNames() {
		s.reportMailboxNames(previous, current, mail)
	}
	for _, folder := range mail {
		before, known := previous[folder.ID]
		if _, hit := touched[folder.ID]; !known || folder.ID == s.selectedFolderID || !all && !hit {
			continue
		}
		if _, own := s.ownFolders[folder.ID]; own {
			continue
		}
		added := folder.NextUID > before.NextUID
		expunged := before.ItemCount+int64(folder.NextUID-before.NextUID) > folder.ItemCount
		flagged := !added && !expunged && folder.HighestModSeq != before.HighestModSeq
		group := n.match(folder.Path, folder.Subscribed, false, func(e notifyEvents) bool {
			return added && e.messageNew || expunged && e.messageExpunge || flagged && e.flagChange
		})
		if group != nil {
			s.sendMailboxStatus(folder, flagged)
		}
	}
}

// foldersRelevant reports whether a touched folder is one NOTIFY could
// report on, judged from the snapshot without reading the store. A folder
// the snapshot does not know may be new.
func (s *Session) foldersRelevant(touched map[string]struct{}) bool {
	n := s.notify
	for folderID := range touched {
		folder, known := n.folders[folderID]
		switch {
		case !known:
			return true
		case folder.Type != model.FolderTypeMail:
		case n.watchesNames():
			return true
		case folderID != s.selectedFolderID && n.match(folder.Path, folder.Subscribed, false, messageEvents) != nil:
			return true
		}
	}
	return false
}

// reportMailboxNames reports mailboxes created, deleted, renamed, and
// (un)subscribed since the previous snapshot, other than by this session.
func (s *Session) reportMailboxNames(previous, current map[string]model.Folder, mail []model.Folder) {
	n := s.notify
	names := func(e notifyEvents) bool { return e.mailboxName }
	for _, folder := range mail {
		before, known := previous[folder.ID]
		switch {
		case s.ownPath(folder.Path) || known && s.ownPath(before.Path):
		case !known:
			if n.match(folder.Path, folder.Subscribed, false, names) != nil {
				s.sendMailboxList(folder, mail, "")
			}
		case before.Path != folder.Path:
			if n.match(folder.Path, folder.Subscribed, false, names) != nil || n.match(before.Path, before.Subscribed, false, names) != nil {
				s.sendMailboxList(folder, mail, before.Path)
			}
		case before.Subscribed != folder.Subscribed:
			if n.match(folder.Path, true, false, func(e notifyEvents) bool { return e.subscriptionChange }) != nil {
				s.sendMailboxList(folder, mail, "")
			}
		}
	}
	for _, before := range sortedFolders(previous) {
		if _, exists := current[before.ID]; exists || before.Type != model.FolderTypeMail || s.ownPath(before.Path) {
			continue
		}
		if n.match(before.Path, before.Subscribed, false, names) != nil {
			s.sendUntagged(fmt.Sprintf(`* LIST (\NonExistent) "/" %s`, s.mailboxToWire(before.Path)))
		}
	}
}

// sendMailboxList sends the LIST response for a mailbox, naming its
// previous name after a rename.
func (s *Session) sendMailboxList(folder model.Folder, mail []model.Folder, oldPath string) {
	line := fmt.Sprintf(`* LIST (%s) "/" %s`, strings.Join(s.listFolderAttrs(folder, mail), " "), s.mailboxToWire(folder.Path))
	if oldPath != "" {
		line += fmt.Sprintf(` ("OLDNAME" (%s))`, s.mailboxToWire(oldPath))
	}
	s.sendUntagged(line)
}
