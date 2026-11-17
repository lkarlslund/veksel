package pop3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/proto"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// State represents the POP3 session state.
type State int

const (
	StateAuthorization State = iota
	StateTransaction
	StateUpdate
)

func (s State) String() string {
	switch s {
	case StateAuthorization:
		return "authorization"
	case StateTransaction:
		return "transaction"
	case StateUpdate:
		return "update"
	default:
		return "unknown"
	}
}

// session represents a single POP3 connection.
type session struct {
	id      uint64
	cfg     *Config
	p       *proto.Conn
	tracked *proto.Session // shutdown tracking; nil outside an accept loop
	// ctx carries the client IP so credential checks can throttle failures.
	ctx context.Context

	state  State
	secure bool

	// USER command buffer
	userName string

	// authenticated user
	userID string

	// folder (INBOX)
	folder model.Folder

	// deletion set (message index -> item ID)
	deleted map[int]string

	// snapshot is the maildrop listing message numbers refer to; nil until
	// the first transaction command loads it.
	snapshot []model.Item

	// authExchange is the AUTH PLAIN/LOGIN exchange awaiting a client
	// response, or nil.
	authExchange *auth.PasswordExchange

	// logger
	logger *log.Logger

	// done signals the run loop to exit
	done bool
}

func newSession(id uint64, cfg *Config, conn net.Conn) *session {
	return &session{
		id:      id,
		cfg:     cfg,
		p:       proto.New(conn),
		ctx:     ratelimit.WithClientIP(context.Background(), ratelimit.AddrIP(conn.RemoteAddr().String())),
		state:   StateAuthorization,
		secure:  cfg.ImplicitTLS,
		deleted: make(map[int]string),
		logger:  logger.With("session", id),
		done:    false,
	}
}

// run is the main session loop.
func (s *session) run() {
	defer s.p.Underlying().Close()

	// Send greeting
	if s.cfg.ImplicitTLS {
		// Upgrade to TLS before greeting
		s.p.ReplaceConn(tls.Server(s.p.Underlying(), s.cfg.TLSConfig))
	}
	s.extendDeadline()
	s.send("+OK " + s.greeting())

	for {
		if s.done {
			return
		}
		s.extendDeadline()
		s.tracked.SetIdle(true)
		line, err := s.p.ReadLine()
		s.tracked.SetIdle(false)
		if err != nil {
			if errors.Is(err, proto.ErrLineTooLong) {
				s.send("-ERR Line too long")
			}
			if err != io.EOF {
				s.logger.Debug("pop3: read error", "error", err)
			}
			return
		}

		if len(line) == 0 {
			continue
		}

		s.handleLine(line)
	}
}

// extendDeadline arms the autologout timer (RFC 1939 section 3) for the next
// command and bounds writing its response. The underlying connection is read
// on every call because STLS replaces it.
func (s *session) extendDeadline() {
	timeout := s.cfg.IdleTimeout
	if timeout <= 0 {
		timeout = DefaultIdleTimeout
	}
	_ = s.p.Underlying().SetDeadline(time.Now().Add(timeout))
}

func (s *session) greeting() string {
	if s.cfg.ServerName != "" {
		return fmt.Sprintf("%s Veksel POP3 ready", s.cfg.ServerName)
	}
	return "Veksel POP3 ready"
}

// send writes a response line to the client and flushes.
func (s *session) send(resp string) {
	if resp == "" {
		return
	}
	s.p.WriteLine(resp)
}

// handleLine dispatches a command based on the current state.
func (s *session) handleLine(line string) {
	// If we're in the middle of an AUTH challenge-response,
	// the client sends a bare line (no command keyword).
	if s.authExchange != nil {
		s.handleAuthContinuation(line)
		return
	}

	// Parse command and argument
	var cmd, arg string
	if idx := strings.IndexByte(line, ' '); idx >= 0 {
		cmd = strings.ToUpper(line[:idx])
		arg = strings.TrimSpace(line[idx+1:])
	} else {
		cmd = strings.ToUpper(line)
	}

	switch s.state {
	case StateAuthorization:
		s.handleAuth(cmd, arg)
	case StateTransaction:
		s.handleTransaction(cmd, arg)
	case StateUpdate:
		s.handleUpdate(cmd, arg)
	}
}

// --- Authorization State ---

func (s *session) handleAuth(cmd, arg string) {
	switch cmd {
	case "USER":
		s.send(s.cmdUser(arg))
	case "PASS":
		s.send(s.cmdPass(arg))
	case "AUTH":
		s.send(s.cmdAuth(arg))
	case "CAPA":
		s.send(s.cmdCapa())
	case "STLS":
		s.send(s.cmdStls(arg))
	case "QUIT":
		s.send("+OK bye")
	default:
		s.send("-ERR command not recognized")
	}
}

func (s *session) cmdUser(arg string) string {
	if !s.authPermitted() {
		return "-ERR [AUTH] TLS required before authentication"
	}
	if arg == "" {
		return "-ERR [AUTH] username required"
	}
	s.userName = arg
	return "+OK OK"
}

func (s *session) cmdPass(arg string) string {
	if !s.authPermitted() {
		s.userName = ""
		return "-ERR [AUTH] TLS required before authentication"
	}
	if s.userName == "" {
		return "-ERR [AUTH] send USER first"
	}
	if arg == "" {
		return "-ERR [AUTH] password required"
	}

	ctx := s.ctx
	userID, err := s.cfg.AuthValidator(ctx, s.userName, arg)
	if err != nil {
		s.logger.Debug("pop3: auth failed", "user", s.userName, "error", err)
		return authFailure(err)
	}

	s.userID = userID
	s.userName = "" // clear

	// Load INBOX folder
	folder, err := s.cfg.FolderSpace.GetFolderByPath(ctx, s.access(), "INBOX")
	if err != nil {
		s.logger.Debug("pop3: INBOX not found", "user", s.userID, "error", err)
		if service.IsTemporarilyUnavailable(err) {
			return "-ERR [SYS/TEMP] account temporarily unavailable; retry later"
		}
		return "-ERR INBOX not found"
	}
	s.folder = folder

	s.state = StateTransaction
	return "+OK signed in"
}

func (s *session) cmdAuth(arg string) string {
	if !s.authPermitted() {
		return "-ERR [AUTH] TLS required before authentication"
	}
	if arg == "" {
		return "-ERR [AUTH] mechanism required"
	}

	parts := strings.Fields(arg)
	if len(parts) > 2 {
		return "-ERR [AUTH] too many arguments"
	}
	mech := strings.ToUpper(parts[0])
	exchange, ok := auth.NewPasswordExchange(mech)
	if !ok || !slices.Contains(s.authMechanisms(), mech) {
		return fmt.Sprintf("-ERR [AUTH] mechanism %s not available", mech)
	}
	initial := ""
	if len(parts) == 2 {
		if mech == auth.SASLLogin {
			return "-ERR [AUTH] LOGIN does not accept an initial response"
		}
		initial = parts[1]
	}
	s.authExchange = exchange
	s.continueAuth(exchange.Start(initial))
	return ""
}

// handleAuthContinuation processes the client's response to an AUTH
// challenge (RFC 5034).
func (s *session) handleAuthContinuation(line string) {
	s.continueAuth(s.authExchange.Next(line))
}

// continueAuth frames one step of the shared SASL exchange: it sends the next
// challenge, reports a failed exchange, or verifies the final credentials.
func (s *session) continueAuth(challenge string, done bool, err error) {
	mechanism := s.authExchange.Mechanism()
	switch {
	case err != nil:
		s.clearAuthExchange()
		s.send(saslFailure(mechanism, err))
	case !done && challenge == "":
		s.send("+")
	case !done:
		s.send("+ " + challenge)
	default:
		username, password := s.authExchange.Credentials()
		s.clearAuthExchange()
		userID, err := s.cfg.AuthValidator(s.ctx, username, password)
		if err != nil {
			s.logger.Debug("pop3: AUTH failed", "mechanism", mechanism, "user", username, "error", err)
			s.send(authFailure(err))
			return
		}
		s.userID = userID
		s.completeAuth()
	}
}

// saslFailure maps a failed SASL exchange to a response.
func saslFailure(mechanism string, err error) string {
	switch {
	case errors.Is(err, auth.ErrSASLCanceled):
		return "-ERR [AUTH] authentication canceled"
	case errors.Is(err, auth.ErrSASLEncoding):
		return "-ERR [AUTH] invalid base64"
	case errors.Is(err, auth.ErrSASLAuthzid):
		return "-ERR [AUTH] authorization identity is not supported"
	default:
		return fmt.Sprintf("-ERR [AUTH] invalid %s credentials", mechanism)
	}
}

// authFailure maps a credential error to a response. Throttling is reported as
// a temporary condition (RFC 3206 SYS/TEMP) so clients retry later instead of
// prompting for a new password; it reveals nothing about the account.
func authFailure(err error) string {
	if errors.Is(err, ratelimit.ErrAuthThrottled) {
		return "-ERR [SYS/TEMP] too many failed authentication attempts; retry later"
	}
	return "-ERR [AUTH] authentication failed"
}

// completeAuth finishes authentication by loading the user's INBOX and transitioning to transaction state.
func (s *session) completeAuth() {
	ctx := s.ctx
	folder, err := s.cfg.FolderSpace.GetFolderByPath(ctx, s.access(), "INBOX")
	if err != nil {
		s.logger.Debug("pop3: INBOX not found", "user", s.userID, "error", err)
		if service.IsTemporarilyUnavailable(err) {
			s.send("-ERR [SYS/TEMP] account temporarily unavailable; retry later")
		} else {
			s.send("-ERR INBOX not found")
		}
		s.userID = ""
		return
	}
	s.folder = folder
	s.state = StateTransaction
	s.send("+OK signed in")
}

func (s *session) cmdCapa() string {
	var b strings.Builder
	b.WriteString("+OK capability list follows\r\n")
	b.WriteString("TOP\r\n")
	b.WriteString("UIDL\r\n")
	b.WriteString("RESP-CODES\r\n")
	b.WriteString("PIPELINING\r\n")
	b.WriteString("EXPIRE NEVER\r\n")
	b.WriteString("IMPLEMENTATION Veksel\r\n")
	if s.state == StateAuthorization {
		if s.authPermitted() {
			b.WriteString("USER\r\n")
			if mechanisms := s.authMechanisms(); len(mechanisms) > 0 {
				b.WriteString("SASL " + strings.Join(mechanisms, " ") + "\r\n")
			}
		}
		if !s.secure && s.cfg.TLSConfig != nil {
			b.WriteString("STLS\r\n")
		}
	}
	b.WriteString(".\r\n")
	s.p.WriteRaw(b.String())
	return ""
}

// --- Transaction State ---

func (s *session) handleTransaction(cmd, arg string) {
	switch cmd {
	case "STAT":
		s.send(s.cmdStat())
	case "LIST":
		s.send(s.cmdList(arg))
	case "RETR":
		s.send(s.cmdRetr(arg))
	case "DELE":
		s.send(s.cmdDele(arg))
	case "RSET":
		s.send(s.cmdRset())
	case "TOP":
		s.send(s.cmdTop(arg))
	case "UIDL":
		s.send(s.cmdUidl(arg))
	case "CAPA":
		s.send(s.cmdCapa())
	case "NOOP":
		s.send("+OK")
	case "QUIT":
		s.send(s.cmdQuit())
		return
	default:
		s.send("-ERR command not recognized")
	}
}

// cmdStls handles the STLS command (RFC 2595) to upgrade to TLS.
func (s *session) cmdStls(arg string) string {
	if arg != "" {
		return "-ERR [SYS/PERM] STLS does not accept arguments"
	}
	if s.state != StateAuthorization || s.secure {
		return "-ERR [SYS/PERM] STLS not permitted in the current state"
	}
	if s.cfg.TLSConfig == nil {
		return "-ERR [SYS/PERM] STLS not available"
	}
	// The client must wait for the response before the handshake. Bytes sent
	// early were read in cleartext and must not run as if they had arrived
	// under TLS (CVE-2011-0411 class command injection).
	if s.p.Buffered() > 0 {
		s.logger.Warn("pop3: data pipelined after STLS")
		s.done = true
		return "-ERR [SYS/PERM] data received after STLS before TLS negotiation"
	}
	// RFC 2595 requires the positive response before the TLS handshake begins.
	s.send("+OK begin TLS negotiation")
	// Upgrade connection to TLS
	tlsConn := tls.Server(s.p.Underlying(), s.cfg.TLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		s.logger.Error("pop3: STLS handshake failed", "error", err)
		s.done = true
		return ""
	}
	s.p.ReplaceConn(tlsConn)
	s.secure = true
	s.userName = ""
	s.clearAuthExchange()
	return ""
}

func (s *session) authPermitted() bool {
	return !s.cfg.RequireTLSForAuth || s.secure
}

func (s *session) authMechanisms() []string {
	result := make([]string, 0, len(s.cfg.AuthMechanisms))
	seen := make(map[string]bool, len(s.cfg.AuthMechanisms))
	for _, mechanism := range s.cfg.AuthMechanisms {
		mechanism = strings.ToUpper(strings.TrimSpace(mechanism))
		if (mechanism == "PLAIN" || mechanism == "LOGIN") && !seen[mechanism] {
			seen[mechanism] = true
			result = append(result, mechanism)
		}
	}
	return result
}

func (s *session) clearAuthExchange() {
	s.authExchange = nil
}

func (s *session) cmdStat() string {
	items, err := s.folderItems()
	if err != nil {
		return pop3StorageError(err)
	}
	// RFC 1939: messages marked as deleted are not counted.
	count, size := 0, int64(0)
	for index, item := range items {
		if _, deleted := s.deleted[index+1]; !deleted {
			count++
			size += itemSize(item)
		}
	}
	return fmt.Sprintf("+OK %d %d", count, size)
}

func (s *session) cmdList(arg string) string {
	items, err := s.folderItems()
	if err != nil {
		return pop3StorageError(err)
	}
	if arg == "" {
		var b strings.Builder
		b.WriteString("+OK scan listing follows\r\n")
		for index, item := range items {
			if _, deleted := s.deleted[index+1]; !deleted {
				b.WriteString(fmt.Sprintf("%d %d\r\n", index+1, itemSize(item)))
			}
		}
		b.WriteString(".\r\n")
		s.p.WriteRaw(b.String())
		return ""
	}
	msgNum, item, failure := s.message(items, arg)
	if failure != "" {
		return failure
	}
	return fmt.Sprintf("+OK %d %d", msgNum, itemSize(item))
}

// message resolves a message-number argument against the session's maildrop
// snapshot. Numbers outside it and messages marked deleted are refused, as
// RFC 1939 requires for RETR, TOP, DELE, LIST, and UIDL.
func (s *session) message(items []model.Item, arg string) (int, model.Item, string) {
	msgNum, err := strconv.Atoi(arg)
	if err != nil || msgNum < 1 {
		return 0, model.Item{}, "-ERR invalid message number"
	}
	if msgNum > len(items) {
		return 0, model.Item{}, "-ERR no such message"
	}
	if _, deleted := s.deleted[msgNum]; deleted {
		return 0, model.Item{}, fmt.Sprintf("-ERR message %d already deleted", msgNum)
	}
	return msgNum, items[msgNum-1], ""
}

// messageContent reads a snapshot item's content, which the metadata-only
// maildrop listing does not carry.
func (s *session) messageContent(item model.Item) ([]byte, error) {
	if item.Data != nil {
		return item.Data, nil
	}
	full, err := s.cfg.FolderSpace.GetItem(s.ctx, s.access(), item.ID)
	if err != nil {
		return nil, err
	}
	return full.Data, nil
}

func itemSize(item model.Item) int64 {
	if item.Size > 0 {
		return item.Size
	}
	return int64(len(item.Data))
}

func (s *session) cmdRetr(arg string) string {
	items, listErr := s.folderItems()
	if listErr != nil {
		return pop3StorageError(listErr)
	}
	_, item, failure := s.message(items, arg)
	if failure != "" {
		return failure
	}
	data, err := s.messageContent(item)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "-ERR message was removed by another session"
		}
		return pop3StorageError(err)
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("+OK %d octets\r\n", len(data)))
	b.Write(dotStuffMessage(data))
	b.WriteString(".\r\n")
	s.p.WriteRaw(b.String())
	return ""
}

func dotStuffMessage(data []byte) []byte {
	normalized := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(normalized, []byte("\n"))
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	var result bytes.Buffer
	for _, line := range lines {
		if len(line) > 0 && line[0] == '.' {
			result.WriteByte('.')
		}
		result.Write(line)
		result.WriteString("\r\n")
	}
	return result.Bytes()
}

func (s *session) cmdDele(arg string) string {
	items, listErr := s.folderItems()
	if listErr != nil {
		return pop3StorageError(listErr)
	}
	msgNum, item, failure := s.message(items, arg)
	if failure != "" {
		return failure
	}
	s.deleted[msgNum] = item.ID
	return fmt.Sprintf("+OK message %d deleted", msgNum)
}

func (s *session) cmdRset() string {
	s.deleted = make(map[int]string)
	items, err := s.folderItems()
	if err != nil {
		return "+OK"
	}
	return fmt.Sprintf("+OK maildrop has %d messages", len(items))
}

// cmdTop answers TOP msg n: the header, the blank line separating it from
// the body, and the first n lines of the body (RFC 1939 section 7).
func (s *session) cmdTop(arg string) string {
	parts := strings.Fields(arg)
	if len(parts) != 2 {
		return "-ERR usage: TOP msg n"
	}
	lineCount, err := strconv.Atoi(parts[1])
	if err != nil || lineCount < 0 {
		return "-ERR invalid line count"
	}
	items, listErr := s.folderItems()
	if listErr != nil {
		return pop3StorageError(listErr)
	}
	_, item, failure := s.message(items, parts[0])
	if failure != "" {
		return failure
	}
	data, err := s.messageContent(item)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "-ERR message was removed by another session"
		}
		return pop3StorageError(err)
	}
	stuffed := dotStuffMessage(data)
	var b strings.Builder
	b.WriteString("+OK top of message follows\r\n")
	inBody := false
	for len(stuffed) > 0 {
		end := bytes.Index(stuffed, []byte("\r\n"))
		line := stuffed[:end+2]
		stuffed = stuffed[end+2:]
		if inBody {
			if lineCount == 0 {
				break
			}
			lineCount--
		} else if end == 0 {
			inBody = true
		}
		b.Write(line)
	}
	b.WriteString(".\r\n")
	s.p.WriteRaw(b.String())
	return ""
}

func (s *session) cmdUidl(arg string) string {
	items, err := s.folderItems()
	if err != nil {
		return pop3StorageError(err)
	}
	if arg == "" {
		var b strings.Builder
		b.WriteString("+OK unique-id listing follows\r\n")
		for index, item := range items {
			if _, deleted := s.deleted[index+1]; !deleted {
				b.WriteString(fmt.Sprintf("%d %s\r\n", index+1, s.uidlForItem(item)))
			}
		}
		b.WriteString(".\r\n")
		s.p.WriteRaw(b.String())
		return ""
	}
	msgNum, item, failure := s.message(items, arg)
	if failure != "" {
		return failure
	}
	return fmt.Sprintf("+OK %d %s", msgNum, s.uidlForItem(item))
}

func (s *session) cmdQuit() string {
	s.done = true
	if failed := s.processQuit(); failed > 0 {
		return fmt.Sprintf("-ERR [SYS/TEMP] %d deleted messages not removed", failed)
	}
	return "+OK signing off"
}

// --- Update State ---

func (s *session) handleUpdate(cmd, arg string) {
	// Only QUIT is allowed in update state
	if cmd == "QUIT" {
		s.send("+OK bye")
		s.done = true
	} else {
		s.send("-ERR command not recognized in update state")
	}
}

// processQuit removes the messages marked with DELE and reports how many
// could not be removed. A message another session already removed counts as
// removed.
func (s *session) processQuit() int {
	failed := 0
	for _, itemID := range s.deleted {
		if err := s.cfg.FolderSpace.DeleteItem(s.ctx, s.access(), itemID); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.logger.Error("pop3: delete failed", "item", itemID, "error", err)
			failed++
		}
	}
	return failed
}

// --- Helpers ---

// folderItems returns the maildrop snapshot taken when the session first
// needed it: INBOX in arrival order (oldest first, the POP3 convention).
// RFC 1939 message numbers must stay stable for the whole session, so mail
// delivered or removed by other sessions does not renumber it; new mail is
// seen at the next login. The listing is metadata only and content is read
// per RETR or TOP.
func (s *session) folderItems() ([]model.Item, error) {
	if s.folder.ID == "" {
		return nil, nil
	}
	if s.snapshot != nil {
		return s.snapshot, nil
	}
	items, err := s.cfg.FolderSpace.ListItems(s.ctx, s.access(), s.folder.ID, service.ItemQuery{MetadataOnly: true})
	if err != nil {
		s.logger.Error("pop3: failed to list items", "error", err)
		return nil, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		if !items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].CreatedAt.Before(items[j].CreatedAt)
		}
		return items[i].UID < items[j].UID
	})
	if items == nil {
		items = []model.Item{}
	}
	s.snapshot = items
	return items, nil
}

func pop3StorageError(err error) string {
	if service.IsTemporarilyUnavailable(err) {
		return "-ERR [SYS/TEMP] account temporarily unavailable; retry later"
	}
	return "-ERR [SYS/TEMP] mailbox state unavailable"
}

func (s *session) access() service.AccessContext {
	return service.UserAccess(s.userID, "pop3")
}

func (s *session) uidlForItem(item model.Item) string {
	return fmt.Sprintf("%s-%d", s.folder.ID, item.UID)
}
