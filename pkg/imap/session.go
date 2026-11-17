package imap

import (
	"bufio"
	"compress/flate"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/proto"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/service"
)

// IMAP session states following RFC 3501 §3.
type sessionState int

const (
	stateNotAuth sessionState = iota
	stateAuthenticated
	stateSelected
	stateLogout
	stateIdle // IDLE mode (RFC 2177)
)

func (s sessionState) String() string {
	switch s {
	case stateNotAuth:
		return "not-auth"
	case stateAuthenticated:
		return "authenticated"
	case stateSelected:
		return "selected"
	case stateLogout:
		return "logout"
	case stateIdle:
		return "idle"
	default:
		return "unknown"
	}
}

// ClientID holds client identification information from the ID command (RFC 2971).
type ClientID struct {
	Name      string
	Version   string
	OS        string
	OSVersion string
	Support   string
	Comment   string
}

// Session represents one IMAP connection.
type Session struct {
	id     uint64
	cfg    *Config
	conn   net.Conn
	rw     *bufio.ReadWriter
	server *Server

	curState sessionState

	// Authentication
	authenticated bool
	userID        string
	ntlmCtx       *auth.NtlmContext // NTLM state machine

	// Selected mailbox
	selectedFolderID string
	selectedFolder   model.Folder
	readOnly         bool // true for EXAMINE
	highestModSeq    uint64
	qresyncEnabled   bool
	// condstoreEnabled records that a CONDSTORE-enabling command ran (RFC
	// 7162 3.1): from then on FETCH responses carrying FLAGS include MODSEQ.
	condstoreEnabled bool

	// view is the selected mailbox as the client knows it (see view.go);
	// viewPending holds UIDs expunged elsewhere but not yet reported.
	view        []model.Item
	viewActive  bool
	viewPending map[uint32]struct{}
	viewSyncing bool
	// commandName is the command being executed ("UID FETCH" for UID
	// commands); it decides which changes its completion may report.
	commandName string
	// unreadLiteral is a literal announced by an APPEND or SEARCH command
	// that the command has not read (see expectLiteral).
	unreadLiteral unreadLiteral
	// idleRead delivers the line a finished IDLE was still reading when the
	// server ended it; the next command read consumes it first.
	idleRead    chan idleLine
	rev2Enabled bool
	// utf8Accept is set by ENABLE UTF8=ACCEPT (RFC 6855): mailbox names
	// travel as UTF-8 and APPEND takes the UTF8 (literal8) form.
	utf8Accept      bool
	savedSearchUIDs []uint32
	savedSearchSet  bool

	// storedPreviews holds the selected mailbox's projected previews for the
	// FETCH in progress.
	storedPreviews map[string]mailindex.StoredPreview

	// bulkContent marks the command in progress as reading the content of
	// many messages once, so those reads do not populate the folder cache.
	bulkContent bool

	// TLS state
	tlsDone bool

	// COMPRESS DEFLATE state (RFC 4978)
	compressed  bool
	flateReader io.ReadCloser
	flateWriter *flate.Writer

	// Client ID from RFC 2971 ID command
	clientID *ClientID

	// notify is the active NOTIFY subscription (RFC 5465), or nil.
	notify *notifyState
	// wake is the session's change registration while it idles or has
	// NOTIFY set (see wake.go). ownFolders and ownPaths are the folders and
	// mailbox paths the session itself changed since it last reported, which
	// NOTIFY does not report back.
	wake       *sessionWake
	ownFolders map[string]struct{}
	ownPaths   []string

	// Context for shutdown
	ctx    *context.Context
	cancel context.CancelFunc

	// Shutdown tracking; nil outside an accept loop.
	tracked *proto.Session

	// Rate limiting
	cmdLimiter  *ratelimit.Limiter // per-connection command limiter
	authLimiter *ratelimit.Limiter // per-IP auth attempt limiter
}

func newSession(id uint64, cfg *Config, conn net.Conn, srv *Server, cmdLimiter, authLimiter *ratelimit.Limiter) *Session {
	configureFolderSpace(cfg)
	ctx, cancel := context.WithCancel(ratelimit.WithClientIP(context.Background(), extractRemoteIP(conn)))
	return &Session{
		id:          id,
		cfg:         cfg,
		conn:        conn,
		rw:          bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
		server:      srv,
		curState:    stateNotAuth,
		ctx:         &ctx,
		cancel:      cancel,
		cmdLimiter:  cmdLimiter,
		authLimiter: authLimiter,
	}
}

// run executes the IMAP protocol loop for this session.
func (s *Session) run() {
	defer s.dropWake()
	defer func() {
		if s.flateWriter != nil {
			s.flateWriter.Close()
		}
		if s.flateReader != nil {
			s.flateReader.Close()
		}
		s.conn.Close()
	}()
	defer s.cancel()

	// Apply implicit TLS if configured
	if s.cfg.TLSConfig != nil && s.cfg.ImplicitTLS {
		tlsConn := tls.Server(s.conn, serverTLSConfig(s.cfg.TLSConfig))
		if err := handshakeTLS(tlsConn); err != nil {
			logger.Error("imap: TLS handshake failed", "session", s.id, "error", err)
			return
		}
		s.conn = tlsConn
		s.rw = bufio.NewReadWriter(bufio.NewReader(s.conn), bufio.NewWriter(s.conn))
		s.tlsDone = true
	}

	// Include the connection-specific capabilities in the greeting so clients
	// can negotiate without a redundant round trip. IMAP4rev2 is only present
	// once transport protection has been established.
	s.sendUntagged(fmt.Sprintf("* OK [CAPABILITY %s] %s Service Ready", strings.Join(s.buildCapabilities(), " "), s.cfg.ServerName))

	// Read commands with a timeout
	for {
		if rc, ok := s.conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = rc.SetReadDeadline(time.Now().Add(10 * time.Minute))
		}
		s.commandName = ""
		if err := s.discardUnreadLiteral(); err != nil {
			if errors.Is(err, errLiteralProtocol) {
				s.sendUntagged("* BYE " + err.Error())
			}
			return
		}
		s.tracked.SetIdle(true)
		line, err := s.readCommandLine()
		s.tracked.SetIdle(false)
		if err != nil {
			if errors.Is(err, errCommandLineTooLong) {
				s.sendUntagged("* BYE Command line too long")
				_ = s.flush()
				return
			}
			if err != io.EOF {
				logConnectionError("imap: read error", s.id, err)
			}
			return
		}

		first := line
		line, err = s.readCommandLiterals(line)
		if err != nil {
			var unusable literalCommandError
			if errors.As(err, &unusable) {
				tag, _, _ := strings.Cut(strings.TrimSpace(first), " ")
				s.sendBAD(tag, "Invalid literal: "+unusable.reason)
				continue
			}
			if errors.Is(err, errLiteralProtocol) || errors.Is(err, errCommandLineTooLong) {
				s.sendUntagged("* BYE " + err.Error())
			}
			return
		}
		if !commandSplicesLiterals(line) {
			s.expectLiteral(line, s.literalLimit(line))
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		logger.Debug("imap: received", "session", s.id, "line", line)

		// Per-connection command rate limiting
		if s.cmdLimiter != nil {
			key := fmt.Sprintf("imap-cmd-%d", s.id)
			if !s.cmdLimiter.Allow(key) {
				logger.Warn("imap: command rate limit exceeded", "session", s.id)
				s.sendUntagged("* BYE Too many commands")
				return
			}
		}

		// Parse tag and command
		tag, cmd, args, parseErr := s.parseCommand(line)
		if tag == "" {
			// Malformed command
			s.sendUntagged("* BAD Bad command format")
			continue
		}
		if parseErr != nil {
			s.sendBAD(tag, "Invalid command syntax: "+parseErr.Error())
			continue
		}

		cmd = strings.ToUpper(cmd)

		// Dispatch based on command
		s.dispatch(tag, cmd, args)
		if s.wake != nil {
			s.refreshWake()
		}

		if s.curState == stateLogout {
			return
		}
	}
}

// parseCommand splits "A001 SELECT INBOX" into ("A001", "SELECT", ["INBOX"]).
func (s *Session) parseCommand(line string) (tag, cmd string, args []string, err error) {
	// Find the first space to extract the tag
	idx := strings.IndexByte(line, ' ')
	if idx < 0 {
		// No space — could be a tag with no command (malformed)
		return strings.TrimSpace(line), "", nil, nil
	}
	tag = strings.TrimSpace(line[:idx])
	rest := strings.TrimSpace(line[idx+1:])

	// Find the command
	idx = strings.IndexByte(rest, ' ')
	if idx < 0 {
		return tag, rest, nil, nil
	}
	cmd = rest[:idx]
	argStr := strings.TrimSpace(rest[idx+1:])
	if argStr != "" {
		upperCommand := strings.ToUpper(cmd)
		switch {
		case upperCommand == "SEARCH" || upperCommand == "SORT" || upperCommand == "THREAD" || upperCommand == "ID":
			args, err = tokenizeSearchCommandArgs(argStr)
		case upperCommand == "NOTIFY":
			// The event groups nest parentheses, quoted names and fetch
			// sections, so the command parser reads the raw text itself.
			// Like every other argument it may not carry NUL or a line break.
			if strings.ContainsAny(argStr, "\x00\r\n") {
				err = errors.New("invalid NOTIFY character")
			} else {
				args = []string{argStr}
			}
		case upperCommand == "UID" && slices.Contains([]string{"SEARCH", "SORT", "THREAD"}, strings.ToUpper(strings.Fields(argStr)[0])):
			subcommand := strings.Fields(argStr)[0]
			searchInput := strings.TrimSpace(argStr[len(subcommand):])
			var searchArgs []string
			searchArgs, err = tokenizeSearchCommandArgs(searchInput)
			args = append([]string{strings.ToUpper(subcommand)}, searchArgs...)
		default:
			args, err = tokenizeCommandArgs(argStr)
		}
	}
	return tag, cmd, args, err
}

// tokenizeSearchCommandArgs retains parenthesized search-key grouping while
// decoding quoted strings as single values. SEARCH needs this richer token
// stream because parentheses alter boolean evaluation and may also occur in a
// quoted search value.
func tokenizeSearchCommandArgs(input string) ([]string, error) {
	var tokens []string
	for index := 0; index < len(input); {
		for index < len(input) && (input[index] == ' ' || input[index] == '\t') {
			index++
		}
		if index == len(input) {
			break
		}
		switch input[index] {
		case '(', ')':
			tokens = append(tokens, input[index:index+1])
			index++
		case '"':
			index++
			var value strings.Builder
			closed := false
			for index < len(input) {
				character := input[index]
				index++
				switch character {
				case '"':
					closed = true
				case '\\':
					if index == len(input) || (input[index] != '"' && input[index] != '\\') {
						return nil, errors.New("invalid quoted search escape")
					}
					value.WriteByte(input[index])
					index++
				case '\r', '\n', 0:
					return nil, errors.New("invalid quoted search character")
				default:
					value.WriteByte(character)
				}
				if closed {
					break
				}
			}
			if !closed {
				return nil, errors.New("unterminated quoted search string")
			}
			if index < len(input) && input[index] != ' ' && input[index] != '\t' && input[index] != ')' {
				return nil, errors.New("quoted search string must end at a boundary")
			}
			tokens = append(tokens, value.String())
		default:
			start := index
			for index < len(input) && input[index] != ' ' && input[index] != '\t' && input[index] != '(' && input[index] != ')' {
				if input[index] == '\r' || input[index] == '\n' || input[index] == 0 || input[index] == '"' {
					return nil, errors.New("invalid search atom")
				}
				index++
			}
			tokens = append(tokens, input[start:index])
		}
	}
	return tokens, nil
}

// tokenizeCommandArgs preserves the old parenthesis-bearing atoms expected by
// command-specific parsers while correctly treating quoted strings (including
// spaces and quoted-pair escapes) as one argument. Literal-bearing commands
// are consumed by their dedicated bounded readers before reaching here.
func tokenizeCommandArgs(input string) ([]string, error) {
	var args []string
	for index := 0; index < len(input); {
		for index < len(input) && (input[index] == ' ' || input[index] == '\t') {
			index++
		}
		if index == len(input) {
			break
		}
		if input[index] == '"' {
			index++
			var value strings.Builder
			closed := false
			for index < len(input) {
				character := input[index]
				index++
				switch character {
				case '"':
					closed = true
				case '\\':
					if index == len(input) {
						return nil, errors.New("unterminated quoted escape")
					}
					character = input[index]
					index++
					if character != '"' && character != '\\' {
						return nil, errors.New("invalid quoted escape")
					}
					value.WriteByte(character)
				case '\r', '\n', 0:
					return nil, errors.New("invalid quoted character")
				default:
					value.WriteByte(character)
				}
				if closed {
					break
				}
			}
			if !closed {
				return nil, errors.New("unterminated quoted string")
			}
			// A quoted string can be immediately followed by closing list or
			// section delimiters. Command-specific parsers historically receive
			// those delimiters attached to the token, so retain that shape. Any
			// other suffix is invalid IMAP syntax.
			for index < len(input) && input[index] != ' ' && input[index] != '\t' {
				if input[index] != ')' && input[index] != ']' {
					return nil, errors.New("quoted string must end at an argument boundary")
				}
				value.WriteByte(input[index])
				index++
			}
			args = append(args, value.String())
			continue
		}
		start := index
		for index < len(input) && input[index] != ' ' && input[index] != '\t' {
			if input[index] == '\r' || input[index] == '\n' || input[index] == 0 {
				return nil, errors.New("invalid atom character")
			}
			index++
		}
		args = append(args, input[start:index])
	}
	return args, nil
}

// stripQuotes remains useful to command-specific parsers that receive legacy
// parenthesis-bearing tokens and in parser fuzz coverage.
func stripQuotes(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}
	return value
}

// maxCommandLineLength caps one client line, excluding literal octets, which
// are read separately with their own announced and bounded sizes. Without a
// cap a client could stream an endless line into server memory.
const maxCommandLineLength = 1 << 20

var errCommandLineTooLong = fmt.Errorf("command line exceeds %d octets", maxCommandLineLength)

// readLine reads a single line, handling both \r\n and \n.
func (s *Session) readLine() (string, error) {
	line, err := appendLineChunk(s.rw.Reader, nil)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// appendLineChunk appends the input up to and including the next LF to line,
// failing once the whole line would exceed maxCommandLineLength. On a read
// error it returns what it has read so far, so a caller can resume after a
// timeout.
func appendLineChunk(reader *bufio.Reader, line []byte) ([]byte, error) {
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(line)+len(chunk) > maxCommandLineLength {
			return line, errCommandLineTooLong
		}
		line = append(line, chunk...)
		if err != bufio.ErrBufferFull {
			return line, err
		}
	}
}

// sendTagged sends a tagged IMAP response, after reporting the mailbox
// changes the command's completion may carry.
func (s *Session) sendTagged(tag string, code imapCode, text string) {
	s.syncBeforeCompletion()
	s.writeLine(fmt.Sprintf("%s %s %s", tag, code, text))
}

// sendUntagged sends an untagged IMAP response.
func (s *Session) sendUntagged(text string) {
	s.writeLine(text)
}

// sendContinuation sends a continuation response (+).
func (s *Session) sendContinuation(text string) {
	s.writeLine(fmt.Sprintf("+ %s", text))
}

// writeLine writes a line to the connection.
func (s *Session) writeLine(line string) {
	msg := line + "\r\n"
	if _, err := s.rw.WriteString(msg); err != nil {
		logConnectionError("imap: write error", s.id, err)
		return
	}
	if err := s.flush(); err != nil {
		logConnectionError("imap: flush error", s.id, err)
	}
}

// logConnectionError logs an I/O error on a client connection. A client
// that resets or closes its connection, or a connection the server already
// closed, is ordinary and logged at debug; anything else is an error.
func logConnectionError(msg string, session uint64, err error) {
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrUnexpectedEOF) {
		logger.Debug(msg, "session", session, "error", err)
		return
	}
	logger.Error(msg, "session", session, "error", err)
}

func (s *Session) flush() error {
	if err := s.rw.Flush(); err != nil {
		return err
	}
	if s.compressed && s.flateWriter != nil {
		return s.flateWriter.Flush()
	}
	return nil
}

// sendOK sends a tagged OK response.
func (s *Session) sendOK(tag string, text string) {
	s.sendTagged(tag, "OK", text)
}

// sendNO sends a tagged NO response.
func (s *Session) sendNO(tag string, text string) {
	s.sendTagged(tag, "NO", text)
}

func (s *Session) sendOperationError(tag, operation string, err error) {
	if errors.Is(err, model.ErrQuotaExceeded) {
		s.sendNO(tag, "[OVERQUOTA] Account quota exceeded")
		return
	}
	if service.IsTemporarilyUnavailable(err) {
		s.sendNO(tag, "[UNAVAILABLE] Account temporarily unavailable; retry later")
		return
	}
	s.sendNO(tag, fmt.Sprintf("%s failed: %v", operation, err))
}

// sendBAD sends a tagged BAD response.
func (s *Session) sendBAD(tag string, text string) {
	s.sendTagged(tag, "BAD", text)
}

// sendOKCode sends a tagged OK response with a response code.
func (s *Session) sendOKCode(tag string, code string, text string) {
	s.syncBeforeCompletion()
	s.writeLine(fmt.Sprintf("%s OK [%s] %s", tag, code, text))
}

type imapCode string

const ()

// dispatch routes commands based on current state and command name.
func (s *Session) dispatch(tag, cmd string, args []string) {
	normalizedArgs, err := s.normalizeMailboxArguments(cmd, args)
	if err != nil {
		s.sendBAD(tag, fmt.Sprintf("Invalid mailbox name: %v", err))
		return
	}
	args = normalizedArgs
	s.commandName = cmd
	if cmd == "UID" && len(args) > 0 {
		s.commandName += " " + strings.ToUpper(args[0])
	}
	if s.cfg.CommandObserver != nil {
		observed := cmd
		if cmd == "UID" && len(args) > 0 {
			observed += " " + strings.ToUpper(args[0])
		}
		s.cfg.CommandObserver(observed)
	}

	// Track IMAP commands
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.IncrementCounter("imap_commands_total", map[string]string{"command": cmd})
	}
	logger.Debug("imap: dispatch", "session", s.id, "command", cmd, "state", s.curState)
	// Commands valid in all states
	switch cmd {
	case "CAPABILITY":
		s.cmdCapability(tag, args)
		return
	case "LOGOUT":
		s.cmdLogout(tag, args)
		return
	case "NOOP":
		s.cmdNoop(tag, args)
		return
	case "COMPRESS":
		s.cmdCompress(tag, args)
		return
	case "ID":
		s.cmdID(tag, args)
		return
	}

	// Commands valid in Not Auth state (and LOGIN/AUTHENTICATE for re-auth)
	if s.curState == stateNotAuth {
		switch cmd {
		case "STARTTLS":
			s.cmdStartTLS(tag, args)
			return
		case "LOGIN":
			s.cmdLogin(tag, args)
			return
		case "AUTHENTICATE":
			s.cmdAuthenticate(tag, args)
			return
		}
		s.sendBAD(tag, "Must authenticate first")
		return
	}

	// Re-authentication is allowed in Authenticated state
	if s.curState == stateAuthenticated {
		switch cmd {
		case "LOGIN":
			s.cmdLogin(tag, args)
			return
		case "AUTHENTICATE":
			s.cmdAuthenticate(tag, args)
			return
		}
	}

	// IDLE can be entered from Authenticated or Selected
	if cmd == "IDLE" && (s.curState == stateAuthenticated || s.curState == stateSelected || s.curState == stateIdle) {
		s.cmdIdle(tag, args)
		return
	}

	// If we're in IDLE state, only DONE is valid
	if s.curState == stateIdle {
		s.sendBAD(tag, "Currently in IDLE mode")
		return
	}

	// Commands valid in Authenticated or Selected state
	if s.curState >= stateAuthenticated {
		// Mailbox commands
		switch cmd {
		case "ENABLE":
			s.cmdEnable(tag, args)
			return
		case "LIST":
			s.cmdList(tag, args)
			return
		case "NAMESPACE":
			s.cmdNamespace(tag, args)
			return
		case "STATUS":
			s.cmdStatus(tag, args)
			return
		case "NOTIFY":
			s.cmdNotify(tag, args)
			return
		case "GETQUOTA":
			s.cmdGetQuota(tag, args)
			return
		case "GETQUOTAROOT":
			s.cmdGetQuotaRoot(tag, args)
			return
		case "LSUB":
			s.cmdLsub(tag, args)
			return
		case "CREATE":
			s.cmdCreate(tag, args)
			return
		case "DELETE":
			s.cmdDelete(tag, args)
			return
		case "RENAME":
			s.cmdRename(tag, args)
			return
		case "SUBSCRIBE":
			s.cmdSubscribe(tag, args)
			return
		case "UNSUBSCRIBE":
			s.cmdUnsubscribe(tag, args)
			return
		case "SELECT":
			s.cmdSelect(tag, args)
			return
		case "EXAMINE":
			s.cmdExamine(tag, args)
			return
		case "GETACL":
			s.cmdGetACL(tag, args)
			return
		case "SETACL":
			s.cmdSetACL(tag, args)
			return
		case "DELETEACL":
			s.cmdDeleteACL(tag, args)
			return
		case "MYRIGHTS":
			s.cmdMyRights(tag, args)
			return
		case "GETMETADATA":
			s.cmdGetMetadata(tag, args)
			return
		case "SETMETADATA":
			s.cmdSetMetadata(tag, args)
			return
		case "APPEND":
			s.cmdAppend(tag, args)
			return
		}
	}

	// Commands valid only in Selected state
	if s.curState == stateSelected {
		switch cmd {
		case "FETCH":
			s.cmdFetch(tag, args)
			return
		case "STORE":
			s.cmdStore(tag, args)
			return
		case "COPY":
			s.cmdCopy(tag, args)
			return
		case "SEARCH":
			s.cmdSearch(tag, args)
			return
		case "SORT":
			s.cmdSort(tag, args)
			return
		case "THREAD":
			s.cmdThread(tag, args)
			return
		case "EXPUNGE":
			s.cmdExpunge(tag, args)
			return
		case "CLOSE":
			s.cmdClose(tag, args)
			return
		case "CHECK":
			s.cmdCheck(tag, args)
			return
		case "MOVE":
			s.cmdMove(tag, args)
			return
		case "UNSELECT":
			s.cmdUnselect(tag, args)
			return
		}
	}

	// UID command prefix
	if cmd == "UID" {
		s.cmdUID(tag, args)
		return
	}

	s.sendBAD(tag, fmt.Sprintf("Command not implemented or invalid in state %s", s.curState))
}

// deselect leaves the Selected state.
func (s *Session) deselect() {
	if s.curState == stateSelected || s.curState == stateIdle {
		s.curState = stateAuthenticated
		s.selectedFolderID = ""
		s.selectedFolder = model.Folder{}
	}
	s.clearView()
}

// cmdCapability handles the CAPABILITY command (RFC 3501).
// The response is dynamic based on connection state (TLS, auth, selected mailbox).
func (s *Session) cmdCapability(tag string, args []string) {
	if len(args) != 0 {
		s.sendBAD(tag, "CAPABILITY does not accept arguments")
		return
	}
	caps := s.buildCapabilities()
	s.sendUntagged(fmt.Sprintf("* CAPABILITY %s", strings.Join(caps, " ")))
	s.sendOK(tag, "CAPABILITY completed")
}

// buildCapabilities returns the list of capabilities based on current connection state.
// Per RFC 3501, capabilities depend on whether the client is authenticated and
// whether a mailbox is selected. Pre-auth capabilities are a subset.
func (s *Session) buildCapabilities() []string {
	caps := []string{
		"IMAP4rev1",
		"ID",
		"IDLE",
		"NAMESPACE",
		"LIST-EXTENDED",
		"LIST-STATUS",
		"SPECIAL-USE",
		"STATUS=SIZE",
		"QUOTA",
		"QUOTA=RES-MESSAGE",
		"ESEARCH",
		"SEARCHRES",
		"UNSELECT",
		"ENABLE",
		"CONDSTORE",
		"UIDPLUS",
		"LITERAL+",
		"MULTIAPPEND",
		"SASL-IR",
		"MOVE",
		"THREAD=REFERENCES",
		"THREAD=ORDEREDSUBJECT",
		"SORT",
		"ACL",
		"RIGHTS",
		"METADATA",
		"ENABLE=METADATA",
		"UTF8=ACCEPT",
		"BINARY",
		"COMPRESS=DEFLATE",
		"OBJECTID",
		"PREVIEW",
		"SAVEDATE",
		"NOTIFY",
	}
	if shouldOfferIMAP4rev2(imap4rev2Available, s.tlsDone) {
		caps = append(caps, "IMAP4rev2")
	}
	if _, ok := s.cfg.FolderSpace.(service.FolderChangeReader); ok {
		caps = append(caps, "QRESYNC")
	}

	// STARTTLS is only advertised before TLS is established
	if s.cfg.TLSConfig != nil && !s.tlsDone {
		caps = append(caps, "STARTTLS")
	}

	// AUTH=* capabilities are only advertised when authentication is possible
	// (pre-auth state, or after deselecting a mailbox)
	if !s.plaintextAuthPermitted() {
		caps = append(caps, "LOGINDISABLED")
	}
	if s.curState == stateNotAuth || s.curState == stateAuthenticated {
		if s.plaintextAuthPermitted() {
			caps = append(caps, "AUTH=PLAIN", "AUTH=LOGIN")
			if s.cfg.OAuth2Validator != nil {
				caps = append(caps, "AUTH=XOAUTH2")
			}
		}
		if s.cfg.NtlmEnabled {
			caps = append(caps, "AUTH=NTLM")
		}
	}

	// Selected mailbox capabilities (RFC 3501 §7.1)
	// These are advertised when a mailbox is selected
	if s.curState == stateSelected {
		// HIGHESTMODSEQ is a selected mailbox capability
		caps = append(caps, "HIGHESTMODSEQ")
	}

	return caps
}

// cmdID handles the ID command (RFC 2971).
// The client sends a list of key-value pairs terminated by NIL.
// The server responds with its own ID information or NIL if it doesn't support it.
func (s *Session) cmdID(tag string, args []string) {
	// Parse the ID response from the client
	// Format: ID ("name" "value" "version" "value" ... NIL)
	// args contains the raw tokens from the command line
	clientID := s.parseClientID(args)

	if clientID != nil {
		s.clientID = clientID
		logger.Info("imap: client ID received",
			"session", s.id,
			"name", clientID.Name,
			"version", clientID.Version,
			"os", clientID.OS,
			"os-version", clientID.OSVersion,
			"support", clientID.Support,
			"comment", clientID.Comment,
		)
	}

	// Send server ID response
	// Per RFC 2971, server MUST respond with its own ID data or NIL
	name, nameErr := quoteIMAPString(s.cfg.ServerName)
	version, versionErr := quoteIMAPString(s.serverVersion())
	operatingSystem, osErr := quoteIMAPString(runtimeGOOS())
	if nameErr != nil || versionErr != nil || osErr != nil {
		s.sendUntagged("* ID NIL")
	} else {
		s.sendUntagged(fmt.Sprintf(`* ID ("name" %s "version" %s "os" %s)`, name, version, operatingSystem))
	}
	s.sendOK(tag, "ID completed")
}

func (s *Session) cmdEnable(tag string, args []string) {
	if s.curState != stateAuthenticated {
		s.sendBAD(tag, "ENABLE is only valid before selecting a mailbox")
		return
	}
	if len(args) == 0 {
		s.sendBAD(tag, "ENABLE requires at least one capability")
		return
	}
	var enabled []string
	for _, capability := range args {
		if !validCapabilityAtom(capability) {
			s.sendBAD(tag, "Invalid ENABLE capability syntax")
			return
		}
		switch strings.ToUpper(capability) {
		case "QRESYNC":
			if _, ok := s.cfg.FolderSpace.(service.FolderChangeReader); ok {
				s.qresyncEnabled = true
				s.condstoreEnabled = true
				enabled = append(enabled, "QRESYNC")
			}
		case "CONDSTORE":
			s.condstoreEnabled = true
			enabled = append(enabled, "CONDSTORE")
		case "UTF8=ACCEPT":
			s.utf8Accept = true
			enabled = append(enabled, "UTF8=ACCEPT")
		case "IMAP4REV2":
			if shouldOfferIMAP4rev2(imap4rev2Available, s.tlsDone) {
				s.rev2Enabled = true
				enabled = append(enabled, "IMAP4rev2")
			}
		}
	}
	response := "* ENABLED"
	if len(enabled) > 0 {
		response += " " + strings.Join(enabled, " ")
	}
	s.sendUntagged(response)
	s.sendOK(tag, "ENABLE completed")
}

func shouldOfferIMAP4rev2(implementationReady, protectedSession bool) bool {
	return implementationReady && protectedSession
}

func validCapabilityAtom(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character >= 0x7f || strings.ContainsRune("()[]{%*\"\\", character) {
			return false
		}
	}
	return true
}

// cmdNamespace implements the single-user personal namespace and the shared
// user namespace. There is no separate public namespace.
func (s *Session) cmdNamespace(tag string, args []string) {
	if len(args) != 0 {
		s.sendBAD(tag, "NAMESPACE does not accept arguments")
		return
	}
	s.sendUntagged(`* NAMESPACE (("" "/")) NIL (("user/" "/"))`)
	s.sendOK(tag, "NAMESPACE completed")
}

// parseClientID parses the ID response arguments from the client.
// Expected format: ("name" "value" "version" "value" ... NIL)
// Returns nil if the client sent NIL (no ID data).
//
// Note: parseCommand uses strings.Fields which splits on whitespace,
// so "(" may be attached to the first key (e.g., "("name"").
// This function handles both cases.
func (s *Session) parseClientID(args []string) *ClientID {
	if len(args) == 0 {
		return nil
	}

	i := 0

	// Skip the list opener "(" if it's a separate token
	if args[0] == "(" {
		i = 1
	} else if args[0] == "NIL" {
		// Client sent ID NIL — no identification data
		return nil
	}

	if i >= len(args) {
		return nil
	}

	// Check for immediate NIL after "("
	if args[i] == "NIL" {
		return nil
	}

	clientID := &ClientID{}

	for i < len(args) {
		// Look for NIL terminator or closing paren
		if args[i] == "NIL" || args[i] == ")" {
			break
		}

		if i+1 >= len(args) {
			break // No value for this key
		}

		key := args[i]
		// Handle "(" attached to the first key (e.g., "("name"")
		key = strings.TrimPrefix(key, "(")
		key = stripQuotes(key)

		value := strings.TrimSuffix(stripQuotes(args[i+1]), ")")
		i += 2

		switch strings.ToLower(key) {
		case "name":
			clientID.Name = value
		case "version":
			clientID.Version = value
		case "os":
			clientID.OS = value
		case "os-version":
			clientID.OSVersion = value
		case "support":
			clientID.Support = value
		case "comment":
			clientID.Comment = value
		}
	}

	return clientID
}

// serverVersion returns a simple version string for the server ID response.
func (s *Session) serverVersion() string {
	if s.cfg != nil && s.cfg.Version != "" {
		return s.cfg.Version
	}
	return "1.0"
}

// cmdLogout handles the LOGOUT command (RFC 3501).
func (s *Session) cmdLogout(tag string, args []string) {
	if len(args) != 0 {
		s.sendBAD(tag, "LOGOUT does not accept arguments")
		return
	}
	s.curState = stateLogout
	s.sendUntagged("* BYE Logging out")
	s.sendOK(tag, "LOGOUT completed")
}

// cmdNoop handles the NOOP command (RFC 3501).
func (s *Session) cmdNoop(tag string, args []string) {
	if len(args) != 0 {
		s.sendBAD(tag, "NOOP does not accept arguments")
		return
	}
	s.sendOK(tag, "NOOP completed")
}

// cmdCompress handles the COMPRESS command (RFC 4978).
// COMPRESS DEFLATE wraps the connection in DEFLATE compression.
func (s *Session) cmdCompress(tag string, args []string) {
	if len(args) != 1 || strings.ToUpper(args[0]) != "DEFLATE" {
		s.sendBAD(tag, "Only COMPRESS DEFLATE is supported")
		return
	}

	if s.compressed {
		s.sendBAD(tag, "Connection is already compressed")
		return
	}

	// Send OK before switching — after this the client expects compressed data
	s.sendOK(tag, "COMPRESS DEFLATE completed")

	// Wrap the connection in flate compression.
	// Per RFC 4978, the server MUST send the tagged OK response before
	// compressing any data. After this point all data sent/received is compressed.
	s.compressed = true

	// Create new bufio layers on top of compressed streams.
	// Read chain: bufio.Reader -> flate.Reader -> conn
	// Write chain: bufio.Writer -> flate.Writer -> conn
	s.flateReader = flate.NewReader(s.conn)
	fw, err := flate.NewWriter(s.conn, 6)
	if err != nil {
		logger.Error("imap: failed to create flate writer", "session", s.id, "error", err)
		s.compressed = false
		return
	}
	s.flateWriter = fw
	s.rw = bufio.NewReadWriter(bufio.NewReader(s.flateReader), bufio.NewWriter(s.flateWriter))
}

func (s *Session) access() service.AccessContext {
	return service.UserAccess(s.userID, "imap")
}
