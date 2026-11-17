// Package eas implements Exchange ActiveSync over Veksel' generic typed-folder
// abstraction. Wire-specific item conversion stays in this package.
package eas

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// protocolVersions are the versions whose semantics this server implements.
// 2.5 is not offered: it predates AirSyncBase bodies, and a client that
// negotiated it would expect the legacy Truncation and raw-MIME forms.
const protocolVersions = "12.0,12.1,14.0,14.1,16.0,16.1"

// protocolCommands lists only implemented commands: clients take the
// advertisement literally and call, for example, ValidateCert before
// sending S/MIME when it is listed.
const protocolCommands = "Sync,SendMail,SmartForward,SmartReply,GetAttachment,FolderSync,FolderCreate,FolderDelete,FolderUpdate,MoveItems,GetItemEstimate,MeetingResponse,Search,Settings,Ping,ItemOperations,Provision,ResolveRecipients,Find"

// serverVersion is the MS-Server-ActiveSync value. Clients read it only as
// an opaque server build; Exchange 2016 sends 15.1 builds with 16.1.
const serverVersion = "15.1"

type Submit func(context.Context, string, []byte) error

type Handler struct {
	space        service.FolderSpace
	authenticate protocolauth.AuthenticateFunc
	states       *StateStore
	maxRequest   int64
	submit       Submit
	account      Account
	searchIndex  service.SearchReader
	scheduler    Scheduler
	minHeartbeat int
	maxHeartbeat int

	// ctx ends with the server; waiting Ping and Sync requests then answer
	// at once so shutdown is not held up by long polls.
	ctx context.Context
	// waits wakes waiting requests on commits to their folders; pingPoll is
	// the fallback poll interval while they wait.
	waits    *pingWaits
	pingPoll time.Duration
}

type Config struct {
	Space           service.FolderSpace
	Authenticate    protocolauth.AuthenticateFunc
	Store           store.Store
	MaxRequestBytes int64
	Submit          Submit
	// Account supplies the user's addresses, out-of-office settings and the
	// global address list. Without it those features answer empty.
	Account Account
	// Search serves Search and Find from the account search index; without
	// it a bounded header scan is used.
	Search service.SearchReader
	// Scheduler answers meeting requests for MeetingResponse.
	Scheduler Scheduler
}

// New builds the handler. ctx bounds its lifetime: when it ends, waiting
// Ping and Sync requests answer immediately and commit notifications stop.
func New(ctx context.Context, cfg Config) (*Handler, error) {
	if cfg.Space == nil || cfg.Authenticate == nil {
		return nil, errors.New("EAS requires folder space and authenticator")
	}
	states, err := NewStateStore(ctx, cfg.Store)
	if err != nil {
		return nil, err
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = 25 << 20
	}
	h := &Handler{
		space: cfg.Space, authenticate: cfg.Authenticate, states: states, maxRequest: cfg.MaxRequestBytes,
		submit: cfg.Submit, account: cfg.Account, searchIndex: cfg.Search, scheduler: cfg.Scheduler,
		minHeartbeat: minHeartbeatSeconds, maxHeartbeat: maxHeartbeatSeconds,
		ctx: ctx, waits: newPingWaits(), pingPoll: unnotifiedPingPoll,
	}
	if notifier, ok := cfg.Space.(service.FolderChangeNotifier); ok {
		context.AfterFunc(ctx, notifier.OnChangesCommitted(h.waits.changesCommitted))
		h.pingPoll = notifiedPingPoll
	}
	return h, nil
}

// DeviceStates exposes the protocol-owned partnership registry to a thin
// executable adapter. The web package deliberately depends on a redacted
// interface so noeas builds do not retain this implementation.
func (h *Handler) DeviceStates() *StateStore { return h.states }

// commandContext carries one authenticated request through a command.
type commandContext struct {
	ctx     context.Context
	access  service.AccessContext
	userID  string
	line    requestLine
	state   *DeviceState
	request *Node
	// raw is a message/rfc822 body: protocol 12.1 and earlier send
	// SendMail, SmartReply and SmartForward as plain MIME, not WBXML.
	raw []byte
	// profile caches the account profile for the request.
	profile *Profile
	// rawResponse replaces the WBXML body (GetAttachment).
	rawResponse    []byte
	rawContentType string
}

func (c *commandContext) version(major, minor int) bool {
	return versionAtLeast(c.line.Version, major, minor)
}

var supportedCommands = map[string]bool{
	"Sync": true, "SendMail": true, "SmartForward": true, "SmartReply": true, "GetAttachment": true,
	"FolderSync": true, "FolderCreate": true, "FolderDelete": true, "FolderUpdate": true,
	"MoveItems": true, "GetItemEstimate": true, "MeetingResponse": true, "Search": true,
	"Settings": true, "Ping": true, "ItemOperations": true, "Provision": true,
	"ResolveRecipients": true, "Find": true,
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("MS-Server-ActiveSync", serverVersion)
		w.Header().Set("MS-ASProtocolVersions", protocolVersions)
		w.Header().Set("MS-ASProtocolCommands", protocolCommands)
		w.Header().Set("Allow", "OPTIONS,POST")
		w.Header().Set("Public", "OPTIONS,POST")
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "OPTIONS,POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		h.unauthorized(w)
		return
	}
	userID, err := h.authenticate(r.Context(), username, password)
	if err != nil {
		h.unauthorized(w)
		return
	}
	line, err := parseRequestLine(r)
	if err != nil || line.Command == "" || line.DeviceID == "" {
		http.Error(w, "Cmd and DeviceId are required", http.StatusBadRequest)
		return
	}
	if !supportedCommands[line.Command] {
		http.Error(w, "command not implemented", http.StatusNotImplemented)
		return
	}
	command := &commandContext{ctx: r.Context(), access: service.UserAccess(userID, "eas"), userID: userID, line: line}
	if err := h.readRequest(w, r, command); err != nil {
		http.Error(w, "invalid WBXML request", http.StatusBadRequest)
		return
	}
	var response *Node
	var commandErr error
	switch line.Command {
	case "Ping":
		response, commandErr = h.ping(command, r)
	case "Sync":
		response, commandErr = h.syncWithWait(command, r)
	default:
		response, commandErr = h.withState(command, r, func(command *commandContext) (*Node, error) {
			return h.dispatch(command)
		})
	}
	h.writeResponse(w, command, response, commandErr)
}

// withState runs fn under the partnership lock after the common device
// bookkeeping and policy check.
func (h *Handler) withState(command *commandContext, r *http.Request, fn func(*commandContext) (*Node, error)) (*Node, error) {
	var response *Node
	var commandErr error
	err := h.states.Update(command.ctx, command.userID, command.line.DeviceID, func(state *DeviceState) error {
		command.state = state
		h.recordDevice(state, command, r)
		if blocked, blockErr := policyBlock(state, command); blocked != nil || blockErr != nil {
			response, commandErr = blocked, blockErr
			return blockErr
		}
		response, commandErr = fn(command)
		return commandErr
	})
	command.state = nil
	if err != nil && commandErr == nil {
		return nil, errStateUnavailable
	}
	return response, err
}

var errStateUnavailable = errors.New("EAS state unavailable")

// errRetryWithProvision is returned when the client must provision first
// and its protocol version predates in-body policy status codes.
var errRetryWithProvision = errors.New("provisioning required")

func (h *Handler) recordDevice(state *DeviceState, command *commandContext, r *http.Request) {
	now := time.Now().UTC()
	if state.FirstSeenAt.IsZero() {
		state.FirstSeenAt = now
	}
	state.LastSeenAt = now
	state.LastCommand = boundedDeviceValue(command.line.Command, 64)
	if command.line.DeviceType != "" {
		state.DeviceType = boundedDeviceValue(command.line.DeviceType, 128)
	}
	state.Protocol = boundedDeviceValue(command.line.Version, 32)
	state.UserAgent = boundedDeviceValue(r.UserAgent(), 512)
	captureDeviceInformation(state, command.request)
}

func (h *Handler) writeResponse(w http.ResponseWriter, command *commandContext, response *Node, err error) {
	if err != nil {
		switch {
		case errors.Is(err, errRetryWithProvision):
			w.WriteHeader(449)
			return
		case errors.Is(err, errAttachmentNotFound):
			http.Error(w, "attachment not found", http.StatusNotFound)
			return
		case errors.Is(err, errStateUnavailable):
			http.Error(w, "state unavailable", http.StatusServiceUnavailable)
			return
		case errors.Is(err, model.ErrQuotaExceeded):
			http.Error(w, "account quota exceeded", http.StatusInsufficientStorage)
			return
		case service.IsTemporarilyUnavailable(err):
			w.Header().Set("Retry-After", "5")
			http.Error(w, "account temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "command failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("MS-Server-ActiveSync", serverVersion)
	if command.rawResponse != nil {
		w.Header().Set("Content-Type", command.rawContentType)
		_, _ = w.Write(command.rawResponse)
		return
	}
	if response == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	encoded, err := Encode(response)
	if err != nil {
		http.Error(w, "response encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.ms-sync.wbxml")
	_, _ = w.Write(encoded)
}

func captureDeviceInformation(state *DeviceState, request *Node) {
	if request == nil {
		return
	}
	info := request.Descendant("DeviceInformation")
	if info == nil {
		return
	}
	for name, destination := range map[string]*string{
		"Model": &state.Model, "FriendlyName": &state.FriendlyName,
		"OS": &state.OS, "OSLanguage": &state.OSLanguage,
	} {
		if value := info.Descendant(name); value != nil {
			*destination = boundedDeviceValue(value.Text, 256)
		}
	}
}

func boundedDeviceValue(value string, limit int) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, "�"))
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.ValidString(value[:limit]) {
		limit--
	}
	return value[:limit]
}

func (h *Handler) readRequest(w http.ResponseWriter, r *http.Request, command *commandContext) error {
	if r.ContentLength == 0 {
		return nil
	}
	var reader io.Reader = http.MaxBytesReader(w, r.Body, h.maxRequest)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		compressed, err := gzip.NewReader(reader)
		if err != nil {
			return err
		}
		defer func() { _ = compressed.Close() }()
		reader = compressed
	}
	data, err := io.ReadAll(reader)
	if err != nil || len(data) == 0 {
		return err
	}
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if strings.EqualFold(mediaType, "message/rfc822") {
		command.raw = data
		return nil
	}
	command.request, err = Decode(data)
	return err
}

func (h *Handler) dispatch(command *commandContext) (*Node, error) {
	switch command.line.Command {
	case "FolderSync":
		return h.folderSync(command)
	case "FolderCreate":
		return h.folderCreate(command)
	case "FolderDelete":
		return h.folderDelete(command)
	case "FolderUpdate":
		return h.folderUpdate(command)
	case "GetItemEstimate":
		return h.itemEstimate(command)
	case "ItemOperations":
		return h.itemOperations(command)
	case "GetAttachment":
		return h.getAttachment(command)
	case "MoveItems":
		return h.moveItems(command)
	case "Provision":
		return h.provision(command)
	case "SendMail":
		return h.sendMail(command)
	case "SmartForward", "SmartReply":
		return h.smartSend(command)
	case "Settings":
		return h.settings(command)
	case "Search":
		return h.search(command)
	case "Find":
		return h.find(command)
	case "ResolveRecipients":
		return h.resolveRecipients(command)
	case "MeetingResponse":
		return h.meetingResponse(command)
	}
	return nil, nil
}

func (h *Handler) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Veksel ActiveSync"`)
	w.WriteHeader(http.StatusUnauthorized)
}

func cleanDeviceID(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" || len(value) > 64 {
		return ""
	}
	for _, r := range value {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return ""
		}
	}
	return value
}

func nodeText(root *Node, tag string) string {
	if root == nil {
		return ""
	}
	found := root.Descendant(tag)
	if found == nil {
		return ""
	}
	return found.Text
}

// childText reads a direct child, which keeps same-named elements of nested
// structures (Status, ServerId, Type) from answering for their parents.
func childText(root *Node, tag string) string {
	if child := root.Child(tag); child != nil {
		return nodeValue(child)
	}
	return ""
}

func nodeValue(node *Node) string {
	if node == nil {
		return ""
	}
	if node.Opaque != nil {
		return string(node.Opaque)
	}
	return node.Text
}

func encodeServerID(prefix, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(prefix + id))
}

func decodeServerID(encoded, prefix string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || !strings.HasPrefix(string(decoded), prefix) {
		return "", errors.New("invalid EAS server identifier")
	}
	return strings.TrimPrefix(string(decoded), prefix), nil
}

func itemSubject(item model.Item) string {
	if item.Headers["Subject"] != "" {
		return item.Headers["Subject"]
	}
	message, err := mail.ReadMessage(bytes.NewReader(item.Data))
	if err == nil {
		return message.Header.Get("Subject")
	}
	return item.Name
}

func hasFlag(flags []string, wanted string) bool {
	for _, flag := range flags {
		if strings.EqualFold(flag, wanted) {
			return true
		}
	}
	return false
}

func setFlag(flags []string, wanted string, enabled bool) []string {
	result := make([]string, 0, len(flags)+1)
	found := false
	for _, flag := range flags {
		if strings.EqualFold(flag, wanted) {
			found = true
			if !enabled {
				continue
			}
		}
		result = append(result, flag)
	}
	if enabled && !found {
		result = append(result, wanted)
	}
	return result
}

func boolNumber(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
