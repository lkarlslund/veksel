// Package pop3 implements a bounded, read-only POP3 synchronization source.
package pop3

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
)

const (
	defaultPageSize   = 100
	defaultTimeout    = 30 * time.Second
	maxLineBytes      = 1 << 20
	maxMessageBytes   = 128 << 20
	maxMailboxItems   = 100_000
	maxCheckpointSize = 6 << 20
	checkpointVersion = 1
)

type Config struct {
	Address   string
	Username  string
	Password  string
	TLSMode   migration.MailSecurityMode
	TLSConfig *tls.Config
	PageSize  int
	Timeout   time.Duration
}

type Source struct {
	conn     net.Conn
	reader   *bufio.Reader
	identity string
	pageSize int
	timeout  time.Duration
	uidls    []uidlEntry
}

type uidlEntry struct {
	Number int
	ID     string
}

type checkpoint struct {
	Version    int    `json:"version"`
	Known      string `json:"known,omitempty"`
	ScanDigest string `json:"scan_digest,omitempty"`
	LastUIDL   string `json:"last_uidl,omitempty"`
}

func Dial(ctx context.Context, cfg Config) (*Source, error) {
	cfg.Address, cfg.Username = strings.TrimSpace(cfg.Address), strings.TrimSpace(cfg.Username)
	if cfg.Address == "" || cfg.Username == "" {
		return nil, errors.New("POP3 address and username are required")
	}
	if invalidCommandValue(cfg.Username) || invalidCommandValue(cfg.Password) {
		return nil, errors.New("POP3 credentials contain invalid command characters")
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = defaultPageSize
	}
	if cfg.PageSize > 1000 {
		return nil, errors.New("POP3 page size must not exceed 1000")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	mode, err := migration.NormalizeMailSecurityMode(string(cfg.TLSMode))
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	var conn net.Conn
	if mode == migration.MailSecurityImplicit {
		var tlsConfig *tls.Config
		if tlsConfig, err = tlsConfiguration(cfg.Address, cfg.TLSConfig); err != nil {
			return nil, err
		}
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", cfg.Address)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", cfg.Address)
	}
	if err != nil {
		return nil, fmt.Errorf("connect POP3: %w", err)
	}
	source := &Source{conn: conn, reader: bufio.NewReaderSize(conn, 64<<10), identity: "pop3://" + cfg.Username + "@" + cfg.Address, pageSize: cfg.PageSize, timeout: cfg.Timeout}
	failed := true
	defer func() {
		if failed {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(operationDeadline(ctx, cfg.Timeout))
	if _, err := source.readResponse(ctx); err != nil {
		return nil, fmt.Errorf("read POP3 greeting: %w", err)
	}
	if mode == migration.MailSecurityStartTLS {
		if _, err := source.command(ctx, "STLS"); err != nil {
			return nil, fmt.Errorf("start POP3 TLS: %w", err)
		}
		tlsConfig, err := tlsConfiguration(cfg.Address, cfg.TLSConfig)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("handshake POP3 TLS: %w", err)
		}
		source.conn, source.reader = tlsConn, bufio.NewReaderSize(tlsConn, 64<<10)
	}
	if _, err := source.command(ctx, "USER "+cfg.Username); err != nil {
		return nil, fmt.Errorf("authenticate POP3 username: %w", err)
	}
	if _, err := source.command(ctx, "PASS "+cfg.Password); err != nil {
		return nil, errors.New("authenticate POP3 password: credentials were rejected")
	}
	failed = false
	return source, nil
}

func (s *Source) ID() string { return s.identity }

func (s *Source) Close() error {
	if s.conn == nil {
		return nil
	}
	_, _ = s.command(context.Background(), "QUIT")
	err := s.conn.Close()
	s.conn = nil
	return err
}

func (s *Source) Folders(ctx context.Context) ([]migration.Folder, error) {
	response, err := s.command(ctx, "STAT")
	if err != nil {
		return nil, fmt.Errorf("read POP3 mailbox status: %w", err)
	}
	fields := strings.Fields(response)
	if len(fields) < 3 {
		return nil, errors.New("POP3 STAT response is malformed")
	}
	count, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || count < 0 || count > maxMailboxItems {
		return nil, errors.New("POP3 STAT message count is invalid or exceeds the supported bound")
	}
	return []migration.Folder{{ID: "INBOX", Name: "Inbox", Type: model.FolderTypeMail, Special: model.SpecialUseInbox, Estimate: count, EstimateKnown: true}}, nil
}

func (s *Source) Items(ctx context.Context, folder migration.Folder, token string) (migration.Page, error) {
	if folder.ID != "INBOX" || folder.Type != model.FolderTypeMail {
		return migration.Page{}, errors.New("POP3 source exposes only its Inbox")
	}
	state, known, err := decodeCheckpoint(token)
	if err != nil {
		return migration.Page{}, err
	}
	uidls, err := s.listUIDLs(ctx)
	if err != nil {
		return migration.Page{}, err
	}
	digest := inventoryDigest(uidls)
	if state.ScanDigest != "" && state.ScanDigest != digest {
		state.LastUIDL = ""
	}
	pending := make([]uidlEntry, 0, len(uidls))
	for _, entry := range uidls {
		if _, exists := known[sha256.Sum256([]byte(entry.ID))]; !exists {
			pending = append(pending, entry)
		}
	}
	start := 0
	if state.LastUIDL != "" {
		found := false
		for index, entry := range pending {
			if entry.ID == state.LastUIDL {
				start, found = index+1, true
				break
			}
		}
		if !found {
			start = 0
		}
	}
	end := min(start+s.pageSize, len(pending))
	items := make([]migration.Item, 0, end-start)
	for _, entry := range pending[start:end] {
		if err := ctx.Err(); err != nil {
			return migration.Page{}, err
		}
		data, err := s.retrieve(ctx, entry.Number)
		if err != nil {
			return migration.Page{}, fmt.Errorf("retrieve POP3 item %s: %w", opaqueUIDL(entry.ID), err)
		}
		headers, date := messageMetadata(data)
		items = append(items, migration.Item{ID: entry.ID, Version: entry.ID, Data: data, Headers: headers, InternalDate: date})
	}
	done := end == len(pending)
	if done {
		state = checkpoint{Version: checkpointVersion, Known: encodeKnown(uidls)}
	} else {
		state.ScanDigest, state.LastUIDL = digest, pending[end-1].ID
	}
	encoded, err := json.Marshal(state)
	if err != nil || len(encoded) > maxCheckpointSize {
		return migration.Page{}, errors.New("POP3 checkpoint exceeds the supported bound")
	}
	return migration.Page{Items: items, Checkpoint: string(encoded), Done: done, InitialCoverageComplete: done, SourceExplicitlyEmpty: len(uidls) == 0}, nil
}

func (s *Source) listUIDLs(ctx context.Context) ([]uidlEntry, error) {
	if s.uidls != nil {
		return s.uidls, nil
	}
	if _, err := s.command(ctx, "UIDL"); err != nil {
		return nil, fmt.Errorf("list POP3 UIDLs: %w", err)
	}
	lines, err := s.readMultiline(ctx, 16<<20)
	if err != nil {
		return nil, fmt.Errorf("read POP3 UIDLs: %w", err)
	}
	if len(lines) > maxMailboxItems {
		return nil, errors.New("POP3 UIDL list exceeds the supported item bound")
	}
	entries := make([]uidlEntry, 0, len(lines))
	numbers, ids := map[int]struct{}{}, map[string]struct{}{}
	for _, line := range lines {
		fields := strings.Fields(string(line))
		if len(fields) != 2 {
			return nil, errors.New("POP3 UIDL response contains a malformed entry")
		}
		number, err := strconv.Atoi(fields[0])
		if err != nil || number < 1 || !validUIDL(fields[1]) {
			return nil, errors.New("POP3 UIDL response contains an invalid entry")
		}
		if _, duplicate := numbers[number]; duplicate {
			return nil, errors.New("POP3 UIDL response contains a duplicate message number")
		}
		if _, duplicate := ids[fields[1]]; duplicate {
			return nil, errors.New("POP3 UIDL response contains a duplicate stable identity")
		}
		numbers[number], ids[fields[1]] = struct{}{}, struct{}{}
		entries = append(entries, uidlEntry{Number: number, ID: fields[1]})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Number < entries[j].Number })
	s.uidls = entries
	return entries, nil
}

func (s *Source) retrieve(ctx context.Context, number int) ([]byte, error) {
	if _, err := s.command(ctx, "RETR "+strconv.Itoa(number)); err != nil {
		return nil, err
	}
	lines, err := s.readMultiline(ctx, maxMessageBytes)
	if err != nil {
		return nil, err
	}
	var data bytes.Buffer
	for _, line := range lines {
		if data.Len()+len(line)+2 > maxMessageBytes {
			return nil, errors.New("POP3 message exceeds the supported size bound")
		}
		data.Write(line)
		data.WriteString("\r\n")
	}
	return data.Bytes(), nil
}

func (s *Source) command(ctx context.Context, command string) (string, error) {
	if s.conn == nil {
		return "", errors.New("POP3 connection is closed")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	stop := context.AfterFunc(ctx, func() { _ = s.conn.SetDeadline(time.Now()) })
	defer stop()
	_ = s.conn.SetDeadline(operationDeadline(ctx, s.timeout))
	if _, err := io.WriteString(s.conn, command+"\r\n"); err != nil {
		return "", networkContextError(ctx, err)
	}
	return s.readResponse(ctx)
}

func (s *Source) readResponse(ctx context.Context) (string, error) {
	line, err := s.readLine()
	if err != nil {
		return "", networkContextError(ctx, err)
	}
	response := string(line)
	if !strings.HasPrefix(response, "+OK") {
		if strings.HasPrefix(response, "-ERR") {
			return "", errors.New("POP3 server rejected the command")
		}
		return "", errors.New("POP3 server returned an invalid response")
	}
	return response, nil
}

func (s *Source) readMultiline(ctx context.Context, maximum int) ([][]byte, error) {
	stop := context.AfterFunc(ctx, func() { _ = s.conn.SetDeadline(time.Now()) })
	defer stop()
	_ = s.conn.SetDeadline(operationDeadline(ctx, s.timeout))
	result, total := [][]byte{}, 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line, err := s.readLine()
		if err != nil {
			return nil, networkContextError(ctx, err)
		}
		if bytes.Equal(line, []byte(".")) {
			return result, nil
		}
		if bytes.HasPrefix(line, []byte("..")) {
			line = line[1:]
		}
		total += len(line) + 2
		if total > maximum {
			return nil, errors.New("POP3 multiline response exceeds the supported size bound")
		}
		result = append(result, append([]byte(nil), line...))
	}
}

func (s *Source) readLine() ([]byte, error) {
	line := make([]byte, 0, 256)
	for {
		fragment, prefix, err := s.reader.ReadLine()
		if err != nil {
			return nil, err
		}
		if len(line)+len(fragment) > maxLineBytes {
			return nil, errors.New("POP3 response line exceeds the supported size bound")
		}
		line = append(line, fragment...)
		if !prefix {
			return line, nil
		}
	}
}

func decodeCheckpoint(token string) (checkpoint, map[[32]byte]struct{}, error) {
	state := checkpoint{Version: checkpointVersion}
	if token != "" {
		if len(token) > maxCheckpointSize || json.Unmarshal([]byte(token), &state) != nil || state.Version != checkpointVersion {
			return checkpoint{}, nil, errors.New("POP3 checkpoint is invalid or unsupported")
		}
		if state.LastUIDL != "" && !validUIDL(state.LastUIDL) {
			return checkpoint{}, nil, errors.New("POP3 checkpoint continuation identity is invalid")
		}
		if state.ScanDigest != "" {
			digest, err := hex.DecodeString(state.ScanDigest)
			if err != nil || len(digest) != 16 {
				return checkpoint{}, nil, errors.New("POP3 checkpoint inventory digest is invalid")
			}
		}
	}
	known := map[[32]byte]struct{}{}
	if state.Known != "" {
		data, err := base64.RawStdEncoding.DecodeString(state.Known)
		if err != nil || len(data)%sha256.Size != 0 || len(data)/sha256.Size > maxMailboxItems {
			return checkpoint{}, nil, errors.New("POP3 checkpoint known-item set is invalid")
		}
		for offset := 0; offset < len(data); offset += sha256.Size {
			var digest [32]byte
			copy(digest[:], data[offset:offset+sha256.Size])
			known[digest] = struct{}{}
		}
	}
	return state, known, nil
}

func encodeKnown(entries []uidlEntry) string {
	digests := make([][32]byte, len(entries))
	for index, entry := range entries {
		digests[index] = sha256.Sum256([]byte(entry.ID))
	}
	sort.Slice(digests, func(i, j int) bool { return bytes.Compare(digests[i][:], digests[j][:]) < 0 })
	data := make([]byte, 0, len(digests)*sha256.Size)
	for _, digest := range digests {
		data = append(data, digest[:]...)
	}
	return base64.RawStdEncoding.EncodeToString(data)
}

func inventoryDigest(entries []uidlEntry) string {
	hash := sha256.New()
	for _, entry := range entries {
		_, _ = fmt.Fprintf(hash, "%d\x00%s\x00", entry.Number, entry.ID)
	}
	return hex.EncodeToString(hash.Sum(nil)[:16])
}

func messageMetadata(data []byte) (map[string]string, time.Time) {
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, time.Time{}
	}
	headers := make(map[string]string, len(message.Header))
	for key := range message.Header {
		headers[key] = message.Header.Get(key)
	}
	date, _ := mail.ParseDate(message.Header.Get("Date"))
	return headers, date
}

func tlsConfiguration(address string, configured *tls.Config) (*tls.Config, error) {
	result := &tls.Config{MinVersion: tls.VersionTLS12}
	if configured != nil {
		result = configured.Clone()
		if result.MinVersion == 0 {
			result.MinVersion = tls.VersionTLS12
		}
	}
	if result.ServerName == "" {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("POP3 address must include a port")
		}
		result.ServerName = host
	}
	return result, nil
}

func operationDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func networkContextError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var networkError net.Error
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) && errors.As(err, &networkError) && networkError.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}

func invalidCommandValue(value string) bool {
	return len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00")
}

func validUIDL(value string) bool {
	if len(value) < 1 || len(value) > 70 {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func opaqueUIDL(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:4])
}
