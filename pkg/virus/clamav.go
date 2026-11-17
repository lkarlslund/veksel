package virus

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	clamAVChunkBytes   = 64 * 1024
	clamAVMaxReplySize = 4096
)

// ClamAVScanner connects to clamd over TCP or a local Unix socket and uses
// the framed, length-prefixed INSTREAM protocol.
type ClamAVScanner struct {
	address string
	timeout time.Duration
}

// NewClamAVScanner accepts host:port, unix:/path, or an absolute Unix-socket
// path. Clamd TCP has no transport security and should only be used on a
// trusted network.
func NewClamAVScanner(address string) *ClamAVScanner {
	return &ClamAVScanner{address: strings.TrimSpace(address), timeout: 30 * time.Second}
}

// Scan preserves the legacy scanner boundary while ScanContext provides the
// cancellable implementation used by the generic content pipeline.
func (s *ClamAVScanner) Scan(data []byte) (name string, infected bool, err error) {
	return s.ScanContext(context.Background(), data)
}

// ScanContext streams data using zINSTREAM framing and honors cancellation.
func (s *ClamAVScanner) ScanContext(parent context.Context, data []byte) (name string, infected bool, err error) {
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()
	conn, err := s.dial(ctx)
	if err != nil {
		return "", false, fmt.Errorf("clamd unavailable: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := writeAll(conn, []byte("zINSTREAM\x00")); err != nil {
		return "", false, fmt.Errorf("send clamd INSTREAM command: %w", err)
	}
	var length [4]byte
	for offset := 0; offset < len(data); {
		end := min(offset+clamAVChunkBytes, len(data))
		binary.BigEndian.PutUint32(length[:], uint32(end-offset))
		if err := writeAll(conn, length[:]); err != nil {
			return "", false, fmt.Errorf("send clamd chunk length: %w", err)
		}
		if err := writeAll(conn, data[offset:end]); err != nil {
			return "", false, fmt.Errorf("send clamd chunk: %w", err)
		}
		offset = end
	}
	binary.BigEndian.PutUint32(length[:], 0)
	if err := writeAll(conn, length[:]); err != nil {
		return "", false, fmt.Errorf("finish clamd stream: %w", err)
	}
	result, err := readClamAVRecord(conn)
	if err != nil {
		return "", false, fmt.Errorf("read clamd scan result: %w", err)
	}
	if strings.HasSuffix(result, ": OK") {
		return "", false, nil
	}
	if virusName, found := ParseClamavInfection(result); found {
		return virusName, true, nil
	}
	if strings.Contains(result, "ERROR") || strings.Contains(strings.ToLower(result), "size limit exceeded") {
		return "", false, fmt.Errorf("clamd scan error: %s", result)
	}
	return "", false, fmt.Errorf("unexpected clamd response: %q", result)
}

func (s *ClamAVScanner) Name() string { return "clamav" }

// Ping checks liveness and returns the daemon version using separate framed
// commands, since ordinary clamd connections process one command each.
func (s *ClamAVScanner) Ping() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), min(s.timeout, 5*time.Second))
	defer cancel()
	pong, err := s.command(ctx, "PING")
	if err != nil {
		return "", err
	}
	if pong != "PONG" {
		return "", fmt.Errorf("unexpected clamd PING response: %q", pong)
	}
	return s.command(ctx, "VERSION")
}

func (s *ClamAVScanner) command(ctx context.Context, command string) (string, error) {
	conn, err := s.dial(ctx)
	if err != nil {
		return "", fmt.Errorf("clamd unavailable: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := writeAll(conn, append(append([]byte("z"), command...), 0)); err != nil {
		return "", fmt.Errorf("send clamd %s: %w", command, err)
	}
	result, err := readClamAVRecord(conn)
	if err != nil {
		return "", fmt.Errorf("read clamd %s: %w", command, err)
	}
	return result, nil
}

func (s *ClamAVScanner) dial(ctx context.Context) (net.Conn, error) {
	network, address := "tcp", s.address
	if strings.HasPrefix(address, "unix:") {
		network, address = "unix", strings.TrimPrefix(address, "unix:")
	} else if strings.HasPrefix(address, "/") {
		network = "unix"
	}
	if address == "" {
		return nil, errors.New("clamd endpoint is empty")
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func readClamAVRecord(reader io.Reader) (string, error) {
	limited := &io.LimitedReader{R: reader, N: clamAVMaxReplySize + 1}
	record, err := bufio.NewReader(limited).ReadString(0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if len(record) > clamAVMaxReplySize {
		return "", errors.New("clamd response exceeds limit")
	}
	if !strings.HasSuffix(record, "\x00") {
		return "", errors.New("unterminated clamd response")
	}
	return strings.TrimSpace(strings.TrimSuffix(record, "\x00")), nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

// ParseClamavInfection extracts and sanitizes the malware name from a FOUND
// response. It never returns unbounded daemon text as message metadata.
func ParseClamavInfection(response string) (virusName string, infected bool) {
	response = strings.TrimSpace(strings.TrimSuffix(response, "\x00"))
	if !strings.HasSuffix(response, " FOUND") {
		return "", false
	}
	virusName = strings.TrimSpace(strings.TrimSuffix(response, " FOUND"))
	if index := strings.Index(virusName, ":"); index >= 0 {
		virusName = strings.TrimSpace(virusName[index+1:])
	}
	cleanRe := regexp.MustCompile(`[^a-zA-Z0-9_.-]`)
	virusName = cleanRe.ReplaceAllString(virusName, "_")
	if len(virusName) > 255 {
		virusName = virusName[:255]
	}
	return virusName, virusName != ""
}
