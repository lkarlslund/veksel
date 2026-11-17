// Package proto provides shared line-based protocol utilities
// used by POP3, IMAP, and SMTP handlers.
//
// All three protocols are text-line protocols that share the same
// low-level I/O pattern: a bufio.ReadWriter on a net.Conn, reading
// lines terminated by \n, writing commands, and flushing after each
// response.
package proto

import (
	"bufio"
	"errors"
	"net"
	"strings"
)

// Conn wraps a net.Conn with buffered I/O for line-based protocols.
type Conn struct {
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
}

// New creates a new buffered connection wrapper.
func New(conn net.Conn) *Conn {
	return &Conn{
		conn: conn,
		r:    bufio.NewReader(conn),
		w:    bufio.NewWriter(conn),
	}
}

// Underlying returns the wrapped net.Conn.
func (c *Conn) Underlying() net.Conn {
	return c.conn
}

// MaxLineLength caps a command line read by Conn.ReadLine. POP3 lines are at
// most 255 octets (RFC 2449); the cap leaves room while keeping a client
// from streaming an endless line into memory.
const MaxLineLength = 8 << 10

// ErrLineTooLong reports a line longer than the reader's limit.
var ErrLineTooLong = errors.New("line too long")

// ReadLine reads a single line terminated by \n.
// Returns the line without the trailing newline.
func (c *Conn) ReadLine() (string, error) {
	line, err := ReadBoundedLine(c.r, MaxLineLength)
	return strings.TrimRight(line, "\r\n"), err
}

// ReadBoundedLine reads up to and including the next LF, failing with
// ErrLineTooLong once the line exceeds limit octets. Unlike
// bufio.Reader.ReadString it never buffers more than limit octets of a line.
func ReadBoundedLine(reader *bufio.Reader, limit int) (string, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(line)+len(chunk) > limit {
			return "", ErrLineTooLong
		}
		line = append(line, chunk...)
		if err != bufio.ErrBufferFull {
			return string(line), err
		}
	}
}

// WriteLine writes a line terminated by \r\n and flushes.
func (c *Conn) WriteLine(s string) error {
	if _, err := c.w.WriteString(s + "\r\n"); err != nil {
		return err
	}
	return c.w.Flush()
}

// WriteRaw writes raw bytes and flushes.
// Used for multi-line responses (e.g. RETR, LIST, CAPA).
func (c *Conn) WriteRaw(s string) error {
	_, err := c.w.WriteString(s)
	if err != nil {
		return err
	}
	return c.w.Flush()
}

// Flush flushes the write buffer without writing a newline.
func (c *Conn) Flush() error {
	return c.w.Flush()
}

// Buffered reports how many received bytes are buffered but not yet read.
func (c *Conn) Buffered() int {
	return c.r.Buffered()
}

// ReplaceConn replaces the underlying connection (e.g. after TLS upgrade)
// and recreates the buffered readers/writers.
func (c *Conn) ReplaceConn(conn net.Conn) {
	c.conn = conn
	c.r = bufio.NewReader(conn)
	c.w = bufio.NewWriter(conn)
}
