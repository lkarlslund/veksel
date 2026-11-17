package proto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/log"
)

// HAProxy PROXY protocol limits. A version 1 header is one text line of at
// most 107 bytes; a version 2 header is a 16-byte preamble followed by an
// address block whose length Veksel caps well above the largest address and
// TLV payload a proxy sends.
const (
	proxyV1MaxLength       = 107
	proxyV2MaxPayload      = 1024
	DefaultProxyTimeout    = 5 * time.Second
	maxConcurrentProxyRead = 256
)

var (
	proxyV1Prefix    = []byte("PROXY ")
	proxyV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

	errMissingProxyHeader   = errors.New("connection did not start with a PROXY protocol header")
	errUntrustedProxyHeader = errors.New("PROXY protocol header from an untrusted source")
)

// ProxyPolicy enables the PROXY protocol on a ProxyListener.
type ProxyPolicy struct {
	// Trusted lists the proxy source prefixes whose connections must begin
	// with a PROXY header. Other sources are served with their socket
	// address and closed if they send a header.
	Trusted []netip.Prefix
	// HeaderTimeout bounds how long a trusted proxy may take to send the
	// header. Zero means DefaultProxyTimeout.
	HeaderTimeout time.Duration
}

func (p *ProxyPolicy) trusts(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	return slices.ContainsFunc(p.Trusted, func(prefix netip.Prefix) bool { return prefix.Contains(ip) })
}

func (p *ProxyPolicy) timeout() time.Duration {
	if p.HeaderTimeout > 0 {
		return p.HeaderTimeout
	}
	return DefaultProxyTimeout
}

// ProxyListener accepts connections whose client address may be relayed by
// a trusted proxy in a PROXY protocol header. Accepted connections report
// the relayed client as their RemoteAddr, so every consumer of the socket
// address (admission, throttling, policy, logs) sees the real client.
//
// Headers are read off the accept path, so a slow proxy never delays other
// connections. The policy can be replaced while the listener runs; a nil
// policy accepts every connection unchanged. Implicit TLS belongs on top of
// a ProxyListener because the header precedes the TLS handshake.
type ProxyListener struct {
	net.Listener
	policy    atomic.Pointer[ProxyPolicy]
	accepted  chan acceptResult
	done      chan struct{}
	closeOnce sync.Once
	reading   chan struct{} // bounds concurrent header reads
}

type acceptResult struct {
	conn net.Conn
	err  error
}

// NewProxyListener wraps ln, applying policy to its connections.
func NewProxyListener(ln net.Listener, policy *ProxyPolicy) *ProxyListener {
	l := &ProxyListener{
		Listener: ln,
		accepted: make(chan acceptResult),
		done:     make(chan struct{}),
		reading:  make(chan struct{}, maxConcurrentProxyRead),
	}
	l.policy.Store(policy)
	go l.run()
	return l
}

// SetPolicy replaces the policy for connections accepted from now on.
func (l *ProxyListener) SetPolicy(policy *ProxyPolicy) {
	l.policy.Store(policy)
}

// Accept returns the next connection ready to be served.
func (l *ProxyListener) Accept() (net.Conn, error) {
	select {
	case result := <-l.accepted:
		return result.conn, result.err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops accepting connections.
func (l *ProxyListener) Close() error {
	err := net.ErrClosed
	l.closeOnce.Do(func() {
		close(l.done)
		err = l.Listener.Close()
	})
	return err
}

func (l *ProxyListener) run() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			if !l.deliver(acceptResult{err: err}) || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		policy := l.policy.Load()
		switch {
		case policy == nil:
			l.deliver(acceptResult{conn: conn})
		case !policy.trusts(conn.RemoteAddr()):
			l.deliver(acceptResult{conn: &proxyConn{Conn: conn, guard: true}})
		default:
			select {
			case l.reading <- struct{}{}:
			case <-l.done:
				_ = conn.Close()
				return
			}
			go func() {
				proxied, err := readProxyHeader(conn, policy.timeout())
				<-l.reading
				if err != nil {
					log.Warn("proxy protocol: refused connection", "listener", l.Addr().String(), "proxy", conn.RemoteAddr().String(), "error", err)
					_ = conn.Close()
					return
				}
				l.deliver(acceptResult{conn: proxied})
			}()
		}
	}
}

// deliver hands result to Accept, closing its connection when the listener
// closes first.
func (l *ProxyListener) deliver(result acceptResult) bool {
	select {
	case l.accepted <- result:
		return true
	case <-l.done:
		if result.conn != nil {
			_ = result.conn.Close()
		}
		return false
	}
}

// proxyConn is a connection whose addresses came from a PROXY header, or an
// untrusted connection guarded against sending one.
type proxyConn struct {
	net.Conn
	remote, local net.Addr // nil keeps the socket address
	pending       []byte   // bytes read past the header, served first
	guard         bool     // refuse a PROXY header on the first read
}

func (c *proxyConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

func (c *proxyConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return c.Conn.LocalAddr()
}

func (c *proxyConn) Read(p []byte) (int, error) {
	if c.guard {
		c.guard = false
		if err := c.refuseHeader(); err != nil {
			return 0, err
		}
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// refuseHeader reads just enough of an untrusted connection's first bytes
// to tell whether it is sending a PROXY header, which only trusted proxies
// may do, and closes it if so.
func (c *proxyConn) refuseHeader() error {
	buf := make([]byte, 0, len(proxyV2Signature))
	for {
		if isProxyHeader(buf) {
			log.Warn("proxy protocol: refused header from untrusted source", "remote", c.Conn.RemoteAddr().String())
			_ = c.Conn.Close()
			return errUntrustedProxyHeader
		}
		if !hasPartialPrefix(buf, proxyV1Prefix) && !hasPartialPrefix(buf, proxyV2Signature) {
			c.pending = buf
			return nil
		}
		n, err := c.Conn.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err != nil {
			c.pending = buf
			if len(buf) == 0 {
				return err
			}
			return nil
		}
	}
}

func isProxyHeader(buf []byte) bool {
	return bytes.HasPrefix(buf, proxyV1Prefix) || bytes.HasPrefix(buf, proxyV2Signature)
}

// hasPartialPrefix reports whether buf and prefix agree on their common
// length.
func hasPartialPrefix(buf, prefix []byte) bool {
	n := min(len(buf), len(prefix))
	return bytes.Equal(buf[:n], prefix[:n])
}

// readProxyHeader reads the PROXY header a trusted proxy must send first,
// within timeout, and returns the connection with the relayed addresses.
func readProxyHeader(conn net.Conn, timeout time.Duration) (net.Conn, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(conn, 256)
	remote, local, err := ParseProxyHeader(reader)
	if err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	proxied := &proxyConn{Conn: conn, remote: remote, local: local}
	if n := reader.Buffered(); n > 0 {
		proxied.pending, _ = reader.Peek(n)
	}
	return proxied, nil
}

// ParseProxyHeader reads one PROXY protocol version 1 or 2 header from r and
// returns the client (source) and server (destination) addresses it relays.
// Both are nil for a LOCAL, UNKNOWN, or unspecified-family header, such as a
// proxy health check, whose connection keeps its socket addresses.
func ParseProxyHeader(r *bufio.Reader) (remote, local net.Addr, err error) {
	start, err := r.Peek(len(proxyV1Prefix))
	if err != nil {
		return nil, nil, fmt.Errorf("read PROXY header: %w", err)
	}
	switch {
	case bytes.Equal(start, proxyV1Prefix):
		return parseProxyV1(r)
	case bytes.Equal(start, proxyV2Signature[:len(start)]):
		return parseProxyV2(r)
	default:
		return nil, nil, errMissingProxyHeader
	}
}

func parseProxyV1(r *bufio.Reader) (net.Addr, net.Addr, error) {
	line := make([]byte, 0, proxyV1MaxLength)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, nil, fmt.Errorf("read PROXY v1 header: %w", err)
		}
		line = append(line, b)
		if b == '\n' {
			break
		}
		if len(line) == proxyV1MaxLength {
			return nil, nil, fmt.Errorf("PROXY v1 header exceeds %d bytes", proxyV1MaxLength)
		}
	}
	text, ok := strings.CutSuffix(string(line), "\r\n")
	if !ok {
		return nil, nil, errors.New("PROXY v1 header does not end in CRLF")
	}
	fields := strings.Split(text, " ")
	if len(fields) >= 2 && fields[1] == "UNKNOWN" {
		return nil, nil, nil
	}
	if len(fields) != 6 || (fields[1] != "TCP4" && fields[1] != "TCP6") {
		return nil, nil, fmt.Errorf("malformed PROXY v1 header %q", text)
	}
	ipv4 := fields[1] == "TCP4"
	source, err := proxyV1Address(fields[2], fields[4], ipv4)
	if err != nil {
		return nil, nil, err
	}
	destination, err := proxyV1Address(fields[3], fields[5], ipv4)
	if err != nil {
		return nil, nil, err
	}
	return source, destination, nil
}

func proxyV1Address(host, port string, ipv4 bool) (net.Addr, error) {
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || ip.Is4() != ipv4 {
		return nil, fmt.Errorf("invalid PROXY v1 address %q", host)
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || (len(port) > 1 && port[0] == '0') {
		return nil, fmt.Errorf("invalid PROXY v1 port %q", port)
	}
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(number))), nil
}

func parseProxyV2(r *bufio.Reader) (net.Addr, net.Addr, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, nil, fmt.Errorf("read PROXY v2 header: %w", err)
	}
	if !bytes.Equal(header[:12], proxyV2Signature) {
		return nil, nil, errMissingProxyHeader
	}
	if header[12]>>4 != 2 {
		return nil, nil, fmt.Errorf("unsupported PROXY protocol version %d", header[12]>>4)
	}
	length := binary.BigEndian.Uint16(header[14:16])
	if length > proxyV2MaxPayload {
		return nil, nil, fmt.Errorf("PROXY v2 address block of %d bytes exceeds %d", length, proxyV2MaxPayload)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, fmt.Errorf("read PROXY v2 addresses: %w", err)
	}
	switch header[12] & 0x0f {
	case 0x0: // LOCAL: the proxy's own connection, such as a health check
		return nil, nil, nil
	case 0x1: // PROXY
	default:
		return nil, nil, fmt.Errorf("unsupported PROXY v2 command %d", header[12]&0x0f)
	}
	tcpAddr := func(ip []byte, port []byte) net.Addr {
		addr, _ := netip.AddrFromSlice(ip)
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, binary.BigEndian.Uint16(port)))
	}
	switch header[13] {
	case 0x00: // UNSPEC
		return nil, nil, nil
	case 0x11: // TCP over IPv4
		if len(payload) < 12 {
			return nil, nil, errors.New("short PROXY v2 IPv4 address block")
		}
		return tcpAddr(payload[0:4], payload[8:10]), tcpAddr(payload[4:8], payload[10:12]), nil
	case 0x21: // TCP over IPv6
		if len(payload) < 36 {
			return nil, nil, errors.New("short PROXY v2 IPv6 address block")
		}
		return tcpAddr(payload[0:16], payload[32:34]), tcpAddr(payload[16:32], payload[34:36]), nil
	default:
		return nil, nil, fmt.Errorf("unsupported PROXY v2 address family 0x%02x", header[13])
	}
}
