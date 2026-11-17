package proto

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func proxyV2Header(command, family byte, addresses []byte) []byte {
	header := append([]byte{}, proxyV2Signature...)
	header = append(header, 0x20|command, family, 0, 0)
	binary.BigEndian.PutUint16(header[14:16], uint16(len(addresses)))
	return append(header, addresses...)
}

func TestParseProxyHeader(t *testing.T) {
	v4 := []byte{203, 0, 113, 7, 192, 0, 2, 1, 0xc3, 0x50, 0, 25}
	v6 := make([]byte, 36)
	copy(v6[0:16], netip.MustParseAddr("2001:db8::7").AsSlice())
	copy(v6[16:32], netip.MustParseAddr("2001:db8::1").AsSlice())
	binary.BigEndian.PutUint16(v6[32:34], 50000)
	binary.BigEndian.PutUint16(v6[34:36], 993)
	tests := []struct {
		name           string
		header         string
		remote, local  string // empty: socket addresses kept
		wantErrContain string
	}{
		{name: "v1 tcp4", header: "PROXY TCP4 203.0.113.7 192.0.2.1 50000 25\r\n", remote: "203.0.113.7:50000", local: "192.0.2.1:25"},
		{name: "v1 tcp6", header: "PROXY TCP6 2001:db8::7 2001:db8::1 50000 993\r\n", remote: "[2001:db8::7]:50000", local: "[2001:db8::1]:993"},
		{name: "v1 unknown", header: "PROXY UNKNOWN\r\n"},
		{name: "v1 unknown with addresses", header: "PROXY UNKNOWN 1.2.3.4 5.6.7.8 1 2\r\n"},
		{name: "v2 tcp4", header: string(proxyV2Header(1, 0x11, v4)), remote: "203.0.113.7:50000", local: "192.0.2.1:25"},
		{name: "v2 tcp6", header: string(proxyV2Header(1, 0x21, v6)), remote: "[2001:db8::7]:50000", local: "[2001:db8::1]:993"},
		{name: "v2 tcp4 with tlvs", header: string(proxyV2Header(1, 0x11, append(append([]byte{}, v4...), 0x04, 0, 1, 'x'))), remote: "203.0.113.7:50000", local: "192.0.2.1:25"},
		{name: "v2 local", header: string(proxyV2Header(0, 0x00, nil))},
		{name: "v2 local ignores addresses", header: string(proxyV2Header(0, 0x11, v4))},
		{name: "v2 unspec", header: string(proxyV2Header(1, 0x00, nil))},
		{name: "missing", header: "EHLO client.example\r\n", wantErrContain: "did not start"},
		{name: "v1 family mismatch", header: "PROXY TCP4 2001:db8::7 192.0.2.1 50000 25\r\n", wantErrContain: "invalid PROXY v1 address"},
		{name: "v1 bad port", header: "PROXY TCP4 203.0.113.7 192.0.2.1 70000 25\r\n", wantErrContain: "invalid PROXY v1 port"},
		{name: "v1 leading zero port", header: "PROXY TCP4 203.0.113.7 192.0.2.1 025 25\r\n", wantErrContain: "invalid PROXY v1 port"},
		{name: "v1 zone", header: "PROXY TCP6 fe80::1%eth0 2001:db8::1 1 2\r\n", wantErrContain: "invalid PROXY v1 address"},
		{name: "v1 missing field", header: "PROXY TCP4 203.0.113.7 192.0.2.1 50000\r\n", wantErrContain: "malformed"},
		{name: "v1 udp", header: "PROXY UDP4 203.0.113.7 192.0.2.1 50000 25\r\n", wantErrContain: "malformed"},
		{name: "v1 bare newline", header: "PROXY TCP4 203.0.113.7 192.0.2.1 50000 25\n", wantErrContain: "CRLF"},
		{name: "v1 oversize", header: "PROXY TCP4 " + strings.Repeat("1", 120) + "\r\n", wantErrContain: "exceeds 107"},
		{name: "v1 truncated", header: "PROXY TCP4 203.0.113.7", wantErrContain: "EOF"},
		{name: "v2 version 1", header: string(append(append([]byte{}, proxyV2Signature...), 0x11, 0x11, 0, 0)), wantErrContain: "version"},
		{name: "v2 bad command", header: string(proxyV2Header(2, 0x11, v4)), wantErrContain: "command"},
		{name: "v2 udp", header: string(proxyV2Header(1, 0x12, v4)), wantErrContain: "family"},
		{name: "v2 short ipv4", header: string(proxyV2Header(1, 0x11, v4[:8])), wantErrContain: "short"},
		{name: "v2 short ipv6", header: string(proxyV2Header(1, 0x21, v6[:20])), wantErrContain: "short"},
		{name: "v2 oversize", header: string(proxyV2Header(1, 0x11, make([]byte, proxyV2MaxPayload+1))), wantErrContain: "exceeds"},
		{name: "v2 truncated", header: string(proxyV2Header(1, 0x11, v4)[:20]), wantErrContain: "EOF"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(test.header + "after"))
			remote, local, err := ParseProxyHeader(reader)
			if test.wantErrContain != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrContain) {
					t.Fatalf("error = %v, want containing %q", err, test.wantErrContain)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := addrString(remote); got != test.remote {
				t.Errorf("remote = %q, want %q", got, test.remote)
			}
			if got := addrString(local); got != test.local {
				t.Errorf("local = %q, want %q", got, test.local)
			}
			rest, _ := io.ReadAll(reader)
			if string(rest) != "after" {
				t.Errorf("bytes after the header = %q, want %q", rest, "after")
			}
		})
	}
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func FuzzParseProxyHeader(f *testing.F) {
	f.Add([]byte("PROXY TCP4 203.0.113.7 192.0.2.1 50000 25\r\n"))
	f.Add(proxyV2Header(1, 0x11, []byte{203, 0, 113, 7, 192, 0, 2, 1, 0xc3, 0x50, 0, 25}))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ParseProxyHeader(bufio.NewReader(bytes.NewReader(data)))
	})
}

// proxyTestListener listens on loopback with policy and returns a function
// that dials it and returns both ends of the next accepted connection.
func proxyTestListener(t *testing.T, policy *ProxyPolicy) (*ProxyListener, func(send string) (client, server net.Conn)) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := NewProxyListener(inner, policy)
	t.Cleanup(func() { _ = ln.Close() })
	return ln, func(send string) (net.Conn, net.Conn) {
		t.Helper()
		client, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		if send != "" {
			if _, err := io.WriteString(client, send); err != nil {
				t.Fatal(err)
			}
		}
		return client, acceptWithin(t, ln, 2*time.Second)
	}
}

func acceptWithin(t *testing.T, ln net.Listener, timeout time.Duration) net.Conn {
	t.Helper()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()
	select {
	case conn, ok := <-accepted:
		if !ok {
			return nil
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	case <-time.After(timeout):
		return nil
	}
}

// closedByServer reports whether the server closed client.
func closedByServer(client net.Conn) bool {
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := client.Read(make([]byte, 1))
	return err == io.EOF || (err != nil && !isTimeout(err))
}

func isTimeout(err error) bool {
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

func TestProxyListenerRelaysTrustedClientAddress(t *testing.T) {
	_, dial := proxyTestListener(t, &ProxyPolicy{Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	_, server := dial("PROXY TCP4 203.0.113.7 192.0.2.1 50000 25\r\nEHLO client\r\n")
	if server == nil {
		t.Fatal("trusted proxied connection not accepted")
	}
	if got := server.RemoteAddr().String(); got != "203.0.113.7:50000" {
		t.Fatalf("RemoteAddr = %q, want the relayed client", got)
	}
	if got := server.LocalAddr().String(); got != "192.0.2.1:25" {
		t.Fatalf("LocalAddr = %q, want the relayed destination", got)
	}
	line, err := bufio.NewReader(server).ReadString('\n')
	if err != nil || line != "EHLO client\r\n" {
		t.Fatalf("data after the header = %q, %v", line, err)
	}

	// LOCAL (a proxy health check) keeps the socket address.
	_, server = dial(string(proxyV2Header(0, 0, nil)))
	if server == nil || !strings.HasPrefix(server.RemoteAddr().String(), "127.0.0.1:") {
		t.Fatalf("LOCAL connection = %v", server)
	}
}

func TestProxyListenerRequiresHeaderFromTrustedSources(t *testing.T) {
	ln, dial := proxyTestListener(t, &ProxyPolicy{Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, HeaderTimeout: 200 * time.Millisecond})
	refused := func(send string) net.Conn {
		t.Helper()
		client, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		if _, err := io.WriteString(client, send); err != nil {
			t.Fatal(err)
		}
		return client
	}
	if !closedByServer(refused("EHLO client\r\n")) {
		t.Fatal("trusted connection without a header was not closed")
	}

	// A proxy that stalls mid-header is closed after the timeout and does
	// not hold up other connections.
	slow := refused("PROXY TCP4 203.0.113.7")
	_, fast := dial("PROXY TCP4 203.0.113.8 192.0.2.1 50000 25\r\n")
	if fast == nil || fast.RemoteAddr().String() != "203.0.113.8:50000" {
		t.Fatalf("a slow header delayed the next connection: %v", fast)
	}
	if !closedByServer(slow) {
		t.Fatal("slow header was not closed after the timeout")
	}
}

func TestProxyListenerRefusesHeaderFromUntrustedSources(t *testing.T) {
	_, dial := proxyTestListener(t, &ProxyPolicy{Trusted: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}})
	for _, header := range []string{"PROXY TCP4 203.0.113.7 192.0.2.1 50000 25\r\n", string(proxyV2Header(1, 0x11, make([]byte, 12)))} {
		client, server := dial(header)
		if server == nil {
			t.Fatal("untrusted connection not accepted")
		}
		if !strings.HasPrefix(server.RemoteAddr().String(), "127.0.0.1:") {
			t.Fatalf("untrusted header was honoured: %s", server.RemoteAddr())
		}
		if _, err := server.Read(make([]byte, 64)); err == nil {
			t.Fatal("untrusted header was served as protocol data")
		}
		if !closedByServer(client) {
			t.Fatal("untrusted connection sending a header was not closed")
		}
	}

	// Ordinary traffic from an untrusted source is served directly, even when
	// it arrives one byte at a time.
	client, server := dial("")
	go func() {
		for _, b := range []byte("PRIVMSG\r\n") {
			_, _ = client.Write([]byte{b})
			time.Sleep(5 * time.Millisecond)
		}
	}()
	line, err := bufio.NewReader(server).ReadString('\n')
	if err != nil || line != "PRIVMSG\r\n" {
		t.Fatalf("direct untrusted data = %q, %v", line, err)
	}
}

func TestProxyListenerPolicyAppliesLive(t *testing.T) {
	ln, dial := proxyTestListener(t, nil)
	_, server := dial("")
	if server == nil || !strings.HasPrefix(server.RemoteAddr().String(), "127.0.0.1:") {
		t.Fatal("disabled policy changed the connection")
	}
	ln.SetPolicy(&ProxyPolicy{Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	_, server = dial("PROXY TCP6 2001:db8::7 2001:db8::1 50000 143\r\n")
	if server == nil || server.RemoteAddr().String() != "[2001:db8::7]:50000" {
		t.Fatalf("enabled policy not applied: %v", server)
	}
	ln.SetPolicy(nil)
	_, server = dial("")
	if server == nil || !strings.HasPrefix(server.RemoteAddr().String(), "127.0.0.1:") {
		t.Fatal("policy not disabled live")
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ln.Accept(); err != net.ErrClosed {
		t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
	}
}

// TestProxyListenerPrecedesImplicitTLS sends the header in cleartext before
// the TLS handshake of an implicit-TLS listener.
func TestProxyListenerPrecedesImplicitTLS(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(NewProxyListener(inner, &ProxyPolicy{Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}), selfSignedTLS(t))
	defer ln.Close()
	served := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			served <- err.Error()
			return
		}
		defer conn.Close()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			served <- err.Error()
			return
		}
		served <- conn.RemoteAddr().String() + " " + line
	}()
	raw, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Write(proxyV2Header(1, 0x11, []byte{203, 0, 113, 7, 192, 0, 2, 1, 0xc3, 0x50, 0x03, 0xe1})); err != nil {
		t.Fatal(err)
	}
	client := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	if _, err := io.WriteString(client, "a1 CAPABILITY\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-served:
		if got != "203.0.113.7:50000 a1 CAPABILITY\r\n" {
			t.Fatalf("served %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("implicit TLS session behind PROXY header not served")
	}
}

func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"mail.example.test"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}
