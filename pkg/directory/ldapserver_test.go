package directory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// testLDAPServer is a minimal in-process LDAPv3 server: simple bind,
// StartTLS, and subtree/base searches with and/or/not/equality/present
// filters. Like many real servers it accepts an unauthenticated bind (a DN
// with an empty password), so tests prove the client never relies on it.
type testLDAPServer struct {
	t        *testing.T
	listener net.Listener
	tls      *tls.Config
	caPEM    string

	mu      sync.Mutex
	entries []testLDAPEntry
	binds   []string
}

type testLDAPEntry struct {
	dn         string
	attributes map[string][]string
}

func newTestLDAPServer(t *testing.T) *testLDAPServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &testLDAPServer{t: t, listener: listener}
	server.tls, server.caPEM = testCertificate(t)
	t.Cleanup(func() { _ = listener.Close() })
	go server.serve()
	return server
}

func (s *testLDAPServer) url() string { return "ldap://" + s.listener.Addr().String() }

func (s *testLDAPServer) add(dn string, attributes map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, testLDAPEntry{dn: dn, attributes: attributes})
}

func (s *testLDAPServer) bindDNs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.binds...)
}

func (s *testLDAPServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *testLDAPServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		packet, err := ber.ReadPacket(conn)
		if err != nil || len(packet.Children) < 2 {
			return
		}
		id := packet.Children[0].Value.(int64)
		op := packet.Children[1]
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			name, password := op.Children[1].Value.(string), op.Children[2].Data.String()
			s.mu.Lock()
			s.binds = append(s.binds, name)
			s.mu.Unlock()
			code := ldap.LDAPResultInvalidCredentials
			if password == "" || s.password(name) == password {
				code = ldap.LDAPResultSuccess
			}
			s.write(conn, id, testResult(ldap.ApplicationBindResponse, code))
		case ldap.ApplicationUnbindRequest:
			return
		case ldap.ApplicationExtendedRequest:
			s.write(conn, id, testResult(ldap.ApplicationExtendedResponse, ldap.LDAPResultSuccess))
			secured := tls.Server(conn, s.tls)
			if secured.Handshake() != nil {
				return
			}
			conn = secured
		case ldap.ApplicationSearchRequest:
			s.search(conn, id, op)
		}
	}
}

func (s *testLDAPServer) password(dn string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.entries {
		if strings.EqualFold(entry.dn, dn) && len(entry.attributes["userPassword"]) > 0 {
			return entry.attributes["userPassword"][0]
		}
	}
	return "\x00no password"
}

func (s *testLDAPServer) search(conn net.Conn, id int64, op *ber.Packet) {
	base := strings.ToLower(op.Children[0].Value.(string))
	scope := op.Children[1].Value.(int64)
	sizeLimit := int(op.Children[3].Value.(int64))
	filter := op.Children[6]
	s.mu.Lock()
	var matches []testLDAPEntry
	baseFound := false
	for _, entry := range s.entries {
		dn := strings.ToLower(entry.dn)
		baseFound = baseFound || dn == base
		inScope := dn == base || scope != ldap.ScopeBaseObject && strings.HasSuffix(dn, ","+base)
		if inScope && testFilterMatches(filter, entry) {
			matches = append(matches, entry)
		}
	}
	s.mu.Unlock()
	if !baseFound && scope == ldap.ScopeBaseObject {
		s.write(conn, id, testResult(ldap.ApplicationSearchResultDone, ldap.LDAPResultNoSuchObject))
		return
	}
	code := ldap.LDAPResultSuccess
	if sizeLimit > 0 && len(matches) > sizeLimit {
		matches, code = matches[:sizeLimit], ldap.LDAPResultSizeLimitExceeded
	}
	for _, entry := range matches {
		result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
		result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, entry.dn, ""))
		attributes := ber.NewSequence("")
		for name, values := range entry.attributes {
			if name == "userPassword" {
				continue
			}
			attribute := ber.NewSequence("")
			attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
			set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
			for _, value := range values {
				set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
			}
			attribute.AppendChild(set)
			attributes.AppendChild(attribute)
		}
		result.AppendChild(attributes)
		s.write(conn, id, result)
	}
	s.write(conn, id, testResult(ldap.ApplicationSearchResultDone, code))
}

func (s *testLDAPServer) write(conn net.Conn, id int64, op *ber.Packet) {
	envelope := ber.NewSequence("")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	envelope.AppendChild(op)
	_, _ = conn.Write(envelope.Bytes())
}

func testResult(tag ber.Tag, code int) *ber.Packet {
	result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), ""))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	return result
}

func testFilterMatches(filter *ber.Packet, entry testLDAPEntry) bool {
	values := func(name string) []string {
		for attribute, values := range entry.attributes {
			if strings.EqualFold(attribute, name) {
				return values
			}
		}
		return nil
	}
	switch filter.Tag {
	case ldap.FilterAnd:
		for _, child := range filter.Children {
			if !testFilterMatches(child, entry) {
				return false
			}
		}
		return true
	case ldap.FilterOr:
		for _, child := range filter.Children {
			if testFilterMatches(child, entry) {
				return true
			}
		}
		return false
	case ldap.FilterNot:
		return !testFilterMatches(filter.Children[0], entry)
	case ldap.FilterEqualityMatch:
		want := filter.Children[1].Data.String()
		for _, value := range values(filter.Children[0].Data.String()) {
			if strings.EqualFold(value, want) {
				return true
			}
		}
		return false
	case ldap.FilterPresent:
		name := filter.Data.String()
		return strings.EqualFold(name, "objectClass") || len(values(name)) > 0
	}
	return false
}

// testCertificate returns a server TLS configuration for 127.0.0.1 and the
// PEM of the self-signed certificate clients must trust.
func testCertificate(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test directory"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
