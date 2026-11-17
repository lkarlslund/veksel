// Package ntlm is an NTLMv2 client for HTTP authentication (MS-NLMP), as
// on-premises Exchange and IIS require when Basic authentication is turned
// off. It binds the authentication to the TLS channel (RFC 5929
// tls-server-end-point), which Exchange's Extended Protection demands, and
// names the HTTP service it authenticates to.
//
// Only authentication is implemented: HTTP needs no NTLM signing or sealing,
// so no session key is exchanged.
package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // MS-NLMP defines NTLMv2 and channel bindings over HMAC-MD5 and MD5.
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // NTOWFv2 is defined over MD4.
)

var signature = []byte("NTLMSSP\x00")

// Negotiate flags (MS-NLMP 2.2.2.5).
const (
	flagUnicode                 = 0x00000001
	flagRequestTarget           = 0x00000004
	flagNTLM                    = 0x00000200
	flagAlwaysSign              = 0x00008000
	flagExtendedSessionSecurity = 0x00080000
	flagTargetInfo              = 0x00800000
	flag128                     = 0x20000000
	flagKeyExchange             = 0x40000000
	flag56                      = 0x80000000
)

// AV_PAIR identifiers (MS-NLMP 2.2.2.1).
const (
	avEOL             = 0x0000
	avTimestamp       = 0x0007
	avTargetName      = 0x0009
	avChannelBindings = 0x000A
)

const negotiateFlags = flagUnicode | flagRequestTarget | flagNTLM | flagAlwaysSign | flagExtendedSessionSecurity | flagTargetInfo | flag128 | flag56

// Negotiate returns the NEGOTIATE message that opens a handshake.
func Negotiate() []byte {
	message := make([]byte, 32)
	copy(message, signature)
	binary.LittleEndian.PutUint32(message[8:], 1)
	binary.LittleEndian.PutUint32(message[12:], negotiateFlags)
	// Domain and workstation fields stay empty; their offsets point at the
	// end of the message.
	binary.LittleEndian.PutUint32(message[20:], 32)
	binary.LittleEndian.PutUint32(message[28:], 32)
	return message
}

// Challenge is a server's CHALLENGE message.
type Challenge struct {
	Flags           uint32
	ServerChallenge [8]byte
	// TargetInfo is the raw AV_PAIR list the server sent.
	TargetInfo []byte
}

// ParseChallenge decodes a CHALLENGE message.
func ParseChallenge(message []byte) (Challenge, error) {
	var challenge Challenge
	if len(message) < 48 || !bytes.Equal(message[:8], signature) || binary.LittleEndian.Uint32(message[8:]) != 2 {
		return challenge, errors.New("ntlm: not a CHALLENGE message")
	}
	challenge.Flags = binary.LittleEndian.Uint32(message[20:])
	copy(challenge.ServerChallenge[:], message[24:32])
	if challenge.Flags&flagTargetInfo != 0 {
		length, offset := int(binary.LittleEndian.Uint16(message[40:])), int(binary.LittleEndian.Uint32(message[44:]))
		if offset > len(message) || length > len(message)-offset {
			return challenge, errors.New("ntlm: CHALLENGE target information is out of bounds")
		}
		challenge.TargetInfo = bytes.Clone(message[offset : offset+length])
		if _, err := avPairs(challenge.TargetInfo); err != nil {
			return challenge, err
		}
	}
	return challenge, nil
}

type avPair struct {
	id    uint16
	value []byte
}

// avPairs decodes an AV_PAIR list up to MsvAvEOL.
func avPairs(data []byte) ([]avPair, error) {
	var pairs []avPair
	for len(data) >= 4 {
		id, length := binary.LittleEndian.Uint16(data), int(binary.LittleEndian.Uint16(data[2:]))
		if id == avEOL {
			return pairs, nil
		}
		if length > len(data)-4 {
			break
		}
		pairs = append(pairs, avPair{id: id, value: data[4 : 4+length]})
		data = data[4+length:]
	}
	return nil, errors.New("ntlm: malformed target information")
}

func encodeAVPairs(pairs []avPair) []byte {
	var out bytes.Buffer
	for _, pair := range append(pairs, avPair{id: avEOL}) {
		_ = binary.Write(&out, binary.LittleEndian, pair.id)
		_ = binary.Write(&out, binary.LittleEndian, uint16(len(pair.value)))
		out.Write(pair.value)
	}
	return out.Bytes()
}

// Credentials name the account. User may be "DOMAIN\user", a user
// principal name ("user@example.local", sent as is with an empty domain),
// or a plain user name.
type Credentials struct {
	User     string
	Password string
}

func (c Credentials) split() (user, domain string) {
	if domain, user, ok := strings.Cut(c.User, `\`); ok {
		return user, domain
	}
	return c.User, ""
}

// Binding is what the AUTHENTICATE message is bound to.
type Binding struct {
	// ChannelBindings is the MD5 of the GSS channel bindings, from
	// TLSChannelBindings; nil sends the all-zero value of an unbound
	// channel.
	ChannelBindings []byte
	// ServicePrincipal is the target service, such as "HTTP/mail.example.com".
	ServicePrincipal string
}

// Authenticate answers challenge with an NTLMv2 AUTHENTICATE message.
func Authenticate(challenge Challenge, credentials Credentials, binding Binding) ([]byte, error) {
	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return nil, err
	}
	return authenticate(challenge, credentials, binding, clientChallenge, time.Now())
}

func authenticate(challenge Challenge, credentials Credentials, binding Binding, clientChallenge []byte, now time.Time) ([]byte, error) {
	if challenge.Flags&flagUnicode == 0 {
		return nil, errors.New("ntlm: the server does not negotiate Unicode")
	}
	user, domain := credentials.split()
	serverPairs, err := avPairs(challenge.TargetInfo)
	if challenge.TargetInfo == nil {
		serverPairs, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	timestamp := windowsTime(now)
	pairs := make([]avPair, 0, len(serverPairs)+2)
	for _, pair := range serverPairs {
		switch pair.id {
		case avTimestamp:
			timestamp = pair.value
		case avChannelBindings, avTargetName:
			continue
		}
		pairs = append(pairs, pair)
	}
	bindings := binding.ChannelBindings
	if len(bindings) != md5.Size {
		bindings = make([]byte, md5.Size)
	}
	pairs = append(pairs, avPair{id: avChannelBindings, value: bindings})
	if binding.ServicePrincipal != "" {
		pairs = append(pairs, avPair{id: avTargetName, value: utf16le(binding.ServicePrincipal)})
	}

	key := ntowfv2(credentials.Password, user, domain)
	ntResponse := ntlmv2Response(key, challenge.ServerChallenge[:], clientChallenge, timestamp, encodeAVPairs(pairs))
	// With target information, the LM response is 24 zero bytes
	// (MS-NLMP 3.1.5.1.2).
	lmResponse := make([]byte, 24)

	flags := challenge.Flags &^ flagKeyExchange
	fields := [][]byte{lmResponse, ntResponse, utf16le(domain), utf16le(user), nil, nil}
	const headerLength = 72 // through the Version field
	header := make([]byte, headerLength)
	copy(header, signature)
	binary.LittleEndian.PutUint32(header[8:], 3)
	offset := headerLength
	for i, field := range fields {
		position := 12 + i*8
		binary.LittleEndian.PutUint16(header[position:], uint16(len(field)))
		binary.LittleEndian.PutUint16(header[position+2:], uint16(len(field)))
		binary.LittleEndian.PutUint32(header[position+4:], uint32(offset))
		offset += len(field)
	}
	binary.LittleEndian.PutUint32(header[60:], flags)
	message := header
	for _, field := range fields {
		message = append(message, field...)
	}
	return message, nil
}

// ntowfv2 is NTOWFv2 (MS-NLMP 3.3.2).
func ntowfv2(password, user, domain string) []byte {
	hash := md4.New()
	hash.Write(utf16le(password))
	mac := hmac.New(md5.New, hash.Sum(nil))
	mac.Write(utf16le(strings.ToUpper(user) + domain))
	return mac.Sum(nil)
}

// ntlmv2Response is NTProofStr followed by the client blob (MS-NLMP 3.3.2).
func ntlmv2Response(key, serverChallenge, clientChallenge, timestamp, targetInfo []byte) []byte {
	blob := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	blob = append(blob, timestamp...)
	blob = append(blob, clientChallenge...)
	blob = append(blob, 0, 0, 0, 0)
	blob = append(blob, targetInfo...)
	blob = append(blob, 0, 0, 0, 0)
	mac := hmac.New(md5.New, key)
	mac.Write(serverChallenge)
	mac.Write(blob)
	return append(mac.Sum(nil), blob...)
}

func windowsTime(t time.Time) []byte {
	value := make([]byte, 8)
	binary.LittleEndian.PutUint64(value, uint64(t.UnixNano()/100+116444736000000000)) //nolint:gosec // time after 1601 is positive
	return value
}

func utf16le(value string) []byte {
	units := utf16.Encode([]rune(value))
	out := make([]byte, 2*len(units))
	for i, unit := range units {
		binary.LittleEndian.PutUint16(out[2*i:], unit)
	}
	return out
}

// TLSChannelBindings returns the MsvAvChannelBindings value for a TLS
// connection to a server presenting certificate: the MD5 of the GSS channel
// bindings whose application data is "tls-server-end-point:" and the
// certificate hash of RFC 5929 section 4.1.
func TLSChannelBindings(certificate *x509.Certificate) []byte {
	var digest []byte
	switch certificate.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		sum := sha512.Sum384(certificate.Raw)
		digest = sum[:]
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		sum := sha512.Sum512(certificate.Raw)
		digest = sum[:]
	default: // MD5, SHA-1, and SHA-256 signatures all use SHA-256
		sum := sha256.Sum256(certificate.Raw)
		digest = sum[:]
	}
	application := append([]byte("tls-server-end-point:"), digest...)
	// gss_channel_bindings_struct: initiator and acceptor address types and
	// lengths are zero, then the application data length and bytes.
	structure := make([]byte, 20, 20+len(application))
	binary.LittleEndian.PutUint32(structure[16:], uint32(len(application))) //nolint:gosec // bounded by the digest size
	structure = append(structure, application...)
	sum := md5.Sum(structure) //nolint:gosec // defined by MS-NLMP
	return sum[:]
}
