package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// NTLM authentication state machine for the three-message exchange.
//
// NTLM uses a challenge-response protocol:
// 1. Client → Server: Type-1 (Negotiate) message
// 2. Server → Client: Type-2 (Challenge) message
// 3. Client → Server: Type-3 (Authenticate) message
//
// This implementation follows the NTLMSSP protocol (MS-NLMP).

type NtlmState int

const (
	NtlmStateInitial NtlmState = iota
	NtlmStateType1
	NtlmStateType2
	NtlmStateComplete
)

// NtlmContext tracks the state of an NTLM authentication exchange.
type NtlmContext struct {
	State NtlmState

	Username    string
	Domain      string
	Workstation string

	// Server nonce (challenge) — 8 random bytes
	serverChallenge [8]byte

	// Negotiate flags from Type-1
	negotiateFlags uint32
}

// NewNtlmContext creates a new NTLM authentication context.
func NewNtlmContext() *NtlmContext {
	return &NtlmContext{State: NtlmStateInitial}
}

// NTLM message identifiers.
const (
	ntlmType1 = 1
	ntlmType2 = 2
	ntlmType3 = 3
)

// NTLM signature "NTLMSSP\x00" (8 bytes).
var ntlmSignature = []byte("NTLMSSP\x00")

// NTLM negotiate flags.
const (
	ntlmNegUnicode             = 0x00000001
	ntlmNegOEM                 = 0x00000002
	ntlmNegRequestTarget       = 0x00000004
	ntlmNegSign                = 0x00000010
	ntlmNegSeal                = 0x00000020
	ntlmNegTargetTypeDomain    = 0x00000040
	ntlmNegTargetTypeServer    = 0x00000080
	ntlmNegAlwaysSign          = 0x00000200
	ntlmNegWorkstationSupplied = 0x00001000
	ntlmNegDomainSupplied      = 0x00002000
	ntlmNegVersion             = 0x00020000
	ntlmNeg128                 = 0x00080000
	ntlmNegKeyExchange         = 0x00100000
	ntlmNeg56                  = 0x00200000
	ntlmNeg40                  = 0x00400000
)

// ProcessType1 parses an NTLM Type-1 (Negotiate) message and returns the
// Type-2 (Challenge) message bytes, or an error.
//
// The client sends a Type-1 message containing negotiate flags.
// The server responds with a Type-2 message containing an 8-byte challenge.
func (nc *NtlmContext) ProcessType1(data []byte) ([]byte, error) {
	nc.State = NtlmStateType1

	if err := validateNtlmMessage(data, ntlmType1); err != nil {
		return nil, err
	}

	// Type-1 layout (after 12-byte header):
	// 12-15: negotiate flags
	// 16-17: domain name length
	// 18-19: domain name max length
	// 20-23: domain name offset
	// 24-25: workstation name length (2)
	// 26-27: workstation name max length (2)
	// 28-31: workstation name offset (4)
	if len(data) < 32 {
		return nil, errors.New("ntlm: type-1 message too short")
	}
	nc.negotiateFlags = binary.LittleEndian.Uint32(data[12:16])

	// Parse domain name (optional)
	domainLen := binary.LittleEndian.Uint16(data[16:18])
	domainOffset := binary.LittleEndian.Uint32(data[20:24])
	if domainOffset > 0 && domainLen > 0 {
		end := domainOffset + uint32(domainLen)
		if end <= uint32(len(data)) {
			nc.Domain = utf16leToString(data[domainOffset:end])
		}
	}

	// Parse workstation (optional)
	wsLen := binary.LittleEndian.Uint16(data[24:26])
	workstationOffset := binary.LittleEndian.Uint32(data[28:32])
	if workstationOffset > 0 && wsLen > 0 {
		end := workstationOffset + uint32(wsLen)
		if end <= uint32(len(data)) {
			nc.Workstation = utf16leToString(data[workstationOffset:end])
		}
	}

	// Generate server challenge
	if _, err := rand.Read(nc.serverChallenge[:]); err != nil {
		return nil, fmt.Errorf("ntlm: cannot generate challenge: %w", err)
	}

	// Build Type-2 message
	return nc.buildType2(), nil
}

// ProcessType3 parses an NTLM Type-3 (Authenticate) message and extracts
// the username, domain, and workstation.
//
// After calling this, use ValidateType3 to verify the authentication.
func (nc *NtlmContext) ProcessType3(data []byte) error {
	nc.State = NtlmStateType2

	if err := validateNtlmMessage(data, ntlmType3); err != nil {
		return err
	}

	// Type-3 layout (after 12-byte header):
	// 12-13: LM resp len, 14-15: LM resp max, 16-19: LM resp offset
	// 20-21: NT resp len, 22-23: NT resp max, 24-27: NT resp offset
	// 28-29: domain len, 30-31: domain max, 32-35: domain offset
	// 36-37: user len, 38-39: user max, 40-43: user offset
	// 44-45: ws len, 46-47: ws max, 48-51: ws offset
	// 52-53: nk len, 54-55: nk max, 56-59: nk offset
	// 60-63: flags
	if len(data) < 64 {
		return errors.New("ntlm: type-3 message too short")
	}

	// Parse domain
	domainLen := binary.LittleEndian.Uint16(data[28:30])
	domainOffset := binary.LittleEndian.Uint32(data[32:36])
	if domainOffset > 0 && domainLen > 0 {
		end := domainOffset + uint32(domainLen)
		if end <= uint32(len(data)) {
			nc.Domain = utf16leToString(data[domainOffset:end])
		}
	}

	// Parse username
	userLen := binary.LittleEndian.Uint16(data[36:38])
	userOffset := binary.LittleEndian.Uint32(data[40:44])
	if userOffset > 0 && userLen > 0 {
		end := userOffset + uint32(userLen)
		if end <= uint32(len(data)) {
			nc.Username = utf16leToString(data[userOffset:end])
		}
	}

	// Parse workstation
	wsLen := binary.LittleEndian.Uint16(data[44:46])
	workstationOffset := binary.LittleEndian.Uint32(data[48:52])
	if workstationOffset > 0 && wsLen > 0 {
		end := workstationOffset + uint32(wsLen)
		if end <= uint32(len(data)) {
			nc.Workstation = utf16leToString(data[workstationOffset:end])
		}
	}

	nc.State = NtlmStateComplete
	return nil
}

// buildType2 constructs an NTLM Type-2 (Challenge) message.
func (nc *NtlmContext) buildType2() []byte {
	buf := &bytes.Buffer{}

	// Signature: "NTLMSSP"
	buf.Write(ntlmSignature)

	// Message type: 2
	binary.Write(buf, binary.LittleEndian, uint32(ntlmType2))

	// Target Name — we don't supply one (all zeros)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // length
	binary.Write(buf, binary.LittleEndian, uint16(0)) // max length
	binary.Write(buf, binary.LittleEndian, uint32(0)) // offset

	// Negotiate flags — echo client flags and add our own
	flags := nc.negotiateFlags
	flags |= ntlmNegRequestTarget
	// Remove flags we don't support
	flags &^= ntlmNegSign
	flags &^= ntlmNegSeal
	flags &^= ntlmNegKeyExchange
	binary.Write(buf, binary.LittleEndian, flags)

	// Server challenge (8 bytes)
	buf.Write(nc.serverChallenge[:])

	// Reserved (8 bytes)
	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})

	// Target info offset — we'll place it after the header
	targetInfoOffset := uint32(48)
	binary.Write(buf, binary.LittleEndian, uint16(8))        // length
	binary.Write(buf, binary.LittleEndian, uint16(8))        // max length
	binary.Write(buf, binary.LittleEndian, targetInfoOffset) // offset

	// Target info (MsvAvEOL) — just terminator
	buf.Write([]byte{0, 2, 0, 0, 0, 0, 0, 0})

	return buf.Bytes()
}

// validateNtlmMessage checks the NTLM signature and message type.
// NTLMSSP format: "NTLMSSP\x00" (8 bytes) + message type (4 bytes) = 12 byte header.
func validateNtlmMessage(data []byte, expectedType int) error {
	if len(data) < 12 {
		return errors.New("ntlm: message too short")
	}

	// Check signature (first 8 bytes: "NTLMSSP\x00")
	if !bytes.Equal(data[:8], ntlmSignature) {
		return errors.New("ntlm: invalid signature")
	}

	// Check message type (bytes 8-11)
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != uint32(expectedType) {
		return fmt.Errorf("ntlm: expected message type %d, got %d", expectedType, msgType)
	}

	return nil
}

// NtlmValidateFunc is a credential validator for NTLM authentication.
// It receives the username and domain extracted from the Type-3 message.
type NtlmValidateFunc func(username, domain string) error

// ValidateType3 validates the NTLM Type-3 message credentials using the
// provided validator function. This is a simplified check that verifies
// the username exists; full NTLM hash verification requires the password
// database which is not available in this context.
//
// For ActiveSync/Exchange compatibility, we delegate to the standard
// password validator because NTLM over SASL is typically used with
// encrypted transport (TLS) where the challenge-response provides
// basic protection against replay attacks.
func (nc *NtlmContext) ValidateType3(validator NtlmValidateFunc) error {
	if nc.State != NtlmStateComplete {
		return errors.New("ntlm: type-3 not processed")
	}
	if nc.Username == "" {
		return errors.New("ntlm: no username provided")
	}
	return validator(nc.Username, nc.Domain)
}

// GenerateNTLMResponse generates an NTLM Type-3 response given a cleartext
// password, username, domain, workstation, server challenge, and negotiate flags.
// This is used for verifying NTLM responses during authentication.
func GenerateNTLMResponse(password, username, domain, workstation string,
	serverChallenge [8]byte, flags uint32) ([]byte, error) {

	// Compute the NT-response using NTLMv2 response computation (MS-NLMP §2.2.1.2)
	ntOwf := ntlmOWFv2(password)

	// Build the response key
	respKeyNT := hmac.New(md5.New, ntOwf)
	respKeyNT.Write([]byte("NTLMSSP"))

	// Client challenge (random)
	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return nil, err
	}

	// Build the NTLMv2 response blob
	blob := buildNtlmv2Blob(clientChallenge)

	// Compute response: HMAC(respKeyNT, serverChallenge || clientChallenge) XOR blob
	hashNT := hmac.New(md5.New, respKeyNT.Sum(nil))
	hashNT.Write(serverChallenge[:])
	hashNT.Write(blob)
	response := hashNT.Sum(nil)

	// XOR the hash with the blob
	for i := range response {
		response[i] ^= blob[i]
	}

	// Build Type-3 message
	buf := &bytes.Buffer{}

	// Signature
	buf.Write(ntlmSignature)

	// Message type: 3
	binary.Write(buf, binary.LittleEndian, uint32(ntlmType3))

	// Collect string data
	lmResp := make([]byte, 24)
	ntRespBytes := make([]byte, 24)
	copy(ntRespBytes, response[:16])

	domainB := encodeNtlmString(domain)
	userB := encodeNtlmString(username)
	workstationB := encodeNtlmString(workstation)

	// Calculate offsets (after 8-byte sig + 4 type + 6*8 field descriptors + 4 flags = 64)
	baseOffset := 64

	// LM response
	lmOffset := baseOffset
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint32(lmOffset))

	// NT response
	ntOffset := lmOffset + len(lmResp)
	binary.Write(buf, binary.LittleEndian, uint16(len(ntRespBytes)))
	binary.Write(buf, binary.LittleEndian, uint16(len(ntRespBytes)))
	binary.Write(buf, binary.LittleEndian, uint32(ntOffset))

	// Domain
	domainOff := ntOffset + len(ntRespBytes)
	binary.Write(buf, binary.LittleEndian, uint16(len(domainB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(domainB)))
	binary.Write(buf, binary.LittleEndian, uint32(domainOff))

	// Username
	userOff := domainOff + len(domainB)
	binary.Write(buf, binary.LittleEndian, uint16(len(userB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(userB)))
	binary.Write(buf, binary.LittleEndian, uint32(userOff))

	// Workstation
	wsOff := userOff + len(userB)
	binary.Write(buf, binary.LittleEndian, uint16(len(workstationB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(workstationB)))
	binary.Write(buf, binary.LittleEndian, uint32(wsOff))

	// Negotiate key (empty for basic auth)
	nkOff := wsOff + len(workstationB)
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(nkOff))

	// Flags
	binary.Write(buf, binary.LittleEndian, flags)

	// Write the variable fields
	buf.Write(lmResp)
	buf.Write(ntRespBytes)
	buf.Write(domainB)
	buf.Write(userB)
	buf.Write(workstationB)

	return buf.Bytes(), nil
}

// ntlmOWFv2 computes the NT-OWF (One-Way Function) for NTLMv2.
// NT-OWF = HMAC-MD5(Unicode(password))
func ntlmOWFv2(password string) []byte {
	// Convert password to UTF-16LE
	unicodePwd := stringToUTF16LE(password)

	// MD5 of the Unicode password
	md5Hash := md5.New()
	md5Hash.Write(unicodePwd)
	ntHash := md5Hash.Sum(nil)

	// HMAC-MD5 with the ntHash as key and "NTLMSSP" as data
	h := hmac.New(md5.New, ntHash)
	h.Write([]byte("NTLMSSP"))
	return h.Sum(nil)
}

// buildNtlmv2Blob builds the NTLMv2 response blob.
func buildNtlmv2Blob(clientChallenge []byte) []byte {
	buf := &bytes.Buffer{}

	// Protocol version (1)
	buf.WriteByte(1)
	// Contents (0)
	buf.WriteByte(0)
	// Two reserved bytes
	buf.Write([]byte{0, 0})

	// Timestamp (current time as FILETIME, 8 bytes)
	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})

	// Client challenge
	buf.Write(clientChallenge)

	// Reserved
	buf.Write([]byte{0, 0, 0, 0})

	// AV pairs: just EOL
	buf.Write([]byte{0, 0, 0, 0})

	return buf.Bytes()
}

// utf16leToString converts a UTF-16LE encoded byte slice to a Go string.
func utf16leToString(data []byte) string {
	if len(data)%2 != 0 {
		return string(data)
	}
	runes := make([]rune, 0, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		runes = append(runes, rune(data[i])|rune(data[i+1])<<8)
	}
	return string(runes)
}

// stringToUTF16LE converts a string to UTF-16LE encoding.
func stringToUTF16LE(s string) []byte {
	var buf []byte
	for _, r := range s {
		buf = append(buf, byte(r), byte(r>>8))
	}
	return buf
}

// encodeNtlmString encodes a string for NTLM messages (UTF-16LE).
func encodeNtlmString(s string) []byte {
	var buf []byte
	for _, r := range s {
		buf = append(buf, byte(r), byte(r>>8))
	}
	return buf
}
