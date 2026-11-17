package auth

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildType1Message constructs a minimal NTLM Type-1 (Negotiate) message.
func buildType1Message(flags uint32) []byte {
	buf := &bytes.Buffer{}

	// Signature: "NTLMSSP\x00"
	buf.Write([]byte("NTLMSSP\x00"))

	// Message type: 1
	binary.Write(buf, binary.LittleEndian, uint32(1))

	// Flags
	binary.Write(buf, binary.LittleEndian, flags)

	// Domain name (empty)
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Workstation (empty)
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	return buf.Bytes()
}

// buildType1MessageWithDomain constructs a Type-1 message with domain and workstation strings.
func buildType1MessageWithDomain(flags uint32, domain, workstation string) []byte {
	buf := &bytes.Buffer{}

	// Signature: "NTLMSSP\x00"
	buf.Write([]byte("NTLMSSP\x00"))

	// Message type: 1
	binary.Write(buf, binary.LittleEndian, uint32(1))

	// Flags
	binary.Write(buf, binary.LittleEndian, flags)

	// Calculate offsets (after 8-byte sig + 4-byte type + 4-byte flags + 8 domain fields + 8 ws fields)
	baseOffset := 32

	// Encode domain
	domainB := encodeNtlmString(domain)
	domainOff := baseOffset
	binary.Write(buf, binary.LittleEndian, uint16(len(domainB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(domainB)))
	binary.Write(buf, binary.LittleEndian, uint32(domainOff))

	// Encode workstation
	workstationB := encodeNtlmString(workstation)
	wsOff := domainOff + len(domainB)
	binary.Write(buf, binary.LittleEndian, uint16(len(workstationB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(workstationB)))
	binary.Write(buf, binary.LittleEndian, uint32(wsOff))

	// Write variable fields
	buf.Write(domainB)
	buf.Write(workstationB)

	return buf.Bytes()
}

func TestValidateNtlmMessage_Type1(t *testing.T) {
	data := buildType1Message(0x00000001)
	if err := validateNtlmMessage(data, 1); err != nil {
		t.Fatalf("validateNtlmMessage(type1) = %v, want nil", err)
	}
}

func TestValidateNtlmMessage_Type2(t *testing.T) {
	// Build a minimal Type-2 message
	buf := &bytes.Buffer{}
	buf.Write([]byte("NTLMSSP\x00"))
	binary.Write(buf, binary.LittleEndian, uint32(2))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	buf.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8}) // challenge
	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // reserved
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	if err := validateNtlmMessage(buf.Bytes(), 2); err != nil {
		t.Fatalf("validateNtlmMessage(type2) = %v, want nil", err)
	}
}

func TestValidateNtlmMessage_BadSignature(t *testing.T) {
	data := buildType1Message(0)
	data[0] = 'X' // corrupt signature
	err := validateNtlmMessage(data, 1)
	if err == nil {
		t.Fatal("validateNtlmMessage(bad sig) = nil, want error")
	}
}

func TestValidateNtlmMessage_WrongType(t *testing.T) {
	data := buildType1Message(0)
	err := validateNtlmMessage(data, 2)
	if err == nil {
		t.Fatal("validateNtlmMessage(wrong type) = nil, want error")
	}
}

func TestValidateNtlmMessage_TooShort(t *testing.T) {
	err := validateNtlmMessage([]byte("NTLM"), 1)
	if err == nil {
		t.Fatal("validateNtlmMessage(too short) = nil, want error")
	}
}

func TestProcessType1(t *testing.T) {
	t.Parallel()
	nc := NewNtlmContext()

	data := buildType1Message(0x00000001)
	type2, err := nc.ProcessType1(data)
	if err != nil {
		t.Fatalf("ProcessType1() = %v", err)
	}

	if nc.State != NtlmStateType1 {
		t.Fatalf("state = %d, want %d", nc.State, NtlmStateType1)
	}

	// Verify Type-2 message structure
	if err := validateNtlmMessage(type2, 2); err != nil {
		t.Fatalf("Type-2 message invalid: %v", err)
	}

	// Type-2 should be at least 48 bytes (header + target info)
	if len(type2) < 48 {
		t.Fatalf("Type-2 message too short: %d bytes", len(type2))
	}
}

func TestProcessType1_WithDomain(t *testing.T) {
	nc := NewNtlmContext()

	data := buildType1MessageWithDomain(0x00002001, "EXAMPLE", "WORKSTATION1")
	type2, err := nc.ProcessType1(data)
	if err != nil {
		t.Fatalf("ProcessType1() = %v", err)
	}

	if nc.Domain != "EXAMPLE" {
		t.Fatalf("domain = %q, want %q", nc.Domain, "EXAMPLE")
	}

	if nc.Workstation != "WORKSTATION1" {
		t.Fatalf("workstation = %q, want %q", nc.Workstation, "WORKSTATION1")
	}

	if err := validateNtlmMessage(type2, 2); err != nil {
		t.Fatalf("Type-2 message invalid: %v", err)
	}
}

func TestProcessType1_TooShort(t *testing.T) {
	nc := NewNtlmContext()

	// Build a truncated Type-1 (only 15 bytes)
	data := buildType1Message(0)
	data = data[:15]
	_, err := nc.ProcessType1(data)
	if err == nil {
		t.Fatal("ProcessType1(too short) = nil, want error")
	}
}

func TestProcessType3(t *testing.T) {
	t.Parallel()
	nc := NewNtlmContext()

	// Build a Type-3 message with username "testuser" and domain "EXAMPLE"
	buf := &bytes.Buffer{}

	// Signature
	buf.Write([]byte("NTLMSSP\x00"))

	// Message type: 3
	binary.Write(buf, binary.LittleEndian, uint32(3))

	// Calculate offsets (after 8-byte sig + 4 type + 6*8 field descriptors + 4 flags = 64)
	baseOffset := 64

	// LM response (24 bytes of zeros)
	lmResp := make([]byte, 24)
	lmOffset := baseOffset
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint32(lmOffset))

	// NT response (24 bytes of zeros)
	ntResp := make([]byte, 24)
	ntOffset := lmOffset + len(lmResp)
	binary.Write(buf, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(buf, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(buf, binary.LittleEndian, uint32(ntOffset))

	// Domain
	domainB := encodeNtlmString("EXAMPLE")
	domainOff := ntOffset + len(ntResp)
	binary.Write(buf, binary.LittleEndian, uint16(len(domainB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(domainB)))
	binary.Write(buf, binary.LittleEndian, uint32(domainOff))

	// Username
	userB := encodeNtlmString("testuser")
	userOff := domainOff + len(domainB)
	binary.Write(buf, binary.LittleEndian, uint16(len(userB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(userB)))
	binary.Write(buf, binary.LittleEndian, uint32(userOff))

	// Workstation
	wsB := encodeNtlmString("WORKSTATION1")
	wsOff := userOff + len(userB)
	binary.Write(buf, binary.LittleEndian, uint16(len(wsB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(wsB)))
	binary.Write(buf, binary.LittleEndian, uint32(wsOff))

	// Negotiate key (empty)
	nkOff := wsOff + len(wsB)
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(nkOff))

	// Flags
	binary.Write(buf, binary.LittleEndian, uint32(0x00000001))

	// Write variable fields
	buf.Write(lmResp)
	buf.Write(ntResp)
	buf.Write(domainB)
	buf.Write(userB)
	buf.Write(wsB)

	err := nc.ProcessType3(buf.Bytes())
	if err != nil {
		t.Fatalf("ProcessType3() = %v", err)
	}

	if nc.State != NtlmStateComplete {
		t.Fatalf("state = %d, want %d", nc.State, NtlmStateComplete)
	}

	if nc.Username != "testuser" {
		t.Fatalf("username = %q, want %q", nc.Username, "testuser")
	}

	if nc.Domain != "EXAMPLE" {
		t.Fatalf("domain = %q, want %q", nc.Domain, "EXAMPLE")
	}

	if nc.Workstation != "WORKSTATION1" {
		t.Fatalf("workstation = %q, want %q", nc.Workstation, "WORKSTATION1")
	}
}

func TestProcessType3_BadSignature(t *testing.T) {
	nc := NewNtlmContext()

	data := []byte("XXXXXXXX")
	err := nc.ProcessType3(data)
	if err == nil {
		t.Fatal("ProcessType3(bad sig) = nil, want error")
	}
}

func TestProcessType3_WrongType(t *testing.T) {
	nc := NewNtlmContext()

	// Send a Type-1 message instead of Type-3
	data := buildType1Message(0)
	err := nc.ProcessType3(data)
	if err == nil {
		t.Fatal("ProcessType3(wrong type) = nil, want error")
	}
}

func TestValidateType3_Success(t *testing.T) {
	nc := NewNtlmContext()
	nc.State = NtlmStateComplete
	nc.Username = "testuser"
	nc.Domain = "EXAMPLE"

	var receivedUser, receivedDomain string
	validator := func(username, domain string) error {
		receivedUser = username
		receivedDomain = domain
		return nil
	}

	err := nc.ValidateType3(validator)
	if err != nil {
		t.Fatalf("ValidateType3() = %v", err)
	}

	if receivedUser != "testuser" {
		t.Fatalf("validator received user = %q, want %q", receivedUser, "testuser")
	}

	if receivedDomain != "EXAMPLE" {
		t.Fatalf("validator received domain = %q, want %q", receivedDomain, "EXAMPLE")
	}
}

func TestValidateType3_NoUsername(t *testing.T) {
	nc := NewNtlmContext()
	nc.State = NtlmStateComplete
	nc.Username = ""

	err := nc.ValidateType3(func(u, d string) error { return nil })
	if err == nil {
		t.Fatal("ValidateType3(no username) = nil, want error")
	}
}

func TestValidateType3_NotProcessed(t *testing.T) {
	nc := NewNtlmContext()
	nc.State = NtlmStateInitial

	err := nc.ValidateType3(func(u, d string) error { return nil })
	if err == nil {
		t.Fatal("ValidateType3(not processed) = nil, want error")
	}
}

func TestFullNtlmExchange(t *testing.T) {
	t.Parallel()
	nc := NewNtlmContext()

	// Step 1: Client sends Type-1
	type1 := buildType1MessageWithDomain(0x00002001, "EXAMPLE", "WORKSTATION1")
	type2, err := nc.ProcessType1(type1)
	if err != nil {
		t.Fatalf("ProcessType1() = %v", err)
	}

	if nc.State != NtlmStateType1 {
		t.Fatalf("after Type-1: state = %d, want %d", nc.State, NtlmStateType1)
	}

	// Verify Type-2 is valid
	if err := validateNtlmMessage(type2, 2); err != nil {
		t.Fatalf("Type-2 message invalid: %v", err)
	}

	// Step 2: Client sends Type-3 (we construct it manually)
	buf := &bytes.Buffer{}
	buf.Write([]byte("NTLMSSP\x00"))
	binary.Write(buf, binary.LittleEndian, uint32(3))

	baseOffset := 64
	lmResp := make([]byte, 24)
	lmOffset := baseOffset
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint32(lmOffset))

	ntResp := make([]byte, 24)
	ntOffset := lmOffset + len(ntResp)
	binary.Write(buf, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(buf, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(buf, binary.LittleEndian, uint32(ntOffset))

	domainB := encodeNtlmString("EXAMPLE")
	domainOff := ntOffset + len(ntResp)
	binary.Write(buf, binary.LittleEndian, uint16(len(domainB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(domainB)))
	binary.Write(buf, binary.LittleEndian, uint32(domainOff))

	userB := encodeNtlmString("alice")
	userOff := domainOff + len(domainB)
	binary.Write(buf, binary.LittleEndian, uint16(len(userB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(userB)))
	binary.Write(buf, binary.LittleEndian, uint32(userOff))

	wsB := encodeNtlmString("WORKSTATION1")
	wsOff := userOff + len(userB)
	binary.Write(buf, binary.LittleEndian, uint16(len(wsB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(wsB)))
	binary.Write(buf, binary.LittleEndian, uint32(wsOff))

	nkOff := wsOff + len(wsB)
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(nkOff))

	binary.Write(buf, binary.LittleEndian, uint32(0x00002001))

	buf.Write(lmResp)
	buf.Write(ntResp)
	buf.Write(domainB)
	buf.Write(userB)
	buf.Write(wsB)

	// Step 3: Server processes Type-3
	err = nc.ProcessType3(buf.Bytes())
	if err != nil {
		t.Fatalf("ProcessType3() = %v", err)
	}

	if nc.State != NtlmStateComplete {
		t.Fatalf("after Type-3: state = %d, want %d", nc.State, NtlmStateComplete)
	}

	if nc.Username != "alice" {
		t.Fatalf("username = %q, want %q", nc.Username, "alice")
	}

	// Step 4: Validate
	var validatedUser string
	err = nc.ValidateType3(func(username, domain string) error {
		validatedUser = username
		return nil
	})
	if err != nil {
		t.Fatalf("ValidateType3() = %v", err)
	}

	if validatedUser != "alice" {
		t.Fatalf("validated user = %q, want %q", validatedUser, "alice")
	}
}

func TestGenerateNTLMResponse(t *testing.T) {
	t.Parallel()
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

	data, err := GenerateNTLMResponse("password123", "testuser", "EXAMPLE", "WORKSTATION1", challenge, 0x00000001)
	if err != nil {
		t.Fatalf("GenerateNTLMResponse() = %v", err)
	}

	// Verify it's a valid Type-3 message
	if err := validateNtlmMessage(data, 3); err != nil {
		t.Fatalf("generated Type-3 invalid: %v", err)
	}

	// Parse the username from the generated message
	nc := NewNtlmContext()
	if err := nc.ProcessType3(data); err != nil {
		t.Fatalf("ProcessType3(generated) = %v", err)
	}

	if nc.Username != "testuser" {
		t.Fatalf("username = %q, want %q", nc.Username, "testuser")
	}

	if nc.Domain != "EXAMPLE" {
		t.Fatalf("domain = %q, want %q", nc.Domain, "EXAMPLE")
	}
}

func TestNtlmContext_StateTransitions(t *testing.T) {
	nc := NewNtlmContext()

	if nc.State != NtlmStateInitial {
		t.Fatalf("initial state = %d, want %d", nc.State, NtlmStateInitial)
	}

	// Process Type-1
	type1 := buildType1Message(0)
	_, err := nc.ProcessType1(type1)
	if err != nil {
		t.Fatalf("ProcessType1() = %v", err)
	}
	if nc.State != NtlmStateType1 {
		t.Fatalf("after Type-1: state = %d, want %d", nc.State, NtlmStateType1)
	}

	// Process Type-3
	buf := &bytes.Buffer{}
	buf.Write([]byte("NTLMSSP\x00"))
	binary.Write(buf, binary.LittleEndian, uint32(3))
	baseOffset := 64
	lmResp := make([]byte, 24)
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint32(baseOffset))
	ntResp := make([]byte, 24)
	ntOffset := baseOffset + len(lmResp)
	binary.Write(buf, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(buf, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(buf, binary.LittleEndian, uint32(ntOffset))
	domainB := encodeNtlmString("DOMAIN")
	domainOff := ntOffset + len(ntResp)
	binary.Write(buf, binary.LittleEndian, uint16(len(domainB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(domainB)))
	binary.Write(buf, binary.LittleEndian, uint32(domainOff))
	userB := encodeNtlmString("user")
	userOff := domainOff + len(domainB)
	binary.Write(buf, binary.LittleEndian, uint16(len(userB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(userB)))
	binary.Write(buf, binary.LittleEndian, uint32(userOff))
	wsB := encodeNtlmString("WS")
	wsOff := userOff + len(userB)
	binary.Write(buf, binary.LittleEndian, uint16(len(wsB)))
	binary.Write(buf, binary.LittleEndian, uint16(len(wsB)))
	binary.Write(buf, binary.LittleEndian, uint32(wsOff))
	nkOff := wsOff + len(wsB)
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(nkOff))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	buf.Write(lmResp)
	buf.Write(ntResp)
	buf.Write(domainB)
	buf.Write(userB)
	buf.Write(wsB)

	err = nc.ProcessType3(buf.Bytes())
	if err != nil {
		t.Fatalf("ProcessType3() = %v", err)
	}
	if nc.State != NtlmStateComplete {
		t.Fatalf("after Type-3: state = %d, want %d", nc.State, NtlmStateComplete)
	}
}
