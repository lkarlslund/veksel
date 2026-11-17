package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // NTLMv2 test server
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unicode/utf16"
)

// TestNTLMv2Vectors checks NTOWFv2 and NTProofStr against MS-NLMP 4.2.4.
func TestNTLMv2Vectors(t *testing.T) {
	key := ntowfv2("Password", "User", "Domain")
	if got := hex.EncodeToString(key); got != "0c868a403bfd7a93a3001ef22ef02e3f" {
		t.Fatalf("NTOWFv2 = %s", got)
	}
	serverChallenge, _ := hex.DecodeString("0123456789abcdef")
	clientChallenge, _ := hex.DecodeString("aaaaaaaaaaaaaaaa")
	targetInfo := encodeAVPairs([]avPair{{id: 2, value: utf16le("Domain")}, {id: 1, value: utf16le("Server")}})
	response := ntlmv2Response(key, serverChallenge, clientChallenge, make([]byte, 8), targetInfo)
	if got := hex.EncodeToString(response[:16]); got != "68cd0ab851e51c96aabc927bebef6a1c" {
		t.Fatalf("NTProofStr = %s", got)
	}
}

func TestParseChallengeRejectsBadMessages(t *testing.T) {
	for name, message := range map[string][]byte{
		"short":     []byte("NTLMSSP\x00"),
		"type":      append(append([]byte("NTLMSSP\x00"), 1, 0, 0, 0), make([]byte, 40)...),
		"outbounds": challengeMessage(flagUnicode|flagTargetInfo, [8]byte{}, nil, 1000),
	} {
		if _, err := ParseChallenge(message); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestCredentialsSplit(t *testing.T) {
	for _, test := range []struct{ in, user, domain string }{
		{`EXAMPLE\alice`, "alice", "EXAMPLE"},
		{"alice@example.local", "alice@example.local", ""},
		{"alice", "alice", ""},
	} {
		if user, domain := (Credentials{User: test.in}).split(); user != test.user || domain != test.domain {
			t.Errorf("%q split to %q, %q", test.in, user, domain)
		}
	}
}

// challengeMessage builds a CHALLENGE message; a non-zero badOffset points
// the target information outside the message.
func challengeMessage(flags uint32, serverChallenge [8]byte, targetInfo []byte, badOffset uint32) []byte {
	message := make([]byte, 48)
	copy(message, signature)
	binary.LittleEndian.PutUint32(message[8:], 2)
	binary.LittleEndian.PutUint32(message[16:], 48)
	binary.LittleEndian.PutUint32(message[20:], flags)
	copy(message[24:], serverChallenge[:])
	binary.LittleEndian.PutUint16(message[40:], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(message[42:], uint16(len(targetInfo)))
	offset := uint32(48)
	if badOffset != 0 {
		offset = badOffset
		binary.LittleEndian.PutUint16(message[40:], 8)
	}
	binary.LittleEndian.PutUint32(message[44:], offset)
	return append(message, targetInfo...)
}

// fakeIIS answers like IIS with Windows authentication: NTLM per
// connection, then the connection stays signed in.
type fakeIIS struct {
	t          *testing.T
	user       string
	domain     string
	password   string
	mu         sync.Mutex
	challenges map[string][8]byte // by remote address
	signedIn   map[string]bool
	handshakes atomic.Int32
	bindings   []byte // expected channel bindings
	bodies     []string
}

func (s *fakeIIS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if s.signedIn[r.RemoteAddr] {
		s.bodies = append(s.bodies, string(body))
		_, _ = w.Write([]byte("ok"))
		return
	}
	scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	data, _ := base64.StdEncoding.DecodeString(token)
	switch {
	case scheme == "NTLM" && len(data) > 12 && data[8] == 1:
		s.handshakes.Add(1)
		challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
		s.challenges[r.RemoteAddr] = challenge
		info := encodeAVPairs([]avPair{{id: 2, value: utf16le("EXAMPLE")}, {id: 1, value: utf16le("EXCH")}, {id: avTimestamp, value: make([]byte, 8)}})
		w.Header().Set("WWW-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(challengeMessage(negotiateFlags, challenge, info, 0)))
		w.WriteHeader(http.StatusUnauthorized)
		return
	case scheme == "NTLM" && len(data) > 64 && data[8] == 3:
		challenge, ok := s.challenges[r.RemoteAddr]
		if !ok {
			s.t.Error("AUTHENTICATE arrived on another connection than the CHALLENGE")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if s.verify(data, challenge) {
			s.signedIn[r.RemoteAddr] = true
			s.bodies = append(s.bodies, string(body))
			_, _ = w.Write([]byte("ok"))
			return
		}
	}
	w.Header().Add("WWW-Authenticate", "Negotiate")
	w.Header().Add("WWW-Authenticate", "NTLM")
	w.WriteHeader(http.StatusUnauthorized)
}

func (s *fakeIIS) verify(message []byte, challenge [8]byte) bool {
	field := func(i int) []byte {
		position := 12 + 8*i
		length, offset := int(binary.LittleEndian.Uint16(message[position:])), int(binary.LittleEndian.Uint32(message[position+4:]))
		return message[offset : offset+length]
	}
	text := func(data []byte) string {
		units := make([]uint16, len(data)/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(data[2*i:])
		}
		return string(utf16.Decode(units))
	}
	ntResponse, domain, user := field(1), text(field(2)), text(field(3))
	if user != s.user || domain != s.domain {
		s.t.Errorf("user %q domain %q", user, domain)
		return false
	}
	proof, blob := ntResponse[:16], ntResponse[16:]
	mac := hmac.New(md5.New, ntowfv2(s.password, user, domain))
	mac.Write(challenge[:])
	mac.Write(blob)
	if !hmac.Equal(mac.Sum(nil), proof) {
		return false // wrong password: refused like IIS does
	}
	pairs, err := avPairs(blob[28:])
	if err != nil {
		s.t.Error(err)
		return false
	}
	var bindings []byte
	var spn string
	for _, pair := range pairs {
		switch pair.id {
		case avChannelBindings:
			bindings = pair.value
		case avTargetName:
			spn = text(pair.value)
		}
	}
	if !bytes.Equal(bindings, s.bindings) {
		s.t.Errorf("channel bindings %x, want %x", bindings, s.bindings)
		return false
	}
	if spn != "HTTP/127.0.0.1" {
		s.t.Errorf("service principal %q", spn)
	}
	return true
}

func TestTransportNTLMWithChannelBinding(t *testing.T) {
	iis := &fakeIIS{t: t, user: "alice", domain: "EXAMPLE", password: "Secret1!", challenges: map[string][8]byte{}, signedIn: map[string]bool{}}
	server := httptest.NewTLSServer(iis)
	defer server.Close()
	iis.bindings = TLSChannelBindings(server.Certificate())

	base := HTTP1Only(server.Client().Transport.(*http.Transport).Clone())
	client := &http.Client{Transport: &Transport{Base: base}}
	for i, body := range []string{"<first/>", "<second/>"} {
		request, _ := http.NewRequest(http.MethodPost, server.URL+"/EWS/Exchange.asmx", strings.NewReader(body))
		request.SetBasicAuth(`EXAMPLE\alice`, "Secret1!")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("request %d: %s", i, response.Status)
		}
	}
	if got := iis.handshakes.Load(); got != 1 {
		t.Errorf("handshakes = %d, want 1 (the connection stays signed in)", got)
	}
	if strings.Join(iis.bodies, "") != "<first/><second/>" {
		t.Errorf("bodies %q", iis.bodies)
	}
}

func TestTransportRefusesWrongPassword(t *testing.T) {
	iis := &fakeIIS{t: t, user: "alice", domain: "EXAMPLE", password: "Secret1!", challenges: map[string][8]byte{}, signedIn: map[string]bool{}}
	server := httptest.NewTLSServer(iis)
	defer server.Close()
	iis.bindings = TLSChannelBindings(server.Certificate())
	client := &http.Client{Transport: &Transport{Base: HTTP1Only(server.Client().Transport.(*http.Transport).Clone())}}
	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	request.SetBasicAuth(`EXAMPLE\alice`, "wrong")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %s", response.Status)
	}
}

func TestTransportBasic(t *testing.T) {
	var challenges atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, password, ok := r.BasicAuth(); ok && user == "alice" && password == "pw" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		challenges.Add(1)
		w.Header().Set("WWW-Authenticate", `Basic realm="exchange"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	for _, allow := range []bool{false, true} {
		challenges.Store(0)
		client := &http.Client{Transport: &Transport{Base: server.Client().Transport, AllowBasic: allow}}
		for range 2 {
			request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
			request.SetBasicAuth("alice", "pw")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if want := map[bool]int{false: http.StatusUnauthorized, true: http.StatusOK}[allow]; response.StatusCode != want {
				t.Fatalf("allow=%v: status %d", allow, response.StatusCode)
			}
		}
		// With Basic allowed, the second request sends it preemptively.
		if want := map[bool]int32{false: 2, true: 1}[allow]; challenges.Load() != want {
			t.Errorf("allow=%v: %d challenges, want %d", allow, challenges.Load(), want)
		}
	}
}

func TestTransportObservesHandshake(t *testing.T) {
	iis := &fakeIIS{t: t, user: "alice", domain: "EXAMPLE", password: "Secret1!", challenges: map[string][8]byte{}, signedIn: map[string]bool{}}
	server := httptest.NewTLSServer(iis)
	defer server.Close()
	iis.bindings = TLSChannelBindings(server.Certificate())
	var seen []Exchange
	transport := &Transport{Base: HTTP1Only(server.Client().Transport.(*http.Transport).Clone()), Observe: func(exchange Exchange) { seen = append(seen, exchange) }}
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/EWS/Exchange.asmx", nil)
	request.SetBasicAuth(`EXAMPLE\alice`, "Secret1!")
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(seen) != 1 {
		t.Fatalf("observed %d exchanges", len(seen))
	}
	got := seen[0]
	if got.Scheme != "NTLM" || fmt.Sprint(got.Statuses) != "[401 401 200]" || got.User != `EXAMPLE\alice` || got.Remote == "" {
		t.Fatalf("exchange = %+v", got)
	}
}

// TestTransportConcurrentHandshakesStayOnTheirConnection: requests running
// in parallel (several folders syncing at once) each complete their NTLM
// handshake on one connection instead of answering a challenge on another
// pooled connection, which IIS refuses with 401.
func TestTransportConcurrentHandshakesStayOnTheirConnection(t *testing.T) {
	iis := &fakeIIS{t: t, user: "alice", domain: "EXAMPLE", password: "Secret1!", challenges: map[string][8]byte{}, signedIn: map[string]bool{}}
	server := httptest.NewTLSServer(iis)
	defer server.Close()
	iis.bindings = TLSChannelBindings(server.Certificate())
	transport := &Transport{Base: HTTP1Only(server.Client().Transport.(*http.Transport).Clone()), MaxSessions: 4}
	client := &http.Client{Transport: transport}
	var wg sync.WaitGroup
	var failures atomic.Int32
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request, _ := http.NewRequest(http.MethodPost, server.URL+"/EWS/Exchange.asmx", strings.NewReader("<x/>"))
			request.SetBasicAuth(`EXAMPLE\alice`, "Secret1!")
			response, err := client.Do(request)
			if err != nil {
				failures.Add(1)
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d of 24 concurrent requests failed", failures.Load())
	}
	if got := iis.handshakes.Load(); got > 4 {
		t.Errorf("handshakes = %d, want at most one per pinned session (4)", got)
	}
}
