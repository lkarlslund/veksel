package virus

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// startMockClamd starts a mock clamd server on a random port.
// It responds to PING, VERSION, and INSTREAM commands.
func startMockClamd(t *testing.T, response string) (addr string, stop func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	var wg sync.WaitGroup
	stop = func() {
		_ = ln.Close()
		wg.Wait()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleMockClamd(conn, response)
			}()
		}
	}()

	return ln.Addr().String(), stop
}

func handleMockClamd(conn net.Conn, response string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	command, err := reader.ReadString(0)
	if err != nil {
		return
	}
	switch command {
	case "zPING\x00":
		_, _ = conn.Write([]byte("PONG\x00"))
	case "zVERSION\x00":
		_, _ = conn.Write([]byte("ClamAV 1.0.0\x00"))
	case "zINSTREAM\x00":
		var length [4]byte
		for {
			if _, err := io.ReadFull(reader, length[:]); err != nil {
				return
			}
			size := binary.BigEndian.Uint32(length[:])
			if size == 0 {
				break
			}
			if _, err := io.CopyN(io.Discard, reader, int64(size)); err != nil {
				return
			}
		}
		_, _ = conn.Write(append([]byte(response), 0))
	}
}

func TestClamAVScanner_Name(t *testing.T) {
	s := NewClamAVScanner("127.0.0.1:0")
	if s.Name() != "clamav" {
		t.Errorf("Name() = %q, want %q", s.Name(), "clamav")
	}
}

func TestClamAVScanner_ConnectionRefused(t *testing.T) {
	s := NewClamAVScanner("127.0.0.1:1") // unlikely port
	_, _, err := s.Scan([]byte("test"))
	if err == nil {
		t.Fatal("Scan() error = nil, want error for connection refused")
	}
}

func TestClamAVScanner_Clean(t *testing.T) {
	addr, stop := startMockClamd(t, "stream: OK\n")
	defer stop()

	s := NewClamAVScanner(addr)
	name, infected, err := s.Scan([]byte("clean message"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if infected {
		t.Errorf("Scan() infected = true, want false; name = %q", name)
	}
}

func TestClamAVScanner_Infected(t *testing.T) {
	addr, stop := startMockClamd(t, "stream: Test.Virus FOUND\n")
	defer stop()

	s := NewClamAVScanner(addr)
	name, infected, err := s.Scan([]byte("infected message"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !infected {
		t.Fatal("Scan() infected = false, want true")
	}
	if name != "Test.Virus" {
		t.Errorf("Scan() name = %q, want %q", name, "Test.Virus")
	}
}

func TestClamAVScanner_Ping(t *testing.T) {
	addr, stop := startMockClamd(t, "stream: OK\n")
	defer stop()

	s := NewClamAVScanner(addr)
	// The mock handles PING first, then VERSION
	version, err := s.Ping()
	if err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if version != "ClamAV 1.0.0" {
		t.Errorf("Ping() version = %q, want %q", version, "ClamAV 1.0.0")
	}
}

func TestClamAVScanner_Ping_ConnectionRefused(t *testing.T) {
	s := NewClamAVScanner("127.0.0.1:1")
	_, err := s.Ping()
	if err == nil {
		t.Fatal("Ping() error = nil, want error for connection refused")
	}
}

func TestParseClamavInfection(t *testing.T) {
	tests := []struct {
		response string
		name     string
		infected bool
	}{
		{"stream: OK", "", false},
		{"stream: Test.Virus FOUND", "Test.Virus", true},
		{"stream: EICAR-AV-Test FOUND", "EICAR-AV-Test", true},
		{"stream: ERROR", "", false},
	}

	for _, tt := range tests {
		name, infected := ParseClamavInfection(tt.response)
		if infected != tt.infected {
			t.Errorf("ParseClamavInfection(%q) infected = %v, want %v", tt.response, infected, tt.infected)
		}
		if name != tt.name {
			t.Errorf("ParseClamavInfection(%q) name = %q, want %q", tt.response, name, tt.name)
		}
	}
}
