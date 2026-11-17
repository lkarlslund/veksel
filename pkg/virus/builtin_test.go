package virus

import (
	"testing"
)

func TestBuiltinScanner_Name(t *testing.T) {
	s := NewBuiltinScanner()
	if s.Name() != "builtin" {
		t.Errorf("Name() = %q, want %q", s.Name(), "builtin")
	}
}

func TestBuiltinScanner_EICAR(t *testing.T) {
	s := NewBuiltinScanner()

	// Test direct EICAR string detection
	name, infected, err := s.Scan([]byte(EICARTestString))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !infected {
		t.Fatal("Scan() infected = false, want true for EICAR test string")
	}
	if name != "EICAR-AV-Test" {
		t.Errorf("Scan() name = %q, want %q", name, "EICAR-AV-Test")
	}
}

func TestBuiltinScanner_EICARInMessage(t *testing.T) {
	s := NewBuiltinScanner()

	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\n\r\n" + EICARTestString + "\r\n"
	name, infected, err := s.Scan([]byte(msg))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !infected {
		t.Fatal("Scan() infected = false, want true for EICAR in message body")
	}
	if name != "EICAR-AV-Test" {
		t.Errorf("Scan() name = %q, want %q", name, "EICAR-AV-Test")
	}
}

func TestBuiltinScanner_EICARCaseInsensitive(t *testing.T) {
	s := NewBuiltinScanner()

	// Test case-insensitive detection
	name, infected, err := s.Scan([]byte("eicar-standard-antivirus-test-file"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !infected {
		t.Fatal("Scan() infected = false, want true for lowercase EICAR")
	}
	if name != "EICAR-AV-Test" {
		t.Errorf("Scan() name = %q, want %q", name, "EICAR-AV-Test")
	}
}

func TestBuiltinScanner_CleanMessage(t *testing.T) {
	s := NewBuiltinScanner()

	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\n\r\nThis is a clean message.\r\n"
	name, infected, err := s.Scan([]byte(msg))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if infected {
		t.Errorf("Scan() infected = true, want false for clean message; name = %q", name)
	}
}

func TestBuiltinScanner_EmptyData(t *testing.T) {
	s := NewBuiltinScanner()

	name, infected, err := s.Scan([]byte{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if infected {
		t.Errorf("Scan() infected = true, want false for empty data; name = %q", name)
	}
}

// TestBuiltinScannerIgnoresBinaryContent pins that ordinary binary or base64
// content is not reported: byte pairs such as "MZ" occur by chance in most
// encoded attachments, and file-type risk belongs to the attachment checks.
func TestBuiltinScannerIgnoresBinaryContent(t *testing.T) {
	s := NewBuiltinScanner()
	for _, data := range [][]byte{
		{0x4D, 0x5A, 0x90, 0x00},
		[]byte("Content-Transfer-Encoding: base64\r\n\r\nQUJDTVpERUY=\r\nxyzMZ.WSF\r\n"),
		{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1},
	} {
		if name, infected, err := s.Scan(data); err != nil || infected {
			t.Errorf("Scan(%q) = %q, %t, %v; want clean", data, name, infected, err)
		}
	}
}

func TestAddVirusHeaders(t *testing.T) {
	headers := make(map[string]string)

	// Test clean scan
	AddVirusHeaders(headers, "", false)
	if headers["X-Virus-Scanned"] != "Veksel" {
		t.Errorf("X-Virus-Scanned = %q, want %q", headers["X-Virus-Scanned"], "Veksel")
	}
	if headers["X-Virus-Status"] != "Clean" {
		t.Errorf("X-Virus-Status = %q, want %q", headers["X-Virus-Status"], "Clean")
	}

	// Test infected scan
	AddVirusHeaders(headers, "EICAR-AV-Test", true)
	if headers["X-Virus-Status"] != "Infected/EICAR-AV-Test" {
		t.Errorf("X-Virus-Status = %q, want %q", headers["X-Virus-Status"], "Infected/EICAR-AV-Test")
	}
}

func TestManager(t *testing.T) {
	s := NewBuiltinScanner()
	m := NewManager(s)

	// Test clean message
	name, infected, err := m.Scan([]byte("clean message"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if infected {
		t.Errorf("Scan() infected = true, want false; name = %q", name)
	}

	// Test EICAR
	name, infected, err = m.Scan([]byte(EICARTestString))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !infected {
		t.Fatal("Scan() infected = false, want true")
	}
	if name != "EICAR-AV-Test" {
		t.Errorf("Scan() name = %q, want %q", name, "EICAR-AV-Test")
	}

	// Test scanner list
	scanners := m.GetScanners()
	if len(scanners) != 1 || scanners[0] != "builtin" {
		t.Errorf("GetScanners() = %v, want [builtin]", scanners)
	}
}

func TestErrVirusDetected(t *testing.T) {
	err := &ErrVirusDetected{VirusName: "EICAR-AV-Test", Scanner: "builtin"}
	expected := "virus detected: EICAR-AV-Test (scanner: builtin)"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}
