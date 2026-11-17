package attachment

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func testPolicy(t *testing.T, mode string) *Policy {
	t.Helper()
	policy, err := NewPolicy(Settings{Mode: mode, BlockedExtensions: DefaultBlockedExtensions()})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

type testPart struct {
	name, mediaType string
	data            []byte
	inline          bool
}

// testMessage builds a multipart/mixed message with a text body and the
// given base64 attachments.
func testMessage(parts ...testPart) []byte {
	var message bytes.Buffer
	message.WriteString("From: a@example.org\r\nTo: b@example.net\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=XX\r\n\r\n")
	message.WriteString("--XX\r\nContent-Type: text/plain\r\n\r\nhello\r\n")
	for _, part := range parts {
		mediaType := part.mediaType
		if mediaType == "" {
			mediaType = "application/octet-stream"
		}
		disposition := "attachment"
		if part.inline {
			disposition = "inline"
		}
		fmt.Fprintf(&message, "--XX\r\nContent-Type: %s; name=\"%s\"\r\nContent-Disposition: %s; filename=\"%s\"\r\nContent-Transfer-Encoding: base64\r\n\r\n", mediaType, part.name, disposition, part.name)
		message.WriteString(base64.StdEncoding.EncodeToString(part.data) + "\r\n")
	}
	message.WriteString("--XX--\r\n")
	return message.Bytes()
}

func testZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		data := entries[name]
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = entry.Write(data)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func testRawZip(t *testing.T, header zip.FileHeader, data []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.CreateRaw(&header)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write(data)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func pe() []byte {
	data := make([]byte, 0x100)
	copy(data, "MZ")
	data[0x3c] = 0x80
	copy(data[0x80:], "PE\x00\x00")
	return data
}

func ole2(extra string) []byte {
	return append(append([]byte{}, magicOLE2...), []byte(extra)...)
}

func findings(report Report) map[string]Finding {
	found := make(map[string]Finding)
	for _, finding := range report.Findings {
		found[finding.Symbol] = finding
	}
	return found
}

func TestAnalyzeDetections(t *testing.T) {
	macroZip := testZip(t, map[string][]byte{"[Content_Types].xml": []byte("x"), "word/vbaProject.bin": []byte("vba")})
	cases := []struct {
		name  string
		parts []testPart
		want  map[string]bool // symbol -> hard
		not   []string
	}{
		{"dangerous extension", []testPart{{name: "setup.exe", data: pe()}}, map[string]bool{SymbolDangerousExt: true}, []string{SymbolTypeMismatch}},
		{"dangerous script", []testPart{{name: "run.JS", data: []byte("x")}}, map[string]bool{SymbolDangerousExt: true}, nil},
		{"double extension", []testPart{{name: "invoice.pdf.exe", data: pe()}}, map[string]bool{SymbolDangerousExt: true, SymbolDoubleExt: true}, nil},
		{"double extension trailing space", []testPart{{name: "invoice.pdf .scr", data: []byte("x")}}, map[string]bool{SymbolDangerousExt: true, SymbolDoubleExt: true}, nil},
		{"executable renamed pdf", []testPart{{name: "report.pdf", mediaType: "application/pdf", data: pe()}}, map[string]bool{SymbolTypeMismatch: true}, []string{SymbolDangerousExt}},
		{"elf renamed", []testPart{{name: "photo.jpg", data: []byte("\x7fELF\x02\x01\x01")}}, map[string]bool{SymbolTypeMismatch: true}, nil},
		{"macho renamed", []testPart{{name: "notes.txt", data: []byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0}}}, map[string]bool{SymbolTypeMismatch: true}, nil},
		{"zip renamed pdf", []testPart{{name: "a.pdf", data: testZip(t, map[string][]byte{"a.txt": []byte("x")})}}, map[string]bool{SymbolTypeMismatch: false}, nil},
		{"genuine pdf", []testPart{{name: "a.pdf", data: []byte("%PDF-1.7 body")}}, nil, []string{SymbolTypeMismatch, SymbolDangerousExt}},
		{"macro extension", []testPart{{name: "budget.xlsm", data: testZip(t, map[string][]byte{"[Content_Types].xml": []byte("x")})}}, map[string]bool{SymbolMacro: false}, nil},
		{"ooxml vba project", []testPart{{name: "letter.docx", data: macroZip}}, map[string]bool{SymbolMacro: false}, nil},
		{"ole2 vba", []testPart{{name: "old.doc", data: ole2("..." + "_\x00V\x00B\x00A\x00_\x00P\x00R\x00O\x00J\x00E\x00C\x00T\x00")}}, map[string]bool{SymbolMacro: false}, nil},
		{"ole2 without vba", []testPart{{name: "old.doc", data: ole2("plain document")}}, nil, []string{SymbolMacro, SymbolTypeMismatch}},
		{"clean office zip", []testPart{{name: "plain.docx", data: testZip(t, map[string][]byte{"[Content_Types].xml": []byte("x"), "word/document.xml": []byte("x")})}}, nil, []string{SymbolMacro, SymbolDangerousExt, SymbolEncryptedArchive}},
		{"rtlo", []testPart{{name: "invoice‮fdp.txt", data: []byte("x")}}, map[string]bool{SymbolRTLO: false}, nil},
		{"zero width", []testPart{{name: "a​.txt", data: []byte("x")}}, map[string]bool{SymbolRTLO: false}, nil},
		{"html form", []testPart{{name: "login.html", mediaType: "text/html", data: []byte("<html><form action=x><input type=password></form></html>")}}, map[string]bool{SymbolHTMLForm: false}, nil},
		{"html script", []testPart{{name: "page.htm", data: []byte("<script>location='x'</script>")}}, map[string]bool{SymbolHTMLForm: false}, nil},
		{"plain html attachment", []testPart{{name: "page.html", data: []byte("<p>hello</p>")}}, nil, []string{SymbolHTMLForm}},
		{"inline body is not inspected", []testPart{{name: "", mediaType: "text/html", data: []byte("<form></form>"), inline: true}}, nil, []string{SymbolHTMLForm}},
		{"zip with executable", []testPart{{name: "files.zip", data: testZip(t, map[string][]byte{"docs/readme.txt": []byte("x"), "docs/invoice.pdf.exe": pe()})}}, map[string]bool{SymbolDangerousExt: true, SymbolDoubleExt: true}, nil},
		{"zip with disguised executable", []testPart{{name: "files.zip", data: testZip(t, map[string][]byte{"pic.jpg": pe()})}}, map[string]bool{SymbolTypeMismatch: true}, nil},
		{"zip with macro document", []testPart{{name: "files.zip", data: testZip(t, map[string][]byte{"a.docm": []byte("x")})}}, map[string]bool{SymbolMacro: false}, nil},
		{"zip with html form", []testPart{{name: "files.zip", data: testZip(t, map[string][]byte{"login.html": []byte("<form>")})}}, map[string]bool{SymbolHTMLForm: false}, nil},
		{"encrypted zip lists names but not content", []testPart{{name: "secret.zip", data: testRawZip(t, zip.FileHeader{Name: "a.exe", Flags: 1, Method: zip.Store, CompressedSize64: 4, UncompressedSize64: 4}, []byte("abcd"))}}, map[string]bool{SymbolEncryptedArchive: false, SymbolDangerousExt: true}, nil},
		{"archive bomb", []testPart{{name: "bomb.zip", data: testRawZip(t, zip.FileHeader{Name: "a.txt", Method: zip.Store, CompressedSize64: 4, UncompressedSize64: 2 << 30}, []byte("abcd"))}}, map[string]bool{SymbolArchiveBomb: false}, nil},
		{"ratio bomb", []testPart{{name: "ratio.zip", data: testRawZip(t, zip.FileHeader{Name: "a.txt", Method: zip.Store, CompressedSize64: 100, UncompressedSize64: 200 << 20}, bytes.Repeat([]byte("a"), 100))}}, map[string]bool{SymbolArchiveBomb: false}, nil},
		{"jar is dangerous but not expanded", []testPart{{name: "tool.jar", data: testZip(t, map[string][]byte{"META-INF/MANIFEST.MF": []byte("x"), "script.js": []byte("x")})}}, map[string]bool{SymbolDangerousExt: true}, nil},
		{"nested zip is not opened", []testPart{{name: "outer.zip", data: testZip(t, map[string][]byte{"inner.zip": testZip(t, map[string][]byte{"evil.exe": pe()})})}}, nil, []string{SymbolDangerousExt}},
	}
	policy := testPolicy(t, "quarantine")
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			found := findings(policy.Analyze(testMessage(test.parts...)))
			for symbol, hard := range test.want {
				finding, ok := found[symbol]
				if !ok {
					t.Errorf("missing %s; got %v", symbol, found)
				} else if finding.Hard != hard {
					t.Errorf("%s hard = %t, want %t", symbol, finding.Hard, hard)
				}
			}
			for _, symbol := range test.not {
				if _, ok := found[symbol]; ok {
					t.Errorf("unexpected %s: %v", symbol, found[symbol])
				}
			}
			if test.want == nil && len(test.not) > 0 && len(found) != 0 {
				t.Errorf("expected no findings, got %v", found)
			}
		})
	}
}

func TestAnalyzeNestedMessage(t *testing.T) {
	inner := testMessage(testPart{name: "evil.scr", data: []byte("x")})
	var message bytes.Buffer
	message.WriteString("From: a@example.org\r\nSubject: fwd\r\nContent-Type: multipart/mixed; boundary=OUT\r\n\r\n--OUT\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"fwd.eml\"\r\n\r\n")
	message.Write(inner)
	message.WriteString("\r\n--OUT--\r\n")
	found := findings(testPolicy(t, "reject").Analyze(message.Bytes()))
	if finding, ok := found[SymbolDangerousExt]; !ok || !finding.Hard || finding.Detail != "evil.scr" {
		t.Fatalf("nested attachment not found: %v", found)
	}
}

func TestAnalyzeEncodedFilename(t *testing.T) {
	message := "From: a@example.org\r\nContent-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"=?UTF-8?B?aW52b2ljZS5wZGYuZXhl?=\"\r\n\r\nMZ\r\n--XX--\r\n"
	found := findings(testPolicy(t, "reject").Analyze([]byte(message)))
	if _, ok := found[SymbolDoubleExt]; !ok {
		t.Fatalf("encoded-word file name not decoded: %v", found)
	}
}

func TestRTLODetailIsEscaped(t *testing.T) {
	found := findings(testPolicy(t, "score").Analyze(testMessage(testPart{name: "doc‮gpj.exe", data: []byte("x")})))
	detail := found[SymbolRTLO].Detail
	if strings.ContainsRune(detail, '‮') || !strings.Contains(detail, "<U+202E>") {
		t.Fatalf("detail = %q", detail)
	}
}

func TestAnalyzeBounds(t *testing.T) {
	policy := testPolicy(t, "quarantine")
	t.Run("part count", func(t *testing.T) {
		parts := make([]testPart, 0, maxParts+20)
		for index := range maxParts + 20 {
			parts = append(parts, testPart{name: fmt.Sprintf("f%d.exe", index), data: []byte("x")})
		}
		if got := len(policy.Analyze(testMessage(parts...)).Findings); got >= maxParts {
			t.Fatalf("findings = %d, want fewer than %d", got, maxParts)
		}
	})
	t.Run("finding count", func(t *testing.T) {
		entries := make(map[string][]byte)
		for index := range maxArchiveEntries {
			entries[fmt.Sprintf("f%d.exe", index)] = []byte("x")
		}
		if got := len(policy.Analyze(testMessage(testPart{name: "a.zip", data: testZip(t, entries)})).Findings); got > maxFindings {
			t.Fatalf("findings = %d", got)
		}
	})
	t.Run("archive entries", func(t *testing.T) {
		entries := make(map[string][]byte)
		for index := range maxArchiveEntries * 3 {
			entries[fmt.Sprintf("f%03d.txt", index)] = []byte("x")
		}
		entries["zzz.exe"] = pe() // sorts after the inspected window
		if _, ok := findings(policy.Analyze(testMessage(testPart{name: "a.zip", data: testZip(t, entries)})))[SymbolDangerousExt]; ok {
			t.Fatal("entries beyond the bound were inspected")
		}
	})
	t.Run("byte budget", func(t *testing.T) {
		big := bytes.Repeat([]byte("a"), maxAttachmentBytes)
		parts := make([]testPart, 0, 6)
		for range 5 {
			parts = append(parts, testPart{name: "big.bin", data: big})
		}
		parts = append(parts, testPart{name: "late.exe", data: []byte("x")})
		if _, ok := findings(policy.Analyze(testMessage(parts...)))[SymbolDangerousExt]; ok {
			t.Fatal("attachment beyond the byte budget was inspected")
		}
	})
	t.Run("depth", func(t *testing.T) {
		message := testMessage(testPart{name: "evil.exe", data: []byte("x")})
		for range maxDepth + 2 {
			message = []byte("From: a@example.org\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"n.eml\"\r\n\r\n" + string(message))
		}
		if _, ok := findings(policy.Analyze(message))[SymbolDangerousExt]; ok {
			t.Fatal("nesting beyond the depth bound was inspected")
		}
	})
	t.Run("not a message", func(t *testing.T) {
		if got := policy.Analyze([]byte("\x00\x01 not mail")); len(got.Findings) != 0 {
			t.Fatalf("findings = %v", got.Findings)
		}
	})
}

func TestCustomBlockedExtensions(t *testing.T) {
	policy, err := NewPolicy(Settings{Mode: "reject", BlockedExtensions: []string{".DOCX"}})
	if err != nil {
		t.Fatal(err)
	}
	found := findings(policy.Analyze(testMessage(testPart{name: "a.docx", data: []byte("x")}, testPart{name: "b.exe", data: []byte("x")})))
	if finding := found[SymbolDangerousExt]; finding.Detail != "a.docx" || !finding.Hard {
		t.Fatalf("found = %v", found)
	}
}

func TestNewPolicyValidation(t *testing.T) {
	for _, settings := range []Settings{
		{Mode: "block"},
		{Mode: "score", BlockedExtensions: []string{"ex e"}},
		{Mode: "score", BlockedExtensions: []string{""}},
		{Mode: "score", BlockedExtensions: make([]string, maxBlockedExtensions+1)},
	} {
		if _, err := NewPolicy(settings); err == nil {
			t.Errorf("NewPolicy(%+v) succeeded", settings)
		}
	}
	for _, mode := range []string{"off", "score", "quarantine", "reject"} {
		if _, err := NewPolicy(Settings{Mode: mode, BlockedExtensions: DefaultBlockedExtensions()}); err != nil {
			t.Errorf("mode %s: %v", mode, err)
		}
	}
}

func TestPolicyApplies(t *testing.T) {
	var none *Policy
	off, _ := NewPolicy(Settings{Mode: "off"})
	score, _ := NewPolicy(Settings{Mode: "score"})
	submissions, _ := NewPolicy(Settings{Mode: "score", CheckSubmissions: true})
	for _, test := range []struct {
		policy        *Policy
		authenticated bool
		want          bool
	}{{none, false, false}, {off, false, false}, {score, false, true}, {score, true, false}, {submissions, true, true}} {
		if got := test.policy.Applies(test.authenticated); got != test.want {
			t.Errorf("Applies(%v) = %t, want %t", test.authenticated, got, test.want)
		}
	}
}

func TestReportReason(t *testing.T) {
	report := testPolicy(t, "quarantine").Analyze(testMessage(testPart{name: "x.exe", data: []byte("x")}))
	if got := report.Reason(); got != "Attachment policy: ATTACH_DANGEROUS_EXT (x.exe)" {
		t.Fatalf("reason = %q", got)
	}
}
