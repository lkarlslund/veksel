package log

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// resetOutput restores the default multiOutput after each test.
func resetOutput() {
	mu.Lock()
	out.consoleWriter = os.Stderr
	out.consoleLevel = LevelInfo
	out.fileWriter = nil
	out.fileLevel = LevelDebug
	moduleLevels = DefaultModuleLevelValues()
	mu.Unlock()
}

func TestModuleRegistryIsCompleteAndStable(t *testing.T) {
	defer resetOutput()
	modules := Modules()
	defaults := DefaultModuleLevels()
	if len(modules) != len(defaults) || len(modules) == 0 {
		t.Fatalf("modules=%d defaults=%d", len(modules), len(defaults))
	}
	labels := make([]string, 0, len(modules))
	seen := make(map[Module]bool, len(modules))
	for _, module := range modules {
		if seen[module.ID] || module.ID == "" || module.Label == "" || module.Settings == "" {
			t.Fatalf("invalid module registry entry: %+v", module)
		}
		seen[module.ID] = true
		labels = append(labels, module.Label)
		if module.Level != "info" || defaults[string(module.ID)] != "info" {
			t.Fatalf("unexpected default for %s: response=%q config=%q", module.ID, module.Level, defaults[string(module.ID)])
		}
	}
	if !sort.StringsAreSorted(labels) {
		t.Fatalf("module labels are not sorted: %v", labels)
	}
}

func TestModuleThresholdsAreIndependentAndLive(t *testing.T) {
	defer resetOutput()
	SetFormat("text")
	mu.Lock()
	out.consoleLevel = LevelTrace
	out.fileWriter = nil
	mu.Unlock()
	buf := captureConsole(t)
	if err := ConfigureModules(map[string]string{"imap": "error", "smtp": "trace"}); err != nil {
		t.Fatal(err)
	}
	For(ModuleIMAP).Debug("hidden imap")
	For(ModuleSMTP).Debug("visible smtp")
	if strings.Contains(buf.String(), "hidden imap") || !strings.Contains(buf.String(), "visible smtp") {
		t.Fatalf("independent filtering failed: %s", buf.String())
	}
	if err := SetModuleLevel(ModuleIMAP, LevelDebug); err != nil {
		t.Fatal(err)
	}
	For(ModuleIMAP).Debug("live imap")
	if !strings.Contains(buf.String(), "live imap") {
		t.Fatalf("live threshold was not applied: %s", buf.String())
	}
}

func TestLoggingRedactsSensitiveMaterial(t *testing.T) {
	defer resetOutput()
	SetFormat("json")
	mu.Lock()
	out.consoleLevel = LevelTrace
	out.fileWriter = nil
	mu.Unlock()
	buf := captureConsole(t)
	For(ModuleAuth).Error("request Bearer abc123 at https://alice:hunter2@example.test/path",
		"password", "hunter2", "access_token", "abc123", "error", errors.New("authorization=BasicXYZ"), "safe", "kept",
		"request", map[string]any{"headers": map[string]string{"Authorization": "Bearer nested-secret"}})
	var entry Entry
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatal(err)
	}
	encoded := buf.String()
	for _, secret := range []string{"hunter2", "abc123", "BasicXYZ", "alice", "nested-secret"} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("log leaked %q: %s", secret, encoded)
		}
	}
	if entry.Fields["password"] != "[redacted]" || entry.Fields["access_token"] != "[redacted]" || entry.Fields["safe"] != "kept" {
		t.Fatalf("redacted fields = %#v", entry.Fields)
	}
}

func TestConcurrentModuleReconfigurationAndWrites(t *testing.T) {
	defer resetOutput()
	SetFormat("json")
	mu.Lock()
	out.consoleWriter = io.Discard
	out.consoleLevel = LevelTrace
	out.fileWriter = nil
	mu.Unlock()
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for index := 0; index < 100; index++ {
				For(ModuleQueue).Debug("concurrent write", "worker", worker, "index", index)
				if index%10 == 0 {
					_ = SetModuleLevel(ModuleQueue, []Level{LevelTrace, LevelInfo}[index/10%2])
				}
			}
		}(worker)
	}
	group.Wait()
}

func TestTraceAndFatalDoNotTerminate(t *testing.T) {
	defer resetOutput()
	SetFormat("text")
	mu.Lock()
	out.consoleLevel = LevelTrace
	out.fileWriter = nil
	mu.Unlock()
	buf := captureConsole(t)
	Trace("trace record")
	Fatal("fatal record")
	Info("continued")
	for _, value := range []string{"TRACE", "FATAL", "continued"} {
		if !strings.Contains(buf.String(), value) {
			t.Fatalf("missing %q in %s", value, buf.String())
		}
	}
}

func TestSetupWritesAndReopensDatedModuleFile(t *testing.T) {
	defer resetOutput()
	directory := t.TempDir()
	write := func(message string) {
		if err := Setup(directory, "json", LevelFatal, LevelTrace); err != nil {
			t.Fatal(err)
		}
		if err := ConfigureModules(map[string]string{"queue": "debug"}); err != nil {
			t.Fatal(err)
		}
		For(ModuleQueue).Debug(message, "password", "not-in-file")
		if err := Close(); err != nil {
			t.Fatal(err)
		}
	}
	write("first process")
	write("second process")
	path := filepath.Join(directory, "veksel-"+time.Now().UTC().Format("2006-01-02")+".log")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{`"module":"queue"`, "first process", "second process", `"password":"[redacted]"`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("dated log is missing %q: %s", expected, text)
		}
	}
	if strings.Contains(text, "not-in-file") {
		t.Fatalf("dated log leaked a password: %s", text)
	}
}

// captureConsole replaces the console writer with a buffer and restores it.
func captureConsole(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := new(bytes.Buffer)
	mu.Lock()
	old := out.consoleWriter
	oldLevel := moduleLevelLocked(ModuleSystem)
	out.consoleWriter = buf
	moduleLevels[ModuleSystem] = LevelTrace
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		out.consoleWriter = old
		moduleLevels[ModuleSystem] = oldLevel
		mu.Unlock()
	})
	return buf
}

// captureFile replaces the file writer with a buffer and restores it.
func captureFile(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := new(bytes.Buffer)
	mu.Lock()
	old := out.fileWriter
	oldLevel := moduleLevelLocked(ModuleSystem)
	out.fileWriter = buf
	moduleLevels[ModuleSystem] = LevelTrace
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		out.fileWriter = old
		moduleLevels[ModuleSystem] = oldLevel
		mu.Unlock()
	})
	return buf
}

func TestTextFormat(t *testing.T) {
	defer resetOutput()
	SetFormat("text")
	defer SetFormat("text")

	mu.Lock()
	out.consoleLevel = LevelDebug
	out.fileWriter = nil
	mu.Unlock()

	buf := captureConsole(t)

	Info("test message", "key", "value", "count", 42)

	out := buf.String()
	if !strings.Contains(out, "test message") {
		t.Errorf("output missing message: %s", out)
	}
	if !strings.Contains(out, "INFO") {
		t.Errorf("output missing level: %s", out)
	}
	if !strings.Contains(out, "key=value") {
		t.Errorf("output missing key=value: %s", out)
	}
	if !strings.Contains(out, "count=42") {
		t.Errorf("output missing count=42: %s", out)
	}
}

func TestJSONFormat(t *testing.T) {
	defer resetOutput()
	SetFormat("json")
	defer SetFormat("text")

	mu.Lock()
	out.consoleLevel = LevelDebug
	out.fileWriter = nil
	mu.Unlock()

	buf := captureConsole(t)

	Info("test message", "key", "value", "count", 42)

	out := strings.TrimSpace(buf.String())
	if out == "" {
		t.Fatal("no output captured")
	}

	var entry Entry
	if err := json.Unmarshal([]byte(out), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v\noutput: %s", err, out)
	}

	if entry.Message != "test message" {
		t.Errorf("message = %q, want %q", entry.Message, "test message")
	}
	if entry.Level != "INFO" {
		t.Errorf("level = %q, want %q", entry.Level, "INFO")
	}
	if entry.Fields["key"] != "value" {
		t.Errorf("fields[key] = %v, want %q", entry.Fields["key"], "value")
	}
	if entry.Fields["count"] != float64(42) {
		t.Errorf("fields[count] = %v, want 42", entry.Fields["count"])
	}
}

func TestDebugLevel(t *testing.T) {
	defer resetOutput()
	SetFormat("text")
	defer SetFormat("text")

	mu.Lock()
	out.consoleLevel = LevelDebug
	out.fileWriter = nil
	mu.Unlock()

	buf := captureConsole(t)

	Debug("debug message", "component", "test")

	out := buf.String()
	if !strings.Contains(out, "DEBUG") {
		t.Errorf("output missing DEBUG level: %s", out)
	}
	if !strings.Contains(out, "debug message") {
		t.Errorf("output missing message: %s", out)
	}
}

func TestWarnLevel(t *testing.T) {
	defer resetOutput()
	SetFormat("text")
	defer SetFormat("text")

	mu.Lock()
	out.consoleLevel = LevelDebug
	out.fileWriter = nil
	mu.Unlock()

	buf := captureConsole(t)

	Warn("warning message")

	out := buf.String()
	if !strings.Contains(out, "WARN") {
		t.Errorf("output missing WARN level: %s", out)
	}
}

func TestErrorLevel(t *testing.T) {
	defer resetOutput()
	SetFormat("text")
	defer SetFormat("text")

	mu.Lock()
	out.consoleLevel = LevelDebug
	out.fileWriter = nil
	mu.Unlock()

	buf := captureConsole(t)

	Error("error message")

	out := buf.String()
	if !strings.Contains(out, "ERROR") {
		t.Errorf("output missing ERROR level: %s", out)
	}
}

func TestLoggerWith(t *testing.T) {
	defer resetOutput()
	SetFormat("text")
	defer SetFormat("text")

	mu.Lock()
	out.consoleLevel = LevelDebug
	out.fileWriter = nil
	mu.Unlock()

	buf := captureConsole(t)

	l := With("component", "imap")
	l.Info("connection accepted", "remote", "127.0.0.1")

	out := buf.String()
	if !strings.Contains(out, "connection accepted") {
		t.Errorf("output missing message: %s", out)
	}
	if !strings.Contains(out, "remote=127.0.0.1") {
		t.Errorf("output missing remote field: %s", out)
	}
}

func TestJSONLoggerWith(t *testing.T) {
	defer resetOutput()
	SetFormat("json")
	defer SetFormat("text")

	mu.Lock()
	out.consoleLevel = LevelDebug
	out.fileWriter = nil
	mu.Unlock()

	buf := captureConsole(t)

	l := With("component", "smtp")
	l.Info("message delivered", "recipient", "alice@example.com")

	out := strings.TrimSpace(buf.String())
	var entry Entry
	if err := json.Unmarshal([]byte(out), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v\noutput: %s", err, out)
	}

	if entry.Fields["recipient"] != "alice@example.com" {
		t.Errorf("fields[recipient] = %v, want %q", entry.Fields["recipient"], "alice@example.com")
	}
}

func TestParseKV(t *testing.T) {
	kv := parseKV([]interface{}{"a", 1, "b", "two", "orphan"})
	if kv["a"] != 1 {
		t.Errorf("kv[a] = %v, want 1", kv["a"])
	}
	if kv["b"] != "two" {
		t.Errorf("kv[b] = %v, want %q", kv["b"], "two")
	}
	if len(kv) != 2 {
		t.Errorf("expected 2 keys, got %d", len(kv))
	}
}

func TestSetFormat(t *testing.T) {
	currentFormat := format
	defer func() { format = currentFormat }()

	SetFormat("json")
	if format != FormatJSON {
		t.Errorf("format = %d, want %d", format, FormatJSON)
	}

	SetFormat("text")
	if format != FormatText {
		t.Errorf("format = %d, want %d", format, FormatText)
	}

	SetFormat("unknown")
	if format != FormatText {
		t.Errorf("format = %d, want %d", format, FormatText)
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		level Level
		want  string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{Level(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("Level(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  Level
	}{
		{"debug", LevelDebug},
		{"DEBUG", LevelDebug},
		{"Debug", LevelDebug},
		{"info", LevelInfo},
		{"INFO", LevelInfo},
		{"warn", LevelWarn},
		{"WARN", LevelWarn},
		{"error", LevelError},
		{"ERROR", LevelError},
		{"trace", LevelTrace},
		{"fatal", LevelFatal},
		{"", LevelInfo},
	}

	for _, tt := range tests {
		if got := ParseLevel(tt.input); got != tt.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestGetLevelAndSetLevel(t *testing.T) {
	// Save and restore the original level
	original := GetLevel()
	defer SetLevel(original)

	// Set and verify each level
	for _, level := range []Level{LevelTrace, LevelDebug, LevelInfo, LevelWarn, LevelError, LevelFatal} {
		SetLevel(level)
		if got := GetLevel(); got != level {
			t.Errorf("GetLevel() = %v, want %v after SetLevel(%v)", got, level, level)
		}
	}
}

// --- Dual output tests ---

func TestMultiWriterConsoleLevelFilter(t *testing.T) {
	defer resetOutput()
	SetFormat("text")

	// Console only shows warn and above
	mu.Lock()
	out.consoleLevel = LevelWarn
	out.fileWriter = nil
	mu.Unlock()

	buf := captureConsole(t)

	Debug("debug msg")
	Info("info msg")
	Warn("warn msg")
	Error("error msg")

	out := buf.String()
	if strings.Contains(out, "debug msg") {
		t.Error("console should not have debug msg")
	}
	if strings.Contains(out, "info msg") {
		t.Error("console should not have info msg")
	}
	if !strings.Contains(out, "warn msg") {
		t.Error("console should have warn msg")
	}
	if !strings.Contains(out, "error msg") {
		t.Error("console should have error msg")
	}
}

func TestMultiWriterFileLevelFilter(t *testing.T) {
	defer resetOutput()
	SetFormat("text")

	// File shows everything from debug
	mu.Lock()
	out.consoleWriter = io.Discard
	out.consoleLevel = LevelInfo
	out.fileLevel = LevelDebug
	mu.Unlock()

	buf := captureFile(t)

	Debug("debug msg")
	Info("info msg")
	Warn("warn msg")
	Error("error msg")

	out := buf.String()
	if !strings.Contains(out, "debug msg") {
		t.Error("file should have debug msg")
	}
	if !strings.Contains(out, "info msg") {
		t.Error("file should have info msg")
	}
	if !strings.Contains(out, "warn msg") {
		t.Error("file should have warn msg")
	}
	if !strings.Contains(out, "error msg") {
		t.Error("file should have error msg")
	}
}

func TestMultiWriterDifferentLevels(t *testing.T) {
	defer resetOutput()
	SetFormat("text")

	// Console=warn, file=debug
	mu.Lock()
	out.consoleLevel = LevelWarn
	out.fileLevel = LevelDebug
	mu.Unlock()

	consoleBuf := captureConsole(t)
	fileBuf := captureFile(t)

	Debug("debug msg")
	Info("info msg")
	Warn("warn msg")

	consoleOut := consoleBuf.String()
	fileOut := fileBuf.String()

	// Console should only have warn
	if strings.Contains(consoleOut, "debug msg") {
		t.Error("console should not have debug")
	}
	if strings.Contains(consoleOut, "info msg") {
		t.Error("console should not have info")
	}
	if !strings.Contains(consoleOut, "warn msg") {
		t.Error("console should have warn")
	}

	// File should have all
	if !strings.Contains(fileOut, "debug msg") {
		t.Error("file should have debug")
	}
	if !strings.Contains(fileOut, "info msg") {
		t.Error("file should have info")
	}
	if !strings.Contains(fileOut, "warn msg") {
		t.Error("file should have warn")
	}
}

func TestMultiWriterJSONFormat(t *testing.T) {
	defer resetOutput()
	SetFormat("json")
	defer SetFormat("text")

	mu.Lock()
	out.consoleLevel = LevelDebug
	out.fileLevel = LevelDebug
	mu.Unlock()

	consoleBuf := captureConsole(t)
	fileBuf := captureFile(t)

	Info("json test", "key", "val")

	consoleOut := strings.TrimSpace(consoleBuf.String())
	fileOut := strings.TrimSpace(fileBuf.String())

	// Both should be valid JSON
	var cEntry Entry
	if err := json.Unmarshal([]byte(consoleOut), &cEntry); err != nil {
		t.Fatalf("console JSON parse failed: %v\noutput: %s", err, consoleOut)
	}
	if cEntry.Message != "json test" {
		t.Errorf("console message = %q, want %q", cEntry.Message, "json test")
	}

	var fEntry Entry
	if err := json.Unmarshal([]byte(fileOut), &fEntry); err != nil {
		t.Fatalf("file JSON parse failed: %v\noutput: %s", err, fileOut)
	}
	if fEntry.Message != "json test" {
		t.Errorf("file message = %q, want %q", fEntry.Message, "json test")
	}
}

// --- Setup/teardown tests ---

func TestSetupAndClose(t *testing.T) {
	tmpDir := t.TempDir()

	err := Setup(tmpDir, "text", LevelInfo, LevelDebug)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer Close()

	// Verify file writer is set
	mu.Lock()
	hasFile := out.fileWriter != nil
	mu.Unlock()
	if !hasFile {
		t.Error("Setup should have set file writer")
	}

	// Close should work
	err = Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

}

func TestSetupCreatesLogDir(t *testing.T) {
	tmpDir := t.TempDir() + "/nested/logs"

	err := Setup(tmpDir, "json", LevelWarn, LevelDebug)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer Close()

	// Check that the directory was created
	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		t.Error("Setup should create log directory")
	}
}

func TestCloseWithoutSetup(t *testing.T) {
	defer resetOutput()
	mu.Lock()
	out.fileWriter = nil
	mu.Unlock()

	// Should not panic
	err := Close()
	if err != nil {
		t.Errorf("Close without Setup should not error: %v", err)
	}
}

func TestNoFileOutputByDefault(t *testing.T) {
	defer resetOutput()
	SetFormat("text")

	mu.Lock()
	out.consoleLevel = LevelDebug
	out.fileWriter = nil
	mu.Unlock()

	buf := captureConsole(t)

	Info("test")

	out := buf.String()
	if !strings.Contains(out, "test") {
		t.Error("console should have output")
	}
}

func TestFileLevelOffOpensNoFileAndCanBeReenabled(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	if err := Setup(dir, "text", LevelInfo, LevelOff); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Close() })
	Info("not written")
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("file logging off created %v", entries)
	}
	SetFileLevel(LevelInfo)
	Info("written")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("re-enabled file logging: entries=%v err=%v", entries, err)
	}
	SetFileLevel(LevelOff)
	mu.Lock()
	closed := out.fileWriter == nil
	mu.Unlock()
	if !closed {
		t.Fatal("file writer stayed open after switching off")
	}
}

func TestCallerIsTheLoggingCallSite(t *testing.T) {
	defer resetOutput()
	SetFormat("json")
	defer SetFormat("text")

	mu.Lock()
	out.consoleLevel = LevelDebug
	out.fileWriter = nil
	mu.Unlock()

	// Each case logs and returns the location of its logging call.
	for name, logf := range map[string]func() string{
		"package": func() string {
			Warn("caller")
			_, file, line, _ := runtime.Caller(0)
			return fmt.Sprintf("%s:%d", file, line-1)
		},
		"logger": func() string {
			For(ModuleSystem).Warn("caller")
			_, file, line, _ := runtime.Caller(0)
			return fmt.Sprintf("%s:%d", file, line-1)
		},
	} {
		buf := captureConsole(t)
		want := logf()
		var entry Entry
		if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if entry.Caller != want {
			t.Errorf("%s: caller = %q, want %q", name, entry.Caller, want)
		}
	}
}
