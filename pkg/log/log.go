// Package log provides structured logging for Veksel.
//
// It supports two output formats: text (default) and JSON.
// The format is controlled explicitly by SetFormat.
//
// Dual output: log entries can be written to both console (stderr) and a
// rotating file, each with independent level filters. Use Setup() to
// configure file output.
//
// Usage:
//
//	log.Info("connection accepted", "remote_addr", conn.RemoteAddr())
//	log.Warn("auth failed", "user", username, "component", "imap")
package log

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Level represents a log severity level.
type Level uint8

const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
	// LevelOff is a threshold above every message level; it disables a sink.
	LevelOff
)

func (l Level) String() string {
	switch l {
	case LevelTrace:
		return "TRACE"
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	case LevelOff:
		return "OFF"
	default:
		return "UNKNOWN"
	}
}

// ConfigString returns the canonical managed-configuration spelling.
func (l Level) ConfigString() string { return strings.ToLower(l.String()) }

// Valid reports whether l is a supported threshold.
func (l Level) Valid() bool { return l <= LevelOff }

// Default rotating-file retention.
const (
	DefaultRetentionDays = 30
	DefaultMaxFiles      = 10
)

// Format is the output format for log entries.
type Format int

const (
	FormatText Format = iota
	FormatJSON
)

// multiOutput manages dual output: console (stderr) and optional rotating file.
// Each output has its own independent level filter.
type multiOutput struct {
	consoleWriter io.Writer
	consoleLevel  Level
	fileWriter    io.Writer
	fileLevel     Level
	fileDir       string
	retentionDays int
	maxFiles      int
}

var (
	mu          sync.Mutex
	format      Format = FormatText
	callerLevel Level  = LevelDebug
	std                = &Logger{
		module: ModuleSystem,
	}
	moduleLevels = DefaultModuleLevelValues()
	out          = &multiOutput{
		consoleWriter: os.Stderr,
		consoleLevel:  LevelInfo,
		fileWriter:    nil,
		fileLevel:     LevelDebug,
		retentionDays: DefaultRetentionDays,
		maxFiles:      DefaultMaxFiles,
	}
)

// Logger writes structured log entries.
type Logger struct {
	module Module
	fields map[string]any
}

// Entry represents a single log record.
type Entry struct {
	Timestamp time.Time      `json:"ts"`
	Level     string         `json:"level"`
	Module    string         `json:"module"`
	Message   string         `json:"msg"`
	Fields    map[string]any `json:"fields,omitempty"`
	Caller    string         `json:"caller,omitempty"`
}

// ParseLevel parses a level string into a Level.
// Accepts all six managed levels case-insensitively.
// Returns LevelInfo for unknown values.
func ParseLevel(s string) Level {
	level, err := ParseLevelStrict(s)
	if err != nil {
		return LevelInfo
	}
	return level
}

// ParseLevelStrict parses a managed level without silently accepting typos.
func ParseLevelStrict(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	case "fatal":
		return LevelFatal, nil
	case "off":
		return LevelOff, nil
	default:
		return LevelInfo, fmt.Errorf("level must be trace, debug, info, warn, error, fatal, or off")
	}
}

// GetLevel returns the current global log level.
func GetLevel() Level {
	mu.Lock()
	defer mu.Unlock()
	return out.consoleLevel
}

// SetLevel changes the global log level.
func SetLevel(l Level) {
	mu.Lock()
	defer mu.Unlock()
	out.consoleLevel = l
}

// SetFileLevel changes the file sink threshold without reopening it.
// SetFileLevel changes the file threshold, opening or closing the rotating
// file when file logging is switched on or off.
func SetFileLevel(level Level) {
	mu.Lock()
	defer mu.Unlock()
	if err := setFileLevelLocked(level); err != nil {
		fmt.Fprintf(os.Stderr, "log: %v\n", err)
	}
}

func setFileLevelLocked(level Level) error {
	out.fileLevel = level
	if level == LevelOff {
		closeFileLocked()
		return nil
	}
	if out.fileWriter != nil || out.fileDir == "" {
		return nil
	}
	rf, err := NewRotatingFile(out.fileDir, "veksel", out.retentionDays, out.maxFiles)
	if err != nil {
		return fmt.Errorf("create rotating file: %w", err)
	}
	out.fileWriter = rf
	return nil
}

// SetFileRetention changes how many days and how many daily files the rotating
// log keeps. An open file is reopened (appending) so the new limits apply
// immediately; non-positive values keep the defaults.
func SetFileRetention(days, files int) {
	mu.Lock()
	defer mu.Unlock()
	if days < 1 {
		days = DefaultRetentionDays
	}
	if files < 1 {
		files = DefaultMaxFiles
	}
	out.retentionDays, out.maxFiles = days, files
	if out.fileWriter == nil {
		return
	}
	_ = closeFileLocked()
	if err := setFileLevelLocked(out.fileLevel); err != nil {
		fmt.Fprintf(os.Stderr, "log: %v\n", err)
	}
}

func closeFileLocked() error {
	writer := out.fileWriter
	out.fileWriter = nil
	if closer, ok := writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SetFormat changes the global log output format.
// Accepts "text" or "json".
func SetFormat(f string) {
	mu.Lock()
	defer mu.Unlock()
	switch f {
	case "json":
		format = FormatJSON
	default:
		format = FormatText
	}
}

// Setup configures dual-output logging with a rotating file writer.
// logDir is the directory for log files (created if needed).
// formatStr is "text" or "json".
// consoleLevel and fileLevel are the independent level filters for each output.
// If fileWriter setup fails, only console output is used.
func Setup(logDir, formatStr string, consoleLevel, fileLevel Level) error {
	mu.Lock()
	defer mu.Unlock()

	// Set format
	switch formatStr {
	case "json":
		format = FormatJSON
	default:
		format = FormatText
	}

	out.consoleWriter = os.Stderr
	out.consoleLevel = consoleLevel
	if logDir != out.fileDir {
		_ = closeFileLocked()
		out.fileDir = logDir
	}
	return setFileLevelLocked(fileLevel)
}

// Close shuts down the rotating file writer.
// Safe to call even if Setup was not called.
func Close() error {
	mu.Lock()
	defer mu.Unlock()

	return closeFileLocked()
}

// Debug logs a debug-level message.
func Debug(msg string, keysAndValues ...interface{}) {
	std.log(LevelDebug, msg, keysAndValues...)
}

// Trace logs the most detailed diagnostic level.
func Trace(msg string, keysAndValues ...interface{}) {
	std.log(LevelTrace, msg, keysAndValues...)
}

// Info logs an info-level message.
func Info(msg string, keysAndValues ...interface{}) {
	std.log(LevelInfo, msg, keysAndValues...)
}

// Warn logs a warning-level message.
func Warn(msg string, keysAndValues ...interface{}) {
	std.log(LevelWarn, msg, keysAndValues...)
}

// Error logs an error-level message.
func Error(msg string, keysAndValues ...interface{}) {
	std.log(LevelError, msg, keysAndValues...)
}

// Fatal logs at fatal severity. It deliberately never exits the process.
func Fatal(msg string, keysAndValues ...interface{}) {
	std.log(LevelFatal, msg, keysAndValues...)
}

// For returns a logger bound to a registered runtime module.
func For(module Module) *Logger {
	if _, ok := knownModules[module]; !ok {
		panic("log: unregistered module " + string(module))
	}
	return &Logger{module: module}
}

// With creates a new logger that includes the given keys and values
// in every log entry.
func With(keysAndValues ...interface{}) *Logger {
	fields := parseKV(keysAndValues)
	module := ModuleSystem
	if value, ok := fields["component"].(string); ok {
		candidate := Module(value)
		if _, registered := knownModules[candidate]; registered {
			module = candidate
		}
	}
	delete(fields, "component")
	return &Logger{module: module, fields: fields}
}

// With returns a child logger retaining its module and context.
func (l *Logger) With(keysAndValues ...interface{}) *Logger {
	fields := make(map[string]any, len(l.fields)+len(keysAndValues)/2)
	for key, value := range l.fields {
		fields[key] = value
	}
	for key, value := range parseKV(keysAndValues) {
		fields[key] = value
	}
	return &Logger{module: l.module, fields: fields}
}

func (l *Logger) log(level Level, msg string, keysAndValues ...interface{}) {
	// Check if this level should be logged at all
	mu.Lock()
	defer mu.Unlock()
	o, f, cl := out, format, callerLevel
	if level < moduleLevelLocked(l.module) {
		return
	}

	// Check console level
	consoleAllowed := o.consoleWriter != nil && level >= o.consoleLevel
	// Check file level
	fileAllowed := o.fileWriter != nil && level >= o.fileLevel

	if !consoleAllowed && !fileAllowed {
		return
	}

	entry := Entry{
		Timestamp: time.Now().UTC(),
		Level:     level.String(),
		Module:    string(l.module),
		Message:   redactText(msg),
		Fields:    mergeAndRedactFields(l.fields, parseKV(keysAndValues)),
	}

	// Capture caller info for levels >= callerLevel
	if level >= cl {
		if _, file, line, ok := runtime.Caller(2); ok {
			entry.Caller = fmt.Sprintf("%s:%d", file, line)
		}
	}

	var line string
	switch f {
	case FormatJSON:
		data, err := json.Marshal(entry)
		if err != nil {
			line = fmt.Sprintf("%s %s: %s", entry.Timestamp.Format(time.RFC3339), entry.Level, entry.Message)
		} else {
			line = string(data)
		}
	default:
		line = fmt.Sprintf("%s %s %s",
			entry.Timestamp.Format(time.RFC3339),
			entry.Level,
			entry.Module+": "+escapeText(entry.Message),
		)
		// Append fields in text format
		for k, v := range entry.Fields {
			line += fmt.Sprintf(" %s=%s", escapeText(k), escapeText(fmt.Sprint(v)))
		}
		if entry.Caller != "" {
			line += fmt.Sprintf(" caller=%s", entry.Caller)
		}
	}

	// Write to each output based on its level
	if consoleAllowed {
		fmt.Fprintln(o.consoleWriter, line)
	}
	if fileAllowed {
		fmt.Fprintln(o.fileWriter, line)
	}
}

// Debug logs a debug-level message with the logger's context.
func (l *Logger) Debug(msg string, keysAndValues ...interface{}) {
	l.log(LevelDebug, msg, keysAndValues...)
}

// Trace logs a trace-level message with the logger's context.
func (l *Logger) Trace(msg string, keysAndValues ...interface{}) {
	l.log(LevelTrace, msg, keysAndValues...)
}

// Info logs an info-level message with the logger's context.
func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	l.log(LevelInfo, msg, keysAndValues...)
}

// Warn logs a warning-level message with the logger's context.
func (l *Logger) Warn(msg string, keysAndValues ...interface{}) {
	l.log(LevelWarn, msg, keysAndValues...)
}

// Error logs an error-level message with the logger's context.
func (l *Logger) Error(msg string, keysAndValues ...interface{}) {
	l.log(LevelError, msg, keysAndValues...)
}

// Fatal logs fatal severity without terminating the process.
func (l *Logger) Fatal(msg string, keysAndValues ...interface{}) {
	l.log(LevelFatal, msg, keysAndValues...)
}

// parseKV converts a variadic list of key-value pairs into a map.
// Pairs are expected as [key, value, key, value, ...].
// Odd trailing values are ignored.
func parseKV(kv []interface{}) map[string]any {
	m := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if key, ok := kv[i].(string); ok {
			m[key] = kv[i+1]
		}
	}
	return m
}

var sensitiveText = regexp.MustCompile(`(?i)(bearer\s+)[^\s]+|((?:password|passwd|secret|token|authorization|cookie|credential)=)[^\s&]+|([a-z][a-z0-9+.-]*://)[^/@\s]+@`)

func mergeAndRedactFields(base, additional map[string]any) map[string]any {
	result := make(map[string]any, len(base)+len(additional))
	for key, value := range base {
		result[key] = redactValue(key, value)
	}
	for key, value := range additional {
		result[key] = redactValue(key, value)
	}
	return result
}

func redactValue(key string, value any) any {
	lower := strings.ToLower(key)
	for _, marker := range []string{"password", "passwd", "secret", "token", "authorization", "cookie", "credential"} {
		if strings.Contains(lower, marker) {
			return "[redacted]"
		}
	}
	return redactAny(value)
}

func redactAny(value any) any {
	if text, ok := value.(string); ok {
		return redactText(text)
	}
	if err, ok := value.(error); ok {
		return redactText(err.Error())
	}
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, nested := range typed {
			result[key] = redactValue(key, nested)
		}
		return result
	case map[string]string:
		result := make(map[string]string, len(typed))
		for key, nested := range typed {
			result[key] = fmt.Sprint(redactValue(key, nested))
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, nested := range typed {
			result[index] = redactAny(nested)
		}
		return result
	case []string:
		result := make([]string, len(typed))
		for index, nested := range typed {
			result[index] = redactText(nested)
		}
		return result
	}
	return value
}

func redactText(value string) string {
	return sensitiveText.ReplaceAllStringFunc(value, func(match string) string {
		lower := strings.ToLower(match)
		if strings.Contains(lower, "://") && strings.HasSuffix(match, "@") {
			return match[:strings.Index(match, "://")+3] + "[redacted]@"
		}
		if index := strings.IndexAny(match, " ="); index >= 0 {
			return match[:index+1] + "[redacted]"
		}
		return "[redacted]"
	})
}

// escapeText keeps a text log line one line of printable UTF-8: control
// characters and invalid bytes (from client-supplied strings such as a
// malformed SMTP command) are written as Go escapes, so line-oriented
// tools such as grep keep treating the file as text.
func escapeText(value string) string {
	clean := true
	for _, r := range value {
		if r == utf8.RuneError || unicode.IsControl(r) {
			clean = false
			break
		}
	}
	if clean {
		return value
	}
	var out strings.Builder
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		switch {
		case r == utf8.RuneError && size <= 1:
			fmt.Fprintf(&out, "\\x%02x", value[0])
		case r == '\n':
			out.WriteString("\\n")
		case r == '\r':
			out.WriteString("\\r")
		case r == '\t':
			out.WriteString("\\t")
		case unicode.IsControl(r):
			if r < 0x100 {
				fmt.Fprintf(&out, "\\x%02x", r)
			} else {
				fmt.Fprintf(&out, "\\u%04x", r)
			}
		default:
			out.WriteString(value[:size])
		}
		value = value[size:]
	}
	return out.String()
}
