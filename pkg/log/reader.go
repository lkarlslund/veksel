package log

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	defaultLogPageSize = 50
	maxLogPageSize     = 200
	maxLogLineBytes    = 64 << 10
	maxLogValueBytes   = 2 << 10
	reverseReadBlock   = 16 << 10
)

var (
	managedLogName = regexp.MustCompile(`^veksel-\d{4}-\d{2}-\d{2}\.log$`)
	textLogLine    = regexp.MustCompile(`^(\S+)\s+(TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+([^:]+):\s?(.*)$`)
	textLogField   = regexp.MustCompile(`(?:^| )([A-Za-z_][A-Za-z0-9_.-]*)=`)
	ErrLogCursor   = errors.New("invalid log cursor")
	ErrLogQuery    = errors.New("invalid log query")
)

// LogQuery describes a bounded query over the managed rotating log files.
// Cursor continues a page toward older records; After (a HeadCursor from an
// earlier page) instead returns only records written since that page. Level
// matches one severity exactly, MinLevel matches that severity and above.
type LogQuery struct {
	Cursor   string
	After    string
	Limit    int
	Level    string
	MinLevel string
	Module   string
	Text     string
}

// LogRecord is the safe, normalized representation returned to administrators.
type LogRecord struct {
	Timestamp time.Time         `json:"timestamp"`
	Level     string            `json:"level"`
	Module    string            `json:"module"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
	Caller    string            `json:"caller,omitempty"`
}

// LogPage is a newest-first page. NextCursor continues toward older records.
// HeadCursor marks the newest complete record seen and is returned for every
// query that does not continue an older page; pass it as After to follow new
// records. Truncated reports that an After query found more than Limit new
// records and returned only the newest of them.
type LogPage struct {
	Records    []LogRecord `json:"records"`
	NextCursor string      `json:"next_cursor,omitempty"`
	HeadCursor string      `json:"head_cursor,omitempty"`
	Truncated  bool        `json:"truncated,omitempty"`
}

type logCursor struct {
	File   string `json:"f"`
	Offset int64  `json:"o"`
}

// QueryManagedLogs reads only Veksel-managed daily log files below dir.
func QueryManagedLogs(dir string, query LogQuery) (LogPage, error) {
	if query.Limit == 0 {
		query.Limit = defaultLogPageSize
	}
	if query.Limit < 1 || query.Limit > maxLogPageSize {
		return LogPage{}, fmt.Errorf("%w: limit must be between 1 and %d", ErrLogQuery, maxLogPageSize)
	}
	if query.Cursor != "" && query.After != "" {
		return LogPage{}, fmt.Errorf("%w: cursor and after are mutually exclusive", ErrLogQuery)
	}
	query.Level = strings.ToUpper(strings.TrimSpace(query.Level))
	if query.Level != "" {
		if _, err := ParseLevelStrict(query.Level); err != nil {
			return LogPage{}, fmt.Errorf("%w: level: %v", ErrLogQuery, err)
		}
	}
	minLevel := LevelTrace
	if raw := strings.TrimSpace(query.MinLevel); raw != "" {
		parsed, err := ParseLevelStrict(raw)
		if err != nil {
			return LogPage{}, fmt.Errorf("%w: min_level: %v", ErrLogQuery, err)
		}
		minLevel = parsed
	}
	query.Module = strings.TrimSpace(query.Module)
	query.Text = strings.ToLower(strings.TrimSpace(query.Text))
	matches := func(record LogRecord, searchable string) bool {
		if level, err := ParseLevelStrict(record.Level); err != nil || level < minLevel {
			return false
		}
		return matchesLogQuery(record, searchable, query)
	}

	files, err := managedLogFiles(dir)
	if err != nil {
		return LogPage{}, err
	}
	if len(files) == 0 {
		return LogPage{Records: []LogRecord{}}, nil
	}

	startFile := 0
	startOffset := int64(-1)
	var after *logCursor
	if query.Cursor != "" {
		cursor, err := decodeLogCursor(query.Cursor)
		if err != nil {
			return LogPage{}, err
		}
		startFile = slices.Index(files, cursor.File)
		if startFile < 0 {
			return LogPage{}, ErrLogCursor
		}
		startOffset = cursor.Offset
	} else if query.After != "" {
		cursor, err := decodeLogCursor(query.After)
		if err != nil {
			return LogPage{}, err
		}
		after = &cursor
	}

	page := LogPage{Records: make([]LogRecord, 0, query.Limit)}
	for fileIndex := startFile; fileIndex < len(files); fileIndex++ {
		name := files[fileIndex]
		stop := int64(0)
		if after != nil {
			if name < after.File {
				break
			}
			if name == after.File {
				stop = after.Offset
			}
		}
		done, err := scanManagedLog(filepath.Join(dir, name), func(end int64) (int64, error) {
			if fileIndex == startFile && startOffset >= 0 {
				if startOffset > end {
					return 0, ErrLogCursor
				}
				end = startOffset
			}
			if query.Cursor == "" && fileIndex == 0 {
				page.HeadCursor = encodeLogCursor(logCursor{File: name, Offset: end})
			}
			if stop > end {
				return 0, ErrLogCursor
			}
			return end, nil
		}, stop, func(record LogRecord, searchable string, lineEnd int64) bool {
			if !matches(record, searchable) {
				return true
			}
			if len(page.Records) == query.Limit {
				if after != nil {
					page.Truncated = true
				} else {
					page.NextCursor = encodeLogCursor(logCursor{File: name, Offset: lineEnd})
				}
				return false
			}
			page.Records = append(page.Records, record)
			return true
		})
		if err != nil {
			return LogPage{}, err
		}
		if done {
			break
		}
	}
	return page, nil
}

// scanManagedLog visits complete records of one managed log newest first.
// start receives the offset just past the last complete record and returns
// where to begin; records are visited until stop or until visit returns false,
// which makes scanManagedLog report done.
func scanManagedLog(path string, start func(end int64) (int64, error), stop int64, visit func(record LogRecord, searchable string, lineEnd int64) bool) (bool, error) {
	name := filepath.Base(path)
	file, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open managed log %s: %w", name, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect managed log %s: %w", name, err)
	}
	position := info.Size()
	if position > 0 {
		last := []byte{0}
		if _, err := file.ReadAt(last, position-1); err != nil {
			return false, err
		}
		if last[0] != '\n' {
			// A writer may be between writing the record and its newline. Do not
			// expose a malformed transient record; it appears on the next refresh.
			_, position, _, err = previousLogLine(file, position)
			if err != nil && !errors.Is(err, io.EOF) {
				return false, err
			}
		}
	}
	if position, err = start(position); err != nil {
		return false, err
	}
	for position > stop {
		lineEnd := position
		line, nextPosition, oversized, err := previousLogLine(file, position)
		position = nextPosition
		if err != nil && !errors.Is(err, io.EOF) {
			return false, err
		}
		if oversized || len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		record, searchable, ok := parseLogRecord(line)
		if ok && !visit(record, searchable, lineEnd) {
			return true, nil
		}
	}
	return false, nil
}

func managedLogFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read managed log directory: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 && managedLogName.MatchString(entry.Name()) {
			files = append(files, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	return files, nil
}

func previousLogLine(file *os.File, end int64) ([]byte, int64, bool, error) {
	if end <= 0 {
		return nil, 0, false, io.EOF
	}
	if b := []byte{0}; end > 0 {
		if _, err := file.ReadAt(b, end-1); err != nil {
			return nil, end, false, err
		}
		if b[0] == '\n' {
			end--
		}
	}
	lineEnd := end
	position := end
	for position > 0 {
		start := position - reverseReadBlock
		if start < 0 {
			start = 0
		}
		chunk := make([]byte, position-start)
		if _, err := file.ReadAt(chunk, start); err != nil {
			return nil, position, false, err
		}
		if index := bytes.LastIndexByte(chunk, '\n'); index >= 0 {
			lineStart := start + int64(index) + 1
			length := lineEnd - lineStart
			if length > maxLogLineBytes {
				return nil, lineStart, true, nil
			}
			line := make([]byte, length)
			if _, err := file.ReadAt(line, lineStart); err != nil {
				return nil, lineStart, false, err
			}
			return line, lineStart, false, nil
		}
		position = start
	}
	if lineEnd > maxLogLineBytes {
		return nil, 0, true, nil
	}
	line := make([]byte, lineEnd)
	if lineEnd > 0 {
		if _, err := file.ReadAt(line, 0); err != nil {
			return nil, 0, false, err
		}
	}
	return line, 0, false, nil
}

func parseLogRecord(line []byte) (LogRecord, string, bool) {
	var entry Entry
	if len(line) > 0 && line[0] == '{' && json.Unmarshal(line, &entry) == nil && !entry.Timestamp.IsZero() {
		record := LogRecord{Timestamp: entry.Timestamp, Level: strings.ToUpper(entry.Level), Module: entry.Module, Message: truncateLogValue(entry.Message), Caller: truncateLogValue(entry.Caller)}
		if len(entry.Fields) > 0 {
			record.Fields = make(map[string]string, len(entry.Fields))
			for key, value := range entry.Fields {
				record.Fields[truncateLogValue(key)] = truncateLogValue(fmt.Sprint(value))
			}
		}
		return record, strings.ToLower(string(line)), record.Module != "" && record.Level != ""
	}
	match := textLogLine.FindSubmatch(line)
	if match == nil {
		return LogRecord{}, "", false
	}
	timestamp, err := time.Parse(time.RFC3339, string(match[1]))
	if err != nil {
		return LogRecord{}, "", false
	}
	remainder := string(match[4])
	record := LogRecord{Timestamp: timestamp, Level: string(match[2]), Module: string(match[3]), Message: truncateLogValue(remainder)}
	fieldMatches := textLogField.FindAllStringSubmatchIndex(remainder, -1)
	if len(fieldMatches) > 0 {
		record.Message = truncateLogValue(strings.TrimSpace(remainder[:fieldMatches[0][0]]))
		for index, fieldMatch := range fieldMatches {
			valueEnd := len(remainder)
			if index+1 < len(fieldMatches) {
				valueEnd = fieldMatches[index+1][0]
			}
			key := remainder[fieldMatch[2]:fieldMatch[3]]
			value := truncateLogValue(strings.TrimSpace(remainder[fieldMatch[1]:valueEnd]))
			if key == "caller" {
				record.Caller = value
				continue
			}
			if record.Fields == nil {
				record.Fields = make(map[string]string)
			}
			record.Fields[key] = value
		}
	}
	return record, strings.ToLower(string(line)), true
}

func matchesLogQuery(record LogRecord, searchable string, query LogQuery) bool {
	return (query.Level == "" || record.Level == query.Level) &&
		(query.Module == "" || record.Module == query.Module) &&
		(query.Text == "" || strings.Contains(searchable, query.Text))
}

func truncateLogValue(value string) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= maxLogValueBytes {
		return value
	}
	value = value[:maxLogValueBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value + "…"
}

func encodeLogCursor(cursor logCursor) string {
	data, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeLogCursor(encoded string) (logCursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(data) > 256 {
		return logCursor{}, ErrLogCursor
	}
	var cursor logCursor
	if json.Unmarshal(data, &cursor) != nil || !managedLogName.MatchString(cursor.File) || cursor.Offset < 0 {
		return logCursor{}, ErrLogCursor
	}
	return cursor, nil
}
