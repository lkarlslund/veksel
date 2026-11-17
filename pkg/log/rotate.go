package log

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RotatingFile implements io.Writer with daily log rotation.
// Each day a new file is created with the pattern {prefix}-{YYYY-MM-DD}.log.
// Old files are cleaned up based on maxAgeDays and maxBackups.
type RotatingFile struct {
	mu         sync.Mutex
	file       *os.File
	path       string
	dir        string
	prefix     string
	maxAgeDays int
	maxBackups int
	currentDay string
}

// NewRotatingFile creates a new rotating file writer in the given directory.
// The directory is created if it does not exist.
// Files are named {prefix}-{YYYY-MM-DD}.log.
// maxAgeDays controls how many days of logs to keep.
// maxBackups controls the maximum number of backup files to retain.
func NewRotatingFile(dir, prefix string, maxAgeDays, maxBackups int) (*RotatingFile, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	rf := &RotatingFile{
		dir:        dir,
		prefix:     prefix,
		maxAgeDays: maxAgeDays,
		maxBackups: maxBackups,
		currentDay: time.Now().UTC().Format("2006-01-02"),
	}

	if err := rf.openToday(); err != nil {
		return nil, err
	}

	return rf, nil
}

// openToday opens (or creates) the log file for the current day.
func (rf *RotatingFile) openDay(day string) error {
	filename := fmt.Sprintf("%s-%s.log", rf.prefix, day)
	path := filepath.Join(rf.dir, filename)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", path, err)
	}

	old := rf.file
	rf.file = f
	rf.path = path
	rf.currentDay = day
	if old != nil {
		if err := old.Close(); err != nil {
			return fmt.Errorf("close previous log file: %w", err)
		}
	}
	return nil
}

func (rf *RotatingFile) openToday() error { return rf.openDay(time.Now().UTC().Format("2006-01-02")) }

// Write implements io.Writer. It checks if the day has changed and rotates
// if necessary before writing.
func (rf *RotatingFile) Write(p []byte) (int, error) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	today := time.Now().UTC().Format("2006-01-02")
	if today != rf.currentDay {
		if err := rf.openDay(today); err != nil {
			return 0, err
		}
		rf.cleanup()
	}
	if rf.file == nil {
		return 0, os.ErrClosed
	}
	return rf.file.Write(p)
}

// Close implements io.Closer. It closes the current log file.
func (rf *RotatingFile) Close() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	if rf.file != nil {
		err := rf.file.Close()
		rf.file = nil
		return err
	}
	return nil
}

// cleanup removes old log files based on maxAgeDays and maxBackups.
func (rf *RotatingFile) cleanup() {
	entries, err := os.ReadDir(rf.dir)
	if err != nil {
		return
	}

	var oldFiles []os.FileInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, rf.prefix+"-") || !strings.HasSuffix(name, ".log") {
			continue
		}

		info, err := e.Info()
		if err != nil {
			continue
		}
		oldFiles = append(oldFiles, info)
	}

	if len(oldFiles) == 0 {
		return
	}

	// Remove files older than maxAgeDays
	cutoff := time.Now().UTC().AddDate(0, 0, -rf.maxAgeDays)
	for _, fi := range oldFiles {
		if fi.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(rf.dir, fi.Name()))
		}
	}

	// Re-read after age-based removal to enforce maxBackups
	entries, err = os.ReadDir(rf.dir)
	if err != nil {
		return
	}

	var backups []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, rf.prefix+"-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		backups = append(backups, name)
	}

	// Keep at most maxBackups files (newest first)
	for len(backups) > rf.maxBackups {
		// Remove the oldest (first in the list since names contain dates)
		os.Remove(filepath.Join(rf.dir, backups[0]))
		backups = backups[1:]
	}
}
