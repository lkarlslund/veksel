package log

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRotatingFileCreatesDir(t *testing.T) {
	tmpDir := filepath.Join(t.TempDir(), "nested", "logs")
	rf, err := NewRotatingFile(tmpDir, "test", 30, 10)
	if err != nil {
		t.Fatalf("NewRotatingFile failed: %v", err)
	}
	defer rf.Close()

	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		t.Error("RotatingFile should create directory if it doesn't exist")
	}
}

func TestRotatingFileCreatesTodayFile(t *testing.T) {
	tmpDir := t.TempDir()
	rf, err := NewRotatingFile(tmpDir, "app", 30, 10)
	if err != nil {
		t.Fatalf("NewRotatingFile failed: %v", err)
	}
	defer rf.Close()

	today := time.Now().UTC().Format("2006-01-02")
	expected := filepath.Join(tmpDir, fmt.Sprintf("app-%s.log", today))

	if _, err := os.Stat(expected); os.IsNotExist(err) {
		t.Errorf("expected log file %s to exist", expected)
	}
}

func TestRotatingFileWrite(t *testing.T) {
	tmpDir := t.TempDir()
	rf, err := NewRotatingFile(tmpDir, "app", 30, 10)
	if err != nil {
		t.Fatalf("NewRotatingFile failed: %v", err)
	}
	defer rf.Close()

	n, err := rf.Write([]byte("hello world\n"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != 12 {
		t.Errorf("Write returned %d, want 12", n)
	}

	// Read the file and verify content
	today := time.Now().UTC().Format("2006-01-02")
	data, err := os.ReadFile(filepath.Join(tmpDir, fmt.Sprintf("app-%s.log", today)))
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !strings.Contains(string(data), "hello world") {
		t.Errorf("file content = %q, want to contain 'hello world'", string(data))
	}
}

func TestRotatingFileAppend(t *testing.T) {
	tmpDir := t.TempDir()
	rf, err := NewRotatingFile(tmpDir, "app", 30, 10)
	if err != nil {
		t.Fatalf("NewRotatingFile failed: %v", err)
	}
	defer rf.Close()

	rf.Write([]byte("line1\n"))
	rf.Write([]byte("line2\n"))

	today := time.Now().UTC().Format("2006-01-02")
	data, err := os.ReadFile(filepath.Join(tmpDir, fmt.Sprintf("app-%s.log", today)))
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "line1") {
		t.Error("file should contain line1")
	}
	if !strings.Contains(content, "line2") {
		t.Error("file should contain line2")
	}
}

func TestRotatingFileDayChangeRotation(t *testing.T) {
	tmpDir := t.TempDir()
	rf, err := NewRotatingFile(tmpDir, "app", 30, 10)
	if err != nil {
		t.Fatalf("NewRotatingFile failed: %v", err)
	}
	defer rf.Close()

	// Write to today's file
	rf.Write([]byte("today\n"))

	// Simulate day change by manually updating the currentDay
	rf.mu.Lock()
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	rf.currentDay = yesterday
	rf.mu.Unlock()

	// This write should trigger rotation to today
	rf.Write([]byte("new day\n"))

	// Today's file should have "new day"
	today := time.Now().UTC().Format("2006-01-02")
	todayFile := filepath.Join(tmpDir, fmt.Sprintf("app-%s.log", today))
	data, err := os.ReadFile(todayFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !strings.Contains(string(data), "new day") {
		t.Errorf("today's file should contain 'new day', got: %s", string(data))
	}
}

func TestRotatingFileCleanupOldFiles(t *testing.T) {
	tmpDir := t.TempDir()
	rf, err := NewRotatingFile(tmpDir, "app", 2, 10) // maxAgeDays = 2
	if err != nil {
		t.Fatalf("NewRotatingFile failed: %v", err)
	}
	defer rf.Close()

	// Create old files manually with old mod times
	oldDate := time.Now().UTC().AddDate(0, 0, -5)
	oldFile := filepath.Join(tmpDir, fmt.Sprintf("app-%s.log", oldDate.Format("2006-01-02")))
	if err := os.WriteFile(oldFile, []byte("old data"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	// Set the mod time to 5 days ago so age-based cleanup removes it
	os.Chtimes(oldFile, oldDate, oldDate)

	// Also create a recent file (1 day ago)
	recentDate := time.Now().UTC().AddDate(0, 0, -1)
	recentFile := filepath.Join(tmpDir, fmt.Sprintf("app-%s.log", recentDate.Format("2006-01-02")))
	if err := os.WriteFile(recentFile, []byte("recent data"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	os.Chtimes(recentFile, recentDate, recentDate)

	// Simulate day change to trigger cleanup
	rf.mu.Lock()
	rf.currentDay = "1999-01-01" // Force rotation on next write
	rf.mu.Unlock()

	rf.Write([]byte("trigger cleanup\n"))

	// Old file should be removed
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Error("old file should have been removed")
	}

	// Recent file should still exist
	if _, err := os.Stat(recentFile); os.IsNotExist(err) {
		t.Error("recent file should still exist")
	}
}

func TestRotatingFileMaxBackups(t *testing.T) {
	tmpDir := t.TempDir()
	rf, err := NewRotatingFile(tmpDir, "app", 365, 3) // maxBackups = 3
	if err != nil {
		t.Fatalf("NewRotatingFile failed: %v", err)
	}
	defer rf.Close()

	// Create 4 old files (all recent so age-based cleanup won't remove them)
	for i := 1; i <= 4; i++ {
		date := time.Now().UTC().AddDate(0, 0, -i)
		file := filepath.Join(tmpDir, fmt.Sprintf("app-%s.log", date.Format("2006-01-02")))
		if err := os.WriteFile(file, []byte(fmt.Sprintf("data %d", i)), 0o644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
	}

	// Simulate day change to trigger cleanup
	rf.mu.Lock()
	rf.currentDay = "1999-01-01"
	rf.mu.Unlock()

	rf.Write([]byte("trigger cleanup\n"))

	// Count remaining backup files
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	count := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "app-") && strings.HasSuffix(e.Name(), ".log") {
			count++
		}
	}

	// Should have at most maxBackups (3) files
	if count > 3 {
		t.Errorf("expected at most 3 backup files, got %d", count)
	}
}

func TestRotatingFileClose(t *testing.T) {
	tmpDir := t.TempDir()
	rf, err := NewRotatingFile(tmpDir, "app", 30, 10)
	if err != nil {
		t.Fatalf("NewRotatingFile failed: %v", err)
	}

	rf.Write([]byte("before close\n"))
	if err := rf.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Double close should not panic
	if err := rf.Close(); err != nil {
		t.Errorf("double Close should not error: %v", err)
	}
	if _, err := rf.Write([]byte("after close\n")); err == nil {
		t.Fatal("write after close succeeded")
	}
}

func TestRotatingFileConcurrentAppendAcrossReopen(t *testing.T) {
	tmpDir := t.TempDir()
	writeBatch := func(prefix string) {
		rf, err := NewRotatingFile(tmpDir, "app", 30, 10)
		if err != nil {
			t.Fatal(err)
		}
		var group sync.WaitGroup
		for worker := 0; worker < 8; worker++ {
			group.Add(1)
			go func(worker int) {
				defer group.Done()
				for index := 0; index < 50; index++ {
					if _, err := fmt.Fprintf(rf, "%s-%d-%d\n", prefix, worker, index); err != nil {
						t.Errorf("write: %v", err)
						return
					}
				}
			}(worker)
		}
		group.Wait()
		if err := rf.Close(); err != nil {
			t.Fatal(err)
		}
	}
	writeBatch("first")
	writeBatch("second")
	today := time.Now().UTC().Format("2006-01-02")
	data, err := os.ReadFile(filepath.Join(tmpDir, "app-"+today+".log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 800 {
		t.Fatalf("appended lines = %d, want 800", len(lines))
	}
}

func TestRotatingFileIgnoresNonMatchingFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a non-matching file
	if err := os.WriteFile(filepath.Join(tmpDir, "other.log"), []byte("other"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "app-nodate.txt"), []byte("no date"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	rf, err := NewRotatingFile(tmpDir, "app", 30, 10)
	if err != nil {
		t.Fatalf("NewRotatingFile failed: %v", err)
	}
	defer rf.Close()

	// Trigger cleanup
	rf.mu.Lock()
	rf.currentDay = "1999-01-01"
	rf.mu.Unlock()
	rf.Write([]byte("trigger\n"))

	// Non-matching files should still exist
	if _, err := os.Stat(filepath.Join(tmpDir, "other.log")); os.IsNotExist(err) {
		t.Error("other.log should not be affected by cleanup")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "app-nodate.txt")); os.IsNotExist(err) {
		t.Error("app-nodate.txt should not be affected by cleanup")
	}
}
