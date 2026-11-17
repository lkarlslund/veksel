package objectstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func testHeader(id string) Header {
	return Header{ItemID: id, FolderID: "fld_inbox", ContentType: "message/rfc822"}
}

func TestPutReadScanAndRotate(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{MaxSegmentSize: 180, SyncWrites: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	payloads := [][]byte{[]byte("first payload"), []byte("second payload"), []byte("third payload")}
	refs := make([]Ref, 0, len(payloads))
	for i, payload := range payloads {
		ref, err := s.Put(t.Context(), testHeader("item_"+string(rune('a'+i))), int64(len(payload)), bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
		refs = append(refs, ref)
	}
	if refs[0].Segment == refs[len(refs)-1].Segment {
		t.Fatalf("expected rotation, all refs use segment %d", refs[0].Segment)
	}
	for i, ref := range refs {
		var got bytes.Buffer
		if err := s.Read(t.Context(), ref, &got); err != nil {
			t.Fatalf("Read %d: %v", i, err)
		}
		if !bytes.Equal(got.Bytes(), payloads[i]) {
			t.Fatalf("Read %d: got %q, want %q", i, got.Bytes(), payloads[i])
		}
	}
	records, err := s.Scan(t.Context())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(records) != len(payloads) {
		t.Fatalf("Scan record count: got %d, want %d", len(records), len(payloads))
	}
}

func TestShortPayloadRollsBackAppend(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{SyncWrites: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.Put(t.Context(), testHeader("short"), 100, bytes.NewReader([]byte("too short"))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Put short payload: got %v, want ErrUnexpectedEOF", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s, err = Open(dir, Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	records, err := s.Scan(t.Context())
	if err != nil || len(records) != 0 {
		t.Fatalf("Scan after rollback: got %d records, %v", len(records), err)
	}
}

func TestOpenTruncatesOnlyIncompleteActiveTail(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{SyncWrites: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	payload := []byte("complete")
	if _, err := s.Put(t.Context(), testHeader("complete"), int64(len(payload)), bytes.NewReader(payload)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	path := segmentPath(dir, 1)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := file.Write(make([]byte, prefixSize)); err != nil {
		t.Fatalf("append provisional prefix: %v", err)
	}
	file.Close()

	s, err = Open(dir, Options{})
	if err != nil {
		t.Fatalf("Open with incomplete tail: %v", err)
	}
	defer s.Close()
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat recovered: %v", err)
	}
	if after.Size() != before.Size() {
		t.Fatalf("recovered size: got %d, want %d", after.Size(), before.Size())
	}
}

func TestOpenRejectsCorruptCommittedHeader(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{SyncWrites: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	payload := []byte("payload")
	ref, err := s.Put(t.Context(), testHeader("corrupt"), int64(len(payload)), bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	file, err := os.OpenFile(segmentPath(dir, ref.Segment), os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := file.WriteAt([]byte{0xff}, ref.Offset+prefixSize); err != nil {
		t.Fatalf("corrupt header: %v", err)
	}
	file.Close()

	if _, err := Open(dir, Options{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open corrupt segment: got %v, want ErrCorrupt", err)
	}
}

// TestOpenSkipsSealedSegments keeps Open independent of account size: only
// the active segment is scanned, while damage in a sealed segment is still
// reported by Read and Scan.
func TestOpenSkipsSealedSegments(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{MaxSegmentSize: 180, SyncWrites: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var refs []Ref
	for i := range 3 {
		payload := []byte("sealed payload")
		ref, err := s.Put(t.Context(), testHeader("item_"+string(rune('a'+i))), int64(len(payload)), bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
		refs = append(refs, ref)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	sealed, active := refs[0], refs[len(refs)-1]
	if sealed.Segment == active.Segment {
		t.Fatalf("expected rotation, all refs use segment %d", sealed.Segment)
	}
	file, err := os.OpenFile(segmentPath(dir, sealed.Segment), os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := file.WriteAt([]byte{0xff}, sealed.Offset+prefixSize); err != nil {
		t.Fatalf("corrupt sealed header: %v", err)
	}
	file.Close()

	s, err = Open(dir, Options{MaxSegmentSize: 180, SyncWrites: true})
	if err != nil {
		t.Fatalf("Open with damaged sealed segment: %v", err)
	}
	defer s.Close()
	if err := s.Verify(t.Context(), active); err != nil {
		t.Fatalf("Verify active record: %v", err)
	}
	if err := s.Verify(t.Context(), sealed); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Verify damaged sealed record: got %v, want ErrCorrupt", err)
	}
	if _, err := s.Scan(t.Context()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Scan damaged sealed segment: got %v, want ErrCorrupt", err)
	}
	payload := []byte("appended")
	if _, err := s.Put(t.Context(), testHeader("appended"), int64(len(payload)), bytes.NewReader(payload)); err != nil {
		t.Fatalf("Put after reopen: %v", err)
	}
}

func TestReadDetectsPayloadCorruption(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{SyncWrites: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	payload := []byte("payload")
	ref, err := s.Put(t.Context(), testHeader("corrupt-payload"), int64(len(payload)), bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	file, err := os.OpenFile(segmentPath(dir, ref.Segment), os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	record, headerLength, _, err := readRecordHeader(file, ref.Segment, ref.Offset)
	if err != nil {
		t.Fatalf("readRecordHeader: %v", err)
	}
	if _, err := file.WriteAt([]byte{'X'}, record.Ref.Offset+prefixSize+int64(headerLength)); err != nil {
		t.Fatalf("corrupt payload: %v", err)
	}
	file.Close()

	s, err = Open(dir, Options{})
	if err != nil {
		t.Fatalf("Open after payload corruption: %v", err)
	}
	defer s.Close()
	if err := s.Verify(t.Context(), ref); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Verify: got %v, want ErrCorrupt", err)
	}
}

func TestPutCanceledContextDoesNotCreateRecord(t *testing.T) {
	s, err := Open(t.TempDir(), Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Put(ctx, testHeader("canceled"), 10, bytes.NewReader(make([]byte, 10))); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put canceled: got %v", err)
	}
	records, err := s.Scan(t.Context())
	if err != nil || len(records) != 0 {
		t.Fatalf("Scan: got %d records, %v", len(records), err)
	}
}

func FuzzDecodeRecordHeader(f *testing.F) {
	f.Add([]byte("not a record"))
	validHeader, _ := json.Marshal(testHeader("fuzz"))
	f.Add(append(encodePrefix(uint32(len(validHeader)), 0, make([]byte, sha256.Size), validHeader), validHeader...))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = readRecordHeader(bytes.NewReader(data), 1, 0)
	})
}

func TestFailedRotationKeepsStoreUsable(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{MaxSegmentSize: 180, SyncWrites: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	payload := []byte("first payload")
	first, err := s.Put(t.Context(), testHeader("item_a"), int64(len(payload)), bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put first: %v", err)
	}
	// Occupy the next segment's path so the rotation cannot create it.
	blocker := segmentPath(dir, first.Segment+1)
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(t.Context(), testHeader("item_b"), int64(len(payload)), bytes.NewReader(payload)); err == nil {
		t.Fatal("Put during blocked rotation succeeded")
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	ref, err := s.Put(t.Context(), testHeader("item_c"), int64(len(payload)), bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put after failed rotation: %v", err)
	}
	var got bytes.Buffer
	if err := s.Read(t.Context(), ref, &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("Read after failed rotation = %q, %v", got.Bytes(), err)
	}
	got.Reset()
	if err := s.Read(t.Context(), first, &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("Read first = %q, %v", got.Bytes(), err)
	}
}

// TestNewSegmentsSyncTheirDirectory covers the directory entries of a
// newly created store and of a rotated segment: both directories are
// synced, and a failed directory sync leaves the store usable.
func TestNewSegmentsSyncTheirDirectory(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "objects")
	var synced []string
	failing := false
	original := syncDirectory
	syncDirectory = func(path string) error {
		synced = append(synced, path)
		if failing {
			return errors.New("sync failed")
		}
		return original(path)
	}
	t.Cleanup(func() { syncDirectory = original })
	s, err := Open(dir, Options{MaxSegmentSize: 180, SyncWrites: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if !slices.Equal(synced, []string{parent, dir}) {
		t.Fatalf("Open synced %v, want parent and store directory", synced)
	}
	payload := []byte("first payload")
	first, err := s.Put(t.Context(), testHeader("item_a"), int64(len(payload)), bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put first: %v", err)
	}
	failing = true
	if _, err := s.Put(t.Context(), testHeader("item_b"), int64(len(payload)), bytes.NewReader(payload)); err == nil {
		t.Fatal("Put with failing directory sync succeeded")
	}
	if _, err := os.Stat(segmentPath(dir, first.Segment+1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsynced segment left behind: %v", err)
	}
	failing, synced = false, nil
	rotated, err := s.Put(t.Context(), testHeader("item_c"), int64(len(payload)), bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put after failed directory sync: %v", err)
	}
	if rotated.Segment != first.Segment+1 || !slices.Equal(synced, []string{dir}) {
		t.Fatalf("rotation to segment %d synced %v", rotated.Segment, synced)
	}
}
