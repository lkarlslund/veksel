// Package objectstore stores immutable account payloads in checksummed segment files.
package objectstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/lkarlslund/veksel/pkg/dek"
)

const (
	formatVersion      = uint16(1)
	prefixSize         = 64
	defaultSegmentSize = int64(64 << 20)
	segmentExtension   = ".seg"
	segmentDigits      = 16
	maxHeaderSize      = 1 << 20
)

var (
	magic              = [8]byte{'S', 'H', 'U', 'P', 'S', 'O', 'B', 'J'}
	crcTable           = crc32.MakeTable(crc32.Castagnoli)
	ErrCorrupt         = errors.New("object segment is corrupt")
	ErrReference       = errors.New("object reference does not match record")
	ErrPayloadTooLarge = errors.New("object payload is too large")
	ErrKeyRequired     = errors.New("object is encrypted and no key is available")
	errIncompleteTail  = errors.New("object segment has an incomplete tail")
)

// Header is backend-independent identity carried alongside an immutable payload.
type Header struct {
	ItemID      string `json:"item_id"`
	FolderID    string `json:"folder_id"`
	ContentType string `json:"content_type"`
}

// Ref locates and authenticates one object record. PayloadLength and Digest
// always describe the logical payload. An encrypted record additionally
// records the length and digest of the ciphertext stored in the segment.
type Ref struct {
	Segment       uint64 `json:"segment"`
	Offset        int64  `json:"offset"`
	RecordLength  int64  `json:"record_length"`
	PayloadLength int64  `json:"payload_length"`
	Digest        string `json:"sha256"`
	StoredLength  int64  `json:"stored_length,omitempty"`
	StoredDigest  string `json:"stored_sha256,omitempty"`
}

// Record describes a segment record without loading its payload.
type Record struct {
	Header Header `json:"header"`
	Ref    Ref    `json:"ref"`
}

// Options controls physical segment behavior.
type Options struct {
	MaxSegmentSize int64
	SyncWrites     bool
	// Key, when set, encrypts every payload written and is required to read
	// encrypted records. A store is either wholly encrypted or plaintext.
	Key *dek.Key
}

// Store owns one directory of immutable object segments.
type Store struct {
	dir     string
	options Options

	mu       sync.Mutex
	activeID uint64
	active   *os.File
	closed   bool
}

// Open validates the active (last) segment, recovers its incomplete tail, and
// opens it for appends. Sealed segments are synced before rotation and never
// written again, so they are not rescanned: that work grows with the account
// and would make opening a large account slow. Their records are still
// checked on every Read and Verify, and Scan validates all segments.
func Open(dir string, options Options) (*Store, error) {
	if options.MaxSegmentSize <= 0 {
		options.MaxSegmentSize = defaultSegmentSize
	}
	if options.MaxSegmentSize < prefixSize+1 {
		return nil, fmt.Errorf("object segment size %d is too small", options.MaxSegmentSize)
	}
	_, statErr := os.Stat(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create object segment directory: %w", err)
	}
	if errors.Is(statErr, os.ErrNotExist) {
		if err := syncDirectory(filepath.Dir(dir)); err != nil {
			return nil, fmt.Errorf("sync object segment parent directory: %w", err)
		}
	}
	ids, err := segmentIDs(dir)
	if err != nil {
		return nil, err
	}
	created := len(ids) == 0
	if created {
		ids = []uint64{1}
	}
	last := ids[len(ids)-1]
	if _, err := scanFile(context.Background(), segmentPath(dir, last), last, true); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(segmentPath(dir, last), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open active object segment: %w", err)
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		file.Close()
		return nil, fmt.Errorf("seek active object segment: %w", err)
	}
	if created {
		if err := syncDirectory(dir); err != nil {
			file.Close()
			return nil, fmt.Errorf("sync object segment directory: %w", err)
		}
	}
	return &Store{dir: dir, options: options, activeID: last, active: file}, nil
}

// Put appends exactly payloadLength bytes from payload and returns a durable
// reference. Payload bytes are never interpreted or rewritten.
func (s *Store) Put(ctx context.Context, header Header, payloadLength int64, payload io.Reader) (Ref, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateHeader(header); err != nil {
		return Ref{}, err
	}
	if payloadLength < 0 {
		return Ref{}, fmt.Errorf("%w: negative length", ErrPayloadTooLarge)
	}
	storedLength := payloadLength
	if s.options.Key != nil {
		// Item and folder identity and content type stay inside the
		// encrypted index; the segment only carries an opaque header.
		header, storedLength = sealedHeader, dek.SealedStreamSize(payloadLength)
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return Ref{}, fmt.Errorf("marshal object header: %w", err)
	}
	if len(headerBytes) > maxHeaderSize {
		return Ref{}, fmt.Errorf("object header is too large: %d", len(headerBytes))
	}
	recordLength := int64(prefixSize+len(headerBytes)) + storedLength
	if recordLength < 0 {
		return Ref{}, ErrPayloadTooLarge
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Ref{}, os.ErrClosed
	}
	if err := s.rotateIfNeeded(recordLength); err != nil {
		return Ref{}, err
	}
	offset, err := s.active.Seek(0, io.SeekEnd)
	if err != nil {
		return Ref{}, fmt.Errorf("seek object segment: %w", err)
	}
	rollback := func(cause error) (Ref, error) {
		if truncateErr := s.active.Truncate(offset); truncateErr != nil {
			return Ref{}, errors.Join(cause, fmt.Errorf("truncate failed object append: %w", truncateErr))
		}
		_, _ = s.active.Seek(0, io.SeekEnd)
		return Ref{}, cause
	}
	if _, err := s.active.Write(make([]byte, prefixSize)); err != nil {
		return rollback(fmt.Errorf("write provisional object prefix: %w", err))
	}
	if _, err := s.active.Write(headerBytes); err != nil {
		return rollback(fmt.Errorf("write object header: %w", err))
	}
	hasher, plainHasher := sha256.New(), sha256.New()
	stored := &countingWriter{next: io.MultiWriter(s.active, hasher)}
	var sink io.Writer = stored
	var sealer io.WriteCloser
	if s.options.Key != nil {
		sealer = s.options.Key.NewSealingWriter(stored, objectAAD(s.activeID, offset))
		sink = io.MultiWriter(sealer, plainHasher)
	}
	written, err := copyExactly(ctx, sink, payload, payloadLength)
	if err != nil {
		return rollback(fmt.Errorf("write object payload after %d bytes: %w", written, err))
	}
	if sealer != nil {
		if err := sealer.Close(); err != nil {
			return rollback(fmt.Errorf("seal object payload: %w", err))
		}
	}
	if stored.count != storedLength {
		return rollback(fmt.Errorf("%w: stored %d payload bytes, expected %d", ErrCorrupt, stored.count, storedLength))
	}
	digest := hasher.Sum(nil)
	prefix := encodePrefix(uint32(len(headerBytes)), uint64(storedLength), digest, headerBytes)
	if _, err := s.active.WriteAt(prefix, offset); err != nil {
		return rollback(fmt.Errorf("finalize object prefix: %w", err))
	}
	if s.options.SyncWrites {
		if err := s.active.Sync(); err != nil {
			return rollback(fmt.Errorf("sync object segment: %w", err))
		}
	}
	if _, err := s.active.Seek(0, io.SeekEnd); err != nil {
		return Ref{}, fmt.Errorf("restore object segment position: %w", err)
	}
	ref := Ref{
		Segment:       s.activeID,
		Offset:        offset,
		RecordLength:  recordLength,
		PayloadLength: payloadLength,
		Digest:        hex.EncodeToString(digest),
	}
	if sealer != nil {
		ref.StoredLength, ref.StoredDigest = storedLength, ref.Digest
		ref.Digest = hex.EncodeToString(plainHasher.Sum(nil))
	}
	return ref, nil
}

// sealedHeader replaces the identity header of encrypted records.
var sealedHeader = Header{ItemID: "sealed", FolderID: "sealed", ContentType: "application/x-veksel-sealed"}

// objectAAD binds an encrypted payload to its physical record so a payload
// copied to another record fails authentication.
func objectAAD(segment uint64, offset int64) []byte {
	aad := make([]byte, 0, 32)
	aad = append(aad, "veksel-object-v1\x00"...)
	aad = binary.BigEndian.AppendUint64(aad, segment)
	return binary.BigEndian.AppendUint64(aad, uint64(offset))
}

type countingWriter struct {
	next  io.Writer
	count int64
}

func (w *countingWriter) Write(data []byte) (int, error) {
	n, err := w.next.Write(data)
	w.count += int64(n)
	return n, err
}

// physical returns the record identity as the segment prefix records it.
func (r Ref) physical() Ref {
	if r.StoredDigest == "" {
		return r
	}
	return Ref{Segment: r.Segment, Offset: r.Offset, RecordLength: r.RecordLength, PayloadLength: r.StoredLength, Digest: r.StoredDigest}
}

// Read streams a referenced payload to destination and verifies its digest.
func (s *Store) Read(ctx context.Context, ref Ref, destination io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	file, err := os.Open(segmentPath(s.dir, ref.Segment))
	if err != nil {
		return fmt.Errorf("open object segment %d: %w", ref.Segment, err)
	}
	defer file.Close()
	record, headerLength, digest, err := readRecordHeader(file, ref.Segment, ref.Offset)
	if err != nil {
		return err
	}
	sealed := ref.StoredDigest != ""
	switch {
	case sealed && s.options.Key == nil:
		return ErrKeyRequired
	case !sealed && s.options.Key != nil:
		// An encrypted store never writes plaintext records.
		return ErrReference
	}
	physical := ref.physical()
	if !sameRef(record.Ref, physical) {
		return ErrReference
	}
	payloadOffset := ref.Offset + prefixSize + int64(headerLength)
	section := io.NewSectionReader(file, payloadOffset, physical.PayloadLength)
	hasher := sha256.New()
	if !sealed {
		written, err := copyExactly(ctx, io.MultiWriter(destination, hasher), section, ref.PayloadLength)
		if err != nil {
			return fmt.Errorf("read object payload after %d bytes: %w", written, err)
		}
		if !bytes.Equal(hasher.Sum(nil), digest) {
			return fmt.Errorf("%w: payload digest at segment %d offset %d", ErrCorrupt, ref.Segment, ref.Offset)
		}
		return nil
	}
	opener := s.options.Key.NewOpeningReader(io.TeeReader(section, hasher), objectAAD(ref.Segment, ref.Offset))
	plainHasher := sha256.New()
	written, err := copyExactly(ctx, io.MultiWriter(destination, plainHasher), opener, ref.PayloadLength)
	if err != nil {
		return fmt.Errorf("read encrypted object payload after %d bytes: %w", written, err)
	}
	if extra, err := opener.Read(make([]byte, 1)); extra != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: encrypted payload length at segment %d offset %d: %v", ErrCorrupt, ref.Segment, ref.Offset, err)
	}
	if !bytes.Equal(hasher.Sum(nil), digest) || hex.EncodeToString(plainHasher.Sum(nil)) != ref.Digest {
		return fmt.Errorf("%w: payload digest at segment %d offset %d", ErrCorrupt, ref.Segment, ref.Offset)
	}
	return nil
}

// Verify validates one reference and payload without retaining its bytes.
func (s *Store) Verify(ctx context.Context, ref Ref) error {
	return s.Read(ctx, ref, io.Discard)
}

// Scan lists all complete records in segment order.
func (s *Store) Scan(ctx context.Context) ([]Record, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ids, err := segmentIDs(s.dir)
	if err != nil {
		return nil, err
	}
	var result []Record
	for _, id := range ids {
		records, err := scanFile(ctx, segmentPath(s.dir, id), id, false)
		if err != nil {
			return nil, err
		}
		result = append(result, records...)
	}
	return result, nil
}

// Sync flushes the active segment.
func (s *Store) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return os.ErrClosed
	}
	return s.active.Sync()
}

// Close flushes and closes the active segment.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(s.active.Sync(), s.active.Close())
}

func (s *Store) rotateIfNeeded(recordLength int64) error {
	info, err := s.active.Stat()
	if err != nil {
		return fmt.Errorf("stat active object segment: %w", err)
	}
	if info.Size() == 0 || info.Size()+recordLength <= s.options.MaxSegmentSize {
		return nil
	}
	if err := s.active.Sync(); err != nil {
		return fmt.Errorf("sync sealed object segment: %w", err)
	}
	// Create the next segment before releasing the current one, so a failed
	// create leaves the store appending to the segment it already had.
	nextID := s.activeID + 1
	path := segmentPath(s.dir, nextID)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create object segment %d: %w", nextID, err)
	}
	// Records synced into the new segment are durable only once its
	// directory entry is.
	if err := syncDirectory(s.dir); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync object segment directory: %w", err)
	}
	sealed := s.active
	s.active, s.activeID = file, nextID
	if err := sealed.Close(); err != nil {
		return fmt.Errorf("close sealed object segment: %w", err)
	}
	return nil
}

// syncDirectory makes the directory's entries durable. A variable so tests
// can observe and fail it.
var syncDirectory = func(path string) error {
	if runtime.GOOS == "windows" {
		// Windows cannot sync a directory handle; its entries are durable
		// with the file's own metadata.
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	err = directory.Sync()
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		// The platform or file system does not support syncing directories.
		err = nil
	}
	return errors.Join(err, directory.Close())
}

func scanFile(ctx context.Context, path string, segmentID uint64, recoverTail bool) ([]Record, error) {
	flags := os.O_RDONLY
	if recoverTail {
		flags = os.O_RDWR
	}
	file, err := os.OpenFile(path, flags, 0)
	if errors.Is(err, os.ErrNotExist) && recoverTail {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open object segment %d: %w", segmentID, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat object segment %d: %w", segmentID, err)
	}

	var records []Record
	for offset := int64(0); offset < info.Size(); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		record, _, _, err := readRecordHeader(file, segmentID, offset)
		if err != nil {
			if recoverTail && tailRecoverable(err) {
				if truncateErr := file.Truncate(offset); truncateErr != nil {
					return nil, errors.Join(err, fmt.Errorf("truncate incomplete object tail: %w", truncateErr))
				}
				if syncErr := file.Sync(); syncErr != nil {
					return nil, fmt.Errorf("sync recovered object segment: %w", syncErr)
				}
				break
			}
			return nil, err
		}
		if offset+record.Ref.RecordLength > info.Size() {
			if recoverTail {
				if err := file.Truncate(offset); err != nil {
					return nil, fmt.Errorf("truncate incomplete object payload: %w", err)
				}
				if err := file.Sync(); err != nil {
					return nil, fmt.Errorf("sync recovered object segment: %w", err)
				}
				break
			}
			return nil, fmt.Errorf("%w: truncated record at segment %d offset %d", ErrCorrupt, segmentID, offset)
		}
		records = append(records, record)
		offset += record.Ref.RecordLength
	}
	return records, nil
}

func readRecordHeader(reader io.ReaderAt, segmentID uint64, offset int64) (Record, uint32, []byte, error) {
	prefix := make([]byte, prefixSize)
	if _, err := reader.ReadAt(prefix, offset); err != nil {
		return Record{}, 0, nil, fmt.Errorf("%w: read prefix at segment %d offset %d: %v", errIncompleteTail, segmentID, offset, err)
	}
	if !bytes.Equal(prefix[:8], magic[:]) {
		if bytes.Equal(prefix, make([]byte, prefixSize)) {
			return Record{}, 0, nil, fmt.Errorf("%w: provisional prefix at segment %d offset %d", errIncompleteTail, segmentID, offset)
		}
		return Record{}, 0, nil, fmt.Errorf("%w: invalid magic at segment %d offset %d", ErrCorrupt, segmentID, offset)
	}
	if version := binary.BigEndian.Uint16(prefix[8:10]); version != formatVersion {
		return Record{}, 0, nil, fmt.Errorf("%w: unsupported version %d", ErrCorrupt, version)
	}
	headerLength := binary.BigEndian.Uint32(prefix[12:16])
	if headerLength == 0 || headerLength > maxHeaderSize {
		return Record{}, 0, nil, fmt.Errorf("%w: invalid header length %d", ErrCorrupt, headerLength)
	}
	payloadLength := binary.BigEndian.Uint64(prefix[16:24])
	if payloadLength > uint64(^uint64(0)>>1) {
		return Record{}, 0, nil, ErrPayloadTooLarge
	}
	headerBytes := make([]byte, headerLength)
	if _, err := reader.ReadAt(headerBytes, offset+prefixSize); err != nil {
		return Record{}, 0, nil, fmt.Errorf("%w: read header at segment %d offset %d: %v", errIncompleteTail, segmentID, offset, err)
	}
	if got, want := crc32.Checksum(headerBytes, crcTable), binary.BigEndian.Uint32(prefix[56:60]); got != want {
		return Record{}, 0, nil, fmt.Errorf("%w: header checksum at segment %d offset %d", ErrCorrupt, segmentID, offset)
	}
	if got, want := crc32.Checksum(prefix[:60], crcTable), binary.BigEndian.Uint32(prefix[60:64]); got != want {
		return Record{}, 0, nil, fmt.Errorf("%w: prefix checksum at segment %d offset %d", ErrCorrupt, segmentID, offset)
	}
	var header Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Record{}, 0, nil, fmt.Errorf("%w: decode header at segment %d offset %d: %v", ErrCorrupt, segmentID, offset, err)
	}
	if err := validateHeader(header); err != nil {
		return Record{}, 0, nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	recordLength := int64(prefixSize) + int64(headerLength) + int64(payloadLength)
	digest := bytes.Clone(prefix[24:56])
	return Record{
		Header: header,
		Ref: Ref{
			Segment:       segmentID,
			Offset:        offset,
			RecordLength:  recordLength,
			PayloadLength: int64(payloadLength),
			Digest:        hex.EncodeToString(digest),
		},
	}, headerLength, digest, nil
}

func encodePrefix(headerLength uint32, payloadLength uint64, digest, header []byte) []byte {
	prefix := make([]byte, prefixSize)
	copy(prefix[:8], magic[:])
	binary.BigEndian.PutUint16(prefix[8:10], formatVersion)
	binary.BigEndian.PutUint32(prefix[12:16], headerLength)
	binary.BigEndian.PutUint64(prefix[16:24], payloadLength)
	copy(prefix[24:56], digest)
	binary.BigEndian.PutUint32(prefix[56:60], crc32.Checksum(header, crcTable))
	binary.BigEndian.PutUint32(prefix[60:64], crc32.Checksum(prefix[:60], crcTable))
	return prefix
}

func sameRef(actual, expected Ref) bool {
	return actual.Segment == expected.Segment &&
		actual.Offset == expected.Offset &&
		actual.RecordLength == expected.RecordLength &&
		actual.PayloadLength == expected.PayloadLength &&
		actual.Digest == expected.Digest
}

func validateHeader(header Header) error {
	if strings.TrimSpace(header.ItemID) == "" {
		return errors.New("object item ID is required")
	}
	if strings.TrimSpace(header.FolderID) == "" {
		return errors.New("object folder ID is required")
	}
	if strings.TrimSpace(header.ContentType) == "" {
		return errors.New("object content type is required")
	}
	return nil
}

func copyExactly(ctx context.Context, destination io.Writer, source io.Reader, length int64) (int64, error) {
	// Most payloads (contacts, events, small messages) are a few KiB; a
	// fixed 128 KiB buffer per read dominated allocation on list requests.
	buffer := make([]byte, max(min(length, 128<<10), 1))
	limited := io.LimitReader(source, length)
	var written int64
	for written < length {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		count, err := limited.Read(buffer)
		if count > 0 {
			output, writeErr := destination.Write(buffer[:count])
			written += int64(output)
			if writeErr != nil {
				return written, writeErr
			}
			if output != count {
				return written, io.ErrShortWrite
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return written, err
		}
	}
	if written != length {
		return written, io.ErrUnexpectedEOF
	}
	return written, nil
}

func segmentIDs(dir string) ([]uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read object segment directory: %w", err)
	}
	ids := make([]uint64, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), segmentExtension) {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), segmentExtension)
		if len(base) != segmentDigits {
			return nil, fmt.Errorf("unexpected object segment name %q", entry.Name())
		}
		id, err := strconv.ParseUint(base, 10, 64)
		if err != nil || id == 0 {
			return nil, fmt.Errorf("invalid object segment name %q", entry.Name())
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for i := 1; i < len(ids); i++ {
		if ids[i] != ids[i-1]+1 {
			return nil, fmt.Errorf("object segment sequence has a gap between %d and %d", ids[i-1], ids[i])
		}
	}
	return ids, nil
}

func segmentPath(dir string, id uint64) string {
	return filepath.Join(dir, fmt.Sprintf("%0*d%s", segmentDigits, id, segmentExtension))
}

func tailRecoverable(err error) bool {
	return errors.Is(err, errIncompleteTail)
}
