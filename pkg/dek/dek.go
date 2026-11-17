// Package dek implements the cryptography of one data-encryption key (DEK).
//
// A DEK is 32 random bytes. Independent subkeys are derived from it with
// HKDF-SHA256 for each use, so the same DEK safely encrypts store values,
// store key names, and object payload streams:
//
//   - Values: XChaCha20-Poly1305 with a random 192-bit nonce per value. The
//     caller binds the record identity (namespace and key) as associated data,
//     so a ciphertext moved to another record fails authentication.
//   - Names: deterministic authenticated encryption (SIV with HMAC-SHA256 and
//     AES-256-CTR). Equal names encrypt equally, which keeps point lookups
//     possible, while the name itself stays confidential.
//   - Streams: chunked XChaCha20-Poly1305 (64 KiB chunks, STREAM construction)
//     with a per-stream random salt, a chunk counter, and a final-chunk flag so
//     truncation, reordering, and extension are all detected.
package dek

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Size is the length of a raw DEK.
	Size = 32

	valueVersion  = byte(1)
	streamVersion = byte(1)
	nameTagSize   = 16
	saltSize      = 16
	// StreamChunkSize is the plaintext size of each full stream chunk.
	StreamChunkSize = 64 << 10
	streamHeader    = 1 + saltSize
	finalFlag       = uint64(1) << 63
)

var (
	// ErrAuthentication reports ciphertext that is corrupt, truncated, bound
	// to different associated data, or sealed under a different key.
	ErrAuthentication = errors.New("encrypted data failed authentication")
	errFormat         = errors.New("unsupported encrypted data format")
)

// Key is a loaded DEK with its derived subkeys. It is safe for concurrent use.
type Key struct {
	value   cipher.AEAD
	stream  cipher.AEAD
	macs    sync.Pool // HMAC-SHA256 instances keyed for name tags
	nameEnc cipher.Block
}

// Generate returns a fresh random DEK.
func Generate() ([]byte, error) {
	raw := make([]byte, Size)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate data-encryption key: %w", err)
	}
	return raw, nil
}

// New derives the subkeys of raw.
func New(raw []byte) (*Key, error) {
	if len(raw) != Size {
		return nil, fmt.Errorf("data-encryption key must be %d bytes", Size)
	}
	derive := func(info string) ([]byte, error) {
		return hkdf.Key(sha256.New, raw, nil, "veksel dek v1 "+info, 32)
	}
	valueKey, err := derive("value")
	if err != nil {
		return nil, err
	}
	streamKey, err := derive("stream")
	if err != nil {
		return nil, err
	}
	nameMAC, err := derive("name mac")
	if err != nil {
		return nil, err
	}
	nameKey, err := derive("name enc")
	if err != nil {
		return nil, err
	}
	key := &Key{}
	key.macs.New = func() any { return hmac.New(sha256.New, nameMAC) }
	if key.value, err = chacha20poly1305.NewX(valueKey); err != nil {
		return nil, err
	}
	if key.stream, err = chacha20poly1305.NewX(streamKey); err != nil {
		return nil, err
	}
	if key.nameEnc, err = aes.NewCipher(nameKey); err != nil {
		return nil, err
	}
	return key, nil
}

// ValueOverhead is the number of bytes Seal adds to a value.
const ValueOverhead = 1 + chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead

// Seal encrypts one value bound to aad.
func (k *Key) Seal(aad, plaintext []byte) ([]byte, error) {
	out := make([]byte, 1+chacha20poly1305.NonceSizeX, ValueOverhead+len(plaintext))
	out[0] = valueVersion
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, err
	}
	return k.value.Seal(out, out[1:], plaintext, aad), nil
}

// Open decrypts a value sealed by Seal with the same aad.
func (k *Key) Open(aad, sealed []byte) ([]byte, error) {
	if len(sealed) < ValueOverhead {
		return nil, ErrAuthentication
	}
	if sealed[0] != valueVersion {
		return nil, errFormat
	}
	nonce := sealed[1 : 1+chacha20poly1305.NonceSizeX]
	plaintext, err := k.value.Open(nil, nonce, sealed[1+chacha20poly1305.NonceSizeX:], aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// SealName deterministically encrypts name bound to aad and returns it as
// unpadded URL-safe base64, which is valid in every store key.
func (k *Key) SealName(aad []byte, name string) string {
	tag := k.nameTag(aad, name)
	out := make([]byte, nameTagSize+len(name))
	copy(out, tag)
	cipher.NewCTR(k.nameEnc, tag).XORKeyStream(out[nameTagSize:], []byte(name))
	return base64.RawURLEncoding.EncodeToString(out)
}

// OpenName reverses SealName.
func (k *Key) OpenName(aad []byte, encoded string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) < nameTagSize {
		return "", ErrAuthentication
	}
	tag := raw[:nameTagSize]
	name := make([]byte, len(raw)-nameTagSize)
	cipher.NewCTR(k.nameEnc, tag).XORKeyStream(name, raw[nameTagSize:])
	if subtle.ConstantTimeCompare(tag, k.nameTag(aad, string(name))) != 1 {
		return "", ErrAuthentication
	}
	return string(name), nil
}

func (k *Key) nameTag(aad []byte, name string) []byte {
	mac := k.macs.Get().(hash.Hash)
	defer k.macs.Put(mac)
	mac.Reset()
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(aad)))
	mac.Write(length[:])
	mac.Write(aad)
	mac.Write([]byte(name))
	var sum [sha256.Size]byte
	return mac.Sum(sum[:0])[:nameTagSize]
}

// SealedStreamSize is the exact ciphertext length of an n-byte stream.
func SealedStreamSize(n int64) int64 {
	chunks := (n + StreamChunkSize - 1) / StreamChunkSize
	if chunks == 0 {
		chunks = 1
	}
	return streamHeader + n + chunks*chacha20poly1305.Overhead
}

// sealedChunkSize is one full ciphertext chunk. Stream buffers hold one more
// byte, which tells a reader whether another chunk follows.
const sealedChunkSize = StreamChunkSize + chacha20poly1305.Overhead

// chunkBuffers recycles stream buffers: most payloads are a few KiB, and
// allocating a full chunk buffer per stream dominated small reads.
var chunkBuffers = sync.Pool{New: func() any {
	buffer := make([]byte, sealedChunkSize+1)
	return &buffer
}}

func getChunkBuffer() *[]byte  { return chunkBuffers.Get().(*[]byte) }
func putChunkBuffer(b *[]byte) { chunkBuffers.Put(b) }

// NewSealingWriter returns a writer that encrypts everything written to it
// into destination. Close writes the final chunk and must be called; it does
// not close destination.
func (k *Key) NewSealingWriter(destination io.Writer, aad []byte) io.WriteCloser {
	return &sealingWriter{key: k, destination: destination, aad: aad}
}

type sealingWriter struct {
	key         *Key
	destination io.Writer
	aad         []byte
	salt        []byte
	counter     uint64
	buffer      *[]byte
	buffered    int
	err         error
	closed      bool
}

func (w *sealingWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, errors.New("write to closed sealing writer")
	}
	if w.buffer == nil {
		w.buffer = getChunkBuffer()
	}
	written := 0
	for len(data) > 0 {
		if w.buffered == StreamChunkSize {
			// More data follows, so the buffered chunk is not the last one.
			if w.err = w.emit(false); w.err != nil {
				return written, w.err
			}
		}
		count := copy((*w.buffer)[w.buffered:StreamChunkSize], data)
		w.buffered += count
		data = data[count:]
		written += count
	}
	return written, nil
}

func (w *sealingWriter) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.buffer == nil {
		w.buffer = getChunkBuffer()
	}
	if w.err == nil {
		w.err = w.emit(true)
	}
	putChunkBuffer(w.buffer)
	w.buffer = nil
	return w.err
}

func (w *sealingWriter) emit(final bool) error {
	if w.salt == nil {
		w.salt = make([]byte, saltSize)
		if _, err := rand.Read(w.salt); err != nil {
			return err
		}
		header := append([]byte{streamVersion}, w.salt...)
		if _, err := w.destination.Write(header); err != nil {
			return err
		}
	}
	buffer := *w.buffer
	sealed := w.key.stream.Seal(buffer[:0], streamNonce(w.salt, w.counter, final), buffer[:w.buffered], w.aad)
	w.counter++
	w.buffered = 0
	_, err := w.destination.Write(sealed)
	return err
}

// NewOpeningReader returns a reader that decrypts a stream written by a
// sealing writer with the same aad. Every chunk is authenticated before its
// plaintext is returned; a missing final chunk or trailing data is an error.
func (k *Key) NewOpeningReader(source io.Reader, aad []byte) io.Reader {
	return &openingReader{key: k, source: source, aad: aad}
}

type openingReader struct {
	key     *Key
	source  io.Reader
	aad     []byte
	salt    []byte
	counter uint64
	buffer  *[]byte
	carry   bool // the buffer's last byte starts the next chunk
	plain   []byte
	done    bool
	err     error
}

func (r *openingReader) Read(p []byte) (int, error) {
	for len(r.plain) == 0 {
		if r.done && r.buffer != nil {
			putChunkBuffer(r.buffer)
			r.buffer = nil
		}
		if r.err != nil {
			return 0, r.err
		}
		if r.done {
			return 0, io.EOF
		}
		r.err = r.next()
	}
	count := copy(p, r.plain)
	r.plain = r.plain[count:]
	return count, nil
}

func (r *openingReader) next() error {
	if r.salt == nil {
		header := make([]byte, streamHeader)
		if _, err := io.ReadFull(r.source, header); err != nil {
			return ErrAuthentication
		}
		if header[0] != streamVersion {
			return errFormat
		}
		r.salt = header[1:]
	}
	if r.buffer == nil {
		r.buffer = getChunkBuffer()
	}
	buffer := *r.buffer
	start := 0
	if r.carry {
		buffer[0], start = buffer[sealedChunkSize], 1
	}
	count, err := io.ReadFull(r.source, buffer[start:])
	count += start
	final := false
	switch {
	case err == nil:
		// A byte beyond the full chunk proves another chunk follows.
		count, r.carry = sealedChunkSize, true
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF) && start > 0:
		final, r.carry = true, false
	case errors.Is(err, io.EOF):
		return ErrAuthentication
	default:
		return err
	}
	plain, err := r.key.stream.Open(buffer[:0], streamNonce(r.salt, r.counter, final), buffer[:count], r.aad)
	if err != nil {
		return ErrAuthentication
	}
	r.counter++
	r.plain, r.done = plain, final
	return nil
}

func streamNonce(salt []byte, counter uint64, final bool) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	copy(nonce, salt)
	if final {
		counter |= finalFlag
	}
	binary.BigEndian.PutUint64(nonce[saltSize:], counter)
	return nonce
}
