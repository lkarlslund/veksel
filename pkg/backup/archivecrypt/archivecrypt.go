// Package archivecrypt encrypts backup archives to age recipients and opens
// encrypted archives with an operator-held identity. The server only ever
// holds public recipient keys, so it can write encrypted backups it cannot
// read back.
package archivecrypt

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

// Extension is appended to the name of an encrypted archive.
const Extension = ".age"

// header starts every binary age file.
var header = []byte("age-encryption.org/")

// HeaderLength is how many leading bytes IsEncrypted needs.
var HeaderLength = len(header)

// ErrIdentityRequired reports an encrypted archive opened without an identity.
var ErrIdentityRequired = errors.New("archive is age-encrypted; provide the matching identity (private key) file to decrypt it")

// ParseRecipients parses public keys, one per entry: native age recipients
// (age1...) or OpenSSH ssh-ed25519 / ssh-rsa public keys. Blank entries and
// entries starting with # are ignored.
func ParseRecipients(entries []string) ([]age.Recipient, error) {
	var recipients []age.Recipient
	for i, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		var (
			recipient age.Recipient
			err       error
		)
		if strings.HasPrefix(entry, "ssh-") {
			recipient, err = agessh.ParseRecipient(entry)
		} else {
			var parsed []age.Recipient
			parsed, err = age.ParseRecipients(strings.NewReader(entry))
			if err == nil {
				recipient = parsed[0]
			}
		}
		if err != nil {
			// Never echo the entry: a private key pasted by mistake must not
			// end up in an error message or log.
			return nil, fmt.Errorf("recipient %d is not an age (age1...) or ssh-ed25519/ssh-rsa public key: %v", i+1, err)
		}
		recipients = append(recipients, recipient)
	}
	return recipients, nil
}

// ParseIdentities parses an identity file: native age secret keys
// (AGE-SECRET-KEY-1..., one per line) or an unencrypted OpenSSH private key.
func ParseIdentities(contents []byte) ([]age.Identity, error) {
	if bytes.Contains(contents, []byte("-----BEGIN")) {
		identity, err := agessh.ParseIdentity(contents)
		if err != nil {
			return nil, fmt.Errorf("parse SSH identity: %w", err)
		}
		return []age.Identity{identity}, nil
	}
	identities, err := age.ParseIdentities(bytes.NewReader(contents))
	if err != nil {
		return nil, fmt.Errorf("parse age identity: %w", err)
	}
	return identities, nil
}

// IsEncrypted reports whether prefix, the first HeaderLength bytes of a file,
// is an age file header.
func IsEncrypted(prefix []byte) bool {
	return bytes.HasPrefix(prefix, header)
}

// Encrypt returns a writer that encrypts to every recipient and writes the
// ciphertext to dst. Close flushes the final chunk and must be called.
func Encrypt(dst io.Writer, recipients []age.Recipient) (io.WriteCloser, error) {
	if len(recipients) == 0 {
		return nil, errors.New("encryption requires at least one recipient")
	}
	return age.Encrypt(dst, recipients...)
}

// Open returns the plaintext of r: r itself when it is not encrypted, or the
// decrypted stream when it is. Encrypted input without identities fails with
// ErrIdentityRequired. encrypted reports which case applied.
func Open(r io.Reader, identities []age.Identity) (plaintext io.Reader, encrypted bool, err error) {
	buffered := bufio.NewReader(r)
	prefix, err := buffered.Peek(HeaderLength)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("read archive: %w", err)
	}
	if !IsEncrypted(prefix) {
		return buffered, false, nil
	}
	if len(identities) == 0 {
		return nil, true, ErrIdentityRequired
	}
	decrypted, err := age.Decrypt(buffered, identities...)
	if err != nil {
		return nil, true, fmt.Errorf("decrypt archive: %w", err)
	}
	return decrypted, true, nil
}
