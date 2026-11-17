package archivecrypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

// sshKeyPair returns an authorized_keys line and an OpenSSH private key file.
func sshKeyPair(t *testing.T) (string, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic))), pem.EncodeToMemory(block)
}

func encrypt(t *testing.T, plaintext []byte, recipients []age.Recipient) []byte {
	t.Helper()
	var ciphertext bytes.Buffer
	writer, err := Encrypt(&ciphertext, recipients)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return ciphertext.Bytes()
}

func TestEncryptOpenRoundTripWithAgeAndSSHKeys(t *testing.T) {
	native, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, sshPrivate := sshKeyPair(t)
	recipients, err := ParseRecipients([]string{"# operator keys", native.Recipient().String(), "", sshPublic})
	if err != nil || len(recipients) != 2 {
		t.Fatalf("ParseRecipients = %d recipients, %v", len(recipients), err)
	}
	plaintext := bytes.Repeat([]byte("installation archive "), 10000)
	ciphertext := encrypt(t, plaintext, recipients)
	if !IsEncrypted(ciphertext[:HeaderLength]) || bytes.Contains(ciphertext, []byte("installation archive")) {
		t.Fatal("ciphertext is not an age file or leaks plaintext")
	}
	for name, identityFile := range map[string][]byte{"age": []byte(native.String() + "\n"), "ssh": sshPrivate} {
		identities, err := ParseIdentities(identityFile)
		if err != nil {
			t.Fatalf("%s identity: %v", name, err)
		}
		reader, encrypted, err := Open(bytes.NewReader(ciphertext), identities)
		if err != nil || !encrypted {
			t.Fatalf("%s Open = %v, %v", name, encrypted, err)
		}
		decrypted, err := io.ReadAll(reader)
		if err != nil || !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("%s decrypted %d bytes, %v", name, len(decrypted), err)
		}
	}
	if _, encrypted, err := Open(bytes.NewReader(ciphertext), nil); !encrypted || !errors.Is(err, ErrIdentityRequired) {
		t.Fatalf("Open without identity = %v, %v", encrypted, err)
	}
	other, _ := age.GenerateX25519Identity()
	if _, _, err := Open(bytes.NewReader(ciphertext), []age.Identity{other}); err == nil {
		t.Fatal("a non-recipient identity decrypted the archive")
	}
	reader, encrypted, err := Open(bytes.NewReader(plaintext), []age.Identity{native})
	if err != nil || encrypted {
		t.Fatalf("plain input Open = %v, %v", encrypted, err)
	}
	if passed, _ := io.ReadAll(reader); !bytes.Equal(passed, plaintext) {
		t.Fatal("plain input was altered")
	}
}

func TestParseRecipientsRejectsPrivateKeysWithoutEchoingThem(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	_, err := ParseRecipients([]string{identity.String()})
	if err == nil {
		t.Fatal("a private key was accepted as a recipient")
	}
	if strings.Contains(err.Error(), identity.String()) {
		t.Fatal("the error message echoes the private key")
	}
	if _, err := ParseRecipients([]string{"ssh-dss AAAA"}); err == nil {
		t.Fatal("an unsupported SSH key type was accepted")
	}
}
