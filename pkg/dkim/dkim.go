// Package dkim implements DKIM (DomainKeys Identified Mail) signing and
// verification per RFC 6376 on top of github.com/emersion/go-msgauth.
//
// It also provides RSA key pair generation and helpers for generating DNS TXT
// records for DKIM, SPF, and DMARC.
package dkim

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	msgauth "github.com/emersion/go-msgauth/dkim"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
)

var log = logpkg.For(logpkg.ModuleDKIM)

// DefaultHeaders are the headers signed by the DKIM signature. Trace headers
// that receivers add or rewrite (Received-SPF, Authentication-Results) are
// deliberately excluded because signing them breaks verification downstream.
var DefaultHeaders = []string{
	"from",
	"reply-to",
	"subject",
	"date",
	"to",
	"cc",
	"message-id",
	"in-reply-to",
	"references",
	"mime-version",
	"content-type",
	"content-transfer-encoding",
}

// GenerateKeyPair generates a 2048-bit RSA key pair for DKIM.
// Returns the private and public keys in PEM format.
func GenerateKeyPair() (private, public []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate RSA key: %w", err)
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey),
	})

	return privatePEM, publicPEM, nil
}

// ParsePrivateKey parses a PEM-encoded RSA private key in PKCS#1 or PKCS#8 form.
func ParsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, not RSA", parsed)
	}
	return key, nil
}

// parsePublicKey parses a PEM-encoded RSA public key in PKCS#1 or
// SubjectPublicKeyInfo form.
func parsePublicKey(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, not RSA", parsed)
	}
	return pub, nil
}

// Sign signs an email message and returns the full message with the
// DKIM-Signature header prepended. The domain and selector identify
// the signing entity, and privateKey is the PEM-encoded RSA private key.
func Sign(message []byte, domain, selector string, privateKey []byte) ([]byte, error) {
	return SignWithHeaders(message, domain, selector, privateKey, DefaultHeaders...)
}

// SignWithHeaders signs an email message with the specified headers to sign,
// using relaxed/relaxed canonicalization and RSA-SHA256.
func SignWithHeaders(message []byte, domain, selector string, privateKey []byte, headers ...string) ([]byte, error) {
	field, err := signatureField(message, domain, selector, privateKey, headers)
	if err != nil {
		return nil, err
	}
	return append([]byte(field), message...), nil
}

// signatureField returns the complete DKIM-Signature header field, with its
// terminating CRLF, for message.
func signatureField(message []byte, domain, selector string, privateKey []byte, headers []string) (string, error) {
	log.Debug("dkim: signing message", "domain", domain, "selector", selector)
	key, err := ParsePrivateKey(privateKey)
	if err != nil {
		log.Error("dkim: failed to parse private key", "error", err)
		return "", fmt.Errorf("parse private key: %w", err)
	}
	if len(headers) == 0 {
		headers = DefaultHeaders
	}
	signer, err := msgauth.NewSigner(&msgauth.SignOptions{
		Domain:                 domain,
		Selector:               selector,
		Signer:                 key,
		HeaderCanonicalization: msgauth.CanonicalizationRelaxed,
		BodyCanonicalization:   msgauth.CanonicalizationRelaxed,
		HeaderKeys:             headers,
	})
	if err != nil {
		return "", fmt.Errorf("sign DKIM: %w", err)
	}
	if _, err := signer.Write(message); err != nil {
		_ = signer.Close()
		return "", fmt.Errorf("sign DKIM: %w", err)
	}
	if err := signer.Close(); err != nil {
		return "", fmt.Errorf("sign DKIM: %w", err)
	}
	return signer.Signature(), nil
}

// DKIMDNSRecord generates the DKIM DNS TXT record for a PEM-encoded RSA public
// key. The p= value is the DER SubjectPublicKeyInfo required by RFC 6376.
func DKIMDNSRecord(publicKey []byte) string {
	pub, err := parsePublicKey(publicKey)
	if err != nil {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

// SPFDNSRecord generates a recommended SPF DNS TXT record.
// UseMX determines whether to use "mx" or "a" mechanism.
func SPFDNSRecord(useMX bool) string {
	if useMX {
		return "v=spf1 mx -all"
	}
	return "v=spf1 a -all"
}

// DMARCDNSRecord generates a recommended DMARC DNS TXT record.
func DMARCDNSRecord(pct int, rua string) string {
	p := "none"
	if pct >= 100 {
		p = "reject"
	} else if pct >= 50 {
		p = "quarantine"
	}
	// pct only matters for quarantine and reject below 100 (RFC 7489 6.3).
	if p == "none" || pct >= 100 {
		return fmt.Sprintf("v=DMARC1; p=%s; rua=mailto:%s", p, rua)
	}
	return fmt.Sprintf("v=DMARC1; p=%s; pct=%d; rua=mailto:%s", p, pct, rua)
}
