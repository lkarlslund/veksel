package cmssign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func testCertificate(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "mail.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

// verify parses the envelope independently of Sign's own types and returns
// the embedded content after checking digest and signature.
func verify(t *testing.T, envelope []byte, certificate *x509.Certificate) []byte {
	t.Helper()
	var info struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if rest, err := asn1.Unmarshal(envelope, &info); err != nil || len(rest) != 0 || !info.Type.Equal(oidSignedData) {
		t.Fatalf("content info: %v rest=%d type=%v", err, len(rest), info.Type)
	}
	var data struct {
		Version      int
		DigestAlgs   asn1.RawValue
		Encapsulated struct {
			Type    asn1.ObjectIdentifier
			Content []byte `asn1:"explicit,tag:0"`
		}
		Certificates asn1.RawValue `asn1:"tag:0"`
		Signers      []struct {
			Version    int
			SID        asn1.RawValue
			DigestAlg  asn1.RawValue
			SignedAttr asn1.RawValue `asn1:"tag:0"`
			SigAlg     asn1.RawValue
			Signature  []byte
		} `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(info.Content.Bytes, &data); err != nil || len(data.Signers) != 1 {
		t.Fatalf("signed data: %v", err)
	}
	content, signer := data.Encapsulated.Content, data.Signers[0]
	if !bytes.Contains(data.Certificates.Bytes, certificate.Raw) {
		t.Fatal("signer certificate is not embedded")
	}
	var attributes []struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}
	if _, err := asn1.UnmarshalWithParams(setOf(signer.SignedAttr.Bytes), &attributes, "set"); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	found := false
	for _, attribute := range attributes {
		if attribute.Type.Equal(oidMessageDigest) {
			var got []byte
			if _, err := asn1.Unmarshal(attribute.Values.Bytes, &got); err != nil || !bytes.Equal(got, digest[:]) {
				t.Fatalf("message digest mismatch: %v", err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("message digest attribute missing")
	}
	signed := sha256.Sum256(setOf(signer.SignedAttr.Bytes))
	switch key := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, signed[:], signer.Signature); err != nil {
			t.Fatalf("RSA signature: %v", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, signed[:], signer.Signature) {
			t.Fatal("ECDSA signature does not verify")
		}
	}
	return content
}

func TestSignRoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]crypto.Signer{"rsa": rsaKey, "ecdsa": ecKey} {
		t.Run(name, func(t *testing.T) {
			certificate := testCertificate(t, key)
			payload := []byte("<plist>profile</plist>")
			envelope, err := Sign(payload, []*x509.Certificate{certificate}, key)
			if err != nil {
				t.Fatal(err)
			}
			if got := verify(t, envelope, certificate); !bytes.Equal(got, payload) {
				t.Fatalf("content = %q", got)
			}
		})
	}
}

func TestSignRejectsMissingKey(t *testing.T) {
	if _, err := Sign([]byte("x"), nil, nil); err == nil {
		t.Fatal("expected an error without a certificate and key")
	}
}
