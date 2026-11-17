package dane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newTestCert issues a certificate for names, signed by parent (or
// self-signed when parent is nil).
func newTestCert(t *testing.T, commonName string, names []string, ca bool, parent *testCert, notAfter time.Time) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, DNSNames: names,
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: ca,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	issuer, signer := template, key
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{cert: cert, key: key}
}

// recordFor builds a TLSA record for cert with the given parameters.
func recordFor(usage, selector, matching uint8, cert *x509.Certificate) Record {
	data := cert.Raw
	if selector == SelectorSPKI {
		data = cert.RawSubjectPublicKeyInfo
	}
	switch matching {
	case MatchSHA256:
		sum := sha256.Sum256(data)
		data = sum[:]
	case MatchSHA512:
		sum := sha512.Sum512(data)
		data = sum[:]
	}
	return Record{Usage: usage, Selector: selector, MatchingType: matching, Data: append([]byte(nil), data...)}
}

func TestDANEEEMatchesEverySelectorAndMatchingType(t *testing.T) {
	later := time.Now().Add(24 * time.Hour)
	leaf := newTestCert(t, "mx", []string{"mx.example.test"}, false, nil, later)
	other := newTestCert(t, "other", []string{"mx.example.test"}, false, nil, later)
	for _, selector := range []uint8{SelectorCert, SelectorSPKI} {
		for _, matching := range []uint8{MatchFull, MatchSHA256, MatchSHA512} {
			record := recordFor(UsageDANEEE, selector, matching, leaf.cert)
			if !record.Usable() {
				t.Fatalf("record %s is not usable", record)
			}
			if !record.Matches(leaf.cert) || record.Matches(other.cert) {
				t.Fatalf("selector %d matching %d: match leaf=%t other=%t", selector, matching, record.Matches(leaf.cert), record.Matches(other.cert))
			}
			if err := Verify([]*x509.Certificate{leaf.cert}, []Record{record}, []string{"mx.example.test"}, time.Now()); err != nil {
				t.Fatalf("selector %d matching %d: Verify() = %v", selector, matching, err)
			}
			err := Verify([]*x509.Certificate{other.cert}, []Record{record}, []string{"mx.example.test"}, time.Now())
			if verifyErr, ok := IsVerifyError(err); !ok || verifyErr.Kind != FailureNoMatch {
				t.Fatalf("selector %d matching %d: mismatched Verify() = %v", selector, matching, err)
			}
		}
	}
}

func TestDANEEEIgnoresNamesAndExpiry(t *testing.T) {
	expired := newTestCert(t, "elsewhere", []string{"unrelated.example"}, false, nil, time.Now().Add(-24*time.Hour))
	record := recordFor(UsageDANEEE, SelectorSPKI, MatchSHA256, expired.cert)
	if err := Verify([]*x509.Certificate{expired.cert}, []Record{record}, []string{"mx.example.test"}, time.Now()); err != nil {
		t.Fatalf("DANE-EE must ignore name and validity: %v", err)
	}
}

func TestDANETAChainAndNameChecks(t *testing.T) {
	later := time.Now().Add(24 * time.Hour)
	ca := newTestCert(t, "Example CA", nil, true, nil, later)
	leaf := newTestCert(t, "mx", []string{"mx.example.test"}, false, ca, later)
	wildcard := newTestCert(t, "wild", []string{"*.example.test"}, false, ca, later)
	rogueCA := newTestCert(t, "Rogue CA", nil, true, nil, later)
	rogueLeaf := newTestCert(t, "mx", []string{"mx.example.test"}, false, rogueCA, later)
	names := []string{"mx.example.test"}
	for _, selector := range []uint8{SelectorCert, SelectorSPKI} {
		for _, matching := range []uint8{MatchFull, MatchSHA256, MatchSHA512} {
			record := recordFor(UsageDANETA, selector, matching, ca.cert)
			if err := Verify([]*x509.Certificate{leaf.cert, ca.cert}, []Record{record}, names, time.Now()); err != nil {
				t.Fatalf("selector %d matching %d: Verify() = %v", selector, matching, err)
			}
			if err := Verify([]*x509.Certificate{rogueLeaf.cert, rogueCA.cert}, []Record{record}, names, time.Now()); err == nil {
				t.Fatalf("selector %d matching %d: chain to another CA verified", selector, matching)
			}
		}
	}
	record := recordFor(UsageDANETA, SelectorSPKI, MatchSHA256, ca.cert)
	err := Verify([]*x509.Certificate{leaf.cert, ca.cert}, []Record{record}, []string{"other.example.test"}, time.Now())
	if verifyErr, ok := IsVerifyError(err); !ok || verifyErr.Kind != FailureNameMismatch {
		t.Fatalf("name mismatch Verify() = %v", err)
	}
	if err := Verify([]*x509.Certificate{wildcard.cert, ca.cert}, []Record{record}, []string{"mx.example.test."}, time.Now()); err != nil {
		t.Fatalf("wildcard name Verify() = %v", err)
	}
	// The TLSA base domain is a reference identifier too (RFC 7672 3.2.2).
	if err := Verify([]*x509.Certificate{leaf.cert, ca.cert}, []Record{record}, []string{"target.example.net", "mx.example.test"}, time.Now()); err != nil {
		t.Fatalf("second reference identifier Verify() = %v", err)
	}
	// A digest names a TA the server must present; a full certificate
	// record supplies the TA itself.
	if err := Verify([]*x509.Certificate{leaf.cert}, []Record{record}, names, time.Now()); err == nil {
		t.Fatal("digest TA absent from the chain verified")
	}
	full := recordFor(UsageDANETA, SelectorCert, MatchFull, ca.cert)
	if err := Verify([]*x509.Certificate{leaf.cert}, []Record{full}, names, time.Now()); err != nil {
		t.Fatalf("full-certificate TA Verify() = %v", err)
	}
	// A DANE-TA record matching only the leaf makes the leaf its own anchor.
	if err := Verify([]*x509.Certificate{leaf.cert, ca.cert}, []Record{recordFor(UsageDANETA, SelectorSPKI, MatchSHA256, leaf.cert)}, names, time.Now()); err != nil {
		t.Fatalf("leaf-as-TA Verify() = %v", err)
	}
}

func TestPKIXUsagesAndMalformedRecordsAreUnusable(t *testing.T) {
	leaf := newTestCert(t, "mx", []string{"mx.example.test"}, false, nil, time.Now().Add(time.Hour))
	unusable := []Record{
		recordFor(UsagePKIXTA, SelectorSPKI, MatchSHA256, leaf.cert),
		recordFor(UsagePKIXEE, SelectorSPKI, MatchSHA256, leaf.cert),
		{Usage: UsageDANEEE, Selector: 2, MatchingType: MatchSHA256, Data: make([]byte, 32)},
		{Usage: UsageDANEEE, Selector: SelectorSPKI, MatchingType: 3, Data: make([]byte, 32)},
		{Usage: UsageDANEEE, Selector: SelectorSPKI, MatchingType: MatchSHA256, Data: make([]byte, 31)},
		{Usage: UsageDANEEE, Selector: SelectorSPKI, MatchingType: MatchSHA512, Data: make([]byte, 32)},
		{Usage: UsageDANEEE, Selector: SelectorCert, MatchingType: MatchFull},
	}
	for _, record := range unusable {
		if record.Usable() {
			t.Fatalf("record %s is usable", record)
		}
	}
	if err := Verify([]*x509.Certificate{leaf.cert}, unusable[:2], nil, time.Now()); err == nil {
		t.Fatal("PKIX-only RRset authenticated the server")
	}
	if err := Verify(nil, []Record{recordFor(UsageDANEEE, SelectorSPKI, MatchSHA256, leaf.cert)}, nil, time.Now()); err == nil {
		t.Fatal("empty chain verified")
	}
}

func TestRecordPresentationForm(t *testing.T) {
	record := Record{Usage: 3, Selector: 1, MatchingType: 1, Data: []byte{0xab, 0x01}}
	if got := record.String(); got != "3 1 1 AB01" {
		t.Fatalf("String() = %q", got)
	}
}
