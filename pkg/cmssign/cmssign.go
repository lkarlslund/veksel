// Package cmssign produces CMS (RFC 5652) SignedData envelopes with the
// content embedded, the form Apple devices expect for signed configuration
// profiles. It supports RSA and ECDSA keys with SHA-256.
package cmssign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"
)

var (
	oidData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

type algorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version    int
	SID        issuerAndSerial
	DigestAlg  algorithm
	SignedAttr asn1.RawValue
	SigAlg     algorithm
	Signature  []byte
}

type encapsulated struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue
}

type signedData struct {
	Version      int
	DigestAlgs   []algorithm `asn1:"set"`
	Encapsulated encapsulated
	Certificates asn1.RawValue
	Signers      []signerInfo `asn1:"set"`
}

type contentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue
}

var asn1Null = asn1.RawValue{Tag: asn1.TagNull}

// Sign wraps content in SignedData signed by key. chain starts with the
// signer's certificate; further certificates are embedded for verifiers.
func Sign(content []byte, chain []*x509.Certificate, key crypto.Signer) ([]byte, error) {
	if len(chain) == 0 || key == nil {
		return nil, errors.New("a signing certificate and key are required")
	}
	signer := chain[0]
	var sigAlg algorithm
	switch key.Public().(type) {
	case *rsa.PublicKey:
		sigAlg = algorithm{Algorithm: oidSHA256WithRSA, Parameters: asn1Null}
	case *ecdsa.PublicKey:
		sigAlg = algorithm{Algorithm: oidECDSAWithSHA256}
	default:
		return nil, fmt.Errorf("unsupported signing key type %T", key.Public())
	}
	digest := sha256.Sum256(content)
	attributes, err := signedAttributes(digest[:])
	if err != nil {
		return nil, err
	}
	// The signature covers the attributes encoded as an explicit SET OF.
	toSign := sha256.Sum256(setOf(attributes))
	signature, err := key.Sign(rand.Reader, toSign[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	var certificates []byte
	for _, certificate := range chain {
		certificates = append(certificates, certificate.Raw...)
	}
	octets, err := asn1.Marshal(content)
	if err != nil {
		return nil, err
	}
	sha := algorithm{Algorithm: oidSHA256, Parameters: asn1Null}
	data, err := asn1.Marshal(signedData{
		Version:      1,
		DigestAlgs:   []algorithm{sha},
		Encapsulated: encapsulated{Type: oidData, Content: explicit0(octets)},
		Certificates: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certificates},
		Signers: []signerInfo{{
			Version:    1,
			SID:        issuerAndSerial{Issuer: asn1.RawValue{FullBytes: signer.RawIssuer}, Serial: signer.SerialNumber},
			DigestAlg:  sha,
			SignedAttr: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attributes},
			SigAlg:     sigAlg,
			Signature:  signature,
		}},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(contentInfo{Type: oidSignedData, Content: explicit0(data)})
}

// signedAttributes returns the DER-sorted concatenation of the content-type,
// signing-time, and message-digest attributes.
func signedAttributes(digest []byte) ([]byte, error) {
	values := []struct {
		oid   asn1.ObjectIdentifier
		value any
	}{
		{oidContentType, oidData},
		{oidSigningTime, time.Now().UTC()},
		{oidMessageDigest, digest},
	}
	encoded := make([][]byte, 0, len(values))
	for _, v := range values {
		inner, err := asn1.Marshal(v.value)
		if err != nil {
			return nil, err
		}
		item, err := asn1.Marshal(attribute{Type: v.oid, Values: asn1.RawValue{FullBytes: setOf(inner)}})
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, item)
	}
	sort.Slice(encoded, func(i, j int) bool { return string(encoded[i]) < string(encoded[j]) })
	var out []byte
	for _, item := range encoded {
		out = append(out, item...)
	}
	return out, nil
}

// explicit0 wraps encoded DER in an explicit, constructed [0] tag.
func explicit0(body []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: body}
}

// setOf wraps already-encoded elements in a SET.
func setOf(body []byte) []byte {
	header, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: body})
	return header
}
