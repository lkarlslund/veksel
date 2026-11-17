package dkim

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Signer DKIM-signs locally originated mail with the active key of the
// enabled hosted domain named by the RFC 5322 From header, so the signature
// aligns for DMARC. The system queue is its only caller: it signs admitted
// messages that carry a Request (authenticated submission and
// server-generated mail), while relayed and forwarded mail never carries one,
// so its original bytes and signatures reach the next hop untouched.
type Signer struct {
	domain func(context.Context, string) (model.Domain, error)
}

// Request marks a locally originated message for signing. The originator
// attaches it; the system queue signs the message with the Signer once mail
// policy has applied its header actions, so the signature covers the final
// headers. Relayed and forwarded mail carries no Request.
type Request struct {
	// Headers are signed in addition to DefaultHeaders.
	Headers []string
	// Required refuses the message when it cannot be signed.
	Required bool
}

// NewSigner returns a Signer that reads keys from domains. Staged and
// retiring keys are published in DNS but never used to sign.
func NewSigner(domains *model.DomainStore) *Signer {
	return &Signer{domain: domains.Get}
}

// SignHeaders signs the message held as a header map and body, adding the
// DKIM-Signature field to headers; extraHeaders are signed in addition to
// DefaultHeaders. signed is false, without error, when the From domain has
// no active key. A message that already carries a DKIM-Signature is left
// unchanged, and reports signed only when that signature is the From
// domain's own, so a message is never signed twice. A nil Signer never signs.
func (s *Signer) SignHeaders(ctx context.Context, headers map[string]string, body []byte, extraHeaders ...string) (signed bool, err error) {
	signed, _, err = s.sign(ctx, headers, nil, body, extraHeaders)
	return signed, err
}

// SignMessage is SignHeaders for a message held as exact bytes, with headers
// as its lookup view. It returns message with the DKIM-Signature field
// prepended, keeping the order and repeated fields of the original bytes,
// and records the field in headers too. The message is returned unchanged
// when signed is false.
func (s *Signer) SignMessage(ctx context.Context, headers map[string]string, message []byte, extraHeaders ...string) (signedMessage []byte, signed bool, err error) {
	signed, field, err := s.sign(ctx, headers, message, nil, extraHeaders)
	if err != nil || field == "" {
		return message, signed, err
	}
	return append([]byte(field), message...), true, nil
}

// sign signs message, or the message built from headers and body when
// message is nil. field is the new folded DKIM-Signature field with its line
// break, or "" when no new signature was made.
func (s *Signer) sign(ctx context.Context, headers map[string]string, message, body []byte, extraHeaders []string) (signed bool, field string, err error) {
	if s == nil {
		return false, "", nil
	}
	domain := fromDomain(headerValue(headers, "From"))
	if domain == "" {
		return false, "", nil
	}
	if existing := headerValue(headers, "DKIM-Signature"); existing != "" {
		return strings.EqualFold(tagList(existing)["d"], domain), "", nil
	}
	hosted, err := s.domain(ctx, domain)
	if errors.Is(err, store.ErrNotFound) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	key, ok := model.ActiveDKIMKey(hosted)
	if !hosted.Enabled || !ok {
		return false, "", nil
	}
	if message == nil {
		message = model.BuildMessage(headers, body)
	}
	signedHeaders := append(append([]string(nil), DefaultHeaders...), extraHeaders...)
	field, err = signatureField(message, domain, key.Selector, []byte(key.PrivateKey), signedHeaders)
	if err != nil {
		return false, "", err
	}
	// The header map holds unfolded values; relaxed canonicalization makes
	// the unfolded field verify identically.
	_, value, _ := strings.Cut(strings.ReplaceAll(field, "\r\n", ""), ":")
	headers["DKIM-Signature"] = strings.TrimSpace(value)
	return true, field, nil
}

// Seal adds an ARC set (RFC 8617) to a message this server forwards, signed
// with the active key of the enabled hosted domain doing the forwarding, so
// the next receiver can trust the authentication results recorded before
// forwarding changed the envelope. authResults is this hop's
// Authentication-Results value and chainValidation its validation of the
// incoming chain. sealed is false, without error, when the domain has no
// active key; an ErrARCNotSealable error leaves a failed, unvalidated, or
// full chain unextended. A nil Signer never seals.
func (s *Signer) Seal(ctx context.Context, domain string, message []byte, authResults, chainValidation string) (sealedMessage []byte, sealed bool, err error) {
	if s == nil || domain == "" {
		return message, false, nil
	}
	hosted, err := s.domain(ctx, strings.ToLower(domain))
	if errors.Is(err, store.ErrNotFound) {
		return message, false, nil
	}
	if err != nil {
		return message, false, err
	}
	key, ok := model.ActiveDKIMKey(hosted)
	if !hosted.Enabled || !ok {
		return message, false, nil
	}
	private, err := ParsePrivateKey([]byte(key.PrivateKey))
	if err != nil {
		return message, false, fmt.Errorf("parse private key: %w", err)
	}
	sealedMessage, err = SealARC(message, ARCSealOptions{Domain: hosted.ID, Selector: key.Selector, Key: private,
		AuthResults: authResults, ChainValidation: chainValidation})
	if err != nil {
		return message, false, err
	}
	return sealedMessage, true, nil
}

// fromDomain returns the lowercase domain shared by every From mailbox, or
// "" when the field is unparsable or names several domains.
func fromDomain(value string) string {
	addresses, err := mail.ParseAddressList(value)
	if err != nil || len(addresses) == 0 {
		return ""
	}
	domain := ""
	for _, address := range addresses {
		at := strings.LastIndex(address.Address, "@")
		if at < 0 {
			return ""
		}
		current := strings.ToLower(address.Address[at+1:])
		if domain != "" && current != domain {
			return ""
		}
		domain = current
	}
	return domain
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}
