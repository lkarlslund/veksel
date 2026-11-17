// Package dkimtest provisions hosted-domain DKIM keys for tests and verifies
// signatures against them without DNS.
package dkimtest

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// ActivateKey creates domain when it does not exist, stages and activates a
// fresh key under selector, and returns a Verifier that resolves that key's
// published DNS record.
func ActivateKey(t testing.TB, domains *model.DomainStore, domain, selector string) dkim.Verifier {
	t.Helper()
	ctx := context.Background()
	current, err := domains.Get(ctx, domain)
	if errors.Is(err, store.ErrNotFound) {
		if err = domains.Create(ctx, domain); err == nil {
			current, err = domains.Get(ctx, domain)
		}
	}
	if err != nil {
		t.Fatalf("provision domain %s: %v", domain, err)
	}
	private, public, err := dkim.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	staged, err := domains.StageDKIMKey(ctx, domain, current.DKIMRevision, model.DKIMKey{Selector: selector, PrivateKey: string(private), PublicKey: string(public)})
	if err != nil {
		t.Fatalf("stage DKIM key: %v", err)
	}
	if _, err := domains.ActivateDKIMKey(ctx, domain, selector, staged.DKIMRevision); err != nil {
		t.Fatalf("activate DKIM key: %v", err)
	}
	record := selector + "._domainkey." + domain
	txt := dkim.DKIMDNSRecord(public)
	return dkim.Verifier{LookupTXT: func(_ context.Context, name string) ([]string, error) {
		if name == record {
			return []string{txt}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}}
}
