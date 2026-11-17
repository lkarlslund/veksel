package main

import (
	"context"

	"github.com/lkarlslund/veksel/pkg/mailidentity"
)

// smtpIdentityProblems explains why name is unlikely to be accepted as an
// EHLO identity by other mail servers. Reverse DNS (FCrDNS) is verified only
// when publicAddr (smtp_public_address) is configured.
func smtpIdentityProblems(ctx context.Context, name, publicAddr string, r mailidentity.Resolver) []string {
	return mailidentity.Problems(ctx, r, name, publicAddr)
}
