package main

import (
	"context"
	"slices"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
)

// directoryLimit bounds one global address list answer.
const directoryLimit = 100

// accountDirectory is the global address list the Exchange protocols
// share: enabled accounts that have a mail domain in common with the
// requester, so one tenant's list never reveals another's.
type accountDirectory struct{ users *model.UserStore }

type directoryEntry struct {
	ID          string
	DisplayName string
	// Addresses lists enabled addresses, primary first.
	Addresses []string
}

// addresses lists a user's enabled addresses with the primary first.
func (d accountDirectory) addresses(ctx context.Context, userID string) []string {
	identities, err := d.users.ListEmailAddressesForUser(ctx, userID)
	if err != nil {
		return nil
	}
	slices.SortStableFunc(identities, func(x, y model.EmailAddress) int {
		if x.Primary != y.Primary {
			if x.Primary {
				return -1
			}
			return 1
		}
		return strings.Compare(x.ID, y.ID)
	})
	addresses := make([]string, 0, len(identities))
	for _, identity := range identities {
		if identity.Enabled {
			addresses = append(addresses, identity.ID)
		}
	}
	return addresses
}

// search matches query against display names, account IDs and address
// prefixes.
func (d accountDirectory) search(ctx context.Context, userID, query string, limit int) ([]directoryEntry, error) {
	domains := map[string]bool{}
	for _, address := range d.addresses(ctx, userID) {
		if _, domain, ok := strings.Cut(address, "@"); ok {
			domains[strings.ToLower(domain)] = true
		}
	}
	if len(domains) == 0 {
		return nil, nil
	}
	users, err := d.users.List(ctx)
	if err != nil {
		return nil, err
	}
	needle := strings.ToLower(strings.TrimSpace(query))
	limit = min(max(limit, 1), directoryLimit)
	var result []directoryEntry
	for _, user := range users {
		if !user.Enabled || len(result) >= limit {
			continue
		}
		addresses := d.addresses(ctx, user.ID)
		shared, matched := false, strings.Contains(strings.ToLower(user.DisplayName), needle) || strings.Contains(strings.ToLower(user.ID), needle)
		for _, address := range addresses {
			if _, domain, ok := strings.Cut(address, "@"); ok && domains[strings.ToLower(domain)] {
				shared = true
			}
			matched = matched || strings.HasPrefix(strings.ToLower(address), needle)
		}
		if shared && matched && len(addresses) > 0 {
			result = append(result, directoryEntry{ID: user.ID, DisplayName: user.DisplayName, Addresses: addresses})
		}
	}
	return result, nil
}
