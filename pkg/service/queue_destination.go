package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

var (
	ErrDisabledLocalRecipient = errors.New("local recipient is disabled")
	ErrUnknownLocalRecipient  = errors.New("unknown recipient in local domain")
	ErrInvalidQueueRecipient  = errors.New("invalid queue recipient")
)

// QueueDestination is the policy result used by the system queue. A zero
// Local address and zero Route represent ordinary external fallback delivery.
type QueueDestination struct {
	Local *model.EmailAddress
	Route *model.OutboundRoute
}

// ClassifyQueueDestination resolves an address without treating control-plane
// outages as absence. Disabled explicit routes intentionally mean “use the
// normal external fallback”; disabled local identities never escape externally.
func ClassifyQueueDestination(ctx context.Context, recipient string,
	lookupAddress func(context.Context, string) (model.EmailAddress, error),
	lookupDomain func(context.Context, string) (model.Domain, error),
	lookupRoute func(context.Context, string) (model.OutboundRoute, error),
) (QueueDestination, error) {
	recipient = strings.TrimSpace(recipient)
	at := strings.LastIndex(recipient, "@")
	if at <= 0 || at == len(recipient)-1 {
		return QueueDestination{}, fmt.Errorf("%w %q", ErrInvalidQueueRecipient, recipient)
	}
	domain := strings.ToLower(strings.TrimSpace(recipient[at+1:]))
	if strings.ContainsAny(domain, "@/\\ :") {
		return QueueDestination{}, fmt.Errorf("%w domain %q", ErrInvalidQueueRecipient, domain)
	}

	address, err := lookupAddress(ctx, recipient)
	if err == nil {
		if !address.Enabled {
			return QueueDestination{}, fmt.Errorf("%w: %s", ErrDisabledLocalRecipient, recipient)
		}
		return QueueDestination{Local: &address}, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return QueueDestination{}, fmt.Errorf("lookup local recipient: %w", err)
	}
	domainRecord, err := lookupDomain(ctx, domain)
	if err == nil {
		if domainRecord.Enabled && domainRecord.UnknownRecipients.Route {
			// Split delivery: the domain's other server hosts the address.
			route, err := lookupRoute(ctx, domain)
			if err != nil || !route.Enabled || route.Transport != model.OutboundTransportRelay {
				return QueueDestination{}, fmt.Errorf("%w: %s (split delivery has no enabled relay route)", ErrUnknownLocalRecipient, recipient)
			}
			return QueueDestination{Route: &route}, nil
		}
		if domainRecord.Enabled {
			return QueueDestination{}, fmt.Errorf("%w: %s", ErrUnknownLocalRecipient, recipient)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return QueueDestination{}, fmt.Errorf("lookup local domain: %w", err)
	}

	route, err := lookupRoute(ctx, domain)
	if err == nil {
		if !route.Enabled {
			return QueueDestination{}, nil
		}
		return QueueDestination{Route: &route}, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return QueueDestination{}, fmt.Errorf("lookup outbound route: %w", err)
	}
	return QueueDestination{}, nil
}
