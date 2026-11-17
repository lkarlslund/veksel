package imap

import (
	"fmt"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

const quotaRootPrefix = "#user/"

// quotaRoot is deliberately account-scoped. Veksel quotas are enforced across
// every typed folder in an account, while the MESSAGE projection below reports
// the current effective mail-item ceiling after non-mail items consume their
// share of that common limit.
func quotaRoot(userID string) string {
	return quotaRootPrefix + userID
}

func (s *Session) cmdGetQuota(tag string, args []string) {
	if len(args) != 1 {
		s.sendBAD(tag, "Expected: GETQUOTA quota-root")
		return
	}
	if args[0] != quotaRoot(s.userID) {
		// Use one response for unknown and foreign roots so the command cannot
		// become an authenticated account-discovery oracle.
		s.sendNO(tag, "Quota root is unavailable")
		return
	}
	response, err := s.accountQuotaResponse()
	if err != nil {
		s.sendOperationError(tag, "GETQUOTA", err)
		return
	}
	s.sendUntagged(response)
	s.sendOK(tag, "GETQUOTA completed")
}

func (s *Session) cmdGetQuotaRoot(tag string, args []string) {
	if len(args) != 1 {
		s.sendBAD(tag, "Expected: GETQUOTAROOT mailbox")
		return
	}
	mailbox := args[0]
	_, ownerID, err := s.resolveMailbox(mailbox)
	if err != nil {
		if service.IsTemporarilyUnavailable(err) {
			s.sendOperationError(tag, "GETQUOTAROOT", err)
		} else {
			s.sendNO(tag, "Mailbox is unavailable")
		}
		return
	}
	wireMailbox := s.mailboxToWire(mailbox)
	if ownerID != s.userID {
		// A grant to one shared mailbox does not grant visibility into the
		// owner's account-wide quota. An empty root list is valid RFC 9208.
		s.sendUntagged("* QUOTAROOT " + wireMailbox)
		s.sendOK(tag, "GETQUOTAROOT completed")
		return
	}

	wireRoot, err := quoteIMAPString(quotaRoot(s.userID))
	if err != nil {
		s.sendNO(tag, "Quota root is unavailable")
		return
	}
	quotaResponse, err := s.accountQuotaResponse()
	if err != nil {
		s.sendOperationError(tag, "GETQUOTAROOT", err)
		return
	}
	s.sendUntagged(fmt.Sprintf("* QUOTAROOT %s %s", wireMailbox, wireRoot))
	s.sendUntagged(quotaResponse)
	s.sendOK(tag, "GETQUOTAROOT completed")
}

func (s *Session) accountQuotaResponse() (string, error) {
	usage, err := s.cfg.FolderSpace.AccountUsage(*s.ctx, s.access())
	if err != nil {
		return "", err
	}
	if !usage.AccountingReady {
		return "", account.ErrTemporarilyUnavailable
	}

	mailItems := int64(0)
	for _, subtotal := range usage.ByType {
		if subtotal.Type == model.FolderTypeMail {
			mailItems = subtotal.Items
			break
		}
	}
	if mailItems < 0 || usage.Items < mailItems {
		return "", fmt.Errorf("invalid account item accounting")
	}

	resources := ""
	if usage.Quota.MaxItems > 0 {
		// The stored limit spans every folder type. Report the exact number of
		// mail messages that can coexist with current non-mail items, so an IMAP
		// client never receives a larger limit than APPEND can actually use.
		nonMailItems := usage.Items - mailItems
		effectiveLimit := int64(usage.Quota.MaxItems) - nonMailItems
		if effectiveLimit < mailItems {
			effectiveLimit = mailItems
		}
		resources = fmt.Sprintf("MESSAGE %d %d", mailItems, effectiveLimit)
	}
	wireRoot, err := quoteIMAPString(quotaRoot(s.userID))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("* QUOTA %s (%s)", wireRoot, resources), nil
}
