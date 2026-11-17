package main

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/smtp"
)

// Mail flow rules (pkg/model/mailflow.go) are read from their stores for
// every message, so administrative changes apply to the next message.
const (
	// mailKindBCC and mailKindJournal mark administrative copies. Copies are
	// never copied again, rewritten, scored, or counted by the send guard.
	mailKindBCC     = "bcc"
	mailKindJournal = "journal"
	// attributeAddressRewrite records the rewrites applied at admission and
	// keeps a message from being rewritten twice.
	attributeAddressRewrite = "address_rewrite"
)

// secretOpener opens credentials sealed with the installation's stored
// credential keys; migration.Store implements it.
type secretOpener interface {
	OpenSecret(purpose, id string, sealed []byte) ([]byte, error)
}

// queueAdmission rewrites locally originated mail, adds Autocrypt headers,
// then applies mail policy, so policy and the DKIM signature that follows see
// the final message.
func (s *server) queueAdmission() func(context.Context, *queue.Message) error {
	policy := mailPolicyAdmission(s.mailPolicies)
	return func(ctx context.Context, message *queue.Message) error {
		if err := s.rewriteOutbound(ctx, message); err != nil {
			return err
		}
		if err := s.addAutocrypt(ctx, message); err != nil {
			return err
		}
		return policy(ctx, message)
	}
}

// rewriteOutbound applies outbound address rewriting once to mail a local
// account submitted or the server wrote (it carries a DKIM request).
func (s *server) rewriteOutbound(ctx context.Context, message *queue.Message) error {
	if message == nil || message.Kind == smtp.MailTaskQuarantine || message.AuthenticatedActor == "" && message.DKIM == nil || message.Attributes[attributeAddressRewrite] != "" {
		return nil
	}
	rules, err := s.ts.AddressRewriteStore().List(ctx)
	if err != nil {
		return fmt.Errorf("address rewriting: %w", err)
	}
	var changes []string
	if rewritten, ok := model.RewriteAddress(rules, model.RewriteOutbound, message.EnvelopeSender, func(rule model.AddressRewrite) bool { return rule.EnvelopeSender }); ok {
		changes = append(changes, "envelope "+message.EnvelopeSender+" > "+rewritten)
		message.EnvelopeSender = rewritten
	}
	from := queueHeader(message.Headers, "From")
	if address, parseErr := mail.ParseAddress(from); parseErr == nil {
		if rewritten, ok := model.RewriteAddress(rules, model.RewriteOutbound, address.Address, func(rule model.AddressRewrite) bool { return rule.HeaderFrom }); ok {
			at := strings.Index(strings.ToLower(from), strings.ToLower(address.Address))
			value := from[:at] + rewritten + from[at+len(address.Address):]
			setQueueHeader(message.Headers, "From", value)
			if len(message.Content) > 0 {
				message.Content = model.ReplaceHeaderField(message.Content, "From", value)
			}
			changes = append(changes, "from "+address.Address+" > "+rewritten)
		}
	}
	if len(changes) == 0 {
		return nil
	}
	if message.Attributes == nil {
		message.Attributes = make(map[string]string)
	}
	message.Attributes[attributeAddressRewrite] = strings.Join(changes, "; ")
	log.Info("mail flow: address rewritten", "id", message.ID, "changes", message.Attributes[attributeAddressRewrite])
	return nil
}

// rewriteRecipient applies inbound address rewriting (masquerading) to an
// envelope recipient. Rules never chain, so applying it again is harmless.
func (s *server) rewriteRecipient(ctx context.Context, address string) (string, error) {
	rules, err := s.ts.AddressRewriteStore().List(ctx)
	if err != nil {
		return "", fmt.Errorf("address rewriting: %w", err)
	}
	rewritten, ok := model.RewriteAddress(rules, model.RewriteInbound, address, nil)
	if ok {
		log.Debug("mail flow: recipient rewritten", "recipient", address, "rewritten", rewritten)
	}
	return rewritten, nil
}

// mailFlowCopies implements queue.Config.Copies: the always-BCC and journal
// copies of each message group (one SMTP transaction or submission) in a
// batch. Administrative copies and derived mail are never copied; journal
// copies list every envelope recipient, BCC copies included.
func (s *server) mailFlowCopies(ctx context.Context, batch []*queue.Message) ([]*queue.Message, error) {
	bccRules, err := s.ts.BCCRuleStore().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("always-BCC rules: %w", err)
	}
	journalRules, err := s.ts.JournalRuleStore().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("journal rules: %w", err)
	}
	if len(bccRules) == 0 && len(journalRules) == 0 {
		return nil, nil
	}
	var order []string
	groups := make(map[string][]*queue.Message)
	for _, message := range batch {
		if message.Kind != "" && message.Kind != smtp.MailTaskQuarantine {
			continue
		}
		if _, seen := groups[message.CorrelationID]; !seen {
			order = append(order, message.CorrelationID)
		}
		groups[message.CorrelationID] = append(groups[message.CorrelationID], message)
	}
	var copies []*queue.Message
	for _, id := range order {
		group := groups[id]
		bcc := bccCopies(bccRules, group)
		journal, err := s.journalCopies(ctx, journalRules, group, bcc)
		if err != nil {
			return nil, err
		}
		copies = append(append(copies, bcc...), journal...)
	}
	return copies, nil
}

// bccCopies returns one copy per distinct always-BCC address of a group's
// sender and recipients that is not already a recipient. Copies keep the
// sender and any hold of their original, and never return a notification.
func bccCopies(rules []model.BCCRule, group []*queue.Message) []*queue.Message {
	recipients := make(map[string]bool)
	for _, message := range group {
		recipients[strings.ToLower(message.Recipient)] = true
	}
	var copies []*queue.Message
	add := func(source *queue.Message, addresses []string) {
		for _, address := range addresses {
			if recipients[address] {
				continue
			}
			recipients[address] = true
			copied := &queue.Message{ID: source.ID + ".bcc" + strconv.Itoa(len(copies)+1), Kind: mailKindBCC, ParentID: source.ID,
				CorrelationID: source.CorrelationID, Direction: source.Direction, EnvelopeSender: source.EnvelopeSender, Recipient: address,
				Headers: maps.Clone(source.Headers), Content: append([]byte(nil), source.RawMessage()...),
				Attributes: map[string]string{"dsn_notify": "never"}, AuthenticatedActor: source.AuthenticatedActor, SourceIP: source.SourceIP,
				Status: source.Status, HoldReason: source.HoldReason, HeldAt: source.HeldAt}
			copies = append(copies, copied)
		}
	}
	for index, message := range group {
		if message.Kind != "" {
			continue
		}
		if index == 0 {
			add(message, model.BCCAddresses(rules, model.BCCSender, message.EnvelopeSender))
		}
		add(message, model.BCCAddresses(rules, model.BCCRecipient, message.Recipient))
	}
	return copies
}

// journalCopies returns one journal copy per distinct journal address whose
// rule matches the group. Mail addressed only to journal addresses is never
// journaled, so a journal copy that comes back is not journaled again.
func (s *server) journalCopies(ctx context.Context, rules []model.JournalRule, group, bcc []*queue.Message) ([]*queue.Message, error) {
	journalAddresses := make(map[string]bool)
	for _, rule := range rules {
		journalAddresses[rule.Address] = true
	}
	first, submitted, onlyJournal := group[0], false, true
	var recipients, localDomains []string
	hosted := make(map[string]bool)
	for _, message := range append(append([]*queue.Message(nil), group...), bcc...) {
		recipient := strings.ToLower(message.Recipient)
		recipients = append(recipients, message.Recipient)
		submitted = submitted || message.AuthenticatedActor != ""
		if message.Kind != mailKindBCC {
			onlyJournal = onlyJournal && journalAddresses[recipient]
		}
		domain := recipientDomain(recipient)
		if _, checked := hosted[domain]; checked || domain == "" {
			continue
		}
		local, err := s.isHostedDomain(ctx, domain)
		if err != nil {
			return nil, fmt.Errorf("journal rules: %w", err)
		}
		if hosted[domain] = local; local {
			localDomains = append(localDomains, domain)
		}
	}
	if onlyJournal {
		return nil, nil
	}
	direction := string(queue.DirectionInbound)
	if submitted {
		direction = string(queue.DirectionOutbound)
	}
	reportDomain := s.systemMailDomain()
	if reportDomain == "" {
		reportDomain = strings.ToLower(s.smtpServerName())
	}
	var copies []*queue.Message
	journaled := make(map[string]bool)
	for _, rule := range rules {
		if journaled[rule.Address] || !rule.Matches(submitted, recipientDomain(first.EnvelopeSender), localDomains) {
			continue
		}
		journaled[rule.Address] = true
		data := smtp.BuildJournalMessage(smtp.JournalRequest{Format: rule.Format, From: "Journal <postmaster@" + reportDomain + ">", To: rule.Address,
			ServerName: s.smtpServerName(), ID: first.ID, Direction: direction, Sender: first.EnvelopeSender, Recipients: recipients,
			Original: first.RawMessage()}, time.Now())
		headers, _ := model.ParseMessageHeaders(data)
		copies = append(copies, &queue.Message{ID: first.ID + ".journal" + strconv.Itoa(len(copies)+1), Kind: mailKindJournal, ParentID: first.ID,
			CorrelationID: first.CorrelationID, Direction: first.Direction, Recipient: rule.Address, Headers: headers, Content: data,
			Attributes: map[string]string{"dsn_notify": "never", "journal_rule": rule.ID}})
	}
	return copies, nil
}

// senderRoute selects the sender-dependent route for an outbound message.
func (s *server) senderRoute(ctx context.Context, message *queue.Message) (model.SenderRoute, bool, error) {
	routes, err := s.ts.SenderRouteStore().List(ctx)
	if err != nil {
		return model.SenderRoute{}, false, err
	}
	route, ok := model.SelectSenderRoute(routes, message.EnvelopeSender, message.AuthenticatedActor, recipientDomain(message.Recipient))
	return route, ok, nil
}

// deliverSenderRoute sends message through a sender-dependent route with
// its sealed relay credential, opened only for this delivery.
func (s *server) deliverSenderRoute(ctx context.Context, message *queue.Message, route model.SenderRoute) error {
	target := smtp.RelayConfig{RequireTLS: route.RequireTLS, TLSSkipVerify: route.TLSSkipVerify}
	if route.Transport == model.OutboundTransportMX {
		target.Port = 25
		queue.RecordDeliveryRoute(ctx, "sender-mx:"+route.ID)
	} else {
		target.Host, target.Port = route.RelayHost, route.RelayPort
		queue.RecordDeliveryRoute(ctx, "sender-relay:"+route.ID+":"+net.JoinHostPort(route.RelayHost, strconv.Itoa(route.RelayPort)))
	}
	if len(route.SealedPassword) > 0 {
		if s.routeSecrets == nil {
			return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "relay credential store is unavailable"}
		}
		password, err := s.routeSecrets.OpenSecret(model.SenderRouteSecretPurpose, route.ID, route.SealedPassword)
		if err != nil {
			return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "relay credential cannot be opened", Err: err}
		}
		target.Username, target.Password = route.Username, string(password)
	}
	return s.relay(ctx, s.outboundClient(target), message)
}

// senderRouteRelays reports whether an enabled sender route could carry
// mail to recipient, which makes it a relayable destination for
// authenticated submission.
func (s *server) senderRouteRelays(ctx context.Context, recipient string) bool {
	routes, err := s.ts.SenderRouteStore().List(ctx)
	if err != nil {
		return false
	}
	domain := recipientDomain(recipient)
	for _, route := range routes {
		if route.Enabled && (route.Destination == "" || route.Destination == domain) {
			return true
		}
	}
	return false
}
