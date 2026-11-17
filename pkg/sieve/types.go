// Package sieve implements a Sieve script parser and interpreter (RFC 5228).
//
// It provides server-side mail filtering: parse a Sieve script into an AST,
// then run the AST against incoming messages to decide delivery actions.
//
// Besides the base language the package implements the extensions listed
// in Extensions; scripts that require anything else are rejected at parse
// time, so ManageSieve CHECKSCRIPT and PUTSCRIPT refuse them.
package sieve

import (
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// Extensions are the capability strings a script may require, in the order
// ManageSieve advertises them. The base comparators "comparator-i;octet"
// and "comparator-i;ascii-casemap" may also be required but are not listed,
// as RFC 5228 makes them implicit.
var Extensions = []string{
	"fileinto", "reject", "ereject", "envelope", "encoded-character",
	"variables", "vacation", "vacation-seconds", "relational",
	"comparator-i;ascii-numeric", "subaddress", "copy", "enotify",
	"mailbox",
}

// NotifyMethods are the RFC 5435 notification methods supported, advertised
// as the ManageSieve NOTIFY capability.
var NotifyMethods = []string{"mailto"}

// Capabilities is the space-separated SIEVE capability string (RFC 5804).
var Capabilities = strings.Join(Extensions, " ")

// MaxRedirects bounds the redirect actions one script run may perform; it is
// advertised as the ManageSieve MAXREDIRECTS capability.
const MaxRedirects = 32

var supportedExtensions = func() map[string]bool {
	set := map[string]bool{"comparator-i;octet": true, "comparator-i;ascii-casemap": true}
	for _, extension := range Extensions {
		set[extension] = true
	}
	return set
}()

// --- AST ---

// Command is an executable Sieve command.
type Command interface{ isCommand() }

// Test is a Sieve test.
type Test interface{ isTest() }

// Script is a parsed script: its commands and the capabilities it requires.
type Script struct {
	Commands []Command
	Requires map[string]bool
}

// IfCommand is an if/elsif/else chain.
type IfCommand struct {
	Branches []Branch
	Else     []Command
}

// Branch is one if or elsif condition with its block.
type Branch struct {
	Test Test
	Body []Command
}

// RequireCommand declares required extensions (RFC 5228 section 3.2).
type RequireCommand struct{ Capabilities []string }

// StopCommand ends script processing.
type StopCommand struct{}

// KeepCommand files the message into the default mailbox.
type KeepCommand struct{}

// DiscardCommand cancels the implicit keep.
type DiscardCommand struct{}

// FileIntoCommand files the message into Mailbox (RFC 5228 section 4.1);
// Copy (RFC 3894) keeps the implicit keep; Create (RFC 5490 section 3.2)
// asks for the mailbox to be created when it does not exist.
type FileIntoCommand struct {
	Mailbox string
	Copy    bool
	Create  bool
}

// RedirectCommand forwards the message to Address (RFC 5228 section 4.2);
// Copy (RFC 3894) keeps the implicit keep.
type RedirectCommand struct {
	Address string
	Copy    bool
}

// RejectCommand refuses the message (RFC 5429). Extended is ereject.
type RejectCommand struct {
	Reason   string
	Extended bool
}

// VacationCommand sends an auto-reply (RFC 5230, RFC 6131 :seconds).
type VacationCommand struct {
	Days       int64
	Seconds    int64
	HasDays    bool
	HasSeconds bool
	Subject    string
	From       string
	Addresses  []string
	Mime       bool
	Handle     string
	Reason     string
}

// NotifyCommand sends a notification (RFC 5435) through Method, a mailto
// URI (RFC 5436).
type NotifyCommand struct {
	From       string
	Importance string
	Options    []string
	Message    string
	Method     string
}

// SetCommand assigns a variable (RFC 5229 section 4).
type SetCommand struct {
	Name      string
	Value     string
	Modifiers []string // applied in this order
}

func (*IfCommand) isCommand()       {}
func (*RequireCommand) isCommand()  {}
func (*StopCommand) isCommand()     {}
func (*KeepCommand) isCommand()     {}
func (*DiscardCommand) isCommand()  {}
func (*FileIntoCommand) isCommand() {}
func (*RedirectCommand) isCommand() {}
func (*RejectCommand) isCommand()   {}
func (*VacationCommand) isCommand() {}
func (*SetCommand) isCommand()      {}
func (*NotifyCommand) isCommand()   {}

// MatchType is a match-type tag (RFC 5228 section 2.7.1, RFC 5231).
type MatchType int

const (
	MatchIs MatchType = iota
	MatchContains
	MatchMatches
	MatchValue
	MatchCount
)

// Comparator names (RFC 4790).
const (
	ComparatorOctet        = "i;octet"
	ComparatorASCIICasemap = "i;ascii-casemap"
	ComparatorASCIINumeric = "i;ascii-numeric"
)

// Matcher combines a match type, its relational operator (:value and
// :count), and a comparator.
type Matcher struct {
	Match      MatchType
	Relation   string // "gt", "ge", "lt", "le", "eq", or "ne"
	Comparator string
}

// AddressPart selects the part of an address that is compared.
type AddressPart int

const (
	PartAll AddressPart = iota
	PartLocalPart
	PartDomain
	PartUser   // RFC 5233
	PartDetail // RFC 5233
)

// AddressTest is the address test, or the envelope test when Envelope is
// set (RFC 5228 sections 5.1 and 5.4).
type AddressTest struct {
	Matcher
	Envelope bool
	Part     AddressPart
	Headers  []string // header names, or envelope parts
	Keys     []string
}

// HeaderTest is the header test (RFC 5228 section 5.7).
type HeaderTest struct {
	Matcher
	Headers []string
	Keys    []string
}

// StringTest is the variables string test (RFC 5229 section 5).
type StringTest struct {
	Matcher
	Sources []string
	Keys    []string
}

// ValidNotifyMethodTest is true when every URI names a usable
// notification method (RFC 5435 section 5).
type ValidNotifyMethodTest struct{ URIs []string }

// MailboxExistsTest is true when every named mailbox exists and the
// message may be filed into it (RFC 5490 section 3.1).
type MailboxExistsTest struct{ Mailboxes []string }

// NotifyMethodCapabilityTest compares a capability of a notification method
// with Keys (RFC 5435 section 6).
type NotifyMethodCapabilityTest struct {
	Matcher
	URI        string
	Capability string
	Keys       []string
}

// ExistsTest is true when every named header exists.
type ExistsTest struct{ Headers []string }

// SizeTest compares the message size with Limit.
type SizeTest struct {
	Over  bool
	Limit int64
}

// NotTest inverts Test.
type NotTest struct{ Test Test }

// AllOfTest is true when every test is true; evaluation short-circuits.
type AllOfTest struct{ Tests []Test }

// AnyOfTest is true when one test is true; evaluation short-circuits.
type AnyOfTest struct{ Tests []Test }

// TrueTest is always true.
type TrueTest struct{}

// FalseTest is always false.
type FalseTest struct{}

func (*AddressTest) isTest()                {}
func (*HeaderTest) isTest()                 {}
func (*StringTest) isTest()                 {}
func (*ExistsTest) isTest()                 {}
func (*SizeTest) isTest()                   {}
func (*NotTest) isTest()                    {}
func (*AllOfTest) isTest()                  {}
func (*AnyOfTest) isTest()                  {}
func (*TrueTest) isTest()                   {}
func (*FalseTest) isTest()                  {}
func (*ValidNotifyMethodTest) isTest()      {}
func (*NotifyMethodCapabilityTest) isTest() {}
func (*MailboxExistsTest) isTest()          {}

// --- Message ---

// Message represents an incoming email message for filtering.
type Message struct {
	Headers map[string][]string // header name (lowercase) -> raw values
	Body    []byte              // raw message
	RawSize int                 // total size of the message in octets

	// EnvelopeFrom and EnvelopeTo are the SMTP envelope sender (empty for
	// the null sender) and the recipient being delivered to.
	EnvelopeFrom string
	EnvelopeTo   string
	// SubaddressDelimiters separate :user from :detail (RFC 5233); each
	// character is a delimiter. Empty disables subaddress detail.
	SubaddressDelimiters string
	// MailboxExists reports whether the recipient has a mailbox of this
	// name that fileinto may deliver to, for the mailboxexists test. Nil
	// makes every mailbox count as missing.
	MailboxExists func(name string) bool
}

// NewMessage creates a Message from raw message bytes.
func NewMessage(raw []byte) *Message {
	return &Message{
		Headers: model.ParseHeaderValues(raw),
		Body:    raw,
		RawSize: len(raw),
	}
}

// --- Execution result ---

// Result holds the actions a script run decided on.
type Result struct {
	// Kept means the message is filed into the default mailbox, by an
	// explicit keep or by the implicit keep.
	Kept bool
	// ImplicitKeep reports that Kept comes from the implicit keep only.
	ImplicitKeep bool
	// FileIntoFolders are the mailboxes named by fileinto, without
	// duplicates, in execution order.
	FileIntoFolders []string
	// CreateFolders are the FileIntoFolders named with :create (RFC 5490),
	// which the caller creates when they do not exist.
	CreateFolders []string
	// RedirectAddresses are external addresses to forward the message to.
	RedirectAddresses []string
	// RejectReason, if non-empty, refuses the message with this reason;
	// ExtendedReject reports that it came from ereject.
	RejectReason   string
	ExtendedReject bool
	// Discarded reports an executed discard.
	Discarded bool
	// NotifyRequests are notifications to send (RFC 5435, RFC 5436).
	NotifyRequests []NotifyResult
	// VacationReply, if set, is an auto-reply to send (RFC 5230). It is nil
	// when vacation ran but RFC 5230 forbids replying to this message.
	VacationReply *VacationResult
}

// NotifyResult is one mailto notification (RFC 5436).
type NotifyResult struct {
	Method     string   // the notification URI
	To         []string // recipient addr-specs from the URI
	From       string   // :from, or empty for the user's address
	Subject    string
	Message    string // notification body
	Importance string // "1" (high), "2" (normal), or "3" (low)
}

// VacationResult holds a vacation auto-reply (RFC 5230).
type VacationResult struct {
	Subject    string // decoded text; the caller encodes it for the header
	Body       string
	Mime       bool   // Body is a MIME entity with its own header fields
	From       string // reply author; empty lets the caller choose
	To         string // envelope sender of the original message
	MessageID  string // original Message-ID for In-Reply-To
	References string // References for the reply, ending with MessageID
	// Handle and Period drive response tracking: one reply per sender and
	// handle within Period.
	Handle string
	Period time.Duration
}

// TrackingKey identifies the response-tracking record for this reply.
func (v *VacationResult) TrackingKey() string {
	return "sieve:" + v.Handle + ":" + strings.ToLower(v.To)
}

// ContentHeaders returns the MIME header fields and the body of the reply.
// A :mime reason supplies its own Content-* fields; a plain reason is sent
// as UTF-8 text.
func (v *VacationResult) ContentHeaders() (map[string]string, []byte) {
	headers := map[string]string{"MIME-Version": "1.0"}
	if !v.Mime {
		headers["Content-Type"] = "text/plain; charset=utf-8"
		headers["Content-Transfer-Encoding"] = "8bit"
		return headers, []byte(v.Body)
	}
	fields, body := model.ParseMessageHeaders([]byte(v.Body))
	for name, value := range fields {
		if strings.HasPrefix(strings.ToLower(name), "content-") {
			headers[name] = value
		}
	}
	if _, ok := headers["Content-Type"]; !ok {
		headers["Content-Type"] = "text/plain; charset=us-ascii"
	}
	return headers, body
}

// StopError is returned internally when a stop command is executed.
type StopError struct{}

func (StopError) Error() string { return "sieve: stop" }

// RuntimeError is a script failure while running; RFC 5228 section 2.10.6
// requires the caller to fall back to the implicit keep.
type RuntimeError struct{ Msg string }

func (e *RuntimeError) Error() string { return "sieve runtime error: " + e.Msg }

// ParseError is returned when the Sieve script cannot be parsed or uses a
// capability it did not require or that is not supported.
type ParseError struct {
	Line   int
	Column int
	Msg    string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("sieve parse error at line %d col %d: %s", e.Line, e.Column, e.Msg)
}
