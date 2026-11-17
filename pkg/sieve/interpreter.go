package sieve

import (
	"strconv"
	"strings"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
)

var log = logpkg.For(logpkg.ModuleSieve)

// Interpreter executes a Sieve AST against a Message.
type Interpreter struct {
	msg       *Message
	variables bool
	vars      map[string]string
	matchVars []string

	keep          bool
	implicitKeep  bool
	fileInto      []string
	create        []string
	redirects     []string
	rejects       int
	reject        string
	ereject       bool
	discarded     bool
	vacationRan   bool
	vacation      *VacationResult
	notifications []NotifyResult
}

// NewInterpreter creates an interpreter for the given message.
func NewInterpreter(msg *Message) *Interpreter {
	return &Interpreter{msg: msg}
}

// Run executes the script and returns the resulting actions. A
// *RuntimeError leaves the caller to apply the implicit keep (RFC 5228
// section 2.10.6).
func (i *Interpreter) Run(script *Script) (*Result, error) {
	*i = Interpreter{msg: i.msg, implicitKeep: true, variables: script.Requires["variables"], vars: map[string]string{}}
	log.Debug("sieve: executing script", "commands", len(script.Commands))
	if err := i.block(script.Commands); err != nil {
		if _, stopped := err.(StopError); !stopped {
			log.Debug("sieve: script execution error", "error", err)
			return nil, err
		}
	}
	if i.rejects > 0 && (i.keep || len(i.fileInto) > 0 || len(i.redirects) > 0 || i.vacationRan) {
		return nil, &RuntimeError{Msg: "reject cannot be combined with keep, fileinto, redirect, or vacation"}
	}
	result := &Result{
		Kept:              i.keep || i.implicitKeep,
		ImplicitKeep:      !i.keep && i.implicitKeep,
		FileIntoFolders:   i.fileInto,
		CreateFolders:     i.create,
		RedirectAddresses: i.redirects,
		RejectReason:      i.reject,
		ExtendedReject:    i.ereject,
		Discarded:         i.discarded,
		VacationReply:     i.vacation,
		NotifyRequests:    i.notifications,
	}
	log.Debug("sieve: script result", "file_into", result.FileIntoFolders, "kept", result.Kept, "redirects", len(result.RedirectAddresses), "reject", result.RejectReason != "")
	return result, nil
}

func (i *Interpreter) block(commands []Command) error {
	for _, command := range commands {
		if err := i.execute(command); err != nil {
			return err
		}
	}
	return nil
}

// expand applies variable expansion when the script requires variables.
func (i *Interpreter) expand(s string) string {
	if !i.variables {
		return s
	}
	return expandVariables(s, func(name string) string {
		if isNumber(name) {
			index, err := strconv.Atoi(name)
			if err != nil || index >= len(i.matchVars) {
				return ""
			}
			return i.matchVars[index]
		}
		return i.vars[name]
	})
}

func (i *Interpreter) expandAll(values []string) []string {
	if !i.variables {
		return values
	}
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = i.expand(value)
	}
	return out
}

func (i *Interpreter) execute(command Command) error {
	switch c := command.(type) {
	case *IfCommand:
		for _, branch := range c.Branches {
			if i.test(branch.Test) {
				return i.block(branch.Body)
			}
		}
		return i.block(c.Else)
	case *StopCommand:
		return StopError{}
	case *KeepCommand:
		i.keep = true
	case *DiscardCommand:
		i.implicitKeep, i.discarded = false, true
	case *FileIntoCommand:
		mailbox := i.expand(c.Mailbox)
		if mailbox == "" {
			return &RuntimeError{Msg: "fileinto with an empty mailbox name"}
		}
		if !contains(i.fileInto, mailbox, false) {
			i.fileInto = append(i.fileInto, mailbox)
		}
		if c.Create && !contains(i.create, mailbox, false) {
			i.create = append(i.create, mailbox)
		}
		if !c.Copy {
			i.implicitKeep = false
		}
	case *RedirectCommand:
		address, err := redirectAddress(i.expand(c.Address))
		if err != nil {
			return &RuntimeError{Msg: "invalid redirect address " + strconv.Quote(i.expand(c.Address))}
		}
		if !contains(i.redirects, address, true) {
			if len(i.redirects) >= MaxRedirects {
				return &RuntimeError{Msg: "too many redirects"}
			}
			i.redirects = append(i.redirects, address)
		}
		if !c.Copy {
			i.implicitKeep = false
		}
	case *RejectCommand:
		i.rejects++
		if i.rejects > 1 {
			return &RuntimeError{Msg: "more than one reject"}
		}
		i.reject, i.ereject, i.implicitKeep = i.expand(c.Reason), c.Extended, false
		if strings.TrimSpace(i.reject) == "" {
			i.reject = "Message rejected"
		}
	case *VacationCommand:
		return i.executeVacation(c)
	case *NotifyCommand:
		return i.executeNotify(c)
	case *SetCommand:
		if _, exists := i.vars[c.Name]; !exists && len(i.vars) >= maxVariables {
			return &RuntimeError{Msg: "too many variables"}
		}
		i.vars[c.Name] = truncateUTF8(applySetModifiers(i.expand(c.Value), c.Modifiers), maxVariableLength)
	}
	return nil
}

func contains(values []string, value string, fold bool) bool {
	for _, existing := range values {
		if existing == value || fold && strings.EqualFold(existing, value) {
			return true
		}
	}
	return false
}

func (i *Interpreter) test(test Test) bool {
	switch t := test.(type) {
	case *TrueTest:
		return true
	case *FalseTest:
		return false
	case *NotTest:
		return !i.test(t.Test)
	case *AllOfTest:
		for _, inner := range t.Tests {
			if !i.test(inner) {
				return false
			}
		}
		return true
	case *AnyOfTest:
		for _, inner := range t.Tests {
			if i.test(inner) {
				return true
			}
		}
		return false
	case *SizeTest:
		if t.Over {
			return int64(i.msg.RawSize) > t.Limit
		}
		return int64(i.msg.RawSize) < t.Limit
	case *ExistsTest:
		for _, name := range i.expandAll(t.Headers) {
			if len(i.msg.Headers[strings.ToLower(name)]) == 0 {
				return false
			}
		}
		return true
	case *HeaderTest:
		var values []string
		for _, name := range i.expandAll(t.Headers) {
			for _, value := range i.msg.Headers[strings.ToLower(name)] {
				values = append(values, decodeHeader(value))
			}
		}
		return i.match(t.Matcher, values, len(values), t.Keys)
	case *StringTest:
		sources := i.expandAll(t.Sources)
		count := 0
		for _, source := range sources {
			if source != "" {
				count++
			}
		}
		return i.match(t.Matcher, sources, count, t.Keys)
	case *AddressTest:
		return i.addressTest(t)
	case *ValidNotifyMethodTest:
		for _, uri := range i.expandAll(t.URIs) {
			if _, err := parseMailtoURI(uri); err != nil {
				return false
			}
		}
		return true
	case *MailboxExistsTest:
		for _, name := range i.expandAll(t.Mailboxes) {
			if i.msg.MailboxExists == nil || !i.msg.MailboxExists(name) {
				return false
			}
		}
		return true
	case *NotifyMethodCapabilityTest:
		value, ok := notifyCapability(i.expand(t.URI), i.expand(t.Capability))
		return ok && i.match(t.Matcher, []string{value}, 1, t.Keys)
	}
	return false
}

// match compares values against keys. :count compares the number of
// values with each key; the other match types succeed when any value
// matches any key. A successful :matches sets the match variables.
func (i *Interpreter) match(m Matcher, values []string, count int, keys []string) bool {
	keys = i.expandAll(keys)
	if m.Match == MatchCount {
		counted := strconv.Itoa(count)
		for _, key := range keys {
			if relationHolds(m.Relation, m.order(counted, key)) {
				return true
			}
		}
		return false
	}
	for _, value := range values {
		for _, key := range keys {
			if ok, captures := m.matchValue(value, key); ok {
				if m.Match == MatchMatches && i.variables {
					i.matchVars = captures
				}
				return true
			}
		}
	}
	return false
}

func (i *Interpreter) addressTest(t *AddressTest) bool {
	var addresses []string
	if t.Envelope {
		for _, part := range i.expandAll(t.Headers) {
			switch strings.ToLower(part) {
			case "from":
				addresses = append(addresses, strings.Trim(strings.TrimSpace(i.msg.EnvelopeFrom), "<>"))
			case "to":
				if to := strings.Trim(strings.TrimSpace(i.msg.EnvelopeTo), "<>"); to != "" {
					addresses = append(addresses, to)
				}
			}
		}
	} else {
		for _, name := range i.expandAll(t.Headers) {
			name = strings.ToLower(name)
			if !addressHeaders[name] {
				continue
			}
			for _, value := range i.msg.Headers[name] {
				addresses = append(addresses, parseAddressList(value)...)
			}
		}
	}
	if t.Match == MatchCount {
		return i.match(t.Matcher, nil, len(addresses), t.Keys)
	}
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if address == "" {
			// RFC 5228 section 5.4: the null reverse-path compares as the
			// empty string whatever the address part.
			values = append(values, "")
			continue
		}
		if value, ok := addressPart(address, t.Part, i.msg.SubaddressDelimiters); ok {
			values = append(values, value)
		}
	}
	return i.match(t.Matcher, values, len(values), t.Keys)
}
