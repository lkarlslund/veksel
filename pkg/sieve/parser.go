package sieve

import (
	"fmt"
	"net/mail"
	"slices"
	"strings"
)

// maxNesting bounds nested blocks and tests so a hostile script cannot
// exhaust the stack of the recursive parser or interpreter.
const maxNesting = 64

// --- Generic syntax (RFC 5228 section 8.2) ---

type argKind int

const (
	argStrings argKind = iota
	argNumber
	argTag
)

type rawArg struct {
	kind      argKind
	strs      []string
	list      bool // written as a bracketed string list
	num       int64
	tag       string
	line, col int
}

type rawTest struct {
	name      string
	args      []rawArg
	tests     []*rawTest
	testList  bool
	line, col int
}

type rawCommand struct {
	name      string
	args      []rawArg
	tests     []*rawTest
	testList  bool
	block     []*rawCommand
	hasBlock  bool
	line, col int
}

// Parser parses a Sieve script into an AST.
type Parser struct {
	tokens []Token
	pos    int
	depth  int
}

// NewParser tokenizes input and returns a parser for it.
func NewParser(input string) (*Parser, error) {
	tokens, err := Tokenize(input)
	if err != nil {
		return nil, err
	}
	return &Parser{tokens: tokens}, nil
}

// Parse parses and validates a script in one step.
func Parse(input string) (*Script, error) {
	p, err := NewParser(input)
	if err != nil {
		return nil, err
	}
	return p.Parse()
}

func (p *Parser) cur() Token { return p.tokens[p.pos] }

func (p *Parser) advance() Token {
	tok := p.tokens[p.pos]
	if tok.Type != TokEOF {
		p.pos++
	}
	return tok
}

func errorAt(line, col int, format string, args ...any) error {
	return &ParseError{Line: line, Column: col, Msg: fmt.Sprintf(format, args...)}
}

func (p *Parser) unexpected(want string) error {
	tok := p.cur()
	got := tok.Type.String()
	if tok.Type == TokIdent || tok.Type == TokTag {
		got += " " + tok.Value
	}
	return errorAt(tok.Line, tok.Col, "expected %s, got %s", want, got)
}

func (p *Parser) expect(typ TokenType) error {
	if p.cur().Type != typ {
		return p.unexpected(typ.String())
	}
	p.advance()
	return nil
}

func (p *Parser) enter() error {
	p.depth++
	if p.depth > maxNesting {
		tok := p.cur()
		return errorAt(tok.Line, tok.Col, "nesting deeper than %d levels", maxNesting)
	}
	return nil
}

// Parse parses the script, checks its require declarations and the
// arguments of every command and test, and returns the AST.
func (p *Parser) Parse() (*Script, error) {
	commands, err := p.commands(true)
	if err != nil {
		return nil, err
	}
	return compile(commands)
}

func (p *Parser) commands(top bool) ([]*rawCommand, error) {
	var out []*rawCommand
	for {
		switch tok := p.cur(); {
		case top && tok.Type == TokEOF, !top && tok.Type == TokRBrace:
			return out, nil
		case tok.Type != TokIdent:
			return nil, p.unexpected("command")
		}
		command, err := p.command()
		if err != nil {
			return nil, err
		}
		out = append(out, command)
	}
}

func (p *Parser) command() (*rawCommand, error) {
	tok := p.advance()
	command := &rawCommand{name: tok.Value, line: tok.Line, col: tok.Col}
	var err error
	if command.args, command.tests, command.testList, err = p.arguments(); err != nil {
		return nil, err
	}
	switch p.cur().Type {
	case TokSemicolon:
		p.advance()
	case TokLBrace:
		p.advance()
		if err := p.enter(); err != nil {
			return nil, err
		}
		if command.block, err = p.commands(false); err != nil {
			return nil, err
		}
		p.depth--
		if err := p.expect(TokRBrace); err != nil {
			return nil, err
		}
		command.hasBlock = true
	default:
		return nil, p.unexpected(`";" or "{"`)
	}
	return command, nil
}

func (p *Parser) arguments() (args []rawArg, tests []*rawTest, testList bool, err error) {
	for {
		tok := p.cur()
		arg := rawArg{line: tok.Line, col: tok.Col}
		switch tok.Type {
		case TokString:
			p.advance()
			arg.kind, arg.strs = argStrings, []string{tok.Value}
		case TokLBracket:
			p.advance()
			arg.kind, arg.list = argStrings, true
			for {
				if p.cur().Type != TokString {
					return nil, nil, false, p.unexpected("string")
				}
				arg.strs = append(arg.strs, p.advance().Value)
				if p.cur().Type != TokComma {
					break
				}
				p.advance()
			}
			if err := p.expect(TokRBracket); err != nil {
				return nil, nil, false, err
			}
		case TokNumber:
			p.advance()
			arg.kind, arg.num = argNumber, tok.Num
		case TokTag:
			p.advance()
			arg.kind, arg.tag = argTag, tok.Value
		default:
			switch tok.Type {
			case TokIdent:
				test, err := p.test()
				if err != nil {
					return nil, nil, false, err
				}
				return args, []*rawTest{test}, false, nil
			case TokLParen:
				p.advance()
				if err := p.enter(); err != nil {
					return nil, nil, false, err
				}
				for {
					test, err := p.test()
					if err != nil {
						return nil, nil, false, err
					}
					tests = append(tests, test)
					if p.cur().Type != TokComma {
						break
					}
					p.advance()
				}
				p.depth--
				if err := p.expect(TokRParen); err != nil {
					return nil, nil, false, err
				}
				return args, tests, true, nil
			}
			return args, nil, false, nil
		}
		args = append(args, arg)
	}
}

func (p *Parser) test() (*rawTest, error) {
	tok := p.cur()
	if tok.Type != TokIdent {
		return nil, p.unexpected("test")
	}
	p.advance()
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	test := &rawTest{name: tok.Value, line: tok.Line, col: tok.Col}
	var err error
	test.args, test.tests, test.testList, err = p.arguments()
	return test, err
}

// --- Semantic checks and AST construction ---

type compiler struct {
	requires map[string]bool
}

func compile(commands []*rawCommand) (*Script, error) {
	c := &compiler{requires: make(map[string]bool)}
	index := 0
	for ; index < len(commands) && commands[index].name == "require"; index++ {
		command := commands[index]
		if len(command.tests) > 0 || command.hasBlock {
			return nil, errorAt(command.line, command.col, "require takes only a capability list")
		}
		args := c.argList(command.name, command.line, command.col, command.args)
		capabilities, err := args.strList("capability list")
		if err != nil {
			return nil, err
		}
		if err := args.end(); err != nil {
			return nil, err
		}
		for _, capability := range capabilities {
			if !supportedExtensions[capability] {
				return nil, errorAt(command.line, command.col, "unsupported extension %q", capability)
			}
			c.requires[capability] = true
		}
	}
	body, err := c.block(commands[index:])
	if err != nil {
		return nil, err
	}
	return &Script{Commands: body, Requires: c.requires}, nil
}

func (c *compiler) need(extension string, line, col int, what string) error {
	if !c.requires[extension] {
		return errorAt(line, col, "%s requires the %q extension", what, extension)
	}
	return nil
}

func (c *compiler) block(commands []*rawCommand) ([]Command, error) {
	var out []Command
	var chain *IfCommand // the if command an elsif or else may extend
	for _, command := range commands {
		switch command.name {
		case "if", "elsif", "else":
			if command.name != "if" && chain == nil {
				return nil, errorAt(command.line, command.col, "%s without a preceding if", command.name)
			}
			if !command.hasBlock || len(command.args) > 0 {
				return nil, errorAt(command.line, command.col, "%s takes a test and a block", command.name)
			}
			body, err := c.block(command.block)
			if err != nil {
				return nil, err
			}
			if command.name == "else" {
				if len(command.tests) > 0 {
					return nil, errorAt(command.line, command.col, "else takes no test")
				}
				chain.Else, chain = body, nil
				continue
			}
			if len(command.tests) != 1 || command.testList {
				return nil, errorAt(command.line, command.col, "%s takes exactly one test", command.name)
			}
			test, err := c.test(command.tests[0])
			if err != nil {
				return nil, err
			}
			if command.name == "if" {
				chain = &IfCommand{}
				out = append(out, chain)
			}
			chain.Branches = append(chain.Branches, Branch{Test: test, Body: body})
			continue
		}
		chain = nil
		if command.hasBlock || len(command.tests) > 0 {
			return nil, errorAt(command.line, command.col, "%s takes no test or block", command.name)
		}
		compiled, err := c.command(command)
		if err != nil {
			return nil, err
		}
		out = append(out, compiled)
	}
	return out, nil
}

func (c *compiler) command(command *rawCommand) (Command, error) {
	line, col := command.line, command.col
	args := c.argList(command.name, line, col, command.args)
	switch command.name {
	case "require":
		return nil, errorAt(line, col, "require must come before any other command")
	case "stop", "keep", "discard":
		if err := args.end(); err != nil {
			return nil, err
		}
		switch command.name {
		case "stop":
			return &StopCommand{}, nil
		case "keep":
			return &KeepCommand{}, nil
		}
		return &DiscardCommand{}, nil
	case "fileinto", "redirect":
		if command.name == "fileinto" {
			if err := c.need("fileinto", line, col, "fileinto"); err != nil {
				return nil, err
			}
		}
		copied, create := false, false
		for tag, ok := args.nextTag(); ok; tag, ok = args.nextTag() {
			switch {
			case tag.tag == "copy" && !copied:
				if err := c.need("copy", tag.line, tag.col, ":copy"); err != nil {
					return nil, err
				}
				copied = true
			case tag.tag == "create" && !create && command.name == "fileinto":
				if err := c.need("mailbox", tag.line, tag.col, ":create"); err != nil {
					return nil, err
				}
				create = true
			default:
				return nil, errorAt(tag.line, tag.col, "unexpected tag :%s for %s", tag.tag, command.name)
			}
		}
		target, err := args.str(command.name + " target")
		if err != nil {
			return nil, err
		}
		if err := args.end(); err != nil {
			return nil, err
		}
		if command.name == "fileinto" {
			if target == "" {
				return nil, errorAt(line, col, "fileinto needs a mailbox name")
			}
			return &FileIntoCommand{Mailbox: target, Copy: copied, Create: create}, nil
		}
		if !c.hasVariables(target) {
			if _, err := redirectAddress(target); err != nil {
				return nil, errorAt(line, col, "invalid redirect address %q", target)
			}
		}
		return &RedirectCommand{Address: target, Copy: copied}, nil
	case "reject", "ereject":
		if err := c.need(command.name, line, col, command.name); err != nil {
			return nil, err
		}
		reason, err := args.str("reason")
		if err != nil {
			return nil, err
		}
		if err := args.end(); err != nil {
			return nil, err
		}
		return &RejectCommand{Reason: reason, Extended: command.name == "ereject"}, nil
	case "vacation":
		return c.vacation(args)
	case "set":
		return c.set(args)
	case "notify":
		return c.notify(args)
	}
	return nil, errorAt(line, col, "unknown command %q", command.name)
}

func (c *compiler) vacation(args *argList) (Command, error) {
	if err := c.need("vacation", args.line, args.col, "vacation"); err != nil {
		return nil, err
	}
	v := &VacationCommand{}
	seen := map[string]bool{}
	for tag, ok := args.nextTag(); ok; tag, ok = args.nextTag() {
		if seen[tag.tag] {
			return nil, errorAt(tag.line, tag.col, "duplicate tag :%s", tag.tag)
		}
		seen[tag.tag] = true
		var err error
		switch tag.tag {
		case "days":
			v.HasDays = true
			v.Days, err = args.num(":days")
		case "seconds":
			if err = c.need("vacation-seconds", tag.line, tag.col, ":seconds"); err == nil {
				v.HasSeconds = true
				v.Seconds, err = args.num(":seconds")
			}
		case "subject":
			v.Subject, err = args.str(":subject")
		case "from":
			if v.From, err = args.str(":from"); err == nil && !c.hasVariables(v.From) {
				if _, parseErr := mail.ParseAddress(v.From); parseErr != nil {
					err = errorAt(tag.line, tag.col, "invalid :from address %q", v.From)
				}
			}
		case "addresses":
			v.Addresses, err = args.strList(":addresses")
		case "mime":
			v.Mime = true
		case "handle":
			v.Handle, err = args.str(":handle")
		default:
			err = errorAt(tag.line, tag.col, "unexpected tag :%s for vacation", tag.tag)
		}
		if err != nil {
			return nil, err
		}
	}
	if v.HasDays && v.HasSeconds {
		return nil, errorAt(args.line, args.col, "vacation takes :days or :seconds, not both")
	}
	var err error
	if v.Reason, err = args.str("vacation reason"); err != nil {
		return nil, err
	}
	return v, args.end()
}

func (c *compiler) notify(args *argList) (Command, error) {
	if err := c.need("enotify", args.line, args.col, "notify"); err != nil {
		return nil, err
	}
	n := &NotifyCommand{}
	seen := map[string]bool{}
	for tag, ok := args.nextTag(); ok; tag, ok = args.nextTag() {
		if seen[tag.tag] {
			return nil, errorAt(tag.line, tag.col, "duplicate tag :%s", tag.tag)
		}
		seen[tag.tag] = true
		var err error
		switch tag.tag {
		case "from":
			if n.From, err = args.str(":from"); err == nil && !c.hasVariables(n.From) {
				if _, parseErr := mail.ParseAddress(n.From); parseErr != nil {
					err = errorAt(tag.line, tag.col, "invalid :from address %q", n.From)
				}
			}
		case "importance":
			if n.Importance, err = args.str(":importance"); err == nil && !c.hasVariables(n.Importance) && !validImportance(n.Importance) {
				err = errorAt(tag.line, tag.col, "invalid :importance %q", n.Importance)
			}
		case "options":
			n.Options, err = args.strList(":options")
		case "message":
			n.Message, err = args.str(":message")
		default:
			err = errorAt(tag.line, tag.col, "unexpected tag :%s for notify", tag.tag)
		}
		if err != nil {
			return nil, err
		}
	}
	var err error
	if n.Method, err = args.str("notification method"); err != nil {
		return nil, err
	}
	if !c.hasVariables(n.Method) {
		if _, parseErr := parseMailtoURI(n.Method); parseErr != nil {
			return nil, errorAt(args.line, args.col, "invalid notification method %q: %v", n.Method, parseErr)
		}
	}
	return n, args.end()
}

// setModifiers maps the RFC 5229 modifiers, and the RFC 5435 :encodeurl,
// to their precedence.
var setModifiers = map[string]int{"lower": 40, "upper": 40, "lowerfirst": 30, "upperfirst": 30, "quotewildcard": 20, "encodeurl": 15, "length": 10}

func (c *compiler) set(args *argList) (Command, error) {
	if err := c.need("variables", args.line, args.col, "set"); err != nil {
		return nil, err
	}
	s := &SetCommand{}
	used := map[int]bool{}
	for tag, ok := args.nextTag(); ok; tag, ok = args.nextTag() {
		precedence, known := setModifiers[tag.tag]
		if !known {
			return nil, errorAt(tag.line, tag.col, "unexpected tag :%s for set", tag.tag)
		}
		if used[precedence] {
			return nil, errorAt(tag.line, tag.col, "conflicting set modifier :%s", tag.tag)
		}
		if tag.tag == "encodeurl" {
			if err := c.need("enotify", tag.line, tag.col, ":encodeurl"); err != nil {
				return nil, err
			}
		}
		used[precedence] = true
		s.Modifiers = append(s.Modifiers, tag.tag)
	}
	slices.SortStableFunc(s.Modifiers, func(a, b string) int { return setModifiers[b] - setModifiers[a] })
	name, err := args.rawStr("variable name")
	if err != nil {
		return nil, err
	}
	if !isVariableName(name) {
		return nil, errorAt(args.line, args.col, "invalid variable name %q", name)
	}
	s.Name = strings.ToLower(name)
	if s.Value, err = args.str("variable value"); err != nil {
		return nil, err
	}
	return s, args.end()
}

func (c *compiler) test(test *rawTest) (Test, error) {
	line, col := test.line, test.col
	if test.name != "not" && test.name != "allof" && test.name != "anyof" && len(test.tests) > 0 {
		return nil, errorAt(line, col, "%s takes no nested test", test.name)
	}
	args := c.argList(test.name, line, col, test.args)
	switch test.name {
	case "true", "false":
		if err := args.end(); err != nil {
			return nil, err
		}
		if test.name == "true" {
			return &TrueTest{}, nil
		}
		return &FalseTest{}, nil
	case "not":
		if len(test.tests) != 1 || test.testList {
			return nil, errorAt(line, col, "not takes exactly one test")
		}
		if err := args.end(); err != nil {
			return nil, err
		}
		inner, err := c.test(test.tests[0])
		return &NotTest{Test: inner}, err
	case "allof", "anyof":
		if !test.testList {
			return nil, errorAt(line, col, "%s takes a parenthesized test list", test.name)
		}
		if err := args.end(); err != nil {
			return nil, err
		}
		tests := make([]Test, 0, len(test.tests))
		for _, raw := range test.tests {
			inner, err := c.test(raw)
			if err != nil {
				return nil, err
			}
			tests = append(tests, inner)
		}
		if test.name == "allof" {
			return &AllOfTest{Tests: tests}, nil
		}
		return &AnyOfTest{Tests: tests}, nil
	case "exists":
		headers, err := args.strList("header list")
		if err != nil {
			return nil, err
		}
		if err := c.checkHeaderNames(headers, line, col); err != nil {
			return nil, err
		}
		return &ExistsTest{Headers: headers}, args.end()
	case "size":
		over, under := false, false
		for tag, ok := args.nextTag(); ok; tag, ok = args.nextTag() {
			switch {
			case tag.tag == "over" && !over && !under:
				over = true
			case tag.tag == "under" && !over && !under:
				under = true
			default:
				return nil, errorAt(tag.line, tag.col, "size takes exactly one of :over or :under")
			}
		}
		if !over && !under {
			return nil, errorAt(line, col, "size takes :over or :under")
		}
		limit, err := args.num("size limit")
		if err != nil {
			return nil, err
		}
		return &SizeTest{Over: over, Limit: limit}, args.end()
	case "address", "envelope", "header", "string", "notify_method_capability":
		return c.matchTest(test.name, args)
	case "valid_notify_method":
		if err := c.need("enotify", line, col, test.name); err != nil {
			return nil, err
		}
		uris, err := args.strList("notification URIs")
		if err != nil {
			return nil, err
		}
		return &ValidNotifyMethodTest{URIs: uris}, args.end()
	case "mailboxexists":
		if err := c.need("mailbox", line, col, test.name); err != nil {
			return nil, err
		}
		mailboxes, err := args.strList("mailbox names")
		if err != nil {
			return nil, err
		}
		return &MailboxExistsTest{Mailboxes: mailboxes}, args.end()
	}
	return nil, errorAt(line, col, "unknown test %q", test.name)
}

var relations = map[string]bool{"gt": true, "ge": true, "lt": true, "le": true, "eq": true, "ne": true}

var addressPartTags = map[string]AddressPart{"all": PartAll, "localpart": PartLocalPart, "domain": PartDomain, "user": PartUser, "detail": PartDetail}

// matchTest compiles the tests that take a comparator and a match type.
func (c *compiler) matchTest(name string, args *argList) (Test, error) {
	line, col := args.line, args.col
	switch name {
	case "envelope", "string", "notify_method_capability":
		extension := map[string]string{"envelope": "envelope", "string": "variables", "notify_method_capability": "enotify"}[name]
		if err := c.need(extension, line, col, name); err != nil {
			return nil, err
		}
	}
	m := Matcher{Comparator: ComparatorASCIICasemap}
	part := PartAll
	haveMatch, haveComparator, havePart := false, false, false
	for tag, ok := args.nextTag(); ok; tag, ok = args.nextTag() {
		if p, isPart := addressPartTags[tag.tag]; isPart && (name == "address" || name == "envelope") {
			if havePart {
				return nil, errorAt(tag.line, tag.col, "more than one address part")
			}
			if (p == PartUser || p == PartDetail) && !c.requires["subaddress"] {
				return nil, errorAt(tag.line, tag.col, ":%s requires the \"subaddress\" extension", tag.tag)
			}
			part, havePart = p, true
			continue
		}
		switch tag.tag {
		case "comparator":
			if haveComparator {
				return nil, errorAt(tag.line, tag.col, "more than one comparator")
			}
			comparator, err := args.rawStr("comparator name")
			if err != nil {
				return nil, err
			}
			comparator = strings.ToLower(comparator)
			switch comparator {
			case ComparatorOctet, ComparatorASCIICasemap:
			case ComparatorASCIINumeric:
				if err := c.need("comparator-"+comparator, tag.line, tag.col, "comparator "+comparator); err != nil {
					return nil, err
				}
			default:
				return nil, errorAt(tag.line, tag.col, "unsupported comparator %q", comparator)
			}
			m.Comparator, haveComparator = comparator, true
		case "is", "contains", "matches", "value", "count":
			if haveMatch {
				return nil, errorAt(tag.line, tag.col, "more than one match type")
			}
			haveMatch = true
			m.Match = map[string]MatchType{"is": MatchIs, "contains": MatchContains, "matches": MatchMatches, "value": MatchValue, "count": MatchCount}[tag.tag]
			if m.Match == MatchValue || m.Match == MatchCount {
				if err := c.need("relational", tag.line, tag.col, ":"+tag.tag); err != nil {
					return nil, err
				}
				relation, err := args.rawStr("relational operator")
				if err != nil {
					return nil, err
				}
				if m.Relation = strings.ToLower(relation); !relations[m.Relation] {
					return nil, errorAt(tag.line, tag.col, "invalid relational operator %q", relation)
				}
			}
		default:
			return nil, errorAt(tag.line, tag.col, "unexpected tag :%s for %s", tag.tag, name)
		}
	}
	if m.Comparator == ComparatorASCIINumeric && (m.Match == MatchContains || m.Match == MatchMatches) {
		return nil, errorAt(line, col, "comparator i;ascii-numeric does not support substring matching")
	}
	if name == "notify_method_capability" {
		uri, err := args.str("notification URI")
		if err != nil {
			return nil, err
		}
		capability, err := args.str("notification capability")
		if err != nil {
			return nil, err
		}
		keys, err := args.strList("key list")
		if err != nil {
			return nil, err
		}
		return &NotifyMethodCapabilityTest{Matcher: m, URI: uri, Capability: capability, Keys: keys}, args.end()
	}
	label := map[string]string{"string": "source list", "envelope": "envelope part list"}[name]
	if label == "" {
		label = "header list"
	}
	sources, err := args.strList(label)
	if err != nil {
		return nil, err
	}
	keys, err := args.strList("key list")
	if err != nil {
		return nil, err
	}
	if err := args.end(); err != nil {
		return nil, err
	}
	switch name {
	case "string":
		return &StringTest{Matcher: m, Sources: sources, Keys: keys}, nil
	case "header":
		if err := c.checkHeaderNames(sources, line, col); err != nil {
			return nil, err
		}
		return &HeaderTest{Matcher: m, Headers: sources, Keys: keys}, nil
	case "envelope":
		for _, envelopePart := range sources {
			if !c.hasVariables(envelopePart) && !validEnvelopePart(envelopePart) {
				return nil, errorAt(line, col, "unsupported envelope part %q", envelopePart)
			}
		}
	default:
		if err := c.checkHeaderNames(sources, line, col); err != nil {
			return nil, err
		}
	}
	return &AddressTest{Matcher: m, Envelope: name == "envelope", Part: part, Headers: sources, Keys: keys}, nil
}

func validEnvelopePart(part string) bool {
	part = strings.ToLower(part)
	return part == "from" || part == "to"
}

func (c *compiler) checkHeaderNames(names []string, line, col int) error {
	for _, name := range names {
		if !c.hasVariables(name) && !validHeaderName(name) {
			return errorAt(line, col, "invalid header name %q", name)
		}
	}
	return nil
}

// validHeaderName reports an RFC 5322 field-name.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c < 33 || c > 126 || c == ':' {
			return false
		}
	}
	return true
}

// hasVariables reports that s holds a variable reference expanded at run
// time, so its value cannot be checked at parse time.
func (c *compiler) hasVariables(s string) bool {
	return c.requires["variables"] && strings.Contains(s, "${")
}

// decode applies the parse-time string transformations: encoded-character
// decoding, and the check that variable references name no namespace.
func (c *compiler) decode(s string, line, col int) (string, error) {
	if c.requires["encoded-character"] {
		decoded, err := decodeEncodedCharacters(s)
		if err != nil {
			return "", errorAt(line, col, "%v", err)
		}
		s = decoded
	}
	if c.requires["variables"] {
		if namespace := variableNamespace(s); namespace != "" {
			return "", errorAt(line, col, "unsupported variable namespace %q", namespace)
		}
	}
	return s, nil
}

// argList walks the arguments of one command or test: tagged arguments
// first, then positional ones.
type argList struct {
	c         *compiler
	name      string
	line, col int
	args      []rawArg
	i         int
}

func (c *compiler) argList(name string, line, col int, args []rawArg) *argList {
	return &argList{c: c, name: name, line: line, col: col, args: args}
}

func (a *argList) nextTag() (rawArg, bool) {
	if a.i < len(a.args) && a.args[a.i].kind == argTag {
		a.i++
		return a.args[a.i-1], true
	}
	return rawArg{}, false
}

func (a *argList) take(what string) (rawArg, error) {
	if a.i >= len(a.args) {
		return rawArg{}, errorAt(a.line, a.col, "%s: missing %s", a.name, what)
	}
	a.i++
	if arg := a.args[a.i-1]; arg.kind == argTag {
		return rawArg{}, errorAt(arg.line, arg.col, "%s: unexpected tag :%s where %s belongs", a.name, arg.tag, what)
	}
	return a.args[a.i-1], nil
}

// rawStr returns a single string argument without parse-time decoding.
func (a *argList) rawStr(what string) (string, error) {
	arg, err := a.take(what)
	if err != nil {
		return "", err
	}
	if arg.kind != argStrings || arg.list {
		return "", errorAt(arg.line, arg.col, "%s: %s must be a string", a.name, what)
	}
	return arg.strs[0], nil
}

func (a *argList) str(what string) (string, error) {
	s, err := a.rawStr(what)
	if err != nil {
		return "", err
	}
	arg := a.args[a.i-1]
	return a.c.decode(s, arg.line, arg.col)
}

func (a *argList) strList(what string) ([]string, error) {
	arg, err := a.take(what)
	if err != nil {
		return nil, err
	}
	if arg.kind != argStrings {
		return nil, errorAt(arg.line, arg.col, "%s: %s must be a string list", a.name, what)
	}
	out := make([]string, len(arg.strs))
	for index, s := range arg.strs {
		if out[index], err = a.c.decode(s, arg.line, arg.col); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (a *argList) num(what string) (int64, error) {
	arg, err := a.take(what)
	if err != nil {
		return 0, err
	}
	if arg.kind != argNumber {
		return 0, errorAt(arg.line, arg.col, "%s: %s must be a number", a.name, what)
	}
	return arg.num, nil
}

func (a *argList) end() error {
	if a.i < len(a.args) {
		arg := a.args[a.i]
		if arg.kind == argTag {
			return errorAt(arg.line, arg.col, "%s: unexpected tag :%s", a.name, arg.tag)
		}
		return errorAt(arg.line, arg.col, "%s: too many arguments", a.name)
	}
	return nil
}

// redirectAddress returns the addr-spec of a redirect target.
func redirectAddress(target string) (string, error) {
	address, err := mail.ParseAddress(target)
	if err != nil {
		return "", err
	}
	return address.Address, nil
}
