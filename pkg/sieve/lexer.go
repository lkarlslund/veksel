package sieve

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

// TokenType classifies a Sieve lexical token (RFC 5228 section 8.1).
type TokenType int

const (
	TokEOF       TokenType = iota
	TokIdent               // identifier, lower-cased
	TokTag                 // ":" identifier, lower-cased without the colon
	TokNumber              // number with an optional K/M/G quantifier
	TokString              // quoted or multi-line string, decoded
	TokLBracket            // [
	TokRBracket            // ]
	TokLParen              // (
	TokRParen              // )
	TokLBrace              // {
	TokRBrace              // }
	TokComma               // ,
	TokSemicolon           // ;
)

func (t TokenType) String() string {
	switch t {
	case TokEOF:
		return "end of script"
	case TokIdent:
		return "identifier"
	case TokTag:
		return "tag"
	case TokNumber:
		return "number"
	case TokString:
		return "string"
	case TokLBracket:
		return `"["`
	case TokRBracket:
		return `"]"`
	case TokLParen:
		return `"("`
	case TokRParen:
		return `")"`
	case TokLBrace:
		return `"{"`
	case TokRBrace:
		return `"}"`
	case TokComma:
		return `","`
	case TokSemicolon:
		return `";"`
	default:
		return "token"
	}
}

// Token is one lexical token. Number tokens carry their value in Num, with
// the quantifier applied.
type Token struct {
	Type  TokenType
	Value string
	Num   int64
	Line  int
	Col   int
}

// Lexer splits a Sieve script into tokens. The input must be valid UTF-8.
type Lexer struct {
	input string
	pos   int
	line  int
	col   int
}

// NewLexer returns a lexer over input.
func NewLexer(input string) *Lexer {
	return &Lexer{input: input, line: 1, col: 1}
}

func (l *Lexer) peek(offset int) byte {
	if l.pos+offset >= len(l.input) {
		return 0
	}
	return l.input[l.pos+offset]
}

func (l *Lexer) next() {
	if l.pos >= len(l.input) {
		return
	}
	if l.input[l.pos] == '\n' {
		l.line++
		l.col = 1
	} else if l.input[l.pos]&0xC0 != 0x80 {
		l.col++
	}
	l.pos++
}

func (l *Lexer) errorf(line, col int, format string, args ...any) error {
	return &ParseError{Line: line, Column: col, Msg: fmt.Sprintf(format, args...)}
}

// skipSpace skips white space, hash comments and bracket comments.
func (l *Lexer) skipSpace() error {
	for l.pos < len(l.input) {
		switch c := l.peek(0); {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			l.next()
		case c == '#':
			for l.pos < len(l.input) && l.peek(0) != '\n' {
				l.next()
			}
		case c == '/' && l.peek(1) == '*':
			line, col := l.line, l.col
			l.next()
			l.next()
			end := strings.Index(l.input[l.pos:], "*/")
			if end < 0 {
				return l.errorf(line, col, "unterminated comment")
			}
			for range end + 2 {
				l.next()
			}
		default:
			return nil
		}
	}
	return nil
}

var singleCharTokens = map[byte]TokenType{'[': TokLBracket, ']': TokRBracket, '(': TokLParen, ')': TokRParen,
	'{': TokLBrace, '}': TokRBrace, ',': TokComma, ';': TokSemicolon}

func isIdentStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

func isIdentChar(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' }

func (l *Lexer) identifier() string {
	start := l.pos
	for l.pos < len(l.input) && isIdentChar(l.peek(0)) {
		l.next()
	}
	return strings.ToLower(l.input[start:l.pos])
}

// Scan returns the next token.
func (l *Lexer) Scan() (Token, error) {
	if err := l.skipSpace(); err != nil {
		return Token{}, err
	}
	line, col := l.line, l.col
	tok := Token{Line: line, Col: col}
	if l.pos >= len(l.input) {
		tok.Type = TokEOF
		return tok, nil
	}
	c := l.peek(0)
	switch {
	case singleCharTokens[c] != TokEOF:
		l.next()
		tok.Type, tok.Value = singleCharTokens[c], string(c)
		return tok, nil
	case c == '"':
		value, err := l.quotedString()
		tok.Type, tok.Value = TokString, value
		return tok, err
	case c == ':':
		l.next()
		if !isIdentStart(l.peek(0)) {
			return Token{}, l.errorf(line, col, "expected tag name after \":\"")
		}
		tok.Type, tok.Value = TokTag, l.identifier()
		return tok, nil
	case c >= '0' && c <= '9':
		return l.number(tok)
	case isIdentStart(c):
		word := l.identifier()
		if word == "text" && l.peek(0) == ':' {
			l.next()
			value, err := l.multilineString(line, col)
			tok.Type, tok.Value = TokString, value
			return tok, err
		}
		tok.Type, tok.Value = TokIdent, word
		return tok, nil
	default:
		r, _ := utf8.DecodeRuneInString(l.input[l.pos:])
		return Token{}, l.errorf(line, col, "unexpected character %q", r)
	}
}

// quotedString decodes a quoted string. RFC 5228 section 2.4.2 defines only
// the \" and \\ escapes; any other backslash is dropped.
func (l *Lexer) quotedString() (string, error) {
	line, col := l.line, l.col
	l.next()
	var b strings.Builder
	for l.pos < len(l.input) {
		c := l.peek(0)
		switch c {
		case '"':
			l.next()
			return b.String(), nil
		case '\\':
			l.next()
			if l.pos >= len(l.input) {
				return "", l.errorf(line, col, "unterminated string")
			}
			c = l.peek(0)
		}
		b.WriteByte(c)
		l.next()
	}
	return "", l.errorf(line, col, "unterminated string")
}

// multilineString decodes "text:" up to a line holding a single ".",
// removing the dot-stuffing of lines that begin with ".".
func (l *Lexer) multilineString(line, col int) (string, error) {
	for l.peek(0) == ' ' || l.peek(0) == '\t' {
		l.next()
	}
	switch {
	case l.peek(0) == '#':
		for l.pos < len(l.input) && l.peek(0) != '\n' {
			l.next()
		}
	case l.peek(0) == '\r' && l.peek(1) == '\n', l.peek(0) == '\n':
	default:
		return "", l.errorf(line, col, "expected line break after \"text:\"")
	}
	if l.peek(0) == '\r' {
		l.next()
	}
	if l.peek(0) != '\n' {
		return "", l.errorf(line, col, "unterminated multi-line string")
	}
	l.next()
	var b strings.Builder
	for l.pos < len(l.input) {
		end := strings.IndexByte(l.input[l.pos:], '\n')
		if end < 0 {
			break
		}
		raw := l.input[l.pos : l.pos+end+1]
		content := strings.TrimSuffix(strings.TrimSuffix(raw, "\n"), "\r")
		for range len(raw) {
			l.next()
		}
		if content == "." {
			return b.String(), nil
		}
		if strings.HasPrefix(raw, ".") {
			raw = raw[1:]
		}
		b.WriteString(raw)
	}
	return "", l.errorf(line, col, "unterminated multi-line string")
}

func (l *Lexer) number(tok Token) (Token, error) {
	var value int64
	for l.pos < len(l.input) && l.peek(0) >= '0' && l.peek(0) <= '9' {
		digit := int64(l.peek(0) - '0')
		if value > (math.MaxInt64-digit)/10 {
			return Token{}, l.errorf(tok.Line, tok.Col, "number too large")
		}
		value = value*10 + digit
		l.next()
	}
	shift := 0
	switch l.peek(0) {
	case 'k', 'K':
		shift = 10
	case 'm', 'M':
		shift = 20
	case 'g', 'G':
		shift = 30
	}
	if shift > 0 {
		l.next()
		if value > math.MaxInt64>>shift {
			return Token{}, l.errorf(tok.Line, tok.Col, "number too large")
		}
		value <<= shift
	}
	if isIdentChar(l.peek(0)) {
		return Token{}, l.errorf(tok.Line, tok.Col, "invalid number")
	}
	tok.Type, tok.Num, tok.Value = TokNumber, value, fmt.Sprint(value)
	return tok, nil
}

// Tokenize returns all tokens of input, ending with TokEOF.
func Tokenize(input string) ([]Token, error) {
	if !utf8.ValidString(input) {
		return nil, &ParseError{Line: 1, Column: 1, Msg: "script is not valid UTF-8"}
	}
	lex := NewLexer(input)
	var tokens []Token
	for {
		tok, err := lex.Scan()
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, tok)
		if tok.Type == TokEOF {
			return tokens, nil
		}
	}
}
