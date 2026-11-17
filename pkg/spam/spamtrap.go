package spam

import "slices"

// SymbolSpamtrapHit marks the copies for real recipients of a transaction
// that also addressed a spamtrap: the sender mails addresses no legitimate
// correspondent knows.
const SymbolSpamtrapHit = "SPAMTRAP_HIT"

func init() {
	builtinSymbols[SymbolSpamtrapHit] = symbolInfo{10.0, "The same transaction was also sent to a spamtrap address"}
}

// DefaultSymbol returns a built-in symbol at its default score, for callers
// that apply a symbol while engine scoring is disabled.
func DefaultSymbol(name string, options ...string) (Symbol, bool) {
	info, ok := builtinSymbols[name]
	if !ok {
		return Symbol{}, false
	}
	return Symbol{Name: name, Score: info.score, Description: info.description, Options: slices.Clone(options)}, true
}
