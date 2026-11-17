package spam

import "maps"

// Connection-stage symbols. The SMTP session observes these facts before
// the message exists (greeting, command stream, reverse DNS, HELO) and
// hands them to the transaction's evaluation as ConnectionFindings.
const (
	SymbolPregreet          = "SMTP_PREGREET"
	SymbolPipelining        = "SMTP_PIPELINING"
	SymbolProtocolViolation = "SMTP_PROTOCOL_VIOLATION"
	SymbolUnknownRecipients = "SMTP_RCPT_UNKNOWN"
	SymbolRDNSNone          = "RDNS_NONE"
	SymbolRDNSNotFCrDNS     = "RDNS_NOT_FCRDNS"
	SymbolRDNSDynamic       = "RDNS_DYNAMIC"
	SymbolHeloBareIP        = "HELO_BARE_IP"
	SymbolHeloNotFQDN       = "HELO_NOT_FQDN"
	SymbolHeloForgedLocal   = "HELO_FORGED_LOCAL"
)

// ConnectionFinding is one connection-stage fact: a connection symbol and
// an optional detail shown as its option.
type ConnectionFinding struct {
	Symbol string
	Detail string
}

// connectionSymbols join builtinSymbols so score overrides and descriptions
// work like any other.
var connectionSymbols = map[string]symbolInfo{
	SymbolPregreet:          {4.0, "Client sent data before the SMTP greeting finished"},
	SymbolPipelining:        {3.0, "Client sent commands before a reply without negotiated PIPELINING"},
	SymbolProtocolViolation: {1.5, "Client broke SMTP command syntax or sequencing (bare LF, NUL, overlong or unknown commands)"},
	SymbolUnknownRecipients: {1.0, "Client probed several unknown recipients in this session"},
	SymbolRDNSNone:          {1.0, "Client address has no reverse DNS name"},
	SymbolRDNSNotFCrDNS:     {0.5, "Client reverse DNS name does not resolve back to the client address"},
	SymbolRDNSDynamic:       {1.0, "Client reverse DNS name looks like a dynamic or residential address"},
	SymbolHeloBareIP:        {1.0, "HELO is a bare IP address instead of a host name or address literal"},
	SymbolHeloNotFQDN:       {1.0, "HELO is not a fully qualified host name"},
	SymbolHeloForgedLocal:   {3.0, "External client announced this server's name or a hosted domain in HELO"},
}

func init() { maps.Copy(builtinSymbols, connectionSymbols) }

// scoreConnection records the connection-stage findings; unknown symbols
// are ignored so a caller cannot invent unscored names.
func scoreConnection(symbols *symbolSet, findings []ConnectionFinding) {
	for _, finding := range findings {
		if _, known := connectionSymbols[finding.Symbol]; known {
			symbols.builtin(finding.Symbol, boundOption(finding.Detail))
		}
	}
}
