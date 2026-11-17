package spam

import "github.com/lkarlslund/veksel/pkg/attachment"

// scoreAttachments records one symbol per kind of attachment finding, with
// the file names that matched as options.
func scoreAttachments(symbols *symbolSet, findings []attachment.Finding) {
	for _, finding := range findings {
		if _, known := builtinSymbols[finding.Symbol]; known {
			symbols.builtin(finding.Symbol, finding.Detail)
		}
	}
}
