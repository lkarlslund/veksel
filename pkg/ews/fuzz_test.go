package ews

import (
	"strings"
	"testing"
	"time"
)

// FuzzDecodeXML feeds EWS SOAP request bodies into the XML tree decoder and
// the item-update parser.
func FuzzDecodeXML(f *testing.F) {
	for _, seed := range []string{
		`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"><soap:Body><m:UpdateItem><m:ItemChanges><t:ItemChange><t:ItemId Id="x"/><t:Updates><t:SetItemField><t:FieldURI FieldURI="item:Subject"/><t:Message><t:Subject>New</t:Subject></t:Message></t:SetItemField></t:Updates></t:ItemChange></m:ItemChanges></m:UpdateItem></soap:Body></soap:Envelope>`,
		`<a>x<!--c-->y<![CDATA[z]]>&amp;</a>`,
		strings.Repeat("<a>", 100),
		"", "<", "</a>",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		root, err := decodeXML(strings.NewReader(input))
		if err != nil {
			return
		}
		var walk func(n *node, depth int)
		walk = func(n *node, depth int) {
			if depth > 64 {
				t.Fatalf("decoded a tree deeper than the nesting limit")
			}
			if n.Name.Local == "Updates" {
				_, _ = parseEWSItemUpdates(n)
			}
			for _, child := range n.Children {
				walk(child, depth+1)
			}
		}
		walk(root, 1)
	})
}

// TestDecodeXMLManyTextRuns guards against quadratic text accumulation:
// character data split by 200k comments was once concatenated run by run.
func TestDecodeXMLManyTextRuns(t *testing.T) {
	input := "<a>" + strings.Repeat("x<!---->", 200000) + "</a>"
	start := time.Now()
	root, err := decodeXML(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second || len(root.Text) != 200000 {
		t.Fatalf("decoded %d text bytes in %v", len(root.Text), elapsed)
	}
}
