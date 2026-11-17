package service

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

var fuzzHTMLSeeds = []string{
	`<p>Hello <b>world</b><br><a href="https://example.com">link</a></p>`,
	`<blockquote type="cite"><ol start="3"><li>one<li>two</ol></blockquote>`,
	`<table><tr><td colspan="2" style="color: red; position: fixed">x</td></tr></table>`,
	`<img src="cid:logo" alt="Logo" width="10" onerror="alert(1)"><img src="//evil.example/x.png">`,
	`<img src="data:image/png;base64,iVBORw0KGgo=">`,
	`<font color="red" face="Arial" size="4" style="background:url(x)">legacy</font>`,
	`<script>alert(1)</script><style>p{}</style><iframe src="x"></iframe>`,
	`<a href="javascript:alert(1)">x</a><a href=" JaVaScRiPt:alert(1)">y</a>`,
	`<svg><a xlink:href="javascript:alert(1)"><text>x</text></a></svg>`,
	`<math><mi xlink:href="javascript:alert(1)">x</mi></math>`,
	`<pre>  keep
  spaces</pre><hr>`,
	`<div style="color: expression(alert(1)); width: -5px">x</div>`,
	`<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>`,
	`<template><script>x</script></template><textarea><script></textarea>`,
	`<!-- comment --><!DOCTYPE html><html><head><title>t</title></head><body>b</body></html>`,
	strings.Repeat("<div>", 600) + "deep",
	"",
	"\x00\xff",
}

// FuzzSanitizeHTML checks that both sanitizer policies only ever emit
// allowlisted elements and attributes, with no script-capable URLs.
func FuzzSanitizeHTML(f *testing.F) {
	for _, seed := range fuzzHTMLSeeds {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	allowedAttributes := map[string]bool{
		"href": true, "title": true, "colspan": true, "rowspan": true, "start": true, "type": true, "dir": true,
		"style": true, "rel": true, "src": true, "data-remote-src": true, "alt": true, "width": true, "height": true,
	}
	f.Fuzz(func(t *testing.T, input string, outgoing bool) {
		var output string
		if outgoing {
			output = SanitizeComposeHTML(input)
		} else {
			output, _, _ = sanitizeEmailHTML(input)
		}
		contextNode := &html.Node{Type: html.ElementNode, Data: "div", DataAtom: atom.Div}
		nodes, err := html.ParseFragment(strings.NewReader(output), contextNode)
		if err != nil {
			t.Fatalf("sanitized output does not parse: %v", err)
		}
		var check func(node *html.Node)
		check = func(node *html.Node) {
			if node.Type == html.ElementNode {
				if !safeEmailElements[node.Data] && node.Data != "span" {
					t.Fatalf("element <%s> survived sanitizing %q as %q", node.Data, input, output)
				}
				if node.Namespace != "" {
					t.Fatalf("foreign element %s:%s survived sanitizing %q", node.Namespace, node.Data, input)
				}
				for _, attribute := range node.Attr {
					if !allowedAttributes[attribute.Key] || attribute.Namespace != "" {
						t.Fatalf("attribute %q survived sanitizing %q as %q", attribute.Key, input, output)
					}
					value := strings.ToLower(strings.Map(func(r rune) rune {
						if r <= ' ' {
							return -1
						}
						return r
					}, attribute.Val))
					if strings.HasPrefix(value, "javascript:") || strings.HasPrefix(value, "vbscript:") ||
						(attribute.Key != "src" && strings.HasPrefix(value, "data:")) {
						t.Fatalf("script-capable %s=%q survived sanitizing %q", attribute.Key, attribute.Val, input)
					}
					if attribute.Key == "style" && (strings.Contains(value, "url(") || strings.Contains(value, "expression(")) {
						t.Fatalf("resource-loading style %q survived sanitizing %q", attribute.Val, input)
					}
				}
			}
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				check(child)
			}
		}
		for _, node := range nodes {
			check(node)
		}
	})
}

// FuzzHTMLToText renders arbitrary HTML as the plain-text alternative.
func FuzzHTMLToText(f *testing.F) {
	for _, seed := range fuzzHTMLSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		// Entities decode to literal text, so the output may legitimately
		// contain markup characters; it only has to be produced.
		_ = HTMLToText(input)
	})
}

const fuzzMIMEMessage = "From: \"Sender\" <sender@example.com>\r\n" +
	"To: rcpt@example.com\r\n" +
	"Subject: =?UTF-8?B?w6Z0dGVy?=\r\n" +
	"Disposition-Notification-To: sender@example.com\r\n" +
	"Message-Id: <m1@example.com>\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=b1\r\n" +
	"\r\n" +
	"--b1\r\n" +
	"Content-Type: multipart/alternative; boundary=b2\r\n" +
	"\r\n" +
	"--b2\r\n" +
	"Content-Type: text/plain; charset=iso-8859-1\r\n" +
	"Content-Transfer-Encoding: quoted-printable\r\n" +
	"\r\n" +
	"caf=E9\r\n" +
	"--b2\r\n" +
	"Content-Type: text/html; charset=utf-8\r\n" +
	"Content-Transfer-Encoding: base64\r\n" +
	"\r\n" +
	"PHA+aGk8L3A+\r\n" +
	"--b2--\r\n" +
	"--b1\r\n" +
	"Content-Type: image/png; name=\"=?UTF-8?Q?l=C3=B8go.png?=\"\r\n" +
	"Content-Disposition: inline; filename*=UTF-8''l%C3%B8go.png\r\n" +
	"Content-Id: <logo>\r\n" +
	"Content-Transfer-Encoding: base64\r\n" +
	"\r\n" +
	"iVBORw0KGgo=\r\n" +
	"--b1--\r\n"

// FuzzMessageProjection parses arbitrary messages through the reader
// projection, the draft parser and the read-receipt builder.
func FuzzMessageProjection(f *testing.F) {
	for _, seed := range []string{
		fuzzMIMEMessage,
		"Subject: plain\r\n\r\nbody",
		"Content-Type: multipart/mixed; boundary=a\r\n\r\n--a\r\nContent-Type: multipart/mixed; boundary=a\r\n\r\n--a--\r\n--a--\r\n",
		"Content-Type: text/plain; charset=x-unknown\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!",
		"Content-Type: message/rfc822\r\n\r\nSubject: inner\r\n\r\nx",
		"",
		"\r\n",
	} {
		f.Add(seed)
	}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, input string) {
		data := []byte(input)
		if projection, err := ProjectMIME(data); err == nil {
			for _, attachment := range projection.Attachments {
				if !validMIMEPartID(attachment.PartID) {
					t.Fatalf("projection produced invalid part ID %q", attachment.PartID)
				}
			}
		}
		_, _ = ParseSubmissionMIME(data)
		_, _ = BuildDispositionNotification(data, "rcpt@example.com", "mx.example.com", now, "<mdn@example.com>")
	})
}
