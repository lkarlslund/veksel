package service

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// mimeTree renders a MIME structure as nested media types, e.g.
// "multipart/mixed[multipart/alternative[text/plain,text/html],image/png]".
func mimeTree(t *testing.T, contentType string, body io.Reader, leaves map[string][]byte) string {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Fatalf("content type %q: %v", contentType, err)
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		return mediaType
	}
	reader := multipart.NewReader(body, params["boundary"])
	var children []string
	for {
		part, err := reader.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		childType := part.Header.Get("Content-Type")
		if strings.HasPrefix(childType, "multipart/") {
			children = append(children, mimeTree(t, childType, part, leaves))
			continue
		}
		data, err := io.ReadAll(model.TransferDecoder(part, part.Header.Get("Content-Transfer-Encoding")))
		if err != nil {
			t.Fatal(err)
		}
		leafType, _, _ := mime.ParseMediaType(childType)
		key := leafType
		if id := part.Header.Get("Content-ID"); id != "" {
			key += " " + id
		}
		leaves[key] = data
		children = append(children, key)
	}
	return mediaType + "[" + strings.Join(children, ",") + "]"
}

func TestBuildSubmissionMIMEHTMLWithInlineImagesAndAttachments(t *testing.T) {
	html := `<p>Hello <b>Bob</b></p><p><img src="cid:logo@veksel" alt="Logo" width="120"></p><ul><li>One</li><li>Two</li></ul><blockquote type="cite">Quoted <a href="https://example.test/x">link</a></blockquote>`
	attachments := []SubmissionAttachment{
		{Name: "logo.png", ContentType: "image/png", ContentID: "logo@veksel", Data: []byte("png-bytes")},
		{Name: "removed.png", ContentType: "image/png", ContentID: "gone@veksel", Data: []byte("unreferenced")},
		{Name: "report.pdf", ContentType: "application/pdf", Data: []byte("pdf")},
	}
	contentType, body, err := BuildSubmissionMIME("ignored plain body", html, attachments)
	if err != nil {
		t.Fatal(err)
	}
	leaves := map[string][]byte{}
	tree := mimeTree(t, contentType, bytes.NewReader(body), leaves)
	want := "multipart/mixed[multipart/alternative[text/plain,multipart/related[text/html,image/png <logo@veksel>]],application/pdf]"
	if tree != want {
		t.Fatalf("MIME tree = %s, want %s", tree, want)
	}
	text := strings.ReplaceAll(string(leaves["text/plain"]), "\r\n", "\n")
	for _, expected := range []string{"Hello Bob", "[Logo]", "- One\n- Two", "> Quoted link <https://example.test/x>"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("generated text/plain lacks %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "ignored plain body") {
		t.Fatalf("text/plain was not generated from HTML: %s", text)
	}
	if !strings.Contains(string(leaves["text/html"]), `src="cid:logo@veksel"`) || string(leaves["image/png <logo@veksel>"]) != "png-bytes" {
		t.Fatalf("related parts = %q", leaves)
	}
	if bytes.Contains(body, []byte("unreferenced")) || bytes.Contains(body, []byte("dW5yZWZlcmVuY2Vk")) {
		t.Fatal("an inline image no longer referenced by the HTML was still sent")
	}

	contentType, body, err = BuildSubmissionMIME("", "<p>Just <i>HTML</i></p>", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tree := mimeTree(t, contentType, bytes.NewReader(body), map[string][]byte{}); tree != "multipart/alternative[text/plain,text/html]" {
		t.Fatalf("HTML-only tree = %s", tree)
	}
	if _, _, err := BuildSubmissionMIME("", "<p>x</p>", []SubmissionAttachment{{Name: "a.png", ContentType: "image/png", ContentID: "bad id<>", Data: []byte("x")}}); err == nil {
		t.Fatal("unsafe Content-ID was accepted")
	}
	if _, _, err := BuildSubmissionMIME("", `<p><img src="cid:x"></p>`, []SubmissionAttachment{{Name: "a.exe", ContentType: "application/x-msdownload", ContentID: "x", Data: []byte("x")}}); err == nil {
		t.Fatal("non-image inline part was accepted")
	}
}

func TestSanitizeComposeHTMLRemovesActiveContent(t *testing.T) {
	vectors := []string{
		`<script>alert(1)</script>`,
		`<img src="x" onerror="alert(1)">`,
		`<img src="javascript:alert(1)">`,
		`<a href="javascript:alert(1)">x</a>`,
		`<a href="jAvAsCrIpT:alert(1)">x</a>`,
		`<a href="java&#x73;cript:alert(1)">x</a>`,
		`<a href=" javascript:alert(1)">x</a>`,
		`<a href="data:text/html,<script>alert(1)</script>">x</a>`,
		`<svg onload="alert(1)"><circle/></svg>`,
		`<math><mtext><script>alert(1)</script></mtext></math>`,
		`<iframe src="https://evil.test"></iframe>`,
		`<object data="evil.swf"></object><embed src="evil.swf">`,
		`<form action="https://evil.test"><input name="password"><button>go</button></form>`,
		`<div style="background-image:url(https://evil.test/x)">x</div>`,
		`<div style="width: expression(alert(1))">x</div>`,
		`<div style="position:fixed;top:0;left:0;z-index:9999">overlay</div>`,
		`<div style="color: \72 ed">x</div>`,
		`<div style="margin-top:-500px">x</div>`,
		`<p onclick="alert(1)" onmouseover="alert(1)">x</p>`,
		`<style>body{display:none}</style>`,
		`<link rel="stylesheet" href="https://evil.test/x.css">`,
		`<meta http-equiv="refresh" content="0;url=https://evil.test">`,
		`<base href="https://evil.test/">`,
		`<img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+">`,
		`<template><script>alert(1)</script></template>`,
		`<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>`,
	}
	for _, vector := range vectors {
		output := strings.ToLower(SanitizeComposeHTML(vector))
		for _, forbidden := range []string{"<script", "javascript:", "onerror", "onload", "onclick", "onmouseover", "<iframe", "<object", "<embed", "<form", "<input", "<svg", "<math", "url(", "expression", "position", "z-index", "<style", "<link", "<meta", "<base", "data:", "-500px", `\72`, "<template", "<noscript"} {
			if strings.Contains(output, forbidden) {
				t.Errorf("SanitizeComposeHTML(%q) = %q retains %q", vector, output, forbidden)
			}
		}
	}
	kept := SanitizeComposeHTML(`<p style="color: rgb(200, 0, 0); text-align: center; font-size: large">Hi <a href="https://example.test">x</a> <img src="https://cdn.example.test/a.png" alt="a"> <font color="#00f" size="5">big</font></p>`)
	for _, expected := range []string{`color: rgb(200, 0, 0)`, `text-align: center`, `font-size: large`, `href="https://example.test"`, `src="https://cdn.example.test/a.png"`, `<span style="color: #00f; font-size: x-large">big</span>`} {
		if !strings.Contains(kept, expected) {
			t.Errorf("sanitized composer HTML lacks %q: %s", expected, kept)
		}
	}
	if strings.Contains(kept, "rel=") || strings.Contains(kept, "data-remote-src") {
		t.Errorf("outgoing HTML gained reader-only attributes: %s", kept)
	}
}

func TestReaderSanitizerKeepsInlineImagesAndBlocksRemoteOnes(t *testing.T) {
	output, removed, remote := sanitizeEmailHTML(`<p><img src="cid:logo@x" alt="logo"><img src="data:image/png;base64,iVBORw0KGgo="><img src="//tracker.test/p.gif"></p>`)
	if !strings.Contains(output, `src="cid:logo@x"`) || !strings.Contains(output, `src="data:image/png;base64,iVBORw0KGgo="`) || !strings.Contains(output, `data-remote-src="https://tracker.test/p.gif"`) || strings.Contains(output, ` src="https:`) {
		t.Fatalf("reader images = %s", output)
	}
	if removed || !remote {
		t.Fatalf("removed=%v remote=%v", removed, remote)
	}
	if _, _, remote := sanitizeEmailHTML(`<p><img src="cid:only"></p>`); remote {
		t.Fatal("an inline cid: image was reported as remote content")
	}
}

// The reader's "unsafe content removed" notice is for active content only:
// presentational markup every newsletter carries must not raise it.
func TestReaderSanitizerFlagsOnlyActiveContent(t *testing.T) {
	benign := `<html><head><title>Deals</title><meta charset="utf-8"><style>p{color:red}</style></head><body><center><table border="1" width="600" align="center" bgcolor="#fff" cellpadding="4" class="x" id="y"><tr><td valign="top" style="display:block;color:#c00">Item</td></tr></table><img src="cid:a@b" border="0" class="logo"></center></body></html>`
	if output, removed, _ := sanitizeEmailHTML(benign); removed || !strings.Contains(output, `style="color: #c00"`) {
		t.Fatalf("benign newsletter markup flagged removed=%v: %s", removed, output)
	}
	for _, active := range []string{
		`<p onclick="x()">a</p>`, `<script>x()</script>`, `<iframe src="https://e.test"></iframe>`, `<form><input></form>`,
		`<a href="javascript:x()">a</a>`, `<p style="background:url(https://t.test/p.gif)">a</p>`, `<meta http-equiv="refresh" content="0;url=https://e.test">`,
		`<center onmouseover="x()">a</center>`, `<img src="javascript:x()">`,
	} {
		if _, removed, _ := sanitizeEmailHTML(active); !removed {
			t.Errorf("active content not flagged: %s", active)
		}
	}
}

func TestHTMLDraftRoundTrip(t *testing.T) {
	html := `<div>Draft <u>body</u></div><div><img src="cid:img1@draft" alt="chart"></div>`
	attachments := []SubmissionAttachment{
		{Name: "chart.png", ContentType: "image/png", ContentID: "img1@draft", Data: []byte("chart")},
		{Name: "notes.txt", ContentType: "text/plain", Data: []byte("notes")},
	}
	contentType, body, err := BuildSubmissionMIME("", html, attachments)
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte("From: alice@example.test\r\nTo: bob@example.test\r\nSubject: Draft\r\nDisposition-Notification-To: alice@example.test\r\nMIME-Version: 1.0\r\nContent-Type: "+contentType+"\r\n\r\n"), body...)
	parsed, err := ParseSubmissionMIME(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.HTML != SanitizeComposeHTML(html) || parsed.Body != "Draft body\n\n[chart]" || !parsed.ReadReceipt {
		t.Fatalf("parsed draft = html %q body %q receipt %v", parsed.HTML, parsed.Body, parsed.ReadReceipt)
	}
	if len(parsed.Attachments) != 2 || parsed.Attachments[0].ContentID != "img1@draft" || string(parsed.Attachments[0].Data) != "chart" || parsed.Attachments[1].ContentID != "" || parsed.Attachments[1].Name != "notes.txt" {
		t.Fatalf("parsed attachments = %+v", parsed.Attachments)
	}
	// Re-saving the parsed draft reproduces the same structure.
	contentType2, body2, err := BuildSubmissionMIME(parsed.Body, parsed.HTML, parsed.Attachments)
	if err != nil {
		t.Fatal(err)
	}
	if mimeTree(t, contentType, bytes.NewReader(body), map[string][]byte{}) != mimeTree(t, contentType2, bytes.NewReader(body2), map[string][]byte{}) {
		t.Fatal("draft round trip changed the MIME structure")
	}
}

func TestHTMLToText(t *testing.T) {
	text := HTMLToText(`<h1>Title</h1><p>One&nbsp;two<br>three</p><ol><li>first</li><li>second</li></ol><pre>  code
  block</pre><p><a href="mailto:bob@example.test">bob@example.test</a></p>`)
	want := "Title\n\nOne two\nthree\n\n1. first\n2. second\n\n  code\n  block\n\nbob@example.test"
	if text != want {
		t.Fatalf("HTMLToText = %q, want %q", text, want)
	}
}

func TestBuildDispositionNotification(t *testing.T) {
	original := []byte("From: Bob <bob@example.net>\r\nTo: alice@example.test\r\nSubject: =?UTF-8?Q?Quarterly_=C3=B8_report?=\r\nMessage-ID: <orig-1@example.net>\r\nDisposition-Notification-To: Bob <bob@example.net>, other@example.net\r\nContent-Type: text/plain\r\n\r\nPlease confirm.\r\n")
	notification, err := BuildDispositionNotification(original, "alice@example.test", "example.test", time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC), "<mdn-1@veksel.local>")
	if err != nil {
		t.Fatal(err)
	}
	if notification.Recipient != "bob@example.net" || notification.Headers["In-Reply-To"] != "<orig-1@example.net>" || notification.Headers["Auto-Submitted"] != "auto-replied" {
		t.Fatalf("notification headers = %+v recipient %s", notification.Headers, notification.Recipient)
	}
	subject, _ := new(mime.WordDecoder).DecodeHeader(notification.Headers["Subject"])
	if subject != "Read: Quarterly ø report" {
		t.Fatalf("subject = %q", subject)
	}
	mediaType, params, _ := mime.ParseMediaType(notification.Headers["Content-Type"])
	if mediaType != "multipart/report" || params["report-type"] != "disposition-notification" {
		t.Fatalf("content type = %s", notification.Headers["Content-Type"])
	}
	leaves := map[string][]byte{}
	if tree := mimeTree(t, notification.Headers["Content-Type"], bytes.NewReader(notification.Body), leaves); tree != "multipart/report[text/plain,message/disposition-notification,text/rfc822-headers]" {
		t.Fatalf("MDN tree = %s", tree)
	}
	report := string(leaves["message/disposition-notification"])
	for _, field := range []string{"Reporting-UA: example.test; Veksel\r\n", "Final-Recipient: rfc822;alice@example.test\r\n", "Original-Message-ID: <orig-1@example.net>\r\n", "Disposition: manual-action/MDN-sent-manually; displayed\r\n"} {
		if !strings.Contains(report, field) {
			t.Fatalf("disposition report lacks %q:\n%s", field, report)
		}
	}
	if !strings.Contains(string(leaves["text/rfc822-headers"]), "Message-ID: <orig-1@example.net>") {
		t.Fatalf("original headers part = %s", leaves["text/rfc822-headers"])
	}
	if _, err := mail.ReadMessage(bytes.NewReader(model.BuildMessage(notification.Headers, notification.Body))); err != nil {
		t.Fatalf("MDN is not a valid message: %v", err)
	}

	if _, err := BuildDispositionNotification([]byte("From: bob@example.net\r\nSubject: x\r\n\r\nbody"), "alice@example.test", "example.test", time.Now(), "<m@x>"); err != ErrNoReceiptRequested {
		t.Fatalf("message without a request: err = %v", err)
	}
	mdn := model.BuildMessage(map[string]string{"From": "bob@example.net", "Disposition-Notification-To": "bob@example.net", "Content-Type": notification.Headers["Content-Type"]}, notification.Body)
	if _, err := BuildDispositionNotification(mdn, "alice@example.test", "example.test", time.Now(), "<m@x>"); err == nil {
		t.Fatal("a read receipt was generated for a read receipt")
	}
}
