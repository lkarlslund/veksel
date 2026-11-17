package spam

import (
	"context"
	"net/mail"
	"strings"
	"testing"
	"time"
)

var anomalyNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func anomalyEngine(t *testing.T) *Engine {
	t.Helper()
	engine := phishEngine(t)
	engine.now = func() time.Time { return anomalyNow }
	return engine
}

// anomalyMessage parses raw (LF line endings) into a Message the way the
// SMTP boundary would.
func anomalyMessage(t *testing.T, raw string, edit ...func(*Message)) Message {
	t.Helper()
	raw = strings.ReplaceAll(strings.TrimLeft(raw, "\n"), "\n", "\r\n")
	parsed, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{}
	for name, values := range parsed.Header {
		headers[name] = values[0]
	}
	m := Message{Content: []byte(raw), Headers: headers, RemoteIP: "203.0.113.9"}
	for _, apply := range edit {
		apply(&m)
	}
	return m
}

// anomalySymbolsOf returns only the anomaly-family symbols of m.
func anomalySymbolsOf(t *testing.T, engine *Engine, m Message) map[string]Symbol {
	t.Helper()
	result, ok := engine.Check(context.Background(), m)
	if !ok {
		t.Fatal("engine did not check")
	}
	found := map[string]Symbol{}
	for _, symbol := range result.Symbols {
		if _, ok := anomalySymbols[symbol.Name]; ok {
			found[symbol.Name] = symbol
		}
	}
	return found
}

const plainHead = `From: Eve <eve@example.net>
To: alice@acmecorp.com
Subject: Hello
Date: Thu, 22 Oct 2026 10:00:00 +0200
Message-ID: <abc123@mail.example.net>
`

const plainBody = "Content-Type: text/plain; charset=utf-8\n\nHi there, this is a perfectly ordinary message.\n"

const plainBase = plainHead + plainBody

func replaceOnce(raw, old, replacement string) string {
	if !strings.Contains(raw, old) {
		panic("missing " + old)
	}
	return strings.Replace(raw, old, replacement, 1)
}

// htmlBase is plainBase with an HTML body.
func htmlBase(body string) string {
	return plainHead + "Content-Type: text/html; charset=utf-8\n\n" + body + "\n"
}

// nestedMultipart builds levels nested multipart/mixed containers.
func nestedMultipart(levels int) string {
	var open, closing strings.Builder
	for level := 1; level <= levels; level++ {
		boundary := "n" + string(rune('a'+level))
		open.WriteString("Content-Type: multipart/mixed; boundary=" + boundary + "\n\n--" + boundary + "\n")
		closing.WriteString("\n--" + boundary + "--\n")
	}
	return open.String() + "Content-Type: text/plain\n\ninner" + closing.String()
}

func TestAnomalySymbolsTriggered(t *testing.T) {
	engine := anomalyEngine(t)
	hiddenFiller := strings.Repeat("buy cheap pills online today ", 12)
	cases := []struct {
		name   string
		symbol string
		raw    string
	}{
		{"date unparseable", "HDR_DATE_INVALID", replaceOnce(plainBase, "Thu, 22 Oct 2026 10:00:00 +0200", "yesterday-ish")},
		{"date future", "HDR_DATE_FUTURE", replaceOnce(plainBase, "Thu, 22 Oct 2026", "Mon, 26 Oct 2026")},
		{"date past", "HDR_DATE_PAST", replaceOnce(plainBase, "Thu, 22 Oct 2026", "Mon, 05 Oct 2026")},
		{"date timezone", "HDR_DATE_TZ", replaceOnce(plainBase, "+0200", "+0733")},
		{"msgid no at", "HDR_MSGID_INVALID", replaceOnce(plainBase, "<abc123@mail.example.net>", "abc123")},
		{"msgid no brackets", "HDR_MSGID_INVALID", replaceOnce(plainBase, "<abc123@mail.example.net>", "abc123@mail.example.net")},
		{"msgid ip", "HDR_MSGID_IP", replaceOnce(plainBase, "mail.example.net", "[192.0.2.5]")},
		{"msgid localhost", "HDR_MSGID_IP", replaceOnce(plainBase, "mail.example.net", "localhost")},
		{"msgid forged hosted", "HDR_MSGID_FORGED_LOCAL", replaceOnce(plainBase, "mail.example.net", "acmecorp.com")},
		{"received forged hosted", "HDR_RCVD_FORGED_LOCAL", "Received: from mx.acmecorp.com (203.0.113.9) by victim.example.org with ESMTP; Thu, 22 Oct 2026 09:59:00 +0200\n" +
			"Received: from a.example.net by mx.acmecorp.com with ESMTP; Thu, 22 Oct 2026 09:58:00 +0200\n" + plainBase},
		{"received out of order", "HDR_RCVD_ORDER", "Received: from b.example.net by mx.example.org; Thu, 22 Oct 2026 09:59:00 +0200\n" +
			"Received: from a.example.net by b.example.net; Mon, 26 Oct 2026 09:58:00 +0200\n" + plainBase},
		{"from multi", "HDR_FROM_MULTI", replaceOnce(plainBase, "From: Eve <eve@example.net>", "From: Eve <eve@example.net>, Mallory <mal@example.net>")},
		{"from duplicate", "HDR_DUPLICATE", "From: Other <o@example.net>\n" + plainBase},
		{"to undisclosed", "HDR_TO_UNDISCLOSED", replaceOnce(plainBase, "To: alice@acmecorp.com", "To: undisclosed-recipients:;")},
		{"to equals from", "HDR_TO_FROM_SAME", replaceOnce(plainBase, "To: alice@acmecorp.com", "To: eve@example.net")},
		{"many recipients", "HDR_RCPT_MANY", replaceOnce(plainBase, "To: alice@acmecorp.com", "To: "+strings.Repeat("u@example.net, ", 25)+"v@example.net\nCc: "+strings.Repeat("w@example.net, ", 25)+"x@example.net")},
		{"subject encoded ascii", "HDR_SUBJ_ENCODED_ASCII", replaceOnce(plainBase, "Subject: Hello", "Subject: =?UTF-8?B?QnV5IGNoZWFwIHBpbGxzIG5vdw==?=")},
		{"subject encoded ascii q", "HDR_SUBJ_ENCODED_ASCII", replaceOnce(plainBase, "Subject: Hello", "Subject: =?utf-8?Q?Buy_cheap_pills=21?=")},
		{"subject mixed charset", "HDR_SUBJ_MIXED_CHARSET", replaceOnce(plainBase, "Subject: Hello", "Subject: =?UTF-8?Q?caf=C3=A9?= =?ISO-8859-1?Q?caf=E9?=")},
		{"subject noise punctuation", "HDR_SUBJ_NOISE", replaceOnce(plainBase, "Subject: Hello", "Subject: Winner!!!!!")},
		{"subject noise emoji", "HDR_SUBJ_NOISE", replaceOnce(plainBase, "Subject: Hello", "Subject: Hello \U0001F4B0\U0001F4B0\U0001F4B0\U0001F4B0\U0001F4B0")},
		{"fake reply", "HDR_FAKE_REPLY", replaceOnce(plainBase, "Subject: Hello", "Subject: RE: your invoice")},
		{"spamware mailer", "HDR_MAILER_SPAMWARE", replaceOnce(plainBase, "Subject: Hello", "X-Mailer: Advanced Mass Sender 4.1\nSubject: Hello")},
		{"spamware user agent", "HDR_MAILER_SPAMWARE", replaceOnce(plainBase, "Subject: Hello", "User-Agent: Atomic Mail Sender v9\nSubject: Hello")},
		{"multipart without boundary", "MIME_NO_BOUNDARY", replaceOnce(plainBase, "Content-Type: text/plain; charset=utf-8", "Content-Type: multipart/mixed")},
		{"multipart unterminated", "MIME_UNTERMINATED", plainHead + "Content-Type: multipart/alternative; boundary=\"b1\"\n\n--b1\nContent-Type: text/plain\n\nhello\n--b1\nContent-Type: text/html\n\n<p>hello</p>\n"},
		{"mime nesting", "MIME_NESTING_DEPTH", plainHead + nestedMultipart(6)},
		{"bad transfer encoding", "MIME_BAD_ENCODING", replaceOnce(plainBase, "charset=utf-8", "charset=utf-8\nContent-Transfer-Encoding: rot13")},
		{"html only", "MIME_HTML_ONLY", htmlBase("<p>Hello there</p>")},
		{"invalid utf-8", "MIME_BAD_CHARSET", replaceOnce(plainBase, "perfectly ordinary", "perfectly \xff\xfe ordinary")},
		{"base64 ascii text", "MIME_BASE64_TEXT", replaceOnce(plainBase, "charset=utf-8\n\nHi there, this is a perfectly ordinary message.\n",
			"charset=utf-8\nContent-Transfer-Encoding: base64\n\nSGkgdGhlcmUsIHRoaXMgaXMgYSBwZXJmZWN0bHkgb3JkaW5hcnkgbWVzc2FnZS4=\n")},
		{"hidden text display none", "HTML_HIDDEN_TEXT", htmlBase("<p>Hello</p><div style=\"display:none\">" + hiddenFiller + "</div>")},
		{"hidden text zero font", "HTML_HIDDEN_TEXT", htmlBase("<p>Hello</p><span style=\"font-size: 0px\"><b>" + hiddenFiller + "</b></span>")},
		{"hidden text white on white", "HTML_HIDDEN_TEXT", htmlBase("<p>Hello</p><p style=\"color:#fff;background-color:white\">" + hiddenFiller + "</p>")},
		{"zero width in words", "TEXT_ZERO_WIDTH", replaceOnce(plainBase, "perfectly ordinary message", "v​i​a​g​r​a free")},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			found := anomalySymbolsOf(t, engine, anomalyMessage(t, test.raw))
			if _, ok := found[test.symbol]; !ok {
				t.Fatalf("%s not raised; got %v", test.symbol, found)
			}
		})
	}
}

func TestAnomalyScoreOverride(t *testing.T) {
	config, err := ParseSettings(Settings{Thresholds: DefaultThresholds(), SymbolScores: []string{"HDR_FAKE_REPLY=4.5"}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := anomalySymbolsOf(t, engine, anomalyMessage(t, replaceOnce(plainBase, "Subject: Hello", "Subject: Re: invoice")))
	if found["HDR_FAKE_REPLY"].Score != 4.5 {
		t.Fatalf("override not applied: %v", found)
	}
}

func TestAnomalySymbolsDescribed(t *testing.T) {
	for name, info := range anomalySymbols {
		if !validSymbolName(name) || info.description == "" || info.score <= 0 || info.score > 3 {
			t.Errorf("symbol %s is badly registered: %+v", name, info)
		}
		if builtinSymbols[name] != info {
			t.Errorf("symbol %s is not a built-in", name)
		}
	}
}

// Realistic messages from common clients and lists must raise no anomaly.
func TestAnomalyFalsePositiveGuards(t *testing.T) {
	engine := anomalyEngine(t)
	samples := map[string]string{
		"thunderbird": `Received: from mail-ej1-f41.google.com (mail-ej1-f41.google.com [209.85.218.41])
	by mx.acmecorp.com (Postfix) with ESMTPS id 4C1; Thu, 22 Oct 2026 10:00:03 +0200 (CEST)
Received: by mail-ej1-f41.google.com with SMTP id x1so1234ejb.0
        for <alice@acmecorp.com>; Thu, 22 Oct 2026 01:00:02 -0700 (PDT)
Message-ID: <6f1b3c0e-2d7a-4a55-9c1d-1d2e3f4a5b6c@example.net>
Date: Thu, 22 Oct 2026 10:00:00 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: =?UTF-8?Q?Sp=C3=B8rgsm=C3=A5l_om_m=C3=B8det?=
Content-Language: da
To: Alice <alice@acmecorp.com>
From: Bob <bob@example.net>
Content-Type: multipart/alternative; boundary="------------abcDEF0123"

This is a multi-part message in MIME format.
--------------abcDEF0123
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 8bit

Hej Alice, ses vi kl. 10?

--------------abcDEF0123
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 8bit

<html><head><meta charset="UTF-8"></head><body><p>Hej Alice, ses vi kl. 10?</p></body></html>
--------------abcDEF0123--
`,
		"outlook": `Received: from outlook-sender.example.com (40.107.1.2) by mx.acmecorp.com with ESMTP; Thu, 22 Oct 2026 08:00:03 +0000
Received: from AM6PR01MB1234.eurprd01.prod.exchangelabs.com (2603:10a6::1) by DB9PR01MB5678.eurprd01.prod.exchangelabs.com with HTTPS; Thu, 22 Oct 2026 08:00:01 +0000
From: Bob Jensen <bob@contoso.example>
To: Alice <alice@acmecorp.com>
Subject: =?iso-8859-1?Q?RE=3A_Tilbud_p=E5_m=F8de?=
Thread-Topic: Tilbud
In-Reply-To: <DB9PR01MB5678AAAA@DB9PR01MB5678.eurprd01.prod.exchangelabs.com>
References: <DB9PR01MB5678AAAA@DB9PR01MB5678.eurprd01.prod.exchangelabs.com>
Date: Thu, 22 Oct 2026 08:00:00 +0000
Message-ID: <DB9PR01MB5678BBBB1C2D3E4F5A6B7C8D9E0F1A@DB9PR01MB5678.eurprd01.prod.exchangelabs.com>
Accept-Language: en-US, da-DK
Content-Language: da-DK
X-MS-Has-Attach:
X-Mailer: Microsoft Outlook 16.0
Content-Type: multipart/alternative; boundary="_000_DB9PR01MB5678_"
MIME-Version: 1.0

--_000_DB9PR01MB5678_
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable

Hej, tak for m=F8det.

--_000_DB9PR01MB5678_
Content-Type: text/html; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable

<html><head><meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Diso-8859-1"><style type=3D"text/css" style=3D"display:none;"> P {margin-top:0;margin-bottom:0;} </style></head><body dir=3D"ltr"><div style=3D"font-size: 12pt; color: rgb(0, 0, 0);">Hej, tak for m=F8det.</div></body></html>
--_000_DB9PR01MB5678_--
`,
		"gmail": `Received: from mail-wm1-f41.google.com (mail-wm1-f41.google.com [209.85.128.41]) by mx.acmecorp.com with ESMTPS; Thu, 22 Oct 2026 10:00:03 +0200
Received: by mail-wm1-f41.google.com with SMTP id q1so123wmq.1 for <alice@acmecorp.com>; Thu, 22 Oct 2026 01:00:02 -0700 (PDT)
MIME-Version: 1.0
From: Bob <bob@gmail.com>
Date: Thu, 22 Oct 2026 10:00:00 +0200
Message-ID: <CAHJkAbCdEfGh1234567890=XyZ@mail.gmail.com>
Subject: Fwd: Reisen
To: Alice <alice@acmecorp.com>
Content-Type: multipart/alternative; boundary="000000000000a1b2c3"

--000000000000a1b2c3
Content-Type: text/plain; charset="UTF-8"

Videresendt besked

--000000000000a1b2c3
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Videresendt besked</div>

--000000000000a1b2c3--
`,
		"mailing list": `Return-Path: <devel-bounces@lists.example.org>
Received: from lists.example.org (lists.example.org [198.51.100.10]) by mx.acmecorp.com with ESMTP; Thu, 22 Oct 2026 10:00:04 +0200
Received: from [10.0.0.4] (unknown [10.0.0.4]) by lists.example.org (Postfix) with ESMTP id 9; Thu, 22 Oct 2026 10:00:02 +0200 (CEST)
From: Carol <carol@example.com>
To: devel@lists.example.org
Subject: [devel] Re: patch review
In-Reply-To: <20261021.1234@example.com>
References: <20261021.1234@example.com>
Date: Thu, 22 Oct 2026 09:59:50 +0200
Message-ID: <20261022.5678@example.com>
List-Id: <devel.lists.example.org>
Precedence: list
Content-Type: text/plain; charset=us-ascii

Looks good to me.
`,
		"newsletter": `From: Shop <news@shop.example>
To: alice@acmecorp.com
Subject: =?UTF-8?B?8J+OgSBFZG1lciBldGlsYnVk?=
Date: Thu, 22 Oct 2026 07:00:00 +0000
Message-ID: <20261022070000.1.abcdef@bounce.shop.example>
List-Unsubscribe: <mailto:unsub@shop.example>
X-Mailer: Mailchimp Mailer
Content-Type: text/html; charset=UTF-8

<html><body><div style="display:none;font-size:1px;color:#fff;max-height:0;overflow:hidden">Spar 20 procent i dag&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;</div><table><tr><td style="color:#333333">Tilbud</td></tr></table></body></html>
`,
	}
	for name, raw := range samples {
		t.Run(name, func(t *testing.T) {
			found := anomalySymbolsOf(t, engine, anomalyMessage(t, raw))
			// The newsletter is HTML only by design; that small symbol is expected.
			delete(found, "MIME_HTML_ONLY")
			if len(found) != 0 {
				t.Fatalf("legitimate %s mail raised %v", name, found)
			}
		})
	}
}

func TestAnomalySkippedForTrustedAndOwnMail(t *testing.T) {
	engine := anomalyEngine(t)
	forged := "Received: from x by mx.acmecorp.com; Thu, 22 Oct 2026 09:59:00 +0200\nReceived: from y by mx.acmecorp.com; Thu, 22 Oct 2026 09:58:00 +0200\n" + plainBase
	// A hosted sender's internal hops are legitimate.
	internal := replaceOnce(forged, "eve@example.net", "alice@acmecorp.com")
	if found := anomalySymbolsOf(t, engine, anomalyMessage(t, internal)); found["HDR_RCVD_FORGED_LOCAL"].Name != "" {
		t.Fatalf("hosted sender flagged: %v", found)
	}
	// A passing DMARC result clears a Message-ID in a hosted domain.
	signed := anomalyMessage(t, replaceOnce(plainBase, "mail.example.net", "acmecorp.com"), func(m *Message) { m.DMARC = "pass" })
	if found := anomalySymbolsOf(t, engine, signed); found["HDR_MSGID_FORGED_LOCAL"].Name != "" {
		t.Fatalf("authenticated sender flagged: %v", found)
	}
	// Authenticated submissions are never scored at all.
	if result, _ := engine.Check(context.Background(), anomalyMessage(t, forged, func(m *Message) { m.Authenticated = true })); len(result.Symbols) != 0 {
		t.Fatalf("authenticated submission scored: %v", result.Symbols)
	}
}
