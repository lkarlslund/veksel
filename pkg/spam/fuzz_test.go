package spam

import (
	"bytes"
	"context"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

// FuzzCheck scores arbitrary inbound messages with the offline engine
// (content, MIME structure, header anomalies, phishing and URI heuristics)
// and tokenizes them for Bayes. Neither may panic or modify the message.
func FuzzCheck(f *testing.F) {
	for _, seed := range []string{
		"From: \"PayPal\" <service@paypa1.example>\r\nTo: a@b.example\r\nSubject: =?UTF-8?B?VXJnZW50?= ACT NOW!!!\r\nDate: Mon, 01 Jan 2024 10:00:00 +0000\r\nMessage-Id: <x@y>\r\nReceived: from unknown (HELO x) ([192.0.2.1]) by mx\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nVisit http://bit.ly/x hxxp://evil[.]example\r\n--b\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\nPGEgaHJlZj0iaHR0cHM6Ly9ldmlsLmV4YW1wbGUiPnBheXBhbC5jb208L2E+PHNwYW4gc3R5bGU9ImRpc3BsYXk6bm9uZSI+aGlkZGVuPC9zcGFuPg==\r\n--b--\r\n",
		"Subject: hi\r\n\r\nbody",
		"Subject: =?x?Q?=ZZ?= =?utf-8?B?!!?=\r\n\r\n",
		"Content-Type: multipart/mixed; boundary=a\r\n\r\n--a\r\nContent-Type: multipart/mixed; boundary=a\r\n\r\n--a--\r\n",
		"",
	} {
		f.Add([]byte(seed))
	}
	config, err := ParseSettings(Settings{Thresholds: DefaultThresholds(), ProtectedBrands: []string{"PayPal"}, URLShorteners: DefaultURLShorteners()})
	if err != nil {
		f.Fatal(err)
	}
	engine, err := NewEngine(config, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		original := bytes.Clone(raw)
		headers, _ := model.ParseMessageHeaders(raw)
		message := Message{Content: raw, Headers: headers, RemoteIP: "192.0.2.1", Helo: "mx.example", EnvelopeFrom: "a@example.com"}
		_, _ = engine.Check(context.Background(), message)
		_, _ = engine.CheckOutbound(context.Background(), message)
		_ = NewSample(raw)
		if !bytes.Equal(raw, original) {
			t.Fatalf("scoring modified the message: %q became %q", original, raw)
		}
	})
}
