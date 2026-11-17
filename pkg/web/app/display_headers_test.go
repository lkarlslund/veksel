package app

import "testing"

func TestDisplayHeadersDecodesEncodedWords(t *testing.T) {
	stored := map[string]string{"From": "Anders =?utf-8?q?Kj=C3=A6r?= <anders@example.test>", "Message-Id": "<=?x?=>"}
	got := displayHeaders(stored)
	if got["From"] != "Anders Kjær <anders@example.test>" || got["Message-Id"] != "<=?x?=>" {
		t.Fatalf("headers %q", got)
	}
	if stored["From"] == got["From"] {
		t.Fatal("stored headers were modified")
	}
}
