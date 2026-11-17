package main

import (
	"encoding/base64"
	"testing"
)

func TestMessageWebhookPayloadParts(t *testing.T) {
	data := []byte("From: =?utf-8?q?Mette_K=C3=A6r?= <mette@example.test>\r\nTo: domains@example.com\r\nSubject: Ny konto\r\nX-Signup: 42\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHej, opret venligst kontoen.\r\n")
	headers := map[string]string{"From": "=?utf-8?q?Mette_K=C3=A6r?= <mette@example.test>", "To": "domains@example.com", "Subject": "Ny konto"}
	summary := messageWebhookPayload("domains", "domains@example.com", "inbox", "item1", data, headers, nil)
	if summary["from"] != "Mette Kær <mette@example.test>" || summary["recipient"] != "domains@example.com" || summary["account_id"] != "domains" {
		t.Fatalf("summary = %v", summary)
	}
	for _, part := range []string{"headers", "text", "html", "attachments", "raw"} {
		if _, ok := summary[part]; ok {
			t.Errorf("summary carries %s without being asked", part)
		}
	}
	full := messageWebhookPayload("domains", "domains@example.com", "inbox", "item1", data, headers, map[string]bool{"headers": true, "text": true, "raw": true})
	if raw, _ := base64.StdEncoding.DecodeString(full["raw"].(string)); string(raw) != string(data) {
		t.Fatal("raw does not round-trip")
	}
	if text, _ := full["text"].(string); text == "" || text[:3] != "Hej" {
		t.Fatalf("text = %q", full["text"])
	}
	if values := full["headers"].(map[string][]string)["x-signup"]; len(values) != 1 || values[0] != "42" {
		t.Fatalf("headers = %v", full["headers"])
	}
}
