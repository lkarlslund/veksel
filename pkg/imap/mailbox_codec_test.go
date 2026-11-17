package imap

import (
	"errors"
	"reflect"
	"testing"

	"golang.org/x/text/unicode/norm"
)

func TestModifiedUTF7RoundTrip(t *testing.T) {
	tests := map[string]string{
		"INBOX":              "INBOX",
		"R&D":                "R&-D",
		"~peter/mail/台北/日本語": "~peter/mail/&U,BTFw-/&ZeVnLIqe-",
		"Archive/🗄":          "Archive/&2D3dxA-",
	}
	for plain, wire := range tests {
		t.Run(plain, func(t *testing.T) {
			gotWire, err := encodeModifiedUTF7(plain)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if gotWire != wire {
				t.Fatalf("encoded = %q, want %q", gotWire, wire)
			}
			gotPlain, err := decodeModifiedUTF7(wire)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if gotPlain != plain {
				t.Fatalf("decoded = %q, want %q", gotPlain, plain)
			}
		})
	}
}

func TestNormalizeMailboxArgumentsUsesNegotiatedEncoding(t *testing.T) {
	session := &Session{cfg: &Config{}}
	args, err := session.normalizeMailboxArguments("RENAME", []string{"&ZeVnLIqe-", "R&-D"})
	if err != nil {
		t.Fatalf("normalize rev1: %v", err)
	}
	if want := []string{"日本語", "R&D"}; !reflect.DeepEqual(args, want) {
		t.Fatalf("rev1 arguments = %#v, want %#v", args, want)
	}

	session.rev2Enabled = true
	args, err = session.normalizeMailboxArguments("UID", []string{"COPY", "1:*", "Cafe\u0301"})
	if err != nil {
		t.Fatalf("normalize rev2: %v", err)
	}
	if want := []string{"COPY", "1:*", "Café"}; !reflect.DeepEqual(args, want) {
		t.Fatalf("rev2 arguments = %#v, want %#v", args, want)
	}
}

func TestMailboxToWireUsesNegotiatedEncoding(t *testing.T) {
	session := &Session{}
	if got := session.mailboxToWire("日本語"); got != `"&ZeVnLIqe-"` {
		t.Fatalf("rev1 wire name = %q", got)
	}
	session.rev2Enabled = true
	if got := session.mailboxToWire("日本語"); got != `"日本語"` {
		t.Fatalf("rev2 wire name = %q", got)
	}
}

func TestIMAP4rev2CapabilityIsAdvertisedOnlyOnProtectedSessions(t *testing.T) {
	for _, protected := range []bool{false, true} {
		session := &Session{cfg: &Config{}, tlsDone: protected}
		offered := false
		for _, capability := range session.buildCapabilities() {
			offered = offered || capability == "IMAP4rev2"
		}
		if offered != protected {
			t.Fatalf("protected=%t: IMAP4rev2 offered=%t", protected, offered)
		}
	}
}

func TestIMAP4rev2CapabilityRequiresImplementationAndTLS(t *testing.T) {
	for _, test := range []struct {
		ready, protected, want bool
	}{
		{ready: false, protected: false, want: false},
		{ready: false, protected: true, want: false},
		{ready: true, protected: false, want: false},
		{ready: true, protected: true, want: true},
	} {
		if got := shouldOfferIMAP4rev2(test.ready, test.protected); got != test.want {
			t.Errorf("shouldOfferIMAP4rev2(%t, %t) = %t, want %t", test.ready, test.protected, got, test.want)
		}
	}
}

func TestModifiedUTF7RejectsNonCanonicalAndMalformedNames(t *testing.T) {
	for _, value := range []string{
		"&AGE-",       // printable ASCII encoded instead of directly represented
		"&U,BTFw==-",  // base64 padding is forbidden
		"&2AA-",       // unpaired high surrogate
		"&3AA-",       // unpaired low surrogate
		"&not-closed", // encoded run has no terminator
		"café",        // raw UTF-8 is forbidden in rev1 mode
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := decodeModifiedUTF7(value); !errors.Is(err, errInvalidMailboxName) {
				t.Fatalf("error = %v, want invalid mailbox name", err)
			}
		})
	}
}

func TestDecodeUTF8MailboxNormalizesToNFC(t *testing.T) {
	decomposed := "Cafe\u0301"
	got, err := decodeUTF8Mailbox(decomposed)
	if err != nil {
		t.Fatalf("decode UTF-8 mailbox: %v", err)
	}
	if got != norm.NFC.String(decomposed) || got != "Café" {
		t.Fatalf("normalized = %q", got)
	}
	for _, invalid := range []string{"bad\x00name", "bad\rname", string([]byte{0xff})} {
		if _, err := decodeUTF8Mailbox(invalid); !errors.Is(err, errInvalidMailboxName) {
			t.Fatalf("decode %q: error = %v", invalid, err)
		}
	}
}

func TestQuoteIMAPString(t *testing.T) {
	got, err := quoteIMAPString(`A "quoted" \\ name`)
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	if got != `"A \"quoted\" \\\\ name"` {
		t.Fatalf("quoted = %q", got)
	}
}
