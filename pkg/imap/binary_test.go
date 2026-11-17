package imap

import (
	"bytes"
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestBinarySectionDecodesTransferEncoding(t *testing.T) {
	message := []byte("MIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8A\r\n")
	got, err := binarySection(message, "")
	if err != nil {
		t.Fatalf("decode BINARY[]: %v", err)
	}
	if !bytes.Equal(got, []byte{'H', 'e', 'l', 'l', 'o', 0}) {
		t.Fatalf("decoded = %q", got)
	}
}

func TestBinarySectionSelectsMultipartLeafAndNormalizesText(t *testing.T) {
	message := []byte("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n" +
		"--x\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nline=201\nline=202\r\n" +
		"--x\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAQID\r\n--x--\r\n")
	text, err := binarySection(message, "1")
	if err != nil {
		t.Fatalf("decode part 1: %v", err)
	}
	if string(text) != "line 1\r\nline 2" {
		t.Fatalf("text part = %q", text)
	}
	binary, err := binarySection(message, "2")
	if err != nil || !bytes.Equal(binary, []byte{1, 2, 3}) {
		t.Fatalf("binary part = %v, %q", err, binary)
	}
	if root, err := binarySection(message, ""); err != nil || !bytes.Equal(root, message) {
		t.Fatalf("multipart root = %v, %q", err, root)
	}
}

func TestBinaryFetchSizePartialAndLiteral8(t *testing.T) {
	item := model.Item{Data: []byte("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8A")}
	session := &Session{}
	parts, literals, err := session.parseFetchAttrs("(BINARY.SIZE[] BINARY.PEEK[]<2.4>)", item)
	if err != nil {
		t.Fatalf("parse BINARY fetch: %v", err)
	}
	if len(parts) != 2 || parts[0] != "BINARY.SIZE[] 6" || parts[1] != "BINARY[]<2> ~{4}" {
		t.Fatalf("parts = %#v", parts)
	}
	if len(literals) != 1 || !bytes.Equal(literals[0].data, []byte{'l', 'l', 'o', 0}) {
		t.Fatalf("literals = %#v", literals)
	}
}

func TestBinaryFetchRejectsUnknownTransferEncoding(t *testing.T) {
	message := []byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: x-unknown\r\n\r\nbody")
	if _, err := binarySection(message, ""); !errors.Is(err, errUnknownCTE) {
		t.Fatalf("error = %v, want UNKNOWN-CTE", err)
	}
}

func TestFetchSeenSemantics(t *testing.T) {
	for _, test := range []struct {
		attrs string
		want  bool
	}{
		{attrs: "UID FLAGS"},
		{attrs: "BODY.PEEK[]"},
		{attrs: "BINARY.PEEK[]"},
		{attrs: "BINARY.SIZE[]"},
		{attrs: "BODY[]", want: true},
		{attrs: "BINARY[]", want: true},
	} {
		t.Run(test.attrs, func(t *testing.T) {
			if got := fetchSetsSeen(test.attrs); got != test.want {
				t.Fatalf("fetchSetsSeen(%q) = %t, want %t", test.attrs, got, test.want)
			}
		})
	}
}
