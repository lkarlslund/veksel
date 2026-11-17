package service

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestMIMEReaderProjectsSanitizedBodiesAndStreamsAttachments(t *testing.T) {
	_, space, _ := testRecipientHistory(t)
	raw := strings.Join([]string{
		"From: =?UTF-8?Q?Alice_=C3=86gir?= <alice@example.test>",
		"To: bob@example.test",
		"Subject: =?UTF-8?Q?Safe_=E2=9C=93?=",
		"Importance: high",
		"X-Priority: 1",
		"Priority: urgent",
		"MIME-Version: 1.0",
		"Content-Type: multipart/mixed; boundary=outer", "",
		"--outer", "Content-Type: multipart/alternative; boundary=choice", "",
		"--choice", "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: quoted-printable", "", "Plain=20body",
		"--choice", "Content-Type: text/html; charset=utf-8", "", `<div style="color:red" onclick="steal()"><script>steal()</script><img src="https://tracker.test/pixel"><p>Hello <strong>world</strong> <a href="https://example.test/path">visit</a> <a href="javascript:steal()">bad</a></p></div>`,
		"--choice--",
		"--outer", `Content-Type: application/octet-stream; name="report.bin"`, `Content-Disposition: attachment; filename="report.bin"`, "Content-Transfer-Encoding: base64", "", "AAECaGVsbG8=",
		"--outer--", "",
	}, "\r\n")
	access := UserAccess("alice", "test")
	item, err := space.CreateItem(t.Context(), access, model.InboxFolderID("alice"), ItemInput{Data: []byte(raw)})
	if err != nil {
		t.Fatal(err)
	}
	reader := NewMIMEReader(space)
	projection, err := reader.Project(t.Context(), access, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if projection.Headers["Subject"] != "Safe ✓" || MessageImportance(projection.Headers) != MailImportanceHigh || !strings.Contains(projection.Headers["From"], "Alice Ægir") || !strings.Contains(projection.Text, "Plain body") {
		t.Fatalf("projection = %+v", projection)
	}
	// Remote images stay inert (no src) and only allowlisted CSS survives.
	for _, unsafe := range []string{"script", "steal()", ` src="https://tracker.test`, "onclick=", "javascript:"} {
		if strings.Contains(strings.ToLower(projection.HTML), strings.ToLower(unsafe)) {
			t.Fatalf("sanitized HTML retained %q: %s", unsafe, projection.HTML)
		}
	}
	if !strings.Contains(projection.HTML, `data-remote-src="https://tracker.test/pixel"`) || !strings.Contains(projection.HTML, `style="color: red"`) {
		t.Fatalf("remote image or safe style not projected: %s", projection.HTML)
	}
	if !strings.Contains(projection.HTML, `href="https://example.test/path"`) || !strings.Contains(projection.HTML, `rel="nofollow noopener noreferrer"`) || !projection.UnsafeContentRemoved || !projection.RemoteContentBlocked {
		t.Fatalf("HTML safety projection = %+v", projection)
	}
	if len(projection.Attachments) != 1 || projection.Attachments[0].PartID != "1.2" || projection.Attachments[0].Name != "report.bin" || projection.Attachments[0].Size != 8 {
		t.Fatalf("attachments = %+v", projection.Attachments)
	}
	stream, err := reader.OpenAttachment(t.Context(), access, item.ID, "1.2")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stream.Reader)
	_ = stream.Reader.Close()
	if err != nil || string(data) != "\x00\x01\x02hello" || stream.ContentType != "application/octet-stream" {
		t.Fatalf("attachment = %q %+v, %v", data, stream.MessageAttachment, err)
	}
	if _, err := reader.OpenAttachment(t.Context(), access, item.ID, "../../items"); err == nil {
		t.Fatal("unsafe part identifier was accepted")
	}
	if _, err := reader.Project(t.Context(), UserAccess("bob", "test"), item.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unauthorized projection error = %v", err)
	}
}

func TestMIMEReaderRejectsNonMailAndMalformedMultipart(t *testing.T) {
	_, space, _ := testRecipientHistory(t)
	access := UserAccess("alice", "test")
	contact, err := space.CreateItem(t.Context(), access, model.FolderKey("alice", "Contacts"), ItemInput{Data: model.ContactToVCard(model.Contact{FN: "Ada"})})
	if err != nil {
		t.Fatal(err)
	}
	reader := NewMIMEReader(space)
	if _, err := reader.Project(t.Context(), access, contact.ID); err == nil || !strings.Contains(err.Error(), "not a mail") {
		t.Fatalf("non-mail projection error = %v", err)
	}
	mailItem, err := space.CreateItem(t.Context(), access, model.InboxFolderID("alice"), ItemInput{Data: []byte("Content-Type: multipart/mixed\r\n\r\nbroken")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Project(t.Context(), access, mailItem.ID); err == nil || !strings.Contains(err.Error(), "boundary") {
		t.Fatalf("malformed multipart error = %v", err)
	}
}
